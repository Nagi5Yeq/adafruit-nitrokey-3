use heapless::{Vec, VecView};
use iso7816::Status;
use trussed_core::types::{KeyId, Location, Message, PathBuf};

use crate::{tlv, Client, Result};

pub const LOCATION: Location = Location::External;
const MESSAGE_LEN: usize = 1024;
const STATE_VERSION_1: u8 = 1;
const STATE_VERSION: u8 = 2;
const STATE_PATH: &str = "state";
const TMP_PATH: &str = "tmp";
const RESET_PATH: &str = "reset";
const MAX_TAG_LEN: usize = 3;
pub const MAX_FCP_LEN: usize = 255;

pub const LCS_INITIALIZATION: u8 = 0x03;
pub const LCS_OPERATIONAL: u8 = 0x05;
pub const LCS_TERMINATED: u8 = 0x0C;

pub const EF_FLAG_CREATED_OPERATIONAL: u8 = 0x01;

pub const KEY_KIND_TDES: u8 = 0x01;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct State {
    pub app_lcs: u8,
    pub pin_len: u8,
    pub pending_pin_len: u8,
}

impl Default for State {
    fn default() -> Self {
        Self {
            app_lcs: LCS_INITIALIZATION,
            pin_len: 0,
            pending_pin_len: 0,
        }
    }
}

impl State {
    pub fn is_operational(&self) -> bool {
        self.app_lcs == LCS_OPERATIONAL
    }

    pub fn is_terminated(&self) -> bool {
        self.app_lcs == LCS_TERMINATED
    }
}

#[derive(Clone, Debug)]
pub struct EfRecord {
    pub lcs: u8,
    pub flags: u8,
    pub fcp: Vec<u8, MAX_FCP_LEN>,
}

impl EfRecord {
    pub fn is_operational(&self) -> bool {
        self.lcs & 0x0C == 0x04
    }

    pub fn is_key_file(&self) -> bool {
        self.descriptor() == Some(crate::FDB_KEY_EF)
    }

    pub fn descriptor(&self) -> Option<u8> {
        self.find(&[0x82]).and_then(|value| value.first().copied())
    }

    pub fn find(&self, tag: &[u8]) -> Option<&[u8]> {
        let mut data = self.fcp.as_slice();
        while !data.is_empty() {
            let (t, value, rest) = tlv::take_tlv(data)?;
            if t == tag {
                return Some(value);
            }
            data = rest;
        }
        None
    }

    pub fn activate(&mut self, key_loaded: bool) {
        if self.is_operational() {
            return;
        }
        let created_operational = self.flags & EF_FLAG_CREATED_OPERATIONAL != 0;
        self.lcs = 0x04 | if created_operational { 0x02 } else { 0x00 };
        self.set_key_loaded(key_loaded);
    }

    pub fn set_key_loaded(&mut self, key_loaded: bool) {
        if self.is_operational() {
            self.lcs = (self.lcs & !0x01) | u8::from(key_loaded);
        }
    }

    pub fn key_usable(&self) -> bool {
        !self.is_operational() || self.lcs & 0x01 != 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyRecord {
    pub kind: u8,
    pub key: KeyId,
    pub public: Option<KeyId>,
}

fn hex_digit(nibble: u8) -> u8 {
    b"0123456789abcdef"[usize::from(nibble & 0x0F)]
}

fn push_hex(buf: &mut Vec<u8, 16>, bytes: &[u8]) {
    for byte in bytes {
        buf.push(hex_digit(byte >> 4)).ok();
        buf.push(hex_digit(*byte)).ok();
    }
}

fn path_from(bytes: &[u8]) -> PathBuf {
    PathBuf::try_from(core::str::from_utf8(bytes).unwrap()).unwrap()
}

fn prefixed(prefix: u8, fid: u16) -> Vec<u8, 16> {
    let mut name = Vec::new();
    name.push(prefix).ok();
    push_hex(&mut name, &fid.to_be_bytes());
    name
}

pub fn ef_path(fid: u16) -> PathBuf {
    path_from(&prefixed(b'f', fid))
}

pub fn key_path(fid: u16) -> PathBuf {
    path_from(&prefixed(b'k', fid))
}

pub fn do_prefix(fid: u16) -> Vec<u8, 16> {
    prefixed(b'd', fid)
}

pub fn do_path(fid: u16, tag: &[u8]) -> PathBuf {
    let mut name = do_prefix(fid);
    push_hex(&mut name, tag);
    path_from(&name)
}

pub fn parse_do_name(name: &str) -> Option<(u16, Vec<u8, MAX_TAG_LEN>)> {
    let bytes = name.as_bytes();
    if bytes.first() != Some(&b'd') || bytes.len() < 7 || bytes.len() % 2 == 0 {
        return None;
    }
    let mut raw: Vec<u8, 8> = Vec::new();
    for pair in bytes[1..].chunks(2) {
        let text = core::str::from_utf8(pair).ok()?;
        raw.push(u8::from_str_radix(text, 16).ok()?).ok()?;
    }
    let fid = u16::from_be_bytes([raw[0], raw[1]]);
    let tag = Vec::from_slice(&raw[2..]).ok()?;
    Some((fid, tag))
}

pub fn exists<T: Client>(trussed: &mut T, path: PathBuf) -> Result<bool> {
    Ok(syscall!(trussed.entry_metadata(LOCATION, path))?
        .metadata
        .is_some())
}

pub fn file_len<T: Client>(trussed: &mut T, path: PathBuf) -> Result<Option<usize>> {
    Ok(syscall!(trussed.entry_metadata(LOCATION, path))?
        .metadata
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len()))
}

pub fn read_small<T: Client>(trussed: &mut T, path: PathBuf) -> Result<Option<Message>> {
    if !exists(trussed, path.clone())? {
        return Ok(None);
    }
    Ok(Some(syscall!(trussed.read_file(LOCATION, path))?.data))
}

pub fn read_into<T: Client>(trussed: &mut T, path: PathBuf, buf: &mut VecView<u8>) -> Result<bool> {
    let Some(len) = file_len(trussed, path.clone())? else {
        return Ok(false);
    };
    if len <= MESSAGE_LEN {
        let data = syscall!(trussed.read_file(LOCATION, path))?.data;
        tlv::extend(buf, &data)?;
        return Ok(true);
    }
    let mut offset = 0;
    while offset < len {
        let length = (len - offset).min(MESSAGE_LEN);
        let reply = syscall!(trussed.partial_read_file(LOCATION, path.clone(), offset, length))?;
        tlv::extend(buf, &reply.data)?;
        offset += length;
    }
    Ok(true)
}

pub fn write<T: Client>(trussed: &mut T, path: PathBuf, data: &[u8]) -> Result {
    if data.len() <= MESSAGE_LEN {
        let message = Message::try_from(data).map_err(|_| Status::NotEnoughMemory)?;
        syscall!(trussed.write_file(LOCATION, path, message, None))?;
        return Ok(());
    }
    let tmp = PathBuf::try_from(TMP_PATH).unwrap();
    let mut chunks = data.chunks(MESSAGE_LEN);
    let first = Message::try_from(chunks.next().unwrap()).unwrap();
    syscall!(trussed.write_file(LOCATION, tmp.clone(), first, None))?;
    for chunk in chunks {
        let message = Message::try_from(chunk).unwrap();
        if let Err(status) = syscall!(trussed.append_file(LOCATION, tmp.clone(), message)) {
            syscall!(trussed.remove_file(LOCATION, tmp)).ok();
            return Err(status);
        }
    }
    syscall!(trussed.rename(LOCATION, tmp, path))?;
    Ok(())
}

pub fn remove<T: Client>(trussed: &mut T, path: PathBuf) -> Result {
    if exists(trussed, path.clone())? {
        syscall!(trussed.remove_file(LOCATION, path))?;
    }
    Ok(())
}

pub fn load_state<T: Client>(trussed: &mut T) -> Result<State> {
    let Some(data) = read_small(trussed, PathBuf::try_from(STATE_PATH).unwrap())? else {
        return Ok(State::default());
    };
    match data.as_slice() {
        [STATE_VERSION_1, app_lcs, pin_len] => Ok(State {
            app_lcs: *app_lcs,
            pin_len: *pin_len,
            pending_pin_len: 0,
        }),
        [STATE_VERSION, app_lcs, pin_len, pending_pin_len] => Ok(State {
            app_lcs: *app_lcs,
            pin_len: *pin_len,
            pending_pin_len: *pending_pin_len,
        }),
        _ => Err(Status::UnspecifiedPersistentExecutionError),
    }
}

pub fn save_state<T: Client>(trussed: &mut T, state: &State) -> Result {
    write(
        trussed,
        PathBuf::try_from(STATE_PATH).unwrap(),
        &[
            STATE_VERSION,
            state.app_lcs,
            state.pin_len,
            state.pending_pin_len,
        ],
    )
}

pub fn load_ef<T: Client>(trussed: &mut T, fid: u16) -> Result<Option<EfRecord>> {
    let Some(data) = read_small(trussed, ef_path(fid))? else {
        return Ok(None);
    };
    let [lcs, flags, fcp @ ..] = data.as_slice() else {
        return Err(Status::UnspecifiedPersistentExecutionError);
    };
    let mut record = EfRecord {
        lcs: *lcs,
        flags: *flags,
        fcp: Vec::from_slice(fcp).map_err(|_| Status::UnspecifiedPersistentExecutionError)?,
    };
    if record.is_key_file() && record.is_operational() {
        let loaded = exists(trussed, key_path(fid))?;
        record.set_key_loaded(loaded);
    }
    Ok(Some(record))
}

pub fn save_ef<T: Client>(trussed: &mut T, fid: u16, record: &EfRecord) -> Result {
    let mut data: Vec<u8, { MAX_FCP_LEN + 2 }> = Vec::new();
    data.extend_from_slice(&[record.lcs, record.flags]).ok();
    data.extend_from_slice(&record.fcp).ok();
    write(trussed, ef_path(fid), &data)
}

pub fn new_fcp(fcp: &[u8]) -> Result<Vec<u8, MAX_FCP_LEN>> {
    Vec::from_slice(fcp).map_err(|_| Status::NotEnoughMemory)
}

pub fn load_key<T: Client>(trussed: &mut T, fid: u16) -> Result<Option<KeyRecord>> {
    let Some(data) = read_small(trussed, key_path(fid))? else {
        return Ok(None);
    };
    let id = |bytes: &[u8]| KeyId::from_value(u128::from_be_bytes(bytes.try_into().unwrap()));
    match data.as_slice() {
        [kind, key @ ..] if key.len() == 16 => Ok(Some(KeyRecord {
            kind: *kind,
            key: id(key),
            public: None,
        })),
        [kind, keys @ ..] if keys.len() == 32 => Ok(Some(KeyRecord {
            kind: *kind,
            key: id(&keys[..16]),
            public: Some(id(&keys[16..])),
        })),
        _ => Err(Status::UnspecifiedPersistentExecutionError),
    }
}

pub fn save_key<T: Client>(trussed: &mut T, fid: u16, record: &KeyRecord) -> Result {
    let mut data = [0u8; 33];
    data[0] = record.kind;
    data[1..17].copy_from_slice(&record.key.value().to_be_bytes());
    let len = match record.public {
        Some(public) => {
            data[17..].copy_from_slice(&public.value().to_be_bytes());
            33
        }
        None => 17,
    };
    write(trussed, key_path(fid), &data[..len])
}

pub fn replace_key<T: Client>(trussed: &mut T, fid: u16, new: Option<&KeyRecord>) -> Result {
    let old = load_key(trussed, fid)?;
    match new {
        Some(record) => save_key(trussed, fid, record)?,
        None => remove(trussed, key_path(fid))?,
    }
    if let Some(old) = old {
        syscall!(trussed.delete(old.key)).ok();
        if let Some(public) = old.public {
            syscall!(trussed.delete(public)).ok();
        }
    }
    Ok(())
}

pub fn delete_key<T: Client>(trussed: &mut T, fid: u16) -> Result {
    replace_key(trussed, fid, None)
}

pub fn for_each_name<T: Client>(
    trussed: &mut T,
    prefix: &[u8],
    mut f: impl FnMut(&mut T, &str) -> Result<bool>,
) -> Result {
    let start = path_from(prefix);
    let mut entry =
        syscall!(trussed.read_dir_first_alphabetical(LOCATION, PathBuf::new(), Some(start)))?.entry;
    while let Some(current) = entry {
        let name = current.file_name().as_str();
        if !name.as_bytes().starts_with(prefix) {
            break;
        }
        if !f(trussed, name)? {
            break;
        }
        entry = syscall!(trussed.read_dir_next())?.entry;
    }
    Ok(())
}

pub fn parse_ef_name(name: &str) -> Option<u16> {
    let hex = name.strip_prefix('f')?;
    if hex.len() != 4 {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

pub fn begin_reset<T: Client>(trussed: &mut T) -> Result {
    write(trussed, PathBuf::try_from(RESET_PATH).unwrap(), &[0x01])
}

pub fn reset_pending<T: Client>(trussed: &mut T) -> Result<bool> {
    exists(trussed, PathBuf::try_from(RESET_PATH).unwrap())
}

pub fn delete_recorded_keys<T: Client>(trussed: &mut T) -> Result {
    let mut result = Ok(());
    for_each_name(trussed, b"k", |trussed, name| {
        let Some(fid) = name
            .strip_prefix('k')
            .filter(|hex| hex.len() == 4)
            .and_then(|hex| u16::from_str_radix(hex, 16).ok())
        else {
            return Ok(true);
        };
        match load_key(trussed, fid) {
            Ok(Some(record)) => {
                syscall!(trussed.delete(record.key)).ok();
                if let Some(public) = record.public {
                    syscall!(trussed.delete(public)).ok();
                }
            }
            Ok(None) => {}
            Err(status) => result = Err(status),
        }
        Ok(true)
    })?;
    result
}

pub fn for_each_do<T: Client>(
    trussed: &mut T,
    prefix: &[u8],
    mut f: impl FnMut(&mut T, u16, &[u8]) -> Result<bool>,
) -> Result {
    let start = path_from(prefix);
    let mut entry =
        syscall!(trussed.read_dir_first_alphabetical(LOCATION, PathBuf::new(), Some(start)))?.entry;
    while let Some(current) = entry {
        let name = current.file_name().as_str();
        if !name.as_bytes().starts_with(prefix) {
            break;
        }
        if let Some((fid, tag)) = parse_do_name(name) {
            if !f(trussed, fid, &tag)? {
                break;
            }
        }
        entry = syscall!(trussed.read_dir_next())?.entry;
    }
    Ok(())
}
