use apdu_app::CommandView;
use heapless::{Vec, VecView};
use iso7816::Status;
use sha1::{Digest, Sha1};
use trussed_core::types::{
    KeyId, KeySerialization, Mechanism, SignatureSerialization, StorageAttributes,
};

use crate::{
    acl,
    admin::find_field,
    store::{self, EfRecord, KeyRecord},
    tlv, Client, Gids, KeyEnvironment, Result,
};

const KEY_TYPE_RSA: u8 = 0x02;
const KEY_TYPE_ECC: u8 = 0x03;
const CRT_DST: u8 = 0xB6;
const CRT_CT: u8 = 0xB8;
const USAGE_COMPUTATION: u8 = 0x40;
const PADDING_MASK: u8 = 0xC0;
const PADDING_NONE: u8 = 0x00;
const PADDING_PKCS1: u8 = 0x40;
const PADDING_OAEP: u8 = 0x80;
const PADDING_INDICATOR_NONE: u8 = 0x00;
const MAX_HASH_LEN: usize = 64;
const SHA1_LEN: usize = 20;
const SHA1_EMPTY: [u8; SHA1_LEN] = [
    0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
    0xAF, 0xD8, 0x07, 0x09,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    P256,
    P384,
}

impl KeyKind {
    pub fn from_algorithm(algorithm: u8) -> Option<Self> {
        match algorithm & 0x0F {
            0x07 => Some(Self::Rsa2048),
            0x08 => Some(Self::Rsa3072),
            0x09 => Some(Self::Rsa4096),
            0x0C => Some(Self::P256),
            0x0D => Some(Self::P384),
            _ => None,
        }
    }

    pub fn from_record(record: &KeyRecord) -> Option<Self> {
        if record.kind == store::KEY_KIND_TDES {
            return None;
        }
        Self::from_algorithm(record.kind)
    }

    fn id(self) -> u8 {
        match self {
            Self::Rsa2048 => 0x07,
            Self::Rsa3072 => 0x08,
            Self::Rsa4096 => 0x09,
            Self::P256 => 0x0C,
            Self::P384 => 0x0D,
        }
    }

    fn mechanism(self) -> Mechanism {
        match self {
            Self::Rsa2048 => Mechanism::Rsa2048Pkcs1v15,
            Self::Rsa3072 => Mechanism::Rsa3072Pkcs1v15,
            Self::Rsa4096 => Mechanism::Rsa4096Pkcs1v15,
            Self::P256 => Mechanism::P256,
            Self::P384 => Mechanism::P384,
        }
    }

    fn raw_mechanism(self) -> Mechanism {
        match self {
            Self::Rsa2048 => Mechanism::Rsa2048Raw,
            Self::Rsa3072 => Mechanism::Rsa3072Raw,
            Self::Rsa4096 => Mechanism::Rsa4096Raw,
            Self::P256 => Mechanism::P256Prehashed,
            Self::P384 => Mechanism::P384Prehashed,
        }
    }

    fn is_rsa(self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }

    fn modulus_len(self) -> usize {
        match self {
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

fn crts(record: &EfRecord) -> impl Iterator<Item = (u8, &[u8])> {
    let mut data = record.find(&[0xA5]).unwrap_or_default();
    core::iter::from_fn(move || {
        let (tag, crt, rest) = tlv::take_tlv(data)?;
        data = rest;
        Some((tag.first().copied().unwrap_or_default(), crt))
    })
}

fn check_crts(record: &EfRecord, kind: KeyKind) -> Result {
    if crts(record).any(|(tag, crt)| {
        matches!(tag, CRT_DST | CRT_CT)
            && crt_byte(crt, 0x80).and_then(KeyKind::from_algorithm) != Some(kind)
    }) {
        return Err(Status::IncorrectDataParameter);
    }
    Ok(())
}

fn crt_byte(crt: &[u8], tag: u8) -> Option<u8> {
    find_field(crt, tag).ok().flatten()?.first().copied()
}

fn usage_limit(crt: &[u8]) -> u16 {
    find_field(crt, 0xA3)
        .ok()
        .flatten()
        .and_then(|template| find_field(template, 0x90).ok().flatten())
        .and_then(|counter| counter.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0)
}

fn take_varint_bytes(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut len = 0usize;
    for (i, byte) in data.iter().enumerate().take(4) {
        len |= usize::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            let rest = &data[i + 1..];
            return (rest.len() >= len).then(|| rest.split_at(len));
        }
    }
    None
}

fn take_der<'a>(data: &'a [u8], tag: u8) -> Result<(&'a [u8], &'a [u8])> {
    match tlv::take_tlv(data) {
        Some((found, value, rest)) if found == [tag] => Ok((value, rest)),
        _ => Err(Status::IncorrectDataParameter),
    }
}

fn unsigned(value: &[u8]) -> &[u8] {
    let zeros = value.iter().take_while(|&&byte| byte == 0).count();
    &value[zeros.min(value.len().saturating_sub(1))..]
}

fn push_postcard_bytes(out: &mut Vec<u8, 1100>, bytes: &[u8]) -> Result {
    let mut len = bytes.len();
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        let byte = if len == 0 { byte } else { byte | 0x80 };
        out.push(byte).map_err(|_| Status::IncorrectDataParameter)?;
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(bytes)
        .map_err(|_| Status::IncorrectDataParameter)
}

fn mgf1_xor(seed: &[u8], target: &mut [u8]) {
    for (counter, chunk) in target.chunks_mut(SHA1_LEN).enumerate() {
        let mask = Sha1::new()
            .chain_update(seed)
            .chain_update((counter as u32).to_be_bytes())
            .finalize();
        chunk.iter_mut().zip(mask).for_each(|(byte, m)| *byte ^= m);
    }
}

fn oaep_decode(block: &mut [u8]) -> Option<&[u8]> {
    if block.len() < 2 * SHA1_LEN + 2 {
        return None;
    }
    let (first, rest) = block.split_at_mut(1);
    let (seed, db) = rest.split_at_mut(SHA1_LEN);
    mgf1_xor(db, seed);
    mgf1_xor(seed, db);
    let (label_hash, tail) = db.split_at(SHA1_LEN);
    let mut bad = first[0]
        | label_hash
            .iter()
            .zip(SHA1_EMPTY)
            .fold(0, |acc, (a, b)| acc | (a ^ b));
    let mut searching = 1u8;
    let mut start = 0usize;
    for (index, &byte) in tail.iter().enumerate() {
        let is_zero = u8::from(byte == 0x00);
        let is_one = u8::from(byte == 0x01);
        let found = searching & is_one;
        start |= usize::from(found) * (index + 1);
        bad |= searching & (1 - is_zero) & (1 - is_one);
        searching &= 1 - found;
    }
    bad |= searching;
    (bad == 0).then(|| &tail[start..])
}

impl<T: Client> Gids<T> {
    fn key_kind(&mut self, fid: u16) -> Result<(KeyKind, KeyRecord)> {
        let record =
            store::load_key(&mut self.trussed, fid)?.ok_or(Status::KeyReferenceNotFound)?;
        let kind = KeyKind::from_record(&record).ok_or(Status::ConditionsOfUseNotSatisfied)?;
        Ok((kind, record))
    }

    fn push_public_key(&mut self, kind: KeyKind, public: KeyId, reply: &mut VecView<u8>) -> Result {
        let mut template: Vec<u8, 600> = Vec::new();
        if kind.is_rsa() {
            let serialized = syscall!(self.trussed.serialize_key(
                kind.mechanism(),
                public,
                KeySerialization::RsaParts
            ))?
            .serialized_key;
            let (n, rest) = take_varint_bytes(&serialized)
                .ok_or(Status::UnspecifiedNonpersistentExecutionError)?;
            let (e, _) =
                take_varint_bytes(rest).ok_or(Status::UnspecifiedNonpersistentExecutionError)?;
            tlv::push_tlv(template.as_mut_view(), &[0x81], n)?;
            tlv::push_tlv(template.as_mut_view(), &[0x82], e)?;
        } else {
            let serialized = syscall!(self.trussed.serialize_key(
                kind.mechanism(),
                public,
                KeySerialization::Raw
            ))?
            .serialized_key;
            let mut point: Vec<u8, 97> = Vec::new();
            point.push(0x04).ok();
            point
                .extend_from_slice(&serialized)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
            tlv::push_tlv(template.as_mut_view(), &[0x86], &point)?;
        }
        tlv::push_tlv(reply, &[0x7F, 0x49], &template)
    }

    pub(crate) fn generate_key_pair(
        &mut self,
        apdu: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result {
        Self::check_p1p2(&apdu)?;
        if self.state()?.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let (tag, template, rest) =
            tlv::take_tlv(apdu.data()).ok_or(Status::IncorrectDataParameter)?;
        if tag != [0xAC] || !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let (algorithm, reference) =
            match (find_field(template, 0x80)?, find_field(template, 0x83)?) {
                (Some([algorithm]), Some([reference])) => (*algorithm, *reference),
                _ => return Err(Status::IncorrectDataParameter),
            };
        let (fid, record) = self.key_file(reference)?;
        self.check_ef_access(&record, acl::OP_KEY_GENERATE)?;
        let kind = KeyKind::from_algorithm(algorithm)
            .filter(|_| algorithm & 0xF0 == 0)
            .ok_or(Status::IncorrectDataParameter)?;
        check_crts(&record, kind).map_err(|_| Status::IncorrectP1OrP2Parameter)?;

        let attributes = StorageAttributes::new().set_persistence(store::LOCATION);
        let key = syscall!(self
            .trussed
            .generate_key(kind.mechanism(), attributes.clone()))?
        .key;
        let public =
            match syscall!(self
                .trussed
                .derive_key(kind.mechanism(), key, None, attributes))
            {
                Ok(reply) => reply.key,
                Err(status) => {
                    syscall!(self.trussed.delete(key)).ok();
                    return Err(status);
                }
            };
        let stored = store::replace_key(
            &mut self.trussed,
            fid,
            Some(&KeyRecord {
                kind: kind.id(),
                key,
                public: Some(public),
            }),
        );
        if let Err(status) = stored {
            syscall!(self.trussed.delete(key)).ok();
            syscall!(self.trussed.delete(public)).ok();
            return Err(status);
        }
        self.forget_key_environments(fid);
        self.push_public_key(kind, public, reply)
    }

    pub(crate) fn import_key(
        &mut self,
        fid: u16,
        record: EfRecord,
        key_type: u8,
        value: &[u8],
    ) -> Result {
        let (kind, key, public) = match key_type {
            KEY_TYPE_RSA => self.import_rsa(&record, value)?,
            KEY_TYPE_ECC => self.import_ec(&record, value)?,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let stored = store::replace_key(
            &mut self.trussed,
            fid,
            Some(&KeyRecord {
                kind: kind.id(),
                key,
                public: Some(public),
            }),
        );
        if stored.is_err() {
            syscall!(self.trussed.delete(key)).ok();
            syscall!(self.trussed.delete(public)).ok();
        }
        stored
    }

    fn inject_checked(
        &mut self,
        kind: KeyKind,
        material: &[u8],
        format: KeySerialization,
        expected_public: &[&[u8]],
    ) -> Result<(KeyKind, KeyId, KeyId)> {
        let attributes = StorageAttributes::new().set_persistence(store::LOCATION);
        let key = syscall!(self.trussed.unsafe_inject_key(
            kind.mechanism(),
            material,
            store::LOCATION,
            format
        ))
        .map_err(|_| Status::IncorrectDataParameter)?
        .key;
        let public =
            match syscall!(self
                .trussed
                .derive_key(kind.mechanism(), key, None, attributes))
            {
                Ok(reply) => reply.key,
                Err(status) => {
                    syscall!(self.trussed.delete(key)).ok();
                    return Err(status);
                }
            };
        let consistent = self.public_matches(kind, public, expected_public);
        if !matches!(consistent, Ok(true)) {
            syscall!(self.trussed.delete(key)).ok();
            syscall!(self.trussed.delete(public)).ok();
            consistent?;
            return Err(Status::IncorrectDataParameter);
        }
        Ok((kind, key, public))
    }

    fn public_matches(&mut self, kind: KeyKind, public: KeyId, expected: &[&[u8]]) -> Result<bool> {
        if kind.is_rsa() {
            let serialized = syscall!(self.trussed.serialize_key(
                kind.mechanism(),
                public,
                KeySerialization::RsaParts
            ))?
            .serialized_key;
            let (n, rest) = take_varint_bytes(&serialized)
                .ok_or(Status::UnspecifiedNonpersistentExecutionError)?;
            let (e, _) =
                take_varint_bytes(rest).ok_or(Status::UnspecifiedNonpersistentExecutionError)?;
            Ok(unsigned(n) == expected[0] && unsigned(e) == expected[1])
        } else {
            let serialized = syscall!(self.trussed.serialize_key(
                kind.mechanism(),
                public,
                KeySerialization::Raw
            ))?
            .serialized_key;
            Ok(serialized.as_slice() == expected[0])
        }
    }

    fn import_rsa(&mut self, record: &EfRecord, value: &[u8]) -> Result<(KeyKind, KeyId, KeyId)> {
        let (sequence, rest) = take_der(value, 0x30)?;
        if !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let (version, rest) = take_der(sequence, 0x02)?;
        if version != [0x00] {
            return Err(Status::IncorrectDataParameter);
        }
        let (n, rest) = take_der(rest, 0x02)?;
        let (e, rest) = take_der(rest, 0x02)?;
        let (_d, rest) = take_der(rest, 0x02)?;
        let (p, rest) = take_der(rest, 0x02)?;
        let (q, _) = take_der(rest, 0x02)?;
        let (n, e, p, q) = (unsigned(n), unsigned(e), unsigned(p), unsigned(q));
        let kind = match n.len() {
            256 => KeyKind::Rsa2048,
            384 => KeyKind::Rsa3072,
            512 => KeyKind::Rsa4096,
            _ => return Err(Status::IncorrectDataParameter),
        };
        check_crts(record, kind)?;
        let mut material: Vec<u8, 1100> = Vec::new();
        push_postcard_bytes(&mut material, e)?;
        push_postcard_bytes(&mut material, p)?;
        push_postcard_bytes(&mut material, q)?;
        let result = self.inject_checked(kind, &material, KeySerialization::RsaParts, &[n, e]);
        material.iter_mut().for_each(|byte| *byte = 0);
        result
    }

    fn import_ec(&mut self, record: &EfRecord, value: &[u8]) -> Result<(KeyKind, KeyId, KeyId)> {
        let (sequence, rest) = take_der(value, 0x30)?;
        if !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let (version, rest) = take_der(sequence, 0x02)?;
        if version != [0x01] {
            return Err(Status::IncorrectDataParameter);
        }
        let (scalar, mut rest) = take_der(rest, 0x04)?;
        let mut point = None;
        while !rest.is_empty() {
            let (tag, field, next) = tlv::take_tlv(rest).ok_or(Status::IncorrectDataParameter)?;
            match tag {
                [0x04] => point = Some(field),
                [0xA0] => {}
                [0xA1] => match take_der(field, 0x03)? {
                    ([0x00, bits @ ..], []) => point = Some(bits),
                    _ => return Err(Status::IncorrectDataParameter),
                },
                _ => return Err(Status::IncorrectDataParameter),
            }
            rest = next;
        }
        let point = point.ok_or(Status::IncorrectDataParameter)?;
        let (kind, field_len) = match point {
            [0x04, coordinates @ ..] if coordinates.len() == 64 => (KeyKind::P256, 32),
            [0x04, coordinates @ ..] if coordinates.len() == 96 => (KeyKind::P384, 48),
            _ => return Err(Status::IncorrectDataParameter),
        };
        check_crts(record, kind)?;
        let scalar = unsigned(scalar);
        if scalar.len() > field_len {
            return Err(Status::IncorrectDataParameter);
        }
        let mut padded = [0u8; 48];
        padded[field_len - scalar.len()..field_len].copy_from_slice(scalar);
        let result = self.inject_checked(
            kind,
            &padded[..field_len],
            KeySerialization::Raw,
            &[&point[1..]],
        );
        padded.fill(0);
        result
    }

    pub(crate) fn get_public_key(&mut self, data: &[u8], reply: &mut VecView<u8>) -> Result {
        let (_, template, rest) = tlv::take_tlv(data).ok_or(Status::IncorrectDataParameter)?;
        if !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let reference = match find_field(template, 0x84)? {
            Some([reference]) => *reference,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let value = find_field(template, 0xA5)?.ok_or(Status::IncorrectDataParameter)?;
        if tlv::take_tag(value).map(|(tag, _)| tag) != Some(&[0x7F, 0x49][..]) {
            return Err(Status::IncorrectDataParameter);
        }
        let (fid, record) = self.key_file(reference)?;
        self.check_ef_access(&record, acl::OP_KEY_GET_PUBLIC)?;
        let (kind, key) = self.key_kind(fid)?;
        let public = key.public.ok_or(Status::KeyReferenceNotFound)?;
        self.push_public_key(kind, public, reply)
    }

    pub(crate) fn forget_key_environments(&mut self, fid: u16) {
        if self.dst.as_ref().is_some_and(|env| env.fid == fid) {
            self.dst = None;
        }
        if self.ct.as_ref().is_some_and(|env| env.fid == fid) {
            self.ct = None;
        }
    }

    pub(crate) fn set_key_environment(&mut self, apdu: CommandView<'_>) -> Result {
        let crt_tag = apdu.p2;
        match crt_tag {
            CRT_DST => self.dst = None,
            CRT_CT => self.ct = None,
            _ => return Err(Status::IncorrectP1OrP2Parameter),
        }
        if apdu.p1 & USAGE_COMPUTATION == 0 {
            return Err(Status::FunctionNotSupported);
        }
        let data = apdu.data();
        let reference = match (find_field(data, 0x84)?, find_field(data, 0x83)?) {
            (Some([reference]), None) | (None, Some([reference])) => *reference,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let algorithm = match find_field(data, 0x80)? {
            Some([algorithm]) => *algorithm,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let (fid, record) = self.key_file(reference)?;
        let crt = crts(&record)
            .find(|(tag, crt)| *tag == crt_tag && crt_byte(crt, 0x80) == Some(algorithm))
            .map(|(_, crt)| crt)
            .ok_or(Status::IncorrectDataParameter)?;
        if crt_byte(crt, 0x95).is_some_and(|usage| usage & USAGE_COMPUTATION == 0) {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let limit = usage_limit(crt);
        self.check_ef_access(&record, acl::OP_KEY_MSE)?;
        let pin_bound = self.enforced(&record)?
            && !acl::allowed(
                record.find(&[0x8C]),
                acl::OP_KEY_MSE,
                acl::SecurityStatus {
                    pin: false,
                    admin: self.security.admin,
                },
            );
        if !record.key_usable() {
            return Err(Status::KeyReferenceNotFound);
        }
        let (kind, key) = self.key_kind(fid)?;
        if KeyKind::from_algorithm(algorithm) != Some(kind) {
            return Err(Status::IncorrectDataParameter);
        }
        let environment = Some(KeyEnvironment {
            fid,
            algorithm,
            limit,
            uses: 0,
            pin_bound,
            kind,
            key: key.key,
            record,
        });
        match crt_tag {
            CRT_DST => self.dst = environment,
            _ => self.ct = environment,
        }
        Ok(())
    }

    fn check_environment(&mut self, signing: bool) -> Result<(u8, KeyKind, KeyId)> {
        if !self.state()?.is_operational() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let environment = if signing { &self.dst } else { &self.ct };
        let environment = environment
            .clone()
            .ok_or(Status::ConditionsOfUseNotSatisfied)?;
        self.check_ef_access(&environment.record, acl::OP_KEY_MSE)?;
        if environment.pin_bound && environment.limit != 0 && environment.uses >= environment.limit
        {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        Ok((environment.algorithm, environment.kind, environment.key))
    }

    pub(crate) fn perform_security_operation(
        &mut self,
        apdu: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result {
        let (result, environment) = match (apdu.p1, apdu.p2) {
            (0x9E, 0x9A) => (self.compute_signature(apdu.data(), reply), &mut self.dst),
            (0x80, 0x86) => (self.decipher(apdu.data(), reply), &mut self.ct),
            (0x86, 0x80) => return Err(Status::FunctionNotSupported),
            _ => return Err(Status::IncorrectP1OrP2Parameter),
        };
        if result.is_ok() {
            if let Some(environment) = environment {
                environment.uses = environment.uses.saturating_add(1);
            }
        }
        result
    }

    fn compute_signature(&mut self, data: &[u8], reply: &mut VecView<u8>) -> Result {
        let (algorithm, kind, key) = self.check_environment(true)?;
        let modulus_len = kind.modulus_len();
        let (mechanism, format) = match (kind.is_rsa(), algorithm & PADDING_MASK) {
            (true, PADDING_PKCS1) if data.len() <= modulus_len - 11 => {
                (kind.mechanism(), SignatureSerialization::Raw)
            }
            (true, PADDING_NONE) if data.len() == modulus_len => {
                (kind.raw_mechanism(), SignatureSerialization::Raw)
            }
            (false, PADDING_NONE) if (modulus_len / 2..=MAX_HASH_LEN).contains(&data.len()) => {
                (kind.raw_mechanism(), SignatureSerialization::Asn1Der)
            }
            _ => return Err(Status::IncorrectDataParameter),
        };
        let signature = syscall!(self.trussed.sign(mechanism, key, data, format))
            .map_err(|_| Status::IncorrectDataParameter)?
            .signature;
        tlv::extend(reply, &signature)
    }

    fn decipher(&mut self, data: &[u8], reply: &mut VecView<u8>) -> Result {
        let (algorithm, kind, key) = self.check_environment(false)?;
        if !kind.is_rsa() {
            return Err(Status::IncorrectDataParameter);
        }
        let data = match data {
            [PADDING_INDICATOR_NONE, cryptogram @ ..] if cryptogram.len() == kind.modulus_len() => {
                cryptogram
            }
            cryptogram if cryptogram.len() == kind.modulus_len() => cryptogram,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let padding = algorithm & PADDING_MASK;
        let mechanism = match padding {
            PADDING_PKCS1 => kind.mechanism(),
            PADDING_NONE | PADDING_OAEP => kind.raw_mechanism(),
            _ => return Err(Status::IncorrectDataParameter),
        };
        let mut plaintext = syscall!(self.trussed.decrypt(mechanism, key, data, &[], &[], &[]))
            .map_err(|_| Status::IncorrectDataParameter)?
            .plaintext
            .ok_or(Status::IncorrectDataParameter)?;
        if padding == PADDING_OAEP {
            let message = oaep_decode(&mut plaintext).ok_or(Status::IncorrectDataParameter)?;
            return tlv::extend(reply, message);
        }
        tlv::extend(reply, &plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_bytes() {
        let data = [0x03, 1, 2, 3, 0x81, 0x01, 9];
        let (first, rest) = take_varint_bytes(&data).unwrap();
        assert_eq!(first, [1, 2, 3]);
        assert!(take_varint_bytes(rest).is_none());
        let mut long = std::vec![0x80, 0x02];
        long.extend(core::iter::repeat_n(7u8, 256));
        assert_eq!(take_varint_bytes(&long).unwrap().0.len(), 256);
    }

    #[test]
    fn sha1_of_empty_label() {
        assert_eq!(Sha1::digest([]).as_slice(), SHA1_EMPTY);
    }

    extern crate std;
}
