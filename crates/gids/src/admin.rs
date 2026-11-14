use apdu_app::CommandView;
use heapless::VecView;
use iso7816::Status;
use trussed_core::types::{KeyId, KeySerialization, Mechanism};

use crate::{
    acl,
    store::{self, EfRecord, KeyRecord},
    tlv, Challenge, Client, Gids, Result,
};

const KEY_TYPE_SYMMETRIC: u8 = 0x01;
const TRANSPORT_KEY_NONE: u8 = 0x00;
const ALG_TDES_3KEY: u8 = 0x02;
const TDES_KEY_LEN: usize = 24;
const BLOCK: usize = 8;
const CRT_AT: u8 = 0xA4;
const USAGE_EXTERNAL_AUTH: u8 = 0x80;
const MSE_SET: u8 = 0x01;
const EXTERNAL_CHALLENGE_LEN: usize = 8;
const MUTUAL_CHALLENGE_LEN: usize = 16;
const MUTUAL_SECRET_LEN: usize = 7;
const MUTUAL_CRYPTOGRAM_LEN: usize = 2 * MUTUAL_CHALLENGE_LEN + MUTUAL_SECRET_LEN + 1;

fn key_fid(reference: u8) -> u16 {
    0xB000 | u16::from(reference)
}

pub(crate) fn find_field<'a>(mut data: &'a [u8], wanted: u8) -> Result<Option<&'a [u8]>> {
    while !data.is_empty() {
        let (tag, value, rest) = tlv::take_tlv(data).ok_or(Status::IncorrectDataParameter)?;
        if tag == [wanted] {
            return Ok(Some(value));
        }
        data = rest;
    }
    Ok(None)
}

fn at_algorithm(record: &EfRecord, require_external: bool) -> Option<u8> {
    let mut crts = record.find(&[0xA5])?;
    while !crts.is_empty() {
        let (tag, crt, rest) = tlv::take_tlv(crts)?;
        if tag == [CRT_AT] {
            let usage = find_field(crt, 0x95).ok()?.and_then(|v| v.first().copied());
            let algorithm = find_field(crt, 0x80).ok()?.and_then(|v| v.first().copied());
            if !require_external || usage.is_some_and(|usage| usage & USAGE_EXTERNAL_AUTH != 0) {
                return algorithm;
            }
        }
        crts = rest;
    }
    None
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl<T: Client> Gids<T> {
    pub(crate) fn key_file(&mut self, reference: u8) -> Result<(u16, EfRecord)> {
        let fid = key_fid(reference);
        let record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::KeyReferenceNotFound)?;
        if !record.is_key_file() {
            return Err(Status::KeyReferenceNotFound);
        }
        Ok((fid, record))
    }

    pub(crate) fn put_key(&mut self, data: &[u8]) -> Result {
        let (tag, template, rest) = tlv::take_tlv(data).ok_or(Status::NcInconsistentWithTlv)?;
        if tag != [0x70] || !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let reference = match find_field(template, 0x84)? {
            Some([reference]) => *reference,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let value_template = find_field(template, 0xA5)?.ok_or(Status::IncorrectDataParameter)?;
        let (fid, record) = self.key_file(reference)?;
        self.check_ef_access(&record, acl::OP_KEY_PUT)?;

        if value_template.is_empty() {
            store::delete_key(&mut self.trussed, fid)?;
            return self.forget_at_key(fid);
        }

        let key_type = match find_field(value_template, 0x83)? {
            None => KEY_TYPE_SYMMETRIC,
            Some([key_type]) => *key_type,
            Some(_) => return Err(Status::IncorrectDataParameter),
        };
        match find_field(value_template, 0x84)? {
            None | Some([TRANSPORT_KEY_NONE]) => {}
            Some(_) => return Err(Status::FunctionNotSupported),
        }
        let value = find_field(value_template, 0x87)?.ok_or(Status::IncorrectDataParameter)?;
        let check_value = find_field(value_template, 0x88)?;

        if key_type != KEY_TYPE_SYMMETRIC {
            self.import_key(fid, record, key_type, value)?;
            return self.forget_at_key(fid);
        }
        if at_algorithm(&record, false) != Some(ALG_TDES_3KEY) || value.len() != TDES_KEY_LEN {
            return Err(Status::IncorrectDataParameter);
        }

        let key = syscall!(self.trussed.unsafe_inject_key(
            Mechanism::Tdes,
            value,
            store::LOCATION,
            KeySerialization::Raw
        ))?
        .key;
        if let Some(expected) = check_value {
            let block = self.tdes(key, &[0; BLOCK], true)?;
            if expected.is_empty()
                || expected.len() > BLOCK
                || !equal(expected, &block[..expected.len()])
            {
                syscall!(self.trussed.delete(key)).ok();
                return Err(Status::IncorrectDataParameter);
            }
        }
        let stored = store::replace_key(
            &mut self.trussed,
            fid,
            Some(&KeyRecord {
                kind: store::KEY_KIND_TDES,
                key,
                public: None,
            }),
        );
        if let Err(status) = stored {
            syscall!(self.trussed.delete(key)).ok();
            return Err(status);
        }
        self.forget_at_key(fid)
    }

    fn forget_at_key(&mut self, fid: u16) -> Result {
        self.forget_key_environments(fid);
        if self.at_key == Some(fid) {
            self.at_key = None;
            self.challenge = Challenge::None;
        }
        Ok(())
    }

    pub(crate) fn manage_security_environment(&mut self, apdu: CommandView<'_>) -> Result {
        if apdu.p1 & 0x0F != MSE_SET {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        let state = self.state()?;
        if state.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        if apdu.p2 != CRT_AT {
            return self.set_key_environment(apdu);
        }
        if apdu.p1 & 0x80 == 0 {
            return Err(Status::FunctionNotSupported);
        }
        let data = apdu.data();
        let reference = match (find_field(data, 0x83)?, find_field(data, 0x84)?) {
            (Some([reference]), None) | (None, Some([reference])) => *reference,
            _ => return Err(Status::IncorrectDataParameter),
        };
        let requested = match find_field(data, 0x80)? {
            None => None,
            Some([algorithm]) => Some(*algorithm),
            Some(_) => return Err(Status::IncorrectDataParameter),
        };
        self.at_key = None;
        self.challenge = Challenge::None;
        let (fid, record) = self.key_file(reference)?;
        let algorithm = at_algorithm(&record, true).ok_or(Status::ConditionsOfUseNotSatisfied)?;
        if requested.is_some_and(|requested| requested != algorithm) || algorithm != ALG_TDES_3KEY {
            return Err(Status::IncorrectDataParameter);
        }
        self.check_ef_access(&record, acl::OP_KEY_MSE)?;
        if !record.key_usable() || store::load_key(&mut self.trussed, fid)?.is_none() {
            return Err(Status::KeyReferenceNotFound);
        }
        self.at_key = Some(fid);
        Ok(())
    }

    fn tdes(&mut self, key: KeyId, block: &[u8], encrypt: bool) -> Result<[u8; BLOCK]> {
        let output = if encrypt {
            syscall!(self.trussed.encrypt(Mechanism::Tdes, key, block, &[], None))?.ciphertext
        } else {
            syscall!(self
                .trussed
                .decrypt(Mechanism::Tdes, key, block, &[], &[], &[]))?
            .plaintext
            .ok_or(Status::UnspecifiedNonpersistentExecutionError)?
        };
        output
            .as_slice()
            .try_into()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
    }

    fn cbc_encrypt(&mut self, key: KeyId, data: &mut [u8]) -> Result {
        let mut chain = [0u8; BLOCK];
        for block in data.chunks_mut(BLOCK) {
            for (byte, previous) in block.iter_mut().zip(chain) {
                *byte ^= previous;
            }
            chain = self.tdes(key, block, true)?;
            block.copy_from_slice(&chain);
        }
        Ok(())
    }

    fn cbc_decrypt(&mut self, key: KeyId, data: &mut [u8]) -> Result {
        let mut chain = [0u8; BLOCK];
        for block in data.chunks_mut(BLOCK) {
            let ciphertext: [u8; BLOCK] = (&*block).try_into().unwrap();
            let plaintext = self.tdes(key, block, false)?;
            for ((byte, plain), previous) in block.iter_mut().zip(plaintext).zip(chain) {
                *byte = plain ^ previous;
            }
            chain = ciphertext;
        }
        Ok(())
    }

    fn random<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = syscall!(self.trussed.random_bytes(N))?.bytes;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
    }

    pub(crate) fn general_authenticate(
        &mut self,
        apdu: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result {
        Self::check_p1p2(&apdu)?;
        let challenge = core::mem::take(&mut self.challenge);
        if !self.state()?.is_operational() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let fid = self.at_key.ok_or(Status::ConditionsOfUseNotSatisfied)?;
        let key = store::load_key(&mut self.trussed, fid)?
            .ok_or(Status::KeyReferenceNotFound)?
            .key;
        let (tag, template, rest) =
            tlv::take_tlv(apdu.data()).ok_or(Status::IncorrectDataParameter)?;
        if tag != [0x7C] || !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }

        if let Some(host) = find_field(template, 0x81)? {
            self.security.admin = false;
            return match host.len() {
                0 => {
                    let card = self.random::<EXTERNAL_CHALLENGE_LEN>()?;
                    self.challenge = Challenge::External(card);
                    Self::push_dynamic(reply, 0x81, &card)
                }
                MUTUAL_CHALLENGE_LEN => {
                    let card = self.random::<MUTUAL_CHALLENGE_LEN>()?;
                    self.challenge = Challenge::Mutual {
                        host: host.try_into().unwrap(),
                        card,
                    };
                    Self::push_dynamic(reply, 0x81, &card)
                }
                _ => Err(Status::IncorrectDataParameter),
            };
        }

        let response = find_field(template, 0x82)?.ok_or(Status::IncorrectDataParameter)?;
        match challenge {
            Challenge::None => Err(Status::ConditionsOfUseNotSatisfied),
            Challenge::External(card) => {
                if response.len() != EXTERNAL_CHALLENGE_LEN
                    || !equal(&self.tdes(key, &card, true)?, response)
                {
                    return Err(Status::SecurityStatusNotSatisfied);
                }
                self.security.admin = true;
                Ok(())
            }
            Challenge::Mutual { host, card } => {
                if response.len() != MUTUAL_CRYPTOGRAM_LEN {
                    return Err(Status::SecurityStatusNotSatisfied);
                }
                let mut plain = [0u8; MUTUAL_CRYPTOGRAM_LEN];
                plain.copy_from_slice(response);
                self.cbc_decrypt(key, &mut plain)?;
                let (card_echo, rest) = plain.split_at(MUTUAL_CHALLENGE_LEN);
                let (host_echo, rest) = rest.split_at(MUTUAL_CHALLENGE_LEN);
                if !equal(card_echo, &card)
                    || !equal(host_echo, &host)
                    || rest[MUTUAL_SECRET_LEN] != 0x80
                {
                    return Err(Status::SecurityStatusNotSatisfied);
                }
                let secret = self.random::<MUTUAL_SECRET_LEN>()?;
                let mut cryptogram = [0u8; MUTUAL_CRYPTOGRAM_LEN];
                cryptogram[..MUTUAL_CHALLENGE_LEN].copy_from_slice(&host);
                cryptogram[MUTUAL_CHALLENGE_LEN..2 * MUTUAL_CHALLENGE_LEN].copy_from_slice(&card);
                cryptogram[2 * MUTUAL_CHALLENGE_LEN..MUTUAL_CRYPTOGRAM_LEN - 1]
                    .copy_from_slice(&secret);
                cryptogram[MUTUAL_CRYPTOGRAM_LEN - 1] = 0x80;
                self.cbc_encrypt(key, &mut cryptogram)?;
                self.security.admin = true;
                Self::push_dynamic(reply, 0x82, &cryptogram)
            }
        }
    }

    fn push_dynamic(reply: &mut VecView<u8>, tag: u8, value: &[u8]) -> Result {
        let mut inner: heapless::Vec<u8, 48> = heapless::Vec::new();
        tlv::push_tlv(inner.as_mut_view(), &[tag], value)?;
        tlv::push_tlv(reply, &[0x7C], &inner)
    }
}
