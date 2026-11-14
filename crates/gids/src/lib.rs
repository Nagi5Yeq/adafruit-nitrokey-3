#![no_std]

#[macro_use]
mod syscall;

mod acl;
mod admin;
mod crypto;
mod data;
mod pin;
mod reset;
mod store;
mod tlv;

#[cfg(test)]
mod tests;

use apdu_app::{App as ApduApp, CommandView, Interface};
use heapless::{Vec, VecView};
use iso7816::{Aid, Instruction, Status};

use acl::SecurityStatus;
use store::{EfRecord, State};

pub type Result<T = ()> = core::result::Result<T, Status>;

pub trait Client:
    trussed_core::CryptoClient
    + trussed_core::FilesystemClient
    + trussed_core::UiClient
    + trussed_auth::AuthClient
    + trussed_chunked::ChunkedClient
{
}

impl<C> Client for C where
    C: trussed_core::CryptoClient
        + trussed_core::FilesystemClient
        + trussed_core::UiClient
        + trussed_auth::AuthClient
        + trussed_chunked::ChunkedClient
{
}

pub const GIDS_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x97, 0x42, 0x54, 0x46, 0x59, 0x02, 0x01,
];
const GIDS_RID_PIX_LEN: usize = 9;

const FID_CURRENT_EF: u16 = 0x0000;
const FID_EF_DIR: u16 = 0x2F00;
const FID_EF_ATR: u16 = 0x2F01;
const FID_MF: u16 = 0x3F00;
const FID_CURRENT_DF: u16 = 0x3FFF;
const FID_INVALID: u16 = 0xFFFF;

const FDB_DF: u8 = 0x38;
const FDB_DO_EF: u8 = 0x39;
const FDB_KEY_EF: u8 = 0x18;

const INS_MSE: u8 = 0x22;
const INS_PSO: u8 = 0x2A;
const INS_ACTIVATE_FILE: u8 = 0x44;
const INS_CREATE_FILE: u8 = 0xE0;
const INS_DELETE_FILE: u8 = 0xE4;
const INS_TERMINATE_DF: u8 = 0xE6;
const INS_RESET_APPLICATION: u8 = 0xFB;

const SUPPORTED_AUTH_PROTOCOLS: u8 = 0xC0;
const PIN_USAGE_POLICY: u8 = 0x60;
const DF_SECURITY_ATTRIBUTE: &[u8] = &[0x23, 0x20, 0x30, 0x30];

const OID_DES_EDE3_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_RSAES_OAEP: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07];
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

const MECHANISMS: &[(u8, &[&[u8]])] = &[
    (0x02, &[OID_DES_EDE3_CBC]),
    (0x07, &[OID_RSA_ENCRYPTION]),
    (0x08, &[OID_RSA_ENCRYPTION]),
    (0x09, &[OID_RSA_ENCRYPTION]),
    (0x0C, &[OID_EC_PUBLIC_KEY, OID_PRIME256V1]),
    (0x0D, &[OID_EC_PUBLIC_KEY, OID_SECP384R1]),
    (0x17, &[OID_RSA_ENCRYPTION]),
    (0x18, &[OID_RSA_ENCRYPTION]),
    (0x19, &[OID_RSA_ENCRYPTION]),
    (0x1C, &[OID_EC_PUBLIC_KEY, OID_PRIME256V1]),
    (0x1D, &[OID_EC_PUBLIC_KEY, OID_SECP384R1]),
    (0x47, &[OID_RSA_ENCRYPTION]),
    (0x48, &[OID_RSA_ENCRYPTION]),
    (0x49, &[OID_RSA_ENCRYPTION]),
    (0x57, &[OID_RSA_ENCRYPTION]),
    (0x58, &[OID_RSA_ENCRYPTION]),
    (0x59, &[OID_RSA_ENCRYPTION]),
    (0x87, &[OID_RSAES_OAEP, OID_SHA1]),
    (0x88, &[OID_RSAES_OAEP, OID_SHA1]),
    (0x89, &[OID_RSAES_OAEP, OID_SHA1]),
];

const EF_ATR: &[u8] = &[
    0x43, 0x01, 0xF4, 0x47, 0x03, 0x08, 0x01, 0xC0, 0x46, 0x08, b'N', b'i', b't', b'r', b'o', b'k',
    b'e', b'y',
];

#[derive(Clone, Copy, Default)]
enum Challenge {
    #[default]
    None,
    External([u8; 8]),
    Mutual {
        host: [u8; 16],
        card: [u8; 16],
    },
}

#[derive(Clone, Debug)]
struct KeyEnvironment {
    fid: u16,
    algorithm: u8,
    limit: u16,
    uses: u16,
    pin_bound: bool,
    kind: crypto::KeyKind,
    key: trussed_core::types::KeyId,
    record: EfRecord,
}

pub struct Gids<T> {
    trussed: T,
    state: Option<State>,
    selected_ef: Option<u16>,
    security: SecurityStatus,
    at_key: Option<u16>,
    dst: Option<KeyEnvironment>,
    ct: Option<KeyEnvironment>,
    challenge: Challenge,
}

impl<T: Client> Gids<T> {
    pub fn new(trussed: T) -> Self {
        Self {
            trussed,
            state: None,
            selected_ef: None,
            security: SecurityStatus::default(),
            at_key: None,
            dst: None,
            ct: None,
            challenge: Challenge::None,
        }
    }

    fn reset_key_uses(&mut self) {
        for environment in [&mut self.dst, &mut self.ct].into_iter().flatten() {
            environment.uses = 0;
        }
    }

    fn reset_security(&mut self) {
        self.security = SecurityStatus::default();
        self.at_key = None;
        self.dst = None;
        self.ct = None;
        self.challenge = Challenge::None;
    }

    fn state(&mut self) -> Result<State> {
        if let Some(state) = self.state {
            return Ok(state);
        }
        if store::reset_pending(&mut self.trussed)? {
            self.finish_reset()?;
            return Ok(State::default());
        }
        let state = store::load_state(&mut self.trussed)?;
        self.state = Some(state);
        Ok(state)
    }

    fn set_state(&mut self, state: State) -> Result {
        store::save_state(&mut self.trussed, &state)?;
        self.state = Some(state);
        Ok(())
    }

    fn enforced(&mut self, record: &EfRecord) -> Result<bool> {
        let state = self.state()?;
        Ok(state.is_terminated() || (state.is_operational() && record.is_operational()))
    }

    fn effective_security(&mut self) -> Result<SecurityStatus> {
        Ok(if self.state()?.is_terminated() {
            SecurityStatus::default()
        } else {
            self.security
        })
    }

    fn check_ef_access(&mut self, record: &EfRecord, operation: u8) -> Result {
        if !self.enforced(record)? {
            return Ok(());
        }
        let security = self.effective_security()?;
        if acl::allowed(record.find(&[0x8C]), operation, security) {
            Ok(())
        } else {
            Err(Status::SecurityStatusNotSatisfied)
        }
    }

    fn check_df_access(&mut self, operation: u8) -> Result {
        if !self.state()?.is_operational() {
            return Ok(());
        }
        if acl::allowed(Some(DF_SECURITY_ATTRIBUTE), operation, self.security) {
            Ok(())
        } else {
            Err(Status::SecurityStatusNotSatisfied)
        }
    }

    fn check_class(apdu: &CommandView<'_>) -> Result {
        let cla = apdu.class().into_inner();
        if cla & 0x0C != 0 {
            return Err(Status::SecureMessagingNotSupported);
        }
        if cla & 0x03 != 0 {
            return Err(Status::LogicalChannelNotSupported);
        }
        if cla & 0xE0 != 0 {
            return Err(Status::ClassNotSupported);
        }
        Ok(())
    }

    fn check_p1p2(apdu: &CommandView<'_>) -> Result {
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        Ok(())
    }

    fn check_select_p2(p2: u8) -> Result {
        if p2 & 0xF1 != 0 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        Ok(())
    }

    fn select_application(&mut self, apdu: CommandView<'_>, reply: &mut VecView<u8>) -> Result {
        Self::check_class(&apdu)?;
        Self::check_select_p2(apdu.p2)?;
        if apdu.p2 & 0x02 != 0 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        self.state = None;
        self.selected_ef = None;
        self.df_response(apdu.p2, reply)
    }

    fn select_file(&mut self, apdu: CommandView<'_>, reply: &mut VecView<u8>) -> Result {
        Self::check_select_p2(apdu.p2)?;
        if apdu.p1 != 0x00 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        if apdu.p2 & 0x02 != 0 {
            return self.select_next(apdu, reply);
        }
        let fid: [u8; 2] = apdu
            .data()
            .try_into()
            .map_err(|_| Status::NcInconsistentWithP1p2)?;
        let fid = match u16::from_be_bytes(fid) {
            FID_CURRENT_DF => {
                self.selected_ef = None;
                return self.df_response(apdu.p2, reply);
            }
            FID_CURRENT_EF => self.selected_ef.ok_or(Status::NotFound)?,
            fid => fid,
        };
        let record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::NotFound)?;
        self.selected_ef = Some(fid);
        Self::ef_response(apdu.p2, &record, reply)
    }

    fn ef_response(p2: u8, record: &EfRecord, reply: &mut VecView<u8>) -> Result {
        match p2 & 0x0C {
            0x00 | 0x04 => Self::ef_fcp(record, reply),
            0x08 => tlv::push_tlv(reply, &[0x64], &[]),
            _ => Ok(()),
        }
    }

    fn select_next(&mut self, apdu: CommandView<'_>, reply: &mut VecView<u8>) -> Result {
        match apdu.data() {
            [] | [0x3F, 0xFF] | [0x00, 0x00] => {}
            _ => return Err(Status::NcInconsistentWithP1p2),
        }
        let current = self.selected_ef;
        let mut next = None;
        store::for_each_name(&mut self.trussed, b"f", |_, name| {
            if let Some(fid) = store::parse_ef_name(name) {
                if current.is_none_or(|current| fid > current) {
                    next = Some(fid);
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        let fid = next.ok_or(Status::NotFound)?;
        let record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::NotFound)?;
        self.selected_ef = Some(fid);
        Self::ef_response(apdu.p2, &record, reply)
    }

    fn df_response(&mut self, p2: u8, reply: &mut VecView<u8>) -> Result {
        let state = self.state()?;
        if state.is_terminated() {
            return Err(Status::SelectedFileInTerminationState);
        }
        match p2 & 0x0C {
            0x00 => Self::application_template(reply),
            0x04 => Self::df_fcp(state.app_lcs, reply),
            0x08 => Self::df_fmd(reply),
            _ => Ok(()),
        }
    }

    fn application_template(reply: &mut VecView<u8>) -> Result {
        let mut inner: Vec<u8, 32> = Vec::new();
        tlv::push_tlv(inner.as_mut_view(), &[0x4F], GIDS_AID)?;
        tlv::push_tlv(
            inner.as_mut_view(),
            &[0x73],
            &[0x40, 0x01, SUPPORTED_AUTH_PROTOCOLS],
        )?;
        tlv::push_tlv(reply, &[0x61], &inner)
    }

    fn df_fcp(lcs: u8, reply: &mut VecView<u8>) -> Result {
        let mut inner: Vec<u8, 512> = Vec::new();
        tlv::push_tlv(inner.as_mut_view(), &[0x82], &[FDB_DF])?;
        tlv::push_tlv(inner.as_mut_view(), &[0x8A], &[lcs])?;
        tlv::push_tlv(inner.as_mut_view(), &[0x84], GIDS_AID)?;
        tlv::push_tlv(inner.as_mut_view(), &[0x8C], DF_SECURITY_ATTRIBUTE)?;
        for (reference, oids) in MECHANISMS {
            let mut template: Vec<u8, 32> = Vec::new();
            tlv::push_tlv(template.as_mut_view(), &[0x80], &[*reference])?;
            for oid in *oids {
                tlv::push_tlv(template.as_mut_view(), &[0x06], oid)?;
            }
            tlv::push_tlv(inner.as_mut_view(), &[0xAC], &template)?;
        }
        tlv::push_tlv(reply, &[0x62], &inner)
    }

    fn df_fmd(reply: &mut VecView<u8>) -> Result {
        let mut inner: Vec<u8, 16> = Vec::new();
        tlv::push_tlv(inner.as_mut_view(), &[0x5F, 0x2F], &[PIN_USAGE_POLICY])?;
        tlv::push_tlv(inner.as_mut_view(), &[0x7F, 0x65], &[0x80, 0x00])?;
        tlv::push_tlv(reply, &[0x64], &inner)
    }

    fn ef_fcp(record: &EfRecord, reply: &mut VecView<u8>) -> Result {
        let mut inner: Vec<u8, { store::MAX_FCP_LEN + 8 }> = Vec::new();
        let mut data = record.fcp.as_slice();
        while let Some((tag, value, rest)) = tlv::take_tlv(data) {
            tlv::push_tlv(inner.as_mut_view(), tag, value)?;
            if tag == [0x83] {
                tlv::push_tlv(inner.as_mut_view(), &[0x8A], &[record.lcs])?;
            }
            data = rest;
        }
        tlv::push_tlv(reply, &[0x62], &inner)
    }

    fn algorithm_supported(crt_tag: u8, algorithm: u8) -> bool {
        let size = algorithm & 0x0F;
        let scheme = algorithm & 0xF0;
        let rsa = matches!(size, 0x07..=0x09);
        let ec = matches!(size, 0x0C | 0x0D);
        match crt_tag {
            0xA4 => algorithm == 0x02,
            0xB6 => {
                (rsa && matches!(scheme, 0x00 | 0x10 | 0x40 | 0x50))
                    || (ec && matches!(scheme, 0x00 | 0x10))
            }
            0xB8 => rsa && matches!(scheme, 0x00 | 0x40 | 0x80),
            _ => false,
        }
    }

    fn validate_crts(fid: u16, crts: &[u8]) -> Result<bool> {
        let mut admin_capable = false;
        let mut symmetric = false;
        let mut key_size = None;
        let mut data = crts;
        if data.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        while !data.is_empty() {
            let (tag, crt, rest) = tlv::take_tlv(data).ok_or(Status::IncorrectDataParameter)?;
            if !matches!(tag, [0xA4] | [0xB6] | [0xB8]) {
                return Err(Status::IncorrectDataParameter);
            }
            let mut has_alg = false;
            let mut has_ref = false;
            let mut fields = crt;
            while !fields.is_empty() {
                let (field, value, rest) =
                    tlv::take_tlv(fields).ok_or(Status::IncorrectDataParameter)?;
                match (field, value) {
                    ([0x80], [algorithm]) => {
                        if !Self::algorithm_supported(tag[0], *algorithm) {
                            return Err(Status::IncorrectDataParameter);
                        }
                        if tag == [0xA4] {
                            symmetric = true;
                        } else if *key_size.get_or_insert(algorithm & 0x0F) != algorithm & 0x0F {
                            return Err(Status::IncorrectDataParameter);
                        }
                        has_alg = true;
                    }
                    ([0x83] | [0x84], [reference]) => {
                        if fid != 0xB000 | u16::from(*reference) {
                            return Err(Status::IncorrectDataParameter);
                        }
                        has_ref = true;
                    }
                    ([0x95], [usage]) => {
                        if tag == [0xA4] && usage & 0x80 != 0 {
                            admin_capable = true;
                        }
                    }
                    ([0xA3], _) => {}
                    _ => return Err(Status::IncorrectDataParameter),
                }
                fields = rest;
            }
            if !has_alg || !has_ref {
                return Err(Status::IncorrectDataParameter);
            }
            data = rest;
        }
        if symmetric && key_size.is_some() {
            return Err(Status::IncorrectDataParameter);
        }
        Ok(admin_capable)
    }

    fn create_file(&mut self, apdu: CommandView<'_>) -> Result {
        Self::check_p1p2(&apdu)?;
        let state = self.state()?;
        if state.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        if apdu.data().is_empty() {
            return Err(Status::WrongLength);
        }
        let (tag, fcp, rest) = tlv::take_tlv(apdu.data()).ok_or(Status::NcInconsistentWithTlv)?;
        if tag != [0x62] || !rest.is_empty() {
            return Err(Status::IncorrectDataParameter);
        }
        let mut descriptor = None;
        let mut fid = None;
        let mut has_acl = false;
        let mut crts = None;
        let mut data = fcp;
        while !data.is_empty() {
            let (tag, value, rest) = tlv::take_tlv(data).ok_or(Status::NcInconsistentWithTlv)?;
            match (tag, value) {
                ([0x82], [fdb]) => descriptor = Some(*fdb),
                ([0x83], [high, low]) => fid = Some(u16::from_be_bytes([*high, *low])),
                ([0x8C], attribute) if acl::validate(attribute) => has_acl = true,
                ([0xA5], value) => crts = Some(value),
                _ => return Err(Status::IncorrectDataParameter),
            }
            data = rest;
        }
        let fid = fid.ok_or(Status::IncorrectDataParameter)?;
        if !has_acl
            || matches!(
                fid,
                FID_CURRENT_EF | FID_EF_DIR | FID_EF_ATR | FID_MF | FID_CURRENT_DF | FID_INVALID
            )
        {
            return Err(Status::IncorrectDataParameter);
        }
        let admin_capable = match (descriptor, crts) {
            (Some(FDB_DO_EF), None) => false,
            (Some(FDB_KEY_EF), Some(crts)) => Self::validate_crts(fid, crts)?,
            _ => return Err(Status::IncorrectDataParameter),
        };
        if store::exists(&mut self.trussed, store::ef_path(fid))? {
            return Err(Status::FileAlreadyExists);
        }
        self.check_df_access(acl::OP_DF_CREATE_EF)?;
        if admin_capable && state.is_operational() && !self.security.admin {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        let record = EfRecord {
            lcs: store::LCS_INITIALIZATION,
            flags: if state.is_operational() {
                store::EF_FLAG_CREATED_OPERATIONAL
            } else {
                0
            },
            fcp: store::new_fcp(fcp)?,
        };
        store::save_ef(&mut self.trussed, fid, &record)?;
        self.selected_ef = Some(fid);
        Ok(())
    }

    fn activate_file(&mut self, apdu: CommandView<'_>) -> Result {
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        if !apdu.data().is_empty() {
            return Err(Status::WrongLength);
        }
        let mut state = self.state()?;
        if state.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        match self.selected_ef {
            None => {
                if !state.is_operational() {
                    state.app_lcs = store::LCS_OPERATIONAL;
                    self.set_state(state)?;
                }
                Ok(())
            }
            Some(fid) => {
                let mut record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::NotFound)?;
                if record.is_operational() {
                    return Ok(());
                }
                let usable =
                    !record.is_key_file() || store::load_key(&mut self.trussed, fid)?.is_some();
                record.activate(usable);
                self.forget_key_environments(fid);
                store::save_ef(&mut self.trussed, fid, &record)
            }
        }
    }

    fn delete_file(&mut self, apdu: CommandView<'_>) -> Result {
        Self::check_p1p2(&apdu)?;
        if !apdu.data().is_empty() {
            return Err(Status::WrongLength);
        }
        if self.state()?.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let fid = self.selected_ef.ok_or(Status::NotFound)?;
        self.check_df_access(acl::OP_DF_DELETE_CHILD)?;
        store::delete_key(&mut self.trussed, fid)?;
        let prefix = store::do_prefix(fid);
        loop {
            let mut found = None;
            store::for_each_do(&mut self.trussed, &prefix, |_, _, tag| {
                found = Vec::<u8, 3>::from_slice(tag).ok();
                Ok(false)
            })?;
            let Some(tag) = found else {
                break;
            };
            store::remove(&mut self.trussed, store::do_path(fid, &tag))?;
        }
        store::remove(&mut self.trussed, store::ef_path(fid))?;
        if self.at_key == Some(fid) {
            self.reset_security();
        }
        self.forget_key_environments(fid);
        self.selected_ef = None;
        Ok(())
    }

    fn terminate_df(&mut self, apdu: CommandView<'_>) -> Result {
        Self::check_p1p2(&apdu)?;
        if !apdu.data().is_empty() {
            return Err(Status::WrongLength);
        }
        let mut state = self.state()?;
        if !state.is_operational() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.check_df_access(acl::OP_DF_TERMINATE)?;
        state.app_lcs = store::LCS_TERMINATED;
        self.set_state(state)?;
        self.reset_security();
        Ok(())
    }
}

impl<T> iso7816::App for Gids<T> {
    fn aid(&self) -> Aid {
        Aid::new_truncatable(GIDS_AID, GIDS_RID_PIX_LEN)
    }
}

impl<T: Client> ApduApp for Gids<T> {
    fn select(
        &mut self,
        interface: Interface,
        apdu: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.select_application(apdu, reply)
    }

    fn deselect(&mut self) {
        self.reset_security();
        self.selected_ef = None;
    }

    fn call(
        &mut self,
        interface: Interface,
        apdu: CommandView<'_>,
        reply: &mut VecView<u8>,
    ) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        Self::check_class(&apdu)?;
        let instruction = apdu.instruction();
        if instruction != Instruction::GeneralAuthenticate {
            self.challenge = Challenge::None;
        }
        match instruction {
            Instruction::Select => self.select_file(apdu, reply),
            Instruction::GetData => self.get_data(apdu, reply),
            Instruction::PutData => self.put_data(apdu),
            Instruction::Verify => self.verify(apdu),
            Instruction::ChangeReferenceData => self.change_reference_data(apdu),
            Instruction::ResetRetryCounter => self.reset_retry_counter(apdu),
            Instruction::GeneralAuthenticate => self.general_authenticate(apdu, reply),
            Instruction::GenerateAsymmetricKeyPair => self.generate_key_pair(apdu, reply),
            Instruction::Unknown(INS_PSO) => self.perform_security_operation(apdu, reply),
            Instruction::Unknown(INS_MSE) => self.manage_security_environment(apdu),
            Instruction::Unknown(INS_CREATE_FILE) => self.create_file(apdu),
            Instruction::Unknown(INS_ACTIVATE_FILE) => self.activate_file(apdu),
            Instruction::Unknown(INS_DELETE_FILE) => self.delete_file(apdu),
            Instruction::Unknown(INS_TERMINATE_DF) => self.terminate_df(apdu),
            Instruction::Unknown(INS_RESET_APPLICATION) => self.reset_application(apdu),
            _ => Err(Status::InstructionNotSupportedOrInvalid),
        }
    }
}
