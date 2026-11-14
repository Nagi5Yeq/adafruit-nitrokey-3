use apdu_app::CommandView;
use heapless::VecView;
use iso7816::Status;
use trussed_auth::{Pin, MAX_PIN_LENGTH};

use crate::{tlv, Client, Gids, Result};

const PIN_ID: u8 = 0;
pub const PIN_RETRIES: u8 = 3;
const MIN_PIN_LEN: usize = 4;
const MAX_GIDS_PIN_LEN: usize = 127;

const REF_GLOBAL_PIN: u8 = 0x00;
const REF_APPLICATION_PIN: u8 = 0x80;
const REF_PUK: u8 = 0x81;
const REF_RESET_SECURITY_STATUS: u8 = 0x82;
const TAG_GLOBAL_PIN_STATUS: &[u8] = &[0x7F, 0x71];
const TAG_LOCAL_PIN_STATUS: &[u8] = &[0x7F, 0x72];

fn pin_length_valid(len: usize) -> bool {
    (MIN_PIN_LEN..=MAX_GIDS_PIN_LEN.min(MAX_PIN_LENGTH)).contains(&len)
}

fn parse_pin(value: &[u8]) -> Option<Pin> {
    if !pin_length_valid(value.len()) {
        return None;
    }
    Pin::try_from(value).ok()
}

fn check_pin_reference(p2: u8) -> Result {
    match p2 {
        REF_GLOBAL_PIN | REF_APPLICATION_PIN => Ok(()),
        REF_PUK => Err(Status::KeyReferenceNotFound),
        _ => Err(Status::IncorrectP1OrP2Parameter),
    }
}

impl<T: Client> Gids<T> {
    fn has_pin(&mut self) -> Result<bool> {
        Ok(syscall!(self.trussed.has_pin(PIN_ID))?.has_pin)
    }

    fn retries(&mut self) -> Result<u8> {
        Ok(syscall!(self.trussed.pin_retries(PIN_ID))?
            .retries
            .unwrap_or(PIN_RETRIES))
    }

    pub(crate) fn pin_present(&mut self) -> Result<bool> {
        self.has_pin()
    }

    pub(crate) fn pin_blocked(&mut self) -> Result<bool> {
        Ok(self.has_pin()? && self.retries()? == 0)
    }

    fn failed_verification(&mut self) -> Status {
        self.security.pin = false;
        match self.retries() {
            Ok(left) => Status::RemainingRetries(left.min(0x0F)),
            Err(status) => status,
        }
    }

    fn check(&mut self, value: &[u8]) -> Result<bool> {
        let pin = parse_pin(value).unwrap_or_default();
        Ok(syscall!(self.trussed.check_pin(PIN_ID, pin))?.success)
    }

    fn pin_verified(&mut self, len: usize) -> Result {
        self.security.pin = true;
        self.reset_key_uses();
        let mut state = self.state()?;
        if usize::from(state.pin_len) != len || state.pending_pin_len != 0 {
            state.pin_len = len as u8;
            state.pending_pin_len = 0;
            self.set_state(state)?;
        }
        Ok(())
    }

    fn replace_pin(&mut self, pin: &[u8]) -> Result {
        let new = parse_pin(pin).ok_or(Status::IncorrectDataParameter)?;
        let mut state = self.state()?;
        state.pending_pin_len = pin.len() as u8;
        self.set_state(state)?;
        syscall!(self.trussed.set_pin(PIN_ID, new, Some(PIN_RETRIES), false))?;
        state.pin_len = pin.len() as u8;
        state.pending_pin_len = 0;
        self.set_state(state)
    }

    pub(crate) fn verify(&mut self, apdu: CommandView<'_>) -> Result {
        if apdu.p1 != 0x00 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        if apdu.p2 == REF_RESET_SECURITY_STATUS {
            self.reset_security();
            return Ok(());
        }
        check_pin_reference(apdu.p2)?;
        if self.state()?.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        if !self.has_pin()? {
            return Err(Status::KeyReferenceNotFound);
        }
        let retries = self.retries()?;
        if apdu.data().is_empty() {
            return if self.security.pin {
                Ok(())
            } else if retries == 0 {
                Err(Status::OperationBlocked)
            } else {
                Err(Status::RemainingRetries(retries.min(0x0F)))
            };
        }
        if retries == 0 {
            self.security.pin = false;
            return Err(Status::OperationBlocked);
        }
        if !pin_length_valid(apdu.data().len()) {
            self.security.pin = false;
            return Err(Status::RemainingRetries(retries.min(0x0F)));
        }
        if self.check(apdu.data())? {
            self.pin_verified(apdu.data().len())
        } else {
            Err(self.failed_verification())
        }
    }

    pub(crate) fn change_reference_data(&mut self, apdu: CommandView<'_>) -> Result {
        check_pin_reference(apdu.p2)?;
        let mut state = self.state()?;
        if state.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        match apdu.p1 {
            0x01 => {
                if state.is_operational() {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                self.replace_pin(apdu.data())?;
                self.security.pin = true;
                self.reset_key_uses();
                Ok(())
            }
            0x00 => {
                if !self.has_pin()? {
                    return Err(Status::KeyReferenceNotFound);
                }
                if self.retries()? == 0 {
                    self.security.pin = false;
                    return Err(Status::OperationBlocked);
                }
                let data = apdu.data();
                let mut candidates: heapless::Vec<usize, 2> = heapless::Vec::new();
                if state.pending_pin_len != 0 {
                    candidates.push(usize::from(state.pending_pin_len)).ok();
                }
                if !candidates.contains(&usize::from(state.pin_len)) {
                    candidates.push(usize::from(state.pin_len)).ok();
                }
                let mut attempted = false;
                for old_len in candidates {
                    if data.len() < old_len {
                        continue;
                    }
                    let (old, new) = data.split_at(old_len);
                    attempted = true;
                    let Some(new_pin) = parse_pin(new) else {
                        if self.check(old)? {
                            self.pin_verified(old_len)?;
                            return Err(Status::IncorrectDataParameter);
                        }
                        continue;
                    };
                    let old = parse_pin(old).unwrap_or_default();
                    state.pending_pin_len = new.len() as u8;
                    self.set_state(state)?;
                    let changed = syscall!(self.trussed.change_pin(PIN_ID, old, new_pin))?.success;
                    if changed {
                        state.pin_len = new.len() as u8;
                        state.pending_pin_len = 0;
                        self.set_state(state)?;
                        self.security.pin = true;
                        self.reset_key_uses();
                        return Ok(());
                    }
                    state.pending_pin_len = 0;
                    self.set_state(state)?;
                    if self.retries()? == 0 {
                        break;
                    }
                }
                if !attempted {
                    self.security.pin = false;
                    return Err(Status::RemainingRetries(self.retries()?.min(0x0F)));
                }
                Err(self.failed_verification())
            }
            _ => Err(Status::IncorrectP1OrP2Parameter),
        }
    }

    pub(crate) fn reset_retry_counter(&mut self, apdu: CommandView<'_>) -> Result {
        match (apdu.p1, apdu.p2) {
            (0x02, REF_GLOBAL_PIN | REF_APPLICATION_PIN) => {}
            (0x00, REF_GLOBAL_PIN | REF_APPLICATION_PIN) => {
                return Err(Status::KeyReferenceNotFound)
            }
            _ => return Err(Status::IncorrectP1OrP2Parameter),
        }
        if self.state()?.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        if !self.security.admin {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        if !self.has_pin()? {
            return Err(Status::KeyReferenceNotFound);
        }
        self.replace_pin(apdu.data())?;
        self.reset_security();
        Ok(())
    }

    pub(crate) fn pin_status(&mut self, tag: &[u8], reply: &mut VecView<u8>) -> Result {
        if !matches!(tag, TAG_GLOBAL_PIN_STATUS | TAG_LOCAL_PIN_STATUS) || !self.has_pin()? {
            return Err(Status::KeyReferenceNotFound);
        }
        let retries = self.retries()?;
        tlv::push_tlv(reply, tag, &[0x97, 0x01, retries, 0x93, 0x01, PIN_RETRIES])
    }
}
