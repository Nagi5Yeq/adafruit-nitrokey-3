use apdu_app::CommandView;
use iso7816::Status;
use trussed_core::types::{Location, PathBuf};

use crate::{
    store::{self, State},
    Client, Gids, Result,
};

const USER_PRESENCE_TIMEOUT_MS: u32 = 15_000;

impl<T: Client> Gids<T> {
    pub(crate) fn reset_application(&mut self, apdu: CommandView<'_>) -> Result {
        if apdu.p1 != 0 || apdu.p2 != 0 {
            return Err(Status::IncorrectP1OrP2Parameter);
        }
        if !apdu.data().is_empty() {
            return Err(Status::WrongLength);
        }
        if !self.reset_allowed()? {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        let consent = syscall!(self.trussed.confirm_user_present(USER_PRESENCE_TIMEOUT_MS))?;
        if consent.result.is_err() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        store::begin_reset(&mut self.trussed)?;
        self.finish_reset()
    }

    fn reset_allowed(&mut self) -> Result<bool> {
        let state = self.state()?;
        if self.security.admin || state.is_terminated() || !state.is_operational() {
            return Ok(true);
        }
        self.pin_blocked()
    }

    pub(crate) fn finish_reset(&mut self) -> Result {
        if syscall!(self.trussed.reset_auth_data()).is_err() && self.pin_present()? {
            return Err(Status::UnspecifiedPersistentExecutionError);
        }
        store::delete_recorded_keys(&mut self.trussed)?;
        for location in [Location::Internal, Location::External, Location::Volatile] {
            syscall!(self.trussed.delete_all(location)).ok();
        }
        for location in [Location::Internal, Location::Volatile] {
            syscall!(self.trussed.remove_dir_all(location, PathBuf::new())).ok();
        }
        syscall!(self.trussed.remove_dir_all(store::LOCATION, PathBuf::new()))?;
        self.reset_security();
        self.selected_ef = None;
        self.state = Some(State::default());
        Ok(())
    }
}
