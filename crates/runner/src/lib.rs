//! Platform-agnostic runner for the NK3 firmware.
//!
//! This crate provides the glue between the vendor `apps` crate (which defines
//! the NK3 application logic) and a platform-specific HAL. It contains no
//! MCU-specific code and no framework (RTIC/Embassy) code.

#![cfg_attr(not(test), no_std)]
#![warn(trivial_casts, unused, unused_qualifications)]

delog::generate_macros!();

pub mod init;
pub mod runtime;
pub mod store;
pub mod ui;

use core::marker::PhantomData;

use apps::{Dispatch, Model};
use littlefs2::{driver::Storage, fs::Filesystem, io::Result as LfsResult};
use nfc_device::traits::nfc::Device as NfcDevice;
use rand_chacha::ChaCha8Rng;
use trussed::platform::{Platform, Syscall};

use crate::{
    store::RunnerStore,
    ui::{buttons::UserPresence, rgb_led::RgbLed, Clock, UserInterface},
};

// Re-export for convenience
pub use apps;
pub use trussed;

pub const WATCHDOG_DURATION_SECONDS: u64 = 15 * 60;

// ---------------------------------------------------------------------------
// Soc trait — must be implemented by platform HAL (e.g. hal-nrf52)
// No MCU-specific types here — all platform details behind associated types.
// ---------------------------------------------------------------------------

pub type Uuid = [u8; 16];

pub trait Soc: 'static {
    type UsbBus: usb_device::bus::UsbBus + 'static;
    type Clock: Clock;
    type Duration: From<embedded_time::duration::Milliseconds>;
    type Syscall: Syscall + Clone + Default + 'static;

    const SOC_NAME: &'static str;
    const VARIANT: apps::Variant;

    fn uuid(&self) -> &Uuid;

    fn reboot() -> !;

    fn reboot_to_firmware_update();

    fn locked() -> bool;
}

// ---------------------------------------------------------------------------
// Board trait — must be implemented by board-specific code (e.g. board.rs)
// ---------------------------------------------------------------------------

pub trait Board {
    type Soc: Soc;
    type Resources;
    type NfcDevice: NfcDevice;
    type Buttons: UserPresence;
    type Led: RgbLed;
    type PersistentStorage: Storage + 'static;

    const BOARD_NAME: &'static str;
    const MODEL: Model;
    const HAS_NFC: bool;

    fn soc(&self) -> &Self::Soc;

    fn revision(&self) -> u8 {
        1
    }

    fn prepare_storage(storage: &mut Self::PersistentStorage) {
        let _ = storage;
    }

    fn recover_storage(storage: &mut Self::PersistentStorage) -> LfsResult<()> {
        Filesystem::format(storage)
    }
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

pub type Trussed<B> =
    trussed::Service<RunnerPlatform<B>, Dispatch>;
pub type Apps<B> = apps::Apps<Runner<B>>;

// ---------------------------------------------------------------------------
// Runner — implements apps::Runner
// ---------------------------------------------------------------------------

pub struct Runner<B> {
    pub uuid: Uuid,
    pub is_efs_available: bool,
    pub is_nfc_powered: bool,
    pub _marker: PhantomData<B>,
}

impl<B: Board> apps::Runner for Runner<B> {
    type Syscall = <B::Soc as Soc>::Syscall;
    type Store = RunnerStore<B>;
    type Twi = ();
    type Se050Timer = ();

    fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    fn is_efs_available(&self) -> bool {
        self.is_efs_available
    }

    fn is_nfc_powered(&self) -> bool {
        self.is_nfc_powered
    }
}

// ---------------------------------------------------------------------------
// RunnerPlatform — implements trussed::Platform
// ---------------------------------------------------------------------------

pub struct RunnerPlatform<B: Board> {
    pub rng: ChaCha8Rng,
    pub store: RunnerStore<B>,
    pub user_interface: UserInterface<<B::Soc as Soc>::Clock, B::Buttons, B::Led>,
}

impl<B: Board> Platform for RunnerPlatform<B> {
    type R = ChaCha8Rng;
    type S = RunnerStore<B>;
    type UI = UserInterface<<B::Soc as Soc>::Clock, B::Buttons, B::Led>;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.user_interface
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        self.store
    }
}

// ---------------------------------------------------------------------------
// Panic handler helper
// ---------------------------------------------------------------------------

pub fn handle_panic<B: Board>(_info: &core::panic::PanicInfo) -> ! {
    error_now!("{}", _info);
    B::Led::set_panic_led();
    loop {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
