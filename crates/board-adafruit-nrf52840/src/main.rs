//! Firmware entry-point for the Adafruit nRF52840 board.
//!
//! Full NK3 app suite (FIDO2, OpenPGP, PIV, Secrets, NDEF, Admin) running
//! on the Adafruit board with two hardware differences vs NK3AM:
//!
//!   1. No SE050 — all crypto falls back to software backends.
//!   2. No external SPI flash — EFS is the `/external` directory of the internal filesystem.

#![no_std]
#![no_main]

#[cfg(feature = "alloc")]
extern crate embedded_alloc;

delog::generate_macros!();

mod board;
mod flash;
mod monotonic;
mod soc;

use cortex_m_rt::{exception, ExceptionFrame};
use utils::Version;

pub const VERSION: Version = Version::from_str(env!("CARGO_PKG_VERSION"));
pub const VERSION_STRING: &str = env!("NK3_FIRMWARE_VERSION");

#[cfg(feature = "alloc")]
#[global_allocator]
static ALLOCATOR: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();

#[cfg(feature = "alloc")]
pub fn init_alloc() {
    use core::mem::MaybeUninit;
    const HEAP_SIZE: usize = 32 * 1024;
    static mut HEAP: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { ALLOCATOR.init(&raw mut HEAP as usize, HEAP_SIZE) }
}

static FLUSHER: runner::init::DelogFlusher = runner::init::DelogFlusher {
    flush_fn: |_msg| {
        #[cfg(feature = "log-rtt")]
        rtt_target::rprint!(_msg);
    },
};

#[rtic::app(device = nrf52840_hal::pac, peripherals = true, dispatchers = [SWI3_EGU3, SWI4_EGU4, SWI5_EGU5])]
mod app {
    use apdu_dispatch::{dispatch::ApduDispatch, interchanges::Channel as CcidChannel};
    use apps::Endpoints;
    use interchange::Channel;
    use nrf52840_hal::{
        gpiote::Gpiote,
        rng::Rng,
        wdt::{self, handles::Hdl0, WatchdogHandle},
    };
    use runner::{
        init::{CtaphidDispatch, Resources, UsbClasses},
        runtime, store, Apps, Soc as _, Trussed,
    };

    use crate::{
        board::{self, AdafruitNRF52840, PersistentFlashStorage},
        monotonic::RtcDuration,
        soc::{self, Nrf52},
    };

    type Board = AdafruitNRF52840;
    type Soc = <Board as runner::Board>::Soc;

    #[shared]
    struct SharedResources {
        trussed: Trussed<Board>,
        apps: Apps<Board>,
        apdu_dispatch: ApduDispatch<'static>,
        ctaphid_dispatch: CtaphidDispatch<'static, 'static>,
        usb_classes: Option<UsbClasses<Soc>>,
    }

    #[local]
    struct LocalResources {
        gpiote: Gpiote,
        power: nrf52840_pac::POWER,
        watchdog_parts: Option<wdt::Parts<WatchdogHandle<Hdl0>>>,
        endpoints: Endpoints,
    }

    #[monotonic(binds = RTC0, default = true)]
    type RtcMonotonic = crate::monotonic::RtcMonotonic;

    #[init(local = [resources: Resources<Board> = Resources::new()])]
    fn init(mut ctx: init::Context) -> (SharedResources, LocalResources, init::Monotonics) {
        let mut init_status = apps::InitStatus::default();

        #[cfg(feature = "alloc")]
        crate::init_alloc();

        ctx.core.DCB.enable_trace();
        ctx.core.DWT.enable_cycle_counter();

        #[cfg(feature = "log-rtt")]
        rtt_target::rtt_init_print!();

        runner::init::init_logger::<Board>(&crate::FLUSHER, crate::VERSION_STRING);

        let reset_reason = soc::reset_reason(&ctx.device.POWER.resetreas);
        debug_now!("Reset Reason: {reset_reason:?}");

        if reset_reason.dog && !reset_reason.sreq {
            Nrf52::reboot_to_firmware_update();
        }

        let soc = soc::init_bootup(&ctx.device.FICR, &ctx.device.UICR);
        let board = AdafruitNRF52840::new(soc);

        let wdt_parts = soc::init_watchdog(ctx.device.WDT);

        let board_gpio = board::init_pins(ctx.device.GPIOTE, ctx.device.P0, ctx.device.P1);

        let usb_bus = soc::setup_usb_bus(
            &mut ctx.local.resources.board,
            ctx.device.CLOCK,
            ctx.device.USBD,
        );

        let persistent_flash = PersistentFlashStorage::new(ctx.device.NVMC);
        let store = store::init_store(
            &mut ctx.local.resources.store,
            persistent_flash,
            &mut init_status,
        );

        static NFC_CHANNEL: CcidChannel = Channel::new();
        let (_nfc_rq, nfc_rp) = NFC_CHANNEL.split().unwrap();
        let usb_nfc = runner::init::init_usb_nfc(
            &mut ctx.local.resources.usb,
            || {},
            Some(usb_bus),
            None, // no NFC hardware
            nfc_rp,
            "Nitrokey 3",     // USB product string
            0x42B2,           // USB product ID
            crate::VERSION,
        );

        let user_interface = board::init_ui(
            board_gpio.neopixel,
            board_gpio.neopixel_power,
            board_gpio.red_led,
            board_gpio.blue_led,
            board_gpio.button,
        );

        let mut dev_rng = Rng::new(ctx.device.RNG);
        let hw_key = board::hw_key(&ctx.device.FICR);
        let mut trussed = runner::init::init_trussed(
            &mut dev_rng,
            store,
            user_interface,
            Some(&hw_key),
        );

        let (apps, endpoints) = runner::init::init_apps(
            &board,
            &mut trussed,
            init_status,
            &store,
            false, // nfc_powered
            crate::VERSION,
            crate::VERSION_STRING,
        );

        let rtc_mono = RtcMonotonic::new(ctx.device.RTC0);

        ui::spawn_after(RtcDuration::from_ms(2500)).ok();

        (
            SharedResources {
                trussed,
                apps,
                apdu_dispatch: usb_nfc.apdu_dispatch,
                ctaphid_dispatch: usb_nfc.ctaphid_dispatch,
                usb_classes: usb_nfc.usb_classes,
            },
            LocalResources {
                gpiote: board_gpio.gpiote,
                power: ctx.device.POWER,
                watchdog_parts: wdt_parts.ok().map(|parts| wdt::Parts {
                    watchdog: parts.watchdog,
                    handles: parts.handles.0,
                }),
                endpoints,
            },
            init::Monotonics(rtc_mono),
        )
    }

    // -------------------------------------------------------------------------
    // Tasks
    // -------------------------------------------------------------------------

    #[idle(shared = [apps, apdu_dispatch, ctaphid_dispatch, usb_classes], local = [watchdog_parts])]
    fn idle(ctx: idle::Context) -> ! {
        let idle::SharedResources {
            mut apps,
            mut apdu_dispatch,
            mut ctaphid_dispatch,
            mut usb_classes,
        } = ctx.shared;

        trace!("idle");

        loop {
            if let Some(ref mut parts) = ctx.local.watchdog_parts {
                parts.handles.pet();
            }

            #[cfg(not(feature = "no-delog"))]
            runner::init::Delogger::flush();

            let (usb_activity, _nfc_activity) =
                (&mut apps, &mut apdu_dispatch, &mut ctaphid_dispatch)
                    .lock(|apps, apdu, ctaphid| runtime::poll_dispatchers(apdu, ctaphid, apps));
            if usb_activity {
                rtic::pend(nrf52840_pac::Interrupt::USBD);
            }

            usb_classes.lock(|usb_classes| {
                runtime::poll_usb(
                    usb_classes,
                    ccid_keepalive::spawn_after,
                    ctaphid_keepalive::spawn_after,
                    monotonics::now().into(),
                );
            });
        }
    }

    #[task(priority = 2, binds = SWI0_EGU0, shared = [trussed], local = [endpoints])]
    fn task_trussed(ctx: task_trussed::Context) {
        let mut trussed = ctx.shared.trussed;
        trussed.lock(|trussed| {
            runtime::run_trussed(trussed, ctx.local.endpoints);
        });
    }

    #[task(priority = 5, binds = GPIOTE, local = [gpiote])]
    fn task_button_irq(_ctx: task_button_irq::Context) {
        trace!("irq GPIOTE");
    }

    #[task(priority = 3, binds = USBD, shared = [usb_classes])]
    fn task_usb(ctx: task_usb::Context) {
        let mut usb_classes = ctx.shared.usb_classes;
        usb_classes.lock(|usb_classes| {
            runtime::poll_usb(
                usb_classes,
                ccid_keepalive::spawn_after,
                ctaphid_keepalive::spawn_after,
                monotonics::now().into(),
            );
        });
    }

    #[task(priority = 3, shared = [usb_classes])]
    fn ccid_keepalive(ctx: ccid_keepalive::Context) {
        let mut usb_classes = ctx.shared.usb_classes;
        usb_classes.lock(|usb_classes| {
            runtime::ccid_keepalive(usb_classes, ccid_keepalive::spawn_after);
        });
    }

    #[task(priority = 3, shared = [usb_classes])]
    fn ctaphid_keepalive(ctx: ctaphid_keepalive::Context) {
        let mut usb_classes = ctx.shared.usb_classes;
        usb_classes.lock(|usb_classes| {
            runtime::ctaphid_keepalive(usb_classes, ctaphid_keepalive::spawn_after);
        });
    }

    #[task(priority = 5, binds = POWER_CLOCK, local = [power])]
    fn power_handler(ctx: power_handler::Context) {
        board::power_handler(ctx.local.power);
    }

    #[task(priority = 1, shared = [trussed])]
    fn ui(ctx: ui::Context) {
        let mut trussed = ctx.shared.trussed;
        trussed.lock(|trussed| {
            trussed.update_ui();
        });
        ui::spawn_after(RtcDuration::from_ms(125)).ok();
    }

    #[task(priority = 6, binds = WDT)]
    fn wdt_handler(_ctx: wdt_handler::Context) {
        #[no_mangle]
        fn wdt_handler_inner() {
            error_now!("Reached interrupt");
        }
        wdt_handler_inner();
    }
}

#[inline(never)]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    runner::handle_panic::<board::AdafruitNRF52840>(info)
}

#[exception]
unsafe fn HardFault(_ef: &ExceptionFrame) -> ! {
    use runner::ui::rgb_led::RgbLed;
    board::AdafruitLed::set_panic_led();
    loop {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
