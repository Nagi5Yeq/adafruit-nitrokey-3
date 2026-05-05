//! Board support for the Adafruit nRF52840 board.
//!
//! Key hardware differences vs NK3AM:
//!   - No SE050 secure element
//!   - No external SPI flash (EFS is RAM-backed)
//!   - Different GPIO pin assignments
//!   - No NFC

use boards::{
    flash::ExtFlashStorage,
    soc::nrf52::{flash::FlashStorage, rtic_monotonic::RtcMonotonic, Nrf52, UsbClockType},
    ui::{
        buttons::{Button, Press, UserPresence},
        rgb_led::{self, Color},
        UserInterface,
    },
    Board,
};
use littlefs2::{
    fs::Allocation,
    io::Result as LfsResult,
};
use nfc_device::traits::nfc::{Device as NfcDevice, Error as NfcError, State as NfcState};
use nrf52840_hal::{
    gpio::{p0, p1, Level, Output, Pin, PushPull},
    gpiote::Gpiote,
    pac::{self, PWM0, PWM1, PWM2},
    prelude::InputPin,
    pwm::{self, Pwm},
};
use nrf52840_pac::{FICR, GPIOTE, P0, P1, POWER};
use utils::RamStorage;

type OutPin = Pin<Output<PushPull>>;

// Adafruit NRF52840 memory layout (with Nordic MBR + Adafruit bootloader)
// MBR: 0x0000-0x1000, App: 0x1000-0xD8000, FS: 0xD8000-0xF4000, Bootloader: 0xF4000+
const FSI_BASE: usize = 0xD8_000;
const FSI_END: usize = 0xE4_000;
const FSE_BASE: usize = 0xE4_000;
const FSE_END: usize = 0xF4_000;

pub struct AdafruitNRF52840;

impl Board for AdafruitNRF52840 {
    type Soc = Nrf52;
    type Resources = UsbClockType;

    type NfcDevice = DummyNfc;
    type Buttons = HardwareButtons;
    type Led = RgbLed;

    type InternalStorage = InternalFlashStorage;
    type ExternalStorage = ExternalFlashStorage;

    // No SE050 on this board
    #[cfg(feature = "se050")]
    type Twi = ();
    #[cfg(feature = "se050")]
    type Se050Timer = ();
    #[cfg(not(feature = "se050"))]
    type Twi = ();
    #[cfg(not(feature = "se050"))]
    type Se050Timer = ();

    const BOARD_NAME: &'static str = "Adafruit-NRF52840";
    const HAS_NFC: bool = false;

    fn prepare_ifs(ifs: &mut Self::InternalStorage) {
        ifs.format_journal_blocks();
    }

    fn recover_ifs(
        ifs_storage: &mut Self::InternalStorage,
        _ifs_alloc: &mut Allocation<Self::InternalStorage>,
        _efs_storage: &mut Self::ExternalStorage,
    ) -> LfsResult<()> {
        // Format the filesystem — no migration from previous NK3AM firmware needed
        littlefs2::fs::Filesystem::format(ifs_storage)
    }
}

/// Internal flash storage using the NRF52840's NVMC peripheral.
/// Same firmware/filesystem split as NK3AM (same MCU, same 1 MB flash).
pub type InternalFlashStorage = FlashStorage<FSI_BASE, FSI_END>;

/// External flash storage — backed by a second region of NRF52840 internal flash.
/// No real SPI flash on this board, but we carve out a separate flash region
/// so apps that use Location::External still work.
pub type ExternalFlashStorage = FlashStorage<FSE_BASE, FSE_END>;

// Dummy SPI/Pin types to parameterise ExtFlashStorage for RamStorage.
// RamStorage never calls the underlying Storage's read/write/erase,
// it only uses the associated constants (BLOCK_SIZE, etc.).
pub struct DummySpi;
pub struct DummyPin;

impl embedded_hal::blocking::spi::Transfer<u8> for DummySpi {
    type Error = core::convert::Infallible;
    fn transfer<'w>(&mut self, _buf: &'w mut [u8]) -> Result<&'w [u8], Self::Error> {
        unreachable!("DummySpi should never be called")
    }
}

impl embedded_hal::digital::v2::OutputPin for DummyPin {
    type Error = core::convert::Infallible;
    fn set_low(&mut self) -> Result<(), Self::Error> {
        unreachable!("DummyPin should never be called")
    }
    fn set_high(&mut self) -> Result<(), Self::Error> {
        unreachable!("DummyPin should never be called")
    }
}

// ---------------------------------------------------------------------------
// Dummy NFC device (no NFC hardware)
// ---------------------------------------------------------------------------

pub struct DummyNfc;

impl NfcDevice for DummyNfc {
    fn read(&mut self, _buf: &mut [u8]) -> Result<NfcState, NfcError> {
        Err(NfcError::NoActivity)
    }
    fn send(&mut self, _buf: &[u8]) -> Result<(), NfcError> {
        Err(NfcError::NoActivity)
    }
    fn frame_size(&self) -> usize {
        0
    }
}

// ---------------------------------------------------------------------------
// User-presence buttons
// ---------------------------------------------------------------------------

pub struct HardwareButtons {
    touch_button: Option<OutPin>,
}

impl HardwareButtons {
    pub fn new(pin: OutPin) -> Self {
        Self {
            touch_button: Some(pin),
        }
    }
}

impl UserPresence for HardwareButtons {
    fn check_user_presence(&mut self) -> trussed::platform::consent::Level {
        if self.is_pressed(Button::A) {
            trussed::platform::consent::Level::Normal
        } else {
            trussed::platform::consent::Level::None
        }
    }
}

impl Press for HardwareButtons {
    fn is_pressed(&mut self, but: Button) -> bool {
        if but == Button::B || but == Button::Middle {
            return false;
        }
        // Capacitive-touch style sampling: drive high, switch to input,
        // check how quickly it goes low.
        let mut ticks = 0;
        let need_ticks = 100;
        if let Some(touch) = self.touch_button.take() {
            let floating = touch.into_floating_input();
            for idx in 0..need_ticks + 1 {
                match floating.is_low() {
                    Err(_) => {}
                    Ok(true) => {
                        ticks = idx;
                        break;
                    }
                    Ok(false) => {
                        if idx >= need_ticks {
                            ticks = idx;
                            break;
                        }
                    }
                }
            }
            self.touch_button = Some(floating.into_push_pull_output(Level::High));
        }
        ticks >= need_ticks
    }
}

// ---------------------------------------------------------------------------
// RGB LED
// ---------------------------------------------------------------------------

pub struct RgbLed {
    pwm_red: Pwm<pac::PWM0>,
    pwm_green: Pwm<pac::PWM1>,
    pwm_blue: Pwm<pac::PWM2>,
}

impl RgbLed {
    fn init_led<T: pwm::Instance>(led: OutPin, raw_pwm: T, channel: pwm::Channel) -> Pwm<T> {
        let pwm = Pwm::new(raw_pwm);
        pwm.set_output_pin(channel, led);
        pwm.set_max_duty(u8::MAX as u16);
        pwm
    }

    fn set_led(&mut self, color: Color, channel: pwm::Channel, intensity: u8) {
        let intensity: f32 = intensity as f32;
        match color {
            Color::Red => {
                self.pwm_red.set_duty_on(channel, (intensity / 4.0) as u16);
            }
            Color::Green => {
                self.pwm_green
                    .set_duty_on(channel, (intensity / 2.0) as u16);
            }
            Color::Blue => {
                self.pwm_blue.set_duty_on(channel, intensity as u16);
            }
        }
    }

    pub fn new(
        leds: [OutPin; 3],
        pwm_red: pac::PWM0,
        pwm_green: pac::PWM1,
        pwm_blue: pac::PWM2,
    ) -> Self {
        let [red, green, blue] = leds;
        Self {
            pwm_red: Self::init_led(red, pwm_red, pwm::Channel::C0),
            pwm_green: Self::init_led(green, pwm_green, pwm::Channel::C1),
            pwm_blue: Self::init_led(blue, pwm_blue, pwm::Channel::C2),
        }
    }
}

impl rgb_led::RgbLed for RgbLed {
    fn set_panic_led() {
        unsafe {
            let pac = nrf52840_pac::Peripherals::steal();
            let p0 = nrf52840_hal::gpio::p0::Parts::new(pac.P0);
            // Red LED on — set low (active-low assumption for external LED)
            p0.p0_06.into_push_pull_output(Level::Low).degrade();
        }
    }

    fn red(&mut self, intensity: u8) {
        self.set_led(Color::Red, pwm::Channel::C0, intensity);
    }
    fn green(&mut self, intensity: u8) {
        self.set_led(Color::Green, pwm::Channel::C1, intensity);
    }
    fn blue(&mut self, intensity: u8) {
        self.set_led(Color::Blue, pwm::Channel::C2, intensity);
    }
}

// ---------------------------------------------------------------------------
// GPIO / peripheral initialisation
// ---------------------------------------------------------------------------

pub struct BoardGPIO {
    pub gpiote: Gpiote,
    pub rgb_led: [OutPin; 3],
    pub touch: OutPin,
}

/// Initialise GPIO pins for the Adafruit nRF52840 board.
///
/// Pin mapping (adjust to your specific board revision):
///
/// | Function      | NRF pin | Notes           |
/// |---------------|---------|-----------------|
/// | User button   | P1.02   | USER / SW       |
/// | LED Red       | P0.06   | Onboard red LED |
/// | LED Green     | P1.09   | NeoPixel data   |
/// | LED Blue      | P0.12   | Blue LED        |
pub fn init_pins(gpiote: GPIOTE, p0: P0, p1: P1) -> BoardGPIO {
    let gpiote = Gpiote::new(gpiote);
    let gpio_p0 = p0::Parts::new(p0);
    let gpio_p1 = p1::Parts::new(p1);

    // User-presence input (push-pull high, same convention as NK3AM touch sensor)
    let touch = gpio_p1.p1_02.into_push_pull_output(Level::High).degrade();

    // RGB LED pins — active-low
    let led_r = gpio_p0.p0_06.into_push_pull_output(Level::Low).degrade();
    let led_g = gpio_p1.p1_09.into_push_pull_output(Level::Low).degrade();
    let led_b = gpio_p0.p0_12.into_push_pull_output(Level::Low).degrade();

    gpiote.reset_events();

    BoardGPIO {
        gpiote,
        rgb_led: [led_r, led_g, led_b],
        touch,
    }
}

/// Build the `UserInterface` for this board.
pub fn init_ui(
    leds: [OutPin; 3],
    pwm_red: PWM0,
    pwm_green: PWM1,
    pwm_blue: PWM2,
    touch: OutPin,
) -> UserInterface<RtcMonotonic, HardwareButtons, RgbLed> {
    let pac = unsafe { nrf52840_pac::Peripherals::steal() };
    let rtc_mono = RtcMonotonic::new(pac.RTC0);

    let rgb = RgbLed::new(leds, pwm_red, pwm_green, pwm_blue);
    let buttons = HardwareButtons::new(touch);

    UserInterface::new(rtc_mono, Some(buttons), Some(rgb))
}

/// Read the NRF52840 Encryption Root from FICR registers.
pub fn hw_key(ficr: &FICR) -> [u8; 16] {
    let mut er = [0; 16];
    for (i, r) in ficr.er.iter().enumerate() {
        let v = r.read().bits().to_be_bytes();
        for (j, w) in v.into_iter().enumerate() {
            er[i * 4 + j] = w;
        }
    }
    er
}

/// Handle USB POWER_CLOCK interrupt events.
pub fn power_handler(power: &mut POWER) {
    if power.events_usbdetected.read().events_usbdetected().bits() {
        power.events_usbdetected.write(|w| unsafe { w.bits(0) });
    }
    if power.events_usbpwrrdy.read().events_usbpwrrdy().bits() {
        power.events_usbpwrrdy.write(|w| unsafe { w.bits(0) });
    }
    if power.events_usbremoved.read().events_usbremoved().bits() {
        power.events_usbremoved.write(|w| unsafe { w.bits(0) });
    }
}
