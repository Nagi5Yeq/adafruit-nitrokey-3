//! Board support for the Adafruit nRF52840 Feather Express.
//!
//! Key hardware differences vs NK3AM:
//!   - No SE050 secure element
//!   - No external SPI flash (EFS is the `/external` directory of the internal filesystem)
//!   - Different GPIO pin assignments
//!   - No NFC
//!   - NeoPixel (WS2812B) RGB LED on P0.16 instead of 3x PWM LEDs
//!   - Mechanical push button on P1.02 instead of capacitive touch

use littlefs2::io::Result as LfsResult;
use nfc_device::traits::nfc::{Device as NfcDevice, Error as NfcError, State as NfcState};
use nrf52840_hal::{
    gpio::{p0, p1, Input, Level, Output, Pin, PullUp, PushPull},
    gpiote::Gpiote,
    pac,
};
use embedded_hal::digital::v2::InputPin;
use nrf52840_pac::{FICR, GPIOTE, P0, P1, POWER};
use adafruit_memory_layout::{FS_BASE, FS_END};
use apps::Model;
use runner::{
    ui::{
        buttons::{Button, Press, UserPresence},
        rgb_led,
        UserInterface,
    },
    Board,
};

use crate::{
    flash::FlashStorage,
    monotonic::RtcMonotonic,
    soc::{Nrf52, UsbClockType},
};

type OutPin = Pin<Output<PushPull>>;
type BtnPin = Pin<Input<PullUp>>;

pub struct AdafruitNRF52840 {
    nrf52: Nrf52,
}

impl AdafruitNRF52840 {
    pub fn new(nrf52: Nrf52) -> Self {
        Self { nrf52 }
    }
}

impl Board for AdafruitNRF52840 {
    type Soc = Nrf52;
    type Resources = UsbClockType;

    type NfcDevice = DummyNfc;
    type Buttons = HardwareButtons;
    type Led = AdafruitLed;

    type PersistentStorage = PersistentFlashStorage;

    const BOARD_NAME: &'static str = "Adafruit-NRF52840";
    const MODEL: Model = Model::NK3;
    const HAS_NFC: bool = false;

    fn soc(&self) -> &Self::Soc {
        &self.nrf52
    }

    fn prepare_storage(storage: &mut Self::PersistentStorage) {
        storage.format_journal_blocks();
    }

    fn recover_storage(storage: &mut Self::PersistentStorage) -> LfsResult<()> {
        littlefs2::fs::Filesystem::format(storage)
    }
}

pub type PersistentFlashStorage = FlashStorage<FS_BASE, FS_END>;

// ---------------------------------------------------------------------------
// Dummy NFC device
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
// User-presence button — mechanical push button, active-low with pullup
// ---------------------------------------------------------------------------

pub struct HardwareButtons {
    button: BtnPin,
}

impl HardwareButtons {
    pub fn new(pin: BtnPin) -> Self {
        Self { button: pin }
    }
}

impl UserPresence for HardwareButtons {
    fn check_user_presence(&mut self) -> trussed_core::types::consent::Level {
        if self.is_pressed(Button::A) {
            trussed_core::types::consent::Level::Normal
        } else {
            trussed_core::types::consent::Level::None
        }
    }
}

impl Press for HardwareButtons {
    fn is_pressed(&mut self, but: Button) -> bool {
        if but == Button::B || but == Button::Middle {
            return false;
        }
        // Mechanical button: active-low, pulled up. Pressed = low.
        self.button.is_low().unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// NeoPixel (WS2812B) RGB LED
//   Data: P0.16, Power: P1.14
//   Uses PWM1 with DMA sequence (same approach as Adafruit bootloader)
//   16MHz clock, CTOPVAL=20 → 1.25us period → 800kHz WS2812B protocol
//   Bit 15 of duty = inverted polarity → HIGH for duty cycles
// ---------------------------------------------------------------------------

const T0H: u16 = 6 | 0x8000;
const T1H: u16 = 13 | 0x8000;
const CTOPVAL: u16 = 20;

// DMA buffer: 24 GRB bits + 2 zero padding. Must be static for DMA access.
static mut PIXEL_PATTERN: [u16; 26] = [0u16; 26];

pub struct AdafruitLed {
    red_led: OutPin,   // P1.15, active-high
    blue_led: OutPin,  // P1.10, active-high
}

impl AdafruitLed {
    pub fn new(neopixel_pin: OutPin, power_pin: OutPin, red_led: OutPin, blue_led: OutPin) -> Self {
        // power_pin (P1.14) is already configured as push-pull HIGH → NeoPixel powered
        let _ = power_pin;

        neopixel_init(neopixel_pin.pin() as u32);

        Self { red_led, blue_led }
    }
}

fn neopixel_init(data_pin: u32) {
    let pwm = unsafe { &*pac::PWM1::ptr() };

    pwm.enable.write(|w| w.enable().disabled());

    // Connect neopixel data pin to PWM1 ch0, disconnect others
    pwm.psel.out[0].write(|w| unsafe { w.bits(data_pin) });
    pwm.psel.out[1].write(|w| unsafe { w.bits(0xFFFFFFFF) });
    pwm.psel.out[2].write(|w| unsafe { w.bits(0xFFFFFFFF) });
    pwm.psel.out[3].write(|w| unsafe { w.bits(0xFFFFFFFF) });

    pwm.mode.write(|w| w.updown().up());
    pwm.prescaler.write(|w| w.prescaler().div_1()); // 16MHz
    pwm.countertop.write(|w| unsafe { w.countertop().bits(CTOPVAL) });
    pwm.decoder.write(|w| { w.load().common(); w.mode().refresh_count() });
    pwm.loop_.write(|w| w.cnt().disabled());
    pwm.seq0.refresh.write(|w| unsafe { w.bits(0) });
    pwm.seq0.enddelay.write(|w| unsafe { w.bits(0) });

    pwm.enable.write(|w| w.enable().enabled());
}

fn neopixel_show(r: u8, g: u8, b: u8) {
    // Scale down brightness — NeoPixel is extremely bright at full duty.
    let r = (r as u16 * 8 / 255) as u8;
    let g = (g as u16 * 8 / 255) as u8;
    let b = (b as u16 * 8 / 255) as u8;
    let grb: [u8; 3] = [g, r, b];
    let pattern = unsafe { &mut *(&raw mut PIXEL_PATTERN) };

    let mut pos = 0;
    for &byte in &grb {
        for bit in (0..8).rev() {
            pattern[pos] = if (byte >> bit) & 1 == 1 { T1H } else { T0H };
            pos += 1;
        }
    }
    pattern[24] = 0 | 0x8000;
    pattern[25] = 0 | 0x8000;

    let pwm = unsafe { &*pac::PWM1::ptr() };

    pwm.seq0.ptr.write(|w| unsafe { w.bits(pattern.as_ptr() as u32) });
    pwm.seq0.cnt.write(|w| unsafe { w.bits(26) });

    pwm.events_seqend[0].reset();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    pwm.tasks_seqstart[0].write(|w| unsafe { w.bits(1) });

    while pwm.events_seqend[0].read().bits() == 0 {}
    pwm.events_seqend[0].reset();
}

impl rgb_led::RgbLed for AdafruitLed {
    fn set_panic_led() {
        let pac = unsafe { nrf52840_pac::Peripherals::steal() };
        let p0 = p0::Parts::new(pac.P0);
        let p1 = p1::Parts::new(pac.P1);
        p1.p1_15.into_push_pull_output(Level::Low);
        p1.p1_10.into_push_pull_output(Level::Low);
        p1.p1_14.into_push_pull_output(Level::High);
        let neopixel = p0.p0_16.into_push_pull_output(Level::Low).degrade();
        neopixel_init(neopixel.pin() as u32);
        neopixel_show(u8::MAX, 0, 0);
    }

    fn red(&mut self, intensity: u8) {
        use embedded_hal::digital::v2::OutputPin;
        if intensity > 0 {
            self.red_led.set_high().ok();
        } else {
            self.red_led.set_low().ok();
        }
    }

    fn green(&mut self, intensity: u8) {
        neopixel_show(0, intensity, 0);
    }

    fn blue(&mut self, intensity: u8) {
        use embedded_hal::digital::v2::OutputPin;
        if intensity > 0 {
            self.blue_led.set_high().ok();
        } else {
            self.blue_led.set_low().ok();
        }
    }

    fn set(&mut self, intensities: rgb_led::Intensities) {
        let white = intensities.red > 0 && intensities.green > 0 && intensities.blue > 0;
        let red = !white && intensities.red > 0;
        let blue = !white && !red && (intensities.green > 0 || intensities.blue > 0);
        self.green(if white { intensities.green } else { 0 });
        self.red(if red { intensities.red } else { 0 });
        self.blue(if blue { u8::MAX } else { 0 });
    }
}

// ---------------------------------------------------------------------------
// GPIO / peripheral initialisation
// ---------------------------------------------------------------------------

pub struct BoardGPIO {
    pub gpiote: Gpiote,
    pub neopixel: OutPin,
    pub neopixel_power: OutPin,
    pub red_led: OutPin,
    pub blue_led: OutPin,
    pub button: BtnPin,
}

/// Initialise GPIO pins for the Adafruit nRF52840 Feather Express.
///
/// | Function        | NRF pin | Notes                          |
/// |-----------------|---------|--------------------------------|
/// | User button     | P1.02   | Active-low, internal pullup    |
/// | NeoPixel data   | P0.16   | WS2812B data                   |
/// | NeoPixel power  | P1.14   | Must be HIGH to power NeoPixel |
/// | Red LED         | P1.15   | Simple GPIO LED (panic only)   |
pub fn init_pins(gpiote: GPIOTE, p0: P0, p1: P1) -> BoardGPIO {
    let gpiote = Gpiote::new(gpiote);
    let gpio_p0 = p0::Parts::new(p0);
    let gpio_p1 = p1::Parts::new(p1);

    let button = gpio_p1.p1_02.into_pullup_input().degrade();
    let neopixel = gpio_p0.p0_16.into_push_pull_output(Level::Low).degrade();
    let neopixel_power = gpio_p1.p1_14.into_push_pull_output(Level::High).degrade();
    let red_led = gpio_p1.p1_15.into_push_pull_output(Level::Low).degrade();
    let blue_led = gpio_p1.p1_10.into_push_pull_output(Level::Low).degrade();

    gpiote.reset_events();

    BoardGPIO {
        gpiote,
        neopixel,
        neopixel_power,
        red_led,
        blue_led,
        button,
    }
}

/// Build the `UserInterface` for this board.
pub fn init_ui(
    neopixel: OutPin,
    neopixel_power: OutPin,
    red_led: OutPin,
    blue_led: OutPin,
    button: BtnPin,
) -> UserInterface<RtcMonotonic, HardwareButtons, AdafruitLed> {
    let pac = unsafe { nrf52840_pac::Peripherals::steal() };
    let rtc_mono = RtcMonotonic::new(pac.RTC0);

    let rgb = AdafruitLed::new(neopixel, neopixel_power, red_led, blue_led);
    let buttons = HardwareButtons::new(button);

    UserInterface::new(rtc_mono, Some(buttons), Some(rgb), false)
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
    if power.events_usbdetected.read().events_usbdetected().bit() {
        power.events_usbdetected.write(|w| unsafe { w.bits(0) });
    }
    if power.events_usbpwrrdy.read().events_usbpwrrdy().bit() {
        power.events_usbpwrrdy.write(|w| unsafe { w.bits(0) });
    }
    if power.events_usbremoved.read().events_usbremoved().bit() {
        power.events_usbremoved.write(|w| unsafe { w.bits(0) });
    }
}
