#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Indicator {
    Off,
    Startup,
    Provisioner,
    Processing,
    UserPresence,
    Wink,
    Error,
    Success,
}

pub trait RgbLed {
    fn panic_loop() -> !;

    fn show(&mut self, indicator: Indicator, lit: bool);
}
