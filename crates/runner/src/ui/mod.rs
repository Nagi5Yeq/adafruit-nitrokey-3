use core::{
    ops::Range,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
    time::Duration,
};

use trussed::{platform, types::ui};
use trussed_core::types::consent;

use buttons::UserPresence;
use rgb_led::{Indicator, RgbLed};

pub mod buttons;
pub mod rgb_led;

const BLINK_PERIOD_MS: u128 = 500;

fn blink(start: Duration, uptime: Duration) -> bool {
    uptime.saturating_sub(start).as_millis() % BLINK_PERIOD_MS < BLINK_PERIOD_MS / 2
}

static WAITING: AtomicBool = AtomicBool::new(false);

fn set_waiting(waiting: bool) {
    WAITING.store(waiting, Relaxed);
}

pub fn is_waiting() -> bool {
    WAITING.load(Relaxed)
}

pub trait Clock {
    fn uptime(&mut self) -> Duration;
}

pub struct UserInterface<C, P, L> {
    clock: C,
    buttons: Option<P>,
    rgb: Option<L>,
    status: Status,
    provisioner: bool,
    is_nfc_passive: bool,
}

impl<C: Clock, P: UserPresence, L: RgbLed> UserInterface<C, P, L> {
    pub fn new(mut clock: C, buttons: Option<P>, rgb: Option<L>, is_nfc_passive: bool) -> Self {
        let uptime = clock.uptime();
        let status = Status::Startup(uptime);
        let buttons = if cfg!(feature = "no-buttons") {
            None
        } else {
            buttons
        };
        let provisioner = cfg!(feature = "provisioner");

        let mut ui = Self {
            clock,
            buttons,
            status,
            rgb,
            provisioner,
            is_nfc_passive,
        };
        ui.refresh_ui(uptime);
        ui
    }

    fn refresh_ui(&mut self, uptime: Duration) {
        if self.is_nfc_passive {
            return;
        }
        if let Some(rgb) = &mut self.rgb {
            self.status.refresh(uptime);
            let (indicator, lit) = self.status.indicator(self.provisioner, uptime);
            rgb.show(indicator, lit);
        }
    }
}

impl<C: Clock, P: UserPresence, L: RgbLed> platform::UserInterface for UserInterface<C, P, L> {
    fn check_user_presence(&mut self) -> consent::Level {
        if let Some(buttons) = &mut self.buttons {
            set_waiting(true);
            let level = buttons.check_user_presence();
            set_waiting(false);
            level
        } else {
            consent::Level::Normal
        }
    }

    fn set_status(&mut self, status: ui::Status) {
        let uptime = self.uptime();
        self.status.update(status, uptime);
        self.refresh_ui(uptime);
    }

    fn refresh(&mut self) {
        let uptime = self.uptime();
        self.refresh_ui(uptime);
    }

    fn uptime(&mut self) -> Duration {
        self.clock.uptime()
    }

    fn wink(&mut self, duration: Duration) {
        let uptime = self.uptime();
        self.status = Status::Winking(uptime..uptime + duration);
        self.refresh_ui(uptime);
    }
}

pub struct CustomStatus(apps::CustomStatus);

impl CustomStatus {
    fn indicator(&self) -> Indicator {
        match self.0 {
            apps::CustomStatus::ReverseHotpSuccess => Indicator::Success,
            apps::CustomStatus::ReverseHotpError => Indicator::Error,
        }
    }

    fn allow_update(&self) -> bool {
        false
    }

    fn duration(&self) -> Option<Duration> {
        match self.0 {
            apps::CustomStatus::ReverseHotpSuccess => Some(Duration::from_secs(10)),
            apps::CustomStatus::ReverseHotpError => None,
        }
    }
}

impl From<apps::CustomStatus> for CustomStatus {
    fn from(status: apps::CustomStatus) -> Self {
        Self(status)
    }
}

impl TryFrom<u8> for CustomStatus {
    type Error = apps::UnknownStatusError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        apps::CustomStatus::try_from(value).map(From::from)
    }
}

pub enum Status {
    Startup(Duration),
    Idle,
    Processing,
    WaitingForUserPresence(Duration),
    Winking(Range<Duration>),
    Error,
    Custom {
        status: CustomStatus,
        start: Duration,
    },
}

impl Status {
    pub fn update(&mut self, status: ui::Status, uptime: Duration) {
        if status == ui::Status::Idle && matches!(self, Self::Startup(_) | Self::Winking(_)) {
            return;
        }
        if let Self::Custom { status, .. } = self {
            if !status.allow_update() {
                return;
            }
        }
        *self = (status, uptime).into();
    }

    pub fn refresh(&mut self, uptime: Duration) {
        let end = match self {
            Self::Startup(ref start) => Some(*start + Duration::from_millis(500)),
            Self::Winking(ref range) => Some(range.end),
            Self::Custom { status, start } => status.duration().map(|duration| *start + duration),
            _ => None,
        };
        if let Some(end) = end {
            if uptime > end {
                *self = Self::Idle;
            }
        }
    }

    pub fn indicator(&self, is_provisioner: bool, uptime: Duration) -> (Indicator, bool) {
        match self {
            Self::Startup(_) => (Indicator::Startup, true),
            Self::Idle if is_provisioner => (Indicator::Provisioner, true),
            Self::Idle => (Indicator::Off, false),
            Self::Processing => (Indicator::Processing, true),
            Self::WaitingForUserPresence(start) => (Indicator::UserPresence, blink(*start, uptime)),
            Self::Error => (Indicator::Error, true),
            Self::Winking(range) => (Indicator::Wink, blink(range.start, uptime)),
            Self::Custom { status, start } => (status.indicator(), blink(*start, uptime)),
        }
    }
}

impl From<(ui::Status, Duration)> for Status {
    fn from((status, uptime): (ui::Status, Duration)) -> Self {
        match status {
            ui::Status::Idle => Self::Idle,
            ui::Status::Processing => Self::Processing,
            ui::Status::WaitingForUserPresence => Self::WaitingForUserPresence(uptime),
            ui::Status::Error => Self::Error,
            ui::Status::Custom(custom) => CustomStatus::try_from(custom)
                .map(|status| Self::Custom {
                    status,
                    start: uptime,
                })
                .unwrap_or_else(|_| {
                    error!("Unsupported custom UI status {}", custom);
                    Self::Error
                }),
            _ => {
                error!("Unsupported UI status {:?}", status);
                Self::Error
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn startup_then_idle() {
        let mut status = Status::Startup(ms(0));
        assert_eq!(status.indicator(false, ms(0)), (Indicator::Startup, true));
        status.update(ui::Status::Idle, ms(100));
        assert_eq!(status.indicator(false, ms(100)), (Indicator::Startup, true));
        status.refresh(ms(600));
        assert_eq!(status.indicator(false, ms(600)), (Indicator::Off, false));
        assert_eq!(
            status.indicator(true, ms(600)),
            (Indicator::Provisioner, true)
        );
    }

    #[test]
    fn processing_and_error_are_constant() {
        let mut status = Status::Idle;
        status.update(ui::Status::Processing, ms(1000));
        assert_eq!(
            status.indicator(false, ms(1300)),
            (Indicator::Processing, true)
        );
        status.update(ui::Status::Error, ms(2000));
        assert_eq!(status.indicator(false, ms(2300)), (Indicator::Error, true));
    }

    #[test]
    fn user_presence_blinks() {
        let mut status = Status::Idle;
        status.update(ui::Status::WaitingForUserPresence, ms(1000));
        assert_eq!(
            status.indicator(false, ms(1000)),
            (Indicator::UserPresence, true)
        );
        assert_eq!(
            status.indicator(false, ms(1300)),
            (Indicator::UserPresence, false)
        );
        assert_eq!(
            status.indicator(false, ms(1500)),
            (Indicator::UserPresence, true)
        );
    }

    #[test]
    fn wink_blinks_until_its_end() {
        let mut status = Status::Winking(ms(1000)..ms(3000));
        assert_eq!(status.indicator(false, ms(1100)), (Indicator::Wink, true));
        assert_eq!(status.indicator(false, ms(1350)), (Indicator::Wink, false));
        status.update(ui::Status::Idle, ms(2000));
        assert_eq!(status.indicator(false, ms(2000)).0, Indicator::Wink);
        status.refresh(ms(3100));
        assert_eq!(status.indicator(false, ms(3100)), (Indicator::Off, false));
    }

    #[test]
    fn reverse_hotp_statuses() {
        let mut status = Status::Custom {
            status: apps::CustomStatus::ReverseHotpSuccess.into(),
            start: ms(0),
        };
        assert_eq!(status.indicator(false, ms(0)), (Indicator::Success, true));
        status.update(ui::Status::Idle, ms(100));
        assert_eq!(status.indicator(false, ms(100)).0, Indicator::Success);
        status.refresh(ms(10_100));
        assert_eq!(status.indicator(false, ms(10_100)), (Indicator::Off, false));

        let mut status = Status::Custom {
            status: apps::CustomStatus::ReverseHotpError.into(),
            start: ms(0),
        };
        status.update(ui::Status::Idle, ms(100));
        status.refresh(ms(60_000));
        assert_eq!(
            status.indicator(false, ms(60_000)),
            (Indicator::Error, true)
        );
        assert_eq!(
            status.indicator(false, ms(60_300)),
            (Indicator::Error, false)
        );
    }
}
