#[derive(Clone, Copy, Default, Debug)]
pub struct SecurityStatus {
    pub pin: bool,
    pub admin: bool,
}

pub const OP_DF_DELETE_CHILD: u8 = 0x01;
pub const OP_DF_CREATE_EF: u8 = 0x02;
pub const OP_DF_TERMINATE: u8 = 0x20;

pub const OP_DO_GET: u8 = 0x01;
pub const OP_DO_PUT: u8 = 0x02;

pub const OP_KEY_GET_PUBLIC: u8 = 0x01;
pub const OP_KEY_PUT: u8 = 0x02;
pub const OP_KEY_MSE: u8 = 0x04;
pub const OP_KEY_GENERATE: u8 = 0x08;

const SCB_ALWAYS: u8 = 0x00;
const SCB_NEVER: u8 = 0xFF;
const SCB_ALL_CONDITIONS: u8 = 0x80;
const SCB_SECURE_MESSAGING: u8 = 0x40;
const SCB_ADMIN: u8 = 0x20;
const SCB_PIN: u8 = 0x10;
const SEID_CONTACT: u8 = 0x01;
const MAX_ACCESS_RULES: usize = 4;

fn scb_satisfied(scb: u8, status: SecurityStatus) -> bool {
    match scb {
        SCB_ALWAYS => return true,
        SCB_NEVER => return false,
        _ => {}
    }
    let seid = scb & 0x0F;
    if seid != 0 && seid != SEID_CONTACT {
        return false;
    }
    if scb & SCB_SECURE_MESSAGING != 0 {
        return false;
    }
    let need_admin = scb & SCB_ADMIN != 0;
    let need_pin = scb & SCB_PIN != 0;
    if !need_admin && !need_pin {
        return true;
    }
    if scb & SCB_ALL_CONDITIONS != 0 {
        (!need_admin || status.admin) && (!need_pin || status.pin)
    } else {
        (need_admin && status.admin) || (need_pin && status.pin)
    }
}

pub fn validate(attribute: &[u8]) -> bool {
    let mut data = attribute;
    let mut rules = 0;
    while let Some((&amb, rest)) = data.split_first() {
        let count = (amb & 0x7F).count_ones() as usize;
        if rest.len() < count || rules == MAX_ACCESS_RULES {
            return false;
        }
        data = &rest[count..];
        rules += 1;
    }
    rules > 0
}

pub fn allowed(attribute: Option<&[u8]>, operation: u8, status: SecurityStatus) -> bool {
    let Some(mut data) = attribute else {
        return false;
    };
    while let Some((&amb, rest)) = data.split_first() {
        let count = (amb & 0x7F).count_ones() as usize;
        let Some(scbs) = rest.get(..count) else {
            return false;
        };
        if amb & operation != 0 {
            let index = (amb & 0x7F & !(operation | (operation - 1))).count_ones() as usize;
            if scb_satisfied(scbs[index], status) {
                return true;
            }
        }
        data = &rest[count..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: SecurityStatus = SecurityStatus {
        pin: false,
        admin: false,
    };
    const PIN: SecurityStatus = SecurityStatus {
        pin: true,
        admin: false,
    };
    const ADMIN: SecurityStatus = SecurityStatus {
        pin: false,
        admin: true,
    };
    const BOTH: SecurityStatus = SecurityStatus {
        pin: true,
        admin: true,
    };

    #[test]
    fn scb_order_follows_amb_bits() {
        let df = [0x23, 0x20, 0x30, 0x30];
        assert!(!allowed(Some(&df), OP_DF_TERMINATE, PIN));
        assert!(allowed(Some(&df), OP_DF_TERMINATE, ADMIN));
        assert!(allowed(Some(&df), OP_DF_CREATE_EF, PIN));
        assert!(allowed(Some(&df), OP_DF_DELETE_CHILD, ADMIN));
        assert!(!allowed(Some(&df), OP_DF_CREATE_EF, NONE));
    }

    #[test]
    fn unlisted_operation_is_denied() {
        assert!(!allowed(Some(&[0x03, 0x30, 0x30]), OP_DF_TERMINATE, BOTH));
        assert!(!allowed(None, OP_DO_GET, BOTH));
    }

    #[test]
    fn always_never_and_all_conditions() {
        let ef = [0x03, 0x90, 0x00];
        assert!(allowed(Some(&ef), OP_DO_GET, NONE));
        assert!(!allowed(Some(&ef), OP_DO_PUT, NONE));
        assert!(allowed(Some(&ef), OP_DO_PUT, PIN));
        assert!(!allowed(Some(&[0x01, 0xFF]), OP_DO_GET, BOTH));
        assert!(!allowed(Some(&[0x01, 0xB0]), OP_DO_GET, PIN));
        assert!(allowed(Some(&[0x01, 0xB0]), OP_DO_GET, BOTH));
    }

    #[test]
    fn seid_and_secure_messaging() {
        assert!(allowed(Some(&[0x01, 0x11]), OP_DO_GET, PIN));
        assert!(!allowed(Some(&[0x01, 0x12]), OP_DO_GET, BOTH));
        assert!(!allowed(Some(&[0x01, 0x40]), OP_DO_GET, BOTH));
    }

    #[test]
    fn rules_are_ored() {
        let attribute = [0x01, 0x12, 0x01, 0x20];
        assert!(allowed(Some(&attribute), OP_DO_GET, ADMIN));
        assert!(!allowed(Some(&attribute), OP_DO_GET, PIN));
    }

    #[test]
    fn key_amb() {
        let key = [0x87, 0x00, 0x20, 0xFF];
        assert!(allowed(Some(&key), OP_KEY_MSE, NONE));
        assert!(allowed(Some(&key), OP_KEY_PUT, ADMIN));
        assert!(!allowed(Some(&key), OP_KEY_GET_PUBLIC, BOTH));
    }

    #[test]
    fn validation() {
        assert!(validate(&[0x23, 0x20, 0x30, 0x30]));
        assert!(!validate(&[0x23, 0x20, 0x30]));
        assert!(!validate(&[]));
    }
}
