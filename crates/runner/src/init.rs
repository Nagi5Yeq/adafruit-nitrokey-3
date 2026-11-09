use apdu_dispatch::{
    dispatch::ApduDispatch,
    interchanges::{Channel as CcidChannel, Responder as CcidResponder, SIZE as CCID_SIZE},
};
#[cfg(feature = "trussed-auth")]
use apps::AUTH_LOCATION;
use apps::{AdminData, ClientBuilder, Data, Dispatch, Endpoints, FidoData, InitStatus};

use ctaphid_dispatch::Channel as CtapChannel;
#[cfg(not(feature = "no-delog"))]
use delog::delog;
use interchange::Channel;
use nfc_device::Iso14443;
use rand::{CryptoRng, Rng as _, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use ref_swap::OptionRefSwap;
use trussed::store::Store as _;
use trussed_core::InterruptFlag;
use usb_device::{
    bus::UsbBusAllocator,
    descriptor::lang_id::LangID,
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
use usbd_ccid::Ccid;
use usbd_ctaphid::CtapHid;
use utils::Version;

use crate::{
    Soc, store::StoreResources, Apps, Board, Runner, RunnerPlatform, RunnerStore, Trussed,
    ui::UserInterface,
};

// This is not the theoretical maximum but a realistic upper bound to reduce stack usage.
pub const CTAPHID_MESSAGE_SIZE: usize = 3072;

pub type CtaphidDispatch<'pipe, 'interrupt> =
    ctaphid_dispatch::Dispatch<'pipe, 'interrupt, CTAPHID_MESSAGE_SIZE>;

#[cfg(not(feature = "no-delog"))]
delog!(Delogger, 3 * 1024, 512, DelogFlusher);

pub struct Resources<B: Board> {
    pub board: Option<B::Resources>,
    pub store: StoreResources<B>,
    pub usb: UsbResources<B>,
}

impl<B: Board> Default for Resources<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Board> Resources<B> {
    pub const fn new() -> Self {
        Self {
            board: None,
            store: StoreResources::new(),
            usb: UsbResources::new(),
        }
    }
}

pub struct UsbResources<B: Board> {
    usb_bus: Option<UsbBusAllocator<<B::Soc as Soc>::UsbBus>>,
}

impl<B: Board> Default for UsbResources<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Board> UsbResources<B> {
    pub const fn new() -> Self {
        Self { usb_bus: None }
    }
}

/// Log flusher — platform must provide the actual flush implementation.
/// The firmware crate should set up delog with a platform-specific flusher
/// (e.g. RTT on Cortex-M, stdout on std).
#[derive(Debug)]
pub struct DelogFlusher {
    pub flush_fn: fn(&str),
}

impl delog::Flusher for DelogFlusher {
    fn flush(&self, msg: &str) {
        (self.flush_fn)(msg);
    }
}

pub fn init_logger<B: Board>(flusher: &'static DelogFlusher, _version: &str) {
    #[cfg(not(feature = "no-delog"))]
    Delogger::init_default(delog::LevelFilter::Debug, flusher).ok();

    info!(
        "Runner ({}:{}) {}",
        B::Soc::SOC_NAME,
        B::BOARD_NAME,
        _version,
    );
}

pub struct UsbClasses<S: Soc> {
    pub usbd: UsbDevice<'static, S::UsbBus>,
    pub ccid: Ccid<'static, 'static, S::UsbBus, CCID_SIZE>,
    pub ctaphid: CtapHid<'static, 'static, 'static, S::UsbBus, CTAPHID_MESSAGE_SIZE>,
}

impl<S: Soc> UsbClasses<S> {
    pub fn poll(&mut self) {
        self.ctaphid.check_for_app_response();
        self.ccid.check_for_app_response();
        self.usbd.poll(&mut [&mut self.ccid, &mut self.ctaphid]);
    }
}

pub struct UsbNfc<B: Board> {
    pub usb_classes: Option<UsbClasses<B::Soc>>,
    pub apdu_dispatch: ApduDispatch<'static>,
    pub ctaphid_dispatch: CtaphidDispatch<'static, 'static>,
    pub iso14443: Option<Iso14443<B::NfcDevice>>,
}

const CARD_ISSUER: &[u8; 13] = b"Nitrokey\0\0\0\0\0";
const USB_MANUFACTURER: &str = "Nitrokey";
const USB_VENDOR_ID: u16 = 0x20A0;

#[allow(clippy::too_many_arguments)]
pub fn init_usb_nfc<B: Board>(
    resources: &'static mut UsbResources<B>,
    nfc_callback: interchange::Callback,
    usb_bus: Option<UsbBusAllocator<<B::Soc as Soc>::UsbBus>>,
    nfc: Option<Iso14443<B::NfcDevice>>,
    nfc_rp: CcidResponder<'static>,
    usb_product: &'static str,
    usb_product_id: u16,
    version: Version,
) -> UsbNfc<B> {
    static CCID_CHANNEL: CcidChannel = Channel::new();
    static CTAP_CHANNEL: CtapChannel<CTAPHID_MESSAGE_SIZE> = Channel::new();
    static CTAP_INTERRUPT: OptionRefSwap<'static, InterruptFlag> = OptionRefSwap::new(None);

    /* claim interchanges */
    let (mut ccid_rq, ccid_rp) = CCID_CHANNEL.split().unwrap();
    let (mut ctaphid_rq, ctaphid_rp) = CTAP_CHANNEL.split().unwrap();
    *ccid_rq.callback_mut() = nfc_callback;
    *ctaphid_rq.callback_mut() = nfc_callback;

    /* initialize dispatchers */
    let apdu_dispatch = ApduDispatch::new(ccid_rp, nfc_rp);
    let ctaphid_dispatch = CtaphidDispatch::with_interrupt(ctaphid_rp, Some(&CTAP_INTERRUPT));

    /* populate requesters (if bus options are provided) */
    let usb_classes = usb_bus.map(|usb_bus| {
        let usb_bus = resources.usb_bus.insert(usb_bus);

        /* Class #1: CCID */
        let ccid = Ccid::new(usb_bus, ccid_rq, Some(CARD_ISSUER));

        /* Class #2: CTAPHID */
        let ctaphid = CtapHid::with_interrupt(usb_bus, ctaphid_rq, Some(&CTAP_INTERRUPT), 0u32)
            .implements_ctap1()
            .implements_ctap2()
            .implements_wink();

        let vidpid = UsbVidPid(USB_VENDOR_ID, usb_product_id);
        let strings = StringDescriptors::new(LangID::EN_US)
            .product(usb_product)
            .manufacturer(USB_MANUFACTURER);
        let usbd = UsbDeviceBuilder::new(usb_bus, vidpid)
            .strings(&[strings])
            .expect("failed to set USB string descriptors")
            .device_release(version.usb_release())
            .max_packet_size_0(64)
            .expect("invalid max packet size for EP0")
            .composite_with_iads()
            .build();

        UsbClasses {
            usbd,
            ccid,
            ctaphid,
        }
    });

    UsbNfc {
        usb_classes,
        apdu_dispatch,
        ctaphid_dispatch,
        iso14443: nfc,
    }
}

pub fn init_apps<B: Board>(
    board: &B,
    trussed: &mut Trussed<B>,
    init_status: InitStatus,
    store: &RunnerStore<B>,
    nfc_powered: bool,
    version: Version,
    version_string: &'static str,
) -> (Apps<B>, Endpoints) {
    let mut admin = AdminData {
        store: *store,
        init_status,
        ifs_blocks: u8::MAX,
        efs_blocks: u16::MAX,
        variant: B::Soc::VARIANT,
        model: B::MODEL,
        revision: board.revision(),
        version,
        version_string,
        reboot: B::Soc::reboot,
        reboot_to_firmware_update: B::Soc::reboot_to_firmware_update,
        locked: B::Soc::locked,
    };
    if !nfc_powered {
        if let Ok(ifs_blocks) = store.ifs().available_blocks() {
            admin.ifs_blocks = u8::try_from(ifs_blocks).unwrap_or(u8::MAX);
        }
        if let Ok(efs_blocks) = store.efs().available_blocks() {
            admin.efs_blocks = u16::try_from(efs_blocks).unwrap_or(u16::MAX);
        }
    }

    #[cfg(feature = "provisioner")]
    let provisioner = {
        let store = store.clone();
        let rebooter: fn() = B::Soc::reboot_to_firmware_update;

        apps::ProvisionerData { store, rebooter }
    };

    let runner = Runner {
        uuid: *board.soc().uuid(),
        is_efs_available: !nfc_powered,
        is_nfc_powered: nfc_powered,
        _marker: Default::default(),
    };
    let data = Data {
        admin,
        fido: FidoData {
            has_nfc: B::HAS_NFC,
            max_message_size: CTAPHID_MESSAGE_SIZE,
        },
        #[cfg(feature = "provisioner")]
        provisioner,
        _marker: Default::default(),
    };

    let mut client_builder = ClientBuilder::new(Default::default());
    let apps = Apps::new(&runner, trussed, &mut client_builder, data);
    let endpoints = client_builder.into_endpoints();
    (apps, endpoints)
}

pub fn init_trussed<B: Board, R: CryptoRng + RngCore>(
    dev_rng: &mut R,
    store: RunnerStore<B>,
    user_interface: UserInterface<<B::Soc as Soc>::Clock, B::Buttons, B::Led>,
    #[cfg(feature = "trussed-auth")] hw_key: Option<&[u8]>,
) -> Trussed<B> {
    let rng = ChaCha8Rng::from_seed(dev_rng.gen());

    let platform = RunnerPlatform {
        rng,
        store,
        user_interface,
    };

    #[cfg(feature = "trussed-auth")]
    let dispatch = if let Some(hw_key) = hw_key {
        Dispatch::with_hw_key(
            AUTH_LOCATION,
            trussed_core::types::Bytes::try_from(hw_key).unwrap(),
        )
    } else {
        Dispatch::new(AUTH_LOCATION)
    };
    #[cfg(not(feature = "trussed-auth"))]
    let dispatch = Dispatch::new();

    Trussed::with_dispatch(platform, dispatch)
}
