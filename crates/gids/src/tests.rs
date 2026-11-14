extern crate std;

use std::{string::String, vec::Vec};

use apdu_app::{App as _, CommandView, Interface};
use des::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use iso7816::{App as _, Status};
use trussed::virt::{self, StoreConfig};

use crate::Gids;

mod dispatch {
    use trussed::{
        backend::{Backend as _, BackendId},
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl as _},
        service::ServiceResources,
        types::Context,
    };
    use trussed_auth::AuthExtension;
    use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout};
    use trussed_chunked::ChunkedExtension;
    use trussed_core::{
        api::{reply, request, Reply, Request},
        types::Location,
        Error,
    };
    use trussed_staging::{StagingBackend, StagingContext};

    pub const BACKENDS: &[BackendId<Backend>] = &[
        BackendId::Custom(Backend::Rsa),
        BackendId::Custom(Backend::Auth),
        BackendId::Custom(Backend::Staging),
        BackendId::Core,
    ];

    pub enum Backend {
        Rsa,
        Auth,
        Staging,
    }

    pub enum Extension {
        Auth,
        Chunked,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::Chunked => 1,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::Chunked),
                _ => Err(Error::InternalError),
            }
        }
    }

    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal, FilesystemLayout::V1),
                staging: StagingBackend::new(),
            }
        }
    }

    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Rsa => trussed_rsa_alloc::SoftwareRsa.request(
                    &mut ctx.core,
                    &mut (),
                    request,
                    resources,
                ),
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match (backend, extension) {
                (Backend::Auth, Extension::Auth) => self.auth.extension_request_serialized(
                    &mut ctx.core,
                    &mut ctx.backends.auth,
                    request,
                    resources,
                ),
                (Backend::Staging, Extension::Chunked) => trussed::serde_extensions::ExtensionImpl::<
                    ChunkedExtension,
                >::extension_request_serialized(
                    &mut self.staging,
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                _ => Err(Error::RequestNotAvailable),
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;
        const ID: Self::Id = Self::Id::Auth;
    }

    impl ExtensionId<ChunkedExtension> for Dispatch {
        type Id = Extension;
        const ID: Self::Id = Self::Id::Chunked;
    }
}

type App<'a> = Gids<virt::Client<'a, dispatch::Dispatch>>;

const ADMIN_KEY: &str = "010203040506070801020304050607080102030405060708";

fn run(f: impl FnOnce(&mut App<'_>)) {
    virt::with_platform(StoreConfig::ram(), |platform| {
        platform.run_client_with_backends(
            "gids",
            dispatch::Dispatch::default(),
            dispatch::BACKENDS,
            |client| f(&mut Gids::new(client)),
        )
    })
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn transmit(app: &mut App<'_>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let command = CommandView::try_from(apdu).unwrap();
    let mut reply: heapless::Vec<u8, 7609> = heapless::Vec::new();
    let result = if command.instruction() == iso7816::Instruction::Select && command.p1 & 0x04 != 0
    {
        app.select(Interface::Contact, command, reply.as_mut_view())
    } else {
        app.call(Interface::Contact, command, reply.as_mut_view())
    };
    match result {
        Ok(()) => (reply.to_vec(), 0x9000),
        Err(status) => (Vec::new(), u16::from(status)),
    }
}

fn exec(app: &mut App<'_>, apdu: &str) -> (Vec<u8>, u16) {
    transmit(app, &hex(apdu))
}

#[track_caller]
fn ok(app: &mut App<'_>, apdu: &str) -> Vec<u8> {
    let (data, sw) = exec(app, apdu);
    assert_eq!(sw, 0x9000, "{apdu}");
    data
}

#[track_caller]
fn sw(app: &mut App<'_>, apdu: &str, expected: u16) {
    assert_eq!(exec(app, apdu).1, expected, "{apdu}");
}

fn put_data(fid: u16, data: &[u8]) -> Vec<u8> {
    let mut apdu = std::vec![0x00, 0xDB, (fid >> 8) as u8, fid as u8];
    if data.len() < 256 {
        apdu.push(data.len() as u8);
    } else {
        apdu.extend_from_slice(&[0x00, (data.len() >> 8) as u8, data.len() as u8]);
    }
    apdu.extend_from_slice(data);
    apdu
}

fn tdes(key: &[u8], block: &mut [u8], encrypt: bool) {
    let cipher = des::TdesEde3::new_from_slice(key).unwrap();
    let block = GenericArray::from_mut_slice(block);
    if encrypt {
        cipher.encrypt_block(block);
    } else {
        cipher.decrypt_block(block);
    }
}

fn cbc(key: &[u8], data: &mut [u8], encrypt: bool) {
    let mut chain = [0u8; 8];
    for block in data.chunks_mut(8) {
        if encrypt {
            block.iter_mut().zip(chain).for_each(|(b, c)| *b ^= c);
            tdes(key, block, true);
            chain.copy_from_slice(block);
        } else {
            let ciphertext: [u8; 8] = (&*block).try_into().unwrap();
            tdes(key, block, false);
            block.iter_mut().zip(chain).for_each(|(b, c)| *b ^= c);
            chain = ciphertext;
        }
    }
}

fn personalize(app: &mut App<'_>) {
    ok(app, "00A4040409A0000003974254465900");
    ok(app, "00240180083132333435363738");
    for (fid, acl) in [
        ("A000", "033000"),
        ("A010", "033000"),
        ("A011", "0330FF"),
        ("A012", "032000"),
        ("A013", "033030"),
        ("A014", "032020"),
    ] {
        ok(app, &std::format!("00E000000E620C8201398302{fid}8C03{acl}"));
        ok(app, "0044000000");
    }
    ok(
        app,
        "00E000001C621A8201188302B0808C04870020FFA50BA4098001028301809501C0",
    );
    ok(app, "0044000000");
    ok(
        app,
        &std::format!("00DB3FFF267024840180A51F8718{ADMIN_KEY}8803B073DC"),
    );
    ok(app, "00DBA00091DF1F818D016d736370000000000000000000000000000000000000000000a00000000000000000000000636172646964000000000020df000012a00000000000000000000000636172646170707300000021df000010a00000000000000000000000636172646366000000000022df000010a000006d7363700000000000636d617066696c6500000023df000010a00000");
    ok(app, "00DBA0100BDF21086d73637000000000");
    ok(app, "00DBA01009DF2206000000000000");
    ok(app, "00DBA01003DF2300");
    ok(app, "00DBA01213DF2010000102030405060708090a0b0c0d0e0f");
    ok(app, "00A4000C023FFF");
    ok(app, "0044000000");
}

fn external_auth(app: &mut App<'_>, key: &str) -> u16 {
    ok(app, "002281A403830180");
    let challenge = ok(app, "00870000047C028100");
    assert_eq!(&challenge[..4], hex("7C0A8108"));
    let mut response: [u8; 8] = challenge[4..12].try_into().unwrap();
    tdes(&hex(key), &mut response, true);
    let mut apdu = hex("008700000C7C0A8208");
    apdu.extend_from_slice(&response);
    transmit(app, &apdu).1
}

fn mutual_auth(app: &mut App<'_>, key: &str) -> u16 {
    let key = hex(key);
    let host = [0x5Au8; 16];
    ok(app, "002281A403830180");
    let mut apdu = hex("00870000147C128110");
    apdu.extend_from_slice(&host);
    let (challenge, status) = transmit(app, &apdu);
    assert_eq!(status, 0x9000);
    assert_eq!(&challenge[..4], hex("7C128110"));
    let card = &challenge[4..20];
    let mut cryptogram = [0u8; 40];
    cryptogram[..16].copy_from_slice(card);
    cryptogram[16..32].copy_from_slice(&host);
    cryptogram[39] = 0x80;
    cbc(&key, &mut cryptogram, true);
    let mut apdu = hex("008700002C7C2A8228");
    apdu.extend_from_slice(&cryptogram);
    let (response, status) = transmit(app, &apdu);
    if status != 0x9000 {
        return status;
    }
    assert_eq!(&response[..4], hex("7C2A8228"));
    let mut plain: [u8; 40] = response[4..44].try_into().unwrap();
    cbc(&key, &mut plain, false);
    assert_eq!(&plain[..16], host);
    assert_eq!(&plain[16..32], card);
    assert_eq!(plain[39], 0x80);
    status
}

#[test]
fn aid_matches_truncated_select() {
    run(|app| {
        assert!(app.aid().matches(&hex("A0 00 00 03 97 42 54 46 59")));
        assert!(app.aid().matches(&hex("A0 00 00 03 97 42 54 46 59 02 01")));
        assert!(!app.aid().matches(&hex("A0 00 00 03 97")));
    });
}

#[test]
fn select_responses() {
    run(|app| {
        assert_eq!(
            ok(app, "00 A4 04 00 09 A0 00 00 03 97 42 54 46 59 00"),
            hex("61 12 4F 0B A0 00 00 03 97 42 54 46 59 02 01 73 03 40 01 C0")
        );
        let fcp = ok(app, "00 A4 04 04 09 A0 00 00 03 97 42 54 46 59 00");
        let inner = find_tlv(&fcp, &[0x62]).unwrap();
        assert_eq!(
            &inner[..25],
            hex("82 01 38 8A 01 03 84 0B A0 00 00 03 97 42 54 46 59 02 01 8C 04 23 20 30 30")
        );
        let mut templates = &inner[25..];
        let mut references = Vec::new();
        while !templates.is_empty() {
            let (tag, value, rest) = crate::tlv::take_tlv(templates).unwrap();
            assert_eq!(tag, [0xAC]);
            references.push(find_tlv(value, &[0x80]).unwrap()[0]);
            assert!(find_tlv(value, &[0x06]).is_some());
            templates = rest;
        }
        assert_eq!(
            references,
            hex("02 07 08 09 0C 0D 17 18 19 1C 1D 47 48 49 57 58 59 87 88 89")
        );
        assert_eq!(
            ok(app, "00 A4 04 08 09 A0 00 00 03 97 42 54 46 59 00"),
            hex("64 09 5F 2F 01 60 7F 65 02 80 00")
        );
        assert_eq!(
            ok(app, "00 A4 04 0C 09 A0 00 00 03 97 42 54 46 59"),
            hex("")
        );
        sw(app, "00 A4 04 02 09 A0 00 00 03 97 42 54 46 59 00", 0x6A86);
        sw(app, "00 A4 00 0C 02 A0 00", 0x6A82);
        sw(app, "00 A4 00 0C 01 3F", 0x6A87);
        sw(app, "00 A4 00 00 02 00 00 00", 0x6A82);
    });
}

#[test]
fn global_data_objects() {
    run(|app| {
        ok(app, "00A4040409A0000003974254465900");
        assert_eq!(
            ok(app, "00 CB 2F 01 02 5C 00 00"),
            hex("43 01 F4 47 03 08 01 C0 46 08 4E 69 74 72 6F 6B 65 79")
        );
        assert_eq!(
            ok(app, "00 CB 2F 00 02 5C 00 00"),
            hex("61 12 4F 0B A0 00 00 03 97 42 54 46 59 02 01 73 03 40 01 C0")
        );
        sw(app, "00 CB 2F 01 02 5C 01 00", 0x6A80);
        sw(app, "00 CB 3F FF 04 5C 02 7F 71 00", 0x6A88);
        sw(app, "00 CB 3F FF 04 5C 02 7F 72 00", 0x6A88);
        sw(app, "00 CB 3F FF 04 5C 02 7F 73 00", 0x6A88);
        assert_eq!(ok(app, "00 CB 3F FF 04 5C 02 7F 62 00"), hex("7F 62 00"));
        assert_eq!(ok(app, "00 CB 3F FF 04 5C 02 7F 63 00"), hex("7F 63 00"));
    });
}

#[test]
fn class_checks() {
    run(|app| {
        sw(app, "0C CB 2F 01 02 5C 00 00", 0x6882);
        sw(app, "01 CB 2F 01 02 5C 00 00", 0x6881);
        sw(app, "00 2A 9E 9A 00", 0x6985);
        sw(app, "00 88 00 00 00", 0x6D00);
        let bytes = hex("00 A4 04 00 09 A0 00 00 03 97 42 54 46 59 00");
        let command = CommandView::try_from(bytes.as_slice()).unwrap();
        let mut reply: heapless::Vec<u8, 64> = heapless::Vec::new();
        assert_eq!(
            app.select(Interface::Contactless, command, reply.as_mut_view()),
            Err(Status::ConditionsOfUseNotSatisfied)
        );
    });
}

#[test]
fn create_select_and_fcp() {
    run(|app| {
        ok(app, "00A4040409A0000003974254465900");
        ok(app, "00E000000E620C8201398302A0108C03033000");
        assert_eq!(
            ok(app, "00 A4 00 04 02 A0 10 00"),
            hex("62 0F 82 01 39 83 02 A0 10 8A 01 03 8C 03 03 30 00")
        );
        sw(app, "00E000000E620C8201398302A0108C03033000", 0x6A89);
        sw(app, "00E000000D620B8201398302A0118C020330", 0x6A80);
        sw(app, "00E000000E620D8201398302A0128C03033000", 0x6A85);
        sw(app, "00E0000011620F820139830201028C030330008A0103", 0x6A80);
        sw(app, "00E000000E620C82013983023FFF8C03033000", 0x6A80);
        sw(app, "00E000000E620C8201188302B0818C03033000", 0x6A80);
        sw(
            app,
            "00E000001C621A8201188302B0818C04870020FFA50BA4098001028301809501C0",
            0x6A80,
        );
        ok(app, "0044000000");
        assert_eq!(
            ok(app, "00 A4 00 00 02 00 00 00"),
            hex("62 0F 82 01 39 83 02 A0 10 8A 01 05 8C 03 03 30 00")
        );
        assert_eq!(ok(app, "00 A4 00 08 02 A0 10 00"), hex("64 00"));
    });
}

#[test]
fn data_objects() {
    run(|app| {
        ok(app, "00A4040409A0000003974254465900");
        ok(app, "00E000000E620C8201398302A0108C03033000");
        sw(app, "00 CB A0 10 02 5C 00 00", 0x6A88);
        ok(app, "00 DB A0 10 05 DF 21 02 AA BB");
        ok(app, "00 DB 00 00 03 DF 22 00");
        ok(app, "00 DB A0 10 06 5F 3F 03 01 02 03");
        assert_eq!(
            ok(app, "00 CB A0 10 04 5C 02 DF 21 00"),
            hex("DF 21 02 AA BB")
        );
        assert_eq!(ok(app, "00 CB A0 10 04 5C 02 DF 22 00"), hex("DF 22 00"));
        assert_eq!(
            ok(app, "00 CB A0 10 02 5C 00 00"),
            hex("5F 3F 03 01 02 03 DF 21 02 AA BB DF 22 00")
        );
        assert_eq!(
            ok(app, "00 CB A0 10 03 5C 01 5C 00"),
            hex("5C 06 5F 3F DF 21 DF 22")
        );
        sw(app, "00 CB A0 10 04 5C 02 DF 23 00", 0x6A88);
        ok(app, "00 DB A0 10 03 DF 21 00");
        sw(app, "00 CB A0 10 04 5C 02 DF 21 00", 0x6A88);
        sw(app, "00 DB A0 10 04 DF 21 02 AA", 0x6A85);
        ok(app, "00 DB 3F FF 04 DF 22 01 CC");
        assert_eq!(ok(app, "00 CB 00 00 04 5C 02 DF 22 00"), hex("DF 22 01 CC"));
        sw(app, "00 DB 3F FF 04 DF 29 01 CC", 0x6A88);
        sw(app, "00 CB B0 80 02 5C 00 00", 0x6A82);
    });
}

#[test]
fn large_data_object() {
    run(|app| {
        ok(app, "00A4040409A0000003974254465900");
        ok(app, "00E000000E620C8201398302A0108C03033000");
        let value: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let mut object = hex("DF 24 82 0B B8");
        object.extend_from_slice(&value);
        assert_eq!(transmit(app, &put_data(0xA010, &object)).1, 0x9000);
        let (data, status) = exec(app, "00 CB A0 10 04 5C 02 DF 24 00");
        assert_eq!(status, 0x9000);
        assert_eq!(data, object);
    });
}

#[test]
fn delete_file_removes_objects() {
    run(|app| {
        ok(app, "00A4040409A0000003974254465900");
        ok(app, "00E000000E620C8201398302A0108C03033000");
        ok(app, "00 DB A0 10 05 DF 21 02 AA BB");
        ok(app, "00 DB A0 10 05 DF 22 02 AA BB");
        ok(app, "00 A4 00 0C 02 A0 10");
        ok(app, "00 E4 00 00");
        sw(app, "00 A4 00 0C 02 A0 10", 0x6A82);
        ok(app, "00E000000E620C8201398302A0108C03033000");
        sw(app, "00 CB A0 10 02 5C 00 00", 0x6A88);
    });
}

#[test]
fn personalization_and_access_rules() {
    run(|app| {
        personalize(app);
        ok(app, "00 20 00 82 00");
        let fcp = ok(app, "00 A4 04 04 09 A0 00 00 03 97 42 54 46 59 00");
        assert_eq!(
            find_tlv(&find_tlv(&fcp, &[0x62]).unwrap(), &[0x8A]).unwrap(),
            [0x05]
        );
        assert_eq!(
            ok(app, "00 CB A0 12 04 5C 02 DF 20 00"),
            hex("DF 20 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        );
        sw(app, "00 CB A0 11 02 5C 00 00", 0x6982);
        sw(app, "00 DB A0 10 04 DF 22 01 01", 0x6982);
        sw(app, "00 DB A0 12 04 DF 20 01 01", 0x6982);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        ok(app, "00 DB A0 10 04 DF 22 01 01");
        sw(app, "00 DB A0 12 04 DF 20 01 01", 0x6982);
        ok(app, "00 DB A0 11 04 DF 30 01 01");
        sw(app, "00 CB A0 11 04 5C 02 DF 30 00", 0x6982);
        assert_eq!(ok(app, "00 CB 3F FF 04 5C 02 DF 22 00"), hex("DF 22 01 01"));
        sw(app, "00 CB 3F FF 04 5C 02 DF 30 00", 0x6982);
        ok(app, "00 20 00 82 00");
        sw(app, "00 DB A0 10 04 DF 22 01 01", 0x6982);
        sw(app, "00E000000E620C8201398302A0208C03033000", 0x6982);
        sw(app, "00 24 01 80 08 31 32 33 34 35 36 37 38", 0x6985);
    });
}

#[test]
fn pin_lifecycle() {
    run(|app| {
        personalize(app);
        ok(app, "00 20 00 82 00");
        assert_eq!(
            ok(app, "00 CB 3F FF 04 5C 02 7F 72 00"),
            hex("7F 72 06 97 01 03 93 01 03")
        );
        sw(app, "00 20 00 80 00", 0x63C3);
        sw(app, "00 20 00 80 08 30 30 30 30 30 30 30 30", 0x63C2);
        sw(app, "00 20 00 80 03 30 30 30", 0x63C2);
        sw(app, "00 20 00 80 02 30 30", 0x63C2);
        sw(app, "00 20 00 80 04 30 30 30 30", 0x63C1);
        assert_eq!(
            ok(app, "00 CB 3F FF 04 5C 02 7F 72 00"),
            hex("7F 72 06 97 01 01 93 01 03")
        );
        assert_eq!(
            ok(app, "00 CB 3F FF 04 5C 02 7F 71 00"),
            hex("7F 71 06 97 01 01 93 01 03")
        );
        sw(app, "00 CB 3F FF 04 5C 02 7F 73 00", 0x6A88);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        ok(app, "00 20 00 80 00");
        ok(app, "00 20 00 82 00");
        ok(app, "00 20 00 00 08 31 32 33 34 35 36 37 38");
        ok(app, "00 20 00 00 00");
        sw(app, "00 20 00 81 08 31 32 33 34 35 36 37 38", 0x6A88);
        sw(
            app,
            "00 24 00 81 10 31 32 33 34 35 36 37 38 39 39 39 39 39 39 39 39",
            0x6A88,
        );
        sw(app, "00 24 00 80 03 31 32 33", 0x63C3);
        sw(
            app,
            "00 24 00 00 10 30 30 30 30 30 30 30 30 39 39 39 39 39 39 39 39",
            0x63C2,
        );
        ok(app, "00 20 00 00 08 31 32 33 34 35 36 37 38");
        sw(
            app,
            "00 24 00 80 10 30 30 30 30 30 30 30 30 39 39 39 39 39 39 39 39",
            0x63C2,
        );
        ok(
            app,
            "00 24 00 80 12 31 32 33 34 35 36 37 38 39 39 39 39 39 39 39 39 39 39",
        );
        sw(app, "00 20 00 80 08 31 32 33 34 35 36 37 38", 0x63C2);
        ok(app, "00 20 00 80 0A 39 39 39 39 39 39 39 39 39 39");
        sw(
            app,
            "00 24 00 80 0D 39 39 39 39 39 39 39 39 39 39 31 31 31",
            0x6A80,
        );
        ok(app, "00 20 00 80 0A 39 39 39 39 39 39 39 39 39 39");
        for expected in [0x63C2, 0x63C1, 0x63C0] {
            sw(app, "00 20 00 80 08 30 30 30 30 30 30 30 30", expected);
        }
        sw(app, "00 20 00 80 0A 39 39 39 39 39 39 39 39 39 39", 0x6983);
        sw(app, "00 20 00 80 00", 0x6983);
        sw(app, "00 2C 02 80 08 31 31 31 31 31 31 31 31", 0x6982);
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        sw(app, "00 2C 02 80 03 31 31 31", 0x6A80);
        ok(app, "00 2C 02 80 08 31 31 31 31 31 31 31 31");
        sw(app, "00 2C 02 80 08 31 31 31 31 31 31 31 31", 0x6982);
        ok(app, "00 20 00 80 08 31 31 31 31 31 31 31 31");
        ok(app, "00 24 00 80 0C 31 31 31 31 31 31 31 31 34 33 32 31");
        ok(app, "00 20 00 82 00");
        ok(app, "00 20 00 80 04 34 33 32 31");
        ok(app, "00 24 00 00 0C 34 33 32 31 31 31 31 31 31 31 31 31");
        ok(app, "00 20 00 80 08 31 31 31 31 31 31 31 31");
        sw(app, "00 2C 00 80 08 31 31 31 31 31 31 31 31", 0x6A88);
    });
}

#[test]
fn external_authentication() {
    run(|app| {
        personalize(app);
        sw(app, "00870000047C028100", 0x6985);
        assert_eq!(
            external_auth(app, "000000000000000000000000000000000000000000000000"),
            0x6982
        );
        sw(app, "008700000C7C0A82080000000000000000", 0x6985);
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 DB A0 12 04 DF 20 01 01");
        ok(app, "00 20 00 82 00");
        sw(app, "00 DB A0 12 04 DF 20 01 01", 0x6982);
    });
}

#[test]
fn mutual_authentication() {
    run(|app| {
        personalize(app);
        assert_eq!(
            mutual_auth(app, "000000000000000000000000000000000000000000000000"),
            0x6982
        );
        assert_eq!(mutual_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 DB A0 14 04 DF 40 01 01");
        assert_eq!(ok(app, "00 CB A0 14 04 5C 02 DF 40 00"), hex("DF 40 01 01"));
    });
}

#[test]
fn challenge_is_dropped_by_other_commands() {
    run(|app| {
        personalize(app);
        ok(app, "002281A403830180");
        let challenge = ok(app, "00870000047C028100");
        let mut response: [u8; 8] = challenge[4..12].try_into().unwrap();
        tdes(&hex(ADMIN_KEY), &mut response, true);
        ok(app, "00 CB 2F 01 02 5C 00 00");
        let mut apdu = hex("008700000C7C0A8208");
        apdu.extend_from_slice(&response);
        assert_eq!(transmit(app, &apdu).1, 0x6985);
    });
}

#[test]
fn admin_key_rules() {
    run(|app| {
        personalize(app);
        sw(app, "002281B603840180", 0x6A81);
        sw(app, "002281A403830181", 0x6A88);
        sw(
            app,
            &std::format!("00DB3FFF267024840180A51F8718{ADMIN_KEY}8803000000"),
            0x6982,
        );
        sw(
            app,
            "00E000001C621A8201188302B0818C04870020FFA50BA4098001028301819501C0",
            0x6982,
        );
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(
            app,
            "00E000001C621A8201188302B0818C04870020FFA50BA4098001028301819501C0",
        );
        sw(
            app,
            &std::format!("00DB3FFF267024840181A51F8718{ADMIN_KEY}8803000000"),
            0x6A80,
        );
        ok(app, "00DB3FFF0770058401 81A500");
    });
}

#[test]
fn terminate() {
    run(|app| {
        personalize(app);
        sw(app, "00 E6 00 00", 0x6982);
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 E6 00 00");
        sw(app, "00A4040409A0000003974254465900", 0x6285);
        assert_eq!(
            ok(app, "00 CB A0 12 04 5C 02 DF 20 00"),
            hex("DF 20 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        );
        sw(app, "00 CB A0 13 02 5C 00 00", 0x6982);
        sw(app, "00 DB A0 10 04 DF 22 01 01", 0x6985);
        sw(app, "002281A403830180", 0x6985);
    });
}

const KEY_FILE_RSA2048: &str = "00E000004962478201188302B0818C058F10101000A537B8098001078301819501 40B8098001878301819501 40B8098001478301819501 40B6098001178301819501 40B6098001578301819501 40";

fn find_tlv(data: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    let mut data = data;
    while !data.is_empty() {
        let (t, value, rest) = crate::tlv::take_tlv(data)?;
        if t == tag {
            return Some(value.to_vec());
        }
        data = rest;
    }
    None
}

fn ec_key_file(algorithm: u8, limit: Option<u16>) -> Vec<u8> {
    let mut crt = hex(&std::format!("8001{algorithm:02X}830181950140"));
    if let Some(limit) = limit {
        crt.extend_from_slice(&[0xA3, 0x04, 0x90, 0x02]);
        crt.extend_from_slice(&limit.to_be_bytes());
    }
    let mut a5 = std::vec![0xB6, crt.len() as u8];
    a5.extend_from_slice(&crt);
    let mut fcp = hex("8201188302B0818C058F10101000");
    fcp.push(0xA5);
    fcp.push(a5.len() as u8);
    fcp.extend_from_slice(&a5);
    let mut apdu = std::vec![
        0x00,
        0xE0,
        0x00,
        0x00,
        fcp.len() as u8 + 2,
        0x62,
        fcp.len() as u8
    ];
    apdu.extend_from_slice(&fcp);
    apdu
}

fn ready(app: &mut App<'_>) {
    personalize(app);
    ok(app, "00 20 00 82 00");
    ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
}

fn generate(app: &mut App<'_>, algorithm: u8) -> Vec<u8> {
    let apdu = std::vec![
        0x00, 0x47, 0x00, 0x00, 0x08, 0xAC, 0x06, 0x80, 0x01, algorithm, 0x83, 0x01, 0x81, 0x00
    ];
    let (data, status) = transmit(app, &apdu);
    assert_eq!(status, 0x9000);
    let public = find_tlv(&data, &[0x7F, 0x49]).unwrap();
    assert_eq!(
        ok(app, "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00"),
        data
    );
    public
}

fn pso(app: &mut App<'_>, p1p2: &str, data: &[u8]) -> (Vec<u8>, u16) {
    let mut apdu = hex(&std::format!("002A{p1p2}"));
    if data.len() < 256 {
        apdu.push(data.len() as u8);
    } else {
        apdu.extend_from_slice(&[0x00, (data.len() >> 8) as u8, data.len() as u8]);
    }
    apdu.extend_from_slice(data);
    transmit(app, &apdu)
}

#[test]
fn ecdsa_p256_and_p384() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    run(|app| {
        ready(app);
        assert_eq!(transmit(app, &ec_key_file(0x1C, None)).1, 0x9000);
        ok(app, "0044000000");
        sw(
            app,
            "002A9E9A20 0000000000000000000000000000000000000000000000000000000000000000",
            0x6985,
        );
        let public = generate(app, 0x0C);
        let point = find_tlv(&public, &[0x86]).unwrap();
        assert_eq!(point.len(), 65);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        ok(app, "002241B606 80011C 840181");
        let hash = [0x42u8; 32];
        let (signature, status) = pso(app, "9E9A", &hash);
        assert_eq!(status, 0x9000);
        let signature = p256::ecdsa::Signature::from_der(&signature).unwrap();
        key.verify_prehash(&hash, &signature).unwrap();
        assert_eq!(pso(app, "9E9A", &[1; 8]).1, 0x6A80);
        sw(app, "002241B606 80011D 840181", 0x6A80);

        ok(app, "00 A4 00 0C 02 B0 81");
        ok(app, "00 E4 00 00");
        assert_eq!(transmit(app, &ec_key_file(0x1D, None)).1, 0x9000);
        sw(app, "00 47 00 00 08 AC 06 80 01 0C 83 01 81 00", 0x6A86);
        let public = generate(app, 0x0D);
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&find_tlv(&public, &[0x86]).unwrap())
            .unwrap();
        ok(app, "002241B606 80011D 840181");
        let hash = [0x24u8; 48];
        let (signature, status) = pso(app, "9E9A", &hash);
        assert_eq!(status, 0x9000);
        key.verify_prehash(
            &hash,
            &p384::ecdsa::Signature::from_der(&signature).unwrap(),
        )
        .unwrap();
    });
}

#[test]
fn key_environment_rules() {
    run(|app| {
        ready(app);
        assert_eq!(transmit(app, &ec_key_file(0x1C, Some(1))).1, 0x9000);
        ok(app, "0044000000");
        sw(app, "002241B606 80011C 840181", 0x6A88);
        ok(app, "00 20 00 82 00");
        sw(app, "00 47 00 00 08 AC 06 80 01 0C 83 01 81 00", 0x6982);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        generate(app, 0x0C);
        sw(app, "00 47 00 00 08 AC 06 80 01 06 83 01 81 00", 0x6A80);
        ok(app, "002241B606 80011C 840181");
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x9000);
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x6982);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x9000);
        ok(app, "00 20 00 82 00");
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x6985);
        sw(app, "002241B606 80011C 840181", 0x6982);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        ok(app, "002241B606 80011C 840181");
        assert_eq!(pso(app, "8086", &[1; 32]).1, 0x6985);
        sw(app, "002241B806 80011C 840181", 0x6A80);
        ok(app, "00 A4 00 0C 02 B0 81");
        ok(app, "00 E4 00 00");
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x6985);
        sw(
            app,
            "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00",
            0x6A88,
        );
    });
}

#[test]
fn rsa2048_sign_and_decrypt() {
    use rsa::{traits::PublicKeyParts, BigUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPublicKey};
    run(|app| {
        ready(app);
        ok(app, KEY_FILE_RSA2048);
        ok(app, "00 44 00 00");
        let public = generate(app, 0x07);
        let n = find_tlv(&public, &[0x81]).unwrap();
        let e = find_tlv(&public, &[0x82]).unwrap();
        assert_eq!(n.len(), 256);
        let key =
            RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();

        let digest_info = hex("3031300D060960864801650304020105000420 CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
        ok(app, "002241B606 800157 840181");
        let (signature, status) = pso(app, "9E9A", &digest_info);
        assert_eq!(status, 0x9000);
        key.verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, &signature)
            .unwrap();

        ok(app, "002241B606 800157 840181");
        let tls = [0xCCu8; 36];
        let (signature, status) = pso(app, "9E9A", &tls);
        assert_eq!(status, 0x9000);
        key.verify(Pkcs1v15Sign::new_unprefixed(), &tls, &signature)
            .unwrap();

        ok(app, "002241B606 800117 840181");
        let mut block = std::vec![0u8; 256];
        block[255] = 7;
        let (signature, status) = pso(app, "9E9A", &block);
        assert_eq!(status, 0x9000);
        let recovered = BigUint::from_bytes_be(&signature).modpow(key.e(), key.n());
        assert_eq!(recovered, BigUint::from(7u32));

        let mut rng =
            <rand_chacha::ChaCha8Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(1);
        let message = b"test1234567890";

        ok(app, "002241B806 800147 840181");
        let ciphertext = key.encrypt(&mut rng, Pkcs1v15Encrypt, message).unwrap();
        let (plain, status) = pso(app, "8086", &ciphertext);
        assert_eq!(status, 0x9000);
        assert_eq!(plain, message);

        ok(app, "002241B806 800187 840181");
        let ciphertext = key
            .encrypt(&mut rng, Oaep::new::<sha1::Sha1>(), message)
            .unwrap();
        let (plain, status) = pso(app, "8086", &ciphertext);
        assert_eq!(status, 0x9000);
        assert_eq!(plain, message);
        let mut tampered = ciphertext.clone();
        tampered[10] ^= 1;
        assert_eq!(pso(app, "8086", &tampered).1, 0x6A80);

        ok(app, "002241B806 800107 840181");
        let ciphertext = key.encrypt(&mut rng, Pkcs1v15Encrypt, message).unwrap();
        let (plain, status) = pso(app, "8086", &ciphertext);
        assert_eq!(status, 0x9000);
        assert_eq!(plain.len(), 256);
        assert_eq!(&plain[256 - message.len()..], message);
        assert_eq!(pso(app, "8086", &ciphertext[1..]).1, 0x6A80);

        ok(app, "002241B806 800147 840181");
        let ciphertext = key.encrypt(&mut rng, Pkcs1v15Encrypt, message).unwrap();
        let mut indicated = std::vec![0x00];
        indicated.extend_from_slice(&ciphertext);
        let (plain, status) = pso(app, "8086", &indicated);
        assert_eq!(status, 0x9000);
        assert_eq!(plain, message);
        indicated[0] = 0x01;
        assert_eq!(pso(app, "8086", &indicated).1, 0x6A80);
        let mut too_long = std::vec![0x00, 0x00];
        too_long.extend_from_slice(&ciphertext);
        assert_eq!(pso(app, "8086", &too_long).1, 0x6A80);
    });
}

#[test]
fn ecdsa_with_offcard_hash_bit_cleared() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    run(|app| {
        ready(app);

        assert_eq!(transmit(app, &ec_key_file(0x0C, None)).1, 0x9000);
        ok(app, "0044000000");
        let public = generate(app, 0x0C);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&find_tlv(&public, &[0x86]).unwrap())
            .unwrap();
        sw(app, "002241B606 80011C 840181", 0x6A80);
        ok(app, "002241B606 80010C 840181");
        let hash = [0x5Au8; 32];
        let (signature, status) = pso(app, "9E9A", &hash);
        assert_eq!(status, 0x9000);
        key.verify_prehash(
            &hash,
            &p256::ecdsa::Signature::from_der(&signature).unwrap(),
        )
        .unwrap();

        ok(app, "00 A4 00 0C 02 B0 81");
        ok(app, "00 E4 00 00");

        assert_eq!(transmit(app, &ec_key_file(0x0D, None)).1, 0x9000);
        ok(app, "0044000000");
        let public = generate(app, 0x0D);
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&find_tlv(&public, &[0x86]).unwrap())
            .unwrap();
        sw(app, "002241B606 80011D 840181", 0x6A80);
        ok(app, "002241B606 80010D 840181");
        let hash = [0xA5u8; 48];
        let (signature, status) = pso(app, "9E9A", &hash);
        assert_eq!(status, 0x9000);
        key.verify_prehash(
            &hash,
            &p384::ecdsa::Signature::from_der(&signature).unwrap(),
        )
        .unwrap();
    });
}

fn der(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    match value.len() {
        0..=0x7F => out.push(value.len() as u8),
        0x80..=0xFF => out.extend_from_slice(&[0x81, value.len() as u8]),
        _ => out.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]),
    }
    out.extend_from_slice(value);
    out
}

fn put_key(reference: u8, key_type: u8, transport: u8, value: &[u8]) -> Vec<u8> {
    let mut template = der(&[0x83], &[key_type]);
    template.extend(der(&[0x84], &[transport]));
    template.extend(der(&[0x87], value));
    let mut usage = der(&[0x84], &[reference]);
    usage.extend(der(&[0xA5], &template));
    put_data(0x3FFF, &der(&[0x70], &usage))
}

fn ec_private_key(scalar: &[u8], point: &[u8], rfc5915: bool) -> Vec<u8> {
    let mut body = der(&[0x02], &[0x01]);
    body.extend(der(&[0x04], scalar));
    if rfc5915 {
        let mut bits = std::vec![0x00];
        bits.extend_from_slice(point);
        body.extend(der(&[0xA1], &der(&[0x03], &bits)));
    } else {
        body.extend(der(&[0x04], point));
    }
    der(&[0x30], &body)
}

#[test]
fn import_rsa2048() {
    use rsa::{
        pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign,
        RsaPrivateKey,
    };
    run(|app| {
        ready(app);
        ok(app, KEY_FILE_RSA2048);
        ok(app, "00 44 00 00");
        let mut rng =
            <rand_chacha::ChaCha8Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(7);
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = private.to_public_key();
        let pkcs1 = private.to_pkcs1_der().unwrap();

        assert_eq!(
            transmit(app, &put_key(0x81, 0x02, 0x05, pkcs1.as_bytes())).1,
            0x6A81
        );

        let mut tampered = pkcs1.as_bytes().to_vec();
        let n_offset = tampered
            .windows(3)
            .position(|w| w == [0x02, 0x82, 0x01])
            .unwrap()
            + 10;
        tampered[n_offset] ^= 0x01;
        assert_eq!(
            transmit(app, &put_key(0x81, 0x02, 0x00, &tampered)).1,
            0x6A80
        );
        sw(
            app,
            "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00",
            0x6A88,
        );

        assert_eq!(
            transmit(app, &put_key(0x81, 0x02, 0x00, pkcs1.as_bytes())).1,
            0x9000
        );
        let read = ok(app, "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00");
        let template = find_tlv(&read, &[0x7F, 0x49]).unwrap();
        assert_eq!(
            find_tlv(&template, &[0x81]).unwrap(),
            public.n().to_bytes_be()
        );
        assert_eq!(
            find_tlv(&template, &[0x82]).unwrap(),
            public.e().to_bytes_be()
        );

        let digest_info = hex("3031300D060960864801650304020105000420 1111111111111111111111111111111111111111111111111111111111111111");
        ok(app, "002241B606 800157 840181");
        let (signature, status) = pso(app, "9E9A", &digest_info);
        assert_eq!(status, 0x9000);
        public
            .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, &signature)
            .unwrap();

        ok(app, "002241B806 800147 840181");
        let ciphertext = public
            .encrypt(&mut rng, Pkcs1v15Encrypt, b"imported")
            .unwrap();
        assert_eq!(pso(app, "8086", &ciphertext).0, b"imported");
        ok(app, "002241B806 800187 840181");
        let ciphertext = public
            .encrypt(&mut rng, Oaep::new::<sha1::Sha1>(), b"imported")
            .unwrap();
        assert_eq!(pso(app, "8086", &ciphertext).0, b"imported");

        ok(app, "00DB3FFF07700584018 1A500");
        sw(
            app,
            "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00",
            0x6A88,
        );
        sw(app, "002241B606 800157 840181", 0x6A88);
        assert_eq!(ok(app, "00 A4 00 04 02 B0 81 00")[11], 0x06);
    });
}

#[test]
fn import_ec_keys() {
    use p256::{ecdsa::signature::hazmat::PrehashVerifier, elliptic_curve::sec1::ToEncodedPoint};
    run(|app| {
        ready(app);
        assert_eq!(transmit(app, &ec_key_file(0x1C, None)).1, 0x9000);
        ok(app, "0044000000");

        let mut scalar = [0u8; 32];
        scalar[1] = 0x01;
        scalar[31] = 0x23;
        let secret = p256::SecretKey::from_slice(&scalar).unwrap();
        let point = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let verifying = p256::ecdsa::VerifyingKey::from(&secret.public_key());

        let mut wrong_point = point.to_vec();
        wrong_point[40] ^= 0x01;
        assert_eq!(
            transmit(
                app,
                &put_key(
                    0x81,
                    0x03,
                    0x00,
                    &ec_private_key(&scalar, &wrong_point, false)
                )
            )
            .1,
            0x6A80
        );
        sw(
            app,
            "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00",
            0x6A88,
        );

        for (encoding, rfc5915) in [(&scalar[1..], false), (&scalar[..], true)] {
            let key = ec_private_key(encoding, &point, rfc5915);
            assert_eq!(transmit(app, &put_key(0x81, 0x03, 0x00, &key)).1, 0x9000);
            let read = ok(app, "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00");
            let template = find_tlv(&read, &[0x7F, 0x49]).unwrap();
            assert_eq!(find_tlv(&template, &[0x86]).unwrap(), point.to_vec());
            ok(app, "002241B606 80011C 840181");
            let hash = [0x77u8; 32];
            let (signature, status) = pso(app, "9E9A", &hash);
            assert_eq!(status, 0x9000);
            verifying
                .verify_prehash(
                    &hash,
                    &p256::ecdsa::Signature::from_der(&signature).unwrap(),
                )
                .unwrap();
        }

        let secret384 = p384::SecretKey::from_slice(&[0x42; 48]).unwrap();
        let point384 = secret384
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(
            transmit(
                app,
                &put_key(
                    0x81,
                    0x03,
                    0x00,
                    &ec_private_key(&[0x42; 48], &point384, false)
                )
            )
            .1,
            0x6A80
        );

        ok(app, "00 A4 00 0C 02 B0 81");
        ok(app, "00 E4 00 00");
        assert_eq!(transmit(app, &ec_key_file(0x1D, None)).1, 0x9000);
        ok(app, "0044000000");
        assert_eq!(
            transmit(
                app,
                &put_key(
                    0x81,
                    0x03,
                    0x00,
                    &ec_private_key(&[0x42; 48], &point384, true)
                )
            )
            .1,
            0x9000
        );
        ok(app, "002241B606 80011D 840181");
        let hash = [0x11u8; 48];
        let (signature, status) = pso(app, "9E9A", &hash);
        assert_eq!(status, 0x9000);
        p384::ecdsa::VerifyingKey::from(&secret384.public_key())
            .verify_prehash(
                &hash,
                &p384::ecdsa::Signature::from_der(&signature).unwrap(),
            )
            .unwrap();
    });
}

fn random_apdu(rng: &mut rand_chacha::ChaCha8Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    use rand_chacha::rand_core::RngCore;
    const INSTRUCTIONS: [u8; 15] = [
        0xA4, 0xCB, 0xDB, 0xE0, 0x44, 0xE4, 0xE6, 0x20, 0x24, 0x2C, 0x22, 0x87, 0x47, 0x2A, 0xC0,
    ];
    const PARAMETERS: [u8; 16] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x0C, 0x3F, 0xFF, 0x41, 0x81, 0x80, 0x86, 0x9E, 0x9A, 0xA4,
        0xB6,
    ];
    let pick = |rng: &mut rand_chacha::ChaCha8Rng, len: usize| (rng.next_u32() as usize) % len;
    let (header, mut data) = if !seeds.is_empty() && rng.next_u32() % 2 == 0 {
        let seed = &seeds[pick(rng, seeds.len())];
        let mut data = seed[4..].to_vec();
        for _ in 0..1 + pick(rng, 4) {
            if data.is_empty() {
                break;
            }
            let index = pick(rng, data.len());
            match rng.next_u32() % 4 {
                0 => data[index] ^= 1 << (rng.next_u32() % 8),
                1 => data[index] = rng.next_u32() as u8,
                2 => data.truncate(index),
                _ => data.insert(index, rng.next_u32() as u8),
            }
        }
        ([seed[0], seed[1], seed[2], seed[3]], data)
    } else {
        let mut data = std::vec![0u8; pick(rng, 300)];
        rng.fill_bytes(&mut data);
        let mut header = [0u8; 4];
        header[1] = INSTRUCTIONS[pick(rng, INSTRUCTIONS.len())];
        header[2] = PARAMETERS[pick(rng, PARAMETERS.len())];
        header[3] = PARAMETERS[pick(rng, PARAMETERS.len())];
        (header, data)
    };
    data.truncate(4000);
    let mut apdu = header.to_vec();
    if data.is_empty() {
        apdu.push(0x00);
    } else if data.len() < 256 {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(&data);
        apdu.push(0x00);
    } else {
        apdu.extend_from_slice(&[0x00, (data.len() >> 8) as u8, data.len() as u8]);
        apdu.extend_from_slice(&data);
        apdu.extend_from_slice(&[0x00, 0x00]);
    }
    apdu
}

#[test]
fn robustness_against_malformed_apdus() {
    run(|app| {
        ready(app);
        assert_eq!(transmit(app, &ec_key_file(0x1C, None)).1, 0x9000);
        ok(app, "0044000000");
        generate(app, 0x0C);
        let seeds: Vec<Vec<u8>> = [
            "00E000000E620C8201398302A0208C03033000",
            "00DBA0100BDF21086d73637000000000",
            "00CBA010045C02DF2100",
            "00CB3FFF045C027F7200",
            "00CB3FFF0A700884018 1A5037F4980",
            "00DB3FFF267024840180A51F8718010203040506070801020304050607080102030405060708 8803B073DC",
            "002281A403830180",
            "00870000047C028100",
            "008700000C7C0A82080000000000000000",
            "00870000147C12811000000000000000000000000000000000",
            "002241B60680011C840181",
            "002A9E9A20 1111111111111111111111111111111111111111111111111111111111111111",
            "002A80860401020304",
            "00470000 08 AC0680010C830181",
            "00200080083132333435363738",
            "0024008010313233343536373831323334353637",
            "002C0280083837363534333231",
            "00A4000402B081",
        ]
        .iter()
        .map(|apdu| {
            let bytes = hex(apdu);
            let data_len = bytes[4] as usize;
            let mut seed = bytes[..4].to_vec();
            seed.extend_from_slice(&bytes[5..5 + data_len.min(bytes.len() - 5)]);
            seed
        })
        .collect();
        let mut rng =
            <rand_chacha::ChaCha8Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(0x6D5);
        let mut accepted = 0;
        for round in 0..6000 {
            let apdu = random_apdu(&mut rng, &seeds);
            if CommandView::try_from(apdu.as_slice()).is_err() {
                continue;
            }
            let (_, status) = transmit(app, &apdu);
            if status == 0x9000 {
                accepted += 1;
            }
            if round % 500 == 0 {
                exec(app, "00A4040409A0000003974254465900");
                exec(app, "002281A403830180");
                if let (challenge, 0x9000) = exec(app, "00870000047C028100") {
                    if challenge.len() == 12 {
                        let mut response: [u8; 8] = challenge[4..12].try_into().unwrap();
                        tdes(&hex(ADMIN_KEY), &mut response, true);
                        let mut apdu = hex("008700000C7C0A8208");
                        apdu.extend_from_slice(&response);
                        transmit(app, &apdu);
                        exec(app, "00 2C 02 80 08 31 32 33 34 35 36 37 38");
                    }
                }
                exec(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
            }
        }
        assert!(accepted > 0);
        let (_, status) = exec(app, "00A4040409A0000003974254465900");
        assert!(status == 0x9000 || status == 0x6285, "{status:04X}");
    });
}

fn create_key_file(
    app: &mut App<'_>,
    reference: u8,
    acl: &str,
    crts: &[(u8, u8, Option<u16>)],
) -> u16 {
    let mut a5 = Vec::new();
    for &(tag, algorithm, limit) in crts {
        let mut crt = std::vec![0x80, 0x01, algorithm, 0x83, 0x01, reference, 0x95, 0x01, 0x40];
        if let Some(limit) = limit {
            crt.extend_from_slice(&[0xA3, 0x04, 0x90, 0x02]);
            crt.extend_from_slice(&limit.to_be_bytes());
        }
        a5.extend(der(&[tag], &crt));
    }
    let mut fcp = der(&[0x82], &[0x18]);
    fcp.extend(der(&[0x83], &[0xB0, reference]));
    fcp.extend(der(&[0x8C], &hex(acl)));
    fcp.extend(der(&[0xA5], &a5));
    let body = der(&[0x62], &fcp);
    let mut apdu = std::vec![0x00, 0xE0, 0x00, 0x00, body.len() as u8];
    apdu.extend_from_slice(&body);
    transmit(app, &apdu).1
}

#[test]
fn multi_object_put_data_validates_before_writing() {
    run(|app| {
        ready(app);
        let mut data = hex("DF 30 02 AA BB");
        data.extend(hex("DF 22 00"));
        data.extend(hex("DF 31 01 01"));
        data.extend(hex("DF 31 01 02"));
        assert_eq!(transmit(app, &put_data(0xA010, &data)).1, 0x9000);
        assert_eq!(
            ok(app, "00 CB A0 10 04 5C 02 DF 30 00"),
            hex("DF 30 02 AA BB")
        );
        sw(app, "00 CB A0 10 04 5C 02 DF 22 00", 0x6A88);
        assert_eq!(ok(app, "00 CB A0 10 04 5C 02 DF 31 00"), hex("DF 31 01 02"));

        let mut data = hex("DF 30 01 CC");
        data.extend(hex("70 03 80 01 01"));
        assert_eq!(transmit(app, &put_data(0xA010, &data)).1, 0x6A80);
        assert_eq!(
            ok(app, "00 CB A0 10 04 5C 02 DF 30 00"),
            hex("DF 30 02 AA BB")
        );

        let mut data = hex("DF 30 01 DD");
        data.extend(hex("DF 20 01 EE"));
        assert_eq!(transmit(app, &put_data(0x3FFF, &data)).1, 0x6982);
        assert_eq!(
            ok(app, "00 CB A0 10 04 5C 02 DF 30 00"),
            hex("DF 30 02 AA BB")
        );
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        assert_eq!(transmit(app, &put_data(0x3FFF, &data)).1, 0x9000);
        assert_eq!(ok(app, "00 CB A0 10 04 5C 02 DF 30 00"), hex("DF 30 01 DD"));
        assert_eq!(ok(app, "00 CB A0 12 04 5C 02 DF 20 00"), hex("DF 20 01 EE"));
    });
}

#[test]
fn put_data_3fff_keeps_current_ef_and_nested_objects_are_checked() {
    run(|app| {
        ready(app);
        ok(app, "00 A4 00 0C 02 A0 12");
        ok(app, "00 DB 3F FF 04 DF 22 01 09");
        assert_eq!(
            ok(app, "00 CB 00 00 04 5C 02 DF 20 00"),
            hex("DF 20 10 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        );
        sw(app, "00 DB A0 10 05 70 03 01 02 03", 0x6A80);
        sw(app, "00 DB A0 10 05 70 03 80 01 01", 0x6A80);
        ok(app, "00 DB A0 10 08 70 06 80 01 01 81 01 02");
        ok(app, "00 DB A0 10 03 7F 21 00");
    });
}

#[test]
fn select_next_occurrence_walks_files() {
    run(|app| {
        ready(app);
        ok(app, "00 A4 00 0C 02 3F FF");
        let mut seen = Vec::new();
        loop {
            let (fcp, status) = exec(app, "00 A4 00 06 00");
            if status == 0x6A82 {
                break;
            }
            assert_eq!(status, 0x9000);
            let inner = find_tlv(&fcp, &[0x62]).unwrap();
            seen.push(find_tlv(&inner, &[0x83]).unwrap());
        }
        assert_eq!(
            seen,
            [
                hex("A000"),
                hex("A010"),
                hex("A011"),
                hex("A012"),
                hex("A013"),
                hex("A014"),
                hex("B080")
            ]
        );
        sw(app, "00 A4 00 06 02 A0 10", 0x6A87);
    });
}

#[test]
fn lifecycle_and_create_validation() {
    run(|app| {
        ready(app);
        sw(app, "00 E0 00 00", 0x6700);
        sw(app, "00 44 01 00", 0x6985);
        assert_eq!(
            create_key_file(app, 0x81, "8F10101000", &[(0xB6, 0x16, None)]),
            0x6A80
        );
        assert_eq!(
            create_key_file(app, 0x81, "8F10101000", &[(0xB6, 0x1E, None)]),
            0x6A80
        );
        assert_eq!(
            create_key_file(app, 0x81, "8F10101000", &[(0xB8, 0x8C, None)]),
            0x6A80
        );
        assert_eq!(
            create_key_file(app, 0x81, "8F10101000", &[(0xA4, 0x03, None)]),
            0x6A80
        );
        assert_eq!(
            create_key_file(
                app,
                0x81,
                "8F10101000",
                &[(0xB6, 0x17, None), (0xB8, 0x48, None)]
            ),
            0x6A80
        );
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        assert_eq!(
            create_key_file(
                app,
                0x81,
                "8F10101000",
                &[(0xA4, 0x02, None), (0xB6, 0x17, None)]
            ),
            0x6A80
        );
        let many: Vec<(u8, u8, Option<u16>)> =
            [0x07, 0x47, 0x87, 0x07, 0x47, 0x87, 0x07, 0x47, 0x87, 0x07]
                .into_iter()
                .map(|algorithm| (0xB8, algorithm, Some(5)))
                .chain([(0xB6, 0x17, Some(5)), (0xB6, 0x57, Some(5))])
                .collect();
        assert_eq!(create_key_file(app, 0x82, "8F10101000", &many), 0x9000);
        let fcp = ok(app, "00 A4 00 04 02 B0 82 00");
        assert!(fcp.len() > 200);
        ok(app, "00 E6 00 00");
        sw(app, "00 20 00 80 08 31 32 33 34 35 36 37 38", 0x6985);
        ok(app, "00 20 00 82 00");
    });
}

#[test]
fn usage_counters_are_per_key_and_pin_bound() {
    run(|app| {
        ready(app);
        assert_eq!(
            create_key_file(app, 0x81, "8F10101000", &[(0xB6, 0x1C, Some(1))]),
            0x9000
        );
        ok(app, "00 44 00 00");
        ok(app, "00 47 00 00 08 AC 06 80 01 0C 83 01 81 00");
        assert_eq!(
            create_key_file(app, 0x82, "8F10101000", &[(0xB8, 0x47, None)]),
            0x9000
        );
        ok(app, "00 44 00 00");
        assert_eq!(
            create_key_file(app, 0x83, "8F10001000", &[(0xB6, 0x1C, Some(1))]),
            0x9000
        );
        ok(app, "00 44 00 00");
        ok(app, "00 47 00 00 08 AC 06 80 01 0C 83 01 83 00");

        ok(app, "002241B606 80011C 840181");
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x9000);
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x6982);
        ok(
            app,
            "00 24 00 80 10 31 32 33 34 35 36 37 38 31 32 33 34 35 36 37 38",
        );
        assert_eq!(pso(app, "9E9A", &[1; 32]).1, 0x9000);

        ok(app, "002241B606 80011C 840183");
        for _ in 0..3 {
            assert_eq!(pso(app, "9E9A", &[2; 32]).1, 0x9000);
        }
    });
}

#[test]
fn pin_length_recovers_after_interrupted_change() {
    run(|app| {
        ready(app);
        let mut state = crate::store::load_state(&mut app.trussed).unwrap();
        state.pending_pin_len = 12;
        crate::store::save_state(&mut app.trussed, &state).unwrap();
        app.state = None;
        ok(app, "00A4040409A0000003974254465900");
        ok(
            app,
            "00 24 00 80 12 31 32 33 34 35 36 37 38 39 39 39 39 39 39 39 39 39 39",
        );
        assert_eq!(
            crate::store::load_state(&mut app.trussed).unwrap().pin_len,
            10
        );

        let mut state = crate::store::load_state(&mut app.trussed).unwrap();
        state.pin_len = 9;
        crate::store::save_state(&mut app.trussed, &state).unwrap();
        app.state = None;
        ok(app, "00A4040409A0000003974254465900");
        ok(app, "00 20 00 80 0A 39 39 39 39 39 39 39 39 39 39");
        assert_eq!(
            crate::store::load_state(&mut app.trussed).unwrap().pin_len,
            10
        );
        ok(
            app,
            "00 24 00 80 12 39 39 39 39 39 39 39 39 39 39 31 32 33 34 35 36 37 38",
        );
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
    });
}

fn assert_blank(app: &mut App<'_>) {
    let fcp = ok(app, "00 A4 04 04 09 A0 00 00 03 97 42 54 46 59 00");
    assert_eq!(
        find_tlv(&find_tlv(&fcp, &[0x62]).unwrap(), &[0x8A]).unwrap(),
        [0x03]
    );
    sw(app, "00 CB 3F FF 04 5C 02 7F 72 00", 0x6A88);
    sw(app, "00 A4 00 0C 02 B0 80", 0x6A82);
    sw(app, "00 A4 00 0C 02 B0 81", 0x6A82);
    sw(app, "00 CB A0 00 04 5C 02 DF 1F 00", 0x6A82);
    sw(app, "00 A4 00 06 00", 0x6A82);
}

fn personalized_with_key(app: &mut App<'_>) {
    ready(app);
    assert_eq!(transmit(app, &ec_key_file(0x1C, None)).1, 0x9000);
    ok(app, "0044000000");
    generate(app, 0x0C);
}

#[test]
fn reset_requires_authorization_and_wipes_everything() {
    run(|app| {
        personalized_with_key(app);
        sw(app, "00 FB 01 00", 0x6A86);
        sw(app, "00 FB 00 00 01 00", 0x6700);
        sw(app, "00 FB 00 00", 0x6982);
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 FB 00 00");
        assert_blank(app);
        personalize(app);
        ok(app, "00 20 00 80 08 31 32 33 34 35 36 37 38");
        sw(
            app,
            "00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00",
            0x6A88,
        );
    });
}

#[test]
fn reset_with_blocked_pin_terminated_or_initialization() {
    run(|app| {
        personalized_with_key(app);
        ok(app, "00 20 00 82 00");
        for expected in [0x63C2, 0x63C1, 0x63C0] {
            sw(app, "00 20 00 80 08 30 30 30 30 30 30 30 30", expected);
        }
        ok(app, "00 FB 00 00");
        assert_blank(app);

        ok(app, "00 FB 00 00");
        assert_blank(app);

        personalize(app);
        assert_eq!(external_auth(app, ADMIN_KEY), 0x9000);
        ok(app, "00 E6 00 00");
        sw(app, "00A4040409A0000003974254465900", 0x6285);
        ok(app, "00 FB 00 00");
        assert_blank(app);
    });
}

#[test]
fn interrupted_reset_resumes() {
    run(|app| {
        personalized_with_key(app);
        crate::store::begin_reset(&mut app.trussed).unwrap();
        app.state = None;
        ok(app, "00A4040409A0000003974254465900");
        assert_blank(app);
        assert!(!crate::store::reset_pending(&mut app.trussed).unwrap());
    });
}

#[test]
fn reset_leaves_other_clients_untouched() {
    use trussed_auth::AuthClient as _;
    use trussed_core::{
        types::{Location, Mechanism, Message, PathBuf, StorageAttributes},
        CryptoClient as _, FilesystemClient as _,
    };
    virt::with_platform(StoreConfig::ram(), |platform| {
        platform.run_clients_with_backends(
            [("gids", dispatch::BACKENDS), ("other", dispatch::BACKENDS)],
            dispatch::Dispatch::default(),
            |[gids, mut other]| {
                let path = PathBuf::try_from("data").unwrap();
                for location in [Location::Internal, Location::External, Location::Volatile] {
                    syscall!(other.write_file(
                        location,
                        path.clone(),
                        Message::try_from(&b"keep"[..]).unwrap(),
                        None
                    ))
                    .unwrap();
                }
                let mut keys = Vec::new();
                for location in [Location::Internal, Location::External] {
                    keys.push(
                        syscall!(other.generate_key(
                            Mechanism::P256,
                            StorageAttributes::new().set_persistence(location)
                        ))
                        .unwrap()
                        .key,
                    );
                }
                syscall!(other.set_pin(
                    0u8,
                    trussed_auth::Pin::try_from(&b"87654321"[..]).unwrap(),
                    Some(3),
                    false
                ))
                .unwrap();

                let mut app = Gids::new(gids);
                personalized_with_key(&mut app);
                assert_eq!(external_auth(&mut app, ADMIN_KEY), 0x9000);
                ok(&mut app, "00 FB 00 00");
                assert_blank(&mut app);

                for location in [Location::Internal, Location::External, Location::Volatile] {
                    assert_eq!(
                        &syscall!(other.read_file(location, path.clone()))
                            .unwrap()
                            .data[..],
                        b"keep"
                    );
                }
                for key in keys {
                    assert!(syscall!(other.exists(Mechanism::P256, key)).unwrap().exists);
                }
                assert!(syscall!(other.has_pin(0u8)).unwrap().has_pin);
                assert!(
                    syscall!(other
                        .check_pin(0u8, trussed_auth::Pin::try_from(&b"87654321"[..]).unwrap()))
                    .unwrap()
                    .success
                );
            },
        )
    });
}
