use std::{env, path::PathBuf};

use adafruit_memory_layout::{FLASH_BASE, FLASH_END, FS_BASE, FS_END};

fn main() {
    println!(
        "cargo:rustc-env=NK3_FIRMWARE_VERSION={}",
        utils::version_string("adafruit-nk3", env!("CARGO_PKG_VERSION"))
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let ld_dir = manifest_dir.join("ld");

    let template =
        std::fs::read_to_string(ld_dir.join("nrf52-memory-template.x")).expect("read template");
    let memory_x = template
        .replace("##FLASH_BASE##", &format!("{:#X}", FLASH_BASE))
        .replace("##FLASH_LENGTH##", &format!("{:#X}", FLASH_END - FLASH_BASE))
        .replace("##FS_BASE##", &format!("{:#X}", FS_BASE))
        .replace("##FS_LENGTH##", &format!("{:#X}", FS_END - FS_BASE));
    std::fs::write(out_dir.join("custom_memory.x"), memory_x).expect("write custom_memory.x");

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-search={}", ld_dir.display());
    println!("cargo:rustc-link-arg=-Tcortex-m-rt_0.7.5_link.x");
    // Without paging, lld does not map the ELF headers into a LOAD segment below
    // FLASH_BASE, which would place them inside the SoftDevice.
    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rerun-if-changed=ld/nrf52-memory-template.x");
}