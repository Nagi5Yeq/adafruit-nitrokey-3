#![no_std]

// Adafruit NRF52840 Feather Express memory layout
// with Nordic SoftDevice S140 + Adafruit UF2 bootloader
//
// Flash (1 MB):
//   MBR            0x00000 - 0x01000   (  4 KB)
//   SoftDevice     0x01000 - 0x27000   (152 KB)
//   App firmware   0x27000 - 0xE0000   (740 KB)
//   Filesystem     0xE0000 - 0xF4000   ( 80 KB)  internal + /external
//   Bootloader     0xF4000 - 0x100000  ( 48 KB)
//
// RAM (256 KB):
//   MBR/SD reserved  0x20000000 - 0x20008000  (32 KB)
//   App RAM          0x20008000 - 0x20040000  (224 KB)

pub const FLASH_BASE: usize = 0x27_000;
pub const FLASH_END: usize = 0xE0_000;
pub const FS_BASE: usize = 0xE0_000;
pub const FS_END: usize = 0xF4_000;
pub const RAM_BASE: usize = 0x2000_8000;
pub const RAM_END: usize = 0x2004_0000;
