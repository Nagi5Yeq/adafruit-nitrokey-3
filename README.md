# Nitrokey 3 Firmware on Adafruit Feather nRF52840

Nitrokey 3 firmware built for the Adafruit Feather nRF52840 Express.

Hardware differences from the NK3AM:

- No SE050: all crypto runs on the software backends.
- No external SPI flash: the internal and external filesystems share the internal flash.

## Structure

| Path | Content |
|---|---|
| `crates/board-adafruit-nrf52840/` | Firmware binary |
| `crates/runner/` | Platform-independent runner |
| `crates/gids/` | GIDS v2.0 smart card app |
| `nk3/` | Upstream NK3 crates as git submodules |
| `bootloader/` | Adafruit nRF52 bootloader as a git submodule |
| `patches/` | Changes to `nk3/` and `bootloader/` submodules |
| `build.sh` | Applies patches and builds |

## Memory map

### Flash (1 MB)

| Region | Start | End | Size |
|---|---|---|---|
| MBR | 0x00000 | 0x01000 | 4 KB |
| SoftDevice S140 (not enabled) | 0x01000 | 0x27000 | 152 KB |
| Firmware | 0x27000 | 0xE0000 | 740 KB |
| Filesystem | 0xE0000 | 0xF4000 | 80 KB |
| Adafruit bootloader | 0xF4000 | 0x100000 | 48 KB |

- The external filesystem (EFS) is the `/external` directory and the internal one (IFS) is everything else. Both are `runner::store::{InternalFs, ExternalFs}`.

### RAM (256 KB)

| Region | Start | End | Size |
|---|---|---|---|
| MBR / SoftDevice reserved | 0x20000000 | 0x20008000 | 32 KB |
| Firmware | 0x20008000 | 0x20040000 | 224 KB |

## Bootloader

- The stock Adafruit bootloader for nRF52840 only keeps 0xEA000–0xF4000 (`DFU_APP_DATA_RESERVED=10*4096`). It treats 0x01000–0xEA000 as application flash, which includes 0xE0000–0xEA000 of the filesystem:
  - A bootloader update via UF2 stages the new bootloader at 0xE0000–0xEA000 before copying it, which corrupts the filesystem (keys, PINs, credentials).
  - Firmware updates (UF2 or serial DFU) only write the image itself and do not touch the filesystem.
- `patches/bootloader.patch` sets `DFU_APP_DATA_RESERVED=0x14000` for nRF52840 in `CMakeLists.txt` and `Makefile`, so the bootloader keeps 0xE0000–0xF4000.

## Usage

Build:

```sh
./build.sh             # apply patches, build release firmware
./build.sh bootloader  # apply patches, build the bootloader (needs arm-none-eabi-gcc and cmake in PATH)
./build.sh patch       # apply patches only
./build.sh clean       # revert patches
```

Output:

- Firmware: `target/thumbv7em-none-eabihf/release/board-adafruit-nrf52840`
- Bootloader (`feather_nrf52840_express`, S140 7.3.0): `target/bootloader/*.hex` and `target/bootloader/update-*.uf2`

Convert to UF2 (family `0xADA52840`, base `0x27000`):

```sh
arm-none-eabi-objcopy -O binary target/thumbv7em-none-eabihf/release/board-adafruit-nrf52840 firmware.bin
python3 uf2conv.py -c -b 0x27000 -f 0xADA52840 -o firmware.uf2 firmware.bin
```

## Ciphers

All algorithms run in software. RSA key generation is slow.

### FIDO2

| Algorithm | COSE |
|---|---|
| ES256 (P-256) | -7 |
| EdDSA (Ed25519) | -8 |
| ES384 (P-384) | -35 |

### OpenPGP

| Algorithm | Generate | Import |
|---|---|---|
| RSA-2048 | yes | yes |
| RSA-3072 | no | yes |
| RSA-4096 | no | yes |
| P-256 | yes | yes |
| P-384 | yes | yes |
| Ed25519 | yes | yes |
| X25519 | yes | yes |

### PIV

| Use | Algorithms |
|---|---|
| Key slots | RSA-2048, RSA-3072, RSA-4096, P-256, P-384 |
| Management key | TDES (default), AES-256 |

### GIDS

| Use | Algorithms |
|---|---|
| Key containers | RSA-2048, RSA-3072, RSA-4096, P-256, P-384 |
| Admin key | TDES |
