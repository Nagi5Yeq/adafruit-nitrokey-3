#!/bin/bash
set -euo pipefail
shopt -s nullglob

cd "$(dirname "$0")"

TARGET=thumbv7em-none-eabihf
NAME=board-adafruit-nrf52840
ELF=target/${TARGET}/release/${NAME}

BOOTLOADER_BOARD=feather_nrf52840_express
BOOTLOADER_SD_VERSION=7.3.0
BOOTLOADER_BUILD_DIR=target/bootloader

patch_dir() {
    local name
    name=$(basename "$1" .patch)
    if [ "${name}" = bootloader ]; then
        echo bootloader
    else
        echo "nk3/${name}"
    fi
}

apply_patches() {
    local patch dir
    for patch in patches/*.patch; do
        dir=$(patch_dir "${patch}")
        if git -C "${dir}" apply --reverse --check "${PWD}/${patch}" 2>/dev/null; then
            continue
        fi
        echo "Applying ${patch} to ${dir}"
        git -C "${dir}" apply "${PWD}/${patch}"
    done
}

revert_patches() {
    local patch dir
    for patch in patches/*.patch; do
        dir=$(patch_dir "${patch}")
        if git -C "${dir}" apply --reverse --check "${PWD}/${patch}" 2>/dev/null; then
            echo "Reverting ${patch} from ${dir}"
            git -C "${dir}" apply --reverse "${PWD}/${patch}"
        elif git -C "${dir}" apply --check "${PWD}/${patch}" 2>/dev/null; then
            continue
        else
            echo "Skipping ${dir}: working tree matches neither the patched nor the clean state of ${patch}" >&2
        fi
    done
}

case "${1:-build}" in
    build)
        apply_patches
        cargo build --target ${TARGET} --release
        echo "Built ${ELF}"
        ;;
    bootloader)
        for tool in arm-none-eabi-gcc arm-none-eabi-objcopy cmake; do
            if ! command -v ${tool} >/dev/null; then
                echo "${tool} not found in PATH" >&2
                exit 1
            fi
        done
        apply_patches
        git -C bootloader submodule update --init
        cmake -S bootloader -B ${BOOTLOADER_BUILD_DIR} \
            -DBOARD=${BOOTLOADER_BOARD} \
            -DSD_VERSION=${BOOTLOADER_SD_VERSION}
        cmake --build ${BOOTLOADER_BUILD_DIR} -j"$(nproc)"
        ls -1 ${BOOTLOADER_BUILD_DIR}/*.hex ${BOOTLOADER_BUILD_DIR}/*.uf2
        ;;
    patch)
        apply_patches
        ;;
    clean)
        revert_patches
        ;;
    *)
        echo "Usage: $0 [build|bootloader|patch|clean]" >&2
        exit 1
        ;;
esac
