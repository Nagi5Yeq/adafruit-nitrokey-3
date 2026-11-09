#!/bin/bash
set -euo pipefail
shopt -s nullglob

cd "$(dirname "$0")"

TARGET=thumbv7em-none-eabihf
NAME=board-adafruit-nrf52840
ELF=target/${TARGET}/release/${NAME}

apply_patches() {
    local patch dir
    for patch in patches/*.patch; do
        dir=nk3/$(basename "${patch}" .patch)
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
        dir=nk3/$(basename "${patch}" .patch)
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
    patch)
        apply_patches
        ;;
    clean)
        revert_patches
        ;;
    *)
        echo "Usage: $0 [build|patch|clean]" >&2
        exit 1
        ;;
esac
