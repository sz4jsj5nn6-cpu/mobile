#!/usr/bin/env bash
# Swap the kernel inside the stock boot image. Touches files only.
set -euo pipefail
cd "$(dirname "$0")"

IMG=${1:-out/Image}
[ -f "$IMG" ] || { echo "missing kernel image: $IMG" >&2; exit 1; }
[ -f backup/boot_a.img ] || { echo "missing backup/boot_a.img" >&2; exit 1; }

python3 tools/mkbootimg.py \
  --header_version 4 --os_version 14.0.0 --os_patch_level 2026-01 \
  --kernel "$IMG" --cmdline '' --output new_boot.img

ls -lh new_boot.img
python3 tools/unpack_bootimg.py --boot_img new_boot.img | head -8
