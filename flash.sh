#!/usr/bin/env bash
# Destructive. Requires an explicit yes.
set -euo pipefail
cd "$(dirname "$0")"
[ -f new_boot.img ] || { echo "run pack.sh first" >&2; exit 1; }

echo "About to flash boot_a with new_boot.img"
echo "Rollback:  fastboot flash boot_a backup/boot_a.img"
read -r -p "type FLASH to continue: " answer
[ "$answer" = "FLASH" ] || { echo "aborted"; exit 1; }

adb reboot bootloader
fastboot flash boot_a new_boot.img
fastboot reboot
