# mobile

Custom GKI kernel build for `com.tencent.tmgp.dfm` device profiling work.

## What is in here

- `src/hlmem.c` — in-kernel address-space reader, built into the kernel image
  (`drivers/misc/`), no loadable module involved.
- `config/device_config` — the kernel config read back from the device itself
  (`/proc/config.gz`), used as the build baseline so the resulting image matches
  the running system.
- `.github/workflows/build.yml` — builds `Image` on a Linux runner with AOSP
  clang r487747c, the exact toolchain the device kernel was built with.

## Build

Actions → build-kernel → Run workflow. Default ref is the last kernel source
commit before 2025-12-12, which is the date of the running build.

## Flash

```
adb pull /dev/block/by-name/boot_a boot_a.img      # backup first
magiskboot unpack boot_a.img
magiskboot cpio ramdisk.cpio  # not needed: GKI keeps ramdisk in init_boot
cp Image kernel
magiskboot repack boot_a.img new_boot.img
fastboot flash boot_a new_boot.img
```

Rollback is `fastboot flash boot_a boot_a_backup.img`.
