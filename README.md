# sysimage

**Declarative system image builder** — describe a whole disk layout, boot
artifacts and network-boot services in one YAML config, and `sysimage` builds
the content-addressed artifacts, writes a manifest, and installs everything
onto a disk image, a block device, a remote NBD export, or a machine over SSH.

The heavy lifting is pure Rust: GPT/MBR partitioning, FAT12/16/32, ext4,
EROFS, cpio/ustar archives, LUKS2 encryption, LVM2 metadata, dm-verity, UKI
stitching, Secure Boot signing and credential encryption all live in-process —
the only intentional external dependency is `podman`, for pulling container
images into the build.

## Pipeline

```
sysimage.config.yml ──build──▶ content-addressed artifacts + manifest (.json)
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
        install (local)         qemu-install / qemu-run   netboot / ssh-install
     disk image / block dev /     raw images + qemu.json   DHCP proxy, TFTP,
     NBD export                   UEFI boot under QEMU     HTTP, PXE
```

Everything is **content-addressed**: each built file is SHA-256 hashed and
stored as `<base64url-sha256>.bin`, and the manifest records its size and
hex digest, so rebuilds are reproducible and unchanged inputs are reused.

## Features

- **Declarative disk layout** — a tree of `gpt`/`mbr` partitions containing
  `fat`, `ext4`, `luks`, `lvm` and raw `image` blocks, with
  `sizeMin`/`sizeMax`/`sizeWeight` disk-space distribution.
- **Build artifacts** — EROFS images (optionally with dm-verity), cpio/ustar
  archives, Unified Kernel Images (pure-Rust `systemd-stub` stitching),
  verity tables, EFI Secure Boot signatures, and `encrypt`/`decrypt`/
  `reencrypt` credential envelopes (AES-256-GCM, see the `senc` crate).
- **Install anywhere** — local image files and block devices, remote NBD
  exports (`nbd://`, `nbd+tcp://`, `nbd+unix://`), or a remote machine over SSH
  (`ssh-install`, driving in-use remote devices through the remote kernel).
- **Smart install** — without `--wipe`, the installer *reconciles*: existing
  GPT partitions, LVM volume groups, LUKS2 containers and filesystems are
  matched by name and reused, and only missing pieces are created. In-use
  devices are handled through the kernel; `--wipe` (with optional `--force`)
  starts from scratch.
- **QEMU workflow** — `qemu-install` renders disk images plus a `qemu.json`
  boot description (UEFI firmware auto-resolved per architecture, optional
  vTPM via `swtpm`, direct-kernel boot, QEMU-only read-only disks);
  `qemu-run` boots it.
- **Network boot** — `netboot` serves the manifest's `netboot` section: a
  proxy DHCP server (PXE/HTTP-boot presets or raw options), TFTP and HTTP,
  with `${NETBOOT_IP}` resolved from the bind interface.
- **Secure Boot** — `sbkey-generate` creates a PK/KEK/db key set (optionally
  SENC-encrypted), and `efisign` build artifacts sign UKIs with
  authenticode-style signatures.
- **Validation** — JSON Schemas (Draft 2020-12) for the config, manifest and
  QEMU documents are generated from the Rust types (`sysimage schema`), and
  configs can `$schema`-reference them for editor completion.

## Requirements

- **Rust** — a recent stable toolchain (the crates use edition 2024).
- **Optional, for the full test suite** (tests skip gracefully when absent,
  see [Testing](#testing)):
  `podman`, `qemu-system-*` + UEFI firmware (OVMF), `qemu-utils` (`qemu-nbd`),
  `erofs-utils` (`fsck.erofs`, `dump.erofs`), `cryptsetup`, `veritysetup`
  (dmsetup), `lvm2` (`pvck`), `sbsigntools` (`sbsign`, `sbverify`) and
  `openssl`.

Build a release binary with:

```sh
cargo build --release
# binaries: target/release/sysimage, target/release/senc
```

## Usage

All commands are driven from a `sysimage.config.yml` (default path; override
with `-c`). The manifest is derived from the config automatically
(`<outputDirectory>/<name>.json`), or passed explicitly with `-m`.

```sh
# 1. Scaffold a config (and its JSON schema) — a complete default with every
#    field present; the commented reference defaults live in the repo at
#    src/model/default_config.yml.
sysimage init -c sysimage.config.yml

# 2. Build artifacts + manifest into ./output (content-addressed .bin files).
sysimage build -c sysimage.config.yml
#    Optional inputs, only needed when the config references them:
#    · `--param name=value` for build parameters — declare each one under
#      `parameters:` in the config first (an undeclared name is an error):
#        parameters:
#          hostname: { default: localhost }
#    · `--key` / `--key-file name=…` for LUKS passphrases and SENC key parts
#    · `--sign name=dir` (+ `--sign-key-file`) for Secure Boot signing keys
sysimage build -c sysimage.config.yml \
    --param hostname=myhost \
    --key-file luks=rootfs.key \
    --sign default=sbkeys --sign-key-file default=sbkeys.pass

# 3a. Install onto a local disk image or block device (reconciles by default).
sysimage install -c sysimage.config.yml -d bootdisk=/path/to/disk.img
sysimage install -c sysimage.config.yml -d bootdisk=/dev/sdX --wipe

# 3b. …or install into raw images and boot under QEMU.
sysimage qemu-install -c sysimage.config.yml          # writes ./qemu/{<disk>.img,qemu.json}
sysimage qemu-run -d qemu                             # boots it (UEFI, KVM if available)

# 3c. …or install onto a remote machine over SSH.
sysimage ssh-install -c sysimage.config.yml --ssh user@host -d bootdisk=/dev/sdX

# 3d. …or serve network boot (DHCP proxy + TFTP + HTTP) for PXE/UEFI clients.
sysimage netboot -c sysimage.config.yml

# Auxiliary commands
sysimage schema -o .            # regenerate the three JSON schemas
sysimage build-uki …            # standalone UKI builder (stub + kernel + initrds)
sysimage sbkey-generate         # Secure Boot PK/KEK/db key set
sysimage version
```

LUKS passphrases are never stored in the config or manifest: they come from
`--key name=…` / `--key-file name=…` at build/install time (matched by the
LUKS block's `name`), or an interactive prompt.

## Configuration

The config is YAML with `camelCase` fields; unknown fields are rejected.
`sysimage init` writes a fully-expanded default with every field present (the
commented reference defaults live in the repo at
`src/model/default_config.yml`). Highlights:

- **Top level**: `name`, `version`, `arch` (`x64`, `arm64`, …), `input`,
  `outputDirectory`, `tempDirectory`, `parameters`, and the sections below.
  Each `parameters` entry (optional `default`, optional `description`) becomes
  a `${name}` variable supplied via `--param name=value`; one without a
  `default` is mandatory, and an undeclared name is rejected.
- **`input`**: where rootfs content comes from — a path/glob, `file:`, a
  `build:<kind>:<name>` artifact, `sign:<name>` (a `--sign` directory), or a
  container image via `podman:` / `podman+build:` (the samples use the latter
  with a `Containerfile`).
- **`build`**: named artifacts of each kind (`erofs`, `cpio`, `uki`,
  `veritytab`, `efisign`, `encrypt`, `decrypt`, `reencrypt`, `block`),
  referenced elsewhere as `build:<kind>:<name>`. A `cpio`/`erofs` artifact's
  `input` is a list of `{ destination, input, includePattern,
  excludePatterns }` entries.
- **`disk`**: the top-level disks (e.g. `bootdisk`), each a block tree rooted
  at `type: gpt` or `type: mbr`. GPT partitions take `name`, a type GUID or
  alias (`efi`, `linux`, `swap`, `lvm`, `raid`, `luks`), size constraints and
  an optional `content` block (`fat`, `ext4`, `luks`, `lvm`, `image`).
- **`lvm`**: volume groups → logical volumes, each with its own `content`.
- **`uki`**, **`erofs`**, **`dmVerity`**, **`cpio`**: shared settings for the
  corresponding artifacts.
- **`qemu`**: machine/firmware overrides, `extraArgs`, `tpms` (vTPM via
  `swtpm`), `kernel`/`initrd`/`dtb` direct-boot files, and `disks` for
  QEMU-only read-only disks.
- **`netboot`**: `dhcp` (profiles with `httpBoot`/`pxeBoot` presets or raw
  options), `tftp` and `http` file servers.

### Variables

`${NAME}`, `${VERSION}`, `${ARCH}`, `${EFIARCH}`, `${OCIARCH}`, `${CONFIGDIR}`
(the config file's directory), `${NETBOOT_IP}` (resolved at `netboot` time)
and `${CONTENTHASH}` (first 8 bytes of the content's SHA-256, base64url) can
be used in strings — filenames, destinations, inputs. User-declared
`parameters` become additional `${name}` variables.

## Samples

`samples/` contains two end-to-end examples, each a minimal container image
(`container/Containerfile`) plus a short `sysimage.config.yml`:

- `alpine` — Alpine + dracut initramfs with a veritytab hook.
- `archlinux` — Arch Linux with systemd-boot/stub UKI.

`cargo test --test samples` builds each sample, installs it with
`qemu-install`, and boots the result under QEMU, failing if the guest never
reaches userspace.

## Testing

```sh
cargo test                      # unit + integration tests
cargo test --test build         # one integration file
cargo test --lib                # embedded unit tests
```

Integration tests build real configs in temp dirs and are hermetic, except
for explicit **interop tests** that shell out to external tools (see the table
in `.github/copilot-instructions.md`). A test whose tools are missing prints a
notice and skips — never fails silently — unless `SYSIMAGE_REQUIRE_TOOLS=1`
is set, which turns every skip into a hard failure (used by CI). Podman-based
samples additionally need a usable podman: rootful, or rootless inside
`podman unshare` (e.g. `podman unshare cargo test --test samples`).

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`, the full
test suite with `SYSIMAGE_REQUIRE_TOOLS=1` under `podman unshare`, and a
release build.

## Workspace layout

```
src/            sysimage library + CLI
  main.rs       clap CLI (build/init/install/qemu-*/ssh-install/netboot/…)
  model/        config & manifest data models + JSON Schema generation
  build/        build pipeline: config expansion → artifacts → manifest
  install.rs    install pipeline (plan/apply, reconciliation, --wipe)
  blockfile.rs  BlockRegion trait — install targets as byte regions
  lvm/          pure-Rust LVM2 on-disk format reader/writer
  luks.rs       pure-Rust LUKS2 writer (+ luks-core reader interop)
  erofs.rs      EROFS image builder        dmverity.rs  dm-verity hash trees
  ukify.rs/pe.rs  UKI / PE-COFF stitching   secboot/     Secure Boot (X.509, ESL, Authenticode)
  netboot.rs    DHCP proxy/TFTP/HTTP servers  qemu.rs   qemu-install/qemu-run
  ssh.rs        ssh-install over SSH (+ NBD tunnel for idle devices)
crates/senc/    SENC envelope crate: library + tiny `senc` encrypt/decrypt CLI
tests/          integration tests (one file per subsystem) + tests/common
samples/        alpine & archlinux end-to-end samples
```

## License

MIT — see `Cargo.toml` (`license = "MIT"`).
