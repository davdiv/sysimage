# Copilot instructions for sysimage

`sysimage` is a **declarative system image builder** written in Rust (edition 2024).
Many modules open with a `//! …` doc comment describing their purpose; treat
those as the authoritative intent for each file.

## Build, test, lint

```sh
cargo build                       # build the lib + `sysimage` CLI binary
cargo test                        # run the whole test suite
cargo test --test build           # run one integration-test file (tests/build.rs)
cargo test builds_manifest_with_  # run a single test function by name substring
cargo test --test build -- builds_manifest_with_erofs_verity_and_lvm   # single test in a file
cargo test --lib                  # unit tests embedded in src/ (e.g. size.rs, build/block.rs)
```

There is no clippy/rustfmt config in the repo; `cargo fmt`/`cargo clippy` use
defaults. Edition 2024 is set in `Cargo.toml`.

The repo is a Cargo **workspace**: the root package is `sysimage`, and
`crates/senc` is a small, dependency-pure crate (only `aes-gcm`, `hkdf`,
`sha2`, `hmac`, `zeroize`, `thiserror`; `lexopt` for its binary) holding the
single implementation of the "SENC" device-bound AEAD envelope and its
HKDF-SHA256 key derivation, exposed both as a library and as the standalone
`senc` encrypt/decrypt binary. `sysimage::encrypt` re-exports it. Key files
(`--key-file`, and `--key-file` in the `senc` CLI) are read **verbatim** — no
trailing-newline stripping — and an `encrypt` artifact's `key` may be a single
name or an ordered list of components that are concatenated **in order** and
combined with HKDF-SHA256 (so `--key-file a --key-file b` matches a file holding
the concatenation `ab`).

### External tools some tests shell out to

Integration tests under `tests/` are self-contained (they create temp dirs under
`std::env::temp_dir()` and clean up via `Drop`), but several **interoperability**
tests invoke external binaries and **skip explicitly** (with a visible
`eprintln!` notice) when a required binary is not on `PATH` — a plain
`cargo test` passes without them:

| Test file        | External tool                  | Purpose                          |
|------------------|--------------------------------|----------------------------------|
| `tests/erofs.rs` | `fsck.erofs`, `dump.erofs`      | validate generated EROFS images   |
| `tests/dmverity.rs` | `veritysetup`               | byte-compare hash tree vs reference |
| `tests/luks.rs`  | `cryptsetup`                   | recognise/unlock our LUKS2 containers |
| `tests/lvm.rs`   | `pvck` (lvm2)                  | validate on-disk PV label layout    |
| `tests/nbd_qemu.rs` | `qemu-nbd`                  | real NBD server for the NBD client |
| `tests/sbkeys.rs`| `sbsign`, `sbverify`, `openssl` | Secure Boot signing/cert cross-checks |
| `tests/samples.rs` | `podman`, `qemu-system-*` + UEFI firmware | end-to-end build → install → boot of `samples/*` |

The skip is **explicit, never silent**: a test declares its external
dependencies with the `skip_if_missing!` macro from `tests/common/mod.rs` and
returns early with a `"<tools> not available — skipping test"` notice when any
are missing:

```rust
mod common;

#[test]
fn builds_uncompressed_fsck_clean() {
    skip_if_missing!("fsck.erofs", "dump.erofs");
    // …from here on both tools are guaranteed present…
}
```

`tests/common/mod.rs` also exposes `has_tool(name)` for tests that only
*optionally* validate against an external tool (the cross-check is a bonus, not
the point of the test) — those branch on `tool_or_skip("…")` and still run the
rest of the body, printing a notice for the skipped cross-check only (see
`tests/lvm.rs::format_pv_pvck_valid`).

**Requiring every tool (hard-fail instead of skip).** Set the
`SYSIMAGE_REQUIRE_TOOLS` environment variable to a truthy value (anything other
than `""`, `"0"`, `"false"`, `"no"`) to make a missing tool a *hard failure*
rather than a graceful skip — `skip_if_missing!` panics and `tool_or_skip`
panics instead of returning `false`. Use this in CI/gating runs where the
environment is expected to provide every interop tool, so reduced coverage is
surfaced as a real test failure:

```sh
SYSIMAGE_REQUIRE_TOOLS=1 cargo test
```

`tests/samples.rs` is a **single test that iterates over every `samples/*`
config**, so it cannot use the early-return `skip_if_missing!` macro (which
would abandon the whole suite on the first missing tool). Instead it branches
**per sample** on `common::require_tools_mode()`: a sample whose config
references `podman` is skipped per-sample when podman is absent or running
rootless (`podman image mount` is refused rootless — run the suite under
`podman unshare cargo test …` to exercise it), and the QEMU boot step is
skipped per-sample when `qemu-system-*` or the UEFI firmware is missing. Under
`SYSIMAGE_REQUIRE_TOOLS` both of those per-sample skips become hard failures
(panics) instead, so CI can gate on every sample being built and booted. A
QEMU boot that *does* run but never prints the `SYSIMAGE-BOOTOK` marker is
always a hard failure, regardless of the env var.

`tests/config_model.rs` validates config parsing and default-expansion against
inline YAML written to temp files — it is fully self-contained (no external
checkout dependency).

## High-level architecture

The project is a **two-phase pipeline**: **build** a manifest + content-addressed
artifacts from a YAML config, then **install** that manifest onto a disk image,
block device, or remote NBD export.

### Phase 1 — build (`src/build/`)

`config (YAML) → artifacts + manifest (JSON)`.

- `config.rs` reads/parses YAML and **expands** it: `ConfigBuild` (a *partial*
  spec, every field optional) is merged over built-in defaults
  (`src/model/default_config.yml` via `default_expanded`) to produce
  `ExpandedConfigBuild`, where every field is present. Adding a config field means
  touching `model/config.rs`, the `expand_config` merge, and `default_config.yml`.
- `build/mod.rs::build_expanded` runs the pipeline. It walks each disk in
  `config.disk`, recursing through the block tree via `build/block.rs`, which
  converts `ConfigBlock`s into `ManifestBlock`s while computing `sizeMin`
  bottom-up.
- `BuildContext` (`build/context.rs`) is the hub: it holds the in-progress
  manifest and **memoizes** artifact builds. It uses interior mutability
  (`RefCell`/`Cell`) so artifact builders — which recurse via `build:` inputs —
  can take `&self` without borrow conflicts. Memoization keys include a recursion
  guard (`InProgress`) so a cyclic `build:` reference errors instead of looping.
- Inputs are resolved by `BuildContext::resolve_input` / `InputManager`
  (`input.rs`). An input string is one of:
  - `build:type:name` — dispatches to an artifact builder in `build/artifacts.rs`
    (`erofs`, `cpio`, `uki`, `veritytab`, `efisign`, `encrypt`, `decrypt`,
    `reencrypt`, `block`); the
    full URL is the memoization key.
  - `podman:` / `podman+build:` — mounts / builds an OCI image via `podman`.
    A `podman+build:` URL may carry build arguments as a query and an in-image
    path as a fragment: `podman+build:<context>?KEY=VALUE&…​#<in-image-path>`;
    each query parameter becomes a `--build-arg`, and `%XX` escapes are
    decoded (`src/input.rs`, `src/url.rs`).
  - `sign:<name>` — resolves to the directory supplied via
    `--sign name=directory` (handy for copying auth/certificate enrollment
    files into an image); when that name was not supplied, resolves to a
    shared empty directory (no error). An `efisign` artifact loads its
    `db.key` through `secboot::x509::load_private_key`, so a key written by
    `sbkey-generate --passphrase-file` (a SENC envelope) is decrypted when the
    matching `--sign-key-file name=path` is supplied; otherwise `db.key` must
    be a plaintext PKCS#8 PEM.
  - `file:` / plain path — resolved relative to the config's input directory,
    optionally globbed (`find_one_file_matching` requires exactly one match).
- **Content addressing**: every built file is SHA-256 hashed
  (`build/context.rs::add_output_file`) and written to the output directory as
  `<base64url-no-pad-of-digest>.bin`. The manifest records `size` + hex digest.
- The final manifest JSON is written as `<name>-<8-byte-hash>.json` plus a stable
  `<name>.json` symlink, alongside `sysimage.manifest.schema.json`.

### Phase 2 — install (`src/install.rs`)

`manifest (JSON) → disk image / block device / NBD export`.

- The pipeline is generic over a `BlockRegion` trait (`blockfile.rs`): each block
  (whole disk, GPT partition, LVM logical volume, LUKS payload, …) is installed
  into a contiguous byte region. Descending the block tree produces **sub-regions**
  that share the backing store and copy no bytes — filesystems are formatted
  *directly* into their partition region rather than staged in temp images.
- Concrete top-level regions are `BlockFile` (local file / `/dev` node) and
  `NbdRegion` (remote NBD export, `src/nbd.rs`), unified behind `DiskRegion`.
  NBD URLs (`nbd://`, `nbd+tcp://`, `nbd+unix://`) are parsed per-disk from
  `--disk name=target`, so one install can mix local and remote targets.
- **`--wipe`** installs everything from scratch; without it the installer
  **reconciles** — it reuses existing GPT partitions / LVM LVs / LUKS2 containers
  / filesystems (matched by name), creates only the missing ones, and leaves the
  rest untouched. The fresh path is also taken, without `--wipe`, for a target
  that was just created by us (a new image file or a previously empty one).
  In-use devices (mounted / open LUKS / active LVM) are handled through the
  kernel instead; `--wipe` refuses them unless `--force` is also given, which
  force-wipes them from scratch via the raw path.
  Reconciliation is **two-phase all-or-nothing**: a plan phase reads and
  validates everything before any byte is written.

### Supporting subsystems

- **`model/`** — the config + manifest data models (`config.rs`, `manifest.rs`)
  and JSON Schema generation (`schema.rs`). Schemas are produced with `schemars`
  (Draft 2020-12) then post-processed by `finalize_schema`: it merges each
  tagged-union `oneOf` entry's variant fields and sets `additionalProperties:
  false` everywhere so unknown/misspelled fields are rejected at load time.
  Validation runs through the `jsonschema` crate (`validate.rs`), with a
  `refine_oneof` pass that surfaces the nested error from the matching variant
  rather than a generic "no subschema matched".
- **`lvm/`** — a pure-Rust reader/writer for LVM2's on-disk text format (label
  sector, MDA header, CRC, text metadata). `compute_vg_layout` bridges the
  manifest model and the LVM model for the install pipeline.
- **`luks.rs`** — pure-Rust LUKS2 writer (byte-compatible with `cryptsetup`) +
  reader via the `luks-core` crate. Passphrases are **never** in config/manifest;
  they are supplied at install time via `--key name=…` / `--key-file name=…`
  (matched by the LUKS block's `name`), or prompted interactively.
- **`erofs.rs`** / **`dmverity.rs`** — pure-Rust EROFS image builder (via
  `rust-fs-erofs`) + dm-verity hash-tree formatter (`veritysetup`-compatible). An
  `erofs` artifact is built, UUID-patched from its content hash, then verity is
  appended and the metadata is captured in `BuildContext::verity`.
- **`ukify.rs`** + **`pe.rs`** — pure-Rust UKI builder.  `pe.rs` implements
  minimal PE/COFF section stitching (strip symbol tables, re-align raw data,
  append `.linux`/`.initrd`/`.cmdline` sections onto a `systemd-stub`),
  replacing the former `ukify` subprocess dependency.
- **`archive.rs`** — cpio (newc, via `hadris-cpio`) / ustar tar archive builder,
  zstd-compressed.
- **`size.rs`** — size parsing (`"10M"`, `"2GB"`, bare bytes) and
  `compute_partition_sizes`, which distributes available disk space across
  partitions by `sizeMin`/`sizeMax`/`sizeWeight`, aligning to a block size.
- **`variables.rs`** — `${VAR}` substitution in strings/values; unknown
  variables are an error.
- **`arch.rs`** — architecture metadata keyed by short names
  (`x64`, `arm64`, `ia32`, `arm`); that name is what's stored in the manifest
  `arch` field.

### CLI (`src/main.rs`)

`sysimage build -c <config.yml>` · `sysimage init -c <config.yml>` (scaffold) ·
`sysimage install -m <manifest> -c <config.yml> -d name=target [--wipe [--force]]` ·
`sysimage schema -o <dir>` (regenerate the two JSON schemas) · `sysimage version` ·
`sysimage sbkey-generate [-o <dir>] [--passphrase-file <path>]` (Secure Boot
PK/KEK/db key set; the optional passphrase file SENC-encrypts each `.key`).

## Key conventions

- **camelCase config, lowercase tags.** All serde structs use
  `#[serde(rename_all = "camelCase")]` to match the YAML/JSON shape inherited
  from the YAML/JSON shape. Block unions use `#[serde(tag = "type", rename_all =
  "lowercase")]` so the config discriminates on a lowercase `type` field
  (`gpt`, `ext4`, `fat`, `luks`, `lvm`, `image`).
- **Error handling.** There is one crate-wide `Error` enum (`error.rs`) and a
  `Result<T> = std::result::Result<T, Error>`. Build ad-hoc errors with
  `Error::msg(...)` or the `bail_msg!(...)` macro; prefer `?` over `unwrap` in
  library code (tests may `unwrap`).
- **`${VAR}` substitution** happens at config-expansion and input-resolution
  time. The build environment exposes `NAME`, `VERSION`, `ARCH`, `CONFIGDIR`,
  `EFIARCH`, `OCIARCH`. `${CONTENTHASH}` (first 8 bytes of the content's SHA-256,
  base64url-no-pad) is substituted into destination filenames and partition
  names — useful for versioned UKI filenames and `rootfs-${CONTENTHASH}` LV names.
- **Build parameters.** A user config may declare a `parameters` map; each entry
  (optional `default`, optional `description`) becomes a `${name}` variable
  usable anywhere the built-in variables are. Values are supplied at build time
  via `sysimage build --param name=value`. A parameter without a `default` is
  mandatory; supplying an undeclared name is an error. Resolution lives in
  `config::resolve_parameters`, called from `build::build_expanded_with_options`
  before any substitution.
- **When adding a config field**: update the partial struct in `model/config.rs`,
  the `ExpandedConfigBuild` struct, the `expand_config` merge in `model/config.rs`,
  and `model/default_config.yml` (for the default value). The JSON Schema is
  generated from the structs, so `sysimage schema` regenerates it automatically —
  the checked-in `sample/*.schema.json` files are produced this way.
- **Pure-Rust first.** Disk/filesystem/partition/encryption backends are
  pure-Rust (`hadris-*`, `rust-fs-*`, `luks-core`). The only intentional external
  shelling-out is `podman` (container inputs); `exec.rs`
  centralizes subprocess execution (logs the command, streams stderr, returns
  trimmed stdout, non-zero exit → error).
- **Tests are hermetic-ish.** Integration tests live in `tests/` (one file per
  subsystem), build real configs in process-namespaced temp dirs, and skip
  *explicitly* (with a visible notice) when external tooling is missing — never
  silently and never by hard-failing. When you add interop coverage that depends
  on an external binary, declare it with `skip_if_missing!(...)` from
  `tests/common/mod.rs` (add `mod common;` to the test file). If the external
  tool is only an optional cross-check, branch on `common::tool_or_skip(...)`
  so the rest of the test still runs. Both honor the `SYSIMAGE_REQUIRE_TOOLS`
  env var, which turns a missing tool into a hard failure (panic) — set it in
  CI to gate on every interop tool being installed.
- **`.gitignore` excludes `/target` and `/sample`** (the sample run is a local
  build artefact, not source).