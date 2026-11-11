//! QEMU configuration type definitions.
//!
//! Two layers of QEMU types live here:
//!
//! 1. **Portable settings** ([`ConfigQemuSettings`] and friends) — the optional
//!    `qemu` section of `sysimage.config.yml`, carried through the manifest.
//!    Every field is optional; unspecified fields fall back to per-architecture
//!    defaults resolved at `qemu-install` time.
//!
//! 2. **Resolved launch config** ([`QemuConfig`] and friends) — the fully
//!    specified `qemu.json` written by `qemu-install` and consumed by
//!    `qemu-run`. All fields are present; architecture-specific pieces (the
//!    `arch` name and disk images) have been filled in.
//!
//! This module contains **only** type definitions — all implementation (the
//! `qemu-install` / `qemu-run` pipeline, firmware resolution, swtpm
//! management, etc.) lives in [`crate::qemu`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Portable settings (user config / manifest)
// ---------------------------------------------------------------------------

/// Portable QEMU launch settings — the optional `qemu` section of the user
/// config, carried through the manifest.
///
/// Every field is optional; unspecified fields fall back to per-architecture
/// defaults derived from the firmware table (see
/// [`crate::qemu::default_qemu_settings`]). The architecture-specific pieces
/// (the `arch` name and the `qemu-system-*` binary) are added by `qemu-install`,
/// so this struct is portable across architectures.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQemuSettings {
    /// `-machine` argument, e.g. `q35,smm=on` or `virt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// `-cpu` argument, e.g. `host` or `cortex-a72`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Number of guest CPUs (`-smp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smp: Option<u32>,
    /// Guest memory size (`-m`), e.g. `4G`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// Extra leading arguments inserted before the firmware/disk arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_args: Option<Vec<String>>,
    /// Per-disk QEMU drive options, keyed by disk name. Each value is a map of
    /// `key=value` drive options (without the `file=` entry, which is added
    /// automatically from the disk image file name). The `if` option defaults
    /// to `virtio` when omitted.
    ///
    /// A key that does not match a manifest disk is a **QEMU-only disk**: it
    /// must provide an `input` (an input specifier resolved at build time, like
    /// `qemu.kernel`) and is attached directly instead of being installed. The
    /// `input` key is sysimage-only and is stripped before QEMU sees the
    /// options. QEMU-only disks are read-only by default; explicitly setting
    /// `readonly` to `off` is rejected because the backing file is a shared
    /// content-addressed artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disks: Option<BTreeMap<String, BTreeMap<String, String>>>,
    /// TPM devices to attach, each backed by an `swtpm` instance, keyed by
    /// name. The name identifies the persistent `swtpm` state directory, so it
    /// should be stable across runs. Unspecified fields fall back to
    /// per-architecture defaults (see [`ConfigQemuTpm`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpms: Option<BTreeMap<String, ConfigQemuTpm>>,
    /// UEFI firmware configuration. When unset (the default), the
    /// per-architecture default firmware is used. Set to `false` to disable
    /// UEFI firmware entirely (no pflash devices; QEMU falls back to SeaBIOS).
    /// Set to `true` to explicitly request the per-architecture default. Set to
    /// an object with `code` (and optionally `vars`) to supply explicit firmware
    /// files; the `code`/`vars` strings are input specifiers resolved through
    /// the input manager at build time, and the resolved files are copied to
    /// the build output as content-addressed files (like any other output file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<ConfigQemuFirmware>,
    /// Input specifier for a kernel image to boot directly (`-kernel`).
    /// Resolved through the input manager at build time and copied into the
    /// QEMU directory by `qemu-install`, like
    /// [`firmware`](Self::firmware).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Input specifier for a shim image (`-shim`). Resolved and copied the
    /// same way as [`kernel`](Self::kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// Input specifier(s) for an initrd image (`-initrd`).
    ///
    /// A single string (`initrd: file:initramfs.img`) or an ordered list
    /// (`initrd: [file:base.img, build:cpio:extra]`) is accepted. A list is
    /// resolved like [`uki.initrd`](crate::model::config::ConfigArtifactUkiPartial::initrd):
    /// directory inputs are packed into cpio archives, and the resulting files
    /// are concatenated in order with each file padded to a 4-byte boundary
    /// (matching ukify). The manifest records the single content-addressed hash
    /// of the concatenated initrd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<ConfigQemuInitrd>,
    /// Input specifier for a device tree blob (`-dtb`). Resolved and copied
    /// the same way as [`kernel`](Self::kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtb: Option<String>,
    /// Kernel command line passed to `-append` (no special processing, like
    /// [`cpu`](Self::cpu)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<String>,
}

/// The `initrd` field of a [`ConfigQemuSettings`]: either a single input
/// specifier or an ordered list of them.
///
/// In the user config this is the raw input specification(s); in the manifest
/// it is the content-addressed hash file name of the concatenated initrd
/// (always the single-value form).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigQemuInitrd {
    /// A single initrd input specifier (or resolved hash file name).
    One(String),
    /// An ordered list of initrd input specifiers, concatenated in order.
    Many(Vec<String>),
}

impl ConfigQemuInitrd {
    /// The ordered input specifiers (or resolved hash file names) as a slice.
    pub fn inputs(&self) -> &[String] {
        match self {
            Self::One(input) => std::slice::from_ref(input),
            Self::Many(inputs) => inputs,
        }
    }

    /// The single value, when this holds exactly one entry.
    pub fn as_single(&self) -> Option<&str> {
        match self.inputs() {
            [one] => Some(one),
            _ => None,
        }
    }
}

/// UEFI firmware configuration in the user config / manifest.
///
/// `false` disables UEFI firmware; `true` requests the per-architecture
/// default; an object supplies explicit firmware files. In the manifest, the
/// `code`/`vars` strings are the content-addressed hash file names produced by
/// the build (resolved from the input specifiers given in the user config).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigQemuFirmware {
    /// `false` = disable UEFI firmware; `true` = per-architecture default.
    Bool(bool),
    /// Explicit firmware files (input specifiers in the config, hash file
    /// names in the manifest).
    Files(ConfigQemuFirmwareFiles),
}

/// Explicit firmware files for [`ConfigQemuFirmware::Files`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQemuFirmwareFiles {
    /// Input specifier for the firmware code ROM (read-only). Resolved through
    /// the input manager at build time, like any other input.
    pub code: String,
    /// Input specifier for the firmware vars template (writable, persistent
    /// across runs).
    pub vars: String,
}

/// A TPM device (partial config) to expose to the guest via an `swtpm`
/// emulator backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQemuTpm {
    /// Frontend device model passed to `-device`, e.g. `tpm-tis`, `tpm-crb` or
    /// `tpm-tis-device`. Defaults to a per-architecture model (`tpm-tis` on x86,
    /// `tpm-tis-device` on arm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// TPM version emulated by `swtpm`: `2.0` (default) or `1.2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Extra arguments appended to the `swtpm socket` invocation for this
    /// device (e.g. `["--log", "level=20"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swtpm_args: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Resolved launch config (qemu.json)
// ---------------------------------------------------------------------------

/// The QEMU launch config written as `qemu.json` and consumed by `qemu-run`.
///
/// All fields are fully resolved: architecture-specific pieces and disk image
/// file names have been filled in by `qemu-install`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QemuConfig {
    /// Architecture (rust `std::env::consts::ARCH` name; selects firmware +
    /// qemu binary).
    pub arch: String,
    /// `-machine` argument, e.g. `q35,smm=on` or `virt`.
    pub machine: String,
    /// `-cpu` argument, e.g. `host` or `cortex-a72`.
    pub cpu: String,
    /// Number of guest CPUs (`-smp`).
    pub smp: u32,
    /// Guest memory size (`-m`), e.g. `4G`.
    pub memory: String,
    /// Extra leading arguments (e.g. the secure-boot pflash global).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    /// Disk images to attach, keyed by disk name, with their `key=value` drive
    /// options (including `file=`). The `if` option is always present and
    /// defaults to `virtio` when no explicit interface was configured. For
    /// QEMU-only disks, `file` names a local `<disk-name>.img` that is normally
    /// a hardlink to a content-addressed artifact (or a copy when hard-linking
    /// is unavailable).
    pub disks: BTreeMap<String, BTreeMap<String, String>>,
    /// TPM devices to attach, keyed by name, each backed by an `swtpm`
    /// instance.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tpms: BTreeMap<String, QemuTpmDevice>,
    /// Resolved UEFI firmware configuration. Defaults to
    /// [`QemuFirmware::Default`] (per-architecture firmware resolved from the
    /// host at `qemu-run` time).
    #[serde(default)]
    pub firmware: QemuFirmware,
    /// Local file name of a kernel image copied into the QEMU directory by
    /// `qemu-install` (used with `-kernel`). `None` when no kernel was
    /// configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Local file name of a shim image (`-shim`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<String>,
    /// Local file name of an initrd image (`-initrd`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<String>,
    /// Local file name of a device tree blob (`-dtb`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtb: Option<String>,
    /// Kernel command line passed to `-append` (no special processing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<String>,
}

/// Resolved firmware configuration in `qemu.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum QemuFirmware {
    /// Use the per-architecture default firmware, resolved from the host's
    /// firmware search paths at `qemu-run` time.
    #[default]
    Default,
    /// Disable UEFI firmware entirely (no pflash devices; SeaBIOS boot).
    Disabled,
    /// Explicit firmware files present in the QEMU directory.
    Files {
        /// Local file name of the firmware code ROM (read-only, shared).
        code: String,
        /// Local file name of the firmware vars file (writable, persistent).
        vars: String,
    },
}

/// A resolved TPM device in `qemu.json`: a `swtpm` backend exposed to the
/// guest as a frontend device.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QemuTpmDevice {
    /// QEMU `-tpmdev` / `-device` id, derived from the device index (`tpm0`...).
    pub id: String,
    /// Frontend device model passed to `-device`, e.g. `tpm-tis`.
    pub model: String,
    /// TPM version emulated by `swtpm`: `2.0` or `1.2`.
    pub version: String,
    /// Extra arguments appended to the `swtpm socket` invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swtpm_args: Vec<String>,
}

/// Options for `qemu-run`.
///
/// This is a plain options struct (not serialized) — it carries the runtime
/// parameters for launching QEMU, not part of the `qemu.json` document.
pub struct QemuRunConfig {
    /// Directory containing `qemu.json` and the disk images.
    pub directory: PathBuf,
    /// Print the resolved `qemu-system-*` command line instead of launching.
    pub print: bool,
    /// Extra arguments appended after the generated `qemu-system-*` arguments.
    pub extra_args: Vec<String>,
}
