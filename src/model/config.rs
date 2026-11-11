//! Configuration model — type definitions only.
//!
//! The YAML config ([`ConfigBuild`]) is a partial specification; it is merged
//! with built-in defaults to produce an [`ExpandedConfigBuild`] where every
//! field is present. Blocks form a tagged union discriminated by `type`.
//!
//! All implementation logic (expansion, default values, MBR type parsing) lives
//! in [`crate::config`]; this module contains **only** the type definitions.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::arch::ArchName;
use crate::model::netboot::ConfigNetboot;
use crate::model::qemu::ConfigQemuSettings;
use crate::model::shared::Guid;

// Re-export shared types so existing `crate::model::config::ArchiveFormat`
// import paths continue to work.
pub use crate::model::shared::{ArchiveFormat, BLOCK_SIZES, BlockSize, FatVersion};

/// A size spec: either a bare number of bytes or a string with a unit
/// (`"10M"`, `"2GB"`, `"500"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigSize {
    Number(u64),
    String(String),
}

impl ConfigSize {
    pub fn as_bytes(&self) -> crate::error::Result<u64> {
        crate::size::size_to_bytes(self)
    }
}

/// EROFS build settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigErofsSettings {
    /// Unix timestamp in milliseconds (EROFS `-T`, in seconds).
    pub timestamp: u64,
    pub block_size: BlockSize,
}

/// dm-verity settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDmVeritySettings {
    /// Hex-encoded verity salt.
    pub salt: String,
    pub hash_block_size: BlockSize,
    pub data_block_size: BlockSize,
}

/// cpio/archive settings (without the per-artifact `input`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigCpioSettings {
    pub compression_level: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ArchiveFormat>,
}

/// A build parameter declared in the config.
///
/// Declaring a parameter makes it available as `${<name>}` anywhere a
/// `${CONFIGDIR}`-style variable is substituted. A declared parameter with no
/// `default` is mandatory: the build fails unless it is supplied on the command
/// line (`sysimage build --param <name>=<value>`). Supplying a parameter that is
/// not declared is likewise an error.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigParameter {
    /// Default value. When omitted, the parameter is mandatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Human-readable description of what the parameter is for (not used by
    /// the build; surfaced in the schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The set of build parameters declared by a config, keyed by parameter name.
pub type ConfigParameters = BTreeMap<String, ConfigParameter>;

/// A glob or `build:` URL referencing input content.
pub type ConfigInputUrlGlob = String;

/// One entry of a `ConfigFilesSet`: where to source the content for a
/// destination path. Using an array (rather than a map keyed by destination)
/// allows multiple entries to target the same output directory, e.g. to
/// overlay content coming from different input directories.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFileEntry {
    /// Destination path within the archive/filesystem. An empty string (or
    /// `"."`) places content at the root. `${CONTENTHASH}` / `${VAR}`
    /// substitution applies at build time.
    pub destination: String,
    pub input: ConfigInputUrlGlob,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_pattern: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_patterns: Option<Vec<String>>,
}

/// A set of destination → source mappings. Entries are processed in order;
/// later entries may overwrite earlier ones at the same destination path.
pub type ConfigFilesSet = Vec<ConfigFileEntry>;

// ---------------------------------------------------------------------------
// Build artifacts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PartialErofsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_size: Option<BlockSize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PartialDmVeritySettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_block_size: Option<BlockSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_block_size: Option<BlockSize>,
}

/// `erofs` artifact: build an EROFS image (optionally with dm-verity).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactErofs {
    pub input: ConfigFilesSet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erofs: Option<PartialErofsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dm_verity: Option<PartialDmVeritySettings>,
}

pub type ConfigArtifactsErofs = BTreeMap<String, ConfigArtifactErofs>;

/// `cpio` artifact: a (zstd-compressed) archive. `input` is required.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactCpio {
    pub input: ConfigFilesSet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_level: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ArchiveFormat>,
}

pub type ConfigArtifactsCpio = BTreeMap<String, ConfigArtifactCpio>;

/// UKI artifact (partial — merged with the top-level `uki` settings).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactUkiPartial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<Option<String>>,
    /// Input (file path) whose contents become the UKI's `.osrel` section.
    /// systemd-boot refuses to recognise a UKI that lacks `.osrel`, so this
    /// defaults to the rootfs `etc/os-release`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osrel: Option<String>,
    /// Input (file path, typically a BMP) whose contents become the UKI's
    /// `.splash` section, displayed by systemd-stub during boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splash: Option<String>,
}

pub type ConfigArtifactsUki = BTreeMap<String, ConfigArtifactUkiPartial>;

/// A full UKI specification (after merging defaults).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactUki {
    pub stub: String,
    pub kernel: String,
    pub initrd: Vec<String>,
    pub cmdline: Option<String>,
    pub osrel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splash: Option<String>,
}

/// `veritytab` artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigVeritytabEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    pub erofs_config: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigVeritytabArtifact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<ConfigVeritytabEntry>>,
}

pub type ConfigArtifactsVeritytab = BTreeMap<String, ConfigVeritytabArtifact>;

/// `efisign` artifact: sign an EFI binary with a Secure Boot key during the
/// build. `input` references the EFI file to sign (any input specifier,
/// including `build:uki:…`); `key` names a signing key supplied on the
/// `sysimage build --sign name=dir` command line.
///
/// When the named signing key is present at build time, the EFI file is signed
/// with the `db.key` + `db.crt` files in the signing-key directory (the kind of
/// directory produced by `sbkey-generate`). When the named key is *not*
/// supplied, the input EFI is passed through unsigned — so the same config can
/// be built with or without signing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactEfiSign {
    pub input: ConfigInputUrlGlob,
    pub key: String,
}

pub type ConfigArtifactsEfiSign = BTreeMap<String, ConfigArtifactEfiSign>;

/// `encrypt` artifact: wrap a plaintext input into a device-bound,
/// authenticated-encryption envelope (the "SENC" format; see
/// [`crate::encrypt`]). `input` is any input specifier; `key` names one or
/// more key components supplied on the `sysimage build --key name=…` /
/// `--key-file name=…` command line (they land in
/// [`crate::build::BuildContext::build_keys`]).
///
/// The key components are combined, **in order**, with HKDF-SHA256 to derive
/// the 32-byte envelope key (so the order is significant). Key files are used
/// exactly as read — no trailing newline is stripped.
///
/// The key is used only during the build — it is never copied into any
/// produced artifact, manifest, or generated image. If a named key is not
/// supplied, the build fails (the plaintext is never passed through).
///
/// The output is deterministic: the same input and key always produce the
/// same ciphertext (the nonce is derived from `HMAC-SHA256(key, plaintext)`),
/// so content-addressed artifact hashes are stable across rebuilds.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactEncrypt {
    /// Plaintext input to encrypt (any input specifier: path, `file:`,
    /// `build:<kind>:<name>`, `${CONFIGDIR}`, …).
    pub input: ConfigInputUrlGlob,
    /// Name(s) of the encryption key component(s), supplied via
    /// `--key name=…` or `--key-file name=…` on the `sysimage build` command
    /// line. A single name or an ordered list is accepted; all components are
    /// concatenated in order and combined with HKDF-SHA256.
    pub key: ConfigEncryptKey,
    /// AEAD algorithm. Defaults to `aes-256-gcm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<crate::encrypt::EncryptAlgorithm>,
}

/// The `key` field of a [`ConfigArtifactEncrypt`]: either a single key-component
/// name (`key: devicekey`) or an ordered list of names
/// (`key: [devicekey, tpm-secret]`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigEncryptKey {
    /// A single key-component name.
    One(String),
    /// An ordered list of key-component names, concatenated in order and
    /// combined with HKDF-SHA256.
    Many(Vec<String>),
}

impl ConfigEncryptKey {
    /// The ordered component names as a slice.
    pub fn names(&self) -> &[String] {
        match self {
            Self::One(name) => std::slice::from_ref(name),
            Self::Many(names) => names,
        }
    }
}

pub type ConfigArtifactsEncrypt = BTreeMap<String, ConfigArtifactEncrypt>;

/// `decrypt` artifact: unwrap a device-bound, authenticated-encryption envelope
/// (the "SENC" format; see [`crate::encrypt`]) back into plaintext at build
/// time. This is the inverse of [`ConfigArtifactEncrypt`]: `input` is any input
/// specifier resolving to a SENC envelope (commonly `build:encrypt:<name>`),
/// and `key` names the same key component(s) the envelope was encrypted with,
/// supplied on the `sysimage build --key name=…` / `--key-file name=…` command
/// line (they land in [`crate::build::BuildContext::build_keys`]).
///
/// The AEAD algorithm is taken from the envelope header (the format is
/// self-describing), so no `algorithm` field is needed.
///
/// The key components are combined, **in order**, with HKDF-SHA256 exactly as
/// for `encrypt` (so the order is significant). Key files are used exactly as
/// read — no trailing newline is stripped. If a named key is not supplied, the
/// build fails and the ciphertext is never passed through.
///
/// Unlike `encrypt`, the output is the **plaintext**: it is content-addressed
/// into the output directory (when reachable from the manifest) like any other
/// built artifact. Use it to feed a decrypted credential into a later build
/// step; keep it out of any image you distribute.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactDecrypt {
    /// SENC envelope to decrypt (any input specifier: path, `file:`,
    /// `build:<kind>:<name>`, `${CONFIGDIR}`, …).
    pub input: ConfigInputUrlGlob,
    /// Name(s) of the decryption key component(s), supplied via
    /// `--key name=…` or `--key-file name=…` on the `sysimage build` command
    /// line. Must match the components — and their order — used to encrypt.
    pub key: ConfigEncryptKey,
}

pub type ConfigArtifactsDecrypt = BTreeMap<String, ConfigArtifactDecrypt>;

/// `reencrypt` artifact: decrypt a SENC envelope with one set of key components
/// and re-encrypt the plaintext under another set, in a single build step. This
/// is `decrypt` followed by `encrypt`, so a credential can be rotated to a new
/// key without the plaintext ever being materialized as a standalone artifact
/// (the intermediate plaintext lives only in memory and is zeroized).
///
/// `input` is any input specifier resolving to a SENC envelope; `decryptKey`
/// names the component(s) the envelope was encrypted with and `encryptKey` the
/// component(s) to encrypt the output with. Both are supplied on the
/// `sysimage build --key name=…` / `--key-file name=…` command line (they land
/// in [`crate::build::BuildContext::build_keys`]); when a named component is not
/// supplied the build fails.
///
/// The output is a SENC envelope under `encryptKey` using `algorithm` (default
/// `aes-256-gcm`) and the same deterministic-nonce scheme as `encrypt`, so the
/// output is byte-stable across rebuilds.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactReencrypt {
    /// SENC envelope to re-encrypt (any input specifier: path, `file:`,
    /// `build:<kind>:<name>`, `${CONFIGDIR}`, …).
    pub input: ConfigInputUrlGlob,
    /// Name(s) of the key component(s) used to decrypt `input` (must match the
    /// components — and their order — used to encrypt it).
    pub decrypt_key: ConfigEncryptKey,
    /// Name(s) of the key component(s) used to encrypt the output envelope.
    pub encrypt_key: ConfigEncryptKey,
    /// AEAD algorithm for the output envelope. Defaults to `aes-256-gcm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<crate::encrypt::EncryptAlgorithm>,
}

pub type ConfigArtifactsReencrypt = BTreeMap<String, ConfigArtifactReencrypt>;

/// All artifact collections (full — every kind is present after expansion).
///
/// `block` holds named [`ConfigBlock`]s that are *rendered* into standalone
/// image files at build time (via `build:block:name`) rather than installed
/// directly into a target disk at install time. The rendered file can then be
/// referenced as an input (e.g. an `image` block's `input`) anywhere a `build:`
/// URL is accepted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifacts {
    pub erofs: ConfigArtifactsErofs,
    pub cpio: ConfigArtifactsCpio,
    pub uki: ConfigArtifactsUki,
    pub veritytab: ConfigArtifactsVeritytab,
    #[serde(default, skip_serializing_if = "ConfigArtifactsEfiSign::is_empty")]
    pub efisign: ConfigArtifactsEfiSign,
    #[serde(default, skip_serializing_if = "ConfigBlocks::is_empty")]
    pub block: ConfigBlocks,
    #[serde(default, skip_serializing_if = "ConfigArtifactsEncrypt::is_empty")]
    pub encrypt: ConfigArtifactsEncrypt,
    #[serde(default, skip_serializing_if = "ConfigArtifactsDecrypt::is_empty")]
    pub decrypt: ConfigArtifactsDecrypt,
    #[serde(default, skip_serializing_if = "ConfigArtifactsReencrypt::is_empty")]
    pub reencrypt: ConfigArtifactsReencrypt,
}

/// Partial artifact collections (each kind optional) — the raw `build:` field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigArtifactsPartial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erofs: Option<ConfigArtifactsErofs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpio: Option<ConfigArtifactsCpio>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uki: Option<ConfigArtifactsUki>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub veritytab: Option<ConfigArtifactsVeritytab>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub efisign: Option<ConfigArtifactsEfiSign>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<ConfigBlocks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<ConfigArtifactsEncrypt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypt: Option<ConfigArtifactsDecrypt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reencrypt: Option<ConfigArtifactsReencrypt>,
}

// ---------------------------------------------------------------------------
// Disk / partition blocks
// ---------------------------------------------------------------------------

/// A partition-size specification (all fields optional in config).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPartitionSize {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_min: Option<ConfigSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_max: Option<ConfigSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_weight: Option<f64>,
}

/// A partition (size spec + optional content block).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigPartition {
    #[serde(flatten)]
    pub size: ConfigPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ConfigBlock>>,
}

/// A well-known GPT partition type alias usable in the config in place of a
/// raw GUID. Resolved to its canonical GUID during config→manifest conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KnownGptPartitionType {
    /// EFI System Partition (ESP).
    Efi,
    /// Linux filesystem data.
    Linux,
    /// Linux swap.
    Swap,
    /// Linux LVM physical volume.
    Lvm,
    /// Linux RAID (md).
    Raid,
    /// Linux LUKS encrypted container.
    Luks,
}

/// A GPT partition type in the user config: either a well-known name or an
/// explicit GUID.
///
/// Deserialized from a string; a valid GUID string is parsed as [`Guid`], any
/// other string is tried as a [`KnownGptPartitionType`] alias. Invalid values
/// (neither a GUID nor a known name) produce a deserialization error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigPartitionType {
    /// An explicit partition type GUID.
    Guid(Guid),
    /// A well-known partition type alias.
    Named(KnownGptPartitionType),
}

/// A GPT partition: a partition plus `name`, partition `type` and optional
/// unique `guid`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigGptPartition {
    #[serde(flatten)]
    pub size: ConfigPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ConfigBlock>>,
    pub name: String,
    /// GPT partition type: a well-known alias (`efi`, `linux`, `swap`, `lvm`,
    /// `raid`, `luks`) or an explicit GUID string.
    #[serde(rename = "type")]
    pub type_guid: ConfigPartitionType,
    /// Optional unique partition GUID. When omitted a random v4 GUID is
    /// generated at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<Guid>,
}

/// A GPT disk block.
///
/// When the optional `mbr` field is present, the GPT is written with a hybrid
/// MBR (a protective entry plus up to three GPT partitions mirrored into MBR
/// slots) for dual BIOS/UEFI boot — i.e. the disk is a *hybrid* GPT. Without
/// `mbr` it is a standard protective-MBR GPT.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockGpt {
    pub partitions: Vec<ConfigGptPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ConfigPartitionSize>,
    /// Optional unique disk GUID. When omitted a random v4 GUID is generated
    /// at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<Guid>,
    /// Hybrid MBR configuration. When present, the disk is a hybrid GPT: the
    /// GPT is written alongside a hybrid MBR mirroring the selected partitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbr: Option<ConfigHybridMbr>,
    /// Optional bootcode (`file:` URL or path) whose first 446 bytes are written
    /// to the protective-MBR bootstrap area (the first 446 bytes of the first
    /// sector). The input file must be at most 512 bytes long.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootcode: Option<String>,
}

/// An MBR partition: a partition plus a legacy `type` byte and a `bootable` flag.
///
/// The `type` is an MBR partition type code: either one of the known names
/// (`"linux"`, `"fat32"`, `"fat16"`, `"fat12"`, `"efi"`, `"swap"`, `"lvm"`,
/// `"raid"`, `"ntfs"`, `"extended"`) or a hex byte written as `"0x83"`. MBR has
/// no partition name or GUID; partitions are matched by slot index (0-3) when
/// reconciling an existing table.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMbrPartition {
    #[serde(flatten)]
    pub size: ConfigPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ConfigBlock>>,
    /// MBR partition type code (a known name or a `"0xNN"` hex byte).
    #[serde(rename = "type")]
    pub type_code: String,
    /// Mark this partition active/bootable in the MBR boot indicator.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bootable: bool,
}

/// An MBR (legacy BIOS) disk block. Supports up to 4 primary partitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockMbr {
    pub partitions: Vec<ConfigMbrPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ConfigPartitionSize>,
    /// Optional bootcode (`file:` URL or path) whose first 446 bytes are written
    /// to the MBR bootstrap area (the first 446 bytes of the first sector). The
    /// input file must be at most 512 bytes long.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootcode: Option<String>,
}

/// A well-known MBR partition type alias usable in the config in place of a
/// raw type byte. Resolved to its byte value during config→manifest conversion.
///
/// The canonical (serde) names match the lower-case aliases accepted by
/// [`crate::config::parse_mbr_type`]; the additional `#[serde(alias = …)]`
/// alternatives keep the historical spelling variants working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KnownMbrPartitionType {
    /// Empty / unused (0x00).
    #[serde(alias = "free")]
    Empty,
    /// FAT12 (0x01).
    Fat12,
    /// FAT16 (0x04).
    Fat16,
    /// Extended partition (0x05).
    Extended,
    /// FAT16 with LBA (0x06).
    Fat16Lba,
    /// NTFS / exFAT (0x07).
    Ntfs,
    /// FAT32 (0x0B).
    Fat32,
    /// FAT32 with LBA (0x0C).
    Fat32Lba,
    /// Extended partition with LBA (0x0F).
    ExtendedLba,
    /// ISO9660 (0x17).
    Iso9660,
    /// Linux swap (0x82).
    #[serde(alias = "linuxswap")]
    Swap,
    /// Linux native filesystem (0x83).
    #[serde(alias = "linuxnative")]
    Linux,
    /// Linux LVM physical volume (0x8E).
    #[serde(alias = "linuxlvm")]
    Lvm,
    /// Linux RAID (0xFD).
    #[serde(alias = "linuxraid")]
    Raid,
    /// EFI System Partition (0xEF).
    #[serde(alias = "efisystem", alias = "esp")]
    Efi,
}

impl KnownMbrPartitionType {
    /// The raw MBR type byte this alias resolves to.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Empty => 0x00,
            Self::Fat12 => 0x01,
            Self::Fat16 => 0x04,
            Self::Extended => 0x05,
            Self::Fat16Lba => 0x06,
            Self::Ntfs => 0x07,
            Self::Fat32 => 0x0B,
            Self::Fat32Lba => 0x0C,
            Self::ExtendedLba => 0x0F,
            Self::Iso9660 => 0x17,
            Self::Swap => 0x82,
            Self::Linux => 0x83,
            Self::Lvm => 0x8E,
            Self::Raid => 0xFD,
            Self::Efi => 0xEF,
        }
    }
}

/// An MBR partition type in the user config: either a well-known name or a
/// raw type byte.
///
/// Deserialized from a JSON/YAML value: a number is taken as the raw byte
/// (0-255), a string is tried as a [`KnownMbrPartitionType`] alias. The
/// protective-MBR type 0xEE is reserved and rejected during resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigMbrType {
    /// A raw MBR type byte (0-255). 0xEE is reserved for the protective MBR.
    Number(u8),
    /// A well-known MBR partition type alias.
    Named(KnownMbrPartitionType),
}

impl ConfigMbrType {
    /// Resolve this config type to a raw MBR type byte. Callers are
    /// responsible for rejecting the reserved protective-MBR value 0xEE in
    /// the appropriate context.
    pub fn resolve(&self) -> crate::error::Result<u8> {
        Ok(match self {
            Self::Number(b) => *b,
            Self::Named(n) => n.byte(),
        })
    }
}

/// A GPT partition mirrored into a hybrid MBR.
///
/// `partition` selects the GPT partition (by name) to mirror; `type` is the
/// MBR type code to use in the MBR entry (a known name or a raw byte);
/// `bootable` marks it active.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMirroredPartition {
    /// Name of the GPT partition to mirror into the MBR.
    pub partition: String,
    /// MBR partition type code: a well-known alias (`linux`, `fat32`, `efi`,
    /// `swap`, `lvm`, `raid`, `ntfs`, …) or a raw type byte (0-255).
    #[serde(rename = "type")]
    pub type_code: ConfigMbrType,
    /// Mark this mirrored partition active/bootable in the MBR.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bootable: bool,
}

/// Hybrid-MBR configuration for a hybrid (GPT + MBR) disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigHybridMbr {
    /// MBR slot (0-3) holding the protective (0xEE) entry. Defaults to 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protective_slot: Option<usize>,
    /// GPT partitions to mirror into the MBR (at most 3).
    #[serde(default)]
    pub mirrored: Vec<ConfigMirroredPartition>,
}

/// A raw image block (`input` references a built output file).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockImage {
    pub input: ConfigInputUrlGlob,
}

/// An ext4 or FAT filesystem block.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockFs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ConfigSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<ConfigFilesSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_format: Option<ArchiveFormat>,
    /// Filesystem block size (bytes). For ext4 this is the filesystem block
    /// size; for FAT it is the cluster size. When `None`, a sensible default
    /// is chosen at build/install time (4096 for ext4, auto for FAT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_size: Option<BlockSize>,
    /// FAT variant to use for `fat` blocks (`auto`, `fat12`, `fat16`,
    /// `fat32`). Defaults to `auto` (selected from the volume size). Ignored
    /// for `ext4` blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fat_version: Option<FatVersion>,
}

/// An LVM physical-volume block.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockLvm {
    #[serde(flatten)]
    pub size: ConfigPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vg: Option<String>,
}

/// A LUKS block: encrypts its `content` into a LUKS2 container.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBlockLuks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ConfigBlock>>,
    /// Name identifying this LUKS container. Used at install time to match a
    /// passphrase supplied via `--key <name>=…` / `--key-file <name>=…`; if no
    /// key is given for this name on the command line, a passphrase is
    /// prompted interactively.
    pub name: String,
    /// Cipher + mode. Only `aes-xts-plain64` is supported (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// Master-key length in bytes: 32 (AES-128-XTS) or 64 (AES-256-XTS).
    /// Defaults to 64 (AES-256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    /// Encryption sector size in bytes: 512 or 4096. Defaults to 4096.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector_size: Option<u32>,
    /// Alignment of the encrypted payload start, in bytes. Defaults to 16 MiB
    /// (matching `cryptsetup luksFormat`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_align: Option<ConfigSize>,
    /// Key-derivation function for the passphrase keyslot. Defaults to
    /// Argon2id with cryptsetup's parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<crate::luks::Luks2Kdf>,
    /// Optional container UUID (canonical GUID string). When omitted a random
    /// v4 UUID is generated at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Guid>,
}

/// A disk block — tagged union on the `type` field.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ConfigBlock {
    Gpt(ConfigBlockGpt),
    Mbr(ConfigBlockMbr),
    Ext4(ConfigBlockFs),
    Fat(ConfigBlockFs),
    Luks(ConfigBlockLuks),
    Lvm(ConfigBlockLvm),
    Image(ConfigBlockImage),
}

pub type ConfigBlocks = BTreeMap<String, ConfigBlock>;

/// An LVM logical-volume partition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigLvmPartition {
    #[serde(flatten)]
    pub size: ConfigPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ConfigBlock>>,
    pub name: String,
}

/// An LVM volume group.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigLvmVg {
    pub partitions: Vec<ConfigLvmPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ConfigPartitionSize>,
}

pub type ConfigLvmVgs = BTreeMap<String, ConfigLvmVg>;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Partial top-level config as deserialized from YAML.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBuild {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<ArchName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<ConfigArtifactsPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk: Option<ConfigBlocks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lvm: Option<ConfigLvmVgs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erofs: Option<PartialErofsSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dm_verity: Option<PartialDmVeritySettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpio: Option<ConfigCpioSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uki: Option<ConfigArtifactUkiPartial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu: Option<ConfigQemuSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netboot: Option<ConfigNetboot>,
    /// Build parameters declared by this config. Each declared parameter may be
    /// supplied on the command line (`--param name=value`) and referenced as
    /// `${name}` in any string field; a parameter without a `default` is
    /// mandatory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ConfigParameters>,
}

/// Fully-resolved config: every field is present.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExpandedConfigBuild {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub name: String,
    pub version: String,
    pub arch: ArchName,
    pub input: String,
    pub output_directory: String,
    pub temp_directory: String,
    pub build: ConfigArtifacts,
    pub disk: ConfigBlocks,
    pub lvm: ConfigLvmVgs,
    pub erofs: ConfigErofsSettings,
    pub dm_verity: ConfigDmVeritySettings,
    pub cpio: ConfigCpioSettings,
    pub uki: ConfigArtifactUki,
    pub qemu: ConfigQemuSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netboot: Option<ConfigNetboot>,
    /// Declared build parameters (name → default/description). Values supplied
    /// on the command line are merged over these at build time.
    #[serde(default, skip_serializing_if = "ConfigParameters::is_empty")]
    pub parameters: ConfigParameters,
}

// ---------------------------------------------------------------------------
// Serde helpers (tightly coupled to field attributes, not business logic)
// ---------------------------------------------------------------------------

/// `skip_serializing_if` predicate for `bool` fields that default to `false`.
fn is_false(b: &bool) -> bool {
    !b
}
