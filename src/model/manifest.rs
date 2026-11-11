//! Manifest model — type definitions only.
//!
//! The manifest is a JSON document describing the built artifacts (content
//! addressed by SHA-256) and the disk/LVM layout to install them into.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::netboot::ConfigNetboot;
use crate::model::qemu::ConfigQemuSettings;
use crate::model::shared::{ArchiveFormat, FatVersion, Guid};

/// A partition size as recorded in the manifest (all bytes).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestPartitionSize {
    pub size_min: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_max: Option<u64>,
    pub size_weight: f64,
}

/// A partition: size spec + optional content block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestPartition {
    #[serde(flatten)]
    pub size: ManifestPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ManifestBlock>>,
}

/// A GPT partition recorded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestGptPartition {
    #[serde(flatten)]
    pub size: ManifestPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ManifestBlock>>,
    pub name: String,
    /// GPT partition type GUID (canonical string form).
    #[serde(rename = "type")]
    pub type_guid: Guid,
    /// Optional unique partition GUID. When `None` a random v4 GUID is
    /// generated at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<Guid>,
}

/// A GPT disk block.
///
/// When `mbr` is present, the disk is a hybrid GPT: the GPT is written
/// alongside a hybrid MBR mirroring the selected partitions for dual BIOS/UEFI
/// boot. Without it, the disk is a standard protective-MBR GPT.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockGpt {
    pub partitions: Vec<ManifestGptPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ManifestPartitionSize>,
    pub size_min: u64,
    /// Optional unique disk GUID. When `None` a random v4 GUID is generated at
    /// install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<Guid>,
    /// Hybrid MBR configuration. Present only for hybrid GPT disks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbr: Option<ManifestHybridMbr>,
    /// Optional bootcode: content-addressed file (hash name in `files`) whose
    /// bytes (≤ 446) are written to the protective-MBR bootstrap area.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootcode: Option<String>,
}

/// An MBR partition recorded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestMbrPartition {
    #[serde(flatten)]
    pub size: ManifestPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ManifestBlock>>,
    /// MBR partition type code (raw byte).
    pub type_code: u8,
    /// Whether the partition is marked active/bootable.
    #[serde(default, skip_serializing_if = "is_false_mbr")]
    pub bootable: bool,
}

/// An MBR (legacy BIOS) disk block. Supports up to 4 primary partitions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockMbr {
    pub partitions: Vec<ManifestMbrPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ManifestPartitionSize>,
    pub size_min: u64,
    /// Optional bootcode: content-addressed file (hash name in `files`) whose
    /// bytes (≤ 446) are written to the MBR bootstrap area.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootcode: Option<String>,
}

/// A GPT partition mirrored into a hybrid MBR.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestMirroredPartition {
    /// Name of the GPT partition mirrored into the MBR.
    pub partition: String,
    /// MBR partition type code (raw byte).
    pub type_code: u8,
    /// Whether the mirrored partition is marked active/bootable.
    #[serde(default, skip_serializing_if = "is_false_mbr")]
    pub bootable: bool,
}

/// Hybrid-MBR configuration for a hybrid (GPT + MBR) disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestHybridMbr {
    /// MBR slot (0-3) holding the protective (0xEE) entry.
    pub protective_slot: usize,
    /// GPT partitions mirrored into the MBR (at most 3).
    pub mirrored: Vec<ManifestMirroredPartition>,
}

/// A raw image block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockImage {
    pub size_min: u64,
    pub file: String,
}

/// A reference to a built archive used to populate a filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestArchive {
    pub file: String,
    pub format: ArchiveFormat,
    pub size: u64,
    pub size_on_disk: u64,
}

/// An ext4 or FAT filesystem block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockFs {
    pub size_min: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<ManifestArchive>,
    /// Build-time only: key into the build context's tree store. When set, the
    /// install path writes the in-memory tree directly into the filesystem
    /// instead of extracting an archive — skipping the compress/decompress
    /// round-trip. Not serialized (the tree is a build-time concept that never
    /// appears in the manifest JSON).
    #[serde(skip, default)]
    pub tree_key: Option<String>,
    /// Filesystem block size in bytes, if specified in the config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_size: Option<u32>,
    /// FAT variant (`auto`, `fat12`, `fat16`, `fat32`), if specified in the
    /// config for a `fat` block. `None` means auto-selection at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fat_version: Option<FatVersion>,
}

/// An LVM physical-volume block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockLvm {
    pub size_min: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vg: Option<String>,
}

/// A LUKS2 block: a `cryptsetup`-compatible encrypted container holding an
/// optional nested content block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBlockLuks {
    pub size_min: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ManifestBlock>>,
    /// Name identifying this LUKS container, used at install time to look up
    /// the passphrase supplied on the command line (`--key` / `--key-file`).
    pub name: String,
    /// Cipher + mode (`aes-xts-plain64`).
    pub cipher: String,
    /// Master-key length in bytes.
    pub key_size: u32,
    /// Encryption sector size in bytes (512 or 4096).
    pub sector_size: u32,
    /// Alignment of the encrypted payload start, in bytes.
    pub payload_align: u64,
    /// Key-derivation function parameters (no salt; the salt is generated at
    /// install time).
    pub kdf: crate::luks::Luks2Kdf,
    /// AF stripe count.
    pub af_stripes: u32,
    /// AF hash (`sha256`).
    pub af_hash: String,
    /// Optional container UUID (canonical GUID). When `None` a random v4 UUID
    /// is generated at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Guid>,
}

/// A disk block — tagged union on `type`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ManifestBlock {
    Gpt(ManifestBlockGpt),
    Mbr(ManifestBlockMbr),
    Ext4(ManifestBlockFs),
    Fat(ManifestBlockFs),
    Luks(ManifestBlockLuks),
    Lvm(ManifestBlockLvm),
    Image(ManifestBlockImage),
}

/// An LVM logical volume.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestLvmPartition {
    #[serde(flatten)]
    pub size: ManifestPartitionSize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Box<ManifestBlock>>,
    pub name: String,
}

/// An LVM volume group.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestLvmVg {
    pub partitions: Vec<ManifestLvmPartition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_space: Option<ManifestPartitionSize>,
    pub size_min: u64,
}

/// A built output file (content-addressed by SHA-256).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
    pub size: u64,
    /// SHA-256 digest, lowercase hex.
    pub hash: String,
}

/// The top-level manifest.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBuild {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub name: String,
    pub version: String,
    /// Architecture (rust `std::env::consts::ARCH` name).
    pub arch: String,
    pub file: BTreeMap<String, ManifestFile>,
    pub disk: BTreeMap<String, ManifestBlock>,
    pub lvm: BTreeMap<String, ManifestLvmVg>,
    /// Portable QEMU launch settings copied from the user config at build time.
    /// Architecture-specific pieces (arch name, qemu binary, disk images) are
    /// added by `qemu-install`, so this field is optional in the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu: Option<ConfigQemuSettings>,
    /// Network-boot settings copied from the user config at build time. The
    /// DHCP settings are passed through unchanged; the TFTP/HTTP `files` map
    /// values are the content-addressed hash file names produced by the build
    /// (resolved from the input specifiers given in the user config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netboot: Option<ConfigNetboot>,
}

// ---------------------------------------------------------------------------
// Serde helpers (tightly coupled to field attributes, not business logic)
// ---------------------------------------------------------------------------

/// `skip_serializing_if` predicate for `bool` fields that default to `false`.
fn is_false_mbr(b: &bool) -> bool {
    !b
}
