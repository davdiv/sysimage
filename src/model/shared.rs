//! Shared model types used by more than one of the config, manifest, and QEMU
//! type sets.
//!
//! - [`Guid`]: a 128-bit GUID stored as 16 raw bytes in RFC-4122 *string* order,
//!   serialized to/from the canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
//!   string form. Conversion to [`hadris_part::gpt::Guid`] (which uses Microsoft
//!   mixed-endian byte order) is handled by [`Guid::to_hadris`] /
//!   [`Guid::from_hadris`].
//! - [`ArchiveFormat`]: `cpio` or `tar`, used by both the config and manifest
//!   models.
//! - [`BlockSize`]: filesystem block size alias, used by the config model.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::uuid;

/// A 128-bit GUID stored as 16 raw bytes in RFC-4122 string order.
///
/// Serializes to and deserializes from the canonical string form
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lowercase hex, case-insensitive on
/// input). The in-memory byte layout is the natural string order — the same
/// order produced by [`uuid::parse_uuid`] — so the first 4 bytes correspond to
/// the first 8 hex digits of the canonical form. This differs from
/// [`hadris_part::gpt::Guid`], which stores the first three components in
/// little-endian; use [`Guid::to_hadris`] / [`Guid::from_hadris`] to convert.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// All-zero (unused) GUID.
    pub const ZERO: Guid = Guid([0; 16]);

    // -- Well-known GPT partition type GUIDs ---------------------------------

    /// EFI System Partition (ESP).
    pub const EFI_SYSTEM: Guid = Guid([
        0xC1, 0x2A, 0x73, 0x28, 0xF8, 0x1F, 0x11, 0xD2, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ]);
    /// Linux filesystem data.
    pub const LINUX_FILESYSTEM: Guid = Guid([
        0x0F, 0xC6, 0x3D, 0xAF, 0x84, 0x83, 0x47, 0x72, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ]);
    /// Linux swap.
    pub const LINUX_SWAP: Guid = Guid([
        0x06, 0x57, 0xFD, 0x6D, 0xA4, 0xAB, 0x43, 0xC4, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F,
        0x4F,
    ]);
    /// Linux LVM.
    pub const LINUX_LVM: Guid = Guid([
        0xE6, 0xD6, 0xD3, 0x79, 0xF5, 0x07, 0x44, 0xC2, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9,
        0x28,
    ]);
    /// Linux RAID (md).
    pub const LINUX_RAID: Guid = Guid([
        0xA1, 0x9D, 0x88, 0x0F, 0x05, 0xFC, 0x4D, 0x3B, 0xA0, 0x06, 0x74, 0x3F, 0x0F, 0x84, 0x91,
        0x1E,
    ]);
    /// Linux LUKS.
    pub const LINUX_LUKS: Guid = Guid([
        0xCA, 0x7D, 0x7C, 0xCB, 0x63, 0xED, 0x4C, 0x53, 0x86, 0x1C, 0x17, 0x42, 0x53, 0x60, 0x59,
        0xCC,
    ]);
    /// Linux extended boot (XBOOTLDR).
    pub const LINUX_EXTENDED_BOOT: Guid = Guid([
        0xBC, 0x13, 0xC2, 0xFF, 0x59, 0xE6, 0x42, 0x62, 0xA3, 0x52, 0xB2, 0x75, 0xFD, 0x6F, 0x71,
        0x72,
    ]);

    // -- Construction --------------------------------------------------------

    /// Wrap raw bytes (RFC-4122 string order).
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Guid(bytes)
    }

    /// Return the raw bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Parse a canonical GUID string (case-insensitive, dashes optional).
    /// Returns `None` for malformed input.
    pub fn parse(s: &str) -> Option<Self> {
        uuid::parse_uuid(s).map(Self)
    }

    /// Convert to [`hadris_part::gpt::Guid`], adjusting the first three
    /// components from string (big-endian) order to Microsoft mixed-endian
    /// order.
    pub fn to_hadris(self) -> hadris_part::gpt::Guid {
        let [
            b0,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
            b8,
            b9,
            b10,
            b11,
            b12,
            b13,
            b14,
            b15,
        ] = self.0;
        hadris_part::gpt::Guid::from_bytes([
            b3, b2, b1, b0, // time_low (LE)
            b5, b4, // time_mid (LE)
            b7, b6, // time_hi_and_version (LE)
            b8, b9, // clock_seq (BE, unchanged)
            b10, b11, b12, b13, b14, b15, // node (BE, unchanged)
        ])
    }

    /// Convert from [`hadris_part::gpt::Guid`], reversing the mixed-endian
    /// swap performed by [`Guid::to_hadris`].
    pub fn from_hadris(g: hadris_part::gpt::Guid) -> Self {
        let b = g.to_bytes();
        Guid([
            b[3], b[2], b[1], b[0], // time_low (BE)
            b[5], b[4], // time_mid (BE)
            b[7], b[6], // time_hi_and_version (BE)
            b[8], b[9], b[10], b[11], b[12], b[13], b[14],
            b[15], // clock_seq + node (unchanged)
        ])
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&uuid::format_uuid(&self.0))
    }
}

impl Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Guid::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid GUID: {s}")))
    }
}

impl JsonSchema for Guid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Guid".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            "description": "A canonical GUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."
        })
    }
}

impl Default for Guid {
    fn default() -> Self {
        Guid::ZERO
    }
}

/// `cpio` or `tar` archive format. Used by both the config (artifact settings)
/// and manifest (archive records) models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    Cpio,
    Tar,
}

/// Filesystem block size in bytes (one of 512/1024/2048/4096).
pub type BlockSize = u32;

/// Acceptable filesystem block sizes.
pub const BLOCK_SIZES: [BlockSize; 4] = [512, 1024, 2048, 4096];

/// FAT filesystem version selection. Used by the config and manifest models
/// for `fat` blocks. `Auto` lets the formatter pick FAT12/16/32 from the
/// volume size; the others force a specific variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FatVersion {
    /// Automatically select FAT12/16/32 based on the volume size.
    #[default]
    Auto,
    /// Force FAT12 (small volumes, < ~16 MB).
    Fat12,
    /// Force FAT16 (volumes < ~2 GB).
    Fat16,
    /// Force FAT32 (volumes >= ~32 MB).
    Fat32,
}

impl FatVersion {
    /// Convert to the `hadris-fat` formatter's selection enum.
    pub fn to_fat_type_selection(self) -> hadris_fat::format::FatTypeSelection {
        match self {
            Self::Auto => hadris_fat::format::FatTypeSelection::Auto,
            Self::Fat12 => hadris_fat::format::FatTypeSelection::Fat12,
            Self::Fat16 => hadris_fat::format::FatTypeSelection::Fat16,
            Self::Fat32 => hadris_fat::format::FatTypeSelection::Fat32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trip() {
        let s = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        let g = Guid::parse(s).unwrap();
        assert_eq!(g.to_string(), s.to_ascii_lowercase());
        assert_eq!(Guid::parse(&g.to_string()).unwrap(), g);
    }

    #[test]
    fn guid_case_insensitive_parse() {
        let upper = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        let lower = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
        assert_eq!(Guid::parse(upper).unwrap(), Guid::parse(lower).unwrap());
    }

    #[test]
    fn guid_invalid() {
        assert!(Guid::parse("not-a-guid").is_none());
        assert!(Guid::parse("C12A7328-F81F-11D2").is_none());
    }

    #[test]
    fn guid_hadris_round_trip() {
        let s = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
        let g = Guid::parse(s).unwrap();
        let h = g.to_hadris();
        assert_eq!(Guid::from_hadris(h), g);
        // hadris Display gives the same canonical string.
        assert_eq!(h.to_string(), s.to_ascii_lowercase());
    }

    #[test]
    fn guid_serde_round_trip() {
        let s = "0fc63daf-8483-4772-8e79-3d69d8477de4";
        let g = Guid::parse(s).unwrap();
        let json = serde_json::to_string(&g).unwrap();
        assert_eq!(json, format!("\"{s}\""));
        let back: Guid = serde_json::from_str(&json).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn guid_serde_invalid_rejected() {
        let err = serde_json::from_str::<Guid>("\"not-a-guid\"");
        assert!(err.is_err());
    }

    #[test]
    fn well_known_constants() {
        assert_eq!(
            Guid::EFI_SYSTEM.to_string(),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        );
        assert_eq!(
            Guid::LINUX_FILESYSTEM.to_string(),
            "0fc63daf-8483-4772-8e79-3d69d8477de4"
        );
        assert_eq!(
            Guid::LINUX_SWAP.to_string(),
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"
        );
        assert_eq!(
            Guid::LINUX_LVM.to_string(),
            "e6d6d379-f507-44c2-a23c-238f2a3df928"
        );
        assert_eq!(
            Guid::LINUX_RAID.to_string(),
            "a19d880f-05fc-4d3b-a006-743f0f84911e"
        );
        assert_eq!(
            Guid::LINUX_LUKS.to_string(),
            "ca7d7ccb-63ed-4c53-861c-1742536059cc"
        );
    }
}
