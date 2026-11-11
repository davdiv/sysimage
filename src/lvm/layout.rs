//! On-disk layout constants and binary structures for LVM2 text format.
//!
//! Mirrors lvm2's on-disk C structures and constants.
//!
//! All multi-byte integer fields are stored little-endian on disk (the `_xl`
//! suffix in the C code stands for "xlate'd"). This module is endian-safe on
//! any host because we explicitly use `to_le_bytes` / `from_le_bytes`.

// ---------------------------------------------------------------------------
// Sector / label constants
// ---------------------------------------------------------------------------

/// Logical sector size used throughout LVM2's on-disk format.
pub const SECTOR_SIZE: u64 = 512;

/// Magic at the start of every label sector.
pub const LABEL_MAGIC: &[u8; 8] = b"LABELONE";

/// Label type string for LVM2.
pub const LABEL_TYPE: &[u8; 8] = b"LVM2 001";

/// Offset of the `pv_header` from the start of the label sector.
///
/// `label_header` is 32 bytes (`id[8]` + `sector_xl[8]` + `crc_xl[4]` +
/// `offset_xl[4]` + `type[8]`), so the pv_header begins at byte 32.
pub const PV_HEADER_OFFSET: usize = 32;

/// MDA header magic.
///
/// Decoded from the octal escape `"\040\114\126\115\062\040\170\133\065\101\045\162\060\116\052\076"`
/// which is `" LVM2 x[5A%r0N*>"`.
pub const FMTT_MAGIC: &[u8; 16] = b" LVM2 x[5A%r0N*>";

/// MDA header format version.
pub const FMTT_VERSION: u32 = 1;

/// Size of the on-disk `mda_header` struct.
pub const MDA_HEADER_SIZE: u64 = 512;

/// Original alignment for metadata content.
pub const MDA_ALIGNMENT: u64 = 512;

/// CRC-32 initial seed.
pub const INITIAL_CRC: u32 = 0xf597_a6cf;

/// PV header extension version.
pub const PV_HEADER_EXTENSION_VSN: u32 = 2;

/// `PV_EXT_USED` flag bit in `pv_header_extension.flags`.
pub const PV_EXT_USED: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Default layout values
// ---------------------------------------------------------------------------

/// Default extent size: 4 MiB (4096 KiB).
pub const DEFAULT_EXTENT_SIZE: u64 = 4 * 1024 * 1024;

/// Default physical extent start: 1 MiB.
///
/// lvm2 places the first PE at 1 MiB (2048 sectors) by default.
pub const DEFAULT_PE_START: u64 = 1024 * 1024;

/// Default first MDA offset: page size (4096 on x86_64 / aarch64).
///
/// lvm2 places the first metadata area at the system page-size offset from
/// the start of the device. We hard-code 4096, the overwhelmingly common page
/// size; the resulting metadata area is `DEFAULT_PE_START -
/// DEFAULT_MDA_OFFSET` = 1 044 480 bytes.
pub const DEFAULT_MDA_OFFSET: u64 = 4096;

/// Compute the default MDA size given pe_start and mda_offset.
pub const fn default_mda_size(pe_start: u64, mda_offset: u64) -> u64 {
    pe_start - mda_offset
}

// ---------------------------------------------------------------------------
// CRC-32 (zlib polynomial 0xEDB88320, custom seed, no final XOR)
// ---------------------------------------------------------------------------

/// LVM2's CRC-32.
///
/// Matches lvm2's CRC-32: uses the zlib polynomial `0xEDB88320`, the given
/// `initial` value as the starting CRC (no XOR with `0xFFFFFFFF`), and no
/// final XOR.
pub fn calc_crc(initial: u32, buf: &[u8]) -> u32 {
    /// Precomputed CRC-32 lookup table (zlib polynomial 0xEDB88320).
    static TABLE: [u32; 256] = build_table();

    const fn build_table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut j = 0;
            while j < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                j += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }

    let mut crc = initial;
    for &b in buf {
        crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

// ---------------------------------------------------------------------------
// On-disk binary structures
// ---------------------------------------------------------------------------

/// A `disk_locn` entry (16 bytes on disk): offset + size, both `u64` LE.
///
/// Used for data areas, metadata areas, and bootloader areas in the
/// `pv_header`. A list is terminated by an all-zero entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskLocn {
    pub offset: u64,
    pub size: u64,
}

impl DiskLocn {
    pub const ZERO: Self = Self { offset: 0, size: 0 };
    pub fn is_zero(&self) -> bool {
        self.offset == 0 && self.size == 0
    }
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..].copy_from_slice(&self.size.to_le_bytes());
        b
    }
    pub fn from_bytes(b: &[u8]) -> Self {
        Self {
            offset: u64::from_le_bytes(b[..8].try_into().unwrap()),
            size: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        }
    }
}

/// Parsed `label_header` (first 32 bytes of the label sector).
#[derive(Debug, Clone)]
pub struct LabelHeader {
    /// Magic — must be `LABEL_MAGIC`.
    pub id: [u8; 8],
    /// Sector number where this label resides.
    pub sector: u64,
    /// CRC-32 of bytes `[offset_xl .. sector_end)`.
    pub crc: u32,
    /// Offset from start of struct to `pv_header` (always 32).
    pub offset: u32,
    /// Label type — must be `LABEL_TYPE`.
    pub r#type: [u8; 8],
}

/// Parsed `pv_header` (starts at byte 32 in the label sector).
#[derive(Debug, Clone)]
pub struct PvHeader {
    /// Raw 32-byte PV UUID (no dashes).
    pub pv_uuid: [u8; 32],
    /// Device size in bytes.
    pub device_size: u64,
    /// Data areas (holding PEs). Usually one entry pointing to `pe_start`
    /// with size 0 (meaning "rest of device").
    pub data_areas: Vec<DiskLocn>,
    /// Metadata area locations.
    pub metadata_areas: Vec<DiskLocn>,
    /// PV header extension version (0 if absent).
    pub ext_version: u32,
    /// PV header extension flags.
    pub ext_flags: u32,
}

/// Parsed `mda_header` (512 bytes at the start of each metadata area).
#[derive(Debug, Clone)]
pub struct MdaHeader {
    /// CRC-32 of bytes `[4 .. 512)`.
    pub checksum: u32,
    /// Must be `FMTT_MAGIC`.
    pub magic: [u8; 16],
    /// Must be `FMTT_VERSION` (1).
    pub version: u32,
    /// Absolute start byte of this metadata area on the device.
    pub start: u64,
    /// Size of the metadata area in bytes.
    pub size: u64,
    /// Committed metadata location (raw_locn slot 0).
    pub committed: RawLocn,
    /// Precommitted metadata location (raw_locn slot 1).
    pub precommitted: RawLocn,
}

/// A `raw_locn` entry (24 bytes on disk): offset + size + checksum + flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawLocn {
    /// Offset within the metadata area (bytes from MDA start).
    pub offset: u64,
    /// Size of the metadata text in bytes (including NUL terminator).
    pub size: u64,
    /// CRC-32 of the metadata text.
    pub checksum: u32,
    /// Flags (0 or `RAW_LOCN_IGNORED` = 1).
    pub flags: u32,
}

impl RawLocn {
    pub const ZERO: Self = Self {
        offset: 0,
        size: 0,
        checksum: 0,
        flags: 0,
    };
    pub fn is_zero(&self) -> bool {
        self.offset == 0 && self.size == 0
    }
}
