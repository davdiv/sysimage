//! Disk I/O for LVM2 text-format PVs: reading and writing the label sector,
//! MDA header, and VG metadata text.
//!
//! All read functions work with a file path (`AsRef<Path>`) and seek to the
//! appropriate offset. Write functions take a `Write + Seek` handle (typically
//! a [`crate::blockfile::BlockFile`] or a raw `File`) and write at position 0
//! (relative to the start of the PV region).

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::lvm::layout::{
    DiskLocn, INITIAL_CRC, LABEL_MAGIC, LABEL_TYPE, LabelHeader, MDA_HEADER_SIZE, MdaHeader,
    PV_EXT_USED, PV_HEADER_EXTENSION_VSN, PV_HEADER_OFFSET, PvHeader, RawLocn, SECTOR_SIZE,
    calc_crc,
};
use crate::lvm::model::{PhysicalVolume, VolumeGroup};
use crate::lvm::text;

// ---------------------------------------------------------------------------
// Label sector construction
// ---------------------------------------------------------------------------

/// Build the 512-byte label sector for a PV.
///
/// Layout (matching lvm2's label-sector writer):
///
/// ```text
/// [label_header: 32 bytes]
///   id[8]          = "LABELONE"
///   sector_xl[8]   = 0  (sector 0)
///   crc_xl[4]      = CRC of bytes [20..512)
///   offset_xl[4]   = 32  (pv_header offset)
///   type[8]        = "LVM2 001"
/// [pv_header: variable]
///   pv_uuid[32]     = raw 32-byte UUID
///   device_size_xl[8] = device size in bytes
///   disk_areas_xl[]  = data areas (NULL-terminated)
///   disk_areas_xl[]  = metadata areas (NULL-terminated)
/// [pv_header_extension: 8+ bytes]
///   version[4]     = 2
///   flags[4]       = PV_EXT_USED
///   bootloader_areas_xl[] = NULL-terminated
/// ```
fn build_label_sector(pv: &PhysicalVolume) -> Vec<u8> {
    let mut buf = vec![0u8; SECTOR_SIZE as usize];

    // --- label_header (32 bytes) ---
    buf[..8].copy_from_slice(LABEL_MAGIC);
    buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // sector_xl = 0
    // crc_xl at [16..20] — filled last
    buf[20..24].copy_from_slice(&(PV_HEADER_OFFSET as u32).to_le_bytes()); // offset_xl = 32
    buf[24..32].copy_from_slice(LABEL_TYPE);

    // --- pv_header (starts at offset 32) ---
    let pv_uuid = pv.id.as_bytes();
    buf[PV_HEADER_OFFSET..PV_HEADER_OFFSET + pv_uuid.len()].copy_from_slice(pv_uuid);
    let dev_size_off = PV_HEADER_OFFSET + 32;
    buf[dev_size_off..dev_size_off + 8].copy_from_slice(&pv.device_size.to_le_bytes());

    // Data areas: one entry pointing to pe_start (size 0 = "rest of device"),
    // followed by a NULL terminator.
    let da_off = dev_size_off + 8;
    let da = DiskLocn {
        offset: pv.pe_start,
        size: 0,
    };
    buf[da_off..da_off + 16].copy_from_slice(&da.to_bytes());
    // NULL terminator for data areas
    buf[da_off + 16..da_off + 32].copy_from_slice(&DiskLocn::ZERO.to_bytes());

    // Metadata areas: one entry pointing to mda_offset with mda_size,
    // followed by a NULL terminator.
    let mda_list_off = da_off + 32;
    let mda = DiskLocn {
        offset: pv.mda_offset,
        size: pv.mda_size,
    };
    buf[mda_list_off..mda_list_off + 16].copy_from_slice(&mda.to_bytes());
    // NULL terminator for metadata areas
    buf[mda_list_off + 16..mda_list_off + 32].copy_from_slice(&DiskLocn::ZERO.to_bytes());

    // --- pv_header_extension ---
    let ext_off = mda_list_off + 32;
    buf[ext_off..ext_off + 4].copy_from_slice(&PV_HEADER_EXTENSION_VSN.to_le_bytes());
    buf[ext_off + 4..ext_off + 8].copy_from_slice(&PV_EXT_USED.to_le_bytes());
    // NULL terminator for bootloader areas
    buf[ext_off + 8..ext_off + 24].copy_from_slice(&DiskLocn::ZERO.to_bytes());

    // --- Label CRC: covers bytes [offset_xl .. sector_end) ---
    let crc = calc_crc(INITIAL_CRC, &buf[20..SECTOR_SIZE as usize]);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());

    buf
}

// ---------------------------------------------------------------------------
// MDA header construction
// ---------------------------------------------------------------------------

/// Build the 512-byte MDA header.
///
/// Layout (matching lvm2's MDA-header writer):
///
/// ```text
/// checksum_xl[4]  = CRC of bytes [4..512)
/// magic[16]      = FMTT_MAGIC
/// version[4]     = 1
/// start[8]       = absolute MDA start byte on device
/// size[8]        = MDA size in bytes
/// raw_locns[]    = committed (slot 0) + precommitted (slot 1), NULL-terminated
/// ```
fn build_mda_header(pv: &PhysicalVolume, raw_locn: RawLocn) -> Vec<u8> {
    let mut buf = vec![0u8; MDA_HEADER_SIZE as usize];

    // checksum_xl at [0..4] — filled last
    // magic at [4..20]
    buf[4..20].copy_from_slice(crate::lvm::layout::FMTT_MAGIC);
    // version at [20..24]
    buf[20..24].copy_from_slice(&crate::lvm::layout::FMTT_VERSION.to_le_bytes());
    // start at [24..32] — absolute start byte of MDA
    buf[24..32].copy_from_slice(&pv.mda_offset.to_le_bytes());
    // size at [32..40] — MDA size
    buf[32..40].copy_from_slice(&pv.mda_size.to_le_bytes());

    // raw_locn[0] (committed) at [40..64]
    write_raw_locn(&mut buf, 40, &raw_locn);
    // raw_locn[1] (precommitted) at [64..88] — zeroed (no precommitted metadata)
    write_raw_locn(&mut buf, 64, &RawLocn::ZERO);

    // Header CRC: covers bytes [4..512)
    let crc = calc_crc(INITIAL_CRC, &buf[4..MDA_HEADER_SIZE as usize]);
    buf[..4].copy_from_slice(&crc.to_le_bytes());

    buf
}

fn write_raw_locn(buf: &mut [u8], offset: usize, rlocn: &RawLocn) {
    buf[offset..offset + 8].copy_from_slice(&rlocn.offset.to_le_bytes());
    buf[offset + 8..offset + 16].copy_from_slice(&rlocn.size.to_le_bytes());
    buf[offset + 16..offset + 20].copy_from_slice(&rlocn.checksum.to_le_bytes());
    buf[offset + 20..offset + 24].copy_from_slice(&rlocn.flags.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Metadata bytes
// ---------------------------------------------------------------------------

/// Build the complete metadata-area bytes (text + NUL terminator).
///
/// Matches lvm2's metadata-export length convention, which includes the
/// trailing NUL. The `raw_locn.size` should be set to this length.
pub fn build_metadata_bytes(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0); // NUL terminator
    bytes
}

/// Compute the raw_locn for committed metadata at the given MDA-internal offset.
fn make_raw_locn(metadata_bytes: &[u8], offset_in_mda: u64) -> RawLocn {
    RawLocn {
        offset: offset_in_mda,
        size: metadata_bytes.len() as u64,
        checksum: calc_crc(INITIAL_CRC, metadata_bytes),
        flags: 0,
    }
}

// ---------------------------------------------------------------------------
// Write operations
// ---------------------------------------------------------------------------

/// Write a complete PV to a writable, seekable handle.
///
/// Writes the label sector (at offset 0), the MDA header (at `mda_offset`),
/// and the VG metadata text (right after the MDA header). All positions are
/// relative to the start of the handle (i.e. the PV's region).
///
/// This is the low-level building block used by both [`format_pv`](super::format_pv)
/// and [`create_vg`](super::create_vg).
pub fn write_pv(
    handle: &mut (impl Write + Seek),
    pv: &PhysicalVolume,
    vg_metadata_text: &str,
) -> Result<()> {
    let metadata_bytes = build_metadata_bytes(vg_metadata_text);
    let metadata_offset_in_mda = MDA_HEADER_SIZE;
    if metadata_offset_in_mda + metadata_bytes.len() as u64 > pv.mda_size {
        return Err(Error::msg(format!(
            "Metadata text ({} B) does not fit in the {}-B metadata area",
            metadata_bytes.len(),
            pv.mda_size
        )));
    }

    let raw_locn = make_raw_locn(&metadata_bytes, metadata_offset_in_mda);
    let label_sector = build_label_sector(pv);
    let mda_header = build_mda_header(pv, raw_locn);

    // Write label sector at offset 0.
    handle.seek(SeekFrom::Start(0))?;
    handle.write_all(&label_sector)?;

    // Write MDA header at mda_offset.
    handle.seek(SeekFrom::Start(pv.mda_offset))?;
    handle.write_all(&mda_header)?;

    // Write metadata text right after the MDA header.
    handle.seek(SeekFrom::Start(pv.mda_offset + MDA_HEADER_SIZE))?;
    handle.write_all(&metadata_bytes)?;

    handle.flush()?;
    Ok(())
}

/// Write only the label sector and an empty MDA (for a standalone PV that is
/// not yet part of a VG).
pub fn write_pv_label(handle: &mut (impl Write + Seek), pv: &PhysicalVolume) -> Result<()> {
    let label_sector = build_label_sector(pv);

    // Empty MDA header (no committed metadata).
    let empty_raw = RawLocn::ZERO;
    let mda_header = build_mda_header(pv, empty_raw);

    handle.seek(SeekFrom::Start(0))?;
    handle.write_all(&label_sector)?;
    handle.seek(SeekFrom::Start(pv.mda_offset))?;
    handle.write_all(&mda_header)?;
    handle.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Read operations
// ---------------------------------------------------------------------------

/// Read the label sector from a PV at `device_offset` within `handle`.
///
/// `handle` is seeked to `device_offset` (absolute within the handle) before
/// reading. The label sector is `SECTOR_SIZE` (512) bytes.
pub fn read_label_from<R: Read + Seek>(
    handle: &mut R,
    device_offset: u64,
) -> Result<(LabelHeader, PvHeader)> {
    let mut sector = vec![0u8; SECTOR_SIZE as usize];
    read_exact_at(handle, &mut sector, device_offset)?;

    // Parse label_header.
    let id = sector[..8].try_into().unwrap();
    if &id != LABEL_MAGIC {
        return Err(Error::msg(format!(
            "Not an LVM PV: bad label magic at offset {device_offset}"
        )));
    }
    let sector_num = u64::from_le_bytes(sector[8..16].try_into().unwrap());
    let stored_crc = u32::from_le_bytes(sector[16..20].try_into().unwrap());
    let offset = u32::from_le_bytes(sector[20..24].try_into().unwrap());
    let typ: [u8; 8] = sector[24..32].try_into().unwrap();
    if &typ != LABEL_TYPE {
        return Err(Error::msg(format!(
            "Unsupported LVM label type: {:?}",
            String::from_utf8_lossy(&typ)
        )));
    }
    // Verify CRC over bytes [offset_xl .. sector_end).
    let computed_crc = calc_crc(INITIAL_CRC, &sector[20..SECTOR_SIZE as usize]);
    if computed_crc != stored_crc {
        return Err(Error::msg(format!(
            "Label header CRC mismatch at offset {device_offset}: expected {stored_crc:#x}, got {computed_crc:#x}"
        )));
    }

    let lh = LabelHeader {
        id,
        sector: sector_num,
        crc: stored_crc,
        offset,
        r#type: typ,
    };

    // Parse pv_header.
    let pv_hdr_off = offset as usize;
    let pv_uuid: [u8; 32] = sector[pv_hdr_off..pv_hdr_off + 32].try_into().unwrap();
    let device_size =
        u64::from_le_bytes(sector[pv_hdr_off + 32..pv_hdr_off + 40].try_into().unwrap());

    // Parse data areas (NULL-terminated list of disk_locn).
    let mut pos = pv_hdr_off + 40;
    let mut data_areas = Vec::new();
    loop {
        if pos + 16 > sector.len() {
            break;
        }
        let dl = DiskLocn::from_bytes(&sector[pos..pos + 16]);
        pos += 16;
        if dl.is_zero() {
            break;
        }
        data_areas.push(dl);
    }

    // Parse metadata areas (NULL-terminated list of disk_locn).
    let mut metadata_areas = Vec::new();
    loop {
        if pos + 16 > sector.len() {
            break;
        }
        let dl = DiskLocn::from_bytes(&sector[pos..pos + 16]);
        pos += 16;
        if dl.is_zero() {
            break;
        }
        metadata_areas.push(dl);
    }

    // Parse pv_header_extension (if present).
    let mut ext_version = 0u32;
    let mut ext_flags = 0u32;
    if pos + 8 <= sector.len() {
        ext_version = u32::from_le_bytes(sector[pos..pos + 4].try_into().unwrap());
        ext_flags = u32::from_le_bytes(sector[pos + 4..pos + 8].try_into().unwrap());
    }

    let pv_header = PvHeader {
        pv_uuid,
        device_size,
        data_areas,
        metadata_areas,
        ext_version,
        ext_flags,
    };

    Ok((lh, pv_header))
}

/// Read the label sector from a PV device path at the given absolute offset.
///
/// Convenience wrapper around [`read_label_from`] that opens the path.
pub fn read_label(path: &Path, device_offset: u64) -> Result<(LabelHeader, PvHeader)> {
    let mut f = std::fs::File::open(path)?;
    read_label_from(&mut f, device_offset)
}

/// Read the MDA header at `mda_abs_offset` within `handle`.
pub fn read_mda_header_from<R: Read + Seek>(
    handle: &mut R,
    mda_abs_offset: u64,
) -> Result<MdaHeader> {
    let mut buf = vec![0u8; MDA_HEADER_SIZE as usize];
    read_exact_at(handle, &mut buf, mda_abs_offset)?;

    let stored_crc = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let magic: [u8; 16] = buf[4..20].try_into().unwrap();
    if &magic != crate::lvm::layout::FMTT_MAGIC {
        return Err(Error::msg("Bad MDA magic"));
    }
    let computed_crc = calc_crc(INITIAL_CRC, &buf[4..MDA_HEADER_SIZE as usize]);
    if computed_crc != stored_crc {
        return Err(Error::msg(format!(
            "MDA header CRC mismatch: expected {stored_crc:#x}, got {computed_crc:#x}"
        )));
    }

    let version = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let start = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let size = u64::from_le_bytes(buf[32..40].try_into().unwrap());

    let committed = read_raw_locn(&buf, 40);
    let precommitted = read_raw_locn(&buf, 64);

    Ok(MdaHeader {
        checksum: stored_crc,
        magic,
        version,
        start,
        size,
        committed,
        precommitted,
    })
}

/// Read the MDA header at the given absolute offset on the device path.
///
/// Convenience wrapper around [`read_mda_header_from`] that opens the path.
pub fn read_mda_header(path: &Path, mda_abs_offset: u64) -> Result<MdaHeader> {
    let mut f = std::fs::File::open(path)?;
    read_mda_header_from(&mut f, mda_abs_offset)
}

fn read_raw_locn(buf: &[u8], offset: usize) -> RawLocn {
    RawLocn {
        offset: u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap()),
        size: u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().unwrap()),
        checksum: u32::from_le_bytes(buf[offset + 16..offset + 20].try_into().unwrap()),
        flags: u32::from_le_bytes(buf[offset + 20..offset + 24].try_into().unwrap()),
    }
}

/// Read the committed VG metadata text from a PV handle at `device_offset`.
///
/// Returns the raw text (without the NUL terminator) and the parsed label/MDA
/// header information.
pub fn read_vg_metadata_from_handle<R: Read + Seek>(
    handle: &mut R,
    device_offset: u64,
) -> Result<(LabelHeader, PvHeader, MdaHeader, String)> {
    let (label, pv_header) = read_label_from(handle, device_offset)?;

    // Use the first metadata area.
    let mda = pv_header
        .metadata_areas
        .first()
        .ok_or_else(|| Error::msg("PV has no metadata areas"))?;

    let mda_abs = device_offset + mda.offset;
    let mdah = read_mda_header_from(handle, mda_abs)?;

    // Read committed metadata.
    let rlocn = &mdah.committed;
    if rlocn.is_zero() {
        return Err(Error::msg("No committed metadata in MDA"));
    }

    let text_offset = mda_abs + rlocn.offset;
    let mut text_bytes = vec![0u8; rlocn.size as usize];
    read_exact_at(handle, &mut text_bytes, text_offset)?;

    // Verify CRC.
    let computed_crc = calc_crc(INITIAL_CRC, &text_bytes);
    if computed_crc != rlocn.checksum {
        return Err(Error::msg(format!(
            "Metadata text CRC mismatch: expected {:#x}, got {:#x}",
            rlocn.checksum, computed_crc
        )));
    }

    // Strip the NUL terminator.
    let text = String::from_utf8_lossy(
        &text_bytes[..text_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(text_bytes.len())],
    )
    .into_owned();

    Ok((label, pv_header, mdah, text))
}

/// Read the committed VG metadata text from a PV.
///
/// Returns the raw text (without the NUL terminator) and the parsed label/MDA
/// header information.
pub fn read_vg_metadata_from_pv(
    path: &Path,
    device_offset: u64,
) -> Result<(LabelHeader, PvHeader, MdaHeader, String)> {
    let mut f = std::fs::File::open(path)?;
    read_vg_metadata_from_handle(&mut f, device_offset)
}

/// Read and parse a [`VolumeGroup`] from one or more PV device paths.
///
/// The first PV with valid committed metadata is used; all PVs should contain
/// identical metadata (LVM duplicates it across all PVs in a VG).
pub fn read_vg_from_paths(paths: &[impl AsRef<Path>]) -> Result<VolumeGroup> {
    if paths.is_empty() {
        return Err(Error::msg("No PV paths provided"));
    }

    let mut last_err = None;
    for path in paths {
        let path = path.as_ref();
        match read_vg_metadata_from_pv(path, 0) {
            Ok((_label, _pv_header, _mdah, text)) => {
                return text::parse_vg_metadata(&text);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::msg("No PVs with valid metadata found")))
}

/// Read and parse a [`VolumeGroup`] from a single seekable PV handle (e.g. a
/// [`crate::blockfile::BlockFile`] sub-region representing a PV). Returns
/// `Ok(None)` when the handle does not contain a valid LVM2 PV label (so
/// callers can distinguish "no existing VG" from "corrupt metadata").
pub fn read_vg_from_handle<R: Read + Seek>(handle: &mut R) -> Result<Option<VolumeGroup>> {
    match read_vg_metadata_from_handle(handle, 0) {
        Ok((_label, _pv_header, _mdah, text)) => Ok(Some(text::parse_vg_metadata(&text)?)),
        Err(e) => {
            // Distinguish "not an LVM PV" (no label magic) from real corruption.
            let msg = e.to_string();
            if msg.contains("Not an LVM PV") || msg.contains("bad label magic") {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Read the raw content of an LV from PV device paths.
///
/// Reads the VG metadata, locates the LV, and reads the content of each
/// segment from the appropriate PV. For a simple linear LV (single segment on
/// a single PV), the content is contiguous.
pub fn read_lv_content(paths: &[impl AsRef<Path>], lv_name: &str) -> Result<Vec<u8>> {
    let vg = read_vg_from_paths(paths)?;
    let lv = vg
        .find_lv(lv_name)
        .ok_or_else(|| Error::msg(format!("LV '{lv_name}' not found in VG '{}'", vg.name)))?;

    // Build a map from PV name to device path (by reading each PV's label).
    let mut pv_paths: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    for path in paths {
        let path = path.as_ref();
        if let Ok((_label, pv_header)) = read_label(path, 0) {
            let pv_id = String::from_utf8_lossy(&pv_header.pv_uuid).to_string();
            // Match by PV UUID.
            for pv in &vg.pvs {
                if pv.id == pv_id {
                    pv_paths.insert(pv.name.clone(), path.to_path_buf());
                }
            }
        }
    }

    let mut content = Vec::with_capacity(lv.size_bytes(vg.extent_size) as usize);
    for seg in &lv.segments {
        let pv = vg
            .find_pv(&seg.pv_name)
            .ok_or_else(|| Error::msg(format!("PV '{}' not found in VG", seg.pv_name)))?;
        let _ = pv;
        let pv_path = pv_paths
            .get(&seg.pv_name)
            .ok_or_else(|| Error::msg(format!("No device path for PV '{}'", seg.pv_name)))?;

        let seg_size = seg.size_bytes(vg.extent_size) as usize;
        let seg_offset = vg
            .find_pv(&seg.pv_name)
            .unwrap()
            .extent_offset(seg.pv_start_extent, vg.extent_size);
        let mut buf = vec![0u8; seg_size];
        let mut f = std::fs::File::open(pv_path)?;
        read_exact_at(&mut f, &mut buf, seg_offset)?;
        content.extend_from_slice(&buf);
    }

    Ok(content)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_exact_at<R: Read + Seek>(handle: &mut R, buf: &mut [u8], pos: u64) -> Result<()> {
    handle.seek(SeekFrom::Start(pos))?;
    handle.read_exact(buf)?;
    Ok(())
}
