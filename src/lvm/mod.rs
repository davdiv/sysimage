//! LVM2 text-format on-disk metadata — pure-Rust reader and writer.
//!
//! This module implements the subset of LVM2's text format needed to:
//!
//! 1. **Format a new physical volume** ([`format_pv`]) — writes the label
//!    sector, MDA header, and empty metadata.
//! 2. **Create a volume group** ([`create_vg`]) — assembles one or more PVs
//!    into a VG and writes the VG metadata to all PVs.
//! 3. **Create a logical volume** ([`create_lv`]) — allocates extents on a PV
//!    and writes the updated VG metadata to all PVs.
//! 4. **Read an existing volume group** ([`read_vg`]) — reads the label, MDA
//!    header, and text metadata from one or more PVs.
//! 5. **List logical volumes** ([`list_lvs`]) — reads the VG and returns the
//!    LV names.
//! 6. **Read LV content** ([`read_lv`]) — reads the raw bytes of an LV from
//!    the PVs' physical extents.
//!
//! The on-disk layout (label sector, MDA header, raw_locn, CRC) and the text
//! metadata format mirror lvm2's.
//!
//! # Example
//!
//! ```no_run
//! use sysimage::lvm;
//! use std::path::Path;
//!
//! // Format a PV on a 16 MiB file.
//! let path = Path::new("/dev/sdb");
//! let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
//! let pv = lvm::format_pv(&mut file, 16 * 1024 * 1024).unwrap();
//!
//! // Create a VG with that PV.
//! let mut vg = lvm::create_vg("myvg", &mut [(file, pv)], 4 * 1024 * 1024).unwrap();
//!
//! // Read the VG back.
//! let read_back = lvm::read_vg(&[path]).unwrap();
//! assert_eq!(read_back.name, "myvg");
//!
//! // List LVs.
//! let lvs = lvm::list_lvs(&[path]).unwrap();
//! ```

pub mod io;
pub mod layout;
pub mod model;
pub mod text;
pub mod uuid;

// Re-export the most commonly used items.
pub use io::{
    read_label_from, read_lv_content, read_mda_header_from, read_vg_from_handle,
    read_vg_from_paths, read_vg_metadata_from_handle, write_pv, write_pv_label,
};
pub use layout::{
    DEFAULT_EXTENT_SIZE, DEFAULT_MDA_OFFSET, DEFAULT_PE_START, DiskLocn, LabelHeader,
    MDA_HEADER_SIZE, MdaHeader, PvHeader, RawLocn, SECTOR_SIZE, calc_crc, default_mda_size,
};
pub use model::{LogicalVolume, LvSegment, PhysicalVolume, VolumeGroup};
pub use text::{emit_vg_metadata, parse_vg_metadata};
pub use uuid::{format_id, generate_id, parse_id};

use std::io::{Seek, Write};
use std::path::Path;

use crate::error::{Error, Result};

// ===========================================================================
// High-level operations
// ===========================================================================

/// Format a new physical volume on a writable, seekable device.
///
/// Writes the label sector (at offset 0), the MDA header (at the page-size
/// offset, 4096 by default), and an empty MDA (no committed metadata). The PV
/// is not yet part of a volume group.
///
/// Returns the [`PhysicalVolume`] descriptor with default layout values.
///
/// # Example
/// ```no_run
/// # use sysimage::lvm;
/// let mut f = std::fs::OpenOptions::new()
///     .write(true).create(true).truncate(true)
///     .open("/tmp/pv.img").unwrap();
/// let pv = lvm::format_pv(&mut f, 16 * 1024 * 1024).unwrap();
/// ```
pub fn format_pv(handle: &mut (impl Write + Seek), device_size: u64) -> Result<PhysicalVolume> {
    let pv = PhysicalVolume::new("pv0", uuid::generate_id(), device_size);
    write_pv_label(handle, &pv)?;
    Ok(pv)
}

/// Create a volume group from one or more formatted physical volumes.
///
/// Each PV must have been previously formatted (e.g. via [`format_pv`]).
/// The VG metadata is written to all PVs. Returns the [`VolumeGroup`].
///
/// `extent_size` is the physical extent size in bytes (default 4 MiB).
pub fn create_vg(
    vg_name: &str,
    pv_handles: &mut [(impl Write + Seek, PhysicalVolume)],
    extent_size: u64,
) -> Result<VolumeGroup> {
    if pv_handles.is_empty() {
        return Err(Error::msg("Cannot create a VG with no PVs"));
    }

    let extent_size = if extent_size == 0 {
        DEFAULT_EXTENT_SIZE
    } else {
        extent_size
    };

    // Assign PV names: pv0, pv1, ...
    let mut pvs: Vec<PhysicalVolume> = pv_handles
        .iter_mut()
        .enumerate()
        .map(|(i, (_, pv))| {
            pv.name = format!("pv{i}");
            pv.clone()
        })
        .collect();

    // Recompute pe_count for each PV with the given extent_size.
    for pv in &mut pvs {
        pv.pe_count = if pv.device_size > pv.pe_start {
            (pv.device_size - pv.pe_start) / extent_size
        } else {
            0
        };
        pv.pe_alloc_count = 0;
    }

    let mut vg = VolumeGroup::new(vg_name, uuid::generate_id(), extent_size);
    vg.pvs = pvs.clone();

    let metadata_text = emit_vg_metadata(&vg);

    // Write the metadata to all PVs.
    for (handle, pv) in pv_handles.iter_mut() {
        write_pv(handle, pv, &metadata_text)?;
    }

    Ok(vg)
}

/// Create a normal (linear) logical volume in a volume group.
///
/// Allocates `size` bytes (rounded up to the extent size) on the first PV with
/// enough free space, creates a single linear segment, and writes the updated
/// VG metadata to all PVs.
///
/// Returns the new [`LogicalVolume`].
pub fn create_lv(
    vg: &mut VolumeGroup,
    pv_handles: &mut [(impl Write + Seek, PhysicalVolume)],
    lv_name: &str,
    size: u64,
) -> Result<LogicalVolume> {
    if vg.find_lv(lv_name).is_some() {
        return Err(Error::msg(format!(
            "LV '{lv_name}' already exists in VG '{}'",
            vg.name
        )));
    }

    let extent_size = vg.extent_size;
    let extent_count = size.div_ceil(extent_size);
    if extent_count == 0 {
        return Err(Error::msg("LV size must be at least one extent"));
    }

    // Find a PV with enough free extents (simple linear allocation).
    let (pv_idx, pv_start_extent) = vg
        .pvs
        .iter()
        .enumerate()
        .find(|(_, pv)| pv.free_extents() >= extent_count)
        .map(|(i, pv)| (i, pv.pe_alloc_count))
        .ok_or_else(|| {
            Error::msg(format!(
                "Not enough free extents in VG '{}' for LV '{lv_name}' (need {extent_count}, have {})",
                vg.name,
                vg.free_extents()
            ))
        })?;

    // Update the PV's allocation count.
    vg.pvs[pv_idx].pe_alloc_count += extent_count;

    let lv = LogicalVolume {
        name: lv_name.to_string(),
        id: uuid::generate_id(),
        segments: vec![LvSegment {
            start_extent: 0,
            extent_count,
            pv_name: vg.pvs[pv_idx].name.clone(),
            pv_start_extent,
        }],
    };

    vg.lvs.push(lv.clone());
    vg.seqno += 1;

    // Write updated metadata to all PVs.
    let metadata_text = emit_vg_metadata(vg);
    for (handle, pv) in pv_handles.iter_mut() {
        // Update the PV's pe_alloc_count in the handle's copy too.
        if let Some(vg_pv) = vg.pvs.iter().find(|p| p.name == pv.name) {
            pv.pe_alloc_count = vg_pv.pe_alloc_count;
            pv.pe_count = vg_pv.pe_count;
        }
        write_pv(handle, pv, &metadata_text)?;
    }

    Ok(lv)
}

/// Read an existing volume group from one or more PV device paths.
///
/// The first PV with valid committed metadata is used. All PVs in a VG
/// contain identical metadata, so any one suffices.
pub fn read_vg(paths: &[impl AsRef<Path>]) -> Result<VolumeGroup> {
    io::read_vg_from_paths(paths)
}

/// List the logical volume names in a volume group.
pub fn list_lvs(paths: &[impl AsRef<Path>]) -> Result<Vec<String>> {
    let vg = read_vg(paths)?;
    Ok(vg.lvs.iter().map(|lv| lv.name.clone()).collect())
}

/// Read the raw content of a logical volume from PV device paths.
///
/// Reads the VG metadata, locates the LV by name, and reads each segment's
/// physical extents from the corresponding PV device.
pub fn read_lv(paths: &[impl AsRef<Path>], lv_name: &str) -> Result<Vec<u8>> {
    io::read_lv_content(paths, lv_name)
}

// ===========================================================================
// Backward-compatible helpers for the sysimage install pipeline
// ===========================================================================

/// Size of a PV's backing region (used by the install pipeline).
#[derive(Debug, Clone, Copy)]
pub struct PvRegion {
    pub device_size: u64,
}

/// Per-LV install plan: where and how large to install the LV's content.
#[derive(Debug, Clone)]
pub struct LvInstallPlan {
    pub partition: crate::model::manifest::ManifestLvmPartition,
    /// Offset of the LV's first extent, relative to the start of the PV region.
    pub relative_offset: u64,
    pub size: u64,
}

/// Resolved VG layout (used by the install pipeline).
#[derive(Debug, Clone)]
pub struct VgLayout {
    pub vg: VolumeGroup,
    pub lv_plans: Vec<LvInstallPlan>,
}

/// Compute a single-PV VG layout and assign each LV a contiguous run of extents.
///
/// This is a sysimage-specific helper that bridges the manifest model and the
/// LVM model. It takes the manifest's VG spec and PV region sizes, computes
/// the LV sizes using the sysimage partition-size algorithm, and returns a
/// [`VgLayout`] with the VG and per-LV install plans.
pub fn compute_vg_layout(
    vg_name: &str,
    vg_manifest: &crate::model::manifest::ManifestLvmVg,
    pv_regions: &[PvRegion],
) -> Result<VgLayout> {
    use crate::model::manifest::ManifestPartitionSize;
    use crate::size::compute_partition_sizes;

    if pv_regions.is_empty() {
        return Err(Error::msg(format!(
            "Volume group \"{vg_name}\" has no physical volumes"
        )));
    }

    let pe_size = DEFAULT_EXTENT_SIZE;
    let pe_start = DEFAULT_PE_START;

    // Build PVs from the regions.
    let mut pvs = Vec::with_capacity(pv_regions.len());
    for (i, region) in pv_regions.iter().enumerate() {
        let device_size = region.device_size;
        if device_size <= pe_start {
            return Err(Error::msg(format!(
                "PV {i} for volume group \"{vg_name}\" is too small ({device_size} B <= {pe_start} B PE start)"
            )));
        }
        let pe_count = (device_size - pe_start) / pe_size;
        if pe_count == 0 && i == 0 {
            return Err(Error::msg(format!(
                "PV for volume group \"{vg_name}\" has no usable extents"
            )));
        }
        pvs.push(PhysicalVolume::new(
            format!("pv{i}"),
            uuid::generate_id(),
            device_size,
        ));
    }

    // For the install pipeline, all LVs are allocated on the first PV.
    let pv0 = &pvs[0];
    let pe_count = pv0.pe_count;
    let usable_bytes = pe_count * pe_size;

    // Compute LV sizes from the manifest.
    let mut size_entries: Vec<ManifestPartitionSize> = vg_manifest
        .partitions
        .iter()
        .map(|p| p.size.clone())
        .collect();
    if let Some(empty) = &vg_manifest.empty_space {
        size_entries.push(empty.clone());
    }
    let computed = compute_partition_sizes(&size_entries, usable_bytes, pe_size)?;
    let lv_sizes = &computed[..vg_manifest.partitions.len()];

    // Build LVs and install plans.
    let mut lvs = Vec::with_capacity(vg_manifest.partitions.len());
    let mut lv_plans = Vec::with_capacity(vg_manifest.partitions.len());
    let mut next_pe: u64 = 0;
    for (i, partition) in vg_manifest.partitions.iter().enumerate() {
        let size = lv_sizes[i];
        let extent_count = size / pe_size;
        if next_pe + extent_count > pe_count {
            return Err(Error::msg(format!(
                "LV \"{}\" does not fit in the PV",
                partition.name
            )));
        }
        lvs.push(LogicalVolume {
            name: partition.name.clone(),
            id: uuid::generate_id(),
            segments: vec![LvSegment {
                start_extent: 0,
                extent_count,
                pv_name: pv0.name.clone(),
                pv_start_extent: next_pe,
            }],
        });
        lv_plans.push(LvInstallPlan {
            partition: partition.clone(),
            relative_offset: pv0.pe_start + next_pe * pe_size,
            size,
        });
        next_pe += extent_count;
    }

    pvs[0].pe_alloc_count = next_pe;

    let vg = VolumeGroup {
        name: vg_name.to_string(),
        id: uuid::generate_id(),
        seqno: 1,
        extent_size: pe_size,
        pvs,
        lvs,
    };

    Ok(VgLayout { vg, lv_plans })
}

// ===========================================================================
// Backward-compatible reader functions (used by tests)
// ===========================================================================

/// Parsed PV label (backward-compatible name for tests).
#[derive(Debug, Clone)]
pub struct ReadPvLabel {
    pub sector: u64,
    pub r#type: String,
    pub pv_id: String,
    pub device_size: u64,
    pub data_areas: Vec<DiskLocn>,
    pub metadata_areas: Vec<DiskLocn>,
}

/// Read a PV label from a device at the given offset.
pub fn read_pv_label(path: &Path, device_offset: u64) -> Result<ReadPvLabel> {
    let (label, pv_header) = io::read_label(path, device_offset)?;
    Ok(ReadPvLabel {
        sector: label.sector,
        r#type: String::from_utf8_lossy(&label.r#type).to_string(),
        pv_id: String::from_utf8_lossy(&pv_header.pv_uuid).to_string(),
        device_size: pv_header.device_size,
        data_areas: pv_header.data_areas,
        metadata_areas: pv_header.metadata_areas,
    })
}

/// Parsed MDA (backward-compatible name for tests).
#[derive(Debug, Clone)]
pub struct ReadMda {
    pub start: u64,
    pub size: u64,
    pub version: u32,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub raw_checksum: u32,
    pub text: Vec<u8>,
}

/// Read the MDA header + text at `mda_offset` (device-relative).
pub fn read_mda(path: &Path, device_offset: u64, mda_offset: u64) -> Result<ReadMda> {
    let mdah = io::read_mda_header(path, device_offset + mda_offset)?;

    let rlocn = &mdah.committed;
    let mut f = std::fs::File::open(path)?;
    let mut text = vec![0u8; rlocn.size as usize];
    use std::io::Read;
    f.seek(std::io::SeekFrom::Start(
        device_offset + mda_offset + rlocn.offset,
    ))?;
    f.read_exact(&mut text)?;

    Ok(ReadMda {
        start: mdah.start,
        size: mdah.size,
        version: mdah.version,
        raw_offset: rlocn.offset,
        raw_size: rlocn.size,
        raw_checksum: rlocn.checksum,
        text,
    })
}
