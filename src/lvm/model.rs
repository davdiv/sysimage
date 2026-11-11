//! In-memory data model for LVM2 volume groups, physical volumes, and logical
//! volumes.
//!
//! These structures are the Rust analogues of lvm2's in-memory volume-group
//! model. Only the fields needed for the text format and the supported
//! operations (linear/striped LVs) are modelled.

use crate::lvm::layout::{
    DEFAULT_EXTENT_SIZE, DEFAULT_MDA_OFFSET, DEFAULT_PE_START, SECTOR_SIZE, default_mda_size,
};

/// A physical volume (PV) — one device's contribution to a VG.
#[derive(Debug, Clone)]
pub struct PhysicalVolume {
    /// Section name in the metadata text, e.g. `"pv0"`.
    pub name: String,
    /// 32-char raw UUID (no dashes).
    pub id: String,
    /// Total device size in bytes.
    pub device_size: u64,
    /// Byte offset of the first physical extent (default 1 MiB).
    pub pe_start: u64,
    /// Metadata area offset on the device (default 4096).
    pub mda_offset: u64,
    /// Metadata area size in bytes.
    pub mda_size: u64,
    /// Total number of physical extents on this PV.
    pub pe_count: u64,
    /// Number of allocated physical extents.
    pub pe_alloc_count: u64,
}

impl PhysicalVolume {
    /// Create a PV with default layout values for the given device size.
    pub fn new(name: impl Into<String>, id: impl Into<String>, device_size: u64) -> Self {
        let pe_start = DEFAULT_PE_START;
        let mda_offset = DEFAULT_MDA_OFFSET;
        let mda_size = default_mda_size(pe_start, mda_offset);
        let extent_size = DEFAULT_EXTENT_SIZE;
        let pe_count = if device_size > pe_start {
            (device_size - pe_start) / extent_size
        } else {
            0
        };
        Self {
            name: name.into(),
            id: id.into(),
            device_size,
            pe_start,
            mda_offset,
            mda_size,
            pe_count,
            pe_alloc_count: 0,
        }
    }

    /// Number of free (unallocated) extents on this PV.
    pub fn free_extents(&self) -> u64 {
        self.pe_count.saturating_sub(self.pe_alloc_count)
    }

    /// Byte offset of a given physical extent on this PV's device.
    pub fn extent_offset(&self, pe: u64, extent_size: u64) -> u64 {
        self.pe_start + pe * extent_size
    }
}

/// A single contiguous segment of an LV mapped onto a PV.
///
/// Corresponds to a `segmentN { ... }` block in the text metadata with
/// `type = "striped"` and `stripe_count = 1` (a linear segment).
#[derive(Debug, Clone)]
pub struct LvSegment {
    /// Logical extent number within the LV where this segment starts.
    pub start_extent: u64,
    /// Number of extents in this segment.
    pub extent_count: u64,
    /// Name of the PV this segment maps to (e.g. `"pv0"`).
    pub pv_name: String,
    /// Starting physical extent on the PV.
    pub pv_start_extent: u64,
}

impl LvSegment {
    /// Byte size of this segment given the VG's extent size.
    pub fn size_bytes(&self, extent_size: u64) -> u64 {
        self.extent_count * extent_size
    }
}

/// A logical volume (LV) within a VG.
#[derive(Debug, Clone)]
pub struct LogicalVolume {
    /// LV name (section key in the metadata text).
    pub name: String,
    /// 32-char raw UUID (no dashes).
    pub id: String,
    /// Ordered list of segments.
    pub segments: Vec<LvSegment>,
}

impl LogicalVolume {
    /// Total number of logical extents across all segments.
    pub fn extent_count(&self) -> u64 {
        self.segments.iter().map(|s| s.extent_count).sum()
    }

    /// Total size in bytes given the VG's extent size.
    pub fn size_bytes(&self, extent_size: u64) -> u64 {
        self.extent_count() * extent_size
    }
}

/// A volume group (VG) — the top-level LVM container.
#[derive(Debug, Clone)]
pub struct VolumeGroup {
    /// VG name (top-level section key in the metadata text).
    pub name: String,
    /// 32-char raw UUID (no dashes).
    pub id: String,
    /// Sequence number, incremented on each metadata update.
    pub seqno: u32,
    /// Physical extent size in bytes (default 4 MiB).
    pub extent_size: u64,
    /// Physical volumes in this VG.
    pub pvs: Vec<PhysicalVolume>,
    /// Logical volumes in this VG.
    pub lvs: Vec<LogicalVolume>,
}

impl VolumeGroup {
    /// Create a new, empty VG with the given name and default extent size.
    pub fn new(name: impl Into<String>, id: impl Into<String>, extent_size: u64) -> Self {
        Self {
            name: name.into(),
            id: id.into(),
            seqno: 1,
            extent_size,
            pvs: Vec::new(),
            lvs: Vec::new(),
        }
    }

    /// Total number of physical extents across all PVs.
    pub fn total_extents(&self) -> u64 {
        self.pvs.iter().map(|pv| pv.pe_count).sum()
    }

    /// Total allocated extents across all PVs.
    pub fn allocated_extents(&self) -> u64 {
        self.pvs.iter().map(|pv| pv.pe_alloc_count).sum()
    }

    /// Total free extents across all PVs.
    pub fn free_extents(&self) -> u64 {
        self.total_extents() - self.allocated_extents()
    }

    /// Find a PV by name.
    pub fn find_pv(&self, name: &str) -> Option<&PhysicalVolume> {
        self.pvs.iter().find(|pv| pv.name == name)
    }

    /// Find a PV by name (mutable).
    pub fn find_pv_mut(&mut self, name: &str) -> Option<&mut PhysicalVolume> {
        self.pvs.iter_mut().find(|pv| pv.name == name)
    }

    /// Find an LV by name.
    pub fn find_lv(&self, name: &str) -> Option<&LogicalVolume> {
        self.lvs.iter().find(|lv| lv.name == name)
    }

    /// Extent size in sectors (as stored in the text metadata).
    pub fn extent_size_sectors(&self) -> u64 {
        self.extent_size / SECTOR_SIZE
    }
}
