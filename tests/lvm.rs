//! Comprehensive tests for the LVM2 text-format implementation.
//!
//! These tests cover all six supported operations:
//! 1. Formatting a new physical volume
//! 2. Creating a volume group with one or more PVs
//! 3. Creating a normal logical volume
//! 4. Reading an existing volume group
//! 5. Listing logical volumes in a volume group
//! 6. Reading the content of a logical volume
//!
//! In addition, the tests validate the on-disk binary layout against `pvck`
//! (when available) and verify round-trip serialization of the text metadata.

mod common;

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::lvm::{
    self, DEFAULT_EXTENT_SIZE, DEFAULT_MDA_OFFSET, DEFAULT_PE_START, LogicalVolume, LvSegment,
    MDA_HEADER_SIZE, PhysicalVolume, VolumeGroup, compute_vg_layout, emit_vg_metadata, generate_id,
    read_mda, read_pv_label,
};
use sysimage::model::manifest::{ManifestLvmPartition, ManifestLvmVg, ManifestPartitionSize};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-lvm-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Create a sparse file of the given size and return its path.
fn make_sparse_file(dir: &TempDir, name: &str, size: u64) -> PathBuf {
    let path = dir.path().join(name);
    let f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.set_len(size).unwrap();
    path
}

/// Open a file for writing at offset 0 with the given size.
fn open_rw(path: &Path) -> fs::File {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

// ---------------------------------------------------------------------------
// 1. Formatting a new physical volume
// ---------------------------------------------------------------------------

#[test]
fn format_pv_writes_valid_label() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 16 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 16 * 1024 * 1024).unwrap();

    // Read back the label.
    let label = read_pv_label(&path, 0).unwrap();
    assert_eq!(label.r#type, "LVM2 001");
    assert_eq!(label.pv_id, pv.id);
    assert_eq!(label.device_size, 16 * 1024 * 1024);
    // One data area at pe_start (1 MiB), size 0 = "rest of device".
    assert_eq!(label.data_areas.len(), 1);
    assert_eq!(label.data_areas[0].offset, DEFAULT_PE_START);
    assert_eq!(label.data_areas[0].size, 0);
    // One metadata area at the page-size offset (4096).
    assert_eq!(label.metadata_areas.len(), 1);
    assert_eq!(label.metadata_areas[0].offset, DEFAULT_MDA_OFFSET);
    assert_eq!(
        label.metadata_areas[0].size,
        DEFAULT_PE_START - DEFAULT_MDA_OFFSET
    );
}

#[test]
fn format_pv_pvck_valid() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 16 * 1024 * 1024);
    let pvck_path = dir.path().join("pvck_test.bin");
    fs::copy(&path, &pvck_path).unwrap();

    let mut f = open_rw(&path);
    lvm::format_pv(&mut f, 16 * 1024 * 1024).unwrap();

    fs::copy(&path, &pvck_path).unwrap();

    // Validate with pvck (the test is primarily about `format_pv`; the pvck
    // cross-check is a bonus, so skip only that part — not the whole test —
    // when pvck is not on PATH, unless `SYSIMAGE_REQUIRE_TOOLS` is set, in
    // which case `tool_or_skip` hard-fails).
    if common::tool_or_skip("pvck") {
        let output = std::process::Command::new("pvck")
            .args(["--dump", "headers", "--labelsector", "0"])
            .arg(&pvck_path)
            .output()
            .expect("pvck available");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        // pvck should find a valid label with no CHECK errors.
        assert!(
            combined.contains("label_header.id LABELONE"),
            "pvck output: {combined}"
        );
        assert!(
            !combined.contains("CHECK: pv_header.pv_uuid invalid format"),
            "pvck found invalid UUID: {combined}"
        );
        assert!(
            !combined.contains("is unexpected # for first mda"),
            "pvck found unexpected MDA offset: {combined}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Creating a volume group with one or more PVs
// ---------------------------------------------------------------------------

#[test]
fn create_vg_single_pv() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    assert_eq!(vg.name, "testvg");
    assert_eq!(vg.pvs.len(), 1);
    assert_eq!(vg.pvs[0].name, "pv0");
    assert_eq!(vg.extent_size, DEFAULT_EXTENT_SIZE);
    // (32 MiB - 1 MiB) / 4 MiB = 7 extents.
    assert_eq!(vg.pvs[0].pe_count, 7);
    assert_eq!(vg.pvs[0].pe_alloc_count, 0);
    assert_eq!(vg.lvs.len(), 0);
}

#[test]
fn create_vg_multi_pv() {
    let dir = TempDir::new();
    let path0 = make_sparse_file(&dir, "pv0.bin", 32 * 1024 * 1024);
    let path1 = make_sparse_file(&dir, "pv1.bin", 32 * 1024 * 1024);

    let mut f0 = open_rw(&path0);
    let pv0 = lvm::format_pv(&mut f0, 32 * 1024 * 1024).unwrap();

    let mut f1 = open_rw(&path1);
    let pv1 = lvm::format_pv(&mut f1, 32 * 1024 * 1024).unwrap();

    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let vg = lvm::create_vg("multivg", &mut [(f0, pv0), (f1, pv1)], DEFAULT_EXTENT_SIZE).unwrap();

    assert_eq!(vg.pvs.len(), 2);
    assert_eq!(vg.pvs[0].name, "pv0");
    assert_eq!(vg.pvs[1].name, "pv1");
    assert_eq!(vg.total_extents(), 14); // 7 + 7
}

#[test]
fn create_vg_writes_metadata_to_all_pvs() {
    let dir = TempDir::new();
    let path0 = make_sparse_file(&dir, "pv0.bin", 32 * 1024 * 1024);
    let path1 = make_sparse_file(&dir, "pv1.bin", 32 * 1024 * 1024);

    let mut f0 = open_rw(&path0);
    let pv0 = lvm::format_pv(&mut f0, 32 * 1024 * 1024).unwrap();
    let mut f1 = open_rw(&path1);
    let pv1 = lvm::format_pv(&mut f1, 32 * 1024 * 1024).unwrap();

    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let vg = lvm::create_vg("testvg", &mut [(f0, pv0), (f1, pv1)], DEFAULT_EXTENT_SIZE).unwrap();

    // Both PVs should have the same metadata.
    let vg0 = lvm::read_vg(&[&path0]).unwrap();
    let vg1 = lvm::read_vg(&[&path1]).unwrap();
    assert_eq!(vg0.name, "testvg");
    assert_eq!(vg1.name, "testvg");
    assert_eq!(vg0.id, vg.id);
    assert_eq!(vg1.id, vg.id);
    assert_eq!(vg0.pvs.len(), 2);
    assert_eq!(vg1.pvs.len(), 2);
}

// ---------------------------------------------------------------------------
// 3. Creating a normal logical volume
// ---------------------------------------------------------------------------

#[test]
fn create_lv_basic() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let lv = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 8 * 1024 * 1024).unwrap();

    assert_eq!(lv.name, "lv0");
    assert_eq!(lv.segments.len(), 1);
    assert_eq!(lv.segments[0].extent_count, 2); // 8 MiB / 4 MiB = 2 extents
    assert_eq!(lv.segments[0].pv_name, "pv0");
    assert_eq!(lv.segments[0].pv_start_extent, 0);
    assert_eq!(vg.pvs[0].pe_alloc_count, 2);
    assert_eq!(vg.seqno, 2); // incremented
}

#[test]
fn create_lv_multiple_lvs() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 64 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 64 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    // Create three LVs.
    for i in 0..3 {
        let f = open_rw(&path);
        let pv_clone = vg.pvs[0].clone();
        lvm::create_lv(
            &mut vg,
            &mut [(f, pv_clone)],
            &format!("lv{i}"),
            4 * 1024 * 1024,
        )
        .unwrap();
    }

    assert_eq!(vg.lvs.len(), 3);
    assert_eq!(vg.pvs[0].pe_alloc_count, 3);
    // Each LV gets a different starting extent.
    assert_eq!(vg.lvs[0].segments[0].pv_start_extent, 0);
    assert_eq!(vg.lvs[1].segments[0].pv_start_extent, 1);
    assert_eq!(vg.lvs[2].segments[0].pv_start_extent, 2);
}

#[test]
fn create_lv_rounds_up_to_extent() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    // 5 MiB request → 2 extents (8 MiB) with 4 MiB extent size.
    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let lv = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 5 * 1024 * 1024).unwrap();

    assert_eq!(lv.segments[0].extent_count, 2);
    assert_eq!(lv.size_bytes(DEFAULT_EXTENT_SIZE), 8 * 1024 * 1024);
}

#[test]
fn create_lv_fails_on_duplicate_name() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 4 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let result = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 4 * 1024 * 1024);

    assert!(result.is_err());
}

#[test]
fn create_lv_fails_on_insufficient_space() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 8 * 1024 * 1024); // very small

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 8 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    // Only 1 extent available (8 MiB - 1 MiB = 7 MiB, 7/4 = 1 extent).
    // Request 2 extents → should fail.
    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let result = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 8 * 1024 * 1024);

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 4. Reading an existing volume group
// ---------------------------------------------------------------------------

#[test]
fn read_vg_round_trip() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let original_vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let read_vg = lvm::read_vg(&[&path]).unwrap();
    assert_eq!(read_vg.name, original_vg.name);
    assert_eq!(read_vg.id, original_vg.id);
    assert_eq!(read_vg.seqno, original_vg.seqno);
    assert_eq!(read_vg.extent_size, original_vg.extent_size);
    assert_eq!(read_vg.pvs.len(), original_vg.pvs.len());
    assert_eq!(read_vg.pvs[0].name, original_vg.pvs[0].name);
    assert_eq!(read_vg.pvs[0].id, original_vg.pvs[0].id);
    assert_eq!(read_vg.pvs[0].pe_start, original_vg.pvs[0].pe_start);
    assert_eq!(read_vg.pvs[0].pe_count, original_vg.pvs[0].pe_count);
}

#[test]
fn read_vg_multi_pv() {
    let dir = TempDir::new();
    let path0 = make_sparse_file(&dir, "pv0.bin", 32 * 1024 * 1024);
    let path1 = make_sparse_file(&dir, "pv1.bin", 32 * 1024 * 1024);

    let mut f0 = open_rw(&path0);
    let pv0 = lvm::format_pv(&mut f0, 32 * 1024 * 1024).unwrap();
    let mut f1 = open_rw(&path1);
    let pv1 = lvm::format_pv(&mut f1, 32 * 1024 * 1024).unwrap();

    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let original_vg =
        lvm::create_vg("multivg", &mut [(f0, pv0), (f1, pv1)], DEFAULT_EXTENT_SIZE).unwrap();

    // Read from either PV.
    let read_vg0 = lvm::read_vg(&[&path0]).unwrap();
    let read_vg1 = lvm::read_vg(&[&path1]).unwrap();
    let read_vg_both = lvm::read_vg(&[&path0, &path1]).unwrap();

    assert_eq!(read_vg0.pvs.len(), 2);
    assert_eq!(read_vg1.pvs.len(), 2);
    assert_eq!(read_vg_both.pvs.len(), 2);
    assert_eq!(read_vg0.id, original_vg.id);
    assert_eq!(read_vg1.id, original_vg.id);
}

#[test]
fn read_vg_with_lvs() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 64 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 64 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    for i in 0..3 {
        let f = open_rw(&path);
        let pv_clone = vg.pvs[0].clone();
        lvm::create_lv(
            &mut vg,
            &mut [(f, pv_clone)],
            &format!("lv{i}"),
            4 * 1024 * 1024,
        )
        .unwrap();
    }

    let read_vg = lvm::read_vg(&[&path]).unwrap();
    assert_eq!(read_vg.lvs.len(), 3);
    for i in 0..3 {
        let lv = &read_vg.lvs[i];
        assert_eq!(lv.name, format!("lv{i}"));
        assert_eq!(lv.segments.len(), 1);
        assert_eq!(lv.segments[0].extent_count, 1);
    }
}

// ---------------------------------------------------------------------------
// 5. Listing logical volumes in a volume group
// ---------------------------------------------------------------------------

#[test]
fn list_lvs_empty_vg() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let lvs = lvm::list_lvs(&[&path]).unwrap();
    assert!(lvs.is_empty());
}

#[test]
fn list_lvs_with_volumes() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 64 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 64 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let names = vec!["root", "var", "home"];
    for name in &names {
        let f = open_rw(&path);
        let pv_clone = vg.pvs[0].clone();
        lvm::create_lv(&mut vg, &mut [(f, pv_clone)], name, 4 * 1024 * 1024).unwrap();
    }

    let lvs = lvm::list_lvs(&[&path]).unwrap();
    assert_eq!(lvs, names);
}

// ---------------------------------------------------------------------------
// 6. Reading the content of a logical volume
// ---------------------------------------------------------------------------

#[test]
fn read_lv_content() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let lv = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 8 * 1024 * 1024).unwrap();

    // Write known content into the LV's physical extents.
    let content_offset = DEFAULT_PE_START; // pe_start + 0 * extent_size
    let content = b"Hello, LVM!";
    let mut f = open_rw(&path);
    f.seek(SeekFrom::Start(content_offset)).unwrap();
    f.write_all(content).unwrap();

    // Read the LV content back.
    let read_content = lvm::read_lv(&[&path], "lv0").unwrap();
    assert_eq!(&read_content[..content.len()], content);
    assert_eq!(
        read_content.len(),
        lv.size_bytes(DEFAULT_EXTENT_SIZE) as usize
    );
}

#[test]
fn read_lv_content_multi_pv() {
    let dir = TempDir::new();
    let path0 = make_sparse_file(&dir, "pv0.bin", 32 * 1024 * 1024);
    let path1 = make_sparse_file(&dir, "pv1.bin", 32 * 1024 * 1024);

    let mut f0 = open_rw(&path0);
    let pv0 = lvm::format_pv(&mut f0, 32 * 1024 * 1024).unwrap();
    let mut f1 = open_rw(&path1);
    let pv1 = lvm::format_pv(&mut f1, 32 * 1024 * 1024).unwrap();

    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let mut vg =
        lvm::create_vg("testvg", &mut [(f0, pv0), (f1, pv1)], DEFAULT_EXTENT_SIZE).unwrap();

    // Fill pv0 entirely (7 extents = 28 MiB) so the next LV goes to pv1.
    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let pv0_clone = vg.pvs[0].clone();
    let pv1_clone = vg.pvs[1].clone();
    lvm::create_lv(
        &mut vg,
        &mut [(f0, pv0_clone), (f1, pv1_clone)],
        "lv0",
        28 * 1024 * 1024,
    )
    .unwrap();

    // lv1 must go to pv1 (pv0 is full).
    let f0 = open_rw(&path0);
    let f1 = open_rw(&path1);
    let pv0_clone = vg.pvs[0].clone();
    let pv1_clone = vg.pvs[1].clone();
    lvm::create_lv(
        &mut vg,
        &mut [(f0, pv0_clone), (f1, pv1_clone)],
        "lv1",
        4 * 1024 * 1024,
    )
    .unwrap();

    // Verify lv1 is on pv1.
    assert_eq!(vg.lvs[1].segments[0].pv_name, "pv1");

    // Write content to lv0 (on pv0, at pe_start).
    let content0 = b"LV0 data on PV0";
    let mut f = open_rw(&path0);
    f.seek(SeekFrom::Start(DEFAULT_PE_START)).unwrap();
    f.write_all(content0).unwrap();

    // Write content to lv1 (on pv1, at pe_start).
    let content1 = b"LV1 data on PV1";
    let mut f = open_rw(&path1);
    f.seek(SeekFrom::Start(DEFAULT_PE_START)).unwrap();
    f.write_all(content1).unwrap();

    // Read both LVs — each segment is on a different PV.
    let read0 = lvm::read_lv(&[&path0, &path1], "lv0").unwrap();
    assert_eq!(&read0[..content0.len()], content0);

    let read1 = lvm::read_lv(&[&path0, &path1], "lv1").unwrap();
    assert_eq!(&read1[..content1.len()], content1);
}

// ---------------------------------------------------------------------------
// Text metadata round-trip
// ---------------------------------------------------------------------------

#[test]
fn text_metadata_round_trip() {
    let mut vg = VolumeGroup::new("roundtrip", generate_id(), DEFAULT_EXTENT_SIZE);
    vg.pvs
        .push(PhysicalVolume::new("pv0", generate_id(), 32 * 1024 * 1024));
    vg.pvs
        .push(PhysicalVolume::new("pv1", generate_id(), 32 * 1024 * 1024));
    vg.lvs.push(LogicalVolume {
        name: "lv0".into(),
        id: generate_id(),
        segments: vec![LvSegment {
            start_extent: 0,
            extent_count: 3,
            pv_name: "pv0".into(),
            pv_start_extent: 0,
        }],
    });
    vg.pvs[0].pe_alloc_count = 3;

    let text = emit_vg_metadata(&vg);
    let parsed = lvm::parse_vg_metadata(&text).unwrap();

    assert_eq!(parsed.name, vg.name);
    assert_eq!(parsed.id, vg.id);
    assert_eq!(parsed.seqno, vg.seqno);
    assert_eq!(parsed.extent_size, vg.extent_size);
    assert_eq!(parsed.pvs.len(), 2);
    assert_eq!(parsed.pvs[0].pe_count, vg.pvs[0].pe_count);
    assert_eq!(parsed.pvs[0].pe_alloc_count, 3);
    assert_eq!(parsed.lvs.len(), 1);
    assert_eq!(parsed.lvs[0].segments[0].pv_name, "pv0");
    assert_eq!(parsed.lvs[0].segments[0].extent_count, 3);
}

// ---------------------------------------------------------------------------
// Binary layout validation
// ---------------------------------------------------------------------------

#[test]
fn label_sector_crc_valid() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 16 * 1024 * 1024);

    let mut f = open_rw(&path);
    lvm::format_pv(&mut f, 16 * 1024 * 1024).unwrap();

    // read_pv_label verifies the CRC internally and returns an error on mismatch.
    let label = read_pv_label(&path, 0).unwrap();
    assert_eq!(label.r#type, "LVM2 001");
}

#[test]
fn mda_header_correct_layout() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    lvm::create_vg("testvg", &mut [(f, pv.clone())], DEFAULT_EXTENT_SIZE).unwrap();

    let mda = read_mda(&path, 0, DEFAULT_MDA_OFFSET).unwrap();
    assert_eq!(mda.version, 1);
    assert_eq!(mda.start, DEFAULT_MDA_OFFSET);
    assert_eq!(mda.size, DEFAULT_PE_START - DEFAULT_MDA_OFFSET);
    // The metadata text starts right after the MDA header.
    assert_eq!(mda.raw_offset, MDA_HEADER_SIZE);
    assert!(mda.raw_size > 0);

    // The text should start with the VG name.
    let text = String::from_utf8_lossy(&mda.text);
    let text = text.trim_end_matches('\0');
    assert!(text.starts_with("testvg {\n"));
    assert!(text.contains("physical_volumes"));
}

// ---------------------------------------------------------------------------
// UUID validation
// ---------------------------------------------------------------------------

#[test]
fn generated_uuids_use_lvm_alphabet() {
    for _ in 0..1000 {
        let id = generate_id();
        assert_eq!(id.len(), 32);
        for c in id.chars() {
            assert!(
                c.is_ascii_digit()
                    || c.is_ascii_lowercase()
                    || c.is_ascii_uppercase()
                    || c == '!'
                    || c == '#',
                "Invalid UUID char: {c}"
            );
            // LVM does NOT use + or /.
            assert!(c != '+' && c != '/', "UUID should not contain {c}");
        }
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible compute_vg_layout (used by install pipeline)
// ---------------------------------------------------------------------------

#[test]
fn compute_vg_layout_assigns_extents() {
    let vg_manifest = ManifestLvmVg {
        partitions: vec![ManifestLvmPartition {
            size: ManifestPartitionSize {
                size_min: 4 * 1024 * 1024,
                size_max: None,
                size_weight: 1.0,
            },
            content: None,
            name: "lv0".into(),
        }],
        empty_space: None,
        size_min: 0,
    };
    let layout = compute_vg_layout(
        "vg0",
        &vg_manifest,
        &[lvm::PvRegion {
            device_size: 16 * 1024 * 1024,
        }],
    )
    .unwrap();
    assert_eq!(layout.vg.pvs[0].pe_count, 3); // (16M - 1M) / 4M = 3
    assert_eq!(layout.lv_plans.len(), 1);
    assert!(layout.lv_plans[0].size >= 4 * 1024 * 1024);
}

// ---------------------------------------------------------------------------
// Full pipeline: format → create_vg → create_lv → write content → read back
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline() {
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 64 * 1024 * 1024);

    // 1. Format PV
    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 64 * 1024 * 1024).unwrap();

    // 2. Create VG
    let f = open_rw(&path);
    let mut vg = lvm::create_vg("sysvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    // 3. Create LV
    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    let lv = lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "root", 8 * 1024 * 1024).unwrap();

    // Write content into the LV.
    let test_data = b"ROOT FILESYSTEM DATA";
    let mut f = open_rw(&path);
    f.seek(SeekFrom::Start(DEFAULT_PE_START)).unwrap();
    f.write_all(test_data).unwrap();

    // 4. Read VG
    let read_vg = lvm::read_vg(&[&path]).unwrap();
    assert_eq!(read_vg.name, "sysvg");
    assert_eq!(read_vg.pvs.len(), 1);

    // 5. List LVs
    let lvs = lvm::list_lvs(&[&path]).unwrap();
    assert_eq!(lvs, vec!["root"]);

    // 6. Read LV content
    let content = lvm::read_lv(&[&path], "root").unwrap();
    assert_eq!(&content[..test_data.len()], test_data);
    assert_eq!(content.len(), lv.size_bytes(DEFAULT_EXTENT_SIZE) as usize);
}

// ---------------------------------------------------------------------------
// pvck validation of a complete VG with LVs
// ---------------------------------------------------------------------------

#[test]
fn pvck_validates_vg_with_lv() {
    skip_if_missing!("pvck");
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);
    let pvck_path = dir.path().join("pvck_vg.bin");

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "lv0", 4 * 1024 * 1024).unwrap();

    fs::copy(&path, &pvck_path).unwrap();

    // Validate with pvck --dump headers (metadata_all requires device-mapper
    // which may not be available in all environments).
    let output = std::process::Command::new("pvck")
        .args(["--dump", "headers", "--labelsector", "0"])
        .arg(&pvck_path)
        .output()
        .expect("pvck available");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("label_header.id LABELONE"),
        "pvck output: {combined}"
    );
    assert!(
        !combined.contains("CHECK: pv_header.pv_uuid invalid format"),
        "pvck found invalid UUID: {combined}"
    );
    assert!(
        !combined.contains("is unexpected # for first mda"),
        "pvck found unexpected MDA offset: {combined}"
    );
    // Should find the MDA header with valid magic.
    assert!(
        combined.contains("mda_header_1"),
        "pvck should find MDA header: {combined}"
    );
}

#[test]
fn pvck_full_validation() {
    skip_if_missing!("pvck");
    let dir = TempDir::new();
    let path = make_sparse_file(&dir, "pv.bin", 32 * 1024 * 1024);
    let pvck_path = dir.path().join("pvck_full.bin");

    let mut f = open_rw(&path);
    let pv = lvm::format_pv(&mut f, 32 * 1024 * 1024).unwrap();
    drop(f);

    let f = open_rw(&path);
    let mut vg = lvm::create_vg("testvg", &mut [(f, pv)], DEFAULT_EXTENT_SIZE).unwrap();

    let f = open_rw(&path);
    let pv_clone = vg.pvs[0].clone();
    lvm::create_lv(&mut vg, &mut [(f, pv_clone)], "root", 8 * 1024 * 1024).unwrap();

    fs::copy(&path, &pvck_path).unwrap();

    // Run pvck --dump headers and check for any issues.
    let output = std::process::Command::new("pvck")
        .args(["--dump", "headers", "--labelsector", "0"])
        .arg(&pvck_path)
        .output()
        .expect("pvck available");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("pvck output:\n{combined}");
    assert!(combined.contains("LABELONE"), "Missing LABELONE");
    assert!(
        !combined.contains("CHECK:"),
        "pvck found CHECK errors: {combined}"
    );
    // Ignore generic non-root warnings from pvck itself.
    let filtered: String = combined
        .lines()
        .filter(|l| {
            !l.contains("non-root")
                && !l.contains("dev/mapper")
                && !l.contains("Incompatible")
                && !l.contains("Functionality")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !filtered.contains("WARNING:"),
        "pvck found warnings: {filtered}"
    );
    assert!(
        !filtered.contains("bad"),
        "pvck found bad values: {filtered}"
    );
}
