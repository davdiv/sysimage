//! Install pipeline: write a built system onto disk images / block devices.
//! Pure-Rust backends: hadris-part (GPT), rust-fs-ext4 (ext4), hadris-fat (FAT).
//!
//! The pipeline is generic over [`BlockRegion`]: each block (a whole disk, a
//! GPT partition, an LVM logical volume, …) is installed into a contiguous
//! byte region. Descending the block tree produces sub-regions via
//! [`BlockRegion::open_region`], which share the backing store and copy no
//! bytes — so filesystems are formatted *directly* into their partition region
//! instead of being staged in a standalone temp image first. Today the concrete
//! top-level regions are [`BlockFile`] (a local file / block device / sub-region)
//! and [`crate::nbd::NbdRegion`] (a remote NBD export), unified behind
//! [`DiskRegion`]; the trait is shaped so further backing stores plug in unchanged.
//!
//! # Wipe vs. reconcile
//!
//! With `--wipe` every target is installed from scratch (the "fresh" path):
//! partition tables, filesystems, LVM metadata and LUKS headers are all
//! (re)created. The fresh path is also taken — without `--wipe` — for any
//! region that was *just created by us* (a new disk image file that did not
//! exist before, or a previously empty zero-byte file): there is no existing
//! data to reconcile against, so installing from scratch is both safe and the
//! only sensible option. Without `--wipe` the installer otherwise *reconciles*
//! the manifest with the existing on-disk structures: it reuses a GPT partition
//! / LVM logical volume / LUKS2 container / ext4-or-FAT filesystem that already
//! exists (matched by name), only *creates* the ones that are missing (when
//! there is enough free space), and otherwise leaves existing data untouched.
//! `image` blocks are always replaced; `ext4`/`fat` blocks extract their
//! archive into the reused filesystem, overwriting same-named files and keeping
//! the rest.
//!
//! Because rewriting a device the kernel is using is destructive, `--wipe` is
//! refused for an in-use device; pass `--force` (with `--wipe`) to force-wipe it
//! from scratch anyway.
//!
//! Reconciliation is a two-phase, all-or-nothing operation: a **plan** phase
//! reads every existing structure on every target and validates that the
//! manifest can be applied (partition sizes, free space, mountable filesystems,
//! unlockable LUKS containers, …). Only if the whole plan succeeds does the
//! **apply** phase write anything. A failure during planning leaves the disks
//! unchanged.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::blockfile::{BlockFile, BlockRegion, LuksRegion};
use crate::error::{Error, Result};
use crate::exec;
use crate::manifest::ManifestWithDirectory;
use crate::model::manifest::{
    ManifestArchive, ManifestBlock, ManifestBlockFs, ManifestBlockGpt, ManifestBlockImage,
    ManifestBlockLuks, ManifestBlockLvm, ManifestBlockMbr, ManifestHybridMbr, ManifestLvmVg,
    ManifestPartitionSize,
};
use crate::nbd::NbdRegion;
use crate::size::{align_size, compute_partition_sizes};
use hadris_fat::sync::{FatVolume, FatVolumeWriteExt};
use hadris_part::gpt::{GptPartitionEntry, Guid};
use hadris_part::hybrid::HybridMbrBuilder;
use hadris_part::mbr::{MasterBootRecord, MbrPartition, MbrPartitionType};
use hadris_part::mbr_io::{MasterBootRecordReadExt, MasterBootRecordWriteExt};
use hadris_part::scheme::GptDisk;
use hadris_part::scheme_io::{GptDiskReadExt, GptDiskWriteExt};
use indicatif::{ProgressBar, ProgressStyle};

/// GPT sector size (bytes).
pub(crate) const GPT_SECTOR_SIZE: u64 = 512;
/// MBR sector size (bytes).
pub(crate) const MBR_SECTOR_SIZE: u64 = 512;
/// First usable LBA for MBR partitions (1 MiB alignment, fdisk convention).
pub(crate) const MBR_FIRST_USABLE_LBA: u64 = 2048;
/// Block size used for alignment and ext4.
pub(crate) const BLOCK_SIZE: u64 = 4096;

/// Install options.
pub struct InstallConfig {
    pub manifest: ManifestWithDirectory,
    pub disk: BTreeMap<String, String>,
    pub wipe: bool,
    /// Allow `--wipe` to force-wipe in-use devices (mounted/active) from scratch
    /// instead of refusing. Only meaningful together with `wipe`.
    pub force: bool,
    /// Passphrases keyed by LUKS container name (`--key name=passphrase`).
    pub key: BTreeMap<String, String>,
    /// Key-file paths keyed by LUKS container name (`--key-file name=path`).
    pub key_file: BTreeMap<String, PathBuf>,
}

/// Resolves a manifest hash file name to its source path.
type FileResolver = Box<dyn Fn(&str) -> Result<PathBuf>>;

/// Resolves an in-memory file-tree key to its tree.
type TreeResolver = Box<dyn Fn(&str) -> Result<crate::archive::TreeNode>>;

pub struct InstallContext {
    pub(crate) manifest: crate::model::manifest::ManifestBuild,
    pub(crate) manifest_directory: PathBuf,
    pub(crate) wipe: bool,
    /// Resolved passphrases (raw bytes) keyed by LUKS container name.
    pub(crate) keys: BTreeMap<String, Vec<u8>>,
    /// Optional override for [`resolve_manifest_file`]: resolves a hash file
    /// name directly to its source path, bypassing the manifest-directory
    /// lookup (and its hash re-verification). Used by the build-time block
    /// renderer, where content-addressed files are still temp files that have
    /// not yet been copied to the output directory.
    pub(crate) file_resolver: Option<FileResolver>,
    /// Optional resolver for in-memory file trees keyed by the `tree_key`
    /// field of [`ManifestBlockFs`]. When set, `install_fs` writes the tree
    /// directly into the filesystem instead of extracting an archive —
    /// skipping the compress/decompress round-trip for build-time blocks.
    pub(crate) tree_resolver: Option<TreeResolver>,
}

impl InstallContext {
    /// Build a fresh install context for the generic [`install_regions`] entry
    /// point (used by remote backends such as a future NBD region store).
    pub fn new(
        manifest: crate::model::manifest::ManifestBuild,
        manifest_directory: PathBuf,
        wipe: bool,
        keys: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            manifest,
            manifest_directory,
            wipe,
            keys,
            file_resolver: None,
            tree_resolver: None,
        }
    }
}

/// Per-volume-group install plan accumulated during the plan phase and applied
/// (written + populated) during finalization.
#[allow(dead_code)]
struct VgPlan<R: BlockRegion> {
    /// PV regions contributing to this VG (in encounter order). Metadata is
    /// duplicated to all of them; the first holds the LV content.
    pvs: Vec<R>,
    /// Existing VG read from the first PV (`None` for a freshly created VG).
    existing: Option<crate::lvm::VolumeGroup>,
    /// The VolumeGroup to commit (fresh layout or reconciled merge of the
    /// existing VG with new LVs).
    vg: crate::lvm::VolumeGroup,
    /// Per-LV install plans, in manifest order.
    lv_plans: Vec<LvPlan>,
}

#[allow(dead_code)]
struct LvPlan {
    /// LV name (matches a manifest LVM partition name).
    name: String,
    /// Offset of the LV's first extent, relative to the first PV's region.
    offset: u64,
    /// LV size in bytes (a whole number of extents).
    size: u64,
    /// Content install plan for the LV (always a [`Plan`]).
    content: Option<Box<Plan>>,
}

type VgPlans<R> = BTreeMap<String, VgPlan<R>>;

// ---------------------------------------------------------------------------
// The install plan (region-agnostic): the check phase builds it, the apply
// phase consumes it.
// ---------------------------------------------------------------------------

/// A planned install operation for one block. Built by [`plan_block`] (which
/// reads existing on-disk state and validates compatibility) and executed by
/// [`apply_block`]. Carrying the decisions in a tree lets the check phase run
/// to completion — and fail without writing — before any bytes are changed.
enum Plan {
    /// Install this block from scratch (wipe, or a freshly created container).
    /// Delegates to the existing fresh installer ([`install_block_fresh`]).
    Fresh(ManifestBlock),
    /// GPT: reuse the existing table, possibly adding new partitions.
    Gpt(GptPlan),
    /// MBR: reuse the existing table, possibly adding new partitions.
    Mbr(Box<MbrPlan>),
    /// Raw image: always copied over the region (replace).
    Image(ImagePlan),
    /// ext4 or FAT: reuse the existing filesystem and merge-extract the archive.
    Fs(FsPlan),
    /// A PV contribution to a volume group. The actual LV install happens in
    /// [`finalize_vgs`]; this node is a no-op during [`apply_block`].
    Lvm,
    /// LUKS2: reuse the existing container. The nested content is planned and
    /// applied directly against a [`LuksRegion`] that transparently decrypts on
    /// read and encrypts on write — no temp file, no full decrypt/re-encrypt.
    Luks(LuksPlan),
}

struct GptPlan {
    /// The GPT table to write, or `None` to leave the existing table untouched
    /// (every manifest partition was reused, nothing was created).
    table: Option<GptDisk>,
    /// One entry per manifest partition (reused or newly created).
    parts: Vec<GptPartPlan>,
    /// Hybrid MBR configuration. When present, the GPT is written alongside a
    /// hybrid MBR mirroring the selected partitions (a hybrid GPT disk).
    mbr: Option<ManifestHybridMbr>,
    /// Optional bootcode: hash file name in the manifest `files` map.
    bootcode: Option<String>,
}

struct GptPartPlan {
    /// Offset relative to the disk region start (bytes).
    offset: u64,
    size: u64,
    /// Content install plan. `Plan::Fresh` for a newly created partition,
    /// otherwise a reconcile plan against the existing partition content.
    content: Option<Box<Plan>>,
}

struct MbrPlan {
    /// The MBR to write, or `None` to leave the existing table untouched
    /// (every manifest partition was reused, nothing was created).
    table: Option<MasterBootRecord>,
    /// One entry per manifest partition (reused or newly created).
    parts: Vec<MbrPartPlan>,
    /// Optional bootcode: hash file name in the manifest `files` map.
    bootcode: Option<String>,
}

struct MbrPartPlan {
    /// Offset relative to the disk region start (bytes).
    offset: u64,
    size: u64,
    /// Content install plan. `Plan::Fresh` for a newly created partition,
    /// otherwise a reconcile plan against the existing partition content.
    content: Option<Box<Plan>>,
}

struct ImagePlan {
    source: PathBuf,
    size: u64,
    /// True when the region already contains the expected bytes (its
    /// [`BlockRegion::region_digest`] matched the manifest digest): the apply
    /// phase skips the copy entirely.
    skip: bool,
}

struct FsPlan {
    fat: bool,
    /// Resolved archive (path + format + total uncompressed content size in
    /// bytes, from the manifest) to extract into the reused filesystem.
    archive: Option<(PathBuf, crate::model::config::ArchiveFormat, u64)>,
}

/// LUKS2 reuse plan. The nested content is planned and applied against a
/// concrete [`LuksRegion`] (which type-erases its encrypted backing behind
/// `dyn BlockDevice`), so nesting LUKS inside LUKS does not grow the `Plan`
/// type — every level erases back to the same `LuksRegion`.
struct LuksPlan {
    payload_size: u64,
    payload_offset: u64,
    sector_size: u32,
    cipher_mode: String,
    iv_tweak: u128,
    master_key: Vec<u8>,
    /// Nested content plan, applied directly into a [`LuksRegion`] wrapping the
    /// encrypted backing region (transparent encrypt-on-write).
    content: Option<Box<Plan>>,
    /// Volume groups discovered inside the decrypted payload, finalized with
    /// the [`LuksRegion`] as their backing store.
    vgs: VgPlans<LuksRegion>,
}

// ---------------------------------------------------------------------------
// LUKS passphrase resolution
// ---------------------------------------------------------------------------

/// Recursively collect the names of every LUKS block reachable from the
/// manifest's disk and LVM trees (including blocks nested inside GPT
/// partitions, LVM logical volumes or other LUKS containers).
fn collect_luks_names(manifest: &crate::model::manifest::ManifestBuild) -> Vec<String> {
    let mut names = Vec::new();
    for block in manifest.disk.values() {
        collect_luks_names_block(block, &mut names);
    }
    for vg in manifest.lvm.values() {
        for part in &vg.partitions {
            if let Some(content) = &part.content {
                collect_luks_names_block(content, &mut names);
            }
        }
    }
    names
}

fn collect_luks_names_block(block: &ManifestBlock, names: &mut Vec<String>) {
    match block {
        ManifestBlock::Luks(b) => {
            names.push(b.name.clone());
            if let Some(content) = &b.content {
                collect_luks_names_block(content, names);
            }
        }
        ManifestBlock::Gpt(b) => {
            for part in &b.partitions {
                if let Some(content) = &part.content {
                    collect_luks_names_block(content, names);
                }
            }
        }
        ManifestBlock::Mbr(b) => {
            for part in &b.partitions {
                if let Some(content) = &part.content {
                    collect_luks_names_block(content, names);
                }
            }
        }
        ManifestBlock::Lvm(_)
        | ManifestBlock::Image(_)
        | ManifestBlock::Ext4(_)
        | ManifestBlock::Fat(_) => {}
    }
}

/// Build the `name → passphrase bytes` map for every LUKS container in the
/// manifest. For each name, the passphrase is taken from `key` (inline) or
/// `key_file` (read from disk and used **exactly as-is** — no trailing-newline
/// stripping). Any name not covered by either map is prompted for
/// interactively.
pub(crate) fn resolve_luks_keys(
    manifest: &crate::model::manifest::ManifestBuild,
    key: &BTreeMap<String, String>,
    key_file: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let names = collect_luks_names(manifest);
    let mut resolved: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for name in &names {
        if resolved.contains_key(name) {
            // The same name may appear more than once; reuse the first result.
            continue;
        }
        let bytes = if let Some(pass) = key.get(name) {
            pass.as_bytes().to_vec()
        } else if let Some(path) = key_file.get(name) {
            std::fs::read(path).map_err(|e| {
                Error::msg(format!("Failed to read key file for \"{}\": {}", name, e))
            })?
        } else {
            prompt_passphrase(name)?
        };
        resolved.insert(name.clone(), bytes);
    }
    Ok(resolved)
}

/// Prompt the user for a passphrase on the controlling terminal, with echo
/// disabled. Falls back to a plain stdin read when the terminal cannot be
/// configured (e.g. piped input).
fn prompt_passphrase(name: &str) -> Result<Vec<u8>> {
    use std::io::Write;
    let prompt = format!("Enter passphrase for LUKS container \"{name}\": ");
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    // Disable terminal echo via `stty` (best-effort; ignored if stdin is not a
    // terminal).
    let _ = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status();

    let mut line = String::new();
    let read_res = std::io::stdin().read_line(&mut line);

    // Always re-enable echo before returning, even on error.
    let _ = std::process::Command::new("stty")
        .arg("echo")
        .stdin(std::process::Stdio::inherit())
        .status();
    eprintln!();

    read_res.map_err(|e| Error::msg(format!("Failed to read passphrase: {e}")))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line.into_bytes())
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Install a built system onto the disks described by the manifest.
///
/// This is the local-file/block-device entry point: each `--disk name=path` is
/// resolved to a [`BlockFile`] region (or an [`NbdRegion`] for an `nbd:` URL).
/// The actual install logic is generic over [`BlockRegion`] (see
/// [`install_regions`]); a remote backing store (e.g. NBD) can reuse it by
/// constructing its own regions and calling [`install_regions`] directly.
///
/// Local block devices are probed for in-use state (mounted, held by `dm-crypt`,
/// registered as an LVM PV): free devices go through the raw pipeline, in-use
/// devices are driven through the local kernel instead of around it. Image
/// files and NBD URLs are never kernel-managed and always take the raw path.
/// `--wipe` is refused for an in-use device unless `--force` is set, in which
/// case the device is force-wiped from scratch. The shared probing + kernel path
/// lives in [`crate::install_kernel`].
pub fn install(config: InstallConfig) -> Result<()> {
    crate::install_kernel::install_with_kernel(
        &crate::install_kernel::LocalHost,
        config.manifest,
        config.disk,
        config.key,
        config.key_file,
        config.wipe,
        config.force,
    )
}

// ---------------------------------------------------------------------------
// Disk backing-store selection (local file/device vs. remote NBD)
// ---------------------------------------------------------------------------

/// A top-level disk backing store: either a local file / block device
/// ([`BlockFile`]) or a remote NBD export ([`NbdRegion`]).
///
/// Each `--disk name=<target>` selects its backend *independently* from the
/// target string — an `nbd:` URL opens a remote NBD region, any other value
/// opens a local [`BlockFile`] — so a single install may freely mix remote
/// and local disks. The generic install pipeline ([`install_regions`]) only
/// ever sees [`DiskRegion`] values, so all of the plan/apply/LUKS/LVM logic
/// is backend-agnostic and works unchanged over either transport.
#[derive(Clone)]
pub enum DiskRegion {
    /// A local image file, block device, or sub-region thereof.
    File(BlockFile),
    /// A remote NBD export (TCP or Unix-domain).
    Nbd(NbdRegion),
}

impl fs_ext4::block_io::BlockDevice for DiskRegion {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        match self {
            DiskRegion::File(f) => f.read_at(offset, buf),
            DiskRegion::Nbd(n) => n.read_at(offset, buf),
        }
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> fs_ext4::error::Result<()> {
        match self {
            DiskRegion::File(f) => f.write_at(offset, buf),
            DiskRegion::Nbd(n) => n.write_at(offset, buf),
        }
    }
    fn size_bytes(&self) -> u64 {
        match self {
            DiskRegion::File(f) => f.size_bytes(),
            DiskRegion::Nbd(n) => n.size_bytes(),
        }
    }
    fn flush(&self) -> fs_ext4::error::Result<()> {
        match self {
            DiskRegion::File(f) => f.flush(),
            DiskRegion::Nbd(n) => n.flush(),
        }
    }
    fn is_writable(&self) -> bool {
        match self {
            DiskRegion::File(f) => f.is_writable(),
            DiskRegion::Nbd(n) => n.is_writable(),
        }
    }
}

impl Read for DiskRegion {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DiskRegion::File(f) => f.read(buf),
            DiskRegion::Nbd(n) => n.read(buf),
        }
    }
}

impl Write for DiskRegion {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            DiskRegion::File(f) => f.write(buf),
            DiskRegion::Nbd(n) => n.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            DiskRegion::File(f) => f.flush(),
            DiskRegion::Nbd(n) => n.flush(),
        }
    }
}

impl Seek for DiskRegion {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            DiskRegion::File(f) => f.seek(pos),
            DiskRegion::Nbd(n) => n.seek(pos),
        }
    }
}

impl BlockRegion for DiskRegion {
    fn open_region(&self, offset: u64, size: u64) -> Self {
        match self {
            DiskRegion::File(f) => DiskRegion::File(f.open_region(offset, size)),
            DiskRegion::Nbd(n) => DiskRegion::Nbd(n.open_region(offset, size)),
        }
    }
    fn region_size(&self) -> u64 {
        match self {
            DiskRegion::File(f) => f.region_size(),
            DiskRegion::Nbd(n) => n.region_size(),
        }
    }
    fn region_base(&self) -> u64 {
        match self {
            DiskRegion::File(f) => f.region_base(),
            DiskRegion::Nbd(n) => n.region_base(),
        }
    }
    fn sync_region(&self) -> std::io::Result<()> {
        match self {
            DiskRegion::File(f) => f.sync_region(),
            DiskRegion::Nbd(n) => n.sync_region(),
        }
    }
    fn write_chunks(&mut self, chunks: &[&[u8]]) -> std::io::Result<()> {
        // Dispatch to the concrete backend so an NBD target gets the pipelined
        // batch implementation; the default (per-chunk `write_all`) would call
        // back into the stop-and-wait `Write` path and lose the overlap.
        match self {
            DiskRegion::File(f) => f.write_chunks(chunks),
            DiskRegion::Nbd(n) => n.write_chunks(chunks),
        }
    }
    fn write_chunks_progress(
        &mut self,
        chunks: &[&[u8]],
        on_written: &mut dyn FnMut(u64),
    ) -> std::io::Result<()> {
        match self {
            DiskRegion::File(f) => f.write_chunks_progress(chunks, on_written),
            DiskRegion::Nbd(n) => n.write_chunks_progress(chunks, on_written),
        }
    }
    fn region_digest(&self, size: u64) -> std::io::Result<Option<[u8; 32]>> {
        match self {
            DiskRegion::File(f) => f.region_digest(size),
            DiskRegion::Nbd(n) => n.region_digest(size),
        }
    }
}

/// True if `target` is an NBD URL (`nbd:`, `nbd+tcp:` or `nbd+unix:`).
pub(crate) fn is_nbd_url(target: &str) -> bool {
    target.starts_with("nbd:") || target.starts_with("nbd+tcp:") || target.starts_with("nbd+unix:")
}

/// Open a `--disk` target as a sized region, choosing the backend per disk.
///
/// An `nbd:` URL opens a remote NBD export whose size is reported by the
/// server; anything else is treated as a local file or block device, created
/// / size-resolved via [`resolve_disk_size`]. The two backends are thus
/// selectable independently for each disk in a single install (mixing remote
/// and local targets is allowed).
///
/// Returns the region plus a `created_by_us` flag — `true` only for a freshly
/// created local image (a new file or a previously empty one) — so a brand-new
/// local disk can be installed from scratch without `--wipe`. A remote NBD
/// export is never "created by us" (it already exists on the server).
pub(crate) fn open_disk(target: &str, min_size: u64) -> Result<(DiskRegion, bool)> {
    if is_nbd_url(target) {
        let region = NbdRegion::open(target)?;
        Ok((DiskRegion::Nbd(region), false))
    } else {
        let target = PathBuf::from(target);
        let (disk_size, created_by_us) = resolve_disk_size(&target, min_size)?;
        let disk = BlockFile::open(&target, 0, disk_size)?;
        Ok((DiskRegion::File(disk), created_by_us))
    }
}

/// Install onto pre-built regions, generic over the backing store.
///
/// [`install`] reaches this with `R = BlockFile`; a remote backend (NBD, …)
/// would build its own `R: BlockRegion` regions and call this directly.
///
/// `fresh_disks` maps disk names to a boolean indicating that the region was
/// freshly created by the caller (a new image file, a just-allocated NBD
/// export, …). A fresh region is installed from scratch even without `--wipe`,
/// because there is no existing data to reconcile against or destroy. Disks
/// not present in the map default to non-fresh (reconcile, or require
/// `--wipe`).
pub fn install_regions<R: BlockRegion>(
    ctx: &mut InstallContext,
    regions: BTreeMap<String, R>,
    fresh_disks: BTreeMap<String, bool>,
) -> Result<()> {
    let disks = ctx.manifest.disk.clone();

    // --- Check phase: build the per-disk plan. Reads existing structures and
    //     validates; aborts (without writing) on any incompatibility. ---
    eprintln!("Planning installation (wipe={})...", ctx.wipe);
    let mut vgs: VgPlans<R> = BTreeMap::new();
    let mut plans: BTreeMap<String, Plan> = BTreeMap::new();
    for (disk_name, disk_block) in &disks {
        eprintln!("  Disk \"{disk_name}\": planning...");
        let region = regions
            .get(disk_name)
            .ok_or_else(|| Error::msg(format!("No target region for disk \"{disk_name}\"")))?;
        let min_size = compute_min_disk_size(disk_block);
        if region.region_size() < min_size {
            return Err(Error::msg(format!(
                "Disk \"{disk_name}\" region ({} bytes) is smaller than the required minimum ({} bytes)",
                region.region_size(),
                min_size
            )));
        }
        // A disk is treated as fresh when `--wipe` is set OR the backing region
        // was freshly created by the caller (new file, empty image, …).
        let fresh = ctx.wipe || fresh_disks.get(disk_name).copied().unwrap_or(false);
        let plan = plan_block(ctx, &mut vgs, disk_block, region, fresh)?;
        plans.insert(disk_name.clone(), plan);
    }
    eprintln!("Planning complete.");

    // --- Apply phase: execute the plans. No reads of existing structures
    //     happen here (everything was decided during planning). ---
    eprintln!("Applying installation...");
    for disk_name in disks.keys() {
        eprintln!("  Disk \"{disk_name}\": applying...");
        let plan = match plans.remove(disk_name) {
            Some(p) => p,
            None => continue,
        };
        let mut region = regions
            .get(disk_name)
            .ok_or_else(|| Error::msg(format!("No target region for disk \"{disk_name}\"")))?
            .clone();
        apply_block(ctx, &mut vgs, plan, &mut region)?;
        eprintln!("  Disk \"{disk_name}\": syncing...");
        region.sync_region()?;
        eprintln!("  Disk \"{disk_name}\": done.");
    }

    finalize_vgs(ctx, &mut vgs)?;
    eprintln!("Installation complete.");
    Ok(())
}

/// Install a single block (and everything nested under it) into `region` using
/// the raw pipeline: plan + apply + finalize deferred volume groups + sync.
///
/// This is the unit of reuse for remote backends (e.g. [`crate::ssh`]): once
/// such a backend has opened a tunnelled [`BlockRegion`] for a particular
/// subtree (a partition, an LV, a closed LUKS container, …), it delegates the
/// rest of the work here so the plan/apply/LUKS/LVM logic is not duplicated.
/// `fresh` selects the from-scratch vs. reconcile path exactly as
/// [`install_regions`] would for a top-level disk.
pub(crate) fn install_block_subtree<R: BlockRegion>(
    ctx: &mut InstallContext,
    block: &ManifestBlock,
    region: &mut R,
    fresh: bool,
) -> Result<()> {
    let mut vgs: VgPlans<R> = BTreeMap::new();
    let plan = plan_block(ctx, &mut vgs, block, region, fresh)?;
    apply_block(ctx, &mut vgs, plan, region)?;
    finalize_vgs(ctx, &mut vgs)?;
    region.sync_region()?;
    Ok(())
}

// ===========================================================================
// Plan phase (check)
// ===========================================================================

/// Plan the install of `block` into `region`. When `fresh` is true the region
/// is known to be empty/newly created (`--wipe`, a disk image file just created
/// by `resolve_disk_size`, or a partition/LV just created by a parent) and the
/// block is installed from scratch without reading the region.
fn plan_block<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlock,
    region: &R,
    fresh: bool,
) -> Result<Plan> {
    match block {
        ManifestBlock::Image(b) => {
            eprintln!("    Image block (file: {}): planning...", b.file);
            plan_image(ctx, b, region, fresh)
        }
        ManifestBlock::Gpt(b) => plan_gpt(ctx, vgs, b, region, fresh),
        ManifestBlock::Mbr(b) => plan_mbr(ctx, vgs, b, region, fresh),
        ManifestBlock::Ext4(b) if !fresh => {
            eprintln!("    ext4 block: checking existing filesystem...");
            plan_fs_reuse(ctx, b, region, false)
        }
        ManifestBlock::Fat(b) if !fresh => {
            eprintln!("    FAT block: checking existing filesystem...");
            plan_fs_reuse(ctx, b, region, true)
        }
        ManifestBlock::Lvm(b) => plan_lvm(ctx, vgs, b, region, fresh),
        ManifestBlock::Luks(b) if !fresh => {
            eprintln!(
                "    LUKS2 block \"{}\": checking existing container...",
                b.name
            );
            plan_luks(ctx, b, region)
        }
        // Fresh shortcut: install from scratch via the existing fresh installer.
        other => {
            eprintln!(
                "    Fresh block ({}): will create from scratch",
                block_type_name(other)
            );
            Ok(Plan::Fresh(other.clone()))
        }
    }
}

/// Return a human-readable name for a manifest block type (for logging).
fn block_type_name(b: &ManifestBlock) -> &'static str {
    match b {
        ManifestBlock::Gpt(_) => "gpt",
        ManifestBlock::Mbr(_) => "mbr",
        ManifestBlock::Image(_) => "image",
        ManifestBlock::Ext4(_) => "ext4",
        ManifestBlock::Fat(_) => "fat",
        ManifestBlock::Lvm(_) => "lvm",
        ManifestBlock::Luks(_) => "luks",
    }
}

fn plan_image<R: BlockRegion>(
    ctx: &InstallContext,
    block: &ManifestBlockImage,
    region: &R,
    fresh: bool,
) -> Result<Plan> {
    let source = resolve_manifest_file(ctx, &block.file)?;
    let file_info =
        ctx.manifest.file.get(&block.file).ok_or_else(|| {
            Error::msg(format!("Manifest has no file entry for \"{}\"", block.file))
        })?;
    if file_info.size > region.region_size() {
        return Err(Error::msg(format!(
            "Image \"{}\" ({} bytes) is larger than its region ({} bytes)",
            block.file,
            file_info.size,
            region.region_size()
        )));
    }
    // Fast path: when the region is not freshly created (i.e. it may already
    // hold data), ask the region for a cheap SHA-256 of its first `size`
    // bytes. A local file hashes in place; an ssh-install NBD export hashes
    // on the remote host over a side channel. A plain `nbd://` URL returns
    // None (hashing would transfer the whole image over the network). When
    // the digest matches the manifest's content hash, skip the copy.
    let mut skip = false;
    if !fresh {
        match region.region_digest(file_info.size) {
            Ok(Some(digest)) if file_info.hash.eq_ignore_ascii_case(&hex::encode(digest)) => {
                eprintln!(
                    "    Image: region already contains the expected content \
                     (digest matches) — will skip the copy."
                );
                skip = true;
            }
            Ok(Some(digest)) => {
                eprintln!(
                    "    Image: region digest {} != expected {} — will overwrite.",
                    hex::encode(digest),
                    file_info.hash,
                );
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("    Image: could not compute region digest ({e}) — will overwrite.");
            }
        }
    }
    Ok(Plan::Image(ImagePlan {
        source,
        size: file_info.size,
        skip,
    }))
}

fn plan_gpt<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockGpt,
    region: &R,
    fresh: bool,
) -> Result<Plan> {
    if fresh {
        // Fresh GPT (--wipe): build the layout and mark every partition as freshly created.
        eprintln!(
            "    GPT: creating fresh partition table (--wipe, {} partitions)",
            block.partitions.len()
        );
        let (gpt, placed) = compute_gpt_layout(block, region.region_size())?;
        for (i, p) in block.partitions.iter().enumerate() {
            let (offset, size) = placed[i];
            eprintln!(
                "      Partition \"{}\": new (offset={}, size={})",
                p.name, offset, size
            );
        }
        let parts = block
            .partitions
            .iter()
            .zip(placed.iter())
            .map(|(p, (offset, size))| GptPartPlan {
                offset: *offset,
                size: *size,
                content: p.content.clone().map(|c| Box::new(Plan::Fresh(*c))),
            })
            .collect();
        return Ok(Plan::Gpt(GptPlan {
            table: Some(gpt),
            parts,
            mbr: block.mbr.clone(),
            bootcode: block.bootcode.clone(),
        }));
    }
    if !has_gpt(region)? {
        return Err(Error::msg(
            "Target does not contain an existing GPT partition table. \
             Use --wipe to create one from scratch (this will destroy all existing data).",
        ));
    }

    // Reuse: read the existing GPT and match partitions by name.
    eprintln!(
        "    GPT: reusing existing partition table ({} manifest partitions)",
        block.partitions.len()
    );
    let mut reader = region.clone();
    let existing = GptDisk::read_from(&mut reader, GPT_SECTOR_SIZE as u32).map_err(map_part_err)?;
    let preserved: Vec<GptPartitionEntry> = existing
        .entries
        .iter()
        .filter(|e| !e.is_unused())
        .cloned()
        .collect();

    let first_usable = existing.primary_header.first_usable_lba.to_ne();
    let last_usable = existing.primary_header.last_usable_lba.to_ne();

    let mut parts: Vec<GptPartPlan> = Vec::with_capacity(block.partitions.len());
    let mut new_indices: Vec<usize> = Vec::new();
    let mut new_specs: Vec<ManifestPartitionSize> = Vec::new();

    for (i, p) in block.partitions.iter().enumerate() {
        let found = preserved
            .iter()
            .find(|e| gpt_name_string(e) == p.name)
            .cloned();
        if let Some(entry) = found {
            let offset = entry.first_lba.to_ne() * GPT_SECTOR_SIZE;
            let size = entry.size_sectors() * GPT_SECTOR_SIZE;
            if size < p.size.size_min {
                return Err(Error::msg(format!(
                    "Existing GPT partition \"{}\" is {} bytes, smaller than the manifest minimum ({} bytes). Use --wipe to recreate it.",
                    p.name, size, p.size.size_min
                )));
            }
            eprintln!(
                "      Partition \"{}\": reused (offset={}, size={})",
                p.name, offset, size
            );
            let content = if let Some(content) = &p.content {
                let sub = region.open_region(offset, size);
                Some(Box::new(plan_block(ctx, vgs, content, &sub, false)?))
            } else {
                None
            };
            parts.push(GptPartPlan {
                offset,
                size,
                content,
            });
        } else {
            eprintln!(
                "      Partition \"{}\": not found in existing table, will create new",
                p.name
            );
            new_indices.push(i);
            new_specs.push(p.size.clone());
        }
    }

    let table = if new_indices.is_empty() {
        // Every manifest partition is reused: leave the existing table untouched.
        None
    } else {
        // Place the new partitions in the free space after the last existing one.
        let max_end = preserved
            .iter()
            .map(|e| e.last_lba.to_ne())
            .max()
            .unwrap_or(first_usable.saturating_sub(1));
        let align_sectors = BLOCK_SIZE / GPT_SECTOR_SIZE;
        let first_free = {
            let start = (max_end + 1).max(first_usable);
            start.div_ceil(align_sectors) * align_sectors
        }
        .max(first_usable);
        if first_free > last_usable {
            return Err(Error::msg(format!(
                "No free space on disk for new GPT partitions (last usable LBA {last_usable} reached)"
            )));
        }
        let available_sectors = last_usable + 1 - first_free;
        let available = available_sectors * GPT_SECTOR_SIZE;

        let mut size_specs = new_specs.clone();
        if let Some(empty) = &block.empty_space {
            size_specs.push(empty.clone());
        }
        let computed = compute_partition_sizes(&size_specs, available, BLOCK_SIZE)?;
        let new_sizes = &computed[..new_specs.len()];

        let disk_sectors = region.region_size() / GPT_SECTOR_SIZE;
        let mut gpt = GptDisk::new(disk_sectors, GPT_SECTOR_SIZE as u32);
        // Preserve the existing disk GUID.
        gpt.primary_header.disk_guid = existing.primary_header.disk_guid;
        gpt.backup_header.disk_guid = existing.primary_header.disk_guid;
        // Re-add every existing entry unchanged (preserves extra partitions that
        // are not in the manifest, and the reused manifest partitions).
        for entry in &preserved {
            gpt.add_partition(*entry).map_err(map_part_err)?;
        }
        // Append the new partitions.
        let mut current = first_free;
        for (k, &i) in new_indices.iter().enumerate() {
            let psize = new_sizes[k];
            let sectors = psize / GPT_SECTOR_SIZE;
            let first_lba = current;
            let last_lba = first_lba + sectors - 1;
            let p = &block.partitions[i];
            let type_guid = p.type_guid.to_hadris();
            let unique_guid = match &p.guid {
                Some(g) => g.to_hadris(),
                None => Guid::generate_v4(),
            };
            let mut entry = GptPartitionEntry::new(type_guid, unique_guid, first_lba, last_lba);
            entry.set_name_ascii(p.name.as_bytes());
            gpt.add_partition(entry).map_err(map_part_err)?;
            parts.push(GptPartPlan {
                offset: first_lba * GPT_SECTOR_SIZE,
                size: psize,
                content: p.content.clone().map(|c| Box::new(Plan::Fresh(*c))),
            });
            current = last_lba + 1;
        }
        gpt.update_crcs();
        Some(gpt)
    };

    Ok(Plan::Gpt(GptPlan {
        table,
        parts,
        mbr: block.mbr.clone(),
        bootcode: block.bootcode.clone(),
    }))
}

fn plan_mbr<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockMbr,
    region: &R,
    fresh: bool,
) -> Result<Plan> {
    if fresh {
        eprintln!(
            "    MBR: creating fresh partition table (--wipe, {} partitions)",
            block.partitions.len()
        );
        let (mbr, placed) = compute_mbr_layout(block, region.region_size())?;
        for (i, _p) in block.partitions.iter().enumerate() {
            let (offset, size) = placed[i];
            eprintln!(
                "      Partition slot {}: new (offset={}, size={})",
                i, offset, size
            );
        }
        let parts = block
            .partitions
            .iter()
            .zip(placed.iter())
            .map(|(p, (offset, size))| MbrPartPlan {
                offset: *offset,
                size: *size,
                content: p.content.clone().map(|c| Box::new(Plan::Fresh(*c))),
            })
            .collect();
        return Ok(Plan::Mbr(Box::new(MbrPlan {
            table: Some(mbr),
            parts,
            bootcode: block.bootcode.clone(),
        })));
    }
    if !has_mbr(region)? {
        return Err(Error::msg(
            "Target does not contain an existing MBR partition table. \
             Use --wipe to create one from scratch (this will destroy all existing data).",
        ));
    }

    eprintln!(
        "    MBR: reusing existing partition table ({} manifest partitions)",
        block.partitions.len()
    );
    let mut reader = region.clone();
    let _ = reader.seek(SeekFrom::Start(0));
    let existing = MasterBootRecord::read_from(&mut reader).map_err(map_part_err)?;
    let existing_parts = existing.get_partition_table();

    // MBR has no names/GUIDs: match partitions by slot index (0-3).
    let mut parts: Vec<MbrPartPlan> = Vec::with_capacity(block.partitions.len());
    let mut need_rebuild = false;

    for (i, p) in block.partitions.iter().enumerate() {
        if let Some(ep) = existing_parts
            .partitions
            .get(i)
            .filter(|ep| ep.part_type != 0)
        {
            let offset = ep.start_lba.to_ne() as u64 * MBR_SECTOR_SIZE;
            let size = ep.sector_count.to_ne() as u64 * MBR_SECTOR_SIZE;
            if size < p.size.size_min {
                return Err(Error::msg(format!(
                    "Existing MBR partition slot {i} is {} bytes, smaller than the manifest minimum ({} bytes). Use --wipe to recreate it.",
                    size, p.size.size_min
                )));
            }
            eprintln!("      Partition slot {i}: reused (offset={offset}, size={size})");
            let content = if let Some(content) = &p.content {
                let sub = region.open_region(offset, size);
                Some(Box::new(plan_block(ctx, vgs, content, &sub, false)?))
            } else {
                None
            };
            parts.push(MbrPartPlan {
                offset,
                size,
                content,
            });
        } else {
            eprintln!("      Partition slot {i}: not found in existing table, will create new");
            need_rebuild = true;
            parts.push(MbrPartPlan {
                offset: 0,
                size: 0,
                content: p.content.clone().map(|c| Box::new(Plan::Fresh(*c))),
            });
        }
    }

    let table = if need_rebuild {
        // Rebuild the full MBR from the manifest (slots that were reused keep
        // their existing geometry; new slots are laid out after the last used).
        let (mbr, new_placed) = compute_mbr_layout(block, region.region_size())?;
        // Fill in offsets/sizes for slots that were newly created.
        for (i, placed) in new_placed.iter().enumerate() {
            if parts[i].offset == 0 && parts[i].size == 0 {
                parts[i].offset = placed.0;
                parts[i].size = placed.1;
            }
        }
        Some(mbr)
    } else {
        None
    };

    Ok(Plan::Mbr(Box::new(MbrPlan {
        table,
        parts,
        bootcode: block.bootcode.clone(),
    })))
}

fn plan_fs_reuse<R: BlockRegion>(
    ctx: &InstallContext,
    block: &ManifestBlockFs,
    region: &R,
    fat: bool,
) -> Result<Plan> {
    // Validate the existing filesystem is mountable (read-only; no writes).
    if fat {
        let dev = region.clone();
        let _fs = hadris_fat::sync::FatVolume::open(dev)
            .map_err(|e| Error::msg(format!(
                "Cannot reuse existing FAT filesystem (the target does not contain a valid FAT volume). \
                 Use --wipe to format a new one (this will destroy all existing data). Original error: {e}"
            )))?;
    } else {
        let dev: Arc<dyn fs_ext4::block_io::BlockDevice> = Arc::new(region.clone());
        let _fs = fs_ext4::fs::Filesystem::mount_lazy(dev)
            .map_err(|e| Error::msg(format!(
                "Cannot reuse existing ext4 filesystem (the target does not contain a valid ext4 volume). \
                 Use --wipe to format a new one (this will destroy all existing data). Original error: {e}"
            )))?;
    }
    let archive = if let Some(archive) = &block.archive {
        Some((resolve_archive(ctx, archive)?, archive.format, archive.size))
    } else {
        None
    };
    Ok(Plan::Fs(FsPlan { fat, archive }))
}

fn plan_lvm<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockLvm,
    region: &R,
    fresh: bool,
) -> Result<Plan> {
    let Some(vg_name) = &block.vg else {
        // A standalone PV not belonging to any VG: nothing to install.
        return Ok(Plan::Lvm);
    };

    // Accumulate multiple PVs of the same VG (encountered across partitions).
    if let Some(existing_plan) = vgs.get_mut(vg_name) {
        existing_plan.pvs.push(region.clone());
        return Ok(Plan::Lvm);
    }

    let vg_manifest = ctx.manifest.lvm.get(vg_name).cloned().ok_or_else(|| {
        Error::msg(format!(
            "No LVM volume group \"{vg_name}\" in manifest but a PV references it"
        ))
    })?;

    let existing = if fresh {
        None
    } else {
        let mut handle = region.clone();
        match crate::lvm::read_vg_from_handle(&mut handle)? {
            Some(vg) => Some(vg),
            None => {
                return Err(Error::msg(format!(
                    "Target does not contain an existing LVM physical volume for volume group \"{vg_name}\". \
                     Use --wipe to create one from scratch (this will destroy all existing data)."
                )));
            }
        }
    };

    eprintln!(
        "    LVM volume group \"{vg_name}\": {}",
        if existing.is_some() {
            "reusing existing"
        } else {
            "creating fresh (--wipe)"
        }
    );
    let plan = match &existing {
        None => register_fresh_vg(vg_name, &vg_manifest, region)?,
        Some(existing_vg) => plan_reuse_vg(ctx, vgs, vg_name, &vg_manifest, existing_vg, region)?,
    };
    vgs.insert(vg_name.clone(), plan);
    Ok(Plan::Lvm)
}

/// Build a fresh single-PV VG layout (all LVs newly created).
fn register_fresh_vg<R: BlockRegion>(
    vg_name: &str,
    vg_manifest: &ManifestLvmVg,
    region: &R,
) -> Result<VgPlan<R>> {
    let layout = crate::lvm::compute_vg_layout(
        vg_name,
        vg_manifest,
        &[crate::lvm::PvRegion {
            device_size: region.region_size(),
        }],
    )?;
    let lv_plans = layout
        .lv_plans
        .iter()
        .map(|p| LvPlan {
            name: p.partition.name.clone(),
            offset: p.relative_offset,
            size: p.size,
            content: p
                .partition
                .content
                .clone()
                .map(|c| Box::new(Plan::Fresh(*c))),
        })
        .collect();
    Ok(VgPlan {
        pvs: vec![region.clone()],
        existing: None,
        vg: layout.vg,
        lv_plans,
    })
}

/// Reconcile an existing VG with the manifest: reuse named LVs (and plan their
/// content recursively), create missing LVs in the free extents.
fn plan_reuse_vg<R: BlockRegion>(
    ctx: &mut InstallContext,
    _vgs: &mut VgPlans<R>,
    vg_name: &str,
    vg_manifest: &ManifestLvmVg,
    existing: &crate::lvm::VolumeGroup,
    region: &R,
) -> Result<VgPlan<R>> {
    let pe_size = existing.extent_size;
    let pv0 = existing.pvs.first().ok_or_else(|| {
        Error::msg(format!(
            "Volume group \"{vg_name}\" has no physical volumes"
        ))
    })?;

    // First free extent = past the last extent used by any existing LV on pv0.
    let first_free = existing
        .lvs
        .iter()
        .flat_map(|lv| lv.segments.iter())
        .filter(|seg| seg.pv_name == pv0.name)
        .map(|seg| seg.pv_start_extent + seg.extent_count)
        .max()
        .unwrap_or(0);

    // Split manifest LVs into reused (already in the VG) and new.
    let mut lv_plans: Vec<LvPlan> = Vec::with_capacity(vg_manifest.partitions.len());
    let mut new_indices: Vec<usize> = Vec::new();
    let mut new_specs: Vec<ManifestPartitionSize> = Vec::new();

    for (i, p) in vg_manifest.partitions.iter().enumerate() {
        if let Some(existing_lv) = existing.find_lv(&p.name) {
            // Reuse the existing LV's extents (assume a single linear segment).
            let seg = existing_lv
                .segments
                .first()
                .ok_or_else(|| Error::msg(format!("LV \"{}\" has no segments", p.name)))?;
            let offset = pv0.extent_offset(seg.pv_start_extent, pe_size);
            let size = seg.size_bytes(pe_size);
            if size < p.size.size_min {
                return Err(Error::msg(format!(
                    "Existing LVM volume \"{}\" is {} bytes, smaller than the manifest minimum ({} bytes). Use --wipe to recreate it.",
                    p.name, size, p.size.size_min
                )));
            }
            let content = if let Some(content) = &p.content {
                let sub = region.open_region(offset, size);
                Some(Box::new(plan_block(ctx, _vgs, content, &sub, false)?))
            } else {
                None
            };
            lv_plans.push(LvPlan {
                name: p.name.clone(),
                offset,
                size,
                content,
            });
        } else {
            new_indices.push(i);
            new_specs.push(p.size.clone());
        }
    }

    // Build the merged VG: clone the existing one and append the new LVs.
    let mut merged = existing.clone();
    merged.seqno = existing.seqno.wrapping_add(1);

    if !new_indices.is_empty() {
        let free_extents = pv0.pe_count.saturating_sub(first_free);
        let mut size_specs = new_specs.clone();
        if let Some(empty) = &vg_manifest.empty_space {
            size_specs.push(empty.clone());
        }
        let computed = compute_partition_sizes(&size_specs, free_extents * pe_size, pe_size)?;
        let new_sizes = &computed[..new_specs.len()];

        let mut next_pe = first_free;
        for (k, &i) in new_indices.iter().enumerate() {
            let p = &vg_manifest.partitions[i];
            let size = new_sizes[k];
            let extent_count = size / pe_size;
            if extent_count == 0 {
                return Err(Error::msg(format!(
                    "New LVM volume \"{}\" is smaller than one extent ({pe_size} bytes)",
                    p.name
                )));
            }
            if next_pe + extent_count > pv0.pe_count {
                return Err(Error::msg(format!(
                    "Not enough free extents in volume group \"{vg_name}\" for new volume \"{}\"",
                    p.name
                )));
            }
            merged.lvs.push(crate::lvm::LogicalVolume {
                name: p.name.clone(),
                id: crate::lvm::generate_id(),
                segments: vec![crate::lvm::LvSegment {
                    start_extent: 0,
                    extent_count,
                    pv_name: pv0.name.clone(),
                    pv_start_extent: next_pe,
                }],
            });
            lv_plans.push(LvPlan {
                name: p.name.clone(),
                offset: pv0.extent_offset(next_pe, pe_size),
                size,
                content: p.content.clone().map(|c| Box::new(Plan::Fresh(*c))),
            });
            next_pe += extent_count;
        }
        // Recompute the allocated-extent count from all LV segments (robust to
        // any pre-existing fragmentation).
        if let Some(pv0m) = merged.pvs.iter_mut().find(|pv| pv.name == pv0.name) {
            pv0m.pe_alloc_count = merged
                .lvs
                .iter()
                .flat_map(|lv| lv.segments.iter())
                .filter(|seg| seg.pv_name == pv0.name)
                .map(|seg| seg.extent_count)
                .sum();
        }
    }

    Ok(VgPlan {
        pvs: vec![region.clone()],
        existing: Some(existing.clone()),
        vg: merged,
        lv_plans,
    })
}

fn plan_luks<R: BlockRegion>(
    ctx: &mut InstallContext,
    block: &ManifestBlockLuks,
    region: &R,
) -> Result<Plan> {
    let passphrase = ctx
        .keys
        .get(&block.name)
        .ok_or_else(|| {
            Error::msg(format!(
                "No passphrase available for LUKS container \"{}\"",
                block.name
            ))
        })?
        .clone();

    // Probe for an existing LUKS2 header.
    let mut probe = region.clone();
    let info = match crate::luks::read_luks2_segment_info(&mut probe)? {
        Some(info) => info,
        None => {
            return Err(Error::msg(format!(
                "Target does not contain an existing LUKS2 container for \"{}\". \
                 Use --wipe to create one from scratch (this will destroy all existing data).",
                block.name
            )));
        }
    };

    // Unlock (validates the passphrase) and recover the master key. The payload
    // is NOT read here: only the header/keyslots are touched (read-only on the
    // target). The master key + segment info let us build a [`LuksRegion`] that
    // decrypts/encrypts sectors on the fly while planning the nested content.
    let mut reader = region.clone();
    let vol = crate::luks::open_luks2(&mut reader, &passphrase)?;
    let master_key = vol.master_key().to_vec();
    drop(vol);

    let region_size = region.region_size();
    let sector_size = info.sector_size as u64;
    let payload_available = region_size.saturating_sub(info.payload_offset);
    let payload_size = (payload_available / sector_size) * sector_size;
    if payload_size == 0 {
        return Err(Error::msg(format!(
            "LUKS2 container \"{}\" payload area is {} bytes (need at least one {}-byte sector)",
            block.name, payload_available, sector_size
        )));
    }

    eprintln!(
        "    LUKS2 \"{}\": reusing existing container ({}-byte payload, on-the-fly crypto)...",
        block.name, payload_size
    );

    // Plan the nested content directly against a decrypting/encrypting view of
    // the data segment. No temp file is created and no full decrypt/re-encrypt
    // pass runs: only the sectors actually read/written by the nested content
    // (filesystem format, merge, GPT, LVM, …) are touched.
    //
    // The encrypted backing is erased behind `Arc<dyn BlockDevice>` so that
    // `LuksRegion` is a single concrete type — nesting LUKS inside LUKS does
    // not grow the region type (and thus cannot recurse the `Plan` type to
    // infinity); every level erases back to the same `LuksRegion`.
    let backing: std::sync::Arc<dyn fs_ext4::block_io::BlockDevice> =
        std::sync::Arc::new(region.clone());
    let luks_region = crate::blockfile::LuksRegion::new(
        backing,
        info.payload_offset,
        payload_size,
        master_key.clone(),
        info.sector_size,
        info.cipher_mode.clone(),
        info.iv_tweak,
    );
    let mut child_vgs: VgPlans<LuksRegion> = BTreeMap::new();
    let content = if let Some(content) = &block.content {
        Some(Box::new(plan_block(
            ctx,
            &mut child_vgs,
            content,
            &luks_region,
            false,
        )?))
    } else {
        None
    };

    Ok(Plan::Luks(LuksPlan {
        payload_size,
        payload_offset: info.payload_offset,
        sector_size: info.sector_size,
        cipher_mode: info.cipher_mode,
        iv_tweak: info.iv_tweak,
        master_key,
        content,
        vgs: child_vgs,
    }))
}

// ===========================================================================
// Apply phase (write)
// ===========================================================================

fn apply_block<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    plan: Plan,
    region: &mut R,
) -> Result<()> {
    match plan {
        Plan::Fresh(block) => {
            eprintln!("    Creating fresh {} block...", block_type_name(&block));
            install_block_fresh(ctx, vgs, &block, region)
        }
        Plan::Gpt(g) => apply_gpt(ctx, vgs, g, region),
        Plan::Mbr(m) => apply_mbr(ctx, vgs, *m, region),
        Plan::Image(i) => {
            if i.skip {
                eprintln!("    Image already present (digest matches) — skipping copy.");
            } else {
                eprintln!("    Copying image ({} bytes)...", i.size);
            }
            apply_image(ctx, i, region)
        }
        Plan::Fs(f) => apply_fs(ctx, f, region),
        Plan::Lvm => Ok(()),
        Plan::Luks(l) => apply_luks(ctx, l, region),
    }
}

fn apply_gpt<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    plan: GptPlan,
    region: &mut R,
) -> Result<()> {
    let GptPlan {
        table,
        parts,
        mbr,
        bootcode,
    } = plan;
    if let Some(table) = &table {
        if let Some(hybrid_mbr) = &mbr {
            eprintln!("    Writing hybrid MBR + GPT partition table...");
            let mbr = build_hybrid_mbr(table, hybrid_mbr)?;
            table
                .write_to_with_mbr(region, &mbr)
                .map_err(map_part_err)?;
        } else {
            eprintln!("    Writing GPT partition table...");
            table.write_to(region).map_err(map_part_err)?;
        }
    } else if mbr.is_some() {
        eprintln!("    Hybrid GPT table unchanged (all partitions reused).");
    } else {
        eprintln!("    GPT table unchanged (all partitions reused).");
    }
    if let Some(bc) = &bootcode {
        write_bootcode(ctx, bc.as_str(), region)?;
    }
    for part in parts {
        if let Some(content) = part.content {
            let mut sub = region.open_region(part.offset, part.size);
            apply_block(ctx, vgs, *content, &mut sub)?;
        }
    }
    Ok(())
}

fn apply_mbr<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    plan: MbrPlan,
    region: &mut R,
) -> Result<()> {
    if let Some(table) = &plan.table {
        eprintln!("    Writing MBR partition table...");
        region.seek(SeekFrom::Start(0))?;
        table.write_to(region).map_err(map_part_err)?;
    } else {
        eprintln!("    MBR table unchanged (all partitions reused).");
    }
    if let Some(bc) = &plan.bootcode {
        write_bootcode(ctx, bc.as_str(), region)?;
    }
    for part in plan.parts {
        if let Some(content) = part.content {
            let mut sub = region.open_region(part.offset, part.size);
            apply_block(ctx, vgs, *content, &mut sub)?;
        }
    }
    Ok(())
}

/// Build a hybrid MBR for a GPT disk, mirroring the configured GPT partitions.
fn build_hybrid_mbr(gpt: &GptDisk, hybrid_mbr: &ManifestHybridMbr) -> Result<MasterBootRecord> {
    let disk_sectors = gpt.backup_header.my_lba.to_ne() + 1;
    let mut builder =
        HybridMbrBuilder::new(disk_sectors).protective_slot(hybrid_mbr.protective_slot);
    for m in &hybrid_mbr.mirrored {
        let idx = gpt
            .partitions()
            .find(|(_, e)| gpt_name_string(e) == m.partition)
            .map(|(i, _)| i as u32)
            .ok_or_else(|| {
                Error::msg(format!(
                    "Hybrid MBR mirror partition \"{}\" not found in GPT",
                    m.partition
                ))
            })?;
        let mbr_type = MbrPartitionType::from_u8(m.type_code);
        builder = builder.mirror_partition(idx, mbr_type, m.bootable);
    }
    builder.build(&gpt.entries).map_err(map_part_err)
}

fn apply_image<R: BlockRegion>(
    _ctx: &mut InstallContext,
    plan: ImagePlan,
    region: &mut R,
) -> Result<()> {
    if plan.skip {
        // The region already holds the expected bytes — verified during
        // planning via region_digest. Nothing to write.
        return Ok(());
    }
    let mut src = std::fs::File::open(&plan.source)?;
    copy_into_region(region, &mut src, plan.size, "Writing image")?;
    Ok(())
}

fn apply_fs<R: BlockRegion>(_ctx: &mut InstallContext, plan: FsPlan, region: &mut R) -> Result<()> {
    let fs_kind = if plan.fat { "FAT" } else { "ext4" };
    if plan.fat {
        eprintln!("    {fs_kind}: mounting existing filesystem and merging content...");
        let dev = region.clone();
        let fs = hadris_fat::sync::FatVolume::builder(dev)
            .fat_cache(FAT_CACHE_SECTORS)
            .open()
            .map_err(|e| Error::msg(format!("fat mount: {e}")))?;
        if let Some((archive_path, format, total_bytes)) = &plan.archive {
            eprintln!("    {fs_kind}: extracting archive directly into filesystem...");
            let mut sink = FatContentSink { fs: &fs };
            extract_archive_into(archive_path, *format, *total_bytes, &mut sink)?;
        }
        // Flush the FAT-sector cache (writes dirty FAT sectors back to every
        // FAT copy) before dropping the handle — without this, never-evicted
        // dirty cache entries would be lost on drop.
        fs.flush().map_err(map_fat_err)?;
        drop(fs);
    } else {
        eprintln!("    {fs_kind}: mounting existing filesystem and merging content...");
        let dev: Arc<dyn fs_ext4::block_io::BlockDevice> = Arc::new(region.clone());
        let fs = fs_ext4::fs::Filesystem::mount(dev).map_err(map_ext4_err)?;
        if let Some((archive_path, format, total_bytes)) = &plan.archive {
            eprintln!("    {fs_kind}: extracting archive directly into filesystem...");
            let mut sink = Ext4ContentSink { fs: &fs };
            extract_archive_into(archive_path, *format, *total_bytes, &mut sink)?;
        }
        fs.dev.flush().map_err(map_ext4_err)?;
    }
    eprintln!("    {fs_kind}: syncing...");
    region.sync_region()?;
    Ok(())
}

fn apply_luks<R: BlockRegion>(
    ctx: &mut InstallContext,
    plan: LuksPlan,
    region: &mut R,
) -> Result<()> {
    let LuksPlan {
        payload_size,
        payload_offset,
        sector_size,
        cipher_mode,
        iv_tweak,
        master_key,
        content,
        mut vgs,
    } = plan;

    // Reconstruct the decrypting/encrypting view of the data segment and apply
    // the nested content straight into it. Every sector written by the nested
    // install (filesystem format/merge, GPT, LVM, …) is XTS-encrypted on the fly
    // and written directly into the container's data segment. The LUKS2 header
    // and keyslots are never touched. No temp file is involved, so there is no
    // full decrypt/re-encrypt pass and no plaintext ever lands on disk.
    eprintln!(
        "    LUKS2: applying content (on-the-fly encryption, {}-byte payload)...",
        payload_size
    );
    let backing: std::sync::Arc<dyn fs_ext4::block_io::BlockDevice> =
        std::sync::Arc::new(region.clone());
    let mut luks = crate::blockfile::LuksRegion::new(
        backing,
        payload_offset,
        payload_size,
        master_key,
        sector_size,
        cipher_mode,
        iv_tweak,
    );
    if let Some(content) = content {
        apply_block(ctx, &mut vgs, *content, &mut luks)?;
    }
    finalize_vgs(ctx, &mut vgs)?;
    luks.sync_region()?;
    Ok(())
}

// ===========================================================================
// Fresh install path (used by Plan::Fresh and the wipe mode)
// ===========================================================================

/// Install `block` into `region` from scratch, creating every structure.
fn install_block_fresh<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlock,
    region: &mut R,
) -> Result<()> {
    match block {
        ManifestBlock::Gpt(b) => install_gpt_fresh(ctx, vgs, b, region),
        ManifestBlock::Mbr(b) => install_mbr_fresh(ctx, vgs, b, region),
        ManifestBlock::Image(b) => install_image(ctx, b, region),
        ManifestBlock::Ext4(b) => install_fs(ctx, b, region, "ext4"),
        ManifestBlock::Fat(b) => install_fs(ctx, b, region, "fat"),
        ManifestBlock::Lvm(b) => install_lvm_fresh(ctx, vgs, b, region),
        ManifestBlock::Luks(b) => install_luks_fresh(ctx, b, region),
    }
}

fn install_gpt_fresh<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockGpt,
    region: &mut R,
) -> Result<()> {
    eprintln!(
        "    GPT: computing layout for {} partitions...",
        block.partitions.len()
    );
    let (gpt, placed) = compute_gpt_layout(block, region.region_size())?;
    if let Some(hybrid_mbr) = &block.mbr {
        eprintln!("    Hybrid: writing GPT + hybrid MBR partition table...");
        let mbr = build_hybrid_mbr(&gpt, hybrid_mbr)?;
        gpt.write_to_with_mbr(region, &mbr).map_err(map_part_err)?;
    } else {
        eprintln!("    GPT: writing partition table...");
        gpt.write_to(region).map_err(map_part_err)?;
    }

    if let Some(bc) = &block.bootcode {
        write_bootcode(ctx, bc.as_str(), region)?;
    }

    for (i, partition) in block.partitions.iter().enumerate() {
        if let Some(content) = &partition.content {
            let (poffset, psize) = placed[i];
            eprintln!(
                "      Partition \"{}\": installing content (offset={}, size={})...",
                partition.name, poffset, psize
            );
            let mut child = region.open_region(poffset, psize);
            install_block_fresh(ctx, vgs, content, &mut child)?;
        }
    }
    Ok(())
}

fn install_mbr_fresh<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockMbr,
    region: &mut R,
) -> Result<()> {
    eprintln!(
        "    MBR: computing layout for {} partitions...",
        block.partitions.len()
    );
    let (mbr, placed) = compute_mbr_layout(block, region.region_size())?;
    eprintln!("    MBR: writing partition table...");
    region.seek(SeekFrom::Start(0))?;
    mbr.write_to(region).map_err(map_part_err)?;

    if let Some(bc) = &block.bootcode {
        write_bootcode(ctx, bc.as_str(), region)?;
    }

    for (i, partition) in block.partitions.iter().enumerate() {
        if let Some(content) = &partition.content {
            let (poffset, psize) = placed[i];
            eprintln!(
                "      Partition slot {i}: installing content (offset={poffset}, size={psize})..."
            );
            let mut child = region.open_region(poffset, psize);
            install_block_fresh(ctx, vgs, content, &mut child)?;
        }
    }
    Ok(())
}

fn install_image<R: BlockRegion>(
    ctx: &mut InstallContext,
    block: &ManifestBlockImage,
    region: &mut R,
) -> Result<()> {
    let source = resolve_manifest_file(ctx, &block.file)?;
    let file_info =
        ctx.manifest.file.get(&block.file).ok_or_else(|| {
            Error::msg(format!("Manifest has no file entry for \"{}\"", block.file))
        })?;
    let copy_size = std::cmp::min(file_info.size, region.region_size());
    let mut src = std::fs::File::open(&source)?;
    copy_into_region(region, &mut src, copy_size, "Installing image")?;
    Ok(())
}

fn install_fs<R: BlockRegion>(
    ctx: &mut InstallContext,
    block: &ManifestBlockFs,
    region: &mut R,
    fs_kind: &str,
) -> Result<()> {
    // Resolve the content archive (if any) for direct extraction into the
    // freshly formatted filesystem — no temp directory involved.
    let archive = if let Some(archive) = &block.archive {
        eprintln!("    {fs_kind}: resolving content archive...");
        let archive_file = resolve_manifest_file(ctx, &archive.file)?;
        Some((archive_file, archive.format, archive.size))
    } else {
        None
    };

    // Resolve the in-memory tree (build-time blocks skip the archive).
    let tree = if let Some(key) = &block.tree_key {
        eprintln!("    {fs_kind}: resolving in-memory tree...");
        let resolver = ctx.tree_resolver.as_ref().ok_or_else(|| {
            Error::msg(format!(
                "FS block has tree_key \"{key}\" but no tree resolver is configured"
            ))
        })?;
        Some(resolver(key)?)
    } else {
        None
    };

    let size = region.region_size();
    let block_size = block.block_size.unwrap_or(BLOCK_SIZE as u32);
    match fs_kind {
        "ext4" => {
            eprintln!(
                "    {fs_kind}: formatting filesystem ({} bytes, block_size={})...",
                size, block_size
            );
            format_ext4(region, size, archive.as_ref(), tree.as_ref(), block_size)?;
        }
        "fat" => {
            eprintln!("    {fs_kind}: formatting filesystem ({} bytes)...", size);
            format_fat(
                region,
                size,
                archive.as_ref(),
                tree.as_ref(),
                block.block_size,
                block.fat_version,
            )?;
        }
        other => return Err(Error::msg(format!("Unknown filesystem kind: {other}"))),
    }
    eprintln!("    {fs_kind}: filesystem created.");
    Ok(())
}

fn install_lvm_fresh<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    block: &ManifestBlockLvm,
    region: &R,
) -> Result<()> {
    let Some(vg_name) = &block.vg else {
        return Ok(());
    };
    eprintln!("    LVM volume group \"{vg_name}\": registering fresh PV...",);
    let vg_manifest = ctx.manifest.lvm.get(vg_name).cloned().ok_or_else(|| {
        Error::msg(format!(
            "No LVM volume group \"{vg_name}\" in manifest but a PV references it"
        ))
    })?;

    if let Some(existing) = vgs.get_mut(vg_name) {
        // Accumulate an additional PV for an already-planned VG.
        existing.pvs.push(region.clone());
        let pv_regions: Vec<crate::lvm::PvRegion> = existing
            .pvs
            .iter()
            .map(|r| crate::lvm::PvRegion {
                device_size: r.region_size(),
            })
            .collect();
        let layout = crate::lvm::compute_vg_layout(vg_name, &vg_manifest, &pv_regions)?;
        existing.vg = layout.vg;
    } else {
        let plan = register_fresh_vg(vg_name, &vg_manifest, region)?;
        vgs.insert(vg_name.clone(), plan);
    }
    Ok(())
}

/// Install a LUKS2 block (fresh): format the header + keyslot, then install
/// the nested content *directly* into a [`LuksRegion`] that encrypts every
/// written sector on the fly. No temp plaintext image and no full-disk
/// encrypt pass: only the sectors the nested content actually writes (e.g.
/// the filesystem metadata + file data) are encrypted and stored.
fn install_luks_fresh<R: BlockRegion>(
    ctx: &mut InstallContext,
    block: &ManifestBlockLuks,
    region: &mut R,
) -> Result<()> {
    use crate::luks::{Luks2Params, format_luks2};

    let passphrase = ctx
        .keys
        .get(&block.name)
        .ok_or_else(|| {
            Error::msg(format!(
                "No passphrase available for LUKS container \"{}\"",
                block.name
            ))
        })?
        .clone();

    eprintln!("    LUKS2 \"{}\": formatting new container...", block.name);
    let params = Luks2Params {
        cipher: block.cipher.clone(),
        key_size: block.key_size,
        sector_size: block.sector_size,
        iv_tweak: 0,
        kdf: block.kdf.clone(),
        af_stripes: block.af_stripes,
        af_hash: block.af_hash.clone(),
        payload_align: block.payload_align,
        uuid: block.uuid.as_ref().map(|g| g.to_string()),
    };

    let result = format_luks2(region, &passphrase, &params)?;

    let sector_size = result.sector_size as u64;
    let payload_available = region.region_size().saturating_sub(result.payload_offset);
    let payload_size = (payload_available / sector_size) * sector_size;
    if payload_size == 0 {
        return Err(Error::msg(format!(
            "LUKS2 container too small: payload area is {} bytes (need at least one {}-byte sector)",
            payload_available, sector_size
        )));
    }

    // Install the nested content straight into the encrypting view of the data
    // segment. The freshly created data segment is sparse zeros; sectors that
    // the nested install never writes stay unwritten (exactly what a real
    // `cryptsetup`-formatted container leaves behind), while every sector the
    // filesystem formatter / populator writes is XTS-encrypted on the fly.
    eprintln!(
        "    LUKS2 \"{}\": installing content (on-the-fly encryption, {}-byte payload)...",
        block.name, payload_size
    );
    let backing: std::sync::Arc<dyn fs_ext4::block_io::BlockDevice> =
        std::sync::Arc::new(region.clone());
    let mut luks = crate::blockfile::LuksRegion::new(
        backing,
        result.payload_offset,
        payload_size,
        result.master_key.clone(),
        result.sector_size,
        result.cipher_mode.clone(),
        result.iv_tweak,
    );
    let mut child_vgs: VgPlans<LuksRegion> = BTreeMap::new();
    if let Some(content) = &block.content {
        install_block_fresh(ctx, &mut child_vgs, content, &mut luks)?;
    }
    finalize_vgs(ctx, &mut child_vgs)?;
    luks.sync_region()?;
    eprintln!("    LUKS2 \"{}\": syncing...", block.name);
    region.sync_region()?;
    Ok(())
}

/// Finalize deferred volume groups: write each VG's metadata to its PVs and
/// install every LV's content into its allocated extents. Runs after the disk
/// plans are applied (so reused partition data is in place). Drains `vgs`;
/// content installs that register further VGs (e.g. LVM inside a freshly
/// created LV) are processed in subsequent passes.
fn finalize_vgs<R: BlockRegion>(ctx: &mut InstallContext, vgs: &mut VgPlans<R>) -> Result<()> {
    loop {
        let pending = std::mem::take(vgs);
        if pending.is_empty() {
            break;
        }
        for (vg_name, plan) in pending {
            eprintln!("  Finalizing LVM volume group \"{vg_name}\"...");
            finalize_one_vg(ctx, vgs, vg_name, plan)?;
        }
    }
    Ok(())
}

fn finalize_one_vg<R: BlockRegion>(
    ctx: &mut InstallContext,
    vgs: &mut VgPlans<R>,
    _vg_name: String,
    plan: VgPlan<R>,
) -> Result<()> {
    let VgPlan {
        mut pvs,
        vg,
        lv_plans,
        ..
    } = plan;
    eprintln!("    Writing LVM metadata to {} PV(s)...", pvs.len());
    let metadata_text = crate::lvm::emit_vg_metadata(&vg);
    // Write the metadata to every registered PV (matched by index to the VG's
    // PV descriptors; single-PV VGs — the common case — match trivially).
    let n_pvs = pvs.len().min(vg.pvs.len());
    for (pv, pv_desc) in pvs.iter_mut().zip(vg.pvs.iter()).take(n_pvs) {
        crate::lvm::write_pv(pv, pv_desc, &metadata_text)?;
    }
    // Install each LV's content into its extents on the first PV.
    if let Some(pv_region) = pvs.into_iter().next() {
        for lv in lv_plans {
            if let Some(content) = lv.content {
                eprintln!(
                    "    Installing LV \"{}\" content (offset={}, size={})...",
                    lv.name, lv.offset, lv.size
                );
                let mut lv_region = pv_region.open_region(lv.offset, lv.size);
                apply_block(ctx, vgs, *content, &mut lv_region)?;
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Direct archive extraction into a target filesystem (no temp directory)
// ===========================================================================

/// Write archive entries directly into a target filesystem (ext4 or FAT),
/// without staging them on the host filesystem first. Each method handles
/// both the fresh case (nothing exists yet) and the merge case (existing
/// entries are overwritten or reused).
trait ContentSink {
    /// Create a directory at `path` (relative, e.g. "foo/bar"), reusing an
    /// existing directory if present. Returns an error if a non-directory
    /// entry exists at `path`.
    fn ensure_dir(&mut self, path: &str, mode: u16) -> Result<()>;
    /// Write a regular file at `path` with the given `mode` and `data`,
    /// creating or replacing as needed. Returns an error if a directory
    /// exists at `path`.
    fn write_file(&mut self, path: &str, mode: u16, data: &[u8]) -> Result<()>;
    /// Write a symlink at `path` pointing to `target`, creating or replacing
    /// as needed. Returns an error if a directory exists at `path`.
    fn write_symlink(&mut self, path: &str, target: &str) -> Result<()>;
    /// Write a device node at `path` with the given `mode`, `major` and
    /// `minor` numbers, creating or replacing as needed. Returns an error
    /// if a directory exists at `path`.
    fn write_device(&mut self, path: &str, mode: u16, major: u32, minor: u32) -> Result<()>;
    /// Set the extended attribute `name` on the entry at `path`. Filesystems
    /// that cannot represent xattrs (FAT) ignore this.
    fn set_xattr(&mut self, path: &str, name: &[u8], value: &[u8]) -> Result<()>;
}

// --- ext4 content sink ---

/// Direct content sink for ext4: writes entries via the ext4 filesystem API
/// using full paths (e.g. "/foo/bar").
struct Ext4ContentSink<'a> {
    fs: &'a fs_ext4::fs::Filesystem,
}

impl ContentSink for Ext4ContentSink<'_> {
    fn ensure_dir(&mut self, path: &str, mode: u16) -> Result<()> {
        let rel = format!("/{path}");
        match ext4_stat(self.fs, &rel)? {
            Some(inode) if !inode.is_dir() => Err(Error::msg(format!(
                "Cannot replace non-directory \"{rel}\" with a directory"
            ))),
            Some(_) => Ok(()), // reuse existing directory
            None => {
                self.fs.apply_mkdir(&rel, mode).map_err(map_ext4_err)?;
                Ok(())
            }
        }
    }

    fn write_file(&mut self, path: &str, mode: u16, data: &[u8]) -> Result<()> {
        let rel = format!("/{path}");
        match self.fs.apply_replace_file_content(&rel, data) {
            Ok(_) => {
                let _ = self.fs.apply_chmod(&rel, mode);
                Ok(())
            }
            Err(fs_ext4::error::Error::NotFound) => {
                self.fs.apply_create(&rel, mode).map_err(map_ext4_err)?;
                self.fs
                    .apply_replace_file_content(&rel, data)
                    .map_err(map_ext4_err)?;
                Ok(())
            }
            Err(fs_ext4::error::Error::IsADirectory)
            | Err(fs_ext4::error::Error::InvalidArgument(_)) => Err(Error::msg(format!(
                "Cannot replace directory \"{rel}\" with a regular file"
            ))),
            Err(e) => Err(map_ext4_err(e)),
        }
    }

    fn write_symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let rel = format!("/{path}");
        match ext4_stat(self.fs, &rel)? {
            Some(inode) if inode.is_dir() => Err(Error::msg(format!(
                "Cannot replace directory \"{rel}\" with a symlink"
            ))),
            Some(_) => {
                self.fs.apply_unlink(&rel).map_err(map_ext4_err)?;
                self.fs.apply_symlink(target, &rel).map_err(map_ext4_err)?;
                Ok(())
            }
            None => {
                self.fs.apply_symlink(target, &rel).map_err(map_ext4_err)?;
                Ok(())
            }
        }
    }

    fn write_device(&mut self, path: &str, mode: u16, major: u32, minor: u32) -> Result<()> {
        let rel = format!("/{path}");
        match ext4_stat(self.fs, &rel)? {
            Some(inode) if inode.is_dir() => Err(Error::msg(format!(
                "Cannot replace directory \"{rel}\" with a device node"
            ))),
            Some(_) => {
                self.fs.apply_unlink(&rel).map_err(map_ext4_err)?;
                self.fs
                    .apply_mknod(&rel, mode, major, minor)
                    .map_err(map_ext4_err)?;
                Ok(())
            }
            None => {
                self.fs
                    .apply_mknod(&rel, mode, major, minor)
                    .map_err(map_ext4_err)?;
                Ok(())
            }
        }
    }

    fn set_xattr(&mut self, path: &str, name: &[u8], value: &[u8]) -> Result<()> {
        let rel = format!("/{path}");
        let name = match std::str::from_utf8(name) {
            Ok(name) => name,
            Err(_) => {
                eprintln!("ext4: skipping xattr with a non-UTF-8 name on \"{rel}\"");
                return Ok(());
            }
        };
        match self.fs.apply_setxattr(&rel, name, value) {
            Ok(()) => Ok(()),
            // The ext4 writer knows the standard Linux namespaces; anything
            // else cannot be encoded on disk. Match the EROFS builder's
            // behaviour of skipping rather than failing the whole install.
            Err(fs_ext4::error::Error::InvalidArgument(_)) => {
                eprintln!("ext4: skipping unsupported xattr {name} on \"{rel}\"");
                Ok(())
            }
            Err(e) => Err(Error::msg(format!(
                "ext4: cannot set xattr {name} on \"{rel}\": {e}"
            ))),
        }
    }
}

/// Look up `path` on the mounted ext4 filesystem, returning the inode if it
/// exists.
fn ext4_stat(fs: &fs_ext4::fs::Filesystem, path: &str) -> Result<Option<fs_ext4::inode::Inode>> {
    let mut reader = |ino: u32| fs.read_inode_verified(ino).map(|(i, _)| i);
    match fs_ext4::path::lookup(fs.dev.as_ref(), &fs.sb, &mut reader, path) {
        Ok(ino) => {
            let (inode, _) = fs.read_inode_verified(ino).map_err(map_ext4_err)?;
            Ok(Some(inode))
        }
        Err(fs_ext4::error::Error::NotFound) => Ok(None),
        Err(e) => Err(map_ext4_err(e)),
    }
}

// --- FAT content sink ---

/// Direct content sink for FAT: writes entries via the FAT filesystem API.
/// Paths are navigated component-by-component from the root directory.
struct FatContentSink<'a, DATA: Read + Write + Seek> {
    fs: &'a FatVolume<DATA>,
}

impl<'a, DATA: Read + Write + Seek> FatContentSink<'a, DATA> {
    /// Navigate to (or create) the directory at `components`, returning a
    /// `FatDir` handle. Each component is created if it does not exist, or
    /// reused if it is already a directory.
    fn navigate_to_dir(&self, components: &[&str]) -> Result<hadris_fat::sync::FatDir<'a, DATA>> {
        let mut dir = self.fs.root_dir();
        for component in components {
            match dir.find(component).map_err(map_fat_err)? {
                Some(entry) if entry.is_directory() => {
                    dir = dir
                        .open_entry(&entry)
                        .map_err(|e| Error::msg(e.to_string()))?;
                }
                Some(_) => {
                    return Err(Error::msg(format!(
                        "Cannot replace non-directory \"{component}\" with a directory on FAT"
                    )));
                }
                None => {
                    dir = self.fs.create_dir(&dir, component).map_err(map_fat_err)?;
                }
            }
        }
        Ok(dir)
    }
}

impl<'a, DATA: Read + Write + Seek> ContentSink for FatContentSink<'a, DATA> {
    fn ensure_dir(&mut self, path: &str, _mode: u16) -> Result<()> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        self.navigate_to_dir(&components)?;
        Ok(())
    }

    fn write_file(&mut self, path: &str, _mode: u16, data: &[u8]) -> Result<()> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            return Err(Error::msg(
                "Cannot write a file at the filesystem root on FAT",
            ));
        }
        let (parent_components, name) = components.split_at(components.len() - 1);
        let parent = self.navigate_to_dir(parent_components)?;
        let name = name[0];
        match parent.find(name).map_err(map_fat_err)? {
            Some(existing) if existing.is_file() => {
                // Replace the existing file: delete + recreate. FAT has no
                // in-place truncate/rename, so this is the simplest correct
                // path; the freed clusters are returned to the pool.
                self.fs.delete(&existing).map_err(map_fat_err)?;
            }
            Some(_) => {
                return Err(Error::msg(format!(
                    "Cannot replace non-file \"{name}\" with a regular file on FAT"
                )));
            }
            None => {}
        }
        let entry = self.fs.create_file(&parent, name).map_err(map_fat_err)?;
        let mut writer = self.fs.write_file(&entry).map_err(map_fat_err)?;

        // Stream the file in fixed-size chunks, flushing the FAT-sector cache
        // between chunks (see `FAT_WRITE_CHUNK`). The writer releases all
        // internal locks after each call, so a `flush()` here is safe and
        // keeps the read-path allocator from starving for clean cache slots.
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + FAT_WRITE_CHUNK).min(data.len());
            writer.write(&data[offset..end]).map_err(map_fat_err)?;
            offset = end;
            if offset < data.len() {
                self.fs.flush().map_err(map_fat_err)?;
            }
        }
        writer.finish().map_err(map_fat_err)?;
        self.fs.flush().map_err(map_fat_err)?;
        Ok(())
    }

    fn write_symlink(&mut self, _path: &str, _target: &str) -> Result<()> {
        // Symlinks are not representable on FAT; skip silently.
        Ok(())
    }

    fn write_device(&mut self, _path: &str, _mode: u16, _major: u32, _minor: u32) -> Result<()> {
        // Device nodes are not representable on FAT; skip silently.
        Ok(())
    }

    fn set_xattr(&mut self, _path: &str, _name: &[u8], _value: &[u8]) -> Result<()> {
        // Extended attributes are not representable on FAT; skip silently.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Filesystem formatting + population (fresh path)
// ---------------------------------------------------------------------------

/// Format (and optionally populate) an ext4 filesystem directly into `region`.
/// When an `archive` is provided, its entries are extracted directly into the
/// freshly mounted filesystem — no temp directory on the host is used.
fn format_ext4<R: BlockRegion>(
    region: &R,
    size: u64,
    archive: Option<&(PathBuf, crate::model::config::ArchiveFormat, u64)>,
    tree: Option<&crate::archive::TreeNode>,
    block_size: u32,
) -> Result<()> {
    use fs_ext4::fs::Filesystem;
    use fs_ext4::mkfs::format_filesystem;

    let dev: Arc<R> = Arc::new(region.clone());
    format_filesystem(&*dev, None, None, size, block_size).map_err(map_ext4_err)?;
    if let Some((archive_path, format, total_bytes)) = archive {
        let fs = Filesystem::mount(dev).map_err(map_ext4_err)?;
        let mut sink = Ext4ContentSink { fs: &fs };
        extract_archive_into(archive_path, *format, *total_bytes, &mut sink)?;
        fs.dev.flush().map_err(map_ext4_err)?;
    } else if let Some(root) = tree {
        let fs = Filesystem::mount(dev).map_err(map_ext4_err)?;
        let mut sink = Ext4ContentSink { fs: &fs };
        write_tree_into(root, &mut sink)?;
        fs.dev.flush().map_err(map_ext4_err)?;
    }
    Ok(())
}

/// Format (and optionally populate) a FAT filesystem directly into `region`.
/// When an `archive` is provided, its entries are extracted directly into the
/// freshly formatted filesystem — no temp directory on the host is used.
fn format_fat<R: BlockRegion>(
    region: &R,
    size: u64,
    archive: Option<&(PathBuf, crate::model::config::ArchiveFormat, u64)>,
    tree: Option<&crate::archive::TreeNode>,
    block_size: Option<u32>,
    fat_version: Option<crate::model::config::FatVersion>,
) -> Result<()> {
    use hadris_fat::format::{FatFormatOptions, FatVolumeFormatter, SectorSize};

    let mut opts = FatFormatOptions::new(size)
        .sector_size(SectorSize::S512)
        .fat_type(fat_version.unwrap_or_default().to_fat_type_selection());
    if let Some(bs) = block_size {
        let spc = (bs as u64 / 512) as u8;
        opts = opts.sectors_per_cluster(spc);
    }
    let dev = region.clone();
    FatVolumeFormatter::format(dev, opts).map_err(map_fat_err)?;
    if let Some((archive_path, format, total_bytes)) = archive {
        let dev = region.clone();
        let fs = hadris_fat::sync::FatVolume::builder(dev)
            .fat_cache(FAT_CACHE_SECTORS)
            .open()
            .map_err(|e| Error::msg(format!("fat mount: {e}")))?;
        let mut sink = FatContentSink { fs: &fs };
        extract_archive_into(archive_path, *format, *total_bytes, &mut sink)?;
        fs.flush().map_err(map_fat_err)?;
    } else if let Some(root) = tree {
        let dev = region.clone();
        let fs = hadris_fat::sync::FatVolume::builder(dev)
            .fat_cache(FAT_CACHE_SECTORS)
            .open()
            .map_err(|e| Error::msg(format!("fat mount: {e}")))?;
        let mut sink = FatContentSink { fs: &fs };
        write_tree_into(root, &mut sink)?;
        fs.flush().map_err(map_fat_err)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive extraction (direct into ContentSink — no host temp directory)
// ---------------------------------------------------------------------------

/// Normalize an archive entry name to a relative path without leading `./` or
/// `/`, and without trailing `/`. Returns `None` for the root or empty names
/// (which should be skipped).
fn normalize_archive_path(name: &str) -> Option<String> {
    let mut name = name;
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    let name = name.strip_prefix('/').unwrap_or(name);
    if name.is_empty() || name == "." {
        None
    } else {
        Some(name.trim_end_matches('/').to_string())
    }
}

/// Ensure all parent directories of `path` exist, creating them with default
/// permissions (0o755) if necessary. The final path component (the entry
/// itself) is not created.
fn ensure_parent_dirs(sink: &mut impl ContentSink, path: &str) -> Result<()> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();
    for component in &components[..components.len().saturating_sub(1)] {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        sink.ensure_dir(&current, 0o755)?;
    }
    Ok(())
}

/// Build a determinate progress bar for `total` bytes of install work, using a
/// shared style that shows bytes, rate, and ETA. `prefix` is shown before the
/// bar (e.g. `"Writing image "` / `"Extracting "`).
///
/// The bar is anchored at a fixed column right after the constant `prefix`, and
/// all following fields have fixed widths, so the bar never shifts as the
/// message (filename) changes length. When `msg_width` is `Some(w)` a trailing
/// `{msg}` column of width `w` is reserved for the current entry name; callers
/// should pass messages through [`fit_message`] so they never overflow `w`.
fn install_progress_bar(total: u64, prefix: &str, msg_width: Option<usize>) -> ProgressBar {
    let pb = ProgressBar::new(total);
    let tmpl = match msg_width {
        Some(w) => format!(
            "    {prefix}[{{bar:30.cyan/blue}}] {{bytes:>10}}/{{total_bytes:>10}} \
             ({{bytes_per_sec:>12}}, ETA {{eta:>8}}) {{msg:<{w}}}",
        ),
        None => format!(
            "    {prefix}[{{bar:30.cyan/blue}}] {{bytes:>10}}/{{total_bytes:>10}} \
             ({{bytes_per_sec:>12}}, ETA {{eta:>8}})",
        ),
    };
    pb.set_style(
        ProgressStyle::with_template(&tmpl)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(250));
    pb
}

/// Render `s` left-aligned within `max` display columns, keeping the tail
/// (leading `…`) when it is too long. Used for progress-bar messages so their
/// column stays a constant width and the bar never shifts; keeping the tail
/// preserves the distinguishing filename end of long paths.
fn fit_message(s: &str, max: usize) -> String {
    let cols = s.chars().count();
    if cols <= max {
        return s.to_string();
    }
    let tail: String = s
        .chars()
        .rev()
        .take(max.saturating_sub(1))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

/// Width of the fixed progress-bar message column used for file extraction.
const PROGRESS_MSG_WIDTH: usize = 40;

/// Number of FAT sectors kept in the in-memory write-back cache when writing
/// into a FAT volume. Each cluster allocation scans the FAT entry by entry;
/// without a cache every lookup is a seek+read on the backing store, which
/// dominates install time for volumes with many files. This mirrors
/// `hadris_fat::cache::DEFAULT_CACHE_CAPACITY` but is sized larger so the
/// cache can absorb a burst of cluster allocations before a flush.
const FAT_CACHE_SECTORS: usize = 64;

/// When populating a FAT volume, file data is streamed to the FAT writer in
/// chunks of this size, flushing the FAT-sector cache after each chunk.
///
/// `hadris-fat`'s cache eviction is asymmetric: the write path can flush a
/// dirty sector on eviction, but the read path (used by the cluster
/// allocator's free-cluster scan) can only evict *clean* sectors and fails
/// with `CacheDirtyEviction` when every resident sector is dirty. Writing a
/// large file in one `FileWriter::write` call dirties one FAT sector per
/// `entries_per_sector` clusters (128 for FAT32/512B), so a file bigger than
/// `FAT_CACHE_SECTORS × 128 × cluster_size` would deadlock the allocator.
/// Chunking with a flush between chunks bounds the dirty sectors to a few,
/// leaving the read path plenty of clean entries to evict.
const FAT_WRITE_CHUNK: usize = 1024 * 1024;

/// Extract a zstd-compressed archive (cpio or tar) directly into `sink`,
/// writing every entry straight into the target filesystem — no temp directory
/// on the host. `total_bytes` is the archive's total uncompressed content size
/// (sum of regular-file lengths), taken from the manifest, so the progress bar
/// has an accurate total without a pre-scan pass.
fn extract_archive_into(
    archive: &Path,
    format: crate::model::config::ArchiveFormat,
    total_bytes: u64,
    sink: &mut impl ContentSink,
) -> Result<()> {
    let compressed = std::fs::File::open(archive)?;
    let decoder = zstd::Decoder::new(compressed).map_err(|e| Error::msg(format!("zstd: {e}")))?;
    let pb = install_progress_bar(total_bytes, "Extracting ", Some(PROGRESS_MSG_WIDTH));
    let result = match format {
        crate::model::config::ArchiveFormat::Cpio => extract_cpio_into(decoder, sink, &pb),
        crate::model::config::ArchiveFormat::Tar => extract_tar_into(decoder, sink, &pb),
    };
    if result.is_err() {
        pb.abandon_with_message("failed");
    } else {
        pb.finish_with_message("done".to_string());
    }
    result
}

fn extract_cpio_into<R: Read>(
    reader: R,
    sink: &mut impl ContentSink,
    pb: &ProgressBar,
) -> Result<()> {
    let mut cr = hadris_cpio::CpioArchiveReader::new(reader);
    let mut index = 0u64;
    while let Some(entry) = cr.next_entry_alloc().map_err(map_cpio_err)? {
        let name = entry
            .name_str()
            .map_err(|e| Error::msg(e.to_string()))?
            .to_string();
        let path = match normalize_archive_path(&name) {
            Some(p) => p,
            None => continue,
        };
        let mode = entry.header().permissions() as u16;
        let data = cr.read_entry_data_alloc(&entry).map_err(map_cpio_err)?;

        use hadris_cpio::FileType;
        match entry.file_type() {
            FileType::Directory => {
                ensure_parent_dirs(sink, &path)?;
                sink.ensure_dir(&path, mode)?;
            }
            FileType::Symlink => {
                let target = String::from_utf8(data).map_err(|e| Error::msg(e.to_string()))?;
                ensure_parent_dirs(sink, &path)?;
                sink.write_symlink(&path, &target)?;
            }
            FileType::Regular => {
                index += 1;
                pb.set_message(fit_message(&format!("#{index} {path}"), PROGRESS_MSG_WIDTH));
                ensure_parent_dirs(sink, &path)?;
                sink.write_file(&path, mode, &data)?;
                pb.inc(data.len() as u64);
            }
            FileType::BlockDevice | FileType::CharDevice => {
                let major = entry.header().rdevmajor;
                let minor = entry.header().rdevminor;
                ensure_parent_dirs(sink, &path)?;
                sink.write_device(&path, mode, major, minor)?;
            }
            _ => {
                // Skip unsupported entry types (sockets, fifos, unknown).
            }
        }
    }
    Ok(())
}

fn extract_tar_into<R: Read>(
    reader: R,
    sink: &mut impl ContentSink,
    pb: &ProgressBar,
) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut index = 0u64;
    for entry in archive
        .entries()
        .map_err(|e| Error::msg(format!("tar: {e}")))?
    {
        let mut entry = entry.map_err(|e| Error::msg(format!("tar: {e}")))?;
        // Read the PAX records before borrowing the header: local extensions
        // are attached by the tar reader to the entry that follows them.
        let xattrs = crate::archive::tar_pax_xattrs(&mut entry)?;
        let header = entry.header();
        let entry_type = header.entry_type();

        // Skip metadata / extension entries.
        if entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            continue;
        }

        let raw_path = header.path().map_err(|e| Error::msg(format!("tar: {e}")))?;
        let path = match normalize_archive_path(&raw_path.to_string_lossy()) {
            Some(p) => p,
            None => continue,
        };

        let mode = (header.mode().map_err(|e| Error::msg(format!("tar: {e}")))? & 0o7777) as u16;

        let mut wrote_entry = false;
        match entry_type {
            tar::EntryType::Directory => {
                ensure_parent_dirs(sink, &path)?;
                sink.ensure_dir(&path, mode)?;
                wrote_entry = true;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|e| Error::msg(format!("tar: {e}")))?;
                index += 1;
                pb.set_message(fit_message(&format!("#{index} {path}"), PROGRESS_MSG_WIDTH));
                ensure_parent_dirs(sink, &path)?;
                sink.write_file(&path, mode, &data)?;
                pb.inc(data.len() as u64);
                wrote_entry = true;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| Error::msg(format!("tar: {e}")))?
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                ensure_parent_dirs(sink, &path)?;
                sink.write_symlink(&path, &target)?;
                wrote_entry = true;
            }
            tar::EntryType::Char | tar::EntryType::Block => {
                let major = header
                    .device_major()
                    .map_err(|e| Error::msg(format!("tar: {e}")))?
                    .unwrap_or(0);
                let minor = header
                    .device_minor()
                    .map_err(|e| Error::msg(format!("tar: {e}")))?
                    .unwrap_or(0);
                ensure_parent_dirs(sink, &path)?;
                sink.write_device(&path, mode, major, minor)?;
                wrote_entry = true;
            }
            _ => {
                // Skip unsupported entry types (hard links, fifos, etc.).
            }
        }
        if wrote_entry {
            for (name, value) in &xattrs {
                sink.set_xattr(&path, name, value)?;
            }
        }
    }
    Ok(())
}

/// Write an in-memory [`TreeNode`] directly into a filesystem via a
/// [`ContentSink`], skipping the compress/decompress archive round-trip. This
/// is used by build-time block rendering (`build_block_artifact`) where the
/// tree is already in memory.
fn write_tree_into(root: &crate::archive::TreeNode, sink: &mut impl ContentSink) -> Result<()> {
    // The root node itself is the top-level directory entry (e.g. "."). Its
    // children are the top-level filesystem entries; we write them with an
    // empty prefix so they land at the filesystem root.
    match root {
        crate::archive::TreeNode::Dir { children, .. } => {
            for (name, child) in children {
                write_tree_entry(name, child, sink)?;
            }
        }
        _ => {
            // A non-directory root is unusual but write it at the root level.
            write_tree_entry("", root, sink)?;
        }
    }
    Ok(())
}

/// Recursively write a tree entry at the given path.
fn write_tree_entry(
    path: &str,
    node: &crate::archive::TreeNode,
    sink: &mut impl ContentSink,
) -> Result<()> {
    let meta = match node {
        crate::archive::TreeNode::Dir { meta, .. }
        | crate::archive::TreeNode::File { meta, .. }
        | crate::archive::TreeNode::Symlink { meta, .. }
        | crate::archive::TreeNode::Device { meta, .. }
        | crate::archive::TreeNode::Fifo { meta, .. } => meta,
    };
    let mode = meta.perms as u16;
    match node {
        crate::archive::TreeNode::Dir { children, .. } => {
            if !path.is_empty() {
                sink.ensure_dir(path, mode)?;
            }
            for (name, child) in children {
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                write_tree_entry(&child_path, child, sink)?;
            }
        }
        crate::archive::TreeNode::File { content, .. } => {
            ensure_parent_dirs(sink, path)?;
            sink.write_file(path, mode, content)?;
        }
        crate::archive::TreeNode::Symlink { target, .. } => {
            ensure_parent_dirs(sink, path)?;
            sink.write_symlink(path, target)?;
        }
        crate::archive::TreeNode::Device {
            dev_type,
            major,
            minor,
            ..
        } => {
            ensure_parent_dirs(sink, path)?;
            sink.write_device(path, mode, *major, *minor)?;
            // dev_type is available for future use (char vs block); the sink
            // handles both via the same `write_device` method.
            let _ = dev_type;
        }
        crate::archive::TreeNode::Fifo { .. } => {
            // FIFOs are skipped — the ContentSink trait has no fifo method.
            return Ok(());
        }
    }
    for (name, value) in &meta.xattrs {
        sink.set_xattr(path, name, value)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Disk / region helpers
// ---------------------------------------------------------------------------// ---------------------------------------------------------------------------
// Disk / region helpers
// ---------------------------------------------------------------------------

/// Build a fresh GPT disk layout (table + per-partition offset/size) for a
/// region of `region_size` bytes. Shared by the fresh install and the fresh
/// branch of the reconcile planner.
fn compute_gpt_layout(
    block: &ManifestBlockGpt,
    region_size: u64,
) -> Result<(GptDisk, Vec<(u64, u64)>)> {
    let disk_sectors = region_size / GPT_SECTOR_SIZE;
    let mut gpt = GptDisk::new(disk_sectors, GPT_SECTOR_SIZE as u32);
    if let Some(guid) = &block.guid {
        gpt.primary_header.disk_guid = guid.to_hadris();
        gpt.backup_header.disk_guid = guid.to_hadris();
    }

    let first_usable = gpt.primary_header.first_usable_lba.to_ne();
    let last_usable = gpt.primary_header.last_usable_lba.to_ne();
    let usable_sectors = last_usable - first_usable + 1;
    let usable_size = usable_sectors * GPT_SECTOR_SIZE;

    let mut size_entries: Vec<ManifestPartitionSize> =
        block.partitions.iter().map(|p| p.size.clone()).collect();
    if let Some(empty) = &block.empty_space {
        size_entries.push(empty.clone());
    }
    let computed = compute_partition_sizes(&size_entries, usable_size, BLOCK_SIZE)?;
    let partition_sizes = &computed[..block.partitions.len()];

    let mut current_lba = first_usable;
    let mut placed = Vec::with_capacity(block.partitions.len());
    for (i, partition) in block.partitions.iter().enumerate() {
        let psize = partition_sizes[i];
        let sector_count = psize / GPT_SECTOR_SIZE;
        let first_lba = current_lba;
        let last_lba = first_lba + sector_count - 1;
        let type_guid = partition.type_guid.to_hadris();
        let unique_guid = match &partition.guid {
            Some(g) => g.to_hadris(),
            None => Guid::generate_v4(),
        };
        let mut entry = GptPartitionEntry::new(type_guid, unique_guid, first_lba, last_lba);
        entry.set_name_ascii(partition.name.as_bytes());
        gpt.add_partition(entry).map_err(map_part_err)?;
        current_lba = last_lba + 1;
        placed.push((first_lba * GPT_SECTOR_SIZE, psize));
    }
    gpt.update_crcs();
    Ok((gpt, placed))
}

/// Compute an MBR layout: place partitions starting at `MBR_FIRST_USABLE_LBA`,
/// aligned to `BLOCK_SIZE`. Returns the built `MasterBootRecord` and a vec of
/// `(offset_bytes, size_bytes)` per manifest partition.
fn compute_mbr_layout(
    block: &ManifestBlockMbr,
    region_size: u64,
) -> Result<(MasterBootRecord, Vec<(u64, u64)>)> {
    if block.partitions.len() > 4 {
        return Err(Error::msg(format!(
            "MBR supports at most 4 primary partitions; {} requested",
            block.partitions.len()
        )));
    }
    let disk_sectors = region_size / MBR_SECTOR_SIZE;
    let first_usable = MBR_FIRST_USABLE_LBA;
    let last_usable = disk_sectors - 1;
    let usable_sectors = last_usable + 1 - first_usable;
    let usable_size = usable_sectors * MBR_SECTOR_SIZE;

    let mut size_entries: Vec<ManifestPartitionSize> =
        block.partitions.iter().map(|p| p.size.clone()).collect();
    if let Some(empty) = &block.empty_space {
        size_entries.push(empty.clone());
    }
    let computed = compute_partition_sizes(&size_entries, usable_size, BLOCK_SIZE)?;
    let partition_sizes = &computed[..block.partitions.len()];

    let mut mbr = MasterBootRecord::default();
    let mut current_lba = first_usable;
    let mut placed = Vec::with_capacity(block.partitions.len());
    mbr.with_partition_table(|table| {
        for (i, partition) in block.partitions.iter().enumerate() {
            let psize = partition_sizes[i];
            let sector_count = psize / MBR_SECTOR_SIZE;
            let start_lba = current_lba;
            let part_type = MbrPartitionType::from_u8(partition.type_code);
            let mut mpart = MbrPartition::new(part_type, start_lba as u32, sector_count as u32);
            mpart.boot_indicator = if partition.bootable { 0x80 } else { 0x00 };
            table.partitions[i] = mpart;
            placed.push((start_lba * MBR_SECTOR_SIZE, psize));
            current_lba = start_lba + sector_count;
        }
    });
    Ok((mbr, placed))
}

pub(crate) fn compute_min_disk_size(block: &ManifestBlock) -> u64 {
    match block {
        ManifestBlock::Gpt(b) => {
            let entry_sectors = 32u64; // 128 entries * 128 bytes / 512
            let overhead = 3 + 2 * entry_sectors; // MBR + header + entries (primary + backup)
            let usable_min: u64 = b
                .partitions
                .iter()
                .map(|p| align_size(p.size.size_min, BLOCK_SIZE))
                .sum::<u64>()
                + b.empty_space
                    .as_ref()
                    .map(|e| align_size(e.size_min, BLOCK_SIZE))
                    .unwrap_or(0);
            (usable_min / GPT_SECTOR_SIZE + overhead) * GPT_SECTOR_SIZE
        }
        ManifestBlock::Mbr(b) => {
            // MBR overhead: 1 sector for the MBR itself + first_usable_lba - 1
            // padding (partitions start at MBR_FIRST_USABLE_LBA).
            let overhead_sectors = MBR_FIRST_USABLE_LBA;
            let usable_min: u64 = b
                .partitions
                .iter()
                .map(|p| align_size(p.size.size_min, BLOCK_SIZE))
                .sum::<u64>()
                + b.empty_space
                    .as_ref()
                    .map(|e| align_size(e.size_min, BLOCK_SIZE))
                    .unwrap_or(0);
            (usable_min / MBR_SECTOR_SIZE + overhead_sectors) * MBR_SECTOR_SIZE
        }
        other => align_size(block_min(other), BLOCK_SIZE),
    }
}

fn block_min(b: &ManifestBlock) -> u64 {
    match b {
        ManifestBlock::Gpt(x) => x.size_min,
        ManifestBlock::Mbr(x) => x.size_min,
        ManifestBlock::Ext4(x) | ManifestBlock::Fat(x) => x.size_min,
        ManifestBlock::Luks(x) => x.size_min,
        ManifestBlock::Lvm(x) => x.size_min,
        ManifestBlock::Image(x) => x.size_min,
    }
}

/// Resolve the size of the target disk and whether it was freshly created by
/// us (did not exist, or was an empty zero-byte file). A block device is never
/// considered fresh — we cannot know its provenance, so `--wipe` is still
/// required to install onto an unrecognised block device without reconciliation.
fn resolve_disk_size(target: &Path, min_size: u64) -> Result<(u64, bool)> {
    match std::fs::metadata(target) {
        Ok(info) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if info.file_type().is_block_device() {
                    let out = exec::exec(&["blockdev", "--getsize64", &target.to_string_lossy()])?;
                    return Ok((out.trim().parse::<u64>().unwrap_or(min_size), false));
                }
            }
            if info.len() == 0 {
                truncate_file(target, min_size)?;
                Ok((min_size, true))
            } else {
                Ok((info.len(), false))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_sparse_file(target, min_size)?;
            Ok((min_size, true))
        }
        Err(e) => Err(Error::from(e)),
    }
}

fn create_sparse_file(path: &Path, size: u64) -> Result<()> {
    let f = std::fs::File::create(path)?;
    drop(f);
    truncate_file(path, size)
}

fn truncate_file(path: &Path, size: u64) -> Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(size)?;
    Ok(())
}

/// True if the region begins with a valid MBR boot signature (0x55AA at offset 510).
fn has_mbr<R: BlockRegion>(region: &R) -> Result<bool> {
    let mut r = region.clone();
    let _ = r.seek(SeekFrom::Start(510));
    let mut sig = [0u8; 2];
    match r.read_exact(&mut sig) {
        Ok(()) => Ok(sig == [0x55, 0xAA]),
        Err(_) => Ok(false),
    }
}

/// True if the region begins with a GPT signature (LBA 1, "EFI PART").
fn has_gpt<R: BlockRegion>(region: &R) -> Result<bool> {
    let mut r = region.clone();
    let _ = r.seek(SeekFrom::Start(GPT_SECTOR_SIZE));
    let mut sig = [0u8; 8];
    match r.read_exact(&mut sig) {
        Ok(()) => Ok(&sig == b"EFI PART"),
        Err(_) => Ok(false),
    }
}

/// Decode a GPT partition entry's UTF-16LE name (up to the first NUL).
pub(crate) fn gpt_name_string(entry: &GptPartitionEntry) -> String {
    let u16s = entry.name.as_u16_slice();
    let len = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
    String::from_utf16_lossy(&u16s[..len])
}

/// Number of chunks `copy_into_region` reads before handing them to the region
/// as one batch. A pipelining backend (NBD) sends all of them before waiting,
/// so this bounds in-flight bytes and hides up to `DEPTH - 1` link round-trips
/// per batch; a local backend just writes them one after another as before.
const COPY_PIPELINE_DEPTH: usize = 16;

/// Copy `size` bytes from `src` into `region`, starting at the region's
/// cursor (seeked to 0). Used to install raw image blocks.
fn copy_into_region<R: BlockRegion>(
    region: &mut R,
    src: &mut dyn Read,
    size: u64,
    label: &str,
) -> Result<()> {
    region.seek(SeekFrom::Start(0))?;
    let pb = install_progress_bar(size, &format!("{label} "), None);
    let chunk = 1024 * 1024usize;
    // One reusable buffer per in-flight chunk; `lens[i]` is how many bytes the
    // last read put in `bufs[i]` (a short read is possible).
    let mut bufs: Vec<Vec<u8>> = (0..COPY_PIPELINE_DEPTH).map(|_| vec![0u8; chunk]).collect();
    let mut lens: Vec<usize> = vec![0; COPY_PIPELINE_DEPTH];
    let mut written = 0u64;
    while written < size {
        let mut n = 0usize;
        while n < COPY_PIPELINE_DEPTH && written < size {
            let to_read = std::cmp::min(chunk as u64, size - written) as usize;
            let got = src.read(&mut bufs[n][..to_read])?;
            if got == 0 {
                break;
            }
            lens[n] = got;
            written += got as u64;
            n += 1;
        }
        if n == 0 {
            break;
        }
        let refs: Vec<&[u8]> = (0..n).map(|i| &bufs[i][..lens[i]]).collect();
        // Report each chunk as its reply arrives, so the bar's rate reflects
        // bytes actually landing instead of stalling between whole batches.
        region.write_chunks_progress(&refs, &mut |done| pb.inc(done))?;
    }
    pb.finish();
    Ok(())
}

pub(crate) fn resolve_manifest_file(ctx: &InstallContext, hash_file_name: &str) -> Result<PathBuf> {
    // Build-time block rendering resolves content straight from the build
    // context's temp files, before they are materialized in the output dir.
    if let Some(resolver) = &ctx.file_resolver {
        return resolver(hash_file_name);
    }
    let info = ctx.manifest.file.get(hash_file_name).ok_or_else(|| {
        Error::msg(format!(
            "Manifest has no file entry for \"{hash_file_name}\""
        ))
    })?;
    let file = ctx.manifest_directory.join(hash_file_name);
    let digest = crate::hash::hash_file(&file)?;
    if hex::encode(&digest) != info.hash {
        return Err(Error::msg(format!(
            "Hash mismatch for {hash_file_name}: expected {}, got {}",
            info.hash,
            hex::encode(&digest)
        )));
    }
    Ok(file)
}

/// Resolve and hash-verify a filesystem archive's backing file.
pub(crate) fn resolve_archive(ctx: &InstallContext, archive: &ManifestArchive) -> Result<PathBuf> {
    resolve_manifest_file(ctx, &archive.file)
}

/// Write bootcode into the first sector's bootstrap area (bytes 0..446) of the
/// region, preserving the partition table (446..510) and boot signature
/// (510..512). The bootcode bytes are zero-padded up to 446 bytes. The existing
/// first sector is read back so the partition table and signature are kept
/// intact — this works both on a freshly written table and on a reconciled one
/// that was left untouched.
fn write_bootcode<R: BlockRegion>(
    ctx: &InstallContext,
    bootcode_file: &str,
    region: &mut R,
) -> Result<()> {
    let source = resolve_manifest_file(ctx, bootcode_file)?;
    let mut bytes = std::fs::read(&source)?;
    if bytes.len() > 446 {
        bytes.truncate(446);
    }
    eprintln!(
        "    Bootcode: writing {} bytes to first sector bootstrap area...",
        bytes.len()
    );
    let mut sector = [0u8; 512];
    region.seek(SeekFrom::Start(0))?;
    // Best-effort read: a freshly created region may be shorter than 512 bytes
    // before the table is written, but the table write above always lands a
    // full first sector. Ignore a short read and fall back to zeros.
    let _ = region.read(&mut sector);
    // Zero the bootstrap area, then copy the (zero-padded) bootcode in.
    for b in &mut sector[..446] {
        *b = 0;
    }
    sector[..bytes.len()].copy_from_slice(&bytes);
    region.seek(SeekFrom::Start(0))?;
    region.write_all(&sector)?;
    Ok(())
}

fn map_part_err(e: hadris_part::error::Error) -> Error {
    Error::msg(format!("gpt: {e}"))
}
fn map_ext4_err(e: fs_ext4::error::Error) -> Error {
    Error::msg(format!("ext4: {e}"))
}
fn map_fat_err(e: hadris_fat::error::Error) -> Error {
    Error::msg(format!("fat: {e}"))
}
fn map_cpio_err(e: hadris_cpio::Error) -> Error {
    Error::msg(format!("cpio: {e}"))
}
