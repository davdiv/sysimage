//! Config-block → manifest-block conversion.

use base64::Engine;

use super::BuildContext;
use crate::config::parse_mbr_type;
use crate::error::{Error, Result};
use crate::install::{BLOCK_SIZE, GPT_SECTOR_SIZE, MBR_FIRST_USABLE_LBA, MBR_SECTOR_SIZE};
use crate::model::config::{
    ConfigBlock, ConfigBlockFs, ConfigBlockGpt, ConfigBlockImage, ConfigBlockLuks, ConfigBlockLvm,
    ConfigBlockMbr, ConfigGptPartition, ConfigLvmPartition, ConfigMbrPartition,
    ConfigPartitionSize, ConfigPartitionType, KnownGptPartitionType,
};
use crate::model::manifest::{
    ManifestBlock, ManifestBlockFs, ManifestBlockGpt, ManifestBlockImage, ManifestBlockLuks,
    ManifestBlockLvm, ManifestBlockMbr, ManifestGptPartition, ManifestHybridMbr,
    ManifestLvmPartition, ManifestLvmVg, ManifestMbrPartition, ManifestMirroredPartition,
    ManifestPartitionSize,
};
use crate::model::shared::Guid;
use crate::size::{align_size, size_to_bytes, to_manifest_partition_size};

/// LVM physical extent size (4 MiB) and first-PE offset (1 MiB), matching
/// the LVM2 on-disk defaults.
const LVM_DEFAULT_PE_SIZE: u64 = 4 * 1024 * 1024;
const LVM_DEFAULT_PE_START: u64 = 1024 * 1024;

/// Resolve a [`ConfigPartitionType`] (a well-known alias or an explicit GUID)
/// into the binary [`Guid`] stored in the manifest.
pub fn resolve_gpt_partition_type(t: &ConfigPartitionType) -> Guid {
    match t {
        ConfigPartitionType::Guid(g) => *g,
        ConfigPartitionType::Named(n) => match n {
            KnownGptPartitionType::Efi => Guid::EFI_SYSTEM,
            KnownGptPartitionType::Linux => Guid::LINUX_FILESYSTEM,
            KnownGptPartitionType::Swap => Guid::LINUX_SWAP,
            KnownGptPartitionType::Lvm => Guid::LINUX_LVM,
            KnownGptPartitionType::Raid => Guid::LINUX_RAID,
            KnownGptPartitionType::Luks => Guid::LINUX_LUKS,
        },
    }
}

/// Convert a config block into a manifest block, computing `sizeMin`
/// recursively over nested content.
///
/// The partition type GUID (e.g. EFI System Partition) has **no** influence on
/// how the content is processed — neither at build time (size computation) nor
/// at install time (filesystem formatting). A FAT block is always treated the
/// same regardless of which partition it ends up in.
pub fn process_block(ctx: &BuildContext, block: &ConfigBlock) -> Result<ManifestBlock> {
    Ok(match block {
        ConfigBlock::Gpt(b) => ManifestBlock::Gpt(process_gpt(ctx, b)?),
        ConfigBlock::Mbr(b) => ManifestBlock::Mbr(process_mbr(ctx, b)?),
        ConfigBlock::Ext4(b) => ManifestBlock::Ext4(process_fs(ctx, b, false)?),
        ConfigBlock::Fat(b) => ManifestBlock::Fat(process_fs(ctx, b, true)?),
        ConfigBlock::Luks(b) => ManifestBlock::Luks(process_luks(ctx, b)?),
        ConfigBlock::Lvm(b) => ManifestBlock::Lvm(process_lvm_block(ctx, b)?),
        ConfigBlock::Image(b) => ManifestBlock::Image(process_image(ctx, b)?),
    })
}

fn process_fs(ctx: &BuildContext, block: &ConfigBlockFs, is_fat: bool) -> Result<ManifestBlockFs> {
    // Default block size: 4096 for ext4, 512 (one sector) for FAT. For FAT the
    // cluster size is auto-selected by the formatter when `block_size` is
    // `None`; 512 is used only for the on-disk size approximation.
    let block_size = block.block_size.unwrap_or(if is_fat { 512 } else { 4096 }) as u64;

    let mut archive_file = None;
    let mut tree_key = None;
    let mut content_size: u64 = 0;
    let mut content_size_on_disk: u64 = 0;
    let mut file_count: u64 = 0;
    let mut dir_count: u64 = 0;

    if let Some(files) = &block.files {
        let mut format = block
            .archive_format
            .or(ctx.config.cpio.format)
            .unwrap_or(crate::model::config::ArchiveFormat::Cpio);
        let level = ctx.config.cpio.compression_level;

        // Resolve inputs (build: dispatch, ${VAR} substitution) and collect the
        // file tree once — used both for size measurement and archive/tree output.
        let resolved = super::artifacts::resolve_files_set(ctx, files)?;
        let root = crate::archive::collect_tree(&resolved)?;

        // CPIO's newc format cannot carry extended attributes. When the tree
        // has any and the format was only defaulted, use tar (whose PAX records
        // do) so a filesystem install does not silently lose them. An explicit
        // cpio request is still honoured, with a warning.
        if !ctx.is_build_time_render()
            && format == crate::model::config::ArchiveFormat::Cpio
            && crate::archive::tree_has_xattrs(&root)
        {
            if block.archive_format.is_some() || ctx.config.cpio.format.is_some() {
                eprintln!(
                    "warning: cpio cannot represent extended attributes; \
                     xattrs will be lost (use archiveFormat: tar to preserve them)"
                );
            } else {
                eprintln!(
                    "note: filesystem content has extended attributes; \
                     using tar instead of cpio so they are preserved"
                );
                format = crate::model::config::ArchiveFormat::Tar;
            }
        }

        let sizes = crate::archive::compute_sizes_from_tree(&root, block_size);
        content_size = sizes.total_size;
        content_size_on_disk = sizes.size_on_disk;
        file_count = sizes.file_count;
        dir_count = sizes.dir_count;

        if ctx.is_build_time_render() {
            // Build-time mini-install: store the in-memory tree and skip the
            // compress/decompress round-trip. The tree is written directly
            // into the filesystem at install time via `tree_resolver`.
            tree_key = Some(ctx.store_tree(root));
        } else {
            let temp = ctx.create_temp_file();
            crate::archive::build_archive_from_tree(&root, format, &temp, level)?;
            let entry = ctx.add_output_file(&temp)?;
            archive_file = Some(crate::model::manifest::ManifestArchive {
                file: entry.hash_file_name,
                format,
                size: content_size,
                size_on_disk: content_size_on_disk,
            });
        }
    }

    let empty = match &block.empty_space {
        Some(s) => size_to_bytes(s)?,
        None => 0,
    };

    let size_min = if is_fat {
        // A FAT volume needs room for its own metadata (reserved sectors, FAT
        // tables, root directory) in addition to the file content. The overhead
        // — and even the FAT type / cluster size — depends on the volume size
        // itself, so it is solved iteratively (see [`fat_min_size`]). The FAT
        // type is auto-selected by the formatter; the partition type GUID has
        // no influence here.
        fat_min_size(
            empty + content_size,
            file_count,
            dir_count,
            block.block_size,
            block.fat_version.unwrap_or_default(),
        )
    } else {
        // ext4: the content occupies `size_on_disk` bytes of data blocks, plus
        // the empty-space reserve, plus the filesystem's own metadata overhead
        // (superblock + backups, block-group descriptors, block/inode bitmaps,
        // inode table, root directory). Without that overhead an empty ext4
        // (no files, no emptySpace) would compute sizeMin = 0 and fail to
        // format at install time. [`ext4_min_size`] mirrors the geometry used
        // by `rust-fs-ext4::mkfs::format_block_groups` and solves iteratively
        // because the metadata grows with the number of block groups.
        ext4_min_size(empty + content_size_on_disk, block_size)
    };

    Ok(ManifestBlockFs {
        size_min,
        archive: archive_file,
        tree_key,
        block_size: block.block_size,
        fat_version: block.fat_version,
    })
}

/// Minimum size (in bytes) of a FAT volume able to hold `data_size` bytes of
/// file content, including the filesystem metadata overhead (reserved
/// sectors, FAT tables, root directory).
///
/// This mirrors the options used at install time by `format_fat`: 512-byte
/// sectors, two FAT copies, auto FAT-type selection. When `block_size` is
/// given it is used as the cluster size (via `sectors_per_cluster`); otherwise
/// the cluster size is auto-selected by the formatter.
///
/// Because the metadata overhead — and even the FAT type / cluster size —
/// depends on the volume size, the result is found by iterating to a fixed
/// point with `hadris_fat::format::calculate_params`.
pub(crate) fn fat_min_size(
    data_size: u64,
    file_count: u64,
    dir_count: u64,
    block_size: Option<u32>,
    fat_version: crate::model::config::FatVersion,
) -> u64 {
    use hadris_fat::format::{FatFormatOptions, FatVolumeFormatter, SectorSize};

    const SECTOR_SIZE: u64 = 512;
    const MIN_VOLUME: u64 = 1024 * 512; // smallest valid FAT12 volume

    let mut volume = std::cmp::max(data_size, MIN_VOLUME);
    volume = crate::size::align_size(volume, SECTOR_SIZE);

    let spc = block_size.map(|bs| (bs as u64 / SECTOR_SIZE) as u8);
    let fat_type = fat_version.to_fat_type_selection();

    for _ in 0..64 {
        let mut opts = FatFormatOptions::new(volume)
            .sector_size(SectorSize::S512)
            .fat_type(fat_type);
        if let Some(s) = spc {
            opts = opts.sectors_per_cluster(s);
        }
        let params = match FatVolumeFormatter::calculate_params(&opts) {
            Ok(p) => p,
            Err(_) => {
                // The current volume is too small or has an invalid cluster
                // count for the auto-selected FAT type. Grow by at least 1 MiB
                // or 25 % of the current volume, whichever is larger, so the
                // search converges quickly even when the minimum is far above
                // the starting point.
                volume += std::cmp::max(1024 * 1024, volume / 4);
                continue;
            }
        };
        let overhead = params.data_start_sector as u64 * SECTOR_SIZE;
        let cluster_size = params.sectors_per_cluster as u64 * SECTOR_SIZE;
        // The content occupies one cluster per file/directory (each entry's
        // data is allocated in whole clusters), plus the data bytes themselves.
        // `data_size.div_ceil(cluster_size)` treats the data as one contiguous
        // blob; adding `file_count + dir_count` accounts for the per-entry
        // cluster overhead (each file and directory takes at least one cluster,
        // and per-file rounding can waste up to one cluster per file).
        let data_clusters = data_size.div_ceil(cluster_size) + file_count + dir_count;
        let needed = overhead + data_clusters * cluster_size;
        if needed <= volume {
            return volume;
        }
        volume = needed;
    }
    volume
}

/// Minimum size (in bytes) of an ext4 filesystem able to hold `data_size`
/// bytes of file content, including the filesystem's own metadata overhead.
///
/// This mirrors the geometry used at install time by
/// `rust-fs-ext4::mkfs::format_block_groups` (the ext4 path, `block_size >=
/// 2048`): 8192 inodes per group, 256-byte inodes, 64-byte group descriptors,
/// `blocks_per_group = 8 * block_size`, and sparse superblock backups (groups
/// 0, 1, and powers of 3/5/7). Each group contributes a superblock backup +
/// GDT copy (when it hosts a backup), a block bitmap, an inode bitmap, an
/// inode table, and group 0 additionally contributes the root directory.
///
/// Because the number of block groups — and thus the GDT size and the count of
/// superblock backups — depends on the total size, the result is found by
/// iterating to a fixed point: grow the device by the metadata overhead, which
/// may push it into another group, until the block count stabilises.
fn ext4_min_size(data_size: u64, block_size: u64) -> u64 {
    const INODES_PER_GROUP: u64 = 8192;
    const INODE_SIZE: u64 = 256; // ext4
    const DESC_SIZE: u64 = 64; // ext4 64-bit block group descriptors
    const MIN_BLOCKS: u64 = 64; // formatter hard minimum (size_bytes / block_size)

    let bpg = 8 * block_size; // blocks per group
    let inode_table_blocks = (INODES_PER_GROUP * INODE_SIZE).div_ceil(block_size);
    let data_blocks = data_size.div_ceil(block_size);

    let mut blocks = std::cmp::max(data_blocks, MIN_BLOCKS);
    for _ in 0..64 {
        let group_count = blocks.div_ceil(bpg).max(1);
        let gdt_blocks = (group_count * DESC_SIZE).div_ceil(block_size);
        let mut overhead: u64 = 0;
        for g in 0..group_count {
            let group_meta = if group_has_super(g) {
                1 + gdt_blocks
            } else {
                0
            };
            // super/backup + GDT + block bitmap + inode bitmap + inode table;
            // group 0 also reserves the root-directory block.
            overhead += group_meta + 2 + inode_table_blocks + u64::from(g == 0);
        }
        let need = std::cmp::max(data_blocks + overhead, MIN_BLOCKS);
        if need == blocks {
            return need * block_size;
        }
        blocks = need;
    }
    blocks * block_size
}

/// Mirror of `rust-fs-ext4::mkfs::group_has_super`: a group hosts a superblock
/// backup when it is 0, 1, or an exact power of 3, 5 or 7.
fn group_has_super(g: u64) -> bool {
    fn is_power_of(mut g: u64, base: u64) -> bool {
        while g.is_multiple_of(base) {
            g /= base;
        }
        g == 1
    }
    g <= 1 || is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7)
}

fn process_gpt(ctx: &BuildContext, block: &ConfigBlockGpt) -> Result<ManifestBlockGpt> {
    let (partitions, empty_space, _) =
        process_partitions(ctx, &block.partitions, &block.empty_space, 0, |p, base| {
            // partitionManifest for GPT: { type, name, ...manifest }
            let name = replace_partition_name_vars(ctx, p.name.as_str(), p.content.as_deref());
            ManifestGptPartition {
                size: base.size,
                content: base.content,
                name,
                type_guid: resolve_gpt_partition_type(&p.type_guid),
                guid: p.guid,
            }
        })?;
    // GPT table overhead: protective MBR (1 sector) + primary header (1) +
    // primary entries (32) + backup entries (32) + backup header (1) = 67
    // sectors. sizeMin must include this so a nested GPT (whose containing
    // partition is sized from this sizeMin) can actually fit its own tables.
    let usable_min: u64 = partitions
        .iter()
        .map(|p| align_size(p.size.size_min, BLOCK_SIZE))
        .sum::<u64>()
        + empty_space
            .as_ref()
            .map(|e| align_size(e.size_min, BLOCK_SIZE))
            .unwrap_or(0);
    let size_min = table_size_min(usable_min, GPT_SECTOR_SIZE, 3 + 2 * 32);
    // When an `mbr` block is present, the GPT is a hybrid GPT: validate the
    // hybrid-MBR configuration and resolve it into the manifest form.
    let mbr = match &block.mbr {
        Some(cfg) => Some(process_hybrid_mbr(cfg, &block.partitions)?),
        None => None,
    };
    let bootcode = process_bootcode(ctx, &block.bootcode)?;
    Ok(ManifestBlockGpt {
        partitions,
        empty_space,
        size_min,
        guid: block.guid,
        mbr,
        bootcode,
    })
}

/// Validate a hybrid-MBR configuration against the GPT partitions and convert
/// it into the manifest form (parsed MBR type codes, resolved protective slot).
fn process_hybrid_mbr(
    cfg: &crate::model::config::ConfigHybridMbr,
    partitions: &[ConfigGptPartition],
) -> Result<ManifestHybridMbr> {
    if cfg.mirrored.len() > 3 {
        return Err(Error::msg(format!(
            "Hybrid MBR mirrors at most 3 partitions, but {} were specified",
            cfg.mirrored.len()
        )));
    }
    let names: std::collections::HashSet<&String> = partitions.iter().map(|p| &p.name).collect();
    let mut mirrored = Vec::with_capacity(cfg.mirrored.len());
    for m in &cfg.mirrored {
        if !names.contains(&m.partition) {
            return Err(Error::msg(format!(
                "Hybrid MBR mirror references unknown GPT partition \"{}\"",
                m.partition
            )));
        }
        let type_code = m.type_code.resolve()?;
        if type_code == 0xEE {
            return Err(Error::msg(
                "Hybrid MBR mirror type 0xEE (protective) is reserved for the protective entry",
            ));
        }
        mirrored.push(ManifestMirroredPartition {
            partition: m.partition.clone(),
            type_code,
            bootable: m.bootable,
        });
    }
    let protective_slot = cfg.protective_slot.unwrap_or(0);
    if protective_slot > 3 {
        return Err(Error::msg(format!(
            "Hybrid MBR protective slot must be 0-3, got {protective_slot}"
        )));
    }
    Ok(ManifestHybridMbr {
        protective_slot,
        mirrored,
    })
}

fn process_mbr(ctx: &BuildContext, block: &ConfigBlockMbr) -> Result<ManifestBlockMbr> {
    if block.partitions.len() > 4 {
        return Err(Error::msg(format!(
            "MBR supports at most 4 primary partitions, but {} were specified",
            block.partitions.len()
        )));
    }
    // Parse the MBR type codes up front (the per-partition closure is infallible).
    let type_codes: Vec<u8> = block
        .partitions
        .iter()
        .map(|p| parse_mbr_type(&p.type_code))
        .collect::<Result<Vec<u8>>>()?;
    let idx = std::cell::Cell::new(0usize);
    let (partitions, empty_space, _) =
        process_partitions(ctx, &block.partitions, &block.empty_space, 0, |p, base| {
            let i = idx.get();
            idx.set(i + 1);
            ManifestMbrPartition {
                size: base.size,
                content: base.content,
                type_code: type_codes[i],
                bootable: p.bootable,
            }
        })?;
    // MBR overhead: partitions start at LBA 2048 (1 MiB), so reserve that
    // many sectors as the table/padding overhead.
    let usable_min: u64 = partitions
        .iter()
        .map(|p| align_size(p.size.size_min, BLOCK_SIZE))
        .sum::<u64>()
        + empty_space
            .as_ref()
            .map(|e| align_size(e.size_min, BLOCK_SIZE))
            .unwrap_or(0);
    let size_min = table_size_min(usable_min, MBR_SECTOR_SIZE, MBR_FIRST_USABLE_LBA);
    let bootcode = process_bootcode(ctx, &block.bootcode)?;
    Ok(ManifestBlockMbr {
        partitions,
        empty_space,
        size_min,
        bootcode,
    })
}

fn process_luks(ctx: &BuildContext, block: &ConfigBlockLuks) -> Result<ManifestBlockLuks> {
    // Resolve the LUKS2 parameters from the config (with defaults).
    let cipher = block
        .cipher
        .clone()
        .unwrap_or_else(|| "aes-xts-plain64".to_string());
    if cipher != "aes-xts-plain64" {
        return Err(Error::msg(format!(
            "Unsupported LUKS cipher \"{cipher}\" (only aes-xts-plain64 is supported)"
        )));
    }
    let key_size = block.key_size.unwrap_or(64);
    if !matches!(key_size, 32 | 64) {
        return Err(Error::msg(format!(
            "Unsupported LUKS key size {key_size} (32 or 64 supported)"
        )));
    }
    let sector_size = block.sector_size.unwrap_or(4096);
    if !matches!(sector_size, 512 | 4096) {
        return Err(Error::msg(format!(
            "Unsupported LUKS sector size {sector_size} (512 or 4096 supported)"
        )));
    }
    let payload_align = match &block.payload_align {
        Some(s) => crate::size::size_to_bytes(s)?,
        None => crate::luks::DEFAULT_PAYLOAD_ALIGN,
    };
    let kdf = block
        .kdf
        .clone()
        .unwrap_or_else(crate::luks::Luks2Kdf::default_argon2id);
    let af_stripes = crate::luks::DEFAULT_AF_STRIPES;
    let af_hash = crate::luks::DEFAULT_AF_HASH.to_string();

    // The passphrase is no longer stored in the config/manifest — it is
    // supplied at install time via `--key` / `--key-file` (or prompted). Only
    // the container's `name` is carried forward so the installer can match it.

    // The on-disk overhead is the payload offset: binary header + JSON area +
    // the keyslot's AF area, aligned to `payload_align`. See
    // [`luks_payload_offset`].
    let luks_overhead = luks_payload_offset(key_size, sector_size, payload_align, af_stripes);

    let content = match &block.content {
        Some(c) => Some(Box::new(process_block(ctx, c)?)),
        None => None,
    };
    let size_min = luks_overhead + content.as_ref().map(|c| block_size_min(c)).unwrap_or(0);
    Ok(ManifestBlockLuks {
        size_min,
        content,
        name: block.name.clone(),
        cipher,
        key_size,
        sector_size,
        payload_align,
        kdf,
        af_stripes,
        af_hash,
        uuid: block.uuid,
    })
}

fn process_image(ctx: &BuildContext, block: &ConfigBlockImage) -> Result<ManifestBlockImage> {
    let entry = ctx.resolve_input_file(&block.input)?;
    Ok(ManifestBlockImage {
        size_min: entry.manifest.size,
        file: entry.hash_file_name,
    })
}

/// Resolve a bootcode input (a `file:` URL / path), validate it is at most 512
/// bytes, and content-address its first 446 bytes. The stored artifact is the
/// first `min(file_len, 446)` bytes of the input.
fn process_bootcode(ctx: &BuildContext, input: &Option<String>) -> Result<Option<String>> {
    let Some(url) = input else { return Ok(None) };
    let bytes = ctx.resolve_input_bytes(url)?;
    if bytes.len() > 512 {
        return Err(Error::msg(format!(
            "Bootcode file \"{}\" is {} bytes, exceeding the 512-byte maximum",
            url,
            bytes.len()
        )));
    }
    let n = bytes.len().min(446);
    let temp = ctx.create_temp_file();
    std::fs::write(&temp, &bytes[..n])?;
    let entry = ctx.add_output_file(&temp)?;
    Ok(Some(entry.hash_file_name))
}

fn process_lvm_block(ctx: &BuildContext, block: &ConfigBlockLvm) -> Result<ManifestBlockLvm> {
    let vg = block.vg.clone();
    let size_min = match &vg {
        Some(vg_name) => {
            let manifest = ctx.ensure_lvm(vg_name)?;
            manifest.size_min
        }
        None => match &block.size.size_min {
            Some(s) => size_to_bytes(s)?,
            None => 0,
        },
    };
    Ok(ManifestBlockLvm { size_min, vg })
}

/// Build (once) the manifest for an LVM volume group.
pub fn process_lvm(ctx: &BuildContext, vg: &str) -> Result<ManifestLvmVg> {
    let config = ctx
        .config
        .lvm
        .get(vg)
        .ok_or_else(|| crate::error::Error::msg(format!("Undefined volume group: {vg}")))?;
    // `process_partitions` returns the partition/empty manifests and a raw
    // sizeMin sum; we discard the sum (the third tuple element) and recompute
    // the VG sizeMin below with per-LV extent rounding.
    let (partitions, empty_space, _raw_size_min) = process_partitions(
        ctx,
        &config.partitions,
        &config.empty_space,
        0,
        |p, base| {
            let name = replace_partition_name_vars(ctx, p.name.as_str(), p.content.as_deref());
            ManifestLvmPartition {
                size: base.size,
                content: base.content,
                name,
            }
        },
    )?;
    // Each logical volume (and the empty-space reserve) occupies a whole
    // number of physical extents at install time: `compute_vg_layout` rounds
    // every partition's `sizeMin` up to `pe_size` (via `compute_partition_sizes`
    // with a `block_size` of `pe_size`). Round each one up here *before* summing
    // so the volume group's `sizeMin` accounts for the per-LV extent rounding.
    // Rounding only the aggregate (as before) underestimates whenever the
    // individual round-ups add up to more than a single aggregate round-up —
    // e.g. two LVs that each need a fraction of an extent need two extents,
    // not one — and install then fails with "Insufficient space".
    let pe_size = LVM_DEFAULT_PE_SIZE;
    let mut extents_bytes: u64 = 0;
    for p in &partitions {
        extents_bytes += align_size(p.size.size_min, pe_size);
    }
    if let Some(e) = &empty_space {
        extents_bytes += align_size(e.size_min, pe_size);
    }
    let size_min = LVM_DEFAULT_PE_START + align_size(extents_bytes, pe_size);
    let manifest = ManifestLvmVg {
        partitions,
        empty_space,
        size_min,
    };
    ctx.set_lvm(vg, manifest.clone());
    Ok(manifest)
}

/// A partition's resolved size + content, before the per-variant name/type
/// fields are attached.
struct PartitionBase {
    size: ManifestPartitionSize,
    content: Option<Box<ManifestBlock>>,
}

/// Common accessors for the two partition kinds (GPT and LVM), which share the
/// flattened size spec + optional content and differ only in their extra
/// fields.
trait PartitionLike {
    fn size(&self) -> &ConfigPartitionSize;
    fn content(&self) -> Option<&ConfigBlock>;
}
impl PartitionLike for ConfigGptPartition {
    fn size(&self) -> &ConfigPartitionSize {
        &self.size
    }
    fn content(&self) -> Option<&ConfigBlock> {
        self.content.as_deref()
    }
}
impl PartitionLike for ConfigLvmPartition {
    fn size(&self) -> &ConfigPartitionSize {
        &self.size
    }
    fn content(&self) -> Option<&ConfigBlock> {
        self.content.as_deref()
    }
}
impl PartitionLike for ConfigMbrPartition {
    fn size(&self) -> &ConfigPartitionSize {
        &self.size
    }
    fn content(&self) -> Option<&ConfigBlock> {
        self.content.as_deref()
    }
}

/// Walk `partitions`, process each one's content, and accumulate `sizeMin`.
/// `make` attaches the variant-specific fields (name/type/guid) to produce the
/// final manifest partition `T`.
/// Compute the `sizeMin` of a GPT or MBR partition table: the aligned
/// partition sizeMins plus the table overhead, rounded to a sector boundary.
/// Mirrors `install::compute_min_disk_size` so that a nested partition table
/// (whose containing partition is sized from this `sizeMin`) can fit its own
/// tables.
fn table_size_min(usable_min: u64, sector_size: u64, overhead_sectors: u64) -> u64 {
    (usable_min / sector_size + overhead_sectors) * sector_size
}

fn process_partitions<P: PartitionLike, T, F>(
    ctx: &BuildContext,
    partitions: &[P],
    empty_space: &Option<ConfigPartitionSize>,
    mut size_min: u64,
    make: F,
) -> Result<(Vec<T>, Option<ManifestPartitionSize>, u64)>
where
    F: Fn(&P, PartitionBase) -> T,
{
    let mut out = Vec::with_capacity(partitions.len());
    for p in partitions {
        let content = match p.content() {
            Some(c) => Some(Box::new(process_block(ctx, c)?)),
            None => None,
        };
        let content_min = content.as_ref().map(|c| block_size_min(c)).unwrap_or(0);
        let size = to_manifest_partition_size(p.size(), content_min)?;
        size_min += size.size_min;
        out.push(make(p, PartitionBase { size, content }));
    }
    let empty = match empty_space {
        Some(e) => Some(to_manifest_partition_size(e, 0)?),
        None => None,
    };
    if let Some(e) = &empty {
        size_min += e.size_min;
    }
    Ok((out, empty, size_min))
}

/// Read `sizeMin` from a manifest block.
pub(crate) fn block_size_min(block: &ManifestBlock) -> u64 {
    match block {
        ManifestBlock::Gpt(b) => b.size_min,
        ManifestBlock::Mbr(b) => b.size_min,
        ManifestBlock::Ext4(b) => b.size_min,
        ManifestBlock::Fat(b) => b.size_min,
        ManifestBlock::Luks(b) => b.size_min,
        ManifestBlock::Lvm(b) => b.size_min,
        ManifestBlock::Image(b) => b.size_min,
    }
}

/// LUKS2 payload offset (the on-disk overhead before the encrypted content):
/// binary header + JSON area + the keyslot's anti-forensic area, aligned up to
/// `max(payloadAlign, sectorSize)`. The AF area size is
/// `round_up(keySize * afStripes, 4096)`, matching `cryptsetup`.
pub(crate) fn luks_payload_offset(
    key_size: u32,
    sector_size: u32,
    payload_align: u64,
    af_stripes: u32,
) -> u64 {
    let af_area_size = {
        let raw = key_size as u64 * af_stripes as u64;

        raw.div_ceil(4096) * 4096
    };
    let keyslot_end = crate::luks::FIRST_KEYSLOT_OFFSET + af_area_size;
    let align = payload_align.max(sector_size as u64);
    keyslot_end.div_ceil(align) * align
}

/// Replace `${CONTENTHASH}` (for image-content partitions) and `${VAR}` in a
/// partition name.
fn replace_partition_name_vars(
    ctx: &BuildContext,
    name: &str,
    content: Option<&ConfigBlock>,
) -> String {
    let mut name = name.to_string();
    if name.contains("${CONTENTHASH}")
        && let Some(ConfigBlock::Image(img)) = content
        && let Ok(entry) = ctx.resolve_input_file(&img.input)
    {
        let digest = hex::decode(&entry.manifest.hash)
            .map_err(|_| Error::msg("invalid content hash"))
            .ok();
        if let Some(digest) = digest {
            let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..8]);
            name = name.replace("${CONTENTHASH}", &h);
        }
    }
    ctx.replace_vars(&name)
}

#[cfg(test)]
mod fat_min_tests {
    use super::fat_min_size;
    use crate::model::config::FatVersion;

    #[test]
    fn empty_floors_at_fat12_min() {
        // No content at all: a FAT volume still needs to be at least the
        // smallest valid FAT12 volume (512 KiB).
        assert_eq!(fat_min_size(0, 0, 0, None, FatVersion::Auto), 1024 * 512);
    }

    #[test]
    fn grows_with_content() {
        let m = fat_min_size(10 * 1024 * 1024, 1, 0, None, FatVersion::Auto);
        assert!(m >= 10 * 1024 * 1024, "{m} should be >= 10 MiB");
    }

    #[test]
    fn rounds_up_overhead() {
        // 64 MiB of content: the volume must hold the content *and* the FAT
        // metadata, so it is strictly larger than 64 MiB.
        let m = fat_min_size(64 * 1024 * 1024, 1, 0, None, FatVersion::Auto);
        assert!(m > 64 * 1024 * 1024, "{m} should exceed 64 MiB");
        // ... but not absurdly large (< 70 MiB).
        assert!(m < 70 * 1024 * 1024, "{m} should stay under 70 MiB");
    }

    #[test]
    fn forced_fat32_floors_at_32mib() {
        // FAT32 needs at least 32 MiB; forcing it on tiny content still
        // produces a 32 MiB minimum (the formatter rejects smaller volumes).
        let m = fat_min_size(0, 0, 0, None, FatVersion::Fat32);
        assert!(m >= 32 * 1024 * 1024, "{m} should be >= 32 MiB for FAT32");
    }
}
