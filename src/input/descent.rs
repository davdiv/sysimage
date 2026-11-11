//! Nested-image descent.
//!
//! Lets one `sysimage build` reference files *deep inside* a block image or
//! archive produced by another build (or by the same build), without ever
//! extracting the intermediate layers to disk.
//!
//! A descent URL has the form:
//!
//! ```text
//! in:<source-input>#<descent>
//! ```
//!
//! where `<source-input>` is any resolvable input specifier (`file:`,
//! `podman:`, `build:` …) that resolves to a regular file on disk, and
//! `<descent>` is a `|`-separated chain of explicit `type:argument` steps
//! applied left to right. Every layer carries an explicit type tag — there is
//! no auto-detection, so the chain is unambiguous and there is no limit on
//! depth.
//!
//! Supported step types:
//!
//! - `gpt:<part-name-or-index>` — GPT partition (match by name, or 1-based index)
//! - `mbr:<slot-1..4>` — MBR primary partition slot
//! - `lvm:<lv-name>` — LVM logical volume (assumes a single PV, PV0)
//! - `luks:<container-name>` — LUKS2 container (passphrase from `--key name=…`)
//! - `erofs:<path>` — EROFS view (a file or a directory tree)
//! - `ext4:<path>` — ext4 view (a file or a directory tree)
//! - `fat:<path>` — FAT12/16/32 view (a file or a directory tree)
//! - `cpio:<path>` — newc cpio archive view (a file or a directory tree);
//!   zstd-compressed archives are decoded transparently
//! - `tar:<path>` — ustar tar archive view (a file or a directory tree);
//!   zstd-compressed archives are decoded transparently
//!
//! Block steps (`gpt`/`mbr`/`lvm`/`luks`) transform a block device into a
//! sub-region (a partition slice, an LV extent range, a decrypted LUKS
//! payload). Filesystem/archive steps (`erofs`/`ext4`/`fat`/`cpio`/`tar`)
//! open a filesystem or parse an archive over the current device and resolve
//! a path:
//!
//! - If the resolved inode is a **regular file**, the bytes are exposed as a
//!   [`VirtualFile`] (streamed once, on demand, into the content-addressed
//!   output — no extraction). When the FS step is *not* the last step, the
//!   file is instead wrapped back into a block device ([`FsFileDev`]) so the
//!   descent can continue into an image nested inside a filesystem — depth is
//!   unlimited.
//! - If the resolved inode is a **directory**, it must be the last step and
//!   yields a [`VirtualTree`] (walked in-memory into a [`TreeNode`]).
//!
//! The `cpio:`/`tar:` steps behave the same way but operate on archive
//! formats rather than block filesystems: the archive is parsed in memory
//! into a [`TreeNode`] and the path is resolved within it. Compression is
//! not part of the step type — a `cpio:`/`tar:` source whose first bytes are
//! the zstd magic is decoded transparently, so a `build:cpio:`/`build:tar:`
//! artifact (which sysimage always zstd-compresses) can be descended into
//! directly.
//!
//! A chain that ends on a block step yields the raw sub-region bytes as a
//! [`VirtualFile`] (useful for referencing a whole decrypted partition or raw
//! partition as an image input).
//!
//! Nothing is extracted: every layer is a thin, on-demand reader stacked over
//! the previous one. Only the final leaf bytes are ever materialized (once,
//! into the content-addressed output), exactly like any other build input.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use fs_core::BlockRead as CoreBlockRead;
use fs_erofs as erofs;
use fs_ext4 as ext4;
use fs_ext4::block_io::BlockDevice;
use fs_ext4::error::Error as Ext4Error;
use fs_ext4::inode::Inode as Ext4Inode;

use crate::archive::{Meta, TreeNode};
use crate::error::{Error, Result};
use crate::install::{GPT_SECTOR_SIZE, MBR_SECTOR_SIZE, gpt_name_string};

/// A type-erased read-only block device — the single region type threaded
/// through the whole descent. Erasure keeps nesting (LUKS-in-LUKS,
/// ext4-file-in-erofs-in-LUKS-in-GPT, …) from growing the type.
type Dev = Arc<dyn BlockDevice>;

// ---------------------------------------------------------------------------
// Region adapters
// ---------------------------------------------------------------------------

/// A sub-region `[base, base + size)` of an inner device. Zero-copy: reads are
/// forwarded with the offset shifted by `base`.
struct SubDev {
    inner: Dev,
    base: u64,
    size: u64,
}

impl BlockDevice for SubDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        match offset.checked_add(buf.len() as u64) {
            Some(e) if e <= self.size => {}
            _ => return Err(Ext4Error::OutOfBounds),
        }
        self.inner.read_at(self.base + offset, buf)
    }
    fn size_bytes(&self) -> u64 {
        self.size
    }
}

fn sub_region(dev: Dev, offset: u64, size: u64) -> Dev {
    Arc::new(SubDev {
        inner: dev,
        base: offset,
        size,
    })
}

/// Bridge an ext4-flavoured [`BlockDevice`] into the shared `fs_core::BlockRead`
/// trait, which is what the EROFS reader expects.
struct CoreBridge {
    dev: Dev,
}

impl CoreBlockRead for CoreBridge {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::error::Result<()> {
        self.dev
            .read_at(offset, buf)
            .map_err(|e| fs_core::Error::Custom(format!("block read: {e}")))
    }
    fn size_bytes(&self) -> u64 {
        self.dev.size_bytes()
    }
}

fn core_view(dev: &Dev) -> Arc<dyn CoreBlockRead> {
    Arc::new(CoreBridge { dev: dev.clone() })
}

/// A cursor over a [`Dev`] implementing `std::io::Read + Seek`. Used by readers
/// that need a streaming view (GPT/MBR/LUKS/LVM probes all take `Read + Seek`).
struct DevCursor {
    dev: Dev,
    pos: u64,
}

impl DevCursor {
    fn new(dev: Dev) -> Self {
        Self { dev, pos: 0 }
    }
    fn size(&self) -> u64 {
        self.dev.size_bytes()
    }
}

impl Read for DevCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.size();
        let n = if self.pos >= size {
            0
        } else {
            (size - self.pos).min(buf.len() as u64) as usize
        };
        if n == 0 {
            return Ok(0);
        }
        self.dev.read_at(self.pos, &mut buf[..n]).map_err(io_err)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for DevCursor {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.size();
        let new = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(o) => (size as i128 + o as i128).max(0) as u64,
            SeekFrom::Current(o) => (self.pos as i128 + o as i128).max(0) as u64,
        };
        self.pos = new;
        Ok(new)
    }
}

/// A file-inside-a-filesystem exposed as a block device, so the descent can
/// keep going into an image nested inside a filesystem.
enum FsFileDev {
    Erofs {
        fs: Arc<erofs::Filesystem>,
        inode: erofs::Inode,
        size: u64,
    },
    Ext4 {
        fs: Arc<ext4::Filesystem>,
        inode: Ext4Inode,
        raw: Vec<u8>,
        ino: u32,
        size: u64,
    },
}

impl BlockDevice for FsFileDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size_bytes())
        {
            return Err(Ext4Error::OutOfBounds);
        }
        match self {
            FsFileDev::Erofs { fs, inode, .. } => fs
                .read_file(inode, offset, buf)
                .map_err(|e| Ext4Error::Io(io::Error::other(format!("erofs: {e}")))),
            FsFileDev::Ext4 {
                fs,
                inode,
                raw,
                ino,
                ..
            } => {
                ext4::file_io::read_with_raw_verified(
                    fs,
                    inode,
                    raw,
                    *ino,
                    offset,
                    buf.len() as u64,
                    buf,
                )
                .map_err(|e| Ext4Error::Io(io::Error::other(format!("ext4: {e}"))))?;
                Ok(())
            }
        }
    }
    fn size_bytes(&self) -> u64 {
        match self {
            FsFileDev::Erofs { size, .. } | FsFileDev::Ext4 { size, .. } => *size,
        }
    }
}

fn io_err(e: Ext4Error) -> io::Error {
    io::Error::other(format!("{e}"))
}

/// An in-memory byte buffer exposed as a block device. Used when a descent
/// step resolves to a regular file inside an archive or FAT filesystem and the
/// chain continues into an image nested inside that file. The content is held
/// in an `Arc<[u8]>` so the same buffer can back both a nested `Dev` and a
/// terminal [`VirtualFile`] without copying.
struct VecDev {
    data: Arc<[u8]>,
}

impl BlockDevice for VecDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_ext4::error::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        match offset.checked_add(buf.len() as u64) {
            Some(e) if e <= self.data.len() as u64 => {
                buf.copy_from_slice(&self.data[offset as usize..e as usize]);
                Ok(())
            }
            _ => Err(Ext4Error::OutOfBounds),
        }
    }
    fn size_bytes(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Resolve a path within an in-memory [`TreeNode`], producing a descent
/// intermediate. A directory becomes a terminal [`VirtualTree::Tree`]; a
/// regular file (or a symlink, whose bytes are its target — matching the
/// erofs/ext4 behaviour) becomes a [`VecDev`] block device so the chain can
/// either end on it or keep descending.
fn tree_resolve(root: &TreeNode, path: &str, kind: &str) -> Result<FsResolve> {
    let node = tree_node_at(root, path, kind)?;
    match node {
        TreeNode::Dir { .. } => Ok(FsResolve::Tree(VirtualTree::Tree {
            root: Box::new(node.clone()),
        })),
        TreeNode::File { meta, content } => Ok(FsResolve::File(FileView {
            dev: Arc::new(VecDev {
                data: Arc::from(content.as_slice()),
            }),
            meta: Some(meta.clone()),
        })),
        TreeNode::Symlink { meta, target } => Ok(FsResolve::File(FileView {
            dev: Arc::new(VecDev {
                data: Arc::from(target.as_bytes()),
            }),
            meta: Some(meta.clone()),
        })),
        TreeNode::Device { .. } | TreeNode::Fifo { .. } => Err(Error::msg(format!(
            "{kind}:{path}: cannot descend into a device/fifo entry"
        ))),
    }
}

/// Navigate `path` within `root`, returning the node. The empty path / `/` /
/// `.` resolve to `root` itself (which must be a directory).
fn tree_node_at<'a>(root: &'a TreeNode, path: &str, kind: &str) -> Result<&'a TreeNode> {
    if path.is_empty() || path == "/" || path == "." {
        return Ok(root);
    }
    let mut cur = root;
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        match cur {
            TreeNode::Dir { children, .. } => {
                cur = children
                    .get(part)
                    .ok_or_else(|| Error::msg(format!("{kind}:{path}: no entry \"{part}\"")))?;
            }
            _ => {
                return Err(Error::msg(format!(
                    "{kind}:{path}: component \"{part}\" is not a directory"
                )));
            }
        }
    }
    Ok(cur)
}

/// Recursively walk a materialized [`TreeNode`] into `root`, honouring
/// include/exclude globs relative to the tree root.
fn walk_tree_node(
    node: &TreeNode,
    dest_prefix: &str,
    includes: &[glob::Pattern],
    excludes: &[glob::Pattern],
    root: &mut TreeNode,
    rel: &str,
) {
    let children = match node {
        TreeNode::Dir { children, .. } => children,
        _ => return,
    };
    for (name, child) in children {
        let child_rel = crate::archive::join_path(rel, name);
        if crate::archive::is_excluded(&child_rel, excludes) {
            continue;
        }
        let dest = crate::archive::join_path(dest_prefix, &child_rel);
        match child {
            TreeNode::Dir { meta, .. } => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                crate::archive::insert_leaf(
                    root,
                    &dest,
                    TreeNode::Dir {
                        meta: meta.clone(),
                        children: BTreeMap::new(),
                    },
                );
                walk_tree_node(child, dest_prefix, includes, excludes, root, &child_rel);
            }
            TreeNode::File { meta, content } => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                crate::archive::insert_leaf(
                    root,
                    &dest,
                    TreeNode::File {
                        meta: meta.clone(),
                        content: content.clone(),
                    },
                );
            }
            TreeNode::Symlink { meta, target } => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                crate::archive::insert_leaf(
                    root,
                    &dest,
                    TreeNode::Symlink {
                        meta: meta.clone(),
                        target: target.clone(),
                    },
                );
            }
            TreeNode::Device { .. } | TreeNode::Fifo { .. } => {
                // Devices/fifos cannot be materialized into a build tree.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal file/tree views
// ---------------------------------------------------------------------------

/// `Read + Seek` fused into a single object trait so a [`VirtualFile`] can hand
/// out fresh readers without growing the return type.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// A lazily-read regular file exposed by a descent. `open` produces a fresh
/// `Read + Seek` over the file's bytes; the bytes are streamed on demand and
/// never fully extracted unless the consumer reads them all.
pub struct VirtualFile {
    pub size: u64,
    /// Metadata from the containing filesystem/archive (mode, ownership,
    /// mtime and xattrs). `None` for raw device views, which have no inode.
    pub meta: Option<Meta>,
    pub open: Box<dyn Fn() -> Result<Box<dyn ReadSeek>> + Send + Sync>,
}

/// A directory tree exposed by a terminal filesystem step, walked in-memory
/// into a [`TreeNode`] (honouring include/exclude globs).
pub enum VirtualTree {
    Erofs {
        fs: Arc<erofs::Filesystem>,
        root: erofs::Inode,
    },
    Ext4 {
        fs: Arc<ext4::Filesystem>,
        root_ino: u32,
    },
    /// An already-materialized in-memory tree (FAT/cpio/tar descent). The root
    /// is the resolved directory node.
    Tree { root: Box<TreeNode> },
}

/// The outcome of resolving an input specifier.
pub enum ResolvedInput {
    /// A real path on the local filesystem (the legacy `file:`/`podman:`/
    /// `build:` case).
    Path(std::path::PathBuf),
    /// A single regular file inside a (possibly nested) image/archive.
    File(VirtualFile),
    /// A directory tree inside a (possibly nested) image/archive.
    Tree(VirtualTree),
}

/// A file exposed by a descent step, together with its metadata when the
/// containing filesystem/archive provides it. The metadata is carried to the
/// terminal [`VirtualFile`] so `collect_tree` can preserve ownership, modes
/// and extended attributes (notably `security.capability`).
struct FileView {
    dev: Dev,
    meta: Option<Meta>,
}

/// Intermediate result of a filesystem step: either a regular file exposed as
/// a block device (so the descent can keep going into an image nested inside
/// it) or a terminal directory tree.
enum FsResolve {
    File(FileView),
    Tree(VirtualTree),
}

/// A [`Dev`] wrapped as a terminal `Read + Seek` reader for any block device
/// (raw sub-region, LUKS payload, or an FS-file-dev).
struct DevReader {
    dev: Dev,
    pos: u64,
}

impl DevReader {
    fn new(dev: Dev) -> Self {
        Self { dev, pos: 0 }
    }
}

impl Read for DevReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.dev.size_bytes();
        let n = if self.pos >= size {
            0
        } else {
            (size - self.pos).min(buf.len() as u64) as usize
        };
        if n == 0 {
            return Ok(0);
        }
        self.dev.read_at(self.pos, &mut buf[..n]).map_err(io_err)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for DevReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.dev.size_bytes();
        let new = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(o) => (size as i128 + o as i128).max(0) as u64,
            SeekFrom::Current(o) => (self.pos as i128 + o as i128).max(0) as u64,
        };
        self.pos = new;
        Ok(new)
    }
}

/// Build a terminal [`VirtualFile`] that streams the raw bytes of `dev`.
fn device_as_file(dev: Dev) -> VirtualFile {
    virtual_file(dev, None)
}

/// Build a terminal [`VirtualFile`] with optional filesystem metadata.
fn virtual_file(dev: Dev, meta: Option<Meta>) -> VirtualFile {
    let size = dev.size_bytes();
    VirtualFile {
        size,
        meta,
        open: Box::new(move || Ok(Box::new(DevReader::new(dev.clone())))),
    }
}

// ---------------------------------------------------------------------------
// Descent steps
// ---------------------------------------------------------------------------

/// One explicit layer of a descent chain.
#[derive(Debug, Clone)]
pub enum DescentStep {
    Gpt(String),
    Mbr(u8),
    Lvm(String),
    Luks(String),
    Erofs(String),
    Ext4(String),
    Fat(String),
    Cpio(String),
    Tar(String),
}

/// Parse a `|`-separated descent chain into steps.
pub fn parse_descent(chain: &str) -> Result<Vec<DescentStep>> {
    let mut steps = Vec::new();
    for raw in chain.split('|') {
        let step = raw.trim();
        if step.is_empty() {
            return Err(Error::msg("descent: empty step (use `type:argument`)"));
        }
        let (kind, arg) = step
            .split_once(':')
            .ok_or_else(|| Error::msg(format!("descent: step \"{step}\" missing `:argument`")))?;
        let arg = arg.to_string();
        let step = match kind {
            "gpt" => DescentStep::Gpt(arg),
            "mbr" => {
                let n: u8 = arg
                    .parse()
                    .map_err(|_| Error::msg(format!("mbr: slot must be 1..=4, got \"{arg}\"")))?;
                if !(1..=4).contains(&n) {
                    return Err(Error::msg(format!("mbr: slot must be 1..=4, got {n}")));
                }
                DescentStep::Mbr(n)
            }
            "lvm" => DescentStep::Lvm(arg),
            "luks" => DescentStep::Luks(arg),
            "erofs" => DescentStep::Erofs(arg),
            "ext4" => DescentStep::Ext4(arg),
            "fat" => DescentStep::Fat(arg),
            "cpio" => DescentStep::Cpio(arg),
            "tar" => DescentStep::Tar(arg),
            other => {
                return Err(Error::msg(format!(
                    "descent: unknown step type \"{other}\" (supported: gpt, mbr, lvm, luks, erofs, ext4, fat, cpio, tar)"
                )));
            }
        };
        steps.push(step);
    }
    if steps.is_empty() {
        return Err(Error::msg("descent: empty chain"));
    }
    Ok(steps)
}

/// Run a descent chain over `source`, returning the terminal view.
pub fn descend(
    source: &Path,
    steps: &[DescentStep],
    keys: &BTreeMap<String, Vec<u8>>,
) -> Result<ResolvedInput> {
    let meta = std::fs::metadata(source)
        .map_err(|e| Error::msg(format!("Cannot stat descent source {source:?}: {e}")))?;
    if meta.is_dir() {
        return Err(Error::msg(format!(
            "descent source {source:?} is a directory; `in:` expects an image/archive file"
        )));
    }
    let size = meta.len();
    let file = std::fs::File::open(source)
        .map_err(|e| Error::msg(format!("Cannot open descent source {source:?}: {e}")))?;
    let mut dev: Dev = Arc::new(crate::blockfile::BlockFile::from_file(file, 0, size));

    let last = steps.len() - 1;
    for (i, step) in steps.iter().enumerate() {
        let is_last = i == last;
        match step {
            DescentStep::Gpt(name) => dev = descend_gpt(dev, name)?,
            DescentStep::Mbr(slot) => dev = descend_mbr(dev, *slot)?,
            DescentStep::Lvm(name) => dev = descend_lvm(dev, name)?,
            DescentStep::Luks(name) => dev = descend_luks(dev, name, keys)?,
            DescentStep::Erofs(path) => match erofs_resolve(dev, path)? {
                FsResolve::File(file) => {
                    if is_last {
                        return Ok(ResolvedInput::File(virtual_file(file.dev, file.meta)));
                    }
                    dev = file.dev;
                }
                FsResolve::Tree(tree) => {
                    if !is_last {
                        return Err(Error::msg(format!(
                            "erofs:{path}: a directory must be the last step of a descent"
                        )));
                    }
                    return Ok(ResolvedInput::Tree(tree));
                }
            },
            DescentStep::Ext4(path) => match ext4_resolve(dev, path)? {
                FsResolve::File(file) => {
                    if is_last {
                        return Ok(ResolvedInput::File(virtual_file(file.dev, file.meta)));
                    }
                    dev = file.dev;
                }
                FsResolve::Tree(tree) => {
                    if !is_last {
                        return Err(Error::msg(format!(
                            "ext4:{path}: a directory must be the last step of a descent"
                        )));
                    }
                    return Ok(ResolvedInput::Tree(tree));
                }
            },
            DescentStep::Fat(path) => match fat_resolve(dev, path)? {
                FsResolve::File(file) => {
                    if is_last {
                        return Ok(ResolvedInput::File(virtual_file(file.dev, file.meta)));
                    }
                    dev = file.dev;
                }
                FsResolve::Tree(tree) => {
                    if !is_last {
                        return Err(Error::msg(format!(
                            "fat:{path}: a directory must be the last step of a descent"
                        )));
                    }
                    return Ok(ResolvedInput::Tree(tree));
                }
            },
            DescentStep::Cpio(path) => match archive_resolve(dev, path, ArchiveKind::Cpio)? {
                FsResolve::File(file) => {
                    if is_last {
                        return Ok(ResolvedInput::File(virtual_file(file.dev, file.meta)));
                    }
                    dev = file.dev;
                }
                FsResolve::Tree(tree) => {
                    if !is_last {
                        return Err(Error::msg(format!(
                            "cpio:{path}: a directory must be the last step of a descent"
                        )));
                    }
                    return Ok(ResolvedInput::Tree(tree));
                }
            },
            DescentStep::Tar(path) => match archive_resolve(dev, path, ArchiveKind::Tar)? {
                FsResolve::File(file) => {
                    if is_last {
                        return Ok(ResolvedInput::File(virtual_file(file.dev, file.meta)));
                    }
                    dev = file.dev;
                }
                FsResolve::Tree(tree) => {
                    if !is_last {
                        return Err(Error::msg(format!(
                            "tar:{path}: a directory must be the last step of a descent"
                        )));
                    }
                    return Ok(ResolvedInput::Tree(tree));
                }
            },
        }
    }
    // The chain ended on a block step: expose the raw sub-region as a file.
    Ok(ResolvedInput::File(device_as_file(dev)))
}

// ---------------------------------------------------------------------------
// Block steps
// ---------------------------------------------------------------------------

fn descend_gpt(dev: Dev, name: &str) -> Result<Dev> {
    use hadris_part::scheme::GptDisk;
    use hadris_part::scheme_io::GptDiskReadExt;

    let mut cursor = DevCursor::new(dev.clone());
    let gpt = GptDisk::read_from(&mut cursor, GPT_SECTOR_SIZE as u32)
        .map_err(|e| Error::msg(format!("gpt: {e}")))?;

    // Match by name; fall back to a 1-based index.
    let entry = if let Ok(idx) = name.parse::<usize>() {
        let pos = idx
            .checked_sub(1)
            .ok_or_else(|| Error::msg(format!("gpt: index must be 1-based, got \"{name}\"")))?;
        *gpt.entries
            .iter()
            .filter(|e| !e.is_unused())
            .nth(pos)
            .ok_or_else(|| Error::msg(format!("gpt: no partition at index {idx}")))?
    } else {
        *gpt.entries
            .iter()
            .filter(|e| !e.is_unused())
            .find(|e| gpt_name_string(e) == name)
            .ok_or_else(|| Error::msg(format!("gpt: no partition named \"{name}\"")))?
    };

    let offset = entry.first_lba.to_ne() * GPT_SECTOR_SIZE;
    let size = entry.size_sectors() * GPT_SECTOR_SIZE;
    if size == 0 {
        return Err(Error::msg(format!("gpt: partition \"{name}\" is empty")));
    }
    Ok(sub_region(dev, offset, size))
}

fn descend_mbr(dev: Dev, slot: u8) -> Result<Dev> {
    use hadris_part::mbr::MasterBootRecord;
    use hadris_part::mbr_io::MasterBootRecordReadExt;

    let mut cursor = DevCursor::new(dev.clone());
    let mbr =
        MasterBootRecord::read_from(&mut cursor).map_err(|e| Error::msg(format!("mbr: {e}")))?;
    let table = mbr.get_partition_table();
    let p = &table.partitions[slot as usize - 1];
    if p.part_type == 0 {
        return Err(Error::msg(format!("mbr: slot {slot} is unused")));
    }
    let offset = p.start_lba.to_ne() as u64 * MBR_SECTOR_SIZE;
    let size = p.sector_count.to_ne() as u64 * MBR_SECTOR_SIZE;
    if size == 0 {
        return Err(Error::msg(format!("mbr: slot {slot} is empty")));
    }
    Ok(sub_region(dev, offset, size))
}

fn descend_lvm(dev: Dev, name: &str) -> Result<Dev> {
    let mut cursor = DevCursor::new(dev.clone());
    let vg = crate::lvm::read_vg_from_handle(&mut cursor)
        .map_err(|e| Error::msg(format!("lvm: {e}")))?
        .ok_or_else(|| Error::msg("lvm: no LVM2 physical volume found at this layer"))?;
    let pe_size = vg.extent_size;
    let pv0 = vg
        .pvs
        .first()
        .ok_or_else(|| Error::msg("lvm: volume group has no physical volumes"))?;
    let lv = vg
        .find_lv(name)
        .ok_or_else(|| Error::msg(format!("lvm: no logical volume named \"{name}\"")))?;
    let seg = lv
        .segments
        .first()
        .ok_or_else(|| Error::msg(format!("lvm: LV \"{name}\" has no segments")))?;
    let offset = pv0.extent_offset(seg.pv_start_extent, pe_size);
    let size = seg.size_bytes(pe_size);
    if size == 0 {
        return Err(Error::msg(format!("lvm: LV \"{name}\" is empty")));
    }
    Ok(sub_region(dev, offset, size))
}

fn descend_luks(dev: Dev, name: &str, keys: &BTreeMap<String, Vec<u8>>) -> Result<Dev> {
    let passphrase = keys
        .get(name)
        .ok_or_else(|| {
            Error::msg(format!(
                "luks: no passphrase for container \"{name}\" (provide it with --key {name}=…)"
            ))
        })?
        .clone();

    let mut probe = DevCursor::new(dev.clone());
    let info = crate::luks::read_luks2_segment_info(&mut probe)
        .map_err(|e| Error::msg(format!("luks: {e}")))?
        .ok_or_else(|| Error::msg("luks: no LUKS2 header found at this layer"))?;

    let unlock = DevCursor::new(dev.clone());
    let vol = crate::luks::open_luks2(unlock, &passphrase)
        .map_err(|e| Error::msg(format!("luks: unlock failed for \"{name}\": {e}")))?;
    let master_key = vol.master_key().to_vec();
    drop(vol);

    let region_size = dev.size_bytes();
    let sector_size = info.sector_size as u64;
    let payload_available = region_size.saturating_sub(info.payload_offset);
    let payload_size = (payload_available / sector_size) * sector_size;
    if payload_size == 0 {
        return Err(Error::msg(format!(
            "luks: container \"{name}\" payload area is too small"
        )));
    }

    let luks = crate::blockfile::LuksRegion::new(
        dev,
        info.payload_offset,
        payload_size,
        master_key,
        info.sector_size,
        info.cipher_mode,
        info.iv_tweak,
    );
    Ok(Arc::new(luks))
}

// ---------------------------------------------------------------------------
// Filesystem steps
// ---------------------------------------------------------------------------

fn erofs_resolve(dev: Dev, path: &str) -> Result<FsResolve> {
    let fs =
        erofs::Filesystem::open(core_view(&dev)).map_err(|e| Error::msg(format!("erofs: {e}")))?;
    let fs = Arc::new(fs);
    let inode = if path.is_empty() || path == "/" || path == "." {
        fs.root_inode()
            .map_err(|e| Error::msg(format!("erofs: {e}")))?
    } else {
        fs.resolve_path(path, true)
            .map_err(|e| Error::msg(format!("erofs: {path}: {e}")))?
    };

    if inode.is_dir() {
        return Ok(FsResolve::Tree(VirtualTree::Erofs { fs, root: inode }));
    }
    let xattrs = fs
        .xattrs(&inode)
        .map_err(|e| Error::msg(format!("erofs: xattrs: {e}")))?;
    let meta = Meta {
        perms: inode.mode as u32 & 0o7777,
        uid: inode.uid,
        gid: inode.gid,
        mtime: inode.mtime as u32,
        xattrs,
    };
    Ok(FsResolve::File(FileView {
        dev: Arc::new(FsFileDev::Erofs {
            fs,
            inode: inode.clone(),
            size: inode.size,
        }),
        meta: Some(meta),
    }))
}

fn ext4_resolve(dev: Dev, path: &str) -> Result<FsResolve> {
    let fs = ext4::fs::Filesystem::mount_lazy(dev).map_err(|e| Error::msg(format!("ext4: {e}")))?;
    let fs = Arc::new(fs);
    let ino = if path.is_empty() || path == "/" || path == "." {
        ext4::path::EXT4_ROOT_INODE
    } else {
        let mut read_inode = |ino: u32| fs.read_inode_verified(ino).map(|(i, _)| i);
        ext4::path::lookup(fs.dev.as_ref(), &fs.sb, &mut read_inode, path)
            .map_err(|e| Error::msg(format!("ext4: {path}: {e}")))?
    };
    let (inode, raw) = fs
        .read_inode_verified(ino)
        .map_err(|e| Error::msg(format!("ext4: {path}: {e}")))?;

    if inode.is_dir() {
        return Ok(FsResolve::Tree(VirtualTree::Ext4 { fs, root_ino: ino }));
    }
    let xattrs = ext4::xattr::read_all(
        fs.dev.as_ref(),
        &inode,
        &raw,
        fs.sb.inode_size,
        fs.sb.block_size(),
    )
    .map_err(|e| Error::msg(format!("ext4: xattrs: {e}")))?
    .into_iter()
    .map(|entry| (entry.name.into_bytes(), entry.value))
    .collect();
    let meta = Meta {
        perms: inode.mode as u32 & 0o7777,
        uid: inode.uid,
        gid: inode.gid,
        mtime: inode.mtime as u32,
        xattrs,
    };
    Ok(FsResolve::File(FileView {
        dev: Arc::new(FsFileDev::Ext4 {
            fs,
            inode: inode.clone(),
            raw,
            ino,
            size: inode.size,
        }),
        meta: Some(meta),
    }))
}

// ---------------------------------------------------------------------------
// FAT step
// ---------------------------------------------------------------------------

fn fat_resolve(dev: Dev, path: &str) -> Result<FsResolve> {
    use hadris_fat::sync::{FatVolume, FatVolumeReadExt};

    let volume =
        FatVolume::open(DevCursor::new(dev)).map_err(|e| Error::msg(format!("fat: {e}")))?;
    let volume = Rc::new(volume);

    let comps = descent_components(path);
    // Navigate to the parent directory, then resolve the final component.
    let (dir, final_name) = fat_navigate(&volume, &comps, path)?;

    match final_name {
        None => {
            // The path resolves to a directory itself.
            let tree = fat_dir_to_tree(&volume, &dir)?;
            Ok(FsResolve::Tree(VirtualTree::Tree {
                root: Box::new(tree),
            }))
        }
        Some(name) => {
            let entry = dir
                .find(&name)
                .map_err(|e| Error::msg(format!("fat:{path}: {e}")))?
                .ok_or_else(|| Error::msg(format!("fat:{path}: no entry \"{name}\"")))?;
            if entry.is_directory() {
                let sub = dir
                    .open_entry(&entry)
                    .map_err(|e| Error::msg(format!("fat:{path}: {e}")))?;
                let tree = fat_dir_to_tree(&volume, &sub)?;
                Ok(FsResolve::Tree(VirtualTree::Tree {
                    root: Box::new(tree),
                }))
            } else {
                // Regular file. FAT has no symlinks.
                let size = entry.len();
                let content = volume
                    .read_file(&entry)
                    .map_err(|e| Error::msg(format!("fat:{path}: {e}")))?
                    .read_to_vec()
                    .map_err(|e| Error::msg(format!("fat:{path}: {e}")))?;
                if content.len() as u64 != size {
                    return Err(Error::msg(format!(
                        "fat:{path}: short read ({} of {size} bytes)",
                        content.len()
                    )));
                }
                Ok(FsResolve::File(FileView {
                    dev: Arc::new(VecDev {
                        data: Arc::from(content.as_slice()),
                    }),
                    meta: Some(meta_from_inode(0o644, 0, 0, 0, Vec::new())),
                }))
            }
        }
    }
}

/// Split a descent path into normalized non-empty components.
fn descent_components(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|p| p.to_string())
        .collect()
}

/// Walk `comps[:-1]` as directories from the root, returning the parent
/// directory and the final component name (or `None` if the path is the root).
fn fat_navigate<'a>(
    volume: &'a Rc<hadris_fat::sync::FatVolume<DevCursor>>,
    comps: &[String],
    path: &str,
) -> Result<(hadris_fat::sync::FatDir<'a, DevCursor>, Option<String>)> {
    let mut dir = volume.root_dir();
    if comps.is_empty() {
        return Ok((dir, None));
    }
    let (last, parents) = comps.split_last().unwrap();
    for name in parents {
        dir = dir
            .open_dir(name)
            .map_err(|e| Error::msg(format!("fat:{path}: {e}")))?;
    }
    Ok((dir, Some(last.clone())))
}

/// Recursively materialize a FAT directory into a [`TreeNode`].
fn fat_dir_to_tree(
    volume: &Rc<hadris_fat::sync::FatVolume<DevCursor>>,
    dir: &hadris_fat::sync::FatDir<'_, DevCursor>,
) -> Result<TreeNode> {
    use hadris_fat::sync::{DirectoryEntry, FatVolumeReadExt};

    let mut node = TreeNode::Dir {
        meta: meta_from_inode(0o040755, 0, 0, 0, Vec::new()),
        children: BTreeMap::new(),
    };
    let entries = dir.entries();
    for res in entries {
        let DirectoryEntry::Entry(entry) =
            res.map_err(|e| Error::msg(format!("fat: read_dir: {e}")))?;
        let name = entry.name().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        if entry.is_directory() {
            let sub = dir
                .open_entry(&entry)
                .map_err(|e| Error::msg(format!("fat: open_dir \"{name}\": {e}")))?;
            let child = fat_dir_to_tree(volume, &sub)?;
            insert_tree_child(&mut node, &name, child);
        } else {
            let content = volume
                .read_file(&entry)
                .map_err(|e| Error::msg(format!("fat: read_file \"{name}\": {e}")))?
                .read_to_vec()
                .map_err(|e| Error::msg(format!("fat: read_file \"{name}\": {e}")))?;
            let file = TreeNode::File {
                meta: meta_from_inode(0o100644, 0, 0, 0, Vec::new()),
                content,
            };
            insert_tree_child(&mut node, &name, file);
        }
    }
    Ok(node)
}

/// Insert a child node into a `Dir` node, creating the node if needed.
fn insert_tree_child(dir: &mut TreeNode, name: &str, child: TreeNode) {
    if let TreeNode::Dir { children, .. } = dir {
        children.insert(name.to_string(), child);
    }
}

// ---------------------------------------------------------------------------
// cpio / tar steps
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ArchiveKind {
    Cpio,
    Tar,
}

impl ArchiveKind {
    fn name(self) -> &'static str {
        match self {
            ArchiveKind::Cpio => "cpio",
            ArchiveKind::Tar => "tar",
        }
    }
}

fn archive_resolve(dev: Dev, path: &str, kind: ArchiveKind) -> Result<FsResolve> {
    let stream = archive_stream(&dev, kind)?;
    let root = match kind {
        ArchiveKind::Cpio => cpio_to_tree(stream)?,
        ArchiveKind::Tar => tar_to_tree(stream)?,
    };
    tree_resolve(&root, path, kind.name())
}

/// Build a `Box<dyn Read>` over the archive, decoding zstd transparently when
/// the first bytes are the zstd magic. This is content-format detection (not
/// step-type auto-detection): the chain still carries an explicit `cpio:` /
/// `tar:` tag, and sysimage's `build:cpio:`/`build:tar:` artifacts are always
/// zstd-compressed, so descending into them works out of the box.
fn archive_stream(dev: &Dev, kind: ArchiveKind) -> Result<Box<dyn Read>> {
    let mut magic = [0u8; 4];
    dev.read_at(0, &mut magic)
        .map_err(|e| Error::msg(format!("{}: {e}", kind.name())))?;
    if magic == [0x28, 0xB5, 0x2F, 0xFD] {
        let dec = zstd::Decoder::new(DevCursor::new(dev.clone()))
            .map_err(|e| Error::msg(format!("{}: zstd: {e}", kind.name())))?;
        Ok(Box::new(dec))
    } else {
        Ok(Box::new(DevCursor::new(dev.clone())))
    }
}

fn cpio_to_tree(reader: Box<dyn Read>) -> Result<TreeNode> {
    use hadris_cpio::{CpioArchiveReader, FileType};

    let mut root = TreeNode::Dir {
        meta: meta_from_inode(0o040755, 0, 0, 0, Vec::new()),
        children: BTreeMap::new(),
    };
    let mut cr = CpioArchiveReader::new(reader);
    while let Some(entry) = cr
        .next_entry_alloc()
        .map_err(|e| Error::msg(format!("cpio: {e}")))?
    {
        let name = entry
            .name_str()
            .map_err(|e| Error::msg(format!("cpio: {e}")))?
            .to_string();
        let path = match normalize_archive_path(&name) {
            Some(p) => p,
            None => {
                // Skip the entry data so the reader stays aligned.
                cr.skip_entry_data_owned(&entry)
                    .map_err(|e| Error::msg(format!("cpio: {e}")))?;
                continue;
            }
        };
        let h = entry.header();
        let meta = meta_from_inode(h.mode, h.uid, h.gid, h.mtime, Vec::new());
        let data = cr
            .read_entry_data_alloc(&entry)
            .map_err(|e| Error::msg(format!("cpio: {e}")))?;
        match entry.file_type() {
            FileType::Directory => {
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Dir {
                        meta,
                        children: BTreeMap::new(),
                    },
                );
            }
            FileType::Symlink => {
                let target = String::from_utf8(data)
                    .map_err(|e| Error::msg(format!("cpio: symlink target: {e}")))?;
                crate::archive::insert_leaf(&mut root, &path, TreeNode::Symlink { meta, target });
            }
            FileType::Regular => {
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::File {
                        meta,
                        content: data,
                    },
                );
            }
            FileType::BlockDevice | FileType::CharDevice => {
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Device {
                        meta,
                        dev_type: entry.file_type(),
                        major: h.rdevmajor,
                        minor: h.rdevminor,
                    },
                );
            }
            _ => {}
        }
    }
    Ok(root)
}

fn tar_to_tree(reader: Box<dyn Read>) -> Result<TreeNode> {
    use hadris_cpio::FileType;

    let mut root = TreeNode::Dir {
        meta: meta_from_inode(0o040755, 0, 0, 0, Vec::new()),
        children: BTreeMap::new(),
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive
        .entries()
        .map_err(|e| Error::msg(format!("tar: {e}")))?
    {
        let mut entry = entry.map_err(|e| Error::msg(format!("tar: {e}")))?;
        let xattrs = crate::archive::tar_pax_xattrs(&mut entry)?;
        let header = entry.header();
        let entry_type = header.entry_type();
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
        let mode = header.mode().map_err(|e| Error::msg(format!("tar: {e}")))? & 0o7777;
        let uid = header.uid().map_err(|e| Error::msg(format!("tar: {e}")))? as u32;
        let gid = header.gid().map_err(|e| Error::msg(format!("tar: {e}")))? as u32;
        let mtime = header
            .mtime()
            .map_err(|e| Error::msg(format!("tar: {e}")))? as u32;
        let meta = meta_from_inode(mode, uid, gid, mtime, xattrs);
        match entry_type {
            tar::EntryType::Directory => {
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Dir {
                        meta,
                        children: BTreeMap::new(),
                    },
                );
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|e| Error::msg(format!("tar: {e}")))?;
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::File {
                        meta,
                        content: data,
                    },
                );
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| Error::msg(format!("tar: {e}")))?
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                crate::archive::insert_leaf(&mut root, &path, TreeNode::Symlink { meta, target });
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
                let dt = if entry_type == tar::EntryType::Block {
                    FileType::BlockDevice
                } else {
                    FileType::CharDevice
                };
                crate::archive::insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Device {
                        meta,
                        dev_type: dt,
                        major,
                        minor,
                    },
                );
            }
            _ => {}
        }
    }
    Ok(root)
}

/// Re-export of the archive path normalizer (strips leading `./` and `/`).
fn normalize_archive_path(name: &str) -> Option<String> {
    crate::archive::normalize_archive_path(name)
}

// ---------------------------------------------------------------------------
// VirtualTree → TreeNode
// ---------------------------------------------------------------------------

impl VirtualTree {
    /// Walk this tree and insert every matching entry under `dest_prefix` in
    /// `root`, honouring include/exclude globs (relative to the tree root).
    pub fn collect_into(
        &self,
        dest_prefix: &str,
        includes: &[String],
        excludes: &[String],
        root: &mut TreeNode,
    ) -> Result<()> {
        let include_pats = crate::archive::compile_patterns(includes);
        let exclude_pats = crate::archive::compile_patterns(excludes);
        match self {
            VirtualTree::Erofs { fs, root: rinode } => walk_erofs(
                fs,
                rinode,
                dest_prefix,
                &include_pats,
                &exclude_pats,
                root,
                "",
            ),
            VirtualTree::Ext4 { fs, root_ino } => walk_ext4(
                fs,
                *root_ino,
                dest_prefix,
                &include_pats,
                &exclude_pats,
                root,
                "",
            ),
            VirtualTree::Tree { root: tree } => {
                walk_tree_node(tree, dest_prefix, &include_pats, &exclude_pats, root, "");
                Ok(())
            }
        }
    }
}

fn meta_from_inode(
    perms: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
) -> Meta {
    Meta {
        perms,
        uid,
        gid,
        mtime,
        xattrs,
    }
}

fn walk_erofs(
    fs: &Arc<erofs::Filesystem>,
    dir: &erofs::Inode,
    dest_prefix: &str,
    includes: &[glob::Pattern],
    excludes: &[glob::Pattern],
    root: &mut TreeNode,
    rel: &str,
) -> Result<()> {
    let entries = fs
        .read_dir(dir)
        .map_err(|e| Error::msg(format!("erofs: read_dir: {e}")))?;
    for e in entries {
        let name = String::from_utf8_lossy(&e.name).into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let child_rel = crate::archive::join_path(rel, &name);
        if crate::archive::is_excluded(&child_rel, excludes) {
            continue;
        }
        let dest = crate::archive::join_path(dest_prefix, &child_rel);
        let inode = fs
            .read_inode(e.nid)
            .map_err(|err| Error::msg(format!("erofs: read_inode: {err}")))?;
        let xattrs = fs
            .xattrs(&inode)
            .map_err(|err| Error::msg(format!("erofs: xattrs: {err}")))?;
        let meta = meta_from_inode(
            inode.mode as u32,
            inode.uid,
            inode.gid,
            inode.mtime as u32,
            xattrs,
        );
        if inode.is_dir() {
            if !crate::archive::is_included(&child_rel, includes) {
                continue;
            }
            crate::archive::insert_leaf(
                root,
                &dest,
                TreeNode::Dir {
                    meta,
                    children: std::collections::BTreeMap::new(),
                },
            );
            walk_erofs(
                fs,
                &inode,
                dest_prefix,
                includes,
                excludes,
                root,
                &child_rel,
            )?;
        } else if inode.is_symlink() {
            if !crate::archive::is_included(&child_rel, includes) {
                continue;
            }
            let target = fs
                .read_symlink_target(&inode)
                .map_err(|err| Error::msg(format!("erofs: symlink: {err}")))?;
            crate::archive::insert_leaf(
                root,
                &dest,
                TreeNode::Symlink {
                    meta,
                    target: String::from_utf8_lossy(&target).into_owned(),
                },
            );
        } else if inode.is_regular_file() {
            if !crate::archive::is_included(&child_rel, includes) {
                continue;
            }
            let mut content = vec![0u8; inode.size as usize];
            if !content.is_empty() {
                fs.read_file(&inode, 0, &mut content)
                    .map_err(|err| Error::msg(format!("erofs: read_file: {err}")))?;
            }
            crate::archive::insert_leaf(root, &dest, TreeNode::File { meta, content });
        }
        // Other types (devices, fifos, sockets) are skipped — they cannot be
        // materialized into a build tree without host device nodes.
    }
    Ok(())
}

fn ext4_list_dir(fs: &Arc<ext4::Filesystem>, dir_ino: u32) -> Result<Vec<ext4::dir::DirEntry>> {
    use ext4::dir::parse_block;
    use ext4::features::Incompat;
    use ext4::inode::InodeFlags;

    let (inode, _raw) = fs
        .read_inode_verified(dir_ino)
        .map_err(|e| Error::msg(format!("ext4: read_inode: {e}")))?;
    if !inode.is_dir() {
        return Err(Error::msg(format!(
            "ext4: inode {dir_ino} is not a directory"
        )));
    }
    let has_filetype = fs.sb.feature_incompat & Incompat::FILETYPE.bits() != 0;
    let block_size = fs.sb.block_size() as u64;
    let mut out = Vec::new();

    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 {
        // Inline directory: the entry data lives directly in the i_block area.
        let n = inode.size.min(inode.block.len() as u64) as usize;
        out.extend(
            parse_block(&inode.block[..n], has_filetype)
                .map_err(|e| Error::msg(format!("ext4: parse inline dir: {e}")))?,
        );
        return Ok(out);
    }

    let total_blocks = inode.size.div_ceil(block_size);
    for logical in 0..total_blocks {
        let phys = fs
            .map_inode_logical(&inode, logical)
            .map_err(|e| Error::msg(format!("ext4: map_inode_logical: {e}")))?;
        if let Some(b) = phys {
            let buf = fs
                .read_block(b)
                .map_err(|e| Error::msg(format!("ext4: read_block: {e}")))?;
            out.extend(
                parse_block(&buf, has_filetype)
                    .map_err(|e| Error::msg(format!("ext4: parse_block: {e}")))?,
            );
        }
        // A sparse (hole) block contributes no entries.
    }
    Ok(out)
}

fn walk_ext4(
    fs: &Arc<ext4::Filesystem>,
    dir_ino: u32,
    dest_prefix: &str,
    includes: &[glob::Pattern],
    excludes: &[glob::Pattern],
    root: &mut TreeNode,
    rel: &str,
) -> Result<()> {
    use ext4::dir::DirEntryType;
    use ext4::inode::InodeFlags;

    let entries = ext4_list_dir(fs, dir_ino)?;
    for e in entries {
        if e.inode == 0 {
            continue;
        }
        let name = String::from_utf8_lossy(&e.name).into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let child_rel = crate::archive::join_path(rel, &name);
        if crate::archive::is_excluded(&child_rel, excludes) {
            continue;
        }
        let dest = crate::archive::join_path(dest_prefix, &child_rel);
        let (inode, raw) = fs
            .read_inode_verified(e.inode)
            .map_err(|err| Error::msg(format!("ext4: read_inode: {err}")))?;
        let xattrs = ext4::xattr::read_all(
            fs.dev.as_ref(),
            &inode,
            &raw,
            fs.sb.inode_size,
            fs.sb.block_size(),
        )
        .map_err(|err| Error::msg(format!("ext4: xattrs: {err}")))?
        .into_iter()
        .map(|entry| (entry.name.into_bytes(), entry.value))
        .collect();
        let meta = meta_from_inode(
            inode.mode as u32,
            inode.uid,
            inode.gid,
            inode.mtime as u32,
            xattrs,
        );
        match e.file_type {
            DirEntryType::Directory => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                crate::archive::insert_leaf(
                    root,
                    &dest,
                    TreeNode::Dir {
                        meta,
                        children: std::collections::BTreeMap::new(),
                    },
                );
                walk_ext4(
                    fs,
                    e.inode,
                    dest_prefix,
                    includes,
                    excludes,
                    root,
                    &child_rel,
                )?;
            }
            DirEntryType::RegFile => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                let mut content = vec![0u8; inode.size as usize];
                if !content.is_empty() {
                    ext4::file_io::read_with_raw_verified(
                        fs,
                        &inode,
                        &raw,
                        e.inode,
                        0,
                        inode.size,
                        &mut content,
                    )
                    .map_err(|err| Error::msg(format!("ext4: read_file: {err}")))?;
                }
                crate::archive::insert_leaf(root, &dest, TreeNode::File { meta, content });
            }
            DirEntryType::Symlink => {
                if !crate::archive::is_included(&child_rel, includes) {
                    continue;
                }
                // Fast symlinks store the target in the i_block area (≤60 B);
                // longer ones use a regular data block.
                let target =
                    if (inode.flags & InodeFlags::INLINE_DATA.bits()) != 0 || inode.size <= 60 {
                        let n = inode.size.min(60) as usize;
                        String::from_utf8_lossy(&inode.block[..n]).into_owned()
                    } else {
                        let mut buf = vec![0u8; inode.size as usize];
                        ext4::file_io::read_with_raw_verified(
                            fs, &inode, &raw, e.inode, 0, inode.size, &mut buf,
                        )
                        .map_err(|err| Error::msg(format!("ext4: symlink target: {err}")))?;
                        String::from_utf8_lossy(&buf).into_owned()
                    };
                crate::archive::insert_leaf(root, &dest, TreeNode::Symlink { meta, target });
            }
            _ => {
                // Devices, fifos, sockets: skipped (no host device nodes).
            }
        }
    }
    Ok(())
}
