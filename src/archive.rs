//! Archive (cpio/tar) building.
//!
//! Walks a [`ConfigFilesSet`] (an ordered list of destination → source
//! mappings, with optional glob include/exclude), preserves file metadata,
//! synthesizes parent directories, and writes a zstd-compressed archive. CPIO
//! ("newc") is produced with `hadris-cpio`; ustar tar with the `tar` crate.
//! Tar carries extended attributes as `SCHILY.xattr.*` PAX records; CPIO's newc
//! format has no place for them.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Path;

pub use hadris_cpio::FileType;
use hadris_cpio::{CpioArchiveReader, CpioArchiveWriter, CpioWriteOptions, FileNode, FileTree};

use crate::error::{Error, Result};
use crate::input::{ResolvedFilesSet, ResolvedSource};
use crate::model::config::ArchiveFormat;

/// Filesystem metadata kept for every archive/erofs entry.
///
/// `xattrs` stores fully-qualified Linux attribute names (for example
/// `user.sysimage.version`) together with their raw values. Names are kept as
/// bytes because the kernel does not require xattr names to be UTF-8. Entries
/// are kept sorted by name so the resulting images are deterministic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub perms: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Meta {
    const fn default_dir() -> Self {
        Meta {
            perms: 0o0755,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: Vec::new(),
        }
    }
}

/// A node in the in-memory file tree shared by the archive and EROFS builders.
#[derive(Clone)]
pub enum TreeNode {
    Dir {
        meta: Meta,
        children: BTreeMap<String, TreeNode>,
    },
    File {
        meta: Meta,
        content: Vec<u8>,
    },
    Symlink {
        meta: Meta,
        target: String,
    },
    Device {
        meta: Meta,
        dev_type: FileType,
        major: u32,
        minor: u32,
    },
    Fifo {
        meta: Meta,
    },
}

/// Computed content sizes for a filesystem's file set.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContentSizes {
    /// Total logical size of all regular files (sum of file content lengths).
    pub total_size: u64,
    /// Total on-disk size: each file rounded up to `block_size`, plus one
    /// `block_size` per directory (except the synthetic root).
    pub size_on_disk: u64,
    /// Number of regular files.
    pub file_count: u64,
    /// Number of directories (excluding the synthetic root).
    pub dir_count: u64,
}

/// Compute the total file size and on-disk size for a files set, as if the
/// content were laid out on a filesystem with the given `block_size` (in
/// bytes). The files set must already have its inputs resolved.
pub fn compute_content_sizes(
    files_set: &ResolvedFilesSet,
    block_size: u64,
) -> Result<ContentSizes> {
    let root = collect_tree(files_set)?;
    Ok(compute_sizes_from_tree(&root, block_size))
}

/// Compute content sizes from an already-built [`TreeNode`] root.
pub fn compute_sizes_from_tree(root: &TreeNode, block_size: u64) -> ContentSizes {
    let mut sizes = ContentSizes::default();
    measure_tree(root, block_size, &mut sizes, true);
    sizes
}

/// Recursively measure a [`TreeNode`], accumulating file sizes and on-disk
/// allocation.
fn measure_tree(node: &TreeNode, block_size: u64, sizes: &mut ContentSizes, is_root: bool) {
    match node {
        TreeNode::Dir { children, .. } => {
            if !is_root {
                sizes.size_on_disk += block_size;
                sizes.dir_count += 1;
            }
            for child in children.values() {
                measure_tree(child, block_size, sizes, false);
            }
        }
        TreeNode::File { content, .. } => {
            sizes.total_size += content.len() as u64;
            sizes.size_on_disk += crate::size::align_size(content.len() as u64, block_size);
            sizes.file_count += 1;
        }
        TreeNode::Symlink { target, .. } => {
            sizes.size_on_disk += crate::size::align_size(target.len() as u64, block_size);
            sizes.file_count += 1;
        }
        TreeNode::Device { .. } | TreeNode::Fifo { .. } => {
            // Device and fifo nodes occupy no data blocks (only metadata).
        }
    }
}

/// Whether any node in `root` carries extended attributes.
///
/// CPIO's newc format has no place for xattrs, so callers that can choose an
/// archive format use this to fall back to tar (which stores them as PAX
/// records) instead of silently dropping them.
pub(crate) fn tree_has_xattrs(root: &TreeNode) -> bool {
    match root {
        TreeNode::Dir { meta, children } => {
            !meta.xattrs.is_empty() || children.values().any(tree_has_xattrs)
        }
        TreeNode::File { meta, .. }
        | TreeNode::Symlink { meta, .. }
        | TreeNode::Device { meta, .. }
        | TreeNode::Fifo { meta } => !meta.xattrs.is_empty(),
    }
}

/// Build a zstd-compressed archive of `files_set` into `output_file`.
pub fn build_archive(
    files_set: &ResolvedFilesSet,
    format: ArchiveFormat,
    output_file: &Path,
    compression_level: i32,
) -> Result<()> {
    let root = collect_tree(files_set)?;
    build_archive_from_tree(&root, format, output_file, compression_level)
}

/// Walk every source of a [`ResolvedFilesSet`] and build the in-memory tree,
/// applying include/exclude patterns and synthesizing parent directories.
/// Local-path sources are walked from disk; virtual files are read in
/// memory; virtual trees are walked in-memory through their FS backend.
pub fn collect_tree(files_set: &ResolvedFilesSet) -> Result<TreeNode> {
    let mut root = TreeNode::Dir {
        meta: Meta::default_dir(),
        children: BTreeMap::new(),
    };
    for entry in files_set {
        let destination = &entry.destination;
        let includes: &[String] = entry.include_pattern.as_deref().unwrap_or(&[]);
        let excludes: &[String] = entry.exclude_patterns.as_deref().unwrap_or(&[]);

        match &entry.source {
            ResolvedSource::Path(source) => {
                let meta = fs::symlink_metadata(source)
                    .map_err(|e| Error::msg(format!("Cannot stat input \"{source:?}\": {e}")))?;
                if meta.is_dir() {
                    walk_source_dir(source, destination, includes, excludes, &mut root)?;
                } else {
                    // A single file/symlink/device → placed at `destination`.
                    let entry_meta = read_meta(&meta, source)?;
                    insert_leaf(
                        &mut root,
                        destination,
                        make_leaf(&meta, entry_meta, source)?,
                    );
                }
            }
            ResolvedSource::File(vf) => {
                use std::io::Read as _;
                let mut r = (vf.open)()?;
                let mut content = Vec::with_capacity(vf.size as usize);
                r.read_to_end(&mut content)
                    .map_err(|e| Error::msg(format!("Cannot read input: {e}")))?;
                insert_leaf(
                    &mut root,
                    destination,
                    TreeNode::File {
                        meta: vf.meta.clone().unwrap_or_else(|| file_meta(0o644)),
                        content,
                    },
                );
            }
            ResolvedSource::Tree(tree) => {
                tree.collect_into(destination, includes, excludes, &mut root)?;
            }
        }
    }
    Ok(root)
}

/// Recursively walk `source` and insert every matching entry under `destination`.
fn walk_source_dir(
    source: &Path,
    destination: &str,
    includes: &[String],
    excludes: &[String],
    root: &mut TreeNode,
) -> Result<()> {
    let include_pats = compile_patterns(includes);
    let exclude_pats = compile_patterns(excludes);
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Skip the root itself from exclude matching; filter relative paths.
            if e.depth() == 0 {
                return true;
            }
            let rel = e.path().strip_prefix(source).unwrap_or(e.path());
            let rel_str = path_to_string(rel);
            !is_excluded(&rel_str, &exclude_pats)
        })
    {
        let entry = entry.map_err(|e| Error::msg(format!("walkdir error: {e}")))?;
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry.path().strip_prefix(source).unwrap_or(entry.path());
        let rel_str = path_to_string(rel);
        if !is_included(&rel_str, &include_pats) {
            continue;
        }
        let name = join_path(destination, &rel_str);
        let meta = entry
            .metadata()
            .map_err(|e| Error::msg(format!("walkdir metadata: {e}")))?;
        let m = read_meta(&meta, entry.path())?;
        insert_leaf(root, &name, make_leaf_from_ftype(&meta, m, &entry)?);
    }
    Ok(())
}

pub(crate) fn compile_patterns(pats: &[String]) -> Vec<glob::Pattern> {
    pats.iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect()
}

/// A relative entry is included if it matches at least one include pattern
/// (default `**` matches everything).
pub(crate) fn is_included(rel: &str, include_pats: &[glob::Pattern]) -> bool {
    if include_pats.is_empty() {
        return true;
    }
    include_pats.iter().any(|p| p.matches(rel))
}

/// A relative entry is excluded if it or any ancestor prefix matches an
/// exclude pattern (so excluding a directory drops its whole subtree).
pub(crate) fn is_excluded(rel: &str, exclude_pats: &[glob::Pattern]) -> bool {
    let mut acc = String::new();
    for part in rel.split('/') {
        if acc.is_empty() {
            acc.push_str(part);
        } else {
            acc.push('/');
            acc.push_str(part);
        }
        if exclude_pats.iter().any(|p| p.matches(&acc)) {
            return true;
        }
    }
    false
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Join a destination prefix and a relative path with a `/`.
pub(crate) fn join_path(prefix: &str, rel: &str) -> String {
    let rel = rel.trim_start_matches("./");
    if prefix.is_empty() || prefix == "." {
        rel.to_string()
    } else if rel.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{rel}")
    }
}

#[cfg(unix)]
fn read_meta(meta: &fs::Metadata, path: &Path) -> Result<Meta> {
    use std::os::unix::fs::MetadataExt;
    Ok(Meta {
        perms: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: meta.mtime() as u32,
        xattrs: read_xattrs(path)?,
    })
}

#[cfg(not(unix))]
fn read_meta(meta: &fs::Metadata, _path: &Path) -> Result<Meta> {
    let perms = if meta.is_dir() { 0o755 } else { 0o644 };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    Ok(Meta {
        perms,
        uid: 0,
        gid: 0,
        mtime,
        xattrs: Vec::new(),
    })
}

/// Read all extended attributes of `path` without following symlinks.
///
/// Filesystems that do not support xattrs simply yield an empty list. A single
/// inaccessible attribute is skipped with a warning (matching `mkfs.erofs`);
/// other errors are reported with the path for context.
#[cfg(unix)]
fn read_xattrs(path: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use std::ffi::OsStr;
    use std::io::ErrorKind;
    use std::os::unix::ffi::OsStrExt;

    let names = match xattr::list(path) {
        Ok(names) => names,
        Err(e) if e.kind() == ErrorKind::Unsupported => return Ok(Vec::new()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            eprintln!(
                "archive: skipping xattrs of {}: {e}",
                path.to_string_lossy()
            );
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(Error::msg(format!(
                "cannot list xattrs of \"{}\": {e}",
                path.display()
            )));
        }
    };

    let mut out = Vec::new();
    for name in names {
        let name_bytes = name.as_os_str().as_bytes().to_vec();
        match xattr::get(path, &name) {
            Ok(Some(value)) => out.push((name_bytes, value)),
            Ok(None) => {}
            Err(e) if e.kind() == ErrorKind::Unsupported || e.kind() == ErrorKind::NotFound => {}
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                eprintln!(
                    "archive: skipping inaccessible xattr {} on {}: {e}",
                    String::from_utf8_lossy(&name_bytes),
                    path.to_string_lossy()
                );
            }
            Err(e) => {
                return Err(Error::msg(format!(
                    "cannot read xattr {} of \"{}\": {e}",
                    String::from_utf8_lossy(&name_bytes),
                    path.display()
                )));
            }
        }
    }
    // Some overlay/FUSE mounts used for container-image inputs hide the
    // security namespace from `listxattr`. Probe the capability attribute
    // directly so file capabilities are not silently dropped before the image
    // is even built. Ignore errors here: the attribute is usually absent.
    const CAPABILITY: &[u8] = b"security.capability";
    if !out.iter().any(|(name, _)| name == CAPABILITY)
        && let Ok(Some(value)) = xattr::get(path, OsStr::from_bytes(CAPABILITY))
    {
        out.push((CAPABILITY.to_vec(), value));
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(not(unix))]
fn read_xattrs(_path: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(Vec::new())
}

/// Build a leaf [`TreeNode`] from a single (non-directory) source path.
fn make_leaf(meta: &fs::Metadata, m: Meta, source: &Path) -> Result<TreeNode> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(source)?;
        Ok(TreeNode::Symlink {
            meta: m,
            target: target.to_string_lossy().into_owned(),
        })
    } else if ft.is_file() {
        let content = fs::read(source)?;
        Ok(TreeNode::File { meta: m, content })
    } else if ft.is_dir() {
        Ok(TreeNode::Dir {
            meta: m,
            children: BTreeMap::new(),
        })
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let major = (meta.rdev() >> 8) as u32;
            let minor = (meta.rdev() & 0xff) as u32;
            let dt = if ft.is_block_device() {
                FileType::BlockDevice
            } else if ft.is_char_device() {
                FileType::CharDevice
            } else {
                return Ok(TreeNode::Fifo { meta: m });
            };
            Ok(TreeNode::Device {
                meta: m,
                dev_type: dt,
                major,
                minor,
            })
        }
        #[cfg(not(unix))]
        Ok(TreeNode::Fifo { meta: m })
    }
}

/// Build a leaf [`TreeNode`] from a walkdir entry whose file type is known
/// through the directory entry (so symlinks are detected correctly).
fn make_leaf_from_ftype(
    meta: &fs::Metadata,
    m: Meta,
    entry: &walkdir::DirEntry,
) -> Result<TreeNode> {
    let ft = entry.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(entry.path())?;
        Ok(TreeNode::Symlink {
            meta: m,
            target: target.to_string_lossy().into_owned(),
        })
    } else if ft.is_dir() {
        Ok(TreeNode::Dir {
            meta: m,
            children: BTreeMap::new(),
        })
    } else if ft.is_file() {
        let content = fs::read(entry.path())?;
        Ok(TreeNode::File { meta: m, content })
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let major = (meta.rdev() >> 8) as u32;
            let minor = (meta.rdev() & 0xff) as u32;
            let dt = if ft.is_block_device() {
                FileType::BlockDevice
            } else if ft.is_char_device() {
                FileType::CharDevice
            } else {
                return Ok(TreeNode::Fifo { meta: m });
            };
            Ok(TreeNode::Device {
                meta: m,
                dev_type: dt,
                major,
                minor,
            })
        }
        #[cfg(not(unix))]
        Ok(TreeNode::Fifo { meta: m })
    }
}

/// Insert a regular file (mode 0644, root-owned) at `path` relative to the
/// tree root, creating synthetic parent directories as needed. An existing
/// node at `path` is replaced.
pub fn insert_file(root: &mut TreeNode, path: &str, content: Vec<u8>) {
    insert_leaf(
        root,
        path,
        TreeNode::File {
            meta: file_meta(0o644),
            content,
        },
    );
}

/// Insert a leaf at `path`, creating synthetic parent directories.
pub(crate) fn insert_leaf(root: &mut TreeNode, path: &str, leaf: TreeNode) {
    let path = path.trim_start_matches("./");
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    insert_leaf_parts(root, &parts, leaf);
}

fn insert_leaf_parts(root: &mut TreeNode, parts: &[&str], leaf: TreeNode) {
    let cur = root;
    let mut node = cur;
    for (i, part) in parts.iter().enumerate() {
        if i + 1 == parts.len() {
            let children = match node {
                TreeNode::Dir { children, .. } => children,
                _ => return,
            };
            // If a synthetic dir was created here, a real leaf replaces it only
            // when the leaf is itself a directory; otherwise keep the dir and
            // ignore (matches the TS `writeDir` early-return for known dirs).
            match leaf {
                TreeNode::Dir { .. } => {
                    children.entry(part.to_string()).or_insert(leaf);
                }
                other => {
                    children.insert(part.to_string(), other);
                }
            }
            return;
        }
        node = get_or_create_child_dir(node, part);
    }
}

/// Get a mutable reference to a child directory, creating a synthetic one if
/// absent. If a non-directory node already occupies the name, it is replaced.
fn get_or_create_child_dir<'a>(node: &'a mut TreeNode, name: &str) -> &'a mut TreeNode {
    let children = match node {
        TreeNode::Dir { children, .. } => children,
        _ => return node,
    };
    if !children.contains_key(name) {
        children.insert(
            name.to_string(),
            TreeNode::Dir {
                meta: Meta::default_dir(),
                children: BTreeMap::new(),
            },
        );
    }
    children.get_mut(name).unwrap()
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

/// Convert the in-memory tree into a hadris [`FileTree`].
fn tree_to_file_tree(root: &TreeNode) -> FileTree {
    let mut out = FileTree::new();
    if let TreeNode::Dir { children, .. } = root {
        for (name, node) in children {
            if let Some(fn_node) = to_file_node(name, node) {
                out.add(fn_node);
            }
        }
    }
    out
}

fn to_file_node(name: &str, node: &TreeNode) -> Option<FileNode> {
    match node {
        TreeNode::Dir { meta, children } => {
            let mut kids = Vec::new();
            for (n, c) in children {
                if let Some(fn_node) = to_file_node(n, c) {
                    kids.push(fn_node);
                }
            }
            Some(FileNode::dir_with_owner(
                name, kids, meta.perms, meta.uid, meta.gid, meta.mtime,
            ))
        }
        TreeNode::File { meta, content } => Some(FileNode::file_with_owner(
            name,
            content.clone(),
            meta.perms,
            meta.uid,
            meta.gid,
            meta.mtime,
        )),
        TreeNode::Symlink { meta, target } => Some(FileNode::Symlink {
            name: std::sync::Arc::new(name.to_string()),
            target: target.clone(),
            permissions: meta.perms,
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
        }),
        TreeNode::Device {
            meta,
            dev_type,
            major,
            minor,
        } => Some(FileNode::DeviceNode {
            name: std::sync::Arc::new(name.to_string()),
            device_type: *dev_type,
            major: *major,
            minor: *minor,
            permissions: meta.perms,
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
        }),
        TreeNode::Fifo { meta } => Some(FileNode::Fifo {
            name: std::sync::Arc::new(name.to_string()),
            permissions: meta.perms,
            uid: meta.uid,
            gid: meta.gid,
            mtime: meta.mtime,
        }),
    }
}

fn write_cpio(root: &TreeNode, output_file: &Path, compression_level: i32) -> Result<()> {
    let tree = tree_to_file_tree(root);
    let file = fs::File::create(output_file)?;
    let encoder = zstd::stream::Encoder::new(file, compression_level)
        .map_err(|e| Error::msg(format!("zstd encoder: {e}")))?;
    let writer = CpioArchiveWriter::new(encoder, CpioWriteOptions { use_crc: false });
    let encoder = writer
        .finish(&tree)
        .map_err(|e| Error::msg(format!("cpio write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| Error::msg(format!("zstd finish: {e}")))?;
    Ok(())
}

fn write_tar(root: &TreeNode, output_file: &Path, compression_level: i32) -> Result<()> {
    let file = fs::File::create(output_file)?;
    let mut encoder = zstd::stream::Encoder::new(file, compression_level)
        .map_err(|e| Error::msg(format!("zstd encoder: {e}")))?;
    {
        let mut builder = tar::Builder::new(&mut encoder);
        append_tree_tar(&mut builder, "", root)?;
        builder
            .finish()
            .map_err(|e| Error::msg(format!("tar finish: {e}")))?;
    }
    encoder
        .finish()
        .map_err(|e| Error::msg(format!("zstd finish: {e}")))?;
    Ok(())
}

fn append_tree_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    prefix: &str,
    node: &TreeNode,
) -> Result<()> {
    if let TreeNode::Dir { children, .. } = node {
        for (name, child) in children {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            append_tar_node(builder, &path, child)?;
        }
    }
    Ok(())
}

/// Append PAX extended-header records carrying `xattrs`.
///
/// GNU tar (and Rust's `tar` reader) represents extended attributes as
/// `SCHILY.xattr.<fully-qualified-name>` PAX records attached to the following
/// entry. Emitting them before every node keeps xattrs across a tar round-trip
/// (and lets an EROFS built from that tar preserve them too).
fn append_tar_xattrs<W: Write>(
    builder: &mut tar::Builder<W>,
    xattrs: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    let mut headers: Vec<(String, &[u8])> = Vec::with_capacity(xattrs.len());
    for (name, value) in xattrs {
        let Ok(name) = std::str::from_utf8(name) else {
            eprintln!("tar: skipping xattr with a non-UTF-8 name");
            continue;
        };
        // The PAX key itself must be representable: `=` separates key from
        // value and a newline terminates the record.
        if name.is_empty() || name.bytes().any(|b| b == b'=' || b == b'\n' || b == 0) {
            eprintln!("tar: skipping xattr with unsupported name {name:?}");
            continue;
        }
        headers.push((format!("SCHILY.xattr.{name}"), value.as_slice()));
    }
    if headers.is_empty() {
        return Ok(());
    }
    builder
        .append_pax_extensions(headers.iter().map(|(name, value)| (name.as_str(), *value)))
        .map_err(io_err)?;
    Ok(())
}

fn append_tar_node<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    node: &TreeNode,
) -> Result<()> {
    let xattrs = match node {
        TreeNode::Dir { meta, .. }
        | TreeNode::File { meta, .. }
        | TreeNode::Symlink { meta, .. }
        | TreeNode::Device { meta, .. }
        | TreeNode::Fifo { meta } => &meta.xattrs,
    };
    append_tar_xattrs(builder, xattrs)?;

    let mut header = tar::Header::new_gnu();
    match node {
        TreeNode::Dir { meta, .. } => {
            header.set_size(0);
            header.set_mode(meta.perms);
            header.set_uid(meta.uid as u64);
            header.set_gid(meta.gid as u64);
            header.set_mtime(meta.mtime as u64);
            header.set_entry_type(tar::EntryType::Directory);
            builder
                .append_data(&mut header, path, &[][..])
                .map_err(io_err)?;
            append_tree_tar(builder, path, node)?;
        }
        TreeNode::File { meta, content } => {
            header.set_size(content.len() as u64);
            header.set_mode(meta.perms);
            header.set_uid(meta.uid as u64);
            header.set_gid(meta.gid as u64);
            header.set_mtime(meta.mtime as u64);
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, path, &content[..])
                .map_err(io_err)?;
        }
        TreeNode::Symlink { meta, target } => {
            header.set_size(0);
            header.set_mode(meta.perms);
            header.set_uid(meta.uid as u64);
            header.set_gid(meta.gid as u64);
            header.set_mtime(meta.mtime as u64);
            header.set_entry_type(tar::EntryType::Symlink);
            builder
                .append_link(&mut header, path, target)
                .map_err(io_err)?;
        }
        TreeNode::Device {
            meta,
            dev_type,
            major,
            minor,
        } => {
            header.set_size(0);
            header.set_mode(meta.perms);
            header.set_uid(meta.uid as u64);
            header.set_gid(meta.gid as u64);
            header.set_mtime(meta.mtime as u64);
            let et = match dev_type {
                FileType::BlockDevice => tar::EntryType::Block,
                FileType::CharDevice => tar::EntryType::Char,
                _ => tar::EntryType::Regular,
            };
            header.set_entry_type(et);
            header.set_device_major(*major).map_err(io_err)?;
            header.set_device_minor(*minor).map_err(io_err)?;
            builder
                .append_data(&mut header, path, &[][..])
                .map_err(io_err)?;
        }
        TreeNode::Fifo { meta } => {
            header.set_size(0);
            header.set_mode(meta.perms);
            header.set_uid(meta.uid as u64);
            header.set_gid(meta.gid as u64);
            header.set_mtime(meta.mtime as u64);
            header.set_entry_type(tar::EntryType::Fifo);
            builder
                .append_data(&mut header, path, &[][..])
                .map_err(io_err)?;
        }
    }
    Ok(())
}

fn io_err(e: std::io::Error) -> Error {
    Error::from(e)
}

// ---------------------------------------------------------------------------
// Public extract/repack helpers
// ---------------------------------------------------------------------------

/// Compute the content sizes of an in-memory tree, as if laid out on a
/// filesystem with the given `block_size` (in bytes).
pub fn tree_content_sizes(root: &TreeNode, block_size: u64) -> ContentSizes {
    let mut sizes = ContentSizes::default();
    measure_tree(root, block_size, &mut sizes, true);
    sizes
}

/// Extract a zstd-compressed archive (cpio or tar) into an in-memory tree.
pub fn extract_archive_to_tree(archive: &Path, format: ArchiveFormat) -> Result<TreeNode> {
    let compressed = fs::File::open(archive)?;
    let decoder = zstd::Decoder::new(compressed).map_err(|e| Error::msg(format!("zstd: {e}")))?;
    match format {
        ArchiveFormat::Cpio => extract_cpio_to_tree(decoder),
        ArchiveFormat::Tar => extract_tar_to_tree(decoder),
    }
}

/// Build a zstd-compressed archive of an in-memory tree into `output_file`.
pub fn build_archive_from_tree(
    root: &TreeNode,
    format: ArchiveFormat,
    output_file: &Path,
    compression_level: i32,
) -> Result<()> {
    match format {
        ArchiveFormat::Cpio => write_cpio(root, output_file, compression_level),
        ArchiveFormat::Tar => write_tar(root, output_file, compression_level),
    }
}

fn cpio_err(e: hadris_cpio::Error) -> Error {
    Error::msg(format!("cpio: {e}"))
}

pub(crate) fn normalize_archive_path(name: &str) -> Option<String> {
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

fn extract_cpio_to_tree<R: Read>(reader: R) -> Result<TreeNode> {
    let mut root = TreeNode::Dir {
        meta: Meta::default_dir(),
        children: BTreeMap::new(),
    };
    let mut cr = CpioArchiveReader::new(reader);
    while let Some(entry) = cr.next_entry_alloc().map_err(cpio_err)? {
        let name = entry
            .name_str()
            .map_err(|e| Error::msg(e.to_string()))?
            .to_string();
        let path = match normalize_archive_path(&name) {
            Some(p) => p,
            None => continue,
        };
        let mode = entry.header().permissions() as u16;
        let data = cr.read_entry_data_alloc(&entry).map_err(cpio_err)?;
        match entry.file_type() {
            FileType::Directory => {
                insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Dir {
                        meta: dir_meta(mode),
                        children: BTreeMap::new(),
                    },
                );
            }
            FileType::Symlink => {
                let target = String::from_utf8(data).map_err(|e| Error::msg(e.to_string()))?;
                insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Symlink {
                        meta: file_meta(mode),
                        target,
                    },
                );
            }
            FileType::Regular => {
                insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::File {
                        meta: file_meta(mode),
                        content: data,
                    },
                );
            }
            FileType::BlockDevice | FileType::CharDevice => {
                let major = entry.header().rdevmajor;
                let minor = entry.header().rdevminor;
                insert_leaf(
                    &mut root,
                    &path,
                    TreeNode::Device {
                        meta: file_meta(mode),
                        dev_type: entry.file_type(),
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

/// Extract extended attributes carried in a tar entry's PAX records.
///
/// Two conventions are in the wild:
/// - GNU tar (and Rust's `tar` writer) uses `SCHILY.xattr.<name>` with the raw
///   value bytes.
/// - libarchive/bsdtar (and therefore most OCI/bootstrap tarballs) uses
///   `LIBARCHIVE.xattr.<name>` with the value encoded as standard base64.
///
/// Supporting both matters for file capabilities: a tarball built by bsdtar
/// would otherwise silently lose `security.capability`.
pub(crate) fn tar_pax_xattrs<R: Read>(
    entry: &mut tar::Entry<'_, R>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use base64::Engine as _;

    let mut xattrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    if let Some(extensions) = entry
        .pax_extensions()
        .map_err(|e| Error::msg(format!("tar: pax extensions: {e}")))?
    {
        for extension in extensions {
            let extension =
                extension.map_err(|e| Error::msg(format!("tar: pax extension: {e}")))?;
            let key = extension.key_bytes();
            if let Some(name) = key.strip_prefix(b"SCHILY.xattr.".as_slice()) {
                xattrs.push((name.to_vec(), extension.value_bytes().to_vec()));
            } else if let Some(name) = key.strip_prefix(b"LIBARCHIVE.xattr.".as_slice()) {
                let value = base64::engine::general_purpose::STANDARD
                    .decode(extension.value_bytes())
                    .or_else(|_| {
                        base64::engine::general_purpose::STANDARD_NO_PAD
                            .decode(extension.value_bytes())
                    })
                    .map_err(|e| {
                        Error::msg(format!(
                            "tar: invalid base64 in LIBARCHIVE.xattr {}: {e}",
                            String::from_utf8_lossy(name)
                        ))
                    })?;
                xattrs.push((name.to_vec(), value));
            }
        }
    }
    // If both conventions describe the same attribute, keep the first one (a
    // raw SCHILY record sorts before the base64 LIBARCHIVE one only by name,
    // so dedupe explicitly while preserving the parsed order).
    let mut seen = std::collections::BTreeSet::new();
    xattrs.retain(|(name, _)| seen.insert(name.clone()));
    xattrs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(xattrs)
}

fn extract_tar_to_tree<R: Read>(reader: R) -> Result<TreeNode> {
    let mut root = TreeNode::Dir {
        meta: Meta::default_dir(),
        children: BTreeMap::new(),
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive
        .entries()
        .map_err(|e| Error::msg(format!("tar: {e}")))?
    {
        let mut entry = entry.map_err(|e| Error::msg(format!("tar: {e}")))?;
        let xattrs = tar_pax_xattrs(&mut entry)?;
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
        let mode = (header.mode().map_err(|e| Error::msg(format!("tar: {e}")))? & 0o7777) as u16;
        let meta = Meta {
            perms: mode as u32,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs,
        };
        match entry_type {
            tar::EntryType::Directory => {
                insert_leaf(
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
                insert_leaf(
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
                insert_leaf(&mut root, &path, TreeNode::Symlink { meta, target });
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
                insert_leaf(
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

fn dir_meta(mode: u16) -> Meta {
    Meta {
        perms: mode as u32,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: Vec::new(),
    }
}

fn file_meta(mode: u16) -> Meta {
    Meta {
        perms: mode as u32,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: Vec::new(),
    }
}
