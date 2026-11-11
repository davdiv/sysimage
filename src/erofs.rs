//! EROFS image building.
//!
//! Converts a [`TreeNode`] tree (produced by [`crate::archive::collect_tree`]
//! from a [`ConfigFilesSet`]) into an in-memory `fs_erofs::Node` tree,
//! optionally compresses regular files (LZ4 by default), builds the image with
//! `rust-fs-erofs`, then patches the superblock UUID and recomputes the CRC32C
//! checksum entirely in process.

use std::collections::BTreeMap;

pub use fs_erofs::mkfs::XattrSpec;
use fs_erofs::mkfs::{
    CompressedAlgo, CompressedFileSpec, CompressedIndexFormat, Node, NodeMeta, build_image,
};

use crate::archive::{Meta, TreeNode};
use crate::error::{Error, Result};

/// Superblock offset (bytes) within an EROFS image.
const EROFS_SUPER_OFFSET: usize = 1024;
/// EROFS magic (`0xe0f5e1e2`, little-endian).
const EROFS_SUPER_MAGIC: u32 = 0xe0f5e1e2;

/// Compression algorithm for EROFS regular files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsCompression {
    None,
    Lz4,
    Lzma,
    Deflate,
}

impl ErofsCompression {
    fn to_algo(self) -> Option<CompressedAlgo> {
        match self {
            ErofsCompression::None => None,
            ErofsCompression::Lz4 => Some(CompressedAlgo::Lz4),
            ErofsCompression::Lzma => Some(CompressedAlgo::Lzma),
            ErofsCompression::Deflate => Some(CompressedAlgo::Deflate),
        }
    }
}

/// Configuration for building an EROFS image.
pub struct ErofsBuildConfig<'a> {
    /// The in-memory file tree (from [`crate::archive::collect_tree`]).
    pub root: &'a TreeNode,
    pub block_size: u32,
    /// Build timestamp in milliseconds (converted to seconds for mtimes).
    pub timestamp_ms: u64,
    pub compression: ErofsCompression,
}

/// Build an EROFS image (with an all-zero UUID) and return it in memory.
///
/// This is the borrowed convenience form. For a build pipeline, prefer
/// [`build_erofs_image_owned`], which consumes the tree instead of cloning
/// every file's contents.
pub fn build_erofs_image(cfg: &ErofsBuildConfig) -> Result<Vec<u8>> {
    build_erofs_image_owned(
        cfg.root.clone(),
        cfg.block_size,
        cfg.timestamp_ms,
        cfg.compression,
    )
}

/// Build an EROFS image from an owned file tree.
///
/// Consuming the tree lets the conversion move each file's bytes into the
/// EROFS node instead of cloning them, which avoids holding a second complete
/// copy of the rootfs in memory. This matters for large container rootfs
/// images, where the old borrowed path could use roughly twice the rootfs
/// size just for the tree.
pub fn build_erofs_image_owned(
    root: TreeNode,
    block_size: u32,
    timestamp_ms: u64,
    compression: ErofsCompression,
) -> Result<Vec<u8>> {
    let blkszbits = log2_block_size(block_size)?;
    let root = tree_to_erofs(root, timestamp_ms, compression)?;
    let image = build_image(root, blkszbits).map_err(map_erofs_err)?;
    Ok(image)
}

/// Patch the EROFS superblock UUID at offset `0x30` and recompute the CRC32C
/// superblock checksum. Returns the formatted UUID string.
pub fn erofs_set_uuid(image: &mut [u8], uuid: [u8; 16]) -> Result<String> {
    let off = EROFS_SUPER_OFFSET;
    if image.len() < off + 0x40 {
        return Err(Error::msg("EROFS image too small for a superblock"));
    }
    let magic = u32::from_le_bytes(image[off..off + 4].try_into().unwrap());
    if magic != EROFS_SUPER_MAGIC {
        return Err(Error::msg(format!(
            "Missing EROFS signature (got 0x{magic:08x})"
        )));
    }
    let blkszbits = image[off + 0x0c];
    let block_size = 1usize << blkszbits;
    let crc_len = block_size - (off % block_size);
    if image.len() < off + crc_len {
        return Err(Error::msg("EROFS image too small for the superblock block"));
    }
    // Zero the checksum field, set the UUID, then recompute.
    image[off + 0x04..off + 0x08].copy_from_slice(&0u32.to_le_bytes());
    image[off + 0x30..off + 0x40].copy_from_slice(&uuid);
    let csum = crc32c::crc32c(&image[off..off + crc_len]) ^ 0xFFFF_FFFF;
    image[off + 0x04..off + 0x08].copy_from_slice(&csum.to_le_bytes());
    let mut uuid_arr = [0u8; 16];
    uuid_arr.copy_from_slice(&image[off + 0x30..off + 0x40]);
    Ok(crate::uuid::format_uuid(&uuid_arr))
}

fn log2_block_size(block_size: u32) -> Result<u8> {
    if !(512..=4096).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(Error::msg(format!(
            "invalid EROFS block size: {block_size}"
        )));
    }
    Ok(block_size.trailing_zeros() as u8)
}

// Unix mode bits for constructing full `st_mode`-style values from the
// permission-only `Meta.perms` stored in [`TreeNode`].
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFBLK: u32 = 0o060000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;

/// Permission bits, including `S_ISUID` (`0o4000`), `S_ISGID` (`0o2000`) and
/// the sticky bit (`0o1000`). Must stay wider than `0o777`.
const MODE_PERM_MASK: u32 = 0o7777;

/// Combine a file-type nibble with the source's permission bits, preserving
/// setuid/setgid/sticky.
fn node_mode(type_bits: u32, perms: u32) -> u16 {
    (type_bits | (perms & MODE_PERM_MASK)) as u16
}

fn node_meta(meta: &Meta, timestamp_ms: u64) -> NodeMeta {
    NodeMeta {
        uid: meta.uid,
        gid: meta.gid,
        mtime: timestamp_ms / 1000,
        mtime_nsec: 0,
    }
}

/// Map full Linux xattr names to EROFS namespace entries.
///
/// The on-disk format stores a namespace index plus the part of the name
/// after that namespace's prefix. POSIX ACL slots use an empty name because
/// the namespace index implies the full attribute name.
fn xattr_specs(meta: &Meta) -> Result<Vec<XattrSpec>> {
    let mut out = Vec::with_capacity(meta.xattrs.len());
    for (name, value) in &meta.xattrs {
        let (name_index, suffix): (u8, &[u8]) = if name.as_slice() == b"system.posix_acl_access" {
            (2, &[])
        } else if name.as_slice() == b"system.posix_acl_default" {
            (3, &[])
        } else if let Some(suffix) = name.strip_prefix(b"user.".as_slice()) {
            (1, suffix)
        } else if let Some(suffix) = name.strip_prefix(b"trusted.".as_slice()) {
            (4, suffix)
        } else if let Some(suffix) = name.strip_prefix(b"lustre.".as_slice()) {
            (5, suffix)
        } else if let Some(suffix) = name.strip_prefix(b"security.".as_slice()) {
            (6, suffix)
        } else {
            // EROFS has no kernel namespace for arbitrary prefixes. `mkfs.erofs`
            // likewise skips attributes it does not recognise.
            eprintln!(
                "erofs: skipping unsupported xattr {}",
                String::from_utf8_lossy(name)
            );
            continue;
        };

        if suffix.len() > u8::MAX as usize {
            return Err(Error::msg(format!(
                "erofs: xattr name too long ({} bytes): {}",
                suffix.len(),
                String::from_utf8_lossy(name)
            )));
        }
        if value.len() > u16::MAX as usize {
            return Err(Error::msg(format!(
                "erofs: xattr value too long ({} bytes): {}",
                value.len(),
                String::from_utf8_lossy(name)
            )));
        }
        out.push(XattrSpec {
            name_index,
            name: suffix.to_vec(),
            value: value.clone(),
        });
    }
    Ok(out)
}

/// Convert a [`TreeNode`] (shared with the archive builder) into an EROFS
/// [`Node`] tree, applying compression to regular files as configured.
///
/// The tree is consumed: each file's `Vec<u8>` is moved into the resulting
/// node rather than cloned. This keeps peak memory close to one copy of the
/// rootfs instead of two.
fn tree_to_erofs(node: TreeNode, timestamp_ms: u64, compression: ErofsCompression) -> Result<Node> {
    match node {
        TreeNode::Dir { meta, children } => {
            let nm = node_meta(&meta, timestamp_ms);
            let xattrs = xattr_specs(&meta)?;
            let mut entries: BTreeMap<String, Node> = BTreeMap::new();
            for (name, child) in children {
                entries.insert(name, tree_to_erofs(child, timestamp_ms, compression)?);
            }
            Ok(Node::Dir {
                mode: node_mode(S_IFDIR, meta.perms),
                entries,
                meta: nm,
                xattrs,
            })
        }
        TreeNode::File { meta, content } => {
            let nm = node_meta(&meta, timestamp_ms);
            let xattrs = xattr_specs(&meta)?;
            Ok(make_file_node(
                node_mode(S_IFREG, meta.perms),
                content,
                nm,
                xattrs,
                compression,
            ))
        }
        TreeNode::Symlink { meta, target } => {
            let nm = node_meta(&meta, timestamp_ms);
            let xattrs = xattr_specs(&meta)?;
            Ok(Node::Symlink {
                mode: node_mode(S_IFLNK, meta.perms),
                target,
                meta: nm,
                xattrs,
            })
        }
        TreeNode::Device {
            meta,
            dev_type,
            major,
            minor,
        } => {
            let nm = node_meta(&meta, timestamp_ms);
            let xattrs = xattr_specs(&meta)?;
            let type_bits = match dev_type {
                crate::archive::FileType::BlockDevice => S_IFBLK,
                crate::archive::FileType::CharDevice => S_IFCHR,
                _ => S_IFCHR,
            };
            Ok(Node::Device {
                mode: node_mode(type_bits, meta.perms),
                rdev: (major << 8) | (minor & 0xff),
                meta: nm,
                xattrs,
            })
        }
        TreeNode::Fifo { meta } => {
            let nm = node_meta(&meta, timestamp_ms);
            let xattrs = xattr_specs(&meta)?;
            Ok(Node::Special {
                mode: node_mode(S_IFIFO, meta.perms),
                meta: nm,
                xattrs,
            })
        }
    }
}

/// Build a regular-file node, compressed or not according to `compression`.
fn make_file_node(
    mode: u16,
    data: Vec<u8>,
    meta: NodeMeta,
    xattrs: Vec<XattrSpec>,
    compression: ErofsCompression,
) -> Node {
    match compression.to_algo() {
        None => Node::File {
            mode,
            data,
            meta,
            xattrs,
        },
        Some(algo) => Node::CompressedFile(CompressedFileSpec {
            mode,
            data,
            algo,
            lclusterbits: 0,
            meta,
            xattrs,
            index_format: CompressedIndexFormat::Compacted2B,
            // `ztailpacking` packs a compressed file's tail pcluster inline
            // into its inode block, saving one block on small files. The
            // `rust-fs-erofs` *writer* supports it, but its *reader*'s
            // compressed-cluster resolver rejects the inline-tail pcluster
            // ("header_algo: cluster_type has no codec"), so images built
            // with `ztailpacking: true` cannot be read back by the same
            // crate — which is exactly what the descent input path does.
            // Disable it so sysimage-built EROFS images are readable by
            // both the kernel and our pure-Rust reader.
            ztailpacking: false,
            target_pcluster_blocks: 1,
        }),
    }
}

fn map_erofs_err(e: fs_erofs::Error) -> Error {
    Error::msg(format!("erofs build: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_xattr_namespaces_to_erofs_indexes() {
        let meta = Meta {
            perms: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: vec![
                (b"user.alpha".to_vec(), b"1".to_vec()),
                (b"trusted.overlay.opaque".to_vec(), b"y".to_vec()),
                (b"security.capability".to_vec(), b"cap".to_vec()),
                (b"system.posix_acl_access".to_vec(), b"acl".to_vec()),
                (b"system.posix_acl_default".to_vec(), b"dacl".to_vec()),
            ],
        };
        let specs = xattr_specs(&meta).unwrap();
        let get = |index: u8| {
            specs
                .iter()
                .find(|spec| spec.name_index == index)
                .unwrap_or_else(|| panic!("missing xattr namespace {index}"))
        };
        assert_eq!(get(1).name, b"alpha");
        assert_eq!(get(1).value, b"1");
        assert_eq!(get(4).name, b"overlay.opaque");
        assert_eq!(get(6).name, b"capability");
        assert_eq!(get(2).name, b"");
        assert_eq!(get(2).value, b"acl");
        assert_eq!(get(3).name, b"");
        assert_eq!(get(3).value, b"dacl");
    }
}
