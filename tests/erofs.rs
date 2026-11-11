//! EROFS build + UUID-patch verification against the system `fsck.erofs`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::archive::collect_tree;
use sysimage::erofs::{ErofsBuildConfig, ErofsCompression, build_erofs_image, erofs_set_uuid};
use sysimage::input::resolve_files_set_paths;
use sysimage::model::config::{ConfigFileEntry, ConfigFilesSet};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-erofs-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

fn make_root(dir: &TempDir) {
    let root = dir.path();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
    fs::write(root.join("hello.txt"), "hello erofs\n".repeat(50)).unwrap();
    fs::create_dir_all(root.join("boot")).unwrap();
    fs::write(root.join("boot").join("vmlinuz"), b"KERNEL").unwrap();
    // An empty subdirectory.
    fs::create_dir_all(root.join("empty")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    }
}

/// Build a `ConfigFilesSet` that maps the root directory to `""`, optionally
/// with an exclude pattern that drops `boot/**`.
fn root_files_set(dir: &TempDir, exclude_boot: bool) -> ConfigFilesSet {
    let entry = ConfigFileEntry {
        destination: String::new(),
        input: dir.path().to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: if exclude_boot {
            Some(vec!["boot/**".to_string()])
        } else {
            None
        },
    };
    vec![entry]
}

fn fsck(image: &Path) -> bool {
    Command::new("fsck.erofs")
        .arg(image)
        .output()
        .map(|o| {
            if !o.status.success() {
                eprintln!("fsck.erofs stderr: {}", String::from_utf8_lossy(&o.stderr));
            }
            o.status.success()
        })
        .unwrap_or(false)
}

#[test]
fn builds_uncompressed_fsck_clean() {
    // Requires both `fsck.erofs` (structural validation) and `dump.erofs`
    // (directory listing to confirm the exclude pattern worked).
    skip_if_missing!("fsck.erofs", "dump.erofs");
    let dir = TempDir::new();
    make_root(&dir);
    let files_set = root_files_set(&dir, true);
    let files_set = resolve_files_set_paths(&files_set, dir.path()).unwrap();
    let root = collect_tree(&files_set).unwrap();
    let cfg = ErofsBuildConfig {
        root: &root,
        block_size: 4096,
        timestamp_ms: 1_700_000_000_000,
        compression: ErofsCompression::None,
    };
    let mut image = build_erofs_image(&cfg).unwrap();
    // Verify the exclude worked: the image should not contain a `boot` dir.
    // (Lightweight check via fsck; deeper structural checks use dump.erofs.)
    let img_path = dir.path().join("rootfs.erofs");
    fs::write(&img_path, &image).unwrap();
    assert!(
        fsck(&img_path),
        "fsck.erofs rejected the uncompressed image"
    );

    // The exclude regex `^boot/.+` must have dropped the `boot` directory.
    let listing = Command::new("dump.erofs")
        .arg("--ls")
        .arg(&img_path)
        .output()
        .unwrap();
    let ls = String::from_utf8_lossy(&listing.stdout).to_string();
    assert!(!ls.contains("boot"), "exclude did not drop `boot`: {ls}");

    let uuid = [0x11u8; 16];
    let uuid_str = erofs_set_uuid(&mut image, uuid).unwrap();
    assert_eq!(uuid_str, "11111111-1111-1111-1111-111111111111");
    fs::write(&img_path, &image).unwrap();
    assert!(
        fsck(&img_path),
        "fsck.erofs rejected the image after UUID patch"
    );
}

#[cfg(unix)]
#[test]
fn preserves_setid_bits_and_xattrs() {
    use std::os::unix::fs::PermissionsExt;

    skip_if_missing!("fsck.erofs");

    let dir = TempDir::new();
    make_root(&dir);
    let privileged = dir.path().join("privileged");
    fs::write(&privileged, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&privileged, fs::Permissions::from_mode(0o6755)).unwrap();

    // Not every host filesystem (or container mount) supports user xattrs.
    if let Err(e) = xattr::set(&privileged, "user.sysimage.test", b"hello xattr") {
        eprintln!("user xattrs not supported here — skipping: {e}");
        return;
    }

    let files_set = root_files_set(&dir, false);
    let files_set = resolve_files_set_paths(&files_set, dir.path()).unwrap();
    let root = collect_tree(&files_set).unwrap();

    for compression in [ErofsCompression::None, ErofsCompression::Lz4] {
        let cfg = ErofsBuildConfig {
            root: &root,
            block_size: 4096,
            timestamp_ms: 1_700_000_000_000,
            compression,
        };
        let image = build_erofs_image(&cfg).unwrap();

        let fs = fs_erofs::Filesystem::open(std::sync::Arc::new(MemDev(image.clone()))).unwrap();
        let inode = fs.lookup_path("privileged").unwrap();
        assert_eq!(
            inode.mode & 0o7777,
            0o6755,
            "setuid/setgid bits were not preserved ({compression:?})"
        );
        let attrs = fs.xattrs(&inode).unwrap();
        assert!(
            attrs
                .iter()
                .any(|(name, value)| name == b"user.sysimage.test" && value == b"hello xattr"),
            "xattr missing from image ({compression:?}): {attrs:?}"
        );

        let img_path = dir.path().join("privileged.erofs");
        fs::write(&img_path, &image).unwrap();
        assert!(
            fsck(&img_path),
            "fsck.erofs rejected an image with setuid/setgid and xattrs"
        );
    }
}

/// A `security.capability` xattr must survive the EROFS writer/reader just like
/// any other namespace. Capabilities are the common way distros mark
/// `newuidmap`/`newgidmap`, so a regression here silently breaks rootless
/// containers in the built image.
#[test]
fn preserves_security_capability_xattr() {
    use std::collections::BTreeMap;
    use sysimage::archive::{Meta, TreeNode};

    // VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, with CAP_SETUID|CAP_SETGID
    // permitted and effective (the value `setcap cap_setuid,cap_setgid+ep`
    // writes on a 64-bit system).
    let cap = vec![
        0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let file_meta = Meta {
        perms: 0o755,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: vec![(b"security.capability".to_vec(), cap.clone())],
    };
    let root = TreeNode::Dir {
        meta: Meta {
            perms: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: Vec::new(),
        },
        children: BTreeMap::from([(
            "newuidmap".to_string(),
            TreeNode::File {
                meta: file_meta,
                content: (0..40_000u32)
                    .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                    .collect::<Vec<u8>>(),
            },
        )]),
    };

    for compression in [ErofsCompression::None, ErofsCompression::Lz4] {
        let image = build_erofs_image(&ErofsBuildConfig {
            root: &root,
            block_size: 4096,
            timestamp_ms: 1_700_000_000_000,
            compression,
        })
        .unwrap();
        let fs = fs_erofs::Filesystem::open(std::sync::Arc::new(MemDev(image))).unwrap();
        let inode = fs.lookup_path("newuidmap").unwrap();
        let attrs = fs.xattrs(&inode).unwrap();
        assert!(
            attrs.iter().any(|(name, value)| {
                name == b"security.capability" && value.as_slice() == cap.as_slice()
            }),
            "security.capability missing or corrupted in EROFS image ({compression:?}): {attrs:?}"
        );
    }
}

/// Minimal in-memory `BlockRead` for inspecting generated images in-process.
struct MemDev(Vec<u8>);

impl fs_core::BlockRead for MemDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::error::Result<()> {
        let offset = offset as usize;
        let end = offset
            .checked_add(buf.len())
            .ok_or_else(|| fs_core::Error::Custom("read offset overflow".to_string()))?;
        if end > self.0.len() {
            return Err(fs_core::Error::OutOfBounds {
                offset: offset as u64,
                len: buf.len() as u64,
                size: self.0.len() as u64,
            });
        }
        buf.copy_from_slice(&self.0[offset..end]);
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
}

#[test]
fn builds_compressed_lz4_fsck_clean() {
    skip_if_missing!("fsck.erofs");
    let dir = TempDir::new();
    make_root(&dir);
    let files_set = root_files_set(&dir, false);
    let files_set = resolve_files_set_paths(&files_set, dir.path()).unwrap();
    let root = collect_tree(&files_set).unwrap();
    let cfg = ErofsBuildConfig {
        root: &root,
        block_size: 4096,
        timestamp_ms: 1_700_000_000_000,
        compression: ErofsCompression::Lz4,
    };
    let image = build_erofs_image(&cfg).unwrap();
    let img_path = dir.path().join("rootfs-lz4.erofs");
    fs::write(&img_path, &image).unwrap();
    assert!(
        fsck(&img_path),
        "fsck.erofs rejected the LZ4-compressed image"
    );
}
