//! Nested-image descent: accessing files deep inside block images/archives
//! produced by one build, as an input to another build — without extraction.
//!
//! These tests exercise the `in:<source>#<descent>` input scheme end to end:
//!
//! - [`descent_into_erofs_file_and_tree`] drives the descent engine directly
//!   against an in-memory EROFS image (file view + directory-tree view).
//! - [`descent_gpt_erofs_via_in_scheme`] runs the full pipeline: build a disk
//!   (GPT → EROFS), install it, then a *second* build references a file inside
//!   the installed disk via `in:` and pulls it into a new EROFS image.
//! - [`descent_luks_erofs_via_in_scheme`] does the same through a LUKS2 layer
//!   (requires `cryptsetup` to create the encrypted container).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::archive::collect_tree;
use sysimage::build::{build_from_file, build_from_file_with_keys};
use sysimage::erofs::{ErofsBuildConfig, ErofsCompression, build_erofs_image};
use sysimage::input::{ResolvedInput, descend, parse_descent, resolve_files_set_paths};
use sysimage::install::{InstallConfig, install};
use sysimage::manifest::{ReadManifestConfig, read_manifest};
use sysimage::model::config::{ConfigFileEntry, ConfigFilesSet};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-descent-{}-{n}", std::process::id()));
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

fn make_rootfs(dir: &Path) {
    fs::create_dir_all(dir.join("etc")).unwrap();
    fs::write(
        dir.join("etc").join("os-release"),
        "ID=descent\nVERSION_ID=1\n",
    )
    .unwrap();
    fs::write(dir.join("hello.txt"), "hello descent\n").unwrap();
    fs::create_dir_all(dir.join("boot")).unwrap();
    fs::write(dir.join("boot").join("vmlinuz"), b"KERNEL").unwrap();
}

/// Read every byte of a [`ResolvedInput::File`].
fn read_virtual_file(r: &ResolvedInput) -> Vec<u8> {
    match r {
        ResolvedInput::File(vf) => {
            let mut reader = (vf.open)().expect("open virtual file");
            let mut buf = Vec::with_capacity(vf.size as usize);
            reader.read_to_end(&mut buf).expect("read virtual file");
            buf
        }
        _ => panic!("expected ResolvedInput::File"),
    }
}

/// Build an EROFS image in memory from a rootfs directory.
fn build_erofs_from_dir(dir: &Path) -> Vec<u8> {
    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: String::new(),
        input: dir.to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];
    let resolved = resolve_files_set_paths(&files, dir).unwrap();
    let root = collect_tree(&resolved).unwrap();
    build_erofs_image(&ErofsBuildConfig {
        root: &root,
        block_size: 4096,
        timestamp_ms: 1_700_000_000_000,
        compression: ErofsCompression::None,
    })
    .unwrap()
}

#[test]
fn descent_into_erofs_file_and_tree() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let image = build_erofs_from_dir(&rootfs);
    let img_path = dir.path().join("rootfs.erofs");
    fs::write(&img_path, &image).unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();

    // --- File view: pull a single file out of the EROFS image. ---
    let steps = parse_descent("erofs:/etc/os-release").unwrap();
    let resolved = descend(&img_path, &steps, &keys).unwrap();
    let content = read_virtual_file(&resolved);
    assert_eq!(content, b"ID=descent\nVERSION_ID=1\n");

    // --- Tree view: walk the whole EROFS root into a TreeNode. ---
    let steps = parse_descent("erofs:/").unwrap();
    let resolved = descend(&img_path, &steps, &keys).unwrap();
    let tree = match resolved {
        ResolvedInput::Tree(t) => t,
        _ => panic!("expected ResolvedInput::Tree for `erofs:/`"),
    };
    let mut root = sysimage::archive::TreeNode::Dir {
        meta: sysimage::archive::Meta {
            perms: 0o0755,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: Vec::new(),
        },
        children: std::collections::BTreeMap::new(),
    };
    tree.collect_into("pulled", &[], &[], &mut root).unwrap();
    // The pulled tree must contain the files we wrote.
    let pulled = match &root {
        sysimage::archive::TreeNode::Dir { children, .. } => children,
        _ => panic!("root must be a Dir"),
    };
    let pulled_dir = match pulled.get("pulled") {
        Some(sysimage::archive::TreeNode::Dir { children, .. }) => children,
        _ => panic!("`pulled` must be a directory"),
    };
    let os_release = match pulled_dir.get("etc").and_then(|d| match d {
        sysimage::archive::TreeNode::Dir { children, .. } => children.get("os-release"),
        _ => None,
    }) {
        Some(sysimage::archive::TreeNode::File { content, .. }) => content,
        _ => panic!("`pulled/etc/os-release` must be a file"),
    };
    assert_eq!(os_release, b"ID=descent\nVERSION_ID=1\n");
    assert!(pulled_dir.contains_key("hello.txt"));
}

/// Locate the single `*.bin` artifact written by a build (used to find the
/// second build's EROFS image, which we then descend back into to verify).
fn only_bin(output: &Path) -> PathBuf {
    let mut bins = Vec::new();
    for entry in fs::read_dir(output).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().ends_with(".bin") {
            bins.push(entry.path());
        }
    }
    assert_eq!(
        bins.len(),
        1,
        "expected exactly one .bin in {output:?}, got {bins:?}"
    );
    bins.pop().unwrap()
}

#[test]
fn descent_gpt_erofs_via_in_scheme() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    // --- Build A: a GPT disk whose `root` partition is an EROFS image. ---
    let output_a = dir.path().join("out-a");
    let temp_a = dir.path().join("tmp-a");
    let config_a = format!(
        r#"
name: diska
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output_a}
tempDirectory: {temp_a}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        rootfs = rootfs.display(),
        output_a = output_a.display(),
        temp_a = temp_a.display(),
    );
    let config_a_path = dir.path().join("a.yml");
    fs::write(&config_a_path, &config_a).unwrap();
    build_from_file(&config_a_path).expect("build A should succeed");

    let disk_image = dir.path().join("disk.img");
    // Pre-size the disk so the installer has room to write.
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&disk_image)
            .unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
    }
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_a_path,
        manifest: None,
    })
    .expect("read manifest A");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: BTreeMap::new(),
        key_file: BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install A should succeed");

    // --- Build B: pull a file out of A's disk via `in:` into a new EROFS. ---
    let output_b = dir.path().join("out-b");
    let temp_b = dir.path().join("tmp-b");
    let disk = disk_image.display();
    let config_b = format!(
        r#"
name: diskb
version: "1"
arch: x86_64
input: {output_b}
outputDirectory: {output_b}
tempDirectory: {temp_b}
build:
  erofs:
    pulled:
      input:
        - destination: "pulled"
          input: "in:{disk}#gpt:root|erofs:/etc/os-release"
disk:
  out:
    type: gpt
    partitions:
      - name: pulled
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:pulled
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        disk = disk,
        output_b = output_b.display(),
        temp_b = temp_b.display(),
    );
    let config_b_path = dir.path().join("b.yml");
    fs::write(&config_b_path, &config_b).unwrap();
    build_from_file(&config_b_path).expect("build B should succeed");

    // --- Verify: descend into B's EROFS and read the pulled file. ---
    // A single-file input is placed AT its `destination` (the destination is
    // the full path, not a directory prefix), so the file lives at `/pulled`.
    let bin_b = only_bin(&output_b);
    let steps = parse_descent("erofs:/pulled").unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let resolved = descend(&bin_b, &steps, &keys).unwrap();
    let content = read_virtual_file(&resolved);
    assert_eq!(content, b"ID=descent\nVERSION_ID=1\n");
}

#[test]
fn descent_luks_erofs_via_in_scheme() {
    // Requires `cryptsetup` to format the LUKS2 container at install time.
    skip_if_missing!("cryptsetup");

    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let passphrase = "correct horse battery staple";
    let output_a = dir.path().join("out-a");
    let temp_a = dir.path().join("tmp-a");
    let config_a = format!(
        r#"
name: diska
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output_a}
tempDirectory: {temp_a}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: luks
          name: cryptroot
          # Use a deliberately lightweight KDF so the descent's
          # `luks_core`-based unlock (which caps Argon2 derivation at a
          # 30 s budget) doesn't refuse the cryptsetup-default 1 GiB /
          # 4-iteration keyslot in the test environment. Real builds keep
          # the strong default (no `kdf:` field).
          kdf:
            type: argon2id
            time: 1
            memory: 1024
            cpus: 1
          content:
            type: image
            input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        rootfs = rootfs.display(),
        output_a = output_a.display(),
        temp_a = temp_a.display(),
    );
    let config_a_path = dir.path().join("a.yml");
    fs::write(&config_a_path, &config_a).unwrap();
    let key_a = [("cryptroot".to_string(), passphrase.to_string())]
        .into_iter()
        .collect();
    build_from_file_with_keys(&config_a_path, &key_a, &BTreeMap::new(), &BTreeMap::new())
        .expect("build A should succeed");

    let disk_image = dir.path().join("disk.img");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&disk_image)
            .unwrap();
        f.set_len(128 * 1024 * 1024).unwrap();
    }
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_a_path,
        manifest: None,
    })
    .expect("read manifest A");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: [("cryptroot".to_string(), passphrase.to_string())]
            .into_iter()
            .collect(),
        key_file: BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install A should succeed");

    // --- Build B: descend through GPT → LUKS → EROFS, no extraction. ---
    let output_b = dir.path().join("out-b");
    let temp_b = dir.path().join("tmp-b");
    let disk = disk_image.display();
    let config_b = format!(
        r#"
name: diskb
version: "1"
arch: x86_64
input: {output_b}
outputDirectory: {output_b}
tempDirectory: {temp_b}
build:
  erofs:
    pulled:
      input:
        - destination: "pulled"
          input: "in:{disk}#gpt:root|luks:cryptroot|erofs:/etc/os-release"
disk:
  out:
    type: gpt
    partitions:
      - name: pulled
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:pulled
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        disk = disk,
        output_b = output_b.display(),
        temp_b = temp_b.display(),
    );
    let config_b_path = dir.path().join("b.yml");
    fs::write(&config_b_path, &config_b).unwrap();
    let key_b = [("cryptroot".to_string(), passphrase.to_string())]
        .into_iter()
        .collect();
    build_from_file_with_keys(&config_b_path, &key_b, &BTreeMap::new(), &BTreeMap::new())
        .expect("build B should succeed");

    let bin_b = only_bin(&output_b);
    let steps = parse_descent("erofs:/pulled").unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let resolved = descend(&bin_b, &steps, &keys).unwrap();
    let content = read_virtual_file(&resolved);
    assert_eq!(content, b"ID=descent\nVERSION_ID=1\n");
}

// ---------------------------------------------------------------------------
// cpio / tar / fat descent steps
// ---------------------------------------------------------------------------

use sysimage::archive::build_archive_from_tree;
use sysimage::model::config::ArchiveFormat;

/// Build an in-memory [`TreeNode`] from a rootfs directory (mirrors what the
/// build pipeline collects before writing an archive).
fn build_tree_from_dir(dir: &Path) -> sysimage::archive::TreeNode {
    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: String::new(),
        input: dir.to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];
    let resolved = resolve_files_set_paths(&files, dir).unwrap();
    collect_tree(&resolved).unwrap()
}

/// Write a zstd-compressed archive of `format` built from `rootfs` and return
/// its path. sysimage always zstd-compresses cpio/tar artifacts, so this is the
/// realistic on-disk shape a `build:cpio:`/archive artifact has.
fn write_zstd_archive(dir: &TempDir, rootfs: &Path, format: ArchiveFormat) -> PathBuf {
    let root = build_tree_from_dir(rootfs);
    let path = dir.path().join(match format {
        ArchiveFormat::Cpio => "rootfs.cpio.zst",
        ArchiveFormat::Tar => "rootfs.tar.zst",
    });
    build_archive_from_tree(&root, format, &path, 0).unwrap();
    path
}

/// Read the whole file at `path` into a `Vec<u8>`.
fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

/// Pull a single file out of a descent and return its bytes.
fn descend_file(src: &Path, chain: &str) -> Vec<u8> {
    let steps = parse_descent(chain).unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let resolved = descend(src, &steps, &keys).unwrap();
    read_virtual_file(&resolved)
}

/// Descend to a directory tree and collect it under `prefix` in a fresh root.
fn descend_tree(src: &Path, chain: &str, prefix: &str) -> sysimage::archive::TreeNode {
    let steps = parse_descent(chain).unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let resolved = descend(src, &steps, &keys).unwrap();
    let tree = match resolved {
        ResolvedInput::Tree(t) => t,
        _ => panic!("expected ResolvedInput::Tree for `{chain}`"),
    };
    let mut root = sysimage::archive::TreeNode::Dir {
        meta: sysimage::archive::Meta {
            perms: 0o0755,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: Vec::new(),
        },
        children: std::collections::BTreeMap::new(),
    };
    tree.collect_into(prefix, &[], &[], &mut root).unwrap();
    root
}

/// Look up `path` (slash-separated, relative to the collection prefix) within a
/// collected tree root and return the file content if it is a file.
fn tree_file<'a>(root: &'a sysimage::archive::TreeNode, prefix: &str, path: &str) -> &'a [u8] {
    let mut cur = root;
    for part in prefix.split('/').chain(path.split('/')) {
        if part.is_empty() {
            continue;
        }
        cur = match cur {
            sysimage::archive::TreeNode::Dir { children, .. } => children
                .get(part)
                .unwrap_or_else(|| panic!("missing entry \"{part}\" in tree")),
            _ => panic!("component \"{part}\" is not a directory"),
        };
    }
    match cur {
        sysimage::archive::TreeNode::File { content, .. } => content,
        _ => panic!("`{prefix}/{path}` is not a file"),
    }
}

#[test]
fn descent_into_cpio_file_and_tree() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let archive = write_zstd_archive(&dir, &rootfs, ArchiveFormat::Cpio);

    // File view: zstd-compressed cpio decoded transparently.
    assert_eq!(
        descend_file(&archive, "cpio:/etc/os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(
        descend_file(&archive, "cpio:/hello.txt"),
        b"hello descent\n"
    );
    assert_eq!(descend_file(&archive, "cpio:/boot/vmlinuz"), b"KERNEL");

    // Tree view: the whole cpio walked into a TreeNode.
    let root = descend_tree(&archive, "cpio:/", "pulled");
    assert_eq!(
        tree_file(&root, "pulled", "etc/os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(tree_file(&root, "pulled", "hello.txt"), b"hello descent\n");
    assert_eq!(tree_file(&root, "pulled", "boot/vmlinuz"), b"KERNEL");

    // A subdirectory tree view resolves just that subtree.
    let root = descend_tree(&archive, "cpio:/boot", "b");
    assert_eq!(tree_file(&root, "b", "vmlinuz"), b"KERNEL");
}

#[test]
fn descent_into_tar_file_and_tree() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let archive = write_zstd_archive(&dir, &rootfs, ArchiveFormat::Tar);

    assert_eq!(
        descend_file(&archive, "tar:/etc/os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(descend_file(&archive, "tar:/boot/vmlinuz"), b"KERNEL");

    let root = descend_tree(&archive, "tar:/", "pulled");
    assert_eq!(
        tree_file(&root, "pulled", "etc/os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(tree_file(&root, "pulled", "boot/vmlinuz"), b"KERNEL");
}

/// A single file pulled out of an archive/FS must carry its metadata into the
/// new tree. In particular `security.capability` (file capabilities) must not
/// be dropped when the only input is one extracted file.
#[test]
fn descent_single_file_carries_xattrs_into_erofs() {
    use std::collections::BTreeMap;
    use sysimage::archive::{Meta, TreeNode, build_archive_from_tree, collect_tree};
    use sysimage::erofs::{ErofsBuildConfig, ErofsCompression, build_erofs_image};
    use sysimage::input::{ResolvedFileEntry, ResolvedFilesSet, ResolvedSource};

    let dir = TempDir::new();
    let cap = vec![0x01, 0x00, 0x00, 0x02, 1, 2, 3, 4];
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
                meta: Meta {
                    perms: 0o755,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    xattrs: vec![(b"security.capability".to_vec(), cap.clone())],
                },
                content: b"ELF".to_vec(),
            },
        )]),
    };
    let archive = dir.path().join("rootfs.tar.zst");
    build_archive_from_tree(&root, ArchiveFormat::Tar, &archive, 0).unwrap();

    let steps = parse_descent("tar:/newuidmap").unwrap();
    let resolved = descend(&archive, &steps, &BTreeMap::new()).unwrap();
    let ResolvedInput::File(vf) = resolved else {
        panic!("expected a single extracted file");
    };
    assert_eq!(
        vf.meta
            .as_ref()
            .expect("extracted file should carry metadata")
            .perms,
        0o755
    );

    let files: ResolvedFilesSet = vec![ResolvedFileEntry {
        destination: "usr/bin/newuidmap".to_string(),
        source: ResolvedSource::File(vf),
        include_pattern: None,
        exclude_patterns: None,
    }];
    let tree = collect_tree(&files).unwrap();
    let node = match &tree {
        TreeNode::Dir { children, .. } => {
            let TreeNode::Dir { children, .. } = children.get("usr").expect("usr") else {
                panic!("usr should be a directory");
            };
            let TreeNode::Dir { children, .. } = children.get("bin").expect("bin") else {
                panic!("bin should be a directory");
            };
            children.get("newuidmap").expect("newuidmap")
        }
        _ => panic!("root should be a directory"),
    };
    let TreeNode::File { meta, .. } = node else {
        panic!("newuidmap should be a file");
    };
    assert!(
        meta.xattrs
            .iter()
            .any(|(name, value)| name == b"security.capability" && value == &cap),
        "single-file descent lost security.capability: {:?}",
        meta.xattrs
    );

    // The same tree must build a valid EROFS image without losing the xattr.
    build_erofs_image(&ErofsBuildConfig {
        root: &tree,
        block_size: 4096,
        timestamp_ms: 0,
        compression: ErofsCompression::Lz4,
    })
    .expect("EROFS build should succeed");
}

/// The `cpio:`/`tar:` steps detect zstd by magic bytes and decode transparently,
/// but a raw (uncompressed) archive must also work. sysimage always zstd-
/// compresses its own artifacts, so decompress one back to raw bytes to exercise
/// the non-zstd branch.
#[test]
fn descent_into_raw_cpio_and_tar() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    for format in [ArchiveFormat::Cpio, ArchiveFormat::Tar] {
        let zstd_path = write_zstd_archive(&dir, &rootfs, format);
        let raw_path = dir.path().join(match format {
            ArchiveFormat::Cpio => "rootfs.cpio",
            ArchiveFormat::Tar => "rootfs.tar",
        });
        let raw = zstd::decode_all(std::io::Cursor::new(read_file(&zstd_path))).unwrap();
        fs::write(&raw_path, &raw).unwrap();
        assert!(!raw.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]));

        let chain = match format {
            ArchiveFormat::Cpio => "cpio:/etc/os-release",
            ArchiveFormat::Tar => "tar:/etc/os-release",
        };
        assert_eq!(
            descend_file(&raw_path, chain),
            b"ID=descent\nVERSION_ID=1\n"
        );
    }
}

/// Build + install a GPT disk whose `esp` partition is a FAT filesystem with a
/// couple of files, then descend into it directly.
#[test]
fn descent_into_fat_file_and_tree() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let output_a = dir.path().join("out-a");
    let temp_a = dir.path().join("tmp-a");
    let config_a = format!(
        r#"
name: diska
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output_a}
tempDirectory: {temp_a}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          fatVersion: fat32
          files:
            - destination: "os-release"
              input: "etc/os-release"
            - destination: "hello.txt"
              input: "hello.txt"
            - destination: "boot/vmlinuz"
              input: "boot/vmlinuz"
"#,
        rootfs = rootfs.display(),
        output_a = output_a.display(),
        temp_a = temp_a.display(),
    );
    let config_a_path = dir.path().join("a.yml");
    fs::write(&config_a_path, &config_a).unwrap();
    build_from_file(&config_a_path).expect("build A should succeed");

    let disk_image = dir.path().join("disk.img");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&disk_image)
            .unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
    }
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_a_path,
        manifest: None,
    })
    .expect("read manifest A");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: BTreeMap::new(),
        key_file: BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install A should succeed");

    // File views through GPT → FAT.
    assert_eq!(
        descend_file(&disk_image, "gpt:esp|fat:/os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(
        descend_file(&disk_image, "gpt:esp|fat:/hello.txt"),
        b"hello descent\n"
    );
    assert_eq!(
        descend_file(&disk_image, "gpt:esp|fat:/boot/vmlinuz"),
        b"KERNEL"
    );

    // Tree view: the whole FAT root.
    let root = descend_tree(&disk_image, "gpt:esp|fat:/", "pulled");
    assert_eq!(
        tree_file(&root, "pulled", "os-release"),
        b"ID=descent\nVERSION_ID=1\n"
    );
    assert_eq!(tree_file(&root, "pulled", "hello.txt"), b"hello descent\n");
    assert_eq!(tree_file(&root, "pulled", "boot/vmlinuz"), b"KERNEL");

    // A subdirectory tree view.
    let root = descend_tree(&disk_image, "gpt:esp|fat:/boot", "b");
    assert_eq!(tree_file(&root, "b", "vmlinuz"), b"KERNEL");
}

/// End-to-end `in:` build pulling a file out of a FAT partition into a new
/// EROFS image — no extraction.
#[test]
fn descent_gpt_fat_via_in_scheme() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let output_a = dir.path().join("out-a");
    let temp_a = dir.path().join("tmp-a");
    let config_a = format!(
        r#"
name: diska
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output_a}
tempDirectory: {temp_a}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          fatVersion: fat32
          files:
            - destination: "os-release"
              input: "etc/os-release"
"#,
        rootfs = rootfs.display(),
        output_a = output_a.display(),
        temp_a = temp_a.display(),
    );
    let config_a_path = dir.path().join("a.yml");
    fs::write(&config_a_path, &config_a).unwrap();
    build_from_file(&config_a_path).expect("build A should succeed");

    let disk_image = dir.path().join("disk.img");
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&disk_image)
            .unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
    }
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_a_path,
        manifest: None,
    })
    .expect("read manifest A");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: BTreeMap::new(),
        key_file: BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install A should succeed");

    // Build B: descend through GPT → FAT, no extraction.
    let output_b = dir.path().join("out-b");
    let temp_b = dir.path().join("tmp-b");
    let disk = disk_image.display();
    let config_b = format!(
        r#"
name: diskb
version: "1"
arch: x86_64
input: {output_b}
outputDirectory: {output_b}
tempDirectory: {temp_b}
build:
  erofs:
    pulled:
      input:
        - destination: "pulled"
          input: "in:{disk}#gpt:esp|fat:/os-release"
disk:
  out:
    type: gpt
    partitions:
      - name: pulled
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:pulled
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        disk = disk,
        output_b = output_b.display(),
        temp_b = temp_b.display(),
    );
    let config_b_path = dir.path().join("b.yml");
    fs::write(&config_b_path, &config_b).unwrap();
    build_from_file(&config_b_path).expect("build B should succeed");

    let bin_b = only_bin(&output_b);
    assert_eq!(
        descend_file(&bin_b, "erofs:/pulled"),
        b"ID=descent\nVERSION_ID=1\n"
    );
}

/// End-to-end `in:` build pulling a file out of a zstd-compressed cpio archive
/// into a new EROFS image. The cpio artifact is produced with
/// `build_archive_from_tree` (the same writer the `build:cpio:` pipeline step
/// uses, always zstd-compressed), then referenced by file path.
#[test]
fn descent_cpio_via_in_scheme() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    // Produce a zstd-compressed cpio artifact (same shape as `build:cpio:`).
    let cpio_bin = write_zstd_archive(&dir, &rootfs, ArchiveFormat::Cpio);

    // Sanity: the artifact really is zstd-compressed.
    let magic = read_file(&cpio_bin);
    assert_eq!(&magic[..4], &[0x28, 0xB5, 0x2F, 0xFD]);

    // Build B: descend into the cpio artifact and pull a file.
    let output_b = dir.path().join("out-b");
    let temp_b = dir.path().join("tmp-b");
    let cpio = cpio_bin.display();
    let config_b = format!(
        r#"
name: diskb
version: "1"
arch: x86_64
input: {output_b}
outputDirectory: {output_b}
tempDirectory: {temp_b}
build:
  erofs:
    pulled:
      input:
        - destination: "pulled"
          input: "in:{cpio}#cpio:/etc/os-release"
disk:
  out:
    type: gpt
    partitions:
      - name: pulled
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:pulled
erofs:
  blockSize: 4096
  timestamp: 1700000000000
"#,
        cpio = cpio,
        output_b = output_b.display(),
        temp_b = temp_b.display(),
    );
    let config_b_path = dir.path().join("b.yml");
    fs::write(&config_b_path, &config_b).unwrap();
    build_from_file(&config_b_path).expect("build B should succeed");

    let bin_b = only_bin(&output_b);
    assert_eq!(
        descend_file(&bin_b, "erofs:/pulled"),
        b"ID=descent\nVERSION_ID=1\n"
    );
}

/// A descent into a path that does not exist inside an archive must error,
/// not panic or return empty data.
#[test]
fn descent_missing_path_errors() {
    let dir = TempDir::new();
    let rootfs = dir.path().join("rootfs");
    make_rootfs(&rootfs);

    let archive = write_zstd_archive(&dir, &rootfs, ArchiveFormat::Cpio);
    let steps = parse_descent("cpio:/no/such/file").unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let err = match descend(&archive, &steps, &keys) {
        Ok(_) => panic!("expected an error for missing path"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("cpio") && (msg.contains("no/such/file") || msg.contains("no entry")),
        "unexpected error message: {msg}"
    );
}

/// `fat:`/`cpio:`/`tar:` are now parsed as real steps, not rejected as
/// unsupported.
#[test]
fn parse_descent_accepts_fat_cpio_tar() {
    assert_eq!(parse_descent("fat:/x").unwrap().len(), 1);
    assert_eq!(parse_descent("cpio:/x").unwrap().len(), 1);
    assert_eq!(parse_descent("tar:/x").unwrap().len(), 1);
    // And they compose with block steps.
    assert_eq!(
        parse_descent("gpt:root|fat:/boot/vmlinuz").unwrap().len(),
        2
    );
}
