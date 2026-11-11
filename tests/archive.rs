//! Round-trip the archive builder: build a cpio/tar from a file set, then read
//! it back and verify contents and metadata.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::archive::{TreeNode, build_archive, extract_archive_to_tree};
use sysimage::input::resolve_files_set_paths;
use sysimage::model::config::{ArchiveFormat, ConfigFileEntry, ConfigFilesSet};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A self-cleaning temp directory.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-test-{}-{n}", std::process::id()));
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

fn make_tree(dir: &TempDir) {
    let root = dir.path();
    fs::write(root.join("hello.txt"), "hello world\n").unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub").join("nested.txt"), "nested\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    }
}

#[test]
fn cpio_round_trip() {
    let dir = TempDir::new();
    make_tree(&dir);
    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: ".".to_string(),
        input: dir.path().to_string_lossy().into_owned(),
        include_pattern: Some(vec!["**".into()]),
        exclude_patterns: Some(vec!["link".into()]),
    }];

    let out = dir.path().join("out.cpio.zst");
    let files = resolve_files_set_paths(&files, dir.path()).unwrap();
    build_archive(&files, ArchiveFormat::Cpio, &out, 3).unwrap();
    let raw = zstd::decode_all(fs::File::open(&out).unwrap()).unwrap();

    let mut reader = hadris_cpio::CpioArchiveReader::new(raw.as_slice());
    let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    while let Some(entry) = reader.next_entry_alloc().unwrap() {
        let name = entry.name_str().unwrap().to_string();
        let data = reader.read_entry_data_alloc(&entry).unwrap();
        found.insert(name, data);
    }
    assert_eq!(
        found.get("hello.txt").map(|d| d.as_slice()),
        Some(&b"hello world\n"[..])
    );
    assert_eq!(
        found.get("sub/nested.txt").map(|d| d.as_slice()),
        Some(&b"nested\n"[..])
    );
    assert!(!found.contains_key("link"));
}

#[test]
fn tar_round_trip() {
    let dir = TempDir::new();
    make_tree(&dir);
    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: ".".to_string(),
        input: dir.path().to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];

    let out = dir.path().join("out.tar.zst");
    let files = resolve_files_set_paths(&files, dir.path()).unwrap();
    build_archive(&files, ArchiveFormat::Tar, &out, 3).unwrap();
    let raw = zstd::decode_all(fs::File::open(&out).unwrap()).unwrap();

    let mut archive = tar::Archive::new(raw.as_slice());
    let mut names: Vec<String> = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        if name == "hello.txt" {
            let mut s = String::new();
            entry.read_to_string(&mut s).unwrap();
            assert_eq!(s, "hello world\n");
        }
        names.push(name);
    }
    assert!(names.iter().any(|n| n == "hello.txt"));
    assert!(names.iter().any(|n| n == "sub/nested.txt"));
}

/// Tar carries xattrs as `SCHILY.xattr.*` PAX records; make sure the writer and
/// reader agree on them.
#[cfg(unix)]
#[test]
fn tar_round_trip_preserves_xattrs() {
    let dir = TempDir::new();
    make_tree(&dir);
    if let Err(e) = xattr::set(
        dir.path().join("hello.txt"),
        "user.sysimage.test",
        b"hello xattr",
    ) {
        eprintln!("user xattrs not supported here — skipping: {e}");
        return;
    }

    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: ".".to_string(),
        input: dir.path().to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];
    let out = dir.path().join("out.tar.zst");
    let files = resolve_files_set_paths(&files, dir.path()).unwrap();
    build_archive(&files, ArchiveFormat::Tar, &out, 3).unwrap();

    let root = extract_archive_to_tree(&out, ArchiveFormat::Tar).unwrap();
    let TreeNode::Dir { children, .. } = root else {
        panic!("archive root should be a directory");
    };
    let TreeNode::File { meta, .. } = children.get("hello.txt").expect("hello.txt") else {
        panic!("hello.txt should be a regular file");
    };
    assert!(
        meta.xattrs
            .iter()
            .any(|(name, value)| name == b"user.sysimage.test" && value == b"hello xattr"),
        "xattr missing after tar round-trip: {:?}",
        meta.xattrs
    );
}

/// libarchive/bsdtar stores xattrs as base64 in `LIBARCHIVE.xattr.*` PAX
/// records. That is the convention used by bootstrap/OCI tarballs, so the
/// reader must understand it (not just GNU tar's raw `SCHILY.xattr.*`).
#[test]
fn tar_reads_libarchive_base64_xattrs() {
    use base64::Engine as _;

    let dir = TempDir::new();
    let cap = vec![0x01, 0x00, 0x00, 0x02, 1, 2, 3, 4, 5, 6, 7, 8];
    let cap64 = base64::engine::general_purpose::STANDARD.encode(&cap);
    let user64 = base64::engine::general_purpose::STANDARD.encode(b"hello");

    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([
            ("LIBARCHIVE.xattr.user.test", user64.as_bytes()),
            ("LIBARCHIVE.xattr.security.capability", cap64.as_bytes()),
        ])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o755);
    header.set_entry_type(tar::EntryType::Regular);
    builder
        .append_data(&mut header, "newuidmap", &b"ELF\n"[..])
        .unwrap();
    builder.finish().unwrap();
    let tar = builder.into_inner().unwrap();

    let out = dir.path().join("out.tar.zst");
    fs::write(&out, zstd::stream::encode_all(&tar[..], 0).unwrap()).unwrap();
    let root = extract_archive_to_tree(&out, ArchiveFormat::Tar).unwrap();
    let TreeNode::Dir { children, .. } = root else {
        panic!("archive root should be a directory");
    };
    let TreeNode::File { meta, .. } = children.get("newuidmap").expect("newuidmap") else {
        panic!("newuidmap should be a regular file");
    };
    assert!(
        meta.xattrs
            .iter()
            .any(|(name, value)| name == b"user.test" && value == b"hello"),
        "LIBARCHIVE user xattr missing: {:?}",
        meta.xattrs
    );
    assert!(
        meta.xattrs
            .iter()
            .any(|(name, value)| name == b"security.capability" && value == &cap),
        "LIBARCHIVE security.capability missing: {:?}",
        meta.xattrs
    );
}

#[test]
fn cpio_single_file_at_destination() {
    let dir = TempDir::new();
    let src = dir.path().join("a.txt");
    fs::write(&src, "AAA").unwrap();
    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: "etc/veritytab".to_string(),
        input: src.to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];
    let out = dir.path().join("v.cpio.zst");
    let files = resolve_files_set_paths(&files, dir.path()).unwrap();
    build_archive(&files, ArchiveFormat::Cpio, &out, 3).unwrap();
    let raw = zstd::decode_all(fs::File::open(&out).unwrap()).unwrap();
    let mut reader = hadris_cpio::CpioArchiveReader::new(raw.as_slice());
    let mut found: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    while let Some(entry) = reader.next_entry_alloc().unwrap() {
        let name = entry.name_str().unwrap().to_string();
        let data = reader.read_entry_data_alloc(&entry).unwrap();
        found.insert(name, data);
    }
    assert_eq!(
        found.get("etc/veritytab").map(|d| d.as_slice()),
        Some(&b"AAA"[..])
    );
    assert!(found.contains_key("etc"));
}
