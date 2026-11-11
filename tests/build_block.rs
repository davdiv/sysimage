//! `build:block:` — rendering named blocks into standalone image files at
//! build time, then referencing them as inputs (e.g. an `image` block's
//! `input`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-buildblock-{}-{n}", std::process::id()));
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
    fs::write(dir.join("etc").join("hosts"), "127.0.0.1 localhost\n").unwrap();
    fs::write(dir.join("hello.txt"), "hello build:block\n").unwrap();
}

/// Read the manifest JSON written for `name` under `output`.
fn read_manifest(output: &Path, name: &str) -> serde_json::Value {
    let symlink = output.join(format!("{name}.json"));
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(output).unwrap() {
            let entry = entry.unwrap();
            let fname = entry.file_name().to_string_lossy().into_owned();
            if fname.starts_with(&format!("{name}-")) && fname.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let text = fs::read_to_string(&manifest_path).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// ext4 superblock magic 0xEF53 lives at byte offset 1024 + 56 = 1080.
const EXT4_MAGIC_OFFSET: usize = 1080;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xef];

/// GPT header signature "EFI PART" lives at LBA 1 = byte offset 512.
const GPT_SIG_OFFSET: usize = 512;
const GPT_SIG: &[u8] = b"EFI PART";

#[test]
fn builds_block_artifact_ext4_as_image() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: blkext4
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    myfs:
      type: ext4
      files:
        - destination: "etc/hosts"
          input: etc/hosts
        - destination: "hello.txt"
          input: hello.txt
      emptySpace: "4M"
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:myfs
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(&output, "blkext4");
    let content = &manifest["disk"]["boot"]["partitions"][0]["content"];
    assert_eq!(content["type"], "image", "content: {content}");
    let file_hash = content["file"].as_str().expect("image block file");
    let bin = output.join(file_hash);
    assert!(bin.exists(), "rendered block file {bin:?} should exist");

    // The rendered file must be a valid ext4 image (superblock magic).
    let bytes = fs::read(&bin).unwrap();
    assert!(
        bytes.len() > EXT4_MAGIC_OFFSET + 2,
        "rendered ext4 image too small ({} bytes)",
        bytes.len()
    );
    assert_eq!(
        &bytes[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2],
        EXT4_MAGIC,
        "rendered block is not a valid ext4 image"
    );

    // The manifest must also record the file in the top-level `file` map.
    assert!(
        manifest["file"].get(file_hash).is_some(),
        "manifest file map should contain {file_hash}"
    );
}

/// Build-time rendered ext4 blocks write the in-memory tree straight into the
/// new filesystem; xattrs must survive that path.
#[cfg(unix)]
#[test]
fn builds_block_artifact_ext4_preserves_xattrs() {
    use std::sync::Arc;

    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    if let Err(e) = xattr::set(
        rootfs.join("hello.txt"),
        "user.sysimage.test",
        b"hello xattr",
    ) {
        eprintln!("user xattrs not supported here — skipping: {e}");
        return;
    }
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: blkext4xattr
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    myfs:
      type: ext4
      files:
        - destination: "hello.txt"
          input: hello.txt
      emptySpace: "4M"
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:myfs
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(&output, "blkext4xattr");
    let file_hash = manifest["disk"]["boot"]["partitions"][0]["content"]["file"]
        .as_str()
        .expect("image block file");
    let bin = output.join(file_hash);
    let size = fs::metadata(&bin).unwrap().len();

    let bf = sysimage::blockfile::BlockFile::open(&bin, 0, size).unwrap();
    let dev: Arc<dyn fs_ext4::block_io::BlockDevice> = Arc::new(bf);
    let fs = fs_ext4::fs::Filesystem::mount(dev).unwrap();
    let ino = fs_ext4::path::lookup(
        fs.dev.as_ref(),
        &fs.sb,
        &mut |i| fs.read_inode_verified(i).map(|(x, _)| x),
        "/hello.txt",
    )
    .unwrap();
    let (inode, raw) = fs.read_inode_verified(ino).unwrap();
    let attrs = fs_ext4::xattr::read_all(
        fs.dev.as_ref(),
        &inode,
        &raw,
        fs.sb.inode_size,
        fs.sb.block_size(),
    )
    .unwrap();
    assert!(
        attrs
            .iter()
            .any(|e| e.name == "user.sysimage.test" && e.value == b"hello xattr"),
        "xattr missing from rendered ext4 image: {attrs:?}"
    );
}

#[test]
fn builds_block_artifact_gpt_as_image() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: blkgpt
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    mydisk:
      type: gpt
      partitions:
        - name: esp
          type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
          content:
            type: fat
            files:
              - destination: "test.txt"
                input: hello.txt
            emptySpace: "2M"
        - name: root
          type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
          content:
            type: ext4
            emptySpace: "4M"
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:mydisk
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(&output, "blkgpt");
    let content = &manifest["disk"]["boot"]["partitions"][0]["content"];
    assert_eq!(content["type"], "image");
    let file_hash = content["file"].as_str().expect("image block file");
    let bin = output.join(file_hash);
    assert!(bin.exists(), "rendered block file {bin:?} should exist");

    // The rendered file must be a valid GPT image (header signature at LBA 1).
    let bytes = fs::read(&bin).unwrap();
    assert!(
        bytes.len() > GPT_SIG_OFFSET + GPT_SIG.len(),
        "rendered GPT image too small ({} bytes)",
        bytes.len()
    );
    assert_eq!(
        &bytes[GPT_SIG_OFFSET..GPT_SIG_OFFSET + GPT_SIG.len()],
        GPT_SIG,
        "rendered block is not a valid GPT image"
    );
}

#[test]
fn build_block_is_memoized_and_referenced_twice() {
    // Referencing the same `build:block:` twice must build it once (memoized)
    // and both image blocks must point at the same content-addressed file.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: blkmemo
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    myfs:
      type: fat
      files:
        - destination: "test.txt"
          input: hello.txt
      emptySpace: "2M"
disk:
  boot:
    type: gpt
    partitions:
      - name: a
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:myfs
      - name: b
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:myfs
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(&output, "blkmemo");
    let parts = manifest["disk"]["boot"]["partitions"].as_array().unwrap();
    let file_a = parts[0]["content"]["file"].as_str().unwrap();
    let file_b = parts[1]["content"]["file"].as_str().unwrap();
    assert_eq!(
        file_a, file_b,
        "both partitions must reference the same (memoized) block file"
    );
    assert!(output.join(file_a).exists(), "block file should exist");
}

/// A `build:block:` whose subtree contains internal filesystem partitions
/// (which themselves build archives) must not leak those internal archives into
/// the output directory or the manifest `file` map. Only the top-level image
/// block — reachable from the disk — is promoted to the output.
#[test]
fn build_block_internal_artifacts_do_not_leak_to_output() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: blkleak
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  block:
    mydisk:
      type: gpt
      partitions:
        - name: esp
          type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
          content:
            type: fat
            files:
              - destination: "test.txt"
                input: hello.txt
            emptySpace: "2M"
        - name: root
          type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
          content:
            type: ext4
            emptySpace: "4M"
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:mydisk
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(&output, "blkleak");
    let content = &manifest["disk"]["boot"]["partitions"][0]["content"];
    let file_hash = content["file"].as_str().expect("image block file");
    assert!(
        output.join(file_hash).exists(),
        "reachable image file should exist"
    );

    // The manifest `file` map must contain exactly one entry — the reachable
    // image block. The internal FAT/ext4 archives must NOT appear.
    let file_map = manifest["file"].as_object().expect("file map");
    assert_eq!(
        file_map.len(),
        1,
        "only the reachable image file should be in the manifest file map, got {file_map:?}"
    );
    assert!(
        file_map.contains_key(file_hash),
        "the reachable image file should be the one in the file map"
    );

    // The output directory must contain exactly one `.bin` file — the
    // reachable image block. The internal archives must not have been copied.
    let bin_files: Vec<_> = std::fs::read_dir(&output)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
        .collect();
    assert_eq!(
        bin_files.len(),
        1,
        "expected exactly 1 .bin in output (the reachable image), got {}",
        bin_files.len()
    );
    assert_eq!(
        bin_files[0].file_name().to_string_lossy(),
        file_hash,
        "the single .bin should be the reachable image file"
    );
}
