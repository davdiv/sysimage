//! End-to-end install: build a config, install it to a disk image, and verify
//! the on-disk layout (GPT + raw image partition + ext4 + FAT).

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;

use sysimage::build::build_from_file;
use sysimage::install::{InstallConfig, install};
use sysimage::manifest::{ReadManifestConfig, read_manifest};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-install-{}-{n}", std::process::id()));
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

fn make_rootfs(dir: &Path) {
    fs::create_dir_all(dir.join("etc")).unwrap();
    fs::write(
        dir.join("etc").join("passwd"),
        "root:x:0:0:root:/root:/bin/sh\n",
    )
    .unwrap();
    fs::write(dir.join("hello.txt"), "hello install\n").unwrap();
}

fn ensure_disk_size(path: &Path, size: u64) {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    f.set_len(size).unwrap();
}
fn read_gpt_signature(disk: &Path) -> [u8; 8] {
    let mut f = fs::File::open(disk).unwrap();
    f.seek(SeekFrom::Start(512)).unwrap();
    let mut sig = [0u8; 8];
    f.read_exact(&mut sig).unwrap();
    sig
}

#[test]
fn installs_gpt_with_image_ext4_and_fat() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: instimg
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
      - name: var
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "64M"
          files:
            - destination: "var/hello.txt"
              input: hello.txt
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          emptySpace: "64M"
          files:
            - destination: "test.txt"
              input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let disk_image = workdir.path().join("disk.img");
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // The disk must now start with a protective MBR + a GPT header at LBA 1.
    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");

    // Read the primary GPT header and find the partitions.
    let mut f = fs::File::open(&disk_image).unwrap();
    f.seek(SeekFrom::Start(512)).unwrap();
    let mut header = [0u8; 92];
    f.read_exact(&mut header).unwrap();
    assert_eq!(&header[0..8], b"EFI PART");
    let first_usable = u64::from_le_bytes(header[40..48].try_into().unwrap());
    // Partition entries start at LBA 2 (offset 1024). Each entry is 128 bytes.
    let root_first_lba = first_usable;
    let root_offset = root_first_lba * 512;

    // The root partition must begin with the EROFS superblock magic.
    f.seek(SeekFrom::Start(root_offset + 1024)).unwrap();
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).unwrap();
    assert_eq!(
        u32::from_le_bytes(magic),
        0xe0f5e1e2,
        "root partition is not an EROFS image"
    );
}

/// The default archive format is cpio, which has no xattr representation; for
/// filesystem content carrying xattrs the build must fall back to tar and the
/// installer must apply them to the freshly formatted ext4.
#[cfg(unix)]
#[test]
fn installed_ext4_preserves_xattrs() {
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
name: instxattr
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "16M"
          files:
            - destination: "hello.txt"
              input: hello.txt
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    let (off, size) = find_partition(&disk_image, "root");
    let attrs = read_ext4_xattrs(&disk_image, off, size, "/hello.txt");
    assert!(
        attrs
            .iter()
            .any(|e| e.name == "user.sysimage.test" && e.value == b"hello xattr"),
        "xattr missing after install: {attrs:?}"
    );
}

#[test]
fn installs_nested_gpt_inside_gpt_partition() {
    // A GPT whose first partition contains another GPT (a nested partition
    // table). Verifies that nesting a partition table inside a partition works
    // end-to-end: the inner GPT header is written at the outer partition's
    // first usable LBA, and the inner FAT content is installed.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nestedgpt
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: gpt
    partitions:
      - name: outer
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: gpt
          partitions:
            - name: inner-esp
              type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
              content:
                type: fat
                emptySpace: "16M"
                files:
                  - destination: "test.txt"
                    input: hello.txt
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let disk_image = workdir.path().join("disk.img");
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // Outer disk starts with a GPT.
    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");

    // Read the outer GPT header to find the first partition's offset.
    let mut f = fs::File::open(&disk_image).unwrap();
    f.seek(SeekFrom::Start(512)).unwrap();
    let mut header = [0u8; 92];
    f.read_exact(&mut header).unwrap();
    let first_usable = u64::from_le_bytes(header[40..48].try_into().unwrap());
    let part_offset = first_usable * 512;

    // The inner GPT signature ("EFI PART") must appear at LBA 1 of the outer
    // partition, i.e. at part_offset + 512.
    f.seek(SeekFrom::Start(part_offset + 512)).unwrap();
    let mut inner_sig = [0u8; 8];
    f.read_exact(&mut inner_sig).unwrap();
    assert_eq!(
        &inner_sig, b"EFI PART",
        "inner partition does not contain a GPT header"
    );

    // The inner GPT's first partition starts at its first usable LBA. Read the
    // inner header to compute that offset, then check for a FAT boot sector.
    f.seek(SeekFrom::Start(part_offset + 512)).unwrap();
    let mut inner_header = [0u8; 92];
    f.read_exact(&mut inner_header).unwrap();
    let inner_first_usable = u64::from_le_bytes(inner_header[40..48].try_into().unwrap());
    let fat_offset = part_offset + inner_first_usable * 512;
    f.seek(SeekFrom::Start(fat_offset)).unwrap();
    let mut bs = [0u8; 3];
    f.read_exact(&mut bs).unwrap();
    // FAT32/VFAT jump instruction: EB 58 90 (or EB xx 90).
    assert_eq!(bs[0], 0xEB, "inner partition content is not a FAT volume");
    assert_eq!(bs[2], 0x90, "inner partition content is not a FAT volume");
}

#[test]
fn installs_fat_esp_without_empty_space() {
    // A FAT partition with no `emptySpace`: the partition size is driven
    // entirely by the content size. This verifies that the total file size
    // and size-on-disk computation produces a partition large enough for the
    // FAT formatter (auto-selected FAT type).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    // Create a ~5 MB "EFI binary" so the content is non-trivial.
    let big = rootfs.join("big.efi");
    fs::write(&big, vec![0x90u8; 5 * 1024 * 1024]).unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: fattest
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          files:
            - destination: "efi/boot/bootx64.efi"
              input: big.efi
            - destination: "test.txt"
              input: hello.txt
      - name: data
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: lvm
          vg: system
lvm:
  system:
    partitions:
      - name: rootfs
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // The FAT partition's sizeMin must be at least the content size (5 MB)
    // — the content size is now correctly computed instead of being 0.
    let boot = &manifest.manifest.disk["boot"];
    use sysimage::model::manifest::ManifestBlock;
    if let ManifestBlock::Gpt(gpt) = boot {
        let esp = &gpt.partitions[0];
        assert!(
            esp.size.size_min >= 5 * 1024 * 1024,
            "FAT partition sizeMin {} should be >= 5 MiB (content size)",
            esp.size.size_min
        );
        if let Some(content) = &esp.content
            && let ManifestBlock::Fat(fat) = content.as_ref()
        {
            assert!(
                fat.archive.as_ref().map(|a| a.size).unwrap_or(0) >= 5 * 1024 * 1024,
                "FAT archive size should account for the 5 MB file"
            );
        }
    }

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");
}

#[test]
fn installs_fat_with_explicit_version() {
    // A FAT partition with `fatVersion: fat32` forces FAT32 even though the
    // content alone is small enough that auto-selection would pick FAT12/16.
    // The partition is sized via `emptySpace` to exceed the 32 MiB FAT32
    // minimum, and the on-disk volume is opened afterwards to confirm its
    // FAT type.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: fatver
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          fatVersion: fat32
          emptySpace: 40M
          files:
            - destination: "test.txt"
              input: hello.txt
      - name: data
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: lvm
          vg: system
lvm:
  system:
    partitions:
      - name: rootfs
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // The manifest must record the explicit FAT version.
    let boot = &manifest.manifest.disk["boot"];
    use sysimage::model::manifest::ManifestBlock;
    if let ManifestBlock::Gpt(gpt) = boot
        && let Some(content) = &gpt.partitions[0].content
        && let ManifestBlock::Fat(fat) = content.as_ref()
    {
        assert_eq!(
            fat.fat_version,
            Some(sysimage::model::config::FatVersion::Fat32),
            "manifest should record fatVersion: fat32"
        );
    } else {
        panic!("expected a FAT block");
    }

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // Open the installed FAT volume and confirm it was formatted as FAT32.
    let (off, size) = find_partition(&disk_image, "esp");
    let bf = sysimage::blockfile::BlockFile::open(&disk_image, off, size).unwrap();
    let fs = hadris_fat::sync::FatVolume::open(bf).unwrap();
    assert_eq!(
        fs.fat_type(),
        hadris_fat::FatType::Fat32,
        "fatVersion: fat32 should produce a FAT32 volume"
    );
}

#[test]
fn installs_fat32_with_large_file_small_clusters() {
    // Regression test for the FAT-sector cache deadlock: writing a large file
    // into a FAT32 volume with small (512-byte) clusters dirties many FAT
    // sectors. With a small write-back cache the cluster allocator's read-path
    // scan can't evict an all-dirty cache and fails with
    // "FAT cache is full and every sector is dirty". The install must instead
    // stream the file in chunks, flushing the cache between them.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    // 8 MB payload: with 512-byte clusters that is 16k clusters → ~125 dirty
    // FAT32 sectors, far exceeding the 64-sector cache.
    let big = rootfs.join("big.efi");
    fs::write(&big, vec![0x55u8; 8 * 1024 * 1024]).unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: fatbig
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          fatVersion: fat32
          blockSize: 512
          emptySpace: 64M
          files:
            - destination: "efi/boot/big.efi"
              input: big.efi
            - destination: "test.txt"
              input: hello.txt
      - name: data
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: lvm
          vg: system
lvm:
  system:
    partitions:
      - name: rootfs
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // Open the installed FAT32 volume and verify the large file is present
    // with the correct size — confirms the chunked write + cache flush path
    // committed every cluster rather than failing mid-write.
    let (off, size) = find_partition(&disk_image, "esp");
    let bf = sysimage::blockfile::BlockFile::open(&disk_image, off, size).unwrap();
    let fs = hadris_fat::sync::FatVolume::open(bf).unwrap();
    assert_eq!(
        fs.fat_type(),
        hadris_fat::FatType::Fat32,
        "fatVersion: fat32 should produce a FAT32 volume"
    );
    let root = fs.root_dir();
    let efi = root.open_dir("efi").expect("efi/ dir present");
    let boot = efi.open_dir("boot").expect("boot/ dir present");
    let entry = boot
        .find("big.efi")
        .expect("lookup ok")
        .expect("big.efi present");
    assert_eq!(
        entry.len(),
        8 * 1024 * 1024,
        "big.efi should be 8 MiB on disk"
    );
}

#[test]
fn installs_lvm_with_two_partial_extent_lvs() {
    // Regression test for per-LV extent rounding in the volume-group sizeMin.
    //
    // At install time `compute_vg_layout` rounds *each* logical volume's
    // sizeMin up to a whole physical extent (pe_size = 4 MiB) before summing.
    // The build-time `process_lvm` must do the same per-LV rounding; rounding
    // only the aggregate once underestimates whenever two (or more) LVs each
    // need a fraction of an extent — they then need two extents, not one —
    // and install fails with "Insufficient space: <pe_size> bytes missing".
    //
    // This config builds two tiny EROFS images (each well under one 4 MiB
    // extent) and places them as two LVs of a single-PV volume group, the
    // exact shape that triggered the bug.
    const PE_SIZE: u64 = 4 * 1024 * 1024;
    const PE_START: u64 = 1024 * 1024;

    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: lvmtwo
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
    etc:
      input:
        - destination: ""
          input: etc
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: data
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: lvm
          vg: system
lvm:
  system:
    partitions:
      - name: rootfs
        content:
          type: image
          input: build:erofs:rootfs
      - name: etc
        content:
          type: image
          input: build:erofs:etc
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // Both LVs are tiny (< 4 MiB), so each rounds up to exactly one extent.
    let vg = &manifest.manifest.lvm["system"];
    let lv0 = vg.partitions[0].size.size_min;
    let lv1 = vg.partitions[1].size.size_min;
    let r0 = lv0.div_ceil(PE_SIZE) * PE_SIZE;
    let r1 = lv1.div_ceil(PE_SIZE) * PE_SIZE;
    let expected_vg_min = PE_START + r0 + r1;
    assert_eq!(
        vg.size_min, expected_vg_min,
        "VG sizeMin must round each LV up to pe_size individually (per-LV), not the aggregate"
    );

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");
}

// ---------------------------------------------------------------------------
// Non-wipe (reconcile) tests
// ---------------------------------------------------------------------------

use std::sync::Arc;

/// Read the installed GPT and return `(offset, size)` in bytes for `name`.
fn find_partition(disk: &Path, name: &str) -> (u64, u64) {
    use hadris_part::scheme_io::GptDiskReadExt;
    let mut f = fs::File::open(disk).unwrap();
    let gpt = hadris_part::scheme::GptDisk::read_from(&mut f, 512).unwrap();
    for entry in gpt.entries.iter() {
        if entry.is_unused() {
            continue;
        }
        let u = entry.name.as_u16_slice();
        let len = u.iter().position(|&c| c == 0).unwrap_or(u.len());
        let n = String::from_utf16_lossy(&u[..len]);
        if n == name {
            return (entry.first_lba.to_ne() * 512, entry.size_sectors() * 512);
        }
    }
    panic!("GPT partition \"{name}\" not found");
}

/// Read a file by path from an ext4 filesystem living in a byte range of `disk`.
fn read_ext4_file(disk: &Path, part_off: u64, part_size: u64, path: &str) -> Vec<u8> {
    let bf = sysimage::blockfile::BlockFile::open(disk, part_off, part_size).unwrap();
    let dev: Arc<dyn fs_ext4::block_io::BlockDevice> = Arc::new(bf);
    let fs = fs_ext4::fs::Filesystem::mount(dev).unwrap();
    let ino = fs_ext4::path::lookup(
        fs.dev.as_ref(),
        &fs.sb,
        &mut |i| fs.read_inode_verified(i).map(|(x, _)| x),
        path,
    )
    .unwrap();
    let (inode, raw) = fs.read_inode_verified(ino).unwrap();
    let size = inode.size as usize;
    let mut buf = vec![0u8; size];
    fs_ext4::file_io::read_with_raw(&fs, &inode, &raw, 0, size as u64, &mut buf).unwrap();
    buf
}

/// Read all xattrs of a file path from an ext4 filesystem in `disk`.
#[cfg(unix)]
fn read_ext4_xattrs(
    disk: &Path,
    part_off: u64,
    part_size: u64,
    path: &str,
) -> Vec<fs_ext4::xattr::XattrEntry> {
    let bf = sysimage::blockfile::BlockFile::open(disk, part_off, part_size).unwrap();
    let dev: Arc<dyn fs_ext4::block_io::BlockDevice> = Arc::new(bf);
    let fs = fs_ext4::fs::Filesystem::mount(dev).unwrap();
    let ino = fs_ext4::path::lookup(
        fs.dev.as_ref(),
        &fs.sb,
        &mut |i| fs.read_inode_verified(i).map(|(x, _)| x),
        path,
    )
    .unwrap();
    let (inode, raw) = fs.read_inode_verified(ino).unwrap();
    fs_ext4::xattr::read_all(
        fs.dev.as_ref(),
        &inode,
        &raw,
        fs.sb.inode_size,
        fs.sb.block_size(),
    )
    .unwrap()
}

fn build_and_read_manifest(config_path: &Path) -> sysimage::manifest::ManifestWithDirectory {
    build_from_file(config_path).expect("build should succeed");
    read_manifest(sysimage::manifest::ReadManifestConfig {
        config: config_path,
        manifest: None,
    })
    .expect("read manifest")
}

#[test]
fn reconcile_ext4_reuses_filesystem_and_merges_archive() {
    // Install (wipe) an ext4 partition with files {var/a, var/b}; then change
    // the source so the new archive has {var/a (modified), var/c} (var/b is gone
    // from the manifest) and reinstall *without* --wipe. The reused ext4
    // filesystem must keep var/b untouched, overwrite var/a, and add var/c.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("var")).unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let cfg = |files: &str| {
        format!(
            r#"
name: reconext
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
          excludePatterns:
            - "var/**"
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: var
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "32M"
          files:
{files}
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            files = files,
        )
    };

    fs::write(rootfs.join("var").join("a1.txt"), "a1\n").unwrap();
    fs::write(rootfs.join("var").join("b1.txt"), "b1\n").unwrap();
    let files1 = "            - destination: \"var/a.txt\"\n              input: var/a1.txt\n            - destination: \"var/b.txt\"\n              input: var/b1.txt\n";
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, cfg(files1)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("first (wipe) install should succeed");

    fs::write(rootfs.join("var").join("a1.txt"), "a2\n").unwrap();
    fs::write(rootfs.join("var").join("c1.txt"), "c1\n").unwrap();
    let files2 = "            - destination: \"var/a.txt\"\n              input: var/a1.txt\n            - destination: \"var/c.txt\"\n              input: var/c1.txt\n";
    fs::write(&config_path, cfg(files2)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("second (reconcile) install should succeed");

    let (off, size) = find_partition(&disk_image, "var");
    assert_eq!(
        read_ext4_file(&disk_image, off, size, "/var/a.txt"),
        b"a2\n",
        "a.txt overwritten"
    );
    assert_eq!(
        read_ext4_file(&disk_image, off, size, "/var/b.txt"),
        b"b1\n",
        "b.txt kept untouched"
    );
    assert_eq!(
        read_ext4_file(&disk_image, off, size, "/var/c.txt"),
        b"c1\n",
        "c.txt added"
    );
}

#[test]
fn reconcile_creates_missing_gpt_partition() {
    // Install (wipe) a single GPT partition; then reinstall without --wipe
    // with a manifest that adds a second partition. The existing partition
    // must be reused (its offset preserved) and the new one created.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let cfg = |second: bool| {
        let part2 = if second {
            r#"      - name: extra
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:etc
"#
        } else {
            ""
        };
        format!(
            r#"
name: reconpart
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
          excludePatterns:
            - "etc/**"
    etc:
      input:
        - destination: ""
          input: etc
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
{part2}
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            part2 = part2,
        )
    };

    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, cfg(false)).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    let (root_off, _) = find_partition(&disk_image, "root");

    fs::write(&config_path, cfg(true)).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("reconcile install should create the missing partition");

    assert_eq!(
        find_partition(&disk_image, "root").0,
        root_off,
        "root partition offset preserved"
    );
    let (extra_off, _) = find_partition(&disk_image, "extra");
    let mut f = fs::File::open(&disk_image).unwrap();
    f.seek(SeekFrom::Start(extra_off + 1024)).unwrap();
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).unwrap();
    assert_eq!(
        u32::from_le_bytes(magic),
        0xe0f5e1e2,
        "extra partition is not an EROFS image"
    );
    f.seek(SeekFrom::Start(root_off + 1024)).unwrap();
    f.read_exact(&mut magic).unwrap();
    assert_eq!(
        u32::from_le_bytes(magic),
        0xe0f5e1e2,
        "root partition image not replaced"
    );
}

#[test]
fn reconcile_idempotent_reinstall_without_wipe() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: reconidem
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
      - name: var
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "16M"
          files:
            - destination: "hello.txt"
              input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest: manifest.clone(),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    use hadris_part::scheme_io::GptDiskReadExt;
    let guid_before = {
        let mut f = fs::File::open(&disk_image).unwrap();
        let gpt = hadris_part::scheme::GptDisk::read_from(&mut f, 512).unwrap();
        gpt.entries
            .iter()
            .filter(|e| !e.is_unused())
            .map(|e| e.unique_guid.to_bytes())
            .collect::<Vec<_>>()
    };

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("idempotent re-install without --wipe");

    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");
    let guid_after = {
        let mut f = fs::File::open(&disk_image).unwrap();
        let gpt = hadris_part::scheme::GptDisk::read_from(&mut f, 512).unwrap();
        gpt.entries
            .iter()
            .filter(|e| !e.is_unused())
            .map(|e| e.unique_guid.to_bytes())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        guid_before, guid_after,
        "reused GPT table must not change partition GUIDs"
    );
}

#[test]
fn reconcile_lvm_reuses_existing_volumes_and_creates_new_one() {
    // Install (wipe) a single-PV VG with one LV (and reserved empty space so
    // the partition is large enough for a later LV); then reinstall without
    // --wipe adding a second LV. The existing LV is reused, the new LV created
    // in the free extents.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let cfg = |second_lv: bool, empty: &str| {
        let lv2 = if second_lv {
            r#"      - name: etc
        content:
          type: image
          input: build:erofs:etc
"#
        } else {
            ""
        };
        let empty_line = if empty.is_empty() {
            String::new()
        } else {
            format!("    emptySpace:\n      sizeMin: \"{empty}\"\n")
        };
        format!(
            r#"
name: reconlvm
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
          excludePatterns:
            - "etc/**"
    etc:
      input:
        - destination: ""
          input: etc
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: data
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: lvm
          vg: system
lvm:
  system:
{empty_line}    partitions:
      - name: rootfs
        content:
          type: image
          input: build:erofs:rootfs
{lv2}
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            lv2 = lv2,
            empty_line = empty_line,
        )
    };

    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, cfg(false, "48M")).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    fs::write(&config_path, cfg(true, "")).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("reconcile install should add the second LV");

    let (pv_off, pv_size) = find_partition(&disk_image, "data");
    let mut pv = sysimage::blockfile::BlockFile::open(&disk_image, pv_off, pv_size).unwrap();
    let vg = sysimage::lvm::read_vg_from_handle(&mut pv)
        .expect("read existing VG")
        .expect("an LVM PV exists");
    let names: Vec<&str> = vg.lvs.iter().map(|lv| lv.name.as_str()).collect();
    assert!(
        names.contains(&"rootfs"),
        "reused LV rootfs missing: {names:?}"
    );
    assert!(names.contains(&"etc"), "new LV etc missing: {names:?}");
}

#[test]
fn reconcile_luks_reuses_container_and_updates_content() {
    // Install (wipe) a LUKS2 container holding an ext4 filesystem with one
    // file; then reinstall without --wipe with the file's content changed and
    // a second file added. The LUKS2 header is reused (byte-identical) and the
    // inner ext4 is updated.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("secret")).unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let cfg = |files: &str| {
        format!(
            r#"
name: reconluks
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  root:
    type: luks
    name: root
    sectorSize: 512
    payloadAlign: "1M"
    kdf:
      type: pbkdf2
      hash: sha256
      iterations: 1000
    content:
      type: ext4
      emptySpace: "8M"
      files:
{files}
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            files = files,
        )
    };

    let config_path = workdir.path().join("sysimage.config.yml");

    fs::write(rootfs.join("secret").join("a1.txt"), "a1\n").unwrap();
    fs::write(rootfs.join("secret").join("b1.txt"), "b1\n").unwrap();
    let files1 = "        - destination: \"a.txt\"\n          input: secret/a1.txt\n        - destination: \"b.txt\"\n          input: secret/b1.txt\n";
    fs::write(&config_path, cfg(files1)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "root".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: [("root".to_string(), "recon-pass".to_string())].into(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    let header_before = fs::read(&disk_image).unwrap()[..4096].to_vec();

    fs::write(rootfs.join("secret").join("a1.txt"), "a2\n").unwrap();
    fs::write(rootfs.join("secret").join("c1.txt"), "c1\n").unwrap();
    let files2 = "        - destination: \"a.txt\"\n          input: secret/a1.txt\n        - destination: \"c.txt\"\n          input: secret/c1.txt\n";
    fs::write(&config_path, cfg(files2)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    install(InstallConfig {
        manifest,
        disk: [(
            "root".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: [("root".to_string(), "recon-pass".to_string())].into(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("reconcile install should reuse the LUKS container");

    let header_after = fs::read(&disk_image).unwrap()[..4096].to_vec();
    assert_eq!(
        header_before, header_after,
        "LUKS2 header changed during reconcile"
    );

    let data = fs::read(&disk_image).unwrap();
    let mut vol = sysimage::luks::open_luks2(std::io::Cursor::new(&data), b"recon-pass")
        .expect("decrypt with the same passphrase");
    let payload_size = vol.payload_size();
    let plain_path = workdir.path().join("plain.img");
    {
        let mut out = fs::File::create(&plain_path).unwrap();
        let chunk = 256 * 1024;
        let mut buf = vec![0u8; chunk];
        let mut off = 0u64;
        while off < payload_size {
            let n = (chunk as u64).min(payload_size - off) as usize;
            vol.read_at(off, &mut buf[..n]).unwrap();
            use std::io::Write;
            out.write_all(&buf[..n]).unwrap();
            off += n as u64;
        }
    }
    assert_eq!(
        read_ext4_file(&plain_path, 0, payload_size, "/a.txt"),
        b"a2\n",
        "a.txt updated"
    );
    assert_eq!(
        read_ext4_file(&plain_path, 0, payload_size, "/b.txt"),
        b"b1\n",
        "b.txt kept"
    );
    assert_eq!(
        read_ext4_file(&plain_path, 0, payload_size, "/c.txt"),
        b"c1\n",
        "c.txt added"
    );
}

fn read_fat_file(disk: &Path, part_off: u64, part_size: u64, path: &str) -> Vec<u8> {
    use hadris_fat::sync::{FatVolume, FatVolumeReadExt};
    let bf = sysimage::blockfile::BlockFile::open(disk, part_off, part_size).unwrap();
    let fs = FatVolume::open(bf).unwrap();
    let comps: Vec<&str> = path.trim_matches('/').split('/').collect();
    let mut dir = fs.root_dir();
    let mut entry = None;
    for (i, comp) in comps.iter().enumerate() {
        let found = dir.find(comp).unwrap().expect("FAT entry not found");
        if i + 1 == comps.len() {
            entry = Some(found);
        } else {
            dir = dir.open_entry(&found).unwrap();
        }
    }
    let entry = entry.unwrap();
    let mut reader = fs.read_file(&entry).unwrap();
    reader.read_to_vec().unwrap()
}

#[test]
fn reconcile_fat_reuses_filesystem_and_merges_archive() {
    // Same merge semantics as the ext4 test, but for a FAT (ESP) partition:
    // keep files absent from the new manifest, overwrite same-named files, add
    // new ones — all without reformatting the volume.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("esp")).unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let cfg = |files: &str| {
        format!(
            r#"
name: reconfat
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
          excludePatterns:
            - "esp/**"
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          emptySpace: "2M"
          files:
{files}
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            files = files,
        )
    };

    fs::write(rootfs.join("esp").join("a1.txt"), "a1\n").unwrap();
    fs::write(rootfs.join("esp").join("b1.txt"), "b1\n").unwrap();
    let files1 = "            - destination: \"a.txt\"\n              input: esp/a1.txt\n            - destination: \"b.txt\"\n              input: esp/b1.txt\n";
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, cfg(files1)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 32 * 1024 * 1024);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("first (wipe) install should succeed");

    fs::write(rootfs.join("esp").join("a1.txt"), "a2\n").unwrap();
    fs::write(rootfs.join("esp").join("c1.txt"), "c1\n").unwrap();
    let files2 = "            - destination: \"a.txt\"\n              input: esp/a1.txt\n            - destination: \"c.txt\"\n              input: esp/c1.txt\n";
    fs::write(&config_path, cfg(files2)).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("second (reconcile) install should succeed");

    let (off, size) = find_partition(&disk_image, "esp");
    assert_eq!(
        read_fat_file(&disk_image, off, size, "/a.txt"),
        b"a2\n",
        "a.txt overwritten"
    );
    assert_eq!(
        read_fat_file(&disk_image, off, size, "/b.txt"),
        b"b1\n",
        "b.txt kept untouched"
    );
    assert_eq!(
        read_fat_file(&disk_image, off, size, "/c.txt"),
        b"c1\n",
        "c.txt added"
    );
}

#[test]
fn reconcile_check_failure_leaves_disk_unchanged() {
    // A reconcile whose check phase fails (a reused partition is too small for
    // the new manifest) must not modify the disk at all.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    // First config: a small image partition "root".
    let cfg1 = format!(
        r#"
name: reconfail
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
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
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &cfg1).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    // Second config: reuse "root" but its content is now an ext4 filesystem
    // far larger than the small reused image partition.
    let cfg2 = format!(
        r#"
name: reconfail
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "48M"
          files:
            - destination: "hello.txt"
              input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    fs::write(&config_path, &cfg2).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let before = fs::read(&disk_image).unwrap();
    let err = install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    });
    assert!(
        err.is_err(),
        "reconcile should fail because the reused partition is too small"
    );
    let after = fs::read(&disk_image).unwrap();
    assert_eq!(before, after, "disk changed despite a failed check phase");
}

// ---------------------------------------------------------------------------
// Safety: refuse to install without --wipe when the target has an
// unrecognized format (no existing GPT / LUKS / LVM / filesystem).
// ---------------------------------------------------------------------------

#[test]
fn refuses_install_without_wipe_on_non_gpt_target() {
    // A file that exists and is non-empty but has no GPT signature.
    // Installing a GPT disk without --wipe must fail with a clear error,
    // not silently destroy the existing data.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: refusenogpt
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
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
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    // Create a pre-existing file with random (non-GPT) data.
    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    // Write some non-zero data at the GPT signature location to make sure
    // it's not accidentally a valid GPT.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&disk_image)
            .unwrap();
        f.seek(SeekFrom::Start(512)).unwrap();
        f.write_all(b"NOTGPT!!").unwrap();
    }

    let err = install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    });
    assert!(
        err.is_err(),
        "install without --wipe on non-GPT target should fail"
    );
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("does not contain an existing GPT") && msg.contains("--wipe"),
        "error message should mention the missing GPT and --wipe, got: {msg}"
    );
}

#[test]
fn refuses_install_without_wipe_on_non_luks_target() {
    // A partition that should hold a LUKS container but the existing
    // partition has no LUKS2 header. Without --wipe, this must fail.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: refusenoluks
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: luks
          name: crypt
          content:
            type: ext4
            emptySpace: "16M"
            files:
              - destination: "hello.txt"
                input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let _manifest = build_and_read_manifest(&config_path);

    // First: do a wipe install to create a disk with a GPT partition "root"
    // that contains a LUKS container.
    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 128 * 1024 * 1024);
    install(InstallConfig {
        manifest: build_and_read_manifest(&config_path),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: [("crypt".to_string(), "testpass".to_string())].into(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("first wipe install should succeed");

    // Now: overwrite the LUKS partition content with random data (simulating
    // a partition that exists but has no LUKS header), then try to reinstall
    // without --wipe. This should fail because the partition content is not
    // a recognized LUKS2 container.
    let (off, size) = find_partition(&disk_image, "root");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&disk_image)
            .unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&vec![0xABu8; size.min(1024 * 1024) as usize])
            .unwrap();
    }

    let err = install(InstallConfig {
        manifest: build_and_read_manifest(&config_path),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: [("crypt".to_string(), "testpass".to_string())].into(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    });
    assert!(
        err.is_err(),
        "install without --wipe on non-LUKS partition should fail"
    );
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("does not contain an existing LUKS2") && msg.contains("--wipe"),
        "error message should mention the missing LUKS2 and --wipe, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Fresh-disk-without-wipe tests
// ---------------------------------------------------------------------------

#[test]
fn fresh_disk_image_installs_without_wipe() {
    // A brand-new disk image file that does not exist yet should be installed
    // from scratch without requiring --wipe (we created it, so there is nothing
    // to reconcile or destroy).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: freshnowipe
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
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
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    // The disk file does NOT exist yet — install should create it and install
    // from scratch, all without --wipe.
    let disk_image = workdir.path().join("disk.img");
    assert!(!disk_image.exists(), "disk image should not exist yet");

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("install to a fresh disk image without --wipe should succeed");

    // The disk must now have a valid GPT.
    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");
    let (_off, size) = find_partition(&disk_image, "root");
    assert!(size > 0, "root partition should have non-zero size");
}

#[test]
fn fresh_empty_disk_image_installs_without_wipe() {
    // A disk image file that exists but is zero bytes should also be treated
    // as fresh (we truncate it to the required size; it has no data to lose).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: freshempty
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "16M"
          files:
            - destination: "hello.txt"
              input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    // Create a zero-byte file.
    let disk_image = workdir.path().join("disk.img");
    fs::write(&disk_image, b"").unwrap();
    assert_eq!(
        fs::metadata(&disk_image).unwrap().len(),
        0,
        "file should be empty"
    );

    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("install to a zero-byte disk image without --wipe should succeed");

    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");
    let (off, size) = find_partition(&disk_image, "root");
    assert_eq!(
        read_ext4_file(&disk_image, off, size, "/hello.txt"),
        b"hello install\n",
        "hello.txt should be present in the ext4 filesystem"
    );
}

// ---------------------------------------------------------------------------
// NBD backend: an in-process NBD server talks the wire protocol over an
// in-memory duplex (no sockets, so the test is hermetic and sandbox-proof),
// and the full install pipeline is driven against it through a
// `NbdRegion<DuplexHalf>` — exercising the whole generic-over-BlockRegion path
// over the NBD protocol end to end.
// ---------------------------------------------------------------------------

/// A blocking in-memory byte-stream channel (one direction of a duplex).
struct Channel {
    buf: Mutex<VecDeque<u8>>,
    closed: Mutex<bool>,
    cv: Condvar,
}

/// One half of an in-memory bidirectional stream. Reads pull from `rx` (the
/// peer's `tx`); writes push into `tx` (the peer's `rx`).
struct DuplexHalf {
    rx: Arc<Channel>,
    tx: Arc<Channel>,
}

fn duplex() -> (DuplexHalf, DuplexHalf) {
    let ab = Arc::new(Channel {
        buf: Mutex::new(VecDeque::new()),
        closed: Mutex::new(false),
        cv: Condvar::new(),
    });
    let ba = Arc::new(Channel {
        buf: Mutex::new(VecDeque::new()),
        closed: Mutex::new(false),
        cv: Condvar::new(),
    });
    (
        DuplexHalf {
            rx: ba.clone(),
            tx: ab.clone(),
        },
        DuplexHalf { rx: ab, tx: ba },
    )
}

impl io::Read for DuplexHalf {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let mut g = self.rx.buf.lock().unwrap();
        while g.is_empty() {
            if *self.rx.closed.lock().unwrap() {
                return Ok(0);
            }
            g = self.rx.cv.wait(g).unwrap();
        }
        let n = b.len().min(g.len());
        for slot in b.iter_mut().take(n) {
            *slot = g.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl io::Write for DuplexHalf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.tx.buf.lock().unwrap().extend(b.iter().copied());
        self.tx.cv.notify_all();
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for DuplexHalf {
    fn drop(&mut self) {
        *self.tx.closed.lock().unwrap() = true;
        self.tx.cv.notify_all();
    }
}

/// Serve a single NBD client over `conn` against the shared `backing` buffer:
/// newstyle fixed handshake with `NBD_OPT_GO`, then READ/WRITE/FLUSH/DISC.
fn serve_nbd(mut conn: DuplexHalf, backing: Arc<Mutex<Vec<u8>>>) {
    // greeting: NBDMAGIC + IHAVEOPT + 2-byte flags (FIXED_NEWSTYLE).
    let mut g = [0u8; 18];
    g[0..8].copy_from_slice(b"NBDMAGIC");
    g[8..16].copy_from_slice(b"IHAVEOPT");
    g[16..18].copy_from_slice(&1u16.to_be_bytes());
    conn.write_all(&g).unwrap();

    // client flags.
    let mut cf = [0u8; 4];
    conn.read_exact(&mut cf).unwrap();

    // NBD_OPT_GO option header + data.
    let mut hdr = [0u8; 16];
    conn.read_exact(&mut hdr).unwrap();
    assert_eq!(
        u64::from_be_bytes(hdr[0..8].try_into().unwrap()),
        0x49484156454F5054
    );
    assert_eq!(u32::from_be_bytes(hdr[8..12].try_into().unwrap()), 7);
    let len = u32::from_be_bytes(hdr[12..16].try_into().unwrap()) as usize;
    let mut data = vec![0u8; len];
    conn.read_exact(&mut data).unwrap();

    // NBD_REP_INFO (NBD_INFO_EXPORT) + NBD_REP_ACK.
    let size = backing.lock().unwrap().len() as u64;
    let trans_flags: u16 = (1 << 0) | (1 << 2); // HAS_FLAGS | SEND_FLUSH (writable)
    let mut info = Vec::new();
    info.extend_from_slice(&0u16.to_be_bytes()); // NBD_INFO_EXPORT
    info.extend_from_slice(&size.to_be_bytes());
    info.extend_from_slice(&trans_flags.to_be_bytes());
    let mut reply = Vec::new();
    reply.extend_from_slice(&0x0003e889045565a9u64.to_be_bytes()); // NBD_REP_MAGIC
    reply.extend_from_slice(&7u32.to_be_bytes()); // opt echo
    reply.extend_from_slice(&3u32.to_be_bytes()); // NBD_REP_INFO
    reply.extend_from_slice(&(info.len() as u32).to_be_bytes());
    reply.extend_from_slice(&info);
    conn.write_all(&reply).unwrap();
    let mut ack = Vec::new();
    ack.extend_from_slice(&0x0003e889045565a9u64.to_be_bytes());
    ack.extend_from_slice(&7u32.to_be_bytes());
    ack.extend_from_slice(&1u32.to_be_bytes()); // NBD_REP_ACK
    ack.extend_from_slice(&0u32.to_be_bytes());
    conn.write_all(&ack).unwrap();

    // transmission loop.
    loop {
        let mut req = [0u8; 28];
        if conn.read_exact(&mut req).is_err() {
            break;
        }
        if u32::from_be_bytes(req[0..4].try_into().unwrap()) != 0x25609513 {
            break;
        }
        let cmd = u16::from_be_bytes(req[6..8].try_into().unwrap());
        let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        let offset = u64::from_be_bytes(req[16..24].try_into().unwrap());
        let length = u32::from_be_bytes(req[24..28].try_into().unwrap());
        match cmd {
            0 /* READ */ => {
                let mut head = Vec::with_capacity(12 + length as usize);
                head.extend_from_slice(&0x67446698u32.to_be_bytes()); // simple reply magic
                head.extend_from_slice(&0u32.to_be_bytes()); // error
                head.extend_from_slice(&handle.to_be_bytes());
                {
                    let b = backing.lock().unwrap();
                    let start = offset as usize;
                    let end = start + length as usize;
                    if end <= b.len() {
                        head.extend_from_slice(&b[start..end]);
                    } else {
                        head.extend(std::iter::repeat_n(0u8, length as usize));
                    }
                }
                conn.write_all(&head).unwrap();
            }
            1 /* WRITE */ => {
                let mut wbuf = vec![0u8; length as usize];
                conn.read_exact(&mut wbuf).unwrap();
                {
                    let mut b = backing.lock().unwrap();
                    let start = offset as usize;
                    let end = start + length as usize;
                    if end <= b.len() {
                        b[start..end].copy_from_slice(&wbuf);
                    }
                }
                let mut head = Vec::with_capacity(12);
                head.extend_from_slice(&0x67446698u32.to_be_bytes());
                head.extend_from_slice(&0u32.to_be_bytes());
                head.extend_from_slice(&handle.to_be_bytes());
                conn.write_all(&head).unwrap();
            }
            3 /* FLUSH */ => {
                let mut head = Vec::with_capacity(12);
                head.extend_from_slice(&0x67446698u32.to_be_bytes());
                head.extend_from_slice(&0u32.to_be_bytes());
                head.extend_from_slice(&handle.to_be_bytes());
                conn.write_all(&head).unwrap();
            }
            2 /* DISC */ => break,
            _ => {
                let mut head = Vec::with_capacity(12);
                head.extend_from_slice(&0x67446698u32.to_be_bytes());
                head.extend_from_slice(&22u32.to_be_bytes()); // EINVAL
                head.extend_from_slice(&handle.to_be_bytes());
                conn.write_all(&head).unwrap();
            }
        }
    }
}

#[test]
fn installs_gpt_over_nbd() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nbdinst
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
      - name: var
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "64M"
          files:
            - destination: "var/hello.txt"
              input: hello.txt
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          emptySpace: "64M"
          files:
            - destination: "test.txt"
              input: hello.txt
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // 256 MiB is comfortably larger than the disk's computed minimum size.
    const EXPORT_SIZE: u64 = 256 * 1024 * 1024;
    let backing = Arc::new(Mutex::new(vec![0u8; EXPORT_SIZE as usize]));
    let (client, server) = duplex();
    let backing_for_server = Arc::clone(&backing);
    let server_thread = thread::spawn(move || serve_nbd(server, backing_for_server));

    // The client side goes through the negotiated export size reported by the
    // server; the install pipeline runs entirely over this NbdRegion.
    let region = sysimage::nbd::NbdRegion::<DuplexHalf>::open_handshake(client, "")
        .expect("NBD handshake should succeed");

    let mut ctx = sysimage::install::InstallContext::new(
        manifest.manifest.clone(),
        manifest.manifest_directory.clone(),
        true,
        std::collections::BTreeMap::new(),
    );
    let regions: std::collections::BTreeMap<String, sysimage::nbd::NbdRegion<DuplexHalf>> =
        std::collections::BTreeMap::from([("boot".to_string(), region)]);
    let fresh_disks = std::collections::BTreeMap::new();
    sysimage::install::install_regions(&mut ctx, regions, fresh_disks)
        .expect("install over NBD should succeed");

    // install_regions consumed the regions; dropping the last Arc<Mutex<NbdConn>>
    // sent NBD_CMD_DISC, so the server thread can now finish.
    server_thread.join().expect("NBD server thread panicked");

    // Verify the GPT was written into the remote export's backing buffer.
    let b = backing.lock().unwrap();
    assert_eq!(
        &b[512..520],
        b"EFI PART",
        "GPT signature missing in NBD export"
    );

    // The root partition begins at the first usable LBA; read the GPT header
    // to locate it, then check the EROFS superblock magic in that partition.
    let header = &b[512..512 + 92];
    assert_eq!(&header[0..8], b"EFI PART");
    let first_usable = u64::from_le_bytes(header[40..48].try_into().unwrap());
    let root_offset = first_usable * 512;
    let magic = u32::from_le_bytes(
        b[root_offset as usize + 1024..root_offset as usize + 1028]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        magic, 0xe0f5e1e2,
        "root partition is not an EROFS image over NBD"
    );
}

// ---------------------------------------------------------------------------
// image-block fast path: skip the copy when the region already contains the
// expected bytes (verified via BlockRegion::region_digest).
// ---------------------------------------------------------------------------

/// A minimal config: one GPT disk with a single raw `image` partition backed
/// by an EROFS build artifact. The image is content-addressed, so reinstalling
/// the same manifest yields the same source digest.
fn image_only_config(rootfs: &Path, output: &Path, temp: &Path) -> String {
    format!(
        r#"
name: imgskip
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
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
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    )
}

fn read_byte_at(disk: &Path, abs_offset: u64) -> u8 {
    let mut f = fs::File::open(disk).unwrap();
    f.seek(SeekFrom::Start(abs_offset)).unwrap();
    let mut b = [0u8; 1];
    f.read_exact(&mut b).unwrap();
    b[0]
}

fn write_byte_at(disk: &Path, abs_offset: u64, v: u8) {
    let mut f = fs::OpenOptions::new().write(true).open(disk).unwrap();
    f.seek(SeekFrom::Start(abs_offset)).unwrap();
    f.write_all(&[v]).unwrap();
}

#[test]
fn image_block_skips_copy_when_region_already_matches() {
    // Install (wipe) an image partition, then reinstall the *same* manifest
    // without --wipe. The image-block fast path computes the region digest,
    // finds it equal to the manifest digest, and skips the copy — the
    // partition bytes are left untouched.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = image_only_config(&rootfs, &output, &temp);
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest: build_and_read_manifest(&config_path),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("first (wipe) install should succeed");

    let (part_off, _part_size) = find_partition(&disk_image, "root");
    // A byte well inside the image (past the EROFS superblock).
    let probe = part_off + 4096;
    let original = read_byte_at(&disk_image, probe);

    // Reinstall the same manifest: the digest matches → copy is skipped.
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("second (reconcile) install should succeed");

    assert_eq!(
        read_byte_at(&disk_image, probe),
        original,
        "partition byte changed after a no-op reinstall (skip path should \
         leave the region untouched)"
    );

    // The partition is still a valid EROFS image.
    let mut f = fs::File::open(&disk_image).unwrap();
    f.seek(SeekFrom::Start(part_off + 1024)).unwrap();
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).unwrap();
    assert_eq!(u32::from_le_bytes(magic), 0xe0f5e1e2);
}

#[test]
fn image_block_recopies_when_region_differs_from_manifest() {
    // Install (wipe) an image partition, corrupt a byte inside it, then
    // reinstall the same manifest without --wipe. The region digest no longer
    // matches the manifest digest, so the fast path must *not* skip — the copy
    // runs and restores the correct image bytes. This proves the digest check
    // actually gates the copy (rather than always skipping).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = image_only_config(&rootfs, &output, &temp);
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let disk_image = workdir.path().join("disk.img");
    ensure_disk_size(&disk_image, 64 * 1024 * 1024);
    install(InstallConfig {
        manifest: build_and_read_manifest(&config_path),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("first (wipe) install should succeed");

    let (part_off, _part_size) = find_partition(&disk_image, "root");
    let probe = part_off + 4096;
    let original = read_byte_at(&disk_image, probe);

    // Corrupt a single byte inside the image partition.
    write_byte_at(&disk_image, probe, original ^ 0xFF);
    assert_ne!(read_byte_at(&disk_image, probe), original);

    install(InstallConfig {
        manifest: build_and_read_manifest(&config_path),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("second (reconcile) install should succeed");

    assert_eq!(
        read_byte_at(&disk_image, probe),
        original,
        "corrupted image partition was not restored — the digest mismatch \
         should have triggered a recopy"
    );
}

/// Read the MBR boot signature (bytes 510-511).
fn read_mbr_signature(disk: &Path) -> [u8; 2] {
    let mut f = fs::File::open(disk).unwrap();
    f.seek(SeekFrom::Start(510)).unwrap();
    let mut sig = [0u8; 2];
    f.read_exact(&mut sig).unwrap();
    sig
}

/// Read MBR partition entry `slot` (0-3): returns (boot_indicator, type_byte,
/// start_lba, sector_count).
fn read_mbr_partition(disk: &Path, slot: usize) -> (u8, u8, u32, u32) {
    let mut f = fs::File::open(disk).unwrap();
    let off = 446 + slot * 16;
    f.seek(SeekFrom::Start(off as u64)).unwrap();
    let mut entry = [0u8; 16];
    f.read_exact(&mut entry).unwrap();
    let boot = entry[0];
    let ptype = entry[4];
    let start_lba = u32::from_le_bytes(entry[8..12].try_into().unwrap());
    let sector_count = u32::from_le_bytes(entry[12..16].try_into().unwrap());
    (boot, ptype, start_lba, sector_count)
}

#[test]
fn installs_mbr_with_ext4_and_fat() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: instmbr
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: mbr
    partitions:
      - type: linux
        content:
          type: ext4
          emptySpace: "64M"
          files:
            - destination: "var/hello.txt"
              input: hello.txt
      - type: fat32
        content:
          type: fat
          emptySpace: "64M"
          files:
            - destination: "test.txt"
              input: hello.txt
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);

    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // MBR boot signature must be present.
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);

    // Slot 0: Linux (0x83), starts at LBA 2048 (1 MiB).
    let (boot0, type0, start0, count0) = read_mbr_partition(&disk_image, 0);
    assert_eq!(type0, 0x83);
    assert_eq!(start0, 2048);
    assert!(count0 > 0, "slot 0 should have non-zero sector count");
    assert_eq!(boot0, 0x00, "slot 0 not bootable");

    // Slot 1: FAT32 (0x0B).
    let (boot1, type1, start1, count1) = read_mbr_partition(&disk_image, 1);
    assert_eq!(type1, 0x0B);
    assert_eq!(start1, 2048 + count0);
    assert!(count1 > 0, "slot 1 should have non-zero sector count");
    assert_eq!(boot1, 0x00, "slot 1 not bootable");

    // Slots 2 and 3 must be empty.
    let (_, type2, _, _) = read_mbr_partition(&disk_image, 2);
    assert_eq!(type2, 0x00, "slot 2 empty");
    let (_, type3, _, _) = read_mbr_partition(&disk_image, 3);
    assert_eq!(type3, 0x00, "slot 3 empty");

    // Verify ext4 content in slot 0.
    let off0 = start0 as u64 * 512;
    let size0 = count0 as u64 * 512;
    let data = read_ext4_file(&disk_image, off0, size0, "var/hello.txt");
    assert_eq!(&data, b"hello install\n");
}

#[test]
fn installs_mbr_with_bootable_flag() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: instmbrboot
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: mbr
    partitions:
      - type: linux
        bootable: true
        content:
          type: ext4
          emptySpace: "32M"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    let (boot, type0, _, _) = read_mbr_partition(&disk_image, 0);
    assert_eq!(boot, 0x80, "slot 0 is bootable");
    assert_eq!(type0, 0x83);
}

#[test]
fn installs_hybrid_mbr_with_mirrored_esp() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: insthybrid
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: fat
          emptySpace: "64M"
          files:
            - destination: "test.txt"
              input: hello.txt
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "64M"
          files:
            - destination: "var/hello.txt"
              input: hello.txt
    mbr:
      protectiveSlot: 0
      mirrored:
        - partition: esp
          type: efi
          bootable: true
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // The disk must have both a valid MBR signature (LBA 0) and a GPT
    // signature (LBA 1).
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    assert_eq!(&read_gpt_signature(&disk_image), b"EFI PART");

    // MBR slot 0 is the protective (0xEE) entry.
    let (_, type0, _, _) = read_mbr_partition(&disk_image, 0);
    assert_eq!(type0, 0xEE, "slot 0 is protective MBR");

    // MBR slot 1 mirrors the ESP (type 0xEF, bootable).
    let (boot1, type1, start1, count1) = read_mbr_partition(&disk_image, 1);
    assert_eq!(type1, 0xEF, "slot 1 is EFI System Partition");
    assert_eq!(boot1, 0x80, "mirrored ESP is bootable");
    assert!(start1 >= 34, "mirrored partition starts after GPT headers");

    // The GPT must also contain the "esp" and "root" partitions.
    let (esp_off, _) = find_partition(&disk_image, "esp");
    let (root_off, _) = find_partition(&disk_image, "root");
    assert_eq!(
        esp_off,
        start1 as u64 * 512,
        "mirrored MBR ESP matches GPT ESP"
    );
    assert!(root_off > esp_off, "root partition after esp");

    // Verify FAT content.
    let esp_size = count1 as u64 * 512;
    let data = read_fat_file(&disk_image, esp_off, esp_size, "test.txt");
    assert_eq!(&data, b"hello install\n");
}

#[test]
fn reconcile_mbr_idempotent_reinstall() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: reconmbr
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: mbr
    partitions:
      - type: linux
        content:
          type: ext4
          emptySpace: "32M"
          files:
            - destination: "hello.txt"
              input: hello.txt
      - type: fat32
        content:
          type: fat
          emptySpace: "16M"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");

    // First install with --wipe.
    install(InstallConfig {
        manifest: manifest.clone(),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    // Capture the partition layout after the first install.
    let (boot0a, type0a, start0a, count0a) = read_mbr_partition(&disk_image, 0);
    let (boot1a, type1a, start1a, count1a) = read_mbr_partition(&disk_image, 1);

    // Second install WITHOUT --wipe — should reconcile and reuse existing
    // MBR partitions (matched by slot index).
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("idempotent re-install without --wipe");

    // The MBR signature and partition layout must be unchanged.
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    let (boot0b, type0b, start0b, count0b) = read_mbr_partition(&disk_image, 0);
    let (boot1b, type1b, start1b, count1b) = read_mbr_partition(&disk_image, 1);
    assert_eq!(
        (boot0a, type0a, start0a, count0a),
        (boot0b, type0b, start0b, count0b)
    );
    assert_eq!(
        (boot1a, type1a, start1a, count1a),
        (boot1b, type1b, start1b, count1b)
    );

    // Content must still be present in the ext4 partition.
    let off0 = start0b as u64 * 512;
    let size0 = count0b as u64 * 512;
    let data = read_ext4_file(&disk_image, off0, size0, "hello.txt");
    assert_eq!(&data, b"hello install\n");
}

#[test]
fn installs_mbr_with_bootcode() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    // 32-byte bootcode with a distinctive pattern.
    let bootcode = workdir.path().join("boot.bin");
    let boot_bytes: Vec<u8> = (0..32).map(|i| 0xA0 + i as u8).collect();
    fs::write(&bootcode, &boot_bytes).unwrap();

    let config = format!(
        r#"
name: instmbrbc
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: mbr
    bootcode: {bootcode}
    partitions:
      - type: linux
        content:
          type: ext4
          emptySpace: "32M"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        bootcode = bootcode.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // Boot signature and partition table must be intact.
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    let (_, type0, start0, count0) = read_mbr_partition(&disk_image, 0);
    assert_eq!(type0, 0x83);
    assert_eq!(start0, 2048);
    assert!(count0 > 0);

    // The first 32 bytes of the disk must be the bootcode; the rest of the
    // 446-byte bootstrap area must be zero.
    let mut f = fs::File::open(&disk_image).unwrap();
    let mut boot = [0u8; 446];
    f.read_exact(&mut boot).unwrap();
    assert_eq!(&boot[..32], &boot_bytes[..]);
    assert!(
        boot[32..].iter().all(|&b| b == 0),
        "bootstrap area zero-padded"
    );
}

#[test]
fn installs_gpt_with_bootcode() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    // 16-byte bootcode.
    let bootcode = workdir.path().join("boot.bin");
    let boot_bytes: Vec<u8> = (0..16).map(|i| 0xB0 + i as u8).collect();
    fs::write(&bootcode, &boot_bytes).unwrap();

    let config = format!(
        r#"
name: instgptbc
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: gpt
    bootcode: {bootcode}
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "32M"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        bootcode = bootcode.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // The protective MBR's partition entry (the 0xEE protective type at slot 0)
    // and the boot signature must be preserved.
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    let (_, ptype, _, _) = read_mbr_partition(&disk_image, 0);
    assert_eq!(ptype, 0xEE, "protective MBR entry preserved");

    // First 16 bytes are the bootcode; the rest of the bootstrap area is zero.
    let mut f = fs::File::open(&disk_image).unwrap();
    let mut boot = [0u8; 446];
    f.read_exact(&mut boot).unwrap();
    assert_eq!(&boot[..16], &boot_bytes[..]);
    assert!(
        boot[16..].iter().all(|&b| b == 0),
        "bootstrap area zero-padded"
    );

    // The GPT header signature ("EFI PART") at LBA 1 must still be present.
    assert_eq!(read_gpt_signature(&disk_image), *b"EFI PART");
}

#[test]
fn reconcile_keeps_bootcode_in_first_sector() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let bootcode = workdir.path().join("boot.bin");
    let boot_bytes: Vec<u8> = (0..20).map(|i| 0xC0 + i as u8).collect();
    fs::write(&bootcode, &boot_bytes).unwrap();

    let config = |boot: &str| {
        format!(
            r#"
name: reconbc
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  boot:
    type: mbr
    bootcode: {boot}
    partitions:
      - type: linux
        content:
          type: ext4
          emptySpace: "32M"
"#,
            rootfs = rootfs.display(),
            output = output.display(),
            temp = temp.display(),
            boot = boot,
        )
    };

    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, config(&bootcode.display().to_string())).unwrap();
    let manifest = build_and_read_manifest(&config_path);
    let disk_image = workdir.path().join("disk.img");

    // First install with --wipe.
    install(InstallConfig {
        manifest: manifest.clone(),
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: true,
    })
    .expect("wipe install");

    // Second install WITHOUT --wipe: the table is reused but the bootcode must
    // still be (re)written into the first sector.
    install(InstallConfig {
        manifest,
        disk: [(
            "boot".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: std::collections::BTreeMap::new(),
        force: false,
        wipe: false,
    })
    .expect("reconcile install");

    let mut f = fs::File::open(&disk_image).unwrap();
    let mut boot = [0u8; 446];
    f.read_exact(&mut boot).unwrap();
    assert_eq!(&boot[..20], &boot_bytes[..]);
    assert!(boot[20..].iter().all(|&b| b == 0));
    assert_eq!(read_mbr_signature(&disk_image), [0x55, 0xAA]);
    let (_, type0, start0, _) = read_mbr_partition(&disk_image, 0);
    assert_eq!(type0, 0x83);
    assert_eq!(start0, 2048);
}
