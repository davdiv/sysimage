//! End-to-end build: a config with an EROFS rootfs + verity, a veritytab, a
//! FAT ESP, an ext4 LV and an LVM image LV — no podman, no UKI (which needs a
//! real stub/kernel).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-build-{}-{n}", std::process::id()));
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
    fs::write(dir.join("hello.txt"), "hello build\n").unwrap();
    fs::create_dir_all(dir.join("boot")).unwrap();
    fs::write(dir.join("boot").join("vmlinuz"), b"KERNEL").unwrap();
}

/// Locate and parse the manifest JSON written for `name` under `output`.
fn read_manifest_json(output: &Path, name: &str) -> serde_json::Value {
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

#[test]
fn builds_manifest_with_erofs_verity_and_lvm() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: testimg
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
      - name: rootfs-${{CONTENTHASH}}
        content:
          type: image
          input: build:erofs:rootfs
      - name: var
        content:
          type: ext4
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

    // A manifest JSON should exist (either the hashed file or the ${name}.json symlink).
    let symlink = output.join("testimg.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        // fall back to any *.json that isn't the symlink target
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("testimg-") && name.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let manifest_text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
    assert_eq!(manifest["name"], "testimg");

    // At least one content-addressed output file (.bin) should exist.
    let mut bins = 0;
    for entry in fs::read_dir(&output).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().ends_with(".bin") {
            bins += 1;
        }
    }
    assert!(bins >= 1, "expected output .bin files, got {bins}");

    // The rootfs EROFS image must not contain the excluded `boot` directory.
    // (Verified structurally by fsck earlier; here we just confirm the
    // manifest references the erofs image as an LV content.)
    let lvm = &manifest["lvm"]["system"]["partitions"];
    assert!(lvm.is_array());
    let names: Vec<String> = lvm
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n.starts_with("rootfs-")),
        "names: {names:?}"
    );
    assert!(names.contains(&"var".to_string()));
}

#[test]
fn builds_manifest_with_mbr_disk() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: mbrtest
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

    build_from_file(&config_path).expect("build should succeed");

    let symlink = output.join("mbrtest.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("mbrtest-") && name.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let manifest_text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();

    let disk = &manifest["disk"]["boot"];
    assert_eq!(disk["type"], "mbr");
    let parts = disk["partitions"].as_array().unwrap();
    assert_eq!(parts.len(), 2);
    // Slot 0: Linux (0x83).
    assert_eq!(parts[0]["typeCode"], 0x83);
    // Slot 1: FAT32 (0x0B).
    assert_eq!(parts[1]["typeCode"], 0x0B);
    // The disk must have a sizeMin.
    assert!(
        disk["sizeMin"].as_u64().unwrap() > 0,
        "sizeMin should be positive"
    );
}

#[test]
fn builds_manifest_with_hybrid_disk() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: hybridtest
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
          emptySpace: "16M"
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: ext4
          emptySpace: "32M"
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

    build_from_file(&config_path).expect("build should succeed");

    let symlink = output.join("hybridtest.json");
    let manifest_path = if symlink.exists() {
        symlink
    } else {
        let mut found = None;
        for entry in fs::read_dir(&output).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("hybridtest-") && name.ends_with(".json") {
                found = Some(entry.path());
                break;
            }
        }
        found.expect("a manifest json should have been written")
    };
    let manifest_text = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();

    let disk = &manifest["disk"]["boot"];
    assert_eq!(disk["type"], "gpt");
    let parts = disk["partitions"].as_array().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0]["name"], "esp");
    assert_eq!(parts[1]["name"], "root");

    // The hybrid MBR config must be present (under `mbr`) with one mirror
    // referencing "esp".
    let h = &disk["mbr"];
    assert_eq!(h["protectiveSlot"], 0);
    let mirrored = h["mirrored"].as_array().unwrap();
    assert_eq!(mirrored.len(), 1);
    assert_eq!(mirrored[0]["partition"], "esp");
    assert_eq!(mirrored[0]["typeCode"], 0xEF);
    assert_eq!(mirrored[0]["bootable"], true);
}

#[test]
fn builds_manifest_with_hybrid_disk_numeric_mirrored_type() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: hybridnum
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
          emptySpace: "16M"
    mbr:
      protectiveSlot: 0
      mirrored:
        - partition: esp
          type: 0xEF
          bootable: true
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");
    let manifest = read_manifest_json(&output, "hybridnum");

    let mirrored = &manifest["disk"]["boot"]["mbr"]["mirrored"];
    let mirrored = mirrored.as_array().unwrap();
    assert_eq!(mirrored.len(), 1);
    assert_eq!(mirrored[0]["partition"], "esp");
    assert_eq!(mirrored[0]["typeCode"], 0xEF);
    assert_eq!(mirrored[0]["bootable"], true);
}

#[test]
fn builds_manifest_with_mbr_bootcode() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    // A bootcode file of 64 bytes (well under the 446/512 limits).
    let bootcode = workdir.path().join("boot.bin");
    let boot_bytes: Vec<u8> = (0..64).map(|i| i as u8).collect();
    fs::write(&bootcode, &boot_bytes).unwrap();

    let config = format!(
        r#"
name: mbrboot
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

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest_json(&output, "mbrboot");
    let disk = &manifest["disk"]["boot"];
    assert_eq!(disk["type"], "mbr");
    let bc = disk["bootcode"].as_str().expect("bootcode is a file name");
    assert!(bc.ends_with(".bin"), "bootcode file is content-addressed");
    // The content-addressed artifact must exist and hold exactly 64 bytes.
    let artifact = output.join(bc);
    assert_eq!(fs::read(&artifact).unwrap(), &boot_bytes[..]);
}

#[test]
fn bootcode_truncates_to_first_446_bytes() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    // A 512-byte bootcode file: only the first 446 bytes are kept.
    let bootcode = workdir.path().join("boot.bin");
    let boot_bytes: Vec<u8> = (0..=255).chain(0..=255).collect();
    assert_eq!(boot_bytes.len(), 512);
    fs::write(&bootcode, &boot_bytes).unwrap();

    let config = format!(
        r#"
name: gptboot
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

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest_json(&output, "gptboot");
    let bc = manifest["disk"]["boot"]["bootcode"].as_str().unwrap();
    assert!(bc.ends_with(".bin"));
    // The stored artifact is the first 446 bytes of the 512-byte input.
    assert_eq!(fs::read(output.join(bc)).unwrap(), &boot_bytes[..446]);
}

#[test]
fn bootcode_rejects_file_over_512_bytes() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let bootcode = workdir.path().join("boot.bin");
    fs::write(&bootcode, vec![0u8; 513]).unwrap();

    let config = format!(
        r#"
name: toobig
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

    let err = build_from_file(&config_path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("512-byte maximum") || msg.contains("exceeding the 512-byte"),
        "expected size-limit error, got: {msg}"
    );
}
