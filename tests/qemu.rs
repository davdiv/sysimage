//! End-to-end `qemu-install`: build a config, install it into raw images in a
//! directory via [`sysimage::qemu::qemu_install`], and verify that the image
//! files are created and a `qemu.json` launch config is generated. Also checks
//! that `qemu-run --print` produces a valid `qemu-system-*` command line.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file;
use sysimage::manifest::{ReadManifestConfig, read_manifest};
use sysimage::qemu::{QEMU_CONFIG_FILE, qemu_install};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-qemutest-{}-{n}", std::process::id()));
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
    fs::write(dir.join("hello.txt"), "hello qemu-install\n").unwrap();
}

#[cfg(unix)]
fn assert_same_inode(a: &Path, b: &Path, what: &str) {
    use std::os::unix::fs::MetadataExt;
    let am = fs::metadata(a).unwrap();
    let bm = fs::metadata(b).unwrap();
    assert_eq!(
        (am.dev(), am.ino()),
        (bm.dev(), bm.ino()),
        "{what}: {} and {} should share an inode",
        a.display(),
        b.display()
    );
}

/// Build a minimal config with the supplied `disk`/`qemu` YAML bodies and
/// return the error message. The bodies must include their own indentation.
fn build_error(workdir: &Path, case: &str, disk: &str, qemu: &str) -> String {
    let rootfs = workdir.join(format!("rootfs-{case}"));
    make_rootfs(&rootfs);
    let output = workdir.join(format!("output-{case}"));
    let temp = workdir.join(format!("temp-{case}"));
    let config = format!(
        r#"
name: qemu{case}
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
{disk}
qemu:
{qemu}
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        disk = disk,
        qemu = qemu,
    );
    let config_path = workdir.join(format!("{case}.yml"));
    fs::write(&config_path, &config).unwrap();
    match build_from_file(&config_path) {
        Ok(_) => panic!("expected build to fail for case {case}"),
        Err(e) => format!("{e}"),
    }
}

#[test]
fn qemu_install_creates_images_and_run_script() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: qemutest
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
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    // The QEMU directory does not exist yet — qemu_install must create it.
    let qemu_dir = workdir.path().join("qemu");
    assert!(!qemu_dir.exists());

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    qemu_install(
        manifest,
        &qemu_dir,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        true,
        false,
    )
    .expect("qemu_install should succeed");

    // The directory was created and holds the raw image + qemu.json config.
    assert!(qemu_dir.is_dir());
    let image = qemu_dir.join("boot.img");
    assert!(image.is_file(), "boot.img should exist");
    assert!(
        image.metadata().unwrap().len() > 0,
        "boot.img should be non-empty"
    );

    let qemu_config_path = qemu_dir.join(QEMU_CONFIG_FILE);
    let config_text = fs::read_to_string(&qemu_config_path).expect("qemu.json should exist");
    let config: sysimage::qemu::QemuConfig =
        serde_json::from_str(&config_text).expect("qemu.json is valid JSON");
    assert_eq!(config.arch, "x86_64");
    assert_eq!(config.disks.len(), 1);
    assert_eq!(config.disks["boot"]["file"], "boot.img");
    assert_eq!(config.disks["boot"]["if"], "virtio");

    // `qemu-run --print` resolves firmware and yields a qemu command line. If
    // the host lacks the UEFI firmware it errors with a clear message instead.
    match sysimage::qemu::build_command_line(&qemu_dir) {
        Ok(out) => {
            assert!(out.contains("qemu-system-x86_64"), "command line: {out}");
            assert!(out.contains("boot.img"), "command line: {out}");
            assert!(
                out.contains("if=pflash,format=raw,unit=0"),
                "command line: {out}"
            );
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("Could not find UEFI firmware"),
                "unexpected error: {msg}"
            );
        }
    }

    // Extra CLI arguments are appended after the generated QEMU arguments and
    // included in the printed command line.
    let extra = vec!["-serial".to_string(), "stdio".to_string()];
    match sysimage::qemu::build_command_line_with_extra_args(&qemu_dir, &extra) {
        Ok(out) => {
            assert!(out.ends_with("-serial stdio"), "command line: {out}");
            assert!(out.contains("boot.img"), "command line: {out}");
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("Could not find UEFI firmware"),
                "unexpected error: {msg}"
            );
        }
    }

    // Re-running without --wipe reuses the existing image file (reconcile path):
    // the file is not recreated and its size is preserved.
    let size_before = fs::metadata(&image).unwrap().len();
    let manifest2 = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest again");
    qemu_install(
        manifest2,
        &qemu_dir,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        false,
        false,
    )
    .expect("re-run qemu_install should succeed");
    let size_after = fs::metadata(&image).unwrap().len();
    assert_eq!(
        size_before, size_after,
        "existing image file should be reused (size preserved)"
    );
}

#[test]
fn qemu_install_copies_kernel_initrd_dtb_and_append() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    // Create kernel/initrd/dtb source files alongside the rootfs.
    let kernel_src = workdir.path().join("vmlinuz");
    let initrd_src = workdir.path().join("initramfs.img");
    let dtb_src = workdir.path().join("board.dtb");
    fs::write(&kernel_src, "kernel-blob").unwrap();
    fs::write(&initrd_src, "initrd-blob").unwrap();
    fs::write(&dtb_src, "dtb-blob").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: qemukernel
version: "1"
arch: aarch64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
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
qemu:
  kernel: {kernel_src}
  initrd: {initrd_src}
  dtb: {dtb_src}
  append: "root=/dev/mapper/rootfs console=ttyS0"
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        kernel_src = kernel_src.display(),
        initrd_src = initrd_src.display(),
        dtb_src = dtb_src.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let qemu_dir = workdir.path().join("qemu");
    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");
    let manifest_dir = manifest.manifest_directory.clone();
    let qemu_settings = manifest.manifest.qemu.clone().expect("qemu settings");
    let kernel_hash = qemu_settings.kernel.clone().expect("kernel hash");
    let initrd_hash = qemu_settings
        .initrd
        .as_ref()
        .and_then(|i| i.as_single())
        .expect("initrd hash")
        .to_string();
    let dtb_hash = qemu_settings.dtb.clone().expect("dtb hash");

    qemu_install(
        manifest,
        &qemu_dir,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        true,
        false,
    )
    .expect("qemu_install should succeed");

    // The kernel/initrd/dtb files should be materialized into the QEMU
    // directory under their stable local names.
    let kernel_file = qemu_dir.join("kernel");
    let initrd_file = qemu_dir.join("initrd");
    let dtb_file = qemu_dir.join("dtb");
    assert!(
        kernel_file.is_file(),
        "kernel file should exist in qemu dir"
    );
    assert_eq!(fs::read_to_string(&kernel_file).unwrap(), "kernel-blob");
    assert!(
        initrd_file.is_file(),
        "initrd file should exist in qemu dir"
    );
    assert_eq!(fs::read_to_string(&initrd_file).unwrap(), "initrd-blob");
    assert!(dtb_file.is_file(), "dtb file should exist in qemu dir");
    assert_eq!(fs::read_to_string(&dtb_file).unwrap(), "dtb-blob");

    // Immutable QEMU inputs are hard-linked to their content-addressed
    // artifacts in the normal same-filesystem case (copy is only a fallback).
    #[cfg(unix)]
    {
        assert_same_inode(&kernel_file, &manifest_dir.join(&kernel_hash), "kernel");
        assert_same_inode(&initrd_file, &manifest_dir.join(&initrd_hash), "initrd");
        assert_same_inode(&dtb_file, &manifest_dir.join(&dtb_hash), "dtb");
    }

    // The qemu.json config should reference the stable local names.
    let qemu_config_path = qemu_dir.join(QEMU_CONFIG_FILE);
    let config_text = fs::read_to_string(&qemu_config_path).expect("qemu.json should exist");
    let config: sysimage::qemu::QemuConfig =
        serde_json::from_str(&config_text).expect("qemu.json is valid JSON");
    assert_eq!(config.kernel.as_deref(), Some("kernel"));
    assert_eq!(config.initrd.as_deref(), Some("initrd"));
    assert_eq!(config.dtb.as_deref(), Some("dtb"));
    assert_eq!(
        config.append.as_deref(),
        Some("root=/dev/mapper/rootfs console=ttyS0")
    );

    // The manifest should record the kernel/initrd/dtb as content-addressed
    // output files (hash file names, not the stable local names).
    let manifest_files: Vec<_> = std::fs::read_dir(&manifest_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
        .collect();
    assert!(
        manifest_files.len() >= 3,
        "expected at least 3 .bin output files (kernel, initrd, dtb), got {}",
        manifest_files.len()
    );
}

#[test]
fn qemu_install_concatenates_multiple_initrds() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let initrd1 = workdir.path().join("initrd1.img");
    let initrd2 = workdir.path().join("initrd2.img");
    fs::write(&initrd1, b"ABCDE").unwrap();
    fs::write(&initrd2, b"XYZ").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: qemumultiinitrd
version: "1"
arch: aarch64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
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
qemu:
  initrd:
    - {initrd1}
    - {initrd2}
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        initrd1 = initrd1.display(),
        initrd2 = initrd2.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");
    let manifest_dir = manifest.manifest_directory.clone();
    let initrd_hash = manifest
        .manifest
        .qemu
        .as_ref()
        .expect("qemu settings")
        .initrd
        .as_ref()
        .and_then(|i| i.as_single())
        .expect("single concatenated initrd hash")
        .to_string();

    // The build output is one content-addressed file with ukify-style padding.
    let expected = b"ABCDE\0\0\0XYZ\0";
    assert_eq!(
        fs::read(manifest_dir.join(&initrd_hash)).unwrap(),
        expected,
        "content-addressed initrd should be the concatenated result"
    );

    let qemu_dir = workdir.path().join("qemu");
    qemu_install(
        manifest,
        &qemu_dir,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        true,
        false,
    )
    .expect("qemu_install should succeed");

    let initrd_file = qemu_dir.join("initrd");
    assert_eq!(fs::read(&initrd_file).unwrap(), expected);

    let config: sysimage::qemu::QemuConfig =
        serde_json::from_str(&fs::read_to_string(qemu_dir.join(QEMU_CONFIG_FILE)).unwrap())
            .unwrap();
    assert_eq!(config.initrd.as_deref(), Some("initrd"));
}

#[test]
fn qemu_install_attaches_external_disk_without_copy() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: qemuexternal
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk: {{}}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
erofs:
  blockSize: 4096
  timestamp: 1700000000000
qemu:
  disks:
    mydisk:
      input: build:erofs:rootfs
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
    assert!(
        manifest.manifest.disk.is_empty(),
        "disk: {{}} should suppress the default bootdisk"
    );
    let hash = manifest
        .manifest
        .qemu
        .as_ref()
        .expect("qemu settings")
        .disks
        .as_ref()
        .expect("qemu disks")
        .get("mydisk")
        .expect("mydisk")
        .get("input")
        .expect("resolved input")
        .clone();
    assert!(
        manifest.manifest.file.contains_key(&hash),
        "resolved artifact {hash} should be in the manifest"
    );
    let artifact = manifest.manifest_directory.join(&hash);
    assert!(artifact.is_file(), "artifact should exist");

    let qemu_dir = workdir.path().join("qemu");
    qemu_install(
        manifest,
        &qemu_dir,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        false,
        false,
    )
    .expect("qemu_install should succeed");

    let image = qemu_dir.join("mydisk.img");
    assert!(image.is_file(), "mydisk.img should exist");
    assert!(
        !qemu_dir.join("bootdisk.img").exists(),
        "the default bootdisk should not be installed"
    );

    #[cfg(unix)]
    assert_same_inode(&image, &artifact, "mydisk.img");

    let qemu_config_path = qemu_dir.join(QEMU_CONFIG_FILE);
    let config_text = fs::read_to_string(&qemu_config_path).expect("qemu.json should exist");
    let config: sysimage::qemu::QemuConfig =
        serde_json::from_str(&config_text).expect("qemu.json is valid JSON");
    assert_eq!(config.disks.len(), 1);
    let disk = &config.disks["mydisk"];
    assert_eq!(disk["file"], "mydisk.img");
    assert_eq!(disk["if"], "virtio");
    assert_eq!(disk["readonly"], "on");
    assert!(!disk.contains_key("input"), "input must not reach QEMU");

    match sysimage::qemu::build_command_line(&qemu_dir) {
        Ok(out) => {
            assert!(out.contains("file=mydisk.img"), "command line: {out}");
            assert!(out.contains("if=virtio"), "command line: {out}");
            assert!(out.contains("readonly=on"), "command line: {out}");
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("Could not find UEFI firmware"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn qemu_disks_input_rejected_for_manifest_disk() {
    let workdir = TempDir::new();
    let msg = build_error(
        workdir.path(),
        "manifest-input",
        "disk:\n  boot:\n    type: image\n    input: build:erofs:rootfs",
        "  disks:\n    boot:\n      input: build:erofs:rootfs\n",
    );
    assert!(
        msg.contains("qemu.disks.boot.input is only valid"),
        "unexpected error: {msg}"
    );
}

#[test]
fn qemu_disks_external_requires_input() {
    let workdir = TempDir::new();
    let msg = build_error(
        workdir.path(),
        "external-no-input",
        "disk: {}",
        "  disks:\n    mydisk:\n      if: virtio\n",
    );
    assert!(
        msg.contains("requires an `input`"),
        "unexpected error: {msg}"
    );
}

#[test]
fn qemu_disks_external_rejects_readonly_off() {
    let workdir = TempDir::new();
    let msg = build_error(
        workdir.path(),
        "external-readonly-off",
        "disk: {}",
        "  disks:\n    mydisk:\n      input: build:erofs:rootfs\n      readonly: \"off\"\n",
    );
    assert!(
        msg.contains("readonly must not be disabled"),
        "unexpected error: {msg}"
    );
}
