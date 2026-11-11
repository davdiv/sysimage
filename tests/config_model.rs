//! Config model: parsing, default-expansion, and partial-override merging.

use std::io::Write;
use sysimage::config::{default_expanded, expand_config, read_config, validate_and_expand_config};

/// Write `contents` to a fresh temp file and return its path. Keeps the tests
/// hermetic (no external checkout dependency).
fn write_temp_config(contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let n = std::process::id();
    static C: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let c = C.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    path.push(format!("sysimg-cfgmodel-{n}-{c}.yml"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

#[test]
fn default_expanded_round_trips() {
    let cfg = default_expanded().expect("default expands");
    // Re-serialize and re-parse to confirm stability.
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    let parsed: serde_json::Value = serde_yaml::from_str(&yaml).unwrap();
    assert!(parsed.get("build").is_some());
    assert!(parsed.get("disk").is_some());
}

#[test]
fn parses_example_config() {
    // A realistic config that overrides build.erofs with two artifacts and a
    // custom erofs timestamp, mirroring a real-world sysimage.config.yml.
    let path = write_temp_config(
        r#"
name: sysimg
input: ./rootfs
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
          excludePatterns:
            - "etc/**"
            - "boot/**"
    etc:
      input:
        - destination: ""
          input: etc
erofs:
  timestamp: 1784835412860
"#,
    );
    let with_dir = read_config(&path).expect("read example config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand example config");
    assert_eq!(expanded.config.name, "sysimg");
    // The config overrides build.erofs with rootfs + etc.
    assert!(expanded.config.build.erofs.contains_key("rootfs"));
    assert!(expanded.config.build.erofs.contains_key("etc"));
    // And defines an `etc` cpio-less erofs with input `etc`.
    let etc_entry = expanded.config.build.erofs["etc"]
        .input
        .iter()
        .find(|e| e.destination.is_empty())
        .expect("etc input has an empty-destination entry");
    assert_eq!(etc_entry.input, "etc");
    assert_eq!(expanded.config.erofs.timestamp, 1784835412860);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn parses_config_with_cpio_and_uki() {
    // A config that defines cpio and uki build artifacts.
    let path = write_temp_config(
        r#"
name: install-container
build:
  cpio:
    initrd:
      input:
        - destination: "etc/hostname"
          input: etc/hostname
  uki:
    uki: {}
"#,
    );
    let with_dir = read_config(&path).expect("read config");
    let expanded = validate_and_expand_config(&with_dir).expect("expand");
    assert_eq!(expanded.config.name, "install-container");
    assert!(expanded.config.build.cpio.contains_key("initrd"));
    assert!(expanded.config.build.uki.contains_key("uki"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn expand_merges_partial_overrides() {
    // Provide only a couple of fields; defaults fill the rest.
    let yaml = r#"
name: custom
erofs:
  blockSize: 2048
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    assert_eq!(expanded.name, "custom");
    assert_eq!(expanded.erofs.block_size, 2048);
    // Defaults still present.
    assert!(expanded.disk.contains_key("bootdisk"));
}

#[test]
fn expand_applies_qemu_overrides_leaving_rest_unset() {
    // Override a couple of QEMU fields; the rest stay unset (None) and are
    // resolved against the arch-derived defaults at `qemu-install` time.
    let yaml = r#"
arch: x86_64
qemu:
  smp: 8
  memory: 16G
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    // Overridden fields are applied.
    assert_eq!(expanded.qemu.smp, Some(8));
    assert_eq!(expanded.qemu.memory.as_deref(), Some("16G"));
    // Non-overridden fields stay unset; arch defaults apply later.
    assert_eq!(expanded.qemu.machine, None);
    assert_eq!(expanded.qemu.cpu, None);
    assert_eq!(expanded.qemu.extra_args, None);
}

#[test]
fn expand_leaves_qemu_unset_when_no_override() {
    // With no qemu override, every qemu field stays unset regardless of arch;
    // the arch-derived defaults are resolved at `qemu-install` time.
    let yaml = r#"
arch: aarch64
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    assert_eq!(expanded.qemu.machine, None);
    assert_eq!(expanded.qemu.cpu, None);
    assert_eq!(expanded.qemu.smp, None);
    assert_eq!(expanded.qemu.memory, None);
    assert_eq!(expanded.qemu.extra_args, None);
}

#[test]
fn expand_applies_qemu_kernel_initrd_dtb_append_overrides() {
    let yaml = r#"
arch: aarch64
qemu:
  kernel: file:vmlinuz
  initrd: file:initramfs.img
  dtb: file:board.dtb
  append: "root=/dev/sda2 console=ttyS0"
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    assert_eq!(expanded.qemu.kernel.as_deref(), Some("file:vmlinuz"));
    assert_eq!(
        expanded.qemu.initrd.as_ref().and_then(|i| i.as_single()),
        Some("file:initramfs.img")
    );
    assert_eq!(expanded.qemu.dtb.as_deref(), Some("file:board.dtb"));
    assert_eq!(
        expanded.qemu.append.as_deref(),
        Some("root=/dev/sda2 console=ttyS0")
    );
    // Non-overridden fields stay unset.
    assert_eq!(expanded.qemu.shim, None);
    assert_eq!(expanded.qemu.machine, None);
}

#[test]
fn expand_accepts_multiple_qemu_initrd_inputs() {
    let yaml = r#"
arch: aarch64
qemu:
  initrd:
    - file:initramfs-base.img
    - build:cpio:extra-files
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    let initrd = expanded.qemu.initrd.as_ref().expect("initrd");
    assert_eq!(
        initrd.inputs(),
        ["file:initramfs-base.img", "build:cpio:extra-files"]
    );
    // The list form is never collapsed to a single value pre-build.
    assert_eq!(initrd.as_single(), None);
}

#[test]
fn expand_accepts_empty_qemu_initrd_list() {
    let yaml = r#"
arch: aarch64
qemu:
  initrd: []
"#;
    let input: sysimage::model::config::ConfigBuild = serde_yaml::from_str(yaml).unwrap();
    let expanded = expand_config(&input).expect("expand");
    assert!(expanded.qemu.initrd.as_ref().unwrap().inputs().is_empty());
}
