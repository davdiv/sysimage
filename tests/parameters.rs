//! Build parameters: declaration, default resolution, mandatory/unknown
//! validation, and `${name}` substitution during a build.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::BuildOverrides;
use sysimage::build::build_from_file_with_options;
use sysimage::config::resolve_parameters;
use sysimage::model::config::ConfigParameters;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-params-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
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

fn declared(yaml: &str) -> ConfigParameters {
    serde_yaml::from_str(yaml).unwrap()
}

/// A minimal FAT-image build config that uses a mandatory `${ROOTFS}` and an
/// optional `${GREETING}`.
fn minimal_config(output: &Path, temp: &Path) -> String {
    format!(
        r#"
name: paramtest
version: "1"
arch: x86_64
input: ${{ROOTFS}}
outputDirectory: {output}
tempDirectory: {temp}
parameters:
  ROOTFS: {{}}
  GREETING:
    default: hello
build:
  block:
    bootimg:
      type: fat
      files:
        - destination: "${{GREETING}}.TXT"
          input: hello.txt
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:bootimg
"#,
        output = output.display(),
        temp = temp.display(),
    )
}

#[test]
fn defaults_are_applied_and_overridden() {
    let decl = declared(
        r#"
GREETING:
  default: hello
COUNT:
  default: "1"
"#,
    );

    // No values supplied: defaults apply.
    let mut supplied = BTreeMap::new();
    let resolved = resolve_parameters(&decl, &supplied).unwrap();
    assert_eq!(resolved["GREETING"], "hello");
    assert_eq!(resolved["COUNT"], "1");

    // Supplied values win over defaults.
    supplied.insert("GREETING".to_string(), "bonjour".to_string());
    let resolved = resolve_parameters(&decl, &supplied).unwrap();
    assert_eq!(resolved["GREETING"], "bonjour");
    assert_eq!(resolved["COUNT"], "1");
}

#[test]
fn missing_mandatory_parameter_errors() {
    let decl = declared(
        r#"
OPTIONAL:
  default: x
MANDATORY: {}
"#,
    );
    let err = resolve_parameters(&decl, &BTreeMap::new()).unwrap_err();
    assert!(
        err.to_string().contains("MANDATORY"),
        "error should name the missing parameter: {err}"
    );
}

#[test]
fn unknown_supplied_parameter_errors() {
    let decl = declared(
        r#"
KNOWN:
  default: x
"#,
    );
    let mut supplied = BTreeMap::new();
    supplied.insert("BOGUS".to_string(), "y".to_string());
    let err = resolve_parameters(&decl, &supplied).unwrap_err();
    assert!(
        err.to_string().contains("BOGUS"),
        "error should name the unknown parameter: {err}"
    );
}

#[test]
fn reserved_parameter_name_is_rejected() {
    let decl = declared(
        r#"
CONFIGDIR:
  default: /tmp
"#,
    );
    let err = resolve_parameters(&decl, &BTreeMap::new()).unwrap_err();
    assert!(
        err.to_string().contains("CONFIGDIR"),
        "error should name the reserved parameter: {err}"
    );
}

#[test]
fn parameter_substitutes_in_inputs_and_destinations() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello build\n").unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: paramtest
version: "1"
arch: x86_64
input: ${{ROOTFS}}
outputDirectory: {output}
tempDirectory: {temp}
parameters:
  ROOTFS: {{}}
  GREETING:
    default: hello
build:
  block:
    bootimg:
      type: fat
      files:
        - destination: "${{GREETING}}.TXT"
          input: hello.txt
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:bootimg
"#,
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let mut params = BTreeMap::new();
    params.insert("ROOTFS".to_string(), rootfs.display().to_string());
    build_from_file_with_options(
        &config_path,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &params,
        &BuildOverrides::default(),
    )
    .expect("build with parameter substitution should succeed");

    // The single rendered FAT image should contain the substituted file name.
    let bin = fs::read_dir(&output)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "bin"))
        .expect("a rendered .bin artifact should exist");
    let bytes = fs::read(&bin).unwrap();
    let needle = b"HELLO";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "the substituted destination name should appear in the FAT image"
    );
}

#[test]
fn missing_mandatory_parameter_fails_build() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello build\n").unwrap();

    let config = format!(
        r#"
name: paramtest
version: "1"
arch: x86_64
input: ${{ROOTFS}}
outputDirectory: {output}
tempDirectory: {temp}
parameters:
  ROOTFS: {{}}
build:
  block:
    bootimg:
      type: fat
      files:
        - destination: ""
          input: hello.txt
disk:
  boot:
    type: gpt
    partitions:
      - name: whole
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:block:bootimg
"#,
        output = workdir.path().join("output").display(),
        temp = workdir.path().join("temp").display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    let err = build_from_file_with_options(
        &config_path,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BuildOverrides::default(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("ROOTFS"),
        "error should name the missing mandatory parameter: {err}"
    );
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sysimage")
}

#[test]
fn cli_build_accepts_declared_parameters() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hi\n").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, minimal_config(&output, &temp)).unwrap();

    let out = std::process::Command::new(bin())
        .arg("build")
        .arg("-c")
        .arg(&config_path)
        .arg("--param")
        .arg(format!("ROOTFS={}", rootfs.display()))
        .arg("--param")
        .arg("GREETING=hi")
        .output()
        .expect("run sysimage build");
    assert!(
        out.status.success(),
        "build should succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_build_rejects_unknown_parameter() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hi\n").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, minimal_config(&output, &temp)).unwrap();

    let out = std::process::Command::new(bin())
        .arg("build")
        .arg("-c")
        .arg(&config_path)
        .arg("--param")
        .arg(format!("ROOTFS={}", rootfs.display()))
        .arg("--param")
        .arg("BOGUS=1")
        .output()
        .expect("run sysimage build");
    assert!(
        !out.status.success(),
        "build should fail on an unknown param"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BOGUS"),
        "stderr should name the unknown parameter: {stderr}"
    );
}

#[test]
fn cli_build_overrides_name_and_version() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hi\n").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, minimal_config(&output, &temp)).unwrap();

    let out = std::process::Command::new(bin())
        .arg("build")
        .arg("-c")
        .arg(&config_path)
        .arg("--param")
        .arg(format!("ROOTFS={}", rootfs.display()))
        .arg("--name")
        .arg("custom")
        .arg("--version")
        .arg("42")
        .output()
        .expect("run sysimage build");
    assert!(
        out.status.success(),
        "build should succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The stable `<name>.json` symlink honors the override.
    let symlink = output.join("custom.json");
    assert!(
        symlink.exists(),
        "expected the manifests symlink custom.json to exist"
    );
    let text = fs::read_to_string(&symlink).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(manifest["name"], "custom");
    assert_eq!(manifest["version"], "42");

    // The original config name is not used for the output names.
    assert!(!output.join("paramtest.json").exists());
}

#[test]
fn cli_build_rejects_empty_name_override() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hi\n").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, minimal_config(&output, &temp)).unwrap();

    let out = std::process::Command::new(bin())
        .arg("build")
        .arg("-c")
        .arg(&config_path)
        .arg("--param")
        .arg(format!("ROOTFS={}", rootfs.display()))
        .arg("--name")
        .arg("")
        .output()
        .expect("run sysimage build");
    assert!(
        !out.status.success(),
        "build should fail on an empty --name override"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--name"),
        "stderr should mention the empty --name: {stderr}"
    );
}
