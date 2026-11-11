//! Integration tests for the `sign:<name>` input URL.
//!
//! A `cpio` artifact pulls content from `sign:enroll` (an enrollment-key
//! directory supplied via `--sign enroll=<dir>`). The cpio is placed in an LVM
//! image LV so it surfaces as a content-addressed `.bin` in the manifest. The
//! test zstd-decompresses the LV bytes and checks the enrollment material is
//! present when `--sign` was supplied and absent (but the build still
//! succeeds) when it was not — the missing-key case resolves to an empty
//! directory, never an error.
//!
//! No external tool is required: the cpio newc format stores filenames and
//! content as plaintext after zstd decompression, so substring checks suffice.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file_with_keys;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-sign-input-{}-{n}", std::process::id()));
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

/// Locate the content-addressed `.bin` backing the `image` LV of `vg` in the
/// manifest, read its bytes from the output directory, and return them.
fn read_image_lv_bytes(
    output: &Path,
    manifest: &serde_json::Value,
    vg: &str,
    lv_prefix: &str,
) -> Vec<u8> {
    let parts = &manifest["lvm"][vg]["partitions"];
    assert!(parts.is_array(), "manifest lvm.{vg}.partitions missing");
    let mut hash_file = None;
    for p in parts.as_array().unwrap() {
        let name = p["name"].as_str().unwrap_or("");
        if name.starts_with(lv_prefix) {
            let content = &p["content"];
            assert_eq!(
                content["type"], "image",
                "expected an image LV for {lv_prefix}"
            );
            hash_file = content["file"].as_str().map(|s| s.to_string());
            break;
        }
    }
    let hash_file = hash_file.unwrap_or_else(|| panic!("no image LV named {lv_prefix}*"));
    let path = output.join(&hash_file);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
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

/// zstd-decompress the LV bytes (a `build:cpio:` artifact stored verbatim).
fn decompress_cpio_lv(bytes: &[u8]) -> Vec<u8> {
    zstd::decode_all(bytes).unwrap_or_else(|e| panic!("zstd decode failed: {e}"))
}

/// Write a config that builds `cpio:enroll` from a files set referencing
/// `sign:enroll` (plus a always-present marker file), placing the result in an
/// LVM image LV so it appears as a content-addressed `.bin` in the manifest.
fn write_config(workdir: &Path, rootfs: &Path, output: &Path, temp: &Path) -> PathBuf {
    let config = format!(
        r#"
name: signinputtest
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  cpio:
    enroll:
      input:
        - destination: "marker.txt"
          input: "marker.txt"
        - destination: "efi/keys"
          input: "sign:enroll"
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
      - name: enroll-${{CONTENTHASH}}
        content:
          type: image
          input: build:cpio:enroll
cpio:
  compressionLevel: 3
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

const ENROLL_FILE: &str = "db.auth";
const ENROLL_SECRET: &str = "ENROLL_SECRET_DB_AUTH_CONTENT";
const MARKER: &str = "MARKER_PRESENT";

/// Materialize the input rootfs (with the always-present marker) and a
/// signing/enrollment-key directory containing one auth file.
fn make_inputs(workdir: &TempDir) -> (PathBuf, PathBuf) {
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("marker.txt"), MARKER.as_bytes()).unwrap();

    let enroll = workdir.path().join("enroll");
    fs::create_dir_all(&enroll).unwrap();
    fs::write(enroll.join(ENROLL_FILE), ENROLL_SECRET.as_bytes()).unwrap();
    (rootfs, enroll)
}

#[test]
fn sign_input_copies_files_when_key_supplied() {
    let workdir = TempDir::new();
    let (rootfs, enroll) = make_inputs(&workdir);

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("enroll".to_string(), enroll.clone());
    build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
    )
    .expect("build with --sign enroll should succeed");

    let manifest = read_manifest(&output, "signinputtest");
    let compressed = read_image_lv_bytes(&output, &manifest, "system", "enroll-");
    let cpio = decompress_cpio_lv(&compressed);

    // The always-present marker confirms the cpio was built and read back.
    assert!(
        cpio.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
        "marker file missing from cpio"
    );
    // The enrollment file name and its secret content must be present.
    assert!(
        cpio.windows(ENROLL_FILE.len())
            .any(|w| w == ENROLL_FILE.as_bytes()),
        "enrollment file name {ENROLL_FILE} missing from cpio"
    );
    assert!(
        cpio.windows(ENROLL_SECRET.len())
            .any(|w| w == ENROLL_SECRET.as_bytes()),
        "enrollment secret content missing from cpio"
    );
}

#[test]
fn sign_input_empty_when_key_not_supplied() {
    let workdir = TempDir::new();
    let (rootfs, _enroll) = make_inputs(&workdir);

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    // No --sign supplied: build must still succeed (sign:enroll → empty dir).
    build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect("build without --sign should succeed (sign: resolves to empty dir)");

    let manifest = read_manifest(&output, "signinputtest");
    let compressed = read_image_lv_bytes(&output, &manifest, "system", "enroll-");
    let cpio = decompress_cpio_lv(&compressed);

    // Marker still present (the cpio was built and read back).
    assert!(
        cpio.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
        "marker file missing from cpio"
    );
    // The enrollment material must be absent — the directory was empty.
    assert!(
        !cpio
            .windows(ENROLL_FILE.len())
            .any(|w| w == ENROLL_FILE.as_bytes()),
        "enrollment file name should be absent when --sign not supplied"
    );
    assert!(
        !cpio
            .windows(ENROLL_SECRET.len())
            .any(|w| w == ENROLL_SECRET.as_bytes()),
        "enrollment secret should be absent when --sign not supplied"
    );
}

#[test]
fn sign_input_shared_empty_dir_for_multiple_names() {
    // Two different unsupplied sign names in one build both resolve to an
    // empty directory and the build succeeds.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("marker.txt"), MARKER.as_bytes()).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config = format!(
        r#"
name: signshared
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  cpio:
    enroll:
      input:
        - destination: "marker.txt"
          input: "marker.txt"
        - destination: "a"
          input: "sign:alpha"
        - destination: "b"
          input: "sign:beta"
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
      - name: enroll-${{CONTENTHASH}}
        content:
          type: image
          input: build:cpio:enroll
cpio:
  compressionLevel: 3
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect("build with two unsupplied sign names should succeed");

    let manifest = read_manifest(&output, "signshared");
    let compressed = read_image_lv_bytes(&output, &manifest, "system", "enroll-");
    let cpio = decompress_cpio_lv(&compressed);
    assert!(
        cpio.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
        "marker file missing from cpio"
    );
}
