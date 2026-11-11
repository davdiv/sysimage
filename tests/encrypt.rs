//! Integration tests for the `encrypt` and `decrypt` build artifacts.
//!
//! A plaintext input in the rootfs input directory is wrapped into a
//! device-bound "SENC" envelope (AES-256-GCM, deterministic nonce) and placed
//! either into an LVM image LV, into a rootfs `ConfigFileEntry`, or into a
//! UKI initramfs. The tests decrypt the produced ciphertext with the public
//! [`sysimage::encrypt::decrypt_envelope`] (the same code path intended for the
//! boot-side helper) and assert round-trip, determinism, and the documented
//! failure modes. No external tool is required.
//!
//! The `decrypt` artifact is the inverse: it unwraps a SENC envelope back into
//! plaintext at build time, so `build:encrypt:…` can be chained into
//! `build:decrypt:…` to feed a decrypted credential into a later build step.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::archive::{TreeNode, extract_archive_to_tree};
use sysimage::build::build_from_file_with_keys;
use sysimage::encrypt::{decrypt_envelope, derive_key};
use sysimage::input::{ResolvedInput, descend, parse_descent};
use sysimage::model::config::ArchiveFormat;
use sysimage::ukify::ukify_inspect;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-encrypt-{}-{n}", std::process::id()));
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

/// The fixed 32-byte test key. The last byte (0x20) is deliberately *not* a
/// newline, so the `--key-file` verbatim convention leaves the key intact.
fn test_key() -> Vec<u8> {
    (1u8..=32).collect()
}

/// The envelope key derived from the single `test_key()` component, matching
/// how the build derives it.
fn derived_key() -> [u8; 32] {
    derive_key(&[&test_key()]).unwrap()
}

/// Write the 32-byte test key to a file and return its path.
fn write_key_file(dir: &Path) -> PathBuf {
    let path = dir.join("devicekey.bin");
    fs::write(&path, test_key()).unwrap();
    path
}

/// Write arbitrary key bytes to `name` under `dir` and return the path.
fn write_key_bytes(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// Write a key file of an explicit length (for the wrong-length failure test).
fn write_key_file_len(dir: &Path, len: usize) -> PathBuf {
    let path = dir.join("shortkey.bin");
    fs::write(&path, vec![7u8; len]).unwrap();
    path
}

fn make_rootfs(dir: &Path) {
    fs::create_dir_all(dir.join("etc")).unwrap();
    fs::write(dir.join("secret.txt"), b"super-secret-luks-key-material\n").unwrap();
    fs::write(dir.join("etc").join("os-release"), "ID=encrypt\n").unwrap();
}

/// Locate and parse the manifest JSON written for `name` under `output`.
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

/// Read the content-addressed `.bin` backing the `image` LV of `vg` in the
/// manifest, returning its bytes and file name.
fn read_image_lv_bytes(
    output: &Path,
    manifest: &serde_json::Value,
    vg: &str,
    lv_prefix: &str,
) -> (Vec<u8>, String) {
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
    (
        fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
        hash_file,
    )
}

/// The single `.bin` file in `output` (used when a build produces exactly one
/// content-addressed artifact).
fn only_bin(output: &Path) -> PathBuf {
    let mut found = Vec::new();
    for entry in fs::read_dir(output).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().ends_with(".bin") {
            found.push(entry.path());
        }
    }
    assert_eq!(found.len(), 1, "expected exactly one .bin, got {found:?}");
    found.pop().unwrap()
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

/// Navigate an in-memory tree to a regular file's content.
fn tree_file<'a>(node: &'a TreeNode, path: &[&str]) -> Option<&'a [u8]> {
    match path.split_first() {
        None => match node {
            TreeNode::File { content, .. } => Some(content),
            _ => None,
        },
        Some((first, rest)) => match node {
            TreeNode::Dir { children, .. } => children.get(*first).and_then(|c| tree_file(c, rest)),
            _ => None,
        },
    }
}

/// A config that wraps `secret.txt` into `build:encrypt:cred` and places it
/// into an LVM image LV, so it surfaces as a content-addressed `.bin`.
fn write_image_config(workdir: &Path, rootfs: &Path, output: &Path, temp: &Path) -> PathBuf {
    let config = format!(
        r#"
name: encrypttest
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: devicekey
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
      - name: cred
        content:
          type: image
          input: build:encrypt:cred
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
    let config_path = workdir.join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

/// Build with a supplied `--key-file` and return the manifest.
fn build_with_key(config_path: &Path, key_path: Option<&Path>) -> sysimage::error::Result<()> {
    let mut key_file = BTreeMap::new();
    if let Some(p) = key_path {
        key_file.insert("devicekey".to_string(), p.to_path_buf());
    }
    build_from_file_with_keys(config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
        .map(|_| ())
}

// --- tests ----------------------------------------------------------------

#[test]
fn encrypt_round_trip_manifest_and_no_plaintext_leak() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_image_config(workdir.path(), &rootfs, &output, &temp);
    let key_path = write_key_file(workdir.path());

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");

    let manifest = read_manifest(&output, "encrypttest");
    let (ciphertext, hash_file) = read_image_lv_bytes(&output, &manifest, "system", "cred");

    // The ciphertext is the SENC envelope: decrypt it and compare.
    assert_eq!(&ciphertext[..4], b"SENC", "envelope magic");
    let plaintext = decrypt_envelope(&ciphertext, &derived_key()).expect("decrypt");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");

    // The manifest records the ciphertext as a normal content-addressed file.
    let entry = &manifest["file"][&hash_file];
    assert_eq!(entry["size"].as_u64().unwrap(), ciphertext.len() as u64);
    assert!(
        entry["hash"].as_str().unwrap().len() == 64,
        "manifest hash is a sha256 hex digest"
    );

    // The plaintext must NOT appear anywhere in the produced output files.
    let needle = b"super-secret-luks-key-material";
    let mut checked = 0;
    for e in fs::read_dir(&output).unwrap() {
        let e = e.unwrap();
        if e.file_name().to_string_lossy().ends_with(".bin") {
            let bytes = fs::read(e.path()).unwrap();
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "plaintext leaked into {}",
                e.path().display()
            );
            // The key must not appear either (it would make the encryption pointless).
            let key = test_key();
            assert!(
                !bytes.windows(key.len()).any(|w| w == key),
                "key material leaked into {}",
                e.path().display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 1, "expected at least one .bin to inspect");
}

#[test]
fn encrypt_is_deterministic_across_builds() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let key_path = write_key_file(workdir.path());

    let mut results = Vec::new();
    for i in 0..2 {
        let output = workdir.path().join(format!("output{i}"));
        let temp = workdir.path().join(format!("temp{i}"));
        let config_path = write_image_config(workdir.path(), &rootfs, &output, &temp);
        build_with_key(&config_path, Some(&key_path)).expect("build should succeed");
        let manifest = read_manifest(&output, "encrypttest");
        let (bytes, hash_file) = read_image_lv_bytes(&output, &manifest, "system", "cred");
        results.push((bytes, hash_file));
    }

    assert_eq!(
        results[0].1, results[1].1,
        "deterministic artifact must have the same content hash across builds"
    );
    assert_eq!(
        results[0].0, results[1].0,
        "deterministic artifact bytes must be identical across builds"
    );
}

#[test]
fn encrypt_fails_without_key() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_image_config(workdir.path(), &rootfs, &output, &temp);

    let res = build_with_key(&config_path, None);
    assert!(res.is_err(), "build must fail when the key is not supplied");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("devicekey") && msg.contains("was not supplied"),
        "error should name the missing key: {msg}"
    );
}

#[test]
fn encrypt_accepts_arbitrary_length_key_components() {
    // Key components are arbitrary-length files combined by HKDF-SHA256 into
    // the 32-byte envelope key; there is no fixed length requirement on the
    // individual components.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_image_config(workdir.path(), &rootfs, &output, &temp);
    let key_path = write_key_file_len(workdir.path(), 31);

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");
    let manifest = read_manifest(&output, "encrypttest");
    let (ciphertext, _) = read_image_lv_bytes(&output, &manifest, "system", "cred");

    let component = [7u8; 31];
    let expected = derive_key(&[&component[..]]).unwrap();
    assert_eq!(
        decrypt_envelope(&ciphertext, &expected).unwrap(),
        b"super-secret-luks-key-material\n"
    );
}

#[test]
fn encrypt_rejects_unsupported_algorithm() {
    // The `algorithm` enum only permits `aes-256-gcm`; anything else must be
    // rejected by schema validation at config load time.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = workdir.path().join("bad.yml");
    let config = format!(
        r#"
name: badalg
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: devicekey
      algorithm: aes-128-gcm
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    fs::write(&config_path, &config).unwrap();

    let res = build_with_key(&config_path, Some(&write_key_file(workdir.path())));
    assert!(res.is_err(), "unsupported algorithm must be rejected");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("aes-128-gcm") || msg.contains("valid") || msg.contains("enum"),
        "error should mention the invalid algorithm: {msg}"
    );
}

#[test]
fn encrypt_placed_in_filesystem_destination() {
    // An `encrypt` artifact used as the `input` of a rootfs `ConfigFileEntry`
    // must land at the requested destination inside the EROFS image.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config = format!(
        r#"
name: encryptfs
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: devicekey
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
        - destination: etc/ssh/keys.enc
          input: build:encrypt:cred
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
    let config_path = workdir.path().join("fs.yml");
    fs::write(&config_path, &config).unwrap();
    let key_path = write_key_file(workdir.path());

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");

    // Descend into the EROFS image and read the placed file back.
    let bin = only_bin(&output);
    let steps = parse_descent("erofs:/etc/ssh/keys.enc").unwrap();
    let keys = BTreeMap::<String, Vec<u8>>::new();
    let resolved = descend(&bin, &steps, &keys).unwrap();
    let ciphertext = read_virtual_file(&resolved);
    assert_eq!(&ciphertext[..4], b"SENC");
    let plaintext = decrypt_envelope(&ciphertext, &derived_key()).expect("decrypt");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");
}

#[test]
fn encrypt_wrapped_in_cpio_in_initramfs() {
    // An encrypted credential reaches the initramfs by being wrapped in a
    // `cpio` artifact that names its in-initramfs path; that `build:cpio:<name>`
    // is what `uki.initrd` lists.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    fs::write(rootfs.join("stub.efi"), build_minimal_stub()).unwrap();
    fs::write(rootfs.join("vmlinuz"), b"FAKE_KERNEL").unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config = format!(
        r#"
name: encryptuki
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: devicekey
  cpio:
    lukscred:
      input:
        - destination: etc/encrypt/cred.enc
          input: build:encrypt:cred
  uki:
    boot:
      stub: stub.efi
      kernel: vmlinuz
      initrd:
        - build:cpio:lukscred
disk:
  boot:
    type: gpt
    partitions:
      - name: esp
        type: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        content:
          type: image
          input: build:uki:boot
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("uki.yml");
    fs::write(&config_path, &config).unwrap();
    let key_path = write_key_file(workdir.path());

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");

    let bin = only_bin(&output);
    let sections = ukify_inspect(&bin).expect("inspect UKI");
    let initrd_hex = sections[".initrd"]
        .as_str()
        .expect("UKI must have an .initrd section");
    let initrd = hex::decode(initrd_hex).unwrap();

    // The initrd is a zstd-compressed cpio: decode it and find the file.
    let archive_path = workdir.path().join("initrd.cpio.zst");
    fs::write(&archive_path, &initrd).unwrap();
    let tree = extract_archive_to_tree(&archive_path, ArchiveFormat::Cpio).expect("extract initrd");

    let placed = tree_file(&tree, &["etc", "encrypt", "cred.enc"])
        .expect("initramfs must contain etc/encrypt/cred.enc");
    assert_eq!(&placed[..4], b"SENC");
    let plaintext = decrypt_envelope(placed, &derived_key()).expect("decrypt");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");
}

// --- multi-component keys and verbatim key files ---------------------------

#[test]
fn encrypt_combines_multiple_key_components() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config = format!(
        r#"
name: encryptmulti
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: [k1, k2]
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
      - name: cred
        content:
          type: image
          input: build:encrypt:cred
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
    let config_path = workdir.path().join("multi.yml");
    fs::write(&config_path, &config).unwrap();

    let k1 = write_key_bytes(workdir.path(), "k1.bin", b"component-one");
    let k2 = write_key_bytes(workdir.path(), "k2.bin", b"component-two");
    let mut key_file = BTreeMap::new();
    key_file.insert("k1".to_string(), k1);
    key_file.insert("k2".to_string(), k2);
    build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
        .expect("build should succeed");

    let manifest = read_manifest(&output, "encryptmulti");
    let (ciphertext, _) = read_image_lv_bytes(&output, &manifest, "system", "cred");
    assert_eq!(&ciphertext[..4], b"SENC");

    // The key is HKDF over the components in config order.
    let expected = derive_key(&[b"component-one", b"component-two"]).unwrap();
    let plaintext = decrypt_envelope(&ciphertext, &expected).expect("decrypt");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");

    // Reversing the component order must NOT decrypt.
    let reversed = derive_key(&[b"component-two", b"component-one"]).unwrap();
    assert!(decrypt_envelope(&ciphertext, &reversed).is_err());
}

#[test]
fn key_file_is_used_verbatim_without_stripping_newline() {
    // A trailing newline in a key file is part of the key material (the
    // standalone `senc` helper reads key files verbatim too).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_image_config(workdir.path(), &rootfs, &output, &temp);
    let key_path = write_key_bytes(workdir.path(), "devicekey.bin", b"with-newline\n");

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");
    let manifest = read_manifest(&output, "encrypttest");
    let (ciphertext, _) = read_image_lv_bytes(&output, &manifest, "system", "cred");

    // The newline is part of the key: the stripped variant must not decrypt…
    let stripped = derive_key(&[b"with-newline"]).unwrap();
    assert!(decrypt_envelope(&ciphertext, &stripped).is_err());
    // …but the verbatim bytes do.
    let verbatim = derive_key(&[b"with-newline\n"]).unwrap();
    assert_eq!(
        decrypt_envelope(&ciphertext, &verbatim).unwrap(),
        b"super-secret-luks-key-material\n"
    );
}

// --- decrypt artifact ------------------------------------------------------

/// A config with an `encrypt` artifact (`cred`) and a matching `decrypt`
/// artifact (`plain`) whose `input` is the encrypt artifact's envelope. The
/// decrypted plaintext is placed into an LVM image LV named `plain`, so it
/// surfaces as a content-addressed `.bin`.
fn write_decrypt_config(
    workdir: &Path,
    rootfs: &Path,
    output: &Path,
    temp: &Path,
    encrypt_key: &str,
    decrypt_key: &str,
    decrypt_input: &str,
) -> PathBuf {
    let config = format!(
        r#"
name: decrypttest
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: {encrypt_key}
  decrypt:
    plain:
      input: {decrypt_input}
      key: {decrypt_key}
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
      - name: plain
        content:
          type: image
          input: build:decrypt:plain
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
    let config_path = workdir.join("sysimage.decrypt.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

#[test]
fn decrypt_round_trips_encrypt_artifact() {
    // `build:decrypt:plain` takes `build:encrypt:cred` as its input: the
    // ciphertext produced by the `encrypt` artifact is unwrapped back into the
    // original plaintext, which lands in the LVM image.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "devicekey",
        "devicekey",
        "build:encrypt:cred",
    );
    let key_path = write_key_file(workdir.path());

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");

    let manifest = read_manifest(&output, "decrypttest");
    let (plaintext, hash_file) = read_image_lv_bytes(&output, &manifest, "system", "plain");
    assert_eq!(
        plaintext, b"super-secret-luks-key-material\n",
        "decrypt must recover the original plaintext"
    );

    // The decrypted plaintext is recorded as a normal content-addressed file.
    let entry = &manifest["file"][&hash_file];
    assert_eq!(entry["size"].as_u64().unwrap(), plaintext.len() as u64);
    assert_eq!(entry["hash"].as_str().unwrap().len(), 64);
}

#[test]
fn decrypt_accepts_plain_file_envelope() {
    // The decrypt artifact's `input` may be any input specifier: here, a SENC
    // envelope written directly into the rootfs input directory (produced by
    // the public `encrypt_envelope` API) is decrypted from a `file:` path.
    use sysimage::encrypt::{EncryptAlgorithm, encrypt_envelope};

    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);

    let key = test_key();
    let derived = derive_key(&[&key]).unwrap();
    let envelope =
        encrypt_envelope(b"from-a-file\n", &derived, EncryptAlgorithm::Aes256Gcm).unwrap();
    fs::write(rootfs.join("cred.enc"), &envelope).unwrap();

    // A decrypt-only config that reads the envelope from the rootfs file.
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config = format!(
        r#"
name: decryptfile
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  decrypt:
    plain:
      input: cred.enc
      key: devicekey
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
      - name: plain
        content:
          type: image
          input: build:decrypt:plain
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
    let config_path = workdir.path().join("file.yml");
    fs::write(&config_path, &config).unwrap();
    let key_path = write_key_file(workdir.path());

    build_with_key(&config_path, Some(&key_path)).expect("build should succeed");

    let manifest = read_manifest(&output, "decryptfile");
    let (plaintext, _) = read_image_lv_bytes(&output, &manifest, "system", "plain");
    assert_eq!(plaintext, b"from-a-file\n");
}

#[test]
fn decrypt_fails_without_key() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "devicekey",
        "devicekey",
        "build:encrypt:cred",
    );

    let res = build_with_key(&config_path, None);
    assert!(res.is_err(), "build must fail when the key is not supplied");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("decrypt") && msg.contains("devicekey") && msg.contains("was not supplied"),
        "error should name the artifact and the missing key: {msg}"
    );
}

#[test]
fn decrypt_fails_with_wrong_key() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "goodkey",
        "badkey",
        "build:encrypt:cred",
    );
    // The envelope is produced with the correct `goodkey`, but decryption is
    // attempted with a different `badkey`, so GCM authentication fails.
    let good = write_key_bytes(workdir.path(), "good.bin", &test_key());
    let bad = write_key_bytes(workdir.path(), "bad.bin", b"the-wrong-key-material");
    let mut key_file = BTreeMap::new();
    key_file.insert("goodkey".to_string(), good);
    key_file.insert("badkey".to_string(), bad);

    let res =
        build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new());
    assert!(res.is_err(), "decryption with the wrong key must fail");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("authentication failed"),
        "error should mention authentication failure: {msg}"
    );
}

#[test]
fn decrypt_rejects_non_envelope_input() {
    // `secret.txt` is plaintext, not a SENC envelope: the decrypt artifact must
    // reject it rather than pass it through.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "devicekey",
        "devicekey",
        "secret.txt",
    );

    let res = build_with_key(&config_path, Some(&write_key_file(workdir.path())));
    assert!(res.is_err(), "a non-envelope input must be rejected");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("too short") || msg.contains("magic"),
        "error should describe the malformed envelope: {msg}"
    );
}

#[test]
fn decrypt_combines_multiple_key_components() {
    // Multi-component keys work the same way as for `encrypt`: the components
    // are combined, in config order, with HKDF-SHA256.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "[k1, k2]",
        "[k1, k2]",
        "build:encrypt:cred",
    );

    let k1 = write_key_bytes(workdir.path(), "k1.bin", b"component-one");
    let k2 = write_key_bytes(workdir.path(), "k2.bin", b"component-two");
    let mut key_file = BTreeMap::new();
    key_file.insert("k1".to_string(), k1);
    key_file.insert("k2".to_string(), k2);
    build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
        .expect("build should succeed");

    let manifest = read_manifest(&output, "decrypttest");
    let (plaintext, _) = read_image_lv_bytes(&output, &manifest, "system", "plain");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");
}

#[test]
fn decrypt_fails_with_reversed_key_order() {
    // A mismatched component order derives a different key and must not
    // authenticate (mirroring the `encrypt` order-sensitivity test).
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_decrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        "[k1, k2]",
        "[k2, k1]",
        "build:encrypt:cred",
    );

    let k1 = write_key_bytes(workdir.path(), "k1.bin", b"component-one");
    let k2 = write_key_bytes(workdir.path(), "k2.bin", b"component-two");
    let mut key_file = BTreeMap::new();
    key_file.insert("k1".to_string(), k1);
    key_file.insert("k2".to_string(), k2);
    let res =
        build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new());
    assert!(res.is_err(), "reversed key order must not authenticate");
}

// --- reencrypt artifact ----------------------------------------------------

/// A config with an `encrypt` artifact (`cred`) and a `reencrypt` artifact
/// (`rot`) that rotates it from `decrypt_key` to `new_key`. The rotated
/// envelope is placed into an LVM image LV named `rotated`.
///
/// `keys` is `(encrypt_key, decrypt_key, new_key)`: the key component name(s)
/// used by the `encrypt` artifact, by `reencrypt`'s `decryptKey`, and by its
/// `encryptKey`, respectively.
fn write_reencrypt_config(
    workdir: &Path,
    rootfs: &Path,
    output: &Path,
    temp: &Path,
    keys: (&str, &str, &str),
    reencrypt_input: &str,
) -> PathBuf {
    let (encrypt_key, decrypt_key, new_key) = keys;
    let config = format!(
        r#"
name: reencrypttest
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  encrypt:
    cred:
      input: secret.txt
      key: {encrypt_key}
  reencrypt:
    rot:
      input: {reencrypt_input}
      decryptKey: {decrypt_key}
      encryptKey: {new_key}
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
      - name: rotated
        content:
          type: image
          input: build:reencrypt:rot
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
    let config_path = workdir.join("sysimage.reencrypt.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

/// The fixed 32-byte "new" key used by the reencrypt tests (distinct from
/// `test_key()`).
fn new_key() -> Vec<u8> {
    (1u8..=32)
        .map(|b| b.wrapping_mul(3).wrapping_add(1))
        .collect()
}

#[test]
fn reencrypt_rotates_to_new_key() {
    // `build:reencrypt:rot` decrypts `build:encrypt:cred` with `oldkey` and
    // re-encrypts under `newkey`: the rotated envelope must decrypt with the
    // new key and must NOT decrypt with the old one.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_reencrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        ("oldkey", "oldkey", "newkey"),
        "build:encrypt:cred",
    );

    let old = write_key_bytes(workdir.path(), "old.bin", &test_key());
    let new = write_key_bytes(workdir.path(), "new.bin", &new_key());
    let mut key_file = BTreeMap::new();
    key_file.insert("oldkey".to_string(), old);
    key_file.insert("newkey".to_string(), new);
    build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
        .expect("build should succeed");

    let manifest = read_manifest(&output, "reencrypttest");
    let (rotated, _) = read_image_lv_bytes(&output, &manifest, "system", "rotated");
    assert_eq!(&rotated[..4], b"SENC", "rotated output is a SENC envelope");

    // Decrypts under the new key…
    let new_derived = derive_key(&[&new_key()]).unwrap();
    let plaintext = decrypt_envelope(&rotated, &new_derived).expect("decrypt with new key");
    assert_eq!(plaintext, b"super-secret-luks-key-material\n");

    // …and not under the old key.
    assert!(
        decrypt_envelope(&rotated, &derived_key()).is_err(),
        "the old key must not decrypt the rotated envelope"
    );
}

#[test]
fn reencrypt_is_deterministic_across_builds() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let old = write_key_bytes(workdir.path(), "old.bin", &test_key());
    let new = write_key_bytes(workdir.path(), "new.bin", &new_key());

    let mut results = Vec::new();
    for i in 0..2 {
        let output = workdir.path().join(format!("output{i}"));
        let temp = workdir.path().join(format!("temp{i}"));
        let config_path = write_reencrypt_config(
            workdir.path(),
            &rootfs,
            &output,
            &temp,
            ("oldkey", "oldkey", "newkey"),
            "build:encrypt:cred",
        );
        let mut key_file = BTreeMap::new();
        key_file.insert("oldkey".to_string(), old.clone());
        key_file.insert("newkey".to_string(), new.clone());
        build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
            .expect("build should succeed");
        let manifest = read_manifest(&output, "reencrypttest");
        let (bytes, hash_file) = read_image_lv_bytes(&output, &manifest, "system", "rotated");
        results.push((bytes, hash_file));
    }

    assert_eq!(
        results[0].1, results[1].1,
        "deterministic rotated artifact must have the same content hash"
    );
    assert_eq!(
        results[0].0, results[1].0,
        "deterministic rotated artifact bytes must be identical"
    );
}

#[test]
fn reencrypt_fails_without_new_key() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_reencrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        ("oldkey", "oldkey", "newkey"),
        "build:encrypt:cred",
    );

    // Only the old key is supplied; the new key is missing.
    let old = write_key_bytes(workdir.path(), "old.bin", &test_key());
    let mut key_file = BTreeMap::new();
    key_file.insert("oldkey".to_string(), old);
    let res =
        build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new());

    assert!(res.is_err(), "build must fail when the new key is missing");
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("encryptKey") && msg.contains("newkey") && msg.contains("was not supplied"),
        "error should name the encryptKey role and the missing key: {msg}"
    );
}

#[test]
fn reencrypt_fails_with_wrong_decrypt_key() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_reencrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        ("goodkey", "badkey", "newkey"),
        "build:encrypt:cred",
    );

    // The envelope is produced with `goodkey` but rot tries to decrypt with a
    // different `badkey`.
    let good = write_key_bytes(workdir.path(), "good.bin", &test_key());
    let bad = write_key_bytes(workdir.path(), "bad.bin", b"the-wrong-key-material");
    let new = write_key_bytes(workdir.path(), "new.bin", &new_key());
    let mut key_file = BTreeMap::new();
    key_file.insert("goodkey".to_string(), good);
    key_file.insert("badkey".to_string(), bad);
    key_file.insert("newkey".to_string(), new);
    let res =
        build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new());

    assert!(
        res.is_err(),
        "reencrypt with the wrong decrypt key must fail"
    );
    let msg = res.unwrap_err().to_string();
    assert!(
        msg.contains("authentication failed"),
        "error should mention authentication failure: {msg}"
    );
}

#[test]
fn reencrypt_rotates_multi_component_keys() {
    // Both key sets may be multi-component and are combined in config order.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    make_rootfs(&rootfs);
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_reencrypt_config(
        workdir.path(),
        &rootfs,
        &output,
        &temp,
        ("[k1, k2]", "[k1, k2]", "[k3, k4]"),
        "build:encrypt:cred",
    );

    let k1 = write_key_bytes(workdir.path(), "k1.bin", b"component-one");
    let k2 = write_key_bytes(workdir.path(), "k2.bin", b"component-two");
    let k3 = write_key_bytes(workdir.path(), "k3.bin", b"component-three");
    let k4 = write_key_bytes(workdir.path(), "k4.bin", b"component-four");
    let mut key_file = BTreeMap::new();
    key_file.insert("k1".to_string(), k1);
    key_file.insert("k2".to_string(), k2);
    key_file.insert("k3".to_string(), k3);
    key_file.insert("k4".to_string(), k4);
    build_from_file_with_keys(&config_path, &BTreeMap::new(), &key_file, &BTreeMap::new())
        .expect("build should succeed");

    let manifest = read_manifest(&output, "reencrypttest");
    let (rotated, _) = read_image_lv_bytes(&output, &manifest, "system", "rotated");

    let new_derived = derive_key(&[b"component-three", b"component-four"]).unwrap();
    assert_eq!(
        decrypt_envelope(&rotated, &new_derived).unwrap(),
        b"super-secret-luks-key-material\n"
    );
    // The original components (or a reordered new set) must not decrypt.
    let old_derived = derive_key(&[b"component-one", b"component-two"]).unwrap();
    assert!(decrypt_envelope(&rotated, &old_derived).is_err());
    let reversed = derive_key(&[b"component-four", b"component-three"]).unwrap();
    assert!(decrypt_envelope(&rotated, &reversed).is_err());
}

// --- minimal synthetic PE stub (for the initramfs test) --------------------

/// Build a minimal valid PE32+ (x86-64) stub with one `.text` section, with
/// enough header space to accept extra section headers. Mirrors the stub used
/// by `tests/ukify.rs`.
fn build_minimal_stub() -> Vec<u8> {
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    let e_lfanew: u32 = 64;
    let size_of_opt_header: u16 = 116 + 128;
    let file_header_off = e_lfanew as usize + 4;
    let opt_header_off = file_header_off + 20;
    let section_headers_off = opt_header_off + size_of_opt_header as usize;
    let headers_end = section_headers_off + 40;
    // Reserve generous header space (4 file-alignment units = 2048 bytes) so
    // the UKI can append `.osrel`, `.cmdline`, `.linux` and `.initrd`.
    let size_of_headers = round_up(headers_end as u32, FILE_ALIGNMENT).max(4 * FILE_ALIGNMENT);
    let text_raw_off = size_of_headers;
    let text_raw_size = FILE_ALIGNMENT;
    let image_base: u64 = 0x1_0000;
    let text_va: u32 = SECTION_ALIGNMENT;
    let size_of_image = round_up(text_va + text_raw_size, SECTION_ALIGNMENT);
    let total_size = text_raw_off as usize + text_raw_size as usize;
    let mut buf = vec![0u8; total_size];

    write_u16(&mut buf, 0, 0x5A4D);
    write_u32(&mut buf, 0x3C, e_lfanew);
    write_u32(&mut buf, e_lfanew as usize, 0x0000_4550);

    let fh = file_header_off;
    write_u16(&mut buf, fh, 0x8664);
    write_u16(&mut buf, fh + 2, 1);
    write_u16(&mut buf, fh + 16, size_of_opt_header);
    write_u16(&mut buf, fh + 18, 0x0022);

    let oh = opt_header_off;
    write_u16(&mut buf, oh, 0x020B);
    write_u32(&mut buf, oh + 4, text_raw_size);
    write_u32(&mut buf, oh + 16, text_va);
    write_u32(&mut buf, oh + 20, text_va);
    write_u64(&mut buf, oh + 24, image_base);
    write_u32(&mut buf, oh + 32, SECTION_ALIGNMENT);
    write_u32(&mut buf, oh + 36, FILE_ALIGNMENT);
    write_u32(&mut buf, oh + 56, size_of_image);
    write_u32(&mut buf, oh + 60, size_of_headers);
    write_u16(&mut buf, oh + 68, 10);
    write_u32(&mut buf, oh + 108, 16);

    let sh = section_headers_off;
    buf[sh..sh + 5].copy_from_slice(b".text");
    write_u32(&mut buf, sh + 8, 16);
    write_u32(&mut buf, sh + 12, text_va);
    write_u32(&mut buf, sh + 16, text_raw_size);
    write_u32(&mut buf, sh + 20, text_raw_off);
    write_u32(&mut buf, sh + 36, 0x6000_0020);
    buf[text_raw_off as usize] = 0xC3;
    buf
}

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}
fn round_up(x: u32, align: u32) -> u32 {
    x.div_ceil(align) * align
}
