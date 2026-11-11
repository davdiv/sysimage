//! Integration tests for the `efisign` build artifact.
//!
//! A minimal synthetic PE32+ (built in-memory, no external stub) is signed (or
//! passed through unsigned) by a `build:efisign:` artifact referenced from an
//! LVM image LV. The signed/unsigned result is read back from the build output
//! and compared against the expected bytes. The signing-key directory is
//! materialized with `sbkey_generate` (pure Rust, no external tool).
//!
//! An optional cross-check against `sbverify` runs only when `sbverify` is on
//! `PATH` (see `tests/common/mod.rs`).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::{build_from_file_with_keys, build_from_file_with_sign_keys};
use sysimage::secboot::generate::{sbkey_generate, sbkey_generate_with_passphrase};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-efisign-{}-{n}", std::process::id()));
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

// --- minimal synthetic PE32+ stub (a valid EFI app `sign_pe` can sign) ----

/// Build a minimal valid PE32+ (x86-64) EFI application with one `.text`
/// section — enough structure for `sign_pe` to hash and patch the Security
/// data directory. Mirrors the stub built in `tests/ukify.rs`.
fn build_minimal_efi() -> Vec<u8> {
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    let e_lfanew: u32 = 64;
    let size_of_opt_header: u16 = 116 + 128; // PE32+ standard + 16 data dirs

    let file_header_off = e_lfanew as usize + 4;
    let opt_header_off = file_header_off + 20;
    let section_headers_off = opt_header_off + size_of_opt_header as usize;

    let headers_end = section_headers_off + 40;
    let size_of_headers = round_up(headers_end as u32, FILE_ALIGNMENT);
    let text_raw_off = size_of_headers;
    let text_raw_size = FILE_ALIGNMENT;

    let image_base: u64 = 0x1_0000;
    let text_va: u32 = SECTION_ALIGNMENT;
    let entry_point: u32 = text_va;
    let size_of_image = round_up(text_va + text_raw_size, SECTION_ALIGNMENT);

    let total_size = text_raw_off as usize + text_raw_size as usize;
    let mut buf = vec![0u8; total_size];

    write_u16(&mut buf, 0, 0x5A4D); // "MZ"
    write_u32(&mut buf, 0x3C, e_lfanew);
    write_u32(&mut buf, e_lfanew as usize, 0x0000_4550); // "PE\0\0"

    let fh = file_header_off;
    write_u16(&mut buf, fh, 0x8664); // Machine = AMD64
    write_u16(&mut buf, fh + 2, 1); // NumberOfSections
    write_u16(&mut buf, fh + 16, size_of_opt_header);
    write_u16(&mut buf, fh + 18, 0x0022); // Characteristics

    let oh = opt_header_off;
    write_u16(&mut buf, oh, 0x020B); // Magic = PE32+
    write_u32(&mut buf, oh + 4, text_raw_size); // SizeOfCode
    write_u32(&mut buf, oh + 16, entry_point); // AddressOfEntryPoint
    write_u32(&mut buf, oh + 20, text_va); // BaseOfCode
    write_u64(&mut buf, oh + 24, image_base); // ImageBase
    write_u32(&mut buf, oh + 32, SECTION_ALIGNMENT);
    write_u32(&mut buf, oh + 36, FILE_ALIGNMENT);
    write_u32(&mut buf, oh + 56, size_of_image); // SizeOfImage
    write_u32(&mut buf, oh + 60, size_of_headers); // SizeOfHeaders
    write_u16(&mut buf, oh + 68, 10); // Subsystem = EFI_APPLICATION
    write_u32(&mut buf, oh + 108, 16); // NumberOfRvaAndSizes

    let sh = section_headers_off;
    buf[sh..sh + 5].copy_from_slice(b".text");
    write_u32(&mut buf, sh + 8, 16); // VirtualSize
    write_u32(&mut buf, sh + 12, text_va); // VirtualAddress
    write_u32(&mut buf, sh + 16, text_raw_size); // SizeOfRawData
    write_u32(&mut buf, sh + 20, text_raw_off); // PointerToRawData
    write_u32(&mut buf, sh + 36, 0x6000_0020); // Characteristics

    buf[text_raw_off as usize] = 0xC3; // `ret`
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

// --- helpers --------------------------------------------------------------

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

/// Write a config that builds `efisign:boot` from `boot.efi` with `key: db`,
/// placing the result in an LVM image LV so it appears as a content-addressed
/// `.bin` in the manifest.
fn write_config(workdir: &Path, rootfs: &Path, output: &Path, temp: &Path) -> PathBuf {
    let config = format!(
        r#"
name: efisigntest
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
  efisign:
    boot:
      input: boot.efi
      key: db
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
      - name: boot-${{CONTENTHASH}}
        content:
          type: image
          input: build:efisign:boot
      - name: rootfs-${{CONTENTHASH}}
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
    let config_path = workdir.join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

/// Write a config with two `efisign` artifacts (`first`, `second`) that share
/// the same `key: db`, placing each signed result in its own LVM image LV.
fn write_multi_config(workdir: &Path, rootfs: &Path, output: &Path, temp: &Path) -> PathBuf {
    let config = format!(
        r#"
name: efisignmulti
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  efisign:
    first:
      input: first.efi
      key: db
    second:
      input: second.efi
      key: db
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
      - name: first-${{CONTENTHASH}}
        content:
          type: image
          input: build:efisign:first
      - name: second-${{CONTENTHASH}}
        content:
          type: image
          input: build:efisign:second
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();
    config_path
}

// --- tests ----------------------------------------------------------------

#[test]
fn efisign_unsigned_when_no_sign_key_supplied() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello\n").unwrap();

    // The EFI file to sign lives in the input (rootfs) directory.
    let efi = build_minimal_efi();
    fs::write(rootfs.join("boot.efi"), &efi).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    // No --sign supplied: build must succeed and pass the EFI through unsigned.
    build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect("unsigned build should succeed");

    let manifest = read_manifest(&output, "efisigntest");
    let built = read_image_lv_bytes(&output, &manifest, "system", "boot-");
    assert_eq!(
        built, efi,
        "without --sign the efisign output must equal the unsigned input"
    );
}

#[test]
fn efisign_signed_when_sign_key_supplied() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello\n").unwrap();

    let efi = build_minimal_efi();
    fs::write(rootfs.join("boot.efi"), &efi).unwrap();

    // Materialize a real Secure Boot key directory with `sbkey_generate`.
    let keydir = workdir.path().join("sbkeys");
    sbkey_generate(&keydir).expect("sbkey_generate");
    assert!(keydir.join("db.key").exists());
    assert!(keydir.join("db.crt").exists());

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), keydir.clone());
    build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
    )
    .expect("signed build should succeed");

    let manifest = read_manifest(&output, "efisigntest");
    let signed = read_image_lv_bytes(&output, &manifest, "system", "boot-");

    // The signed PE must differ from the unsigned input and be larger (the
    // WIN_CERTIFICATE PKCS#7 entry is appended).
    assert_ne!(signed, efi, "signed output must differ from unsigned input");
    assert!(
        signed.len() > efi.len(),
        "signed PE ({}) should be larger than unsigned ({})",
        signed.len(),
        efi.len()
    );

    // The Security data directory (data-dir index 4) must now be non-zero.
    let e_lfanew = u32::from_le_bytes(signed[0x3c..0x40].try_into().unwrap()) as usize;
    let opt_header = e_lfanew + 24;
    let magic = u16::from_le_bytes(signed[opt_header..opt_header + 2].try_into().unwrap());
    let data_dir_start = if magic == 0x10b {
        opt_header + 96
    } else {
        opt_header + 112
    };
    let sec_dir = data_dir_start + 4 * 8;
    let cert_addr = u32::from_le_bytes(signed[sec_dir..sec_dir + 4].try_into().unwrap());
    let cert_size = u32::from_le_bytes(signed[sec_dir + 4..sec_dir + 8].try_into().unwrap());
    assert!(
        cert_addr >= efi.len() as u32,
        "cert table should start past the original PE"
    );
    assert!(cert_size > 0, "cert table size should be non-zero");
    assert!(
        (cert_addr as usize) + (cert_size as usize) <= signed.len(),
        "cert table should fit within the signed PE"
    );

    // Optional cross-check with `sbverify` (sbsigntools) when available.
    if common::tool_or_skip("sbverify") {
        let signed_path = output.join(".efisign-tmp-signed.efi");
        fs::write(&signed_path, &signed).unwrap();
        let cert = keydir.join("db.crt");
        let status = Command::new("sbverify")
            .arg("--cert")
            .arg(&cert)
            .arg(&signed_path)
            .status()
            .expect("spawn sbverify");
        assert!(
            status.success(),
            "sbverify rejected the signed PE (cert={})",
            cert.display()
        );
        let _ = fs::remove_file(&signed_path);
    }
}

#[test]
fn efisign_signed_when_encrypted_sign_key_supplied() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello\n").unwrap();

    let efi = build_minimal_efi();
    fs::write(rootfs.join("boot.efi"), &efi).unwrap();

    // A real Secure Boot key directory with SENC-encrypted private keys.
    let keydir = workdir.path().join("sbkeys");
    let passphrase = b"correct horse battery staple";
    sbkey_generate_with_passphrase(&keydir, Some(passphrase)).expect("sbkey_generate");
    let key_bytes = fs::read(keydir.join("db.key")).unwrap();
    assert_eq!(&key_bytes[..4], b"SENC", "db.key must be a SENC envelope");

    // The passphrase file is a `--sign-key-file`; its exact bytes must match.
    let pass_file = workdir.path().join("db.pass");
    fs::write(&pass_file, passphrase).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), keydir.clone());
    let mut sign_key_files = std::collections::BTreeMap::new();
    sign_key_files.insert("db".to_string(), pass_file.clone());
    build_from_file_with_sign_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
        &sign_key_files,
        &Default::default(),
        &Default::default(),
    )
    .expect("signed build with an encrypted key should succeed");

    let manifest = read_manifest(&output, "efisigntest");
    let signed = read_image_lv_bytes(&output, &manifest, "system", "boot-");
    assert_ne!(signed, efi, "signed output must differ from unsigned input");
    assert!(signed.len() > efi.len());

    if common::tool_or_skip("sbverify") {
        let signed_path = output.join(".efisign-tmp-signed.efi");
        fs::write(&signed_path, &signed).unwrap();
        let cert = keydir.join("db.crt");
        let status = Command::new("sbverify")
            .arg("--cert")
            .arg(&cert)
            .arg(&signed_path)
            .status()
            .expect("spawn sbverify");
        assert!(
            status.success(),
            "sbverify rejected the PE signed with an encrypted key (cert={})",
            cert.display()
        );
        let _ = fs::remove_file(&signed_path);
    }
}

#[test]
fn efisign_signs_multiple_efis_with_same_encrypted_key() {
    // Two distinct `efisign` artifacts share one `key: db`, exercising the
    // case where a single encrypted key is looked up (and decrypted) more than
    // once in the same build.
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();

    let first = build_minimal_efi();
    let mut second = build_minimal_efi();
    // Flip the `ret` instruction byte so the two inputs differ within the
    // hashed `.text` section (both remain valid PEs).
    let ret = second
        .iter()
        .position(|&b| b == 0xC3)
        .expect("the stub contains a `ret` byte");
    second[ret] ^= 0xFF;
    assert_ne!(first, second);
    fs::write(rootfs.join("first.efi"), &first).unwrap();
    fs::write(rootfs.join("second.efi"), &second).unwrap();

    let keydir = workdir.path().join("sbkeys");
    let passphrase = b"multi-key-passphrase";
    sbkey_generate_with_passphrase(&keydir, Some(passphrase)).expect("sbkey_generate");
    let pass_file = workdir.path().join("db.pass");
    fs::write(&pass_file, passphrase).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_multi_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), keydir.clone());
    let mut sign_key_files = std::collections::BTreeMap::new();
    sign_key_files.insert("db".to_string(), pass_file);
    build_from_file_with_sign_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
        &sign_key_files,
        &Default::default(),
        &Default::default(),
    )
    .expect("both efisign artifacts should sign with the shared encrypted key");

    let manifest = read_manifest(&output, "efisignmulti");
    let signed_first = read_image_lv_bytes(&output, &manifest, "system", "first-");
    let signed_second = read_image_lv_bytes(&output, &manifest, "system", "second-");
    assert_ne!(signed_first, first);
    assert_ne!(signed_second, second);
    assert!(signed_first.len() > first.len());
    assert!(signed_second.len() > second.len());

    if common::tool_or_skip("sbverify") {
        for (bytes, input) in [(&signed_first, &first), (&signed_second, &second)] {
            let signed_path = output.join(".efisign-tmp-multi.efi");
            fs::write(&signed_path, bytes).unwrap();
            let status = Command::new("sbverify")
                .arg("--cert")
                .arg(keydir.join("db.crt"))
                .arg(&signed_path)
                .status()
                .expect("spawn sbverify");
            assert!(status.success(), "sbverify rejected a multi-key signature");
            assert_ne!(bytes, input);
            let _ = fs::remove_file(&signed_path);
        }
    }
}

#[cfg(unix)]
#[test]
fn sign_key_file_is_read_once_per_build() {
    // The passphrase source must be consumed exactly once per build, so that a
    // one-shot source (a FIFO here; a shell `<(pass …)` process substitution in
    // practice) works even when several EFIs share the same key.
    //
    // If the implementation re-read the passphrase per artifact, the second
    // open of the already-drained FIFO would block forever; the watchdog below
    // turns that regression into a test failure instead of a hang.
    use std::io::Write as _;

    if !common::tool_or_skip("mkfifo") {
        return;
    }

    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("first.efi"), build_minimal_efi()).unwrap();
    let mut second = build_minimal_efi();
    let ret = second
        .iter()
        .position(|&b| b == 0xC3)
        .expect("the stub contains a `ret` byte");
    second[ret] ^= 0xFF;
    fs::write(rootfs.join("second.efi"), &second).unwrap();

    let keydir = workdir.path().join("sbkeys");
    let passphrase = b"one-shot-passphrase";
    sbkey_generate_with_passphrase(&keydir, Some(passphrase)).expect("sbkey_generate");

    let fifo = workdir.path().join("db.pass.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    // A single writer: open (blocks until the reader opens), write, close.
    let fifo_writer = fifo.clone();
    let pass = passphrase.to_vec();
    let writer = std::thread::spawn(move || {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_writer)
            .expect("open passphrase fifo for writing");
        f.write_all(&pass).expect("write passphrase");
    });

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_multi_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), keydir);
    let mut sign_key_files = std::collections::BTreeMap::new();
    sign_key_files.insert("db".to_string(), fifo);

    // Run the build on its own thread so a blocking double-read fails via the
    // watchdog rather than hanging the whole test binary.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = build_from_file_with_sign_keys(
            &config_path,
            &Default::default(),
            &Default::default(),
            &sign_keys,
            &sign_key_files,
            &Default::default(),
            &Default::default(),
        );
        let _ = tx.send(res.map(|_| ()));
    });

    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("build with a one-shot passphrase source failed: {e}"),
        Err(_) => panic!(
            "build did not finish: the passphrase was read more than once \
             (the drained FIFO blocked on a second read)"
        ),
    }
    writer.join().unwrap();

    let manifest = read_manifest(&output, "efisignmulti");
    let signed_first = read_image_lv_bytes(&output, &manifest, "system", "first-");
    let signed_second = read_image_lv_bytes(&output, &manifest, "system", "second-");
    assert_ne!(signed_first, build_minimal_efi());
    assert_ne!(signed_second, second);
}

#[test]
fn efisign_errors_when_encrypted_key_without_passphrase() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello\n").unwrap();
    let efi = build_minimal_efi();
    fs::write(rootfs.join("boot.efi"), &efi).unwrap();

    let keydir = workdir.path().join("sbkeys");
    sbkey_generate_with_passphrase(&keydir, Some(b"hunter2")).expect("sbkey_generate");

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), keydir);
    // No --sign-key-file: the encrypted db.key cannot be decrypted.
    let res = build_from_file_with_sign_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
        &Default::default(),
        &Default::default(),
        &Default::default(),
    );
    assert!(
        res.is_err(),
        "build must error when the signing key is encrypted and no passphrase is supplied"
    );
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("passphrase") || msg.contains("signing key"),
        "error should mention the missing passphrase: {msg}"
    );
}

#[test]
fn efisign_errors_when_sign_key_dir_missing_db_files() {
    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(&rootfs).unwrap();
    fs::write(rootfs.join("hello.txt"), "hello\n").unwrap();
    let efi = build_minimal_efi();
    fs::write(rootfs.join("boot.efi"), &efi).unwrap();

    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");
    let config_path = write_config(workdir.path(), &rootfs, &output, &temp);

    // Supply a signing key name pointing at an empty directory: db.key/db.crt
    // are absent, so the build must error.
    let empty_keydir = workdir.path().join("emptykeys");
    fs::create_dir_all(&empty_keydir).unwrap();
    let mut sign_keys = std::collections::BTreeMap::new();
    sign_keys.insert("db".to_string(), empty_keydir);

    let res = build_from_file_with_keys(
        &config_path,
        &Default::default(),
        &Default::default(),
        &sign_keys,
    );
    assert!(
        res.is_err(),
        "build must error when --sign dir lacks db.key/db.crt"
    );
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("db.key") || msg.contains("db.crt"),
        "error should mention the missing db.key/db.crt file: {msg}"
    );
}
