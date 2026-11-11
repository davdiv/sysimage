//! LUKS2 integration tests: round-trip, cryptsetup interop, and end-to-end
//! install of an encrypted partition.

mod common;

use std::fs;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::build::build_from_file;
use sysimage::install::{InstallConfig, install};
use sysimage::luks::{self, Luks2Kdf, Luks2Params};
use sysimage::manifest::{ReadManifestConfig, read_manifest};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-luks-{}-{n}", std::process::id()));
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

/// Format a LUKS2 container in memory, then read it back through luks-core and
/// confirm the plaintext survives. Exercises both the writer and the reader.
#[test]
fn luks2_roundtrip_in_memory() {
    let plain: Vec<u8> = (0..100_000u32)
        .map(|i| (i as u8).wrapping_mul(7) ^ 0x3c)
        .collect();
    let mut img: Vec<u8> = Vec::new();
    let res = {
        use std::io::Cursor;
        let mut w = Cursor::new(&mut img);
        let res = luks::format_luks2(
            &mut w,
            b"roundtrip-pass",
            &Luks2Params {
                kdf: Luks2Kdf::Pbkdf2 {
                    hash: "sha256".to_string(),
                    iterations: 1000,
                },
                sector_size: 512,
                payload_align: 512,
                ..Default::default()
            },
        )
        .unwrap();
        // Grow to hold the payload.
        let end = res.payload_offset + plain.len() as u64;
        w.seek(SeekFrom::Start(end)).unwrap();
        res
    };
    let mut r = std::io::Cursor::new(&plain);
    let mut w = std::io::Cursor::new(&mut img);
    w.seek(SeekFrom::Start(0)).unwrap();
    luks::encrypt_payload(&mut w, &mut r, &res, plain.len() as u64).unwrap();

    let mut vol = luks::open_luks2(std::io::Cursor::new(&img), b"roundtrip-pass").unwrap();
    assert_eq!(vol.info().version, 2);
    assert_eq!(vol.info().cipher_mode, "xts-plain64");
    assert_eq!(vol.info().key_bytes, 64);
    let mut got = vec![0u8; plain.len()];
    vol.read_at(0, &mut got).unwrap();
    assert_eq!(got, plain);
}

/// A container we format must be recognised by real `cryptsetup` (header
/// checksum + JSON parse) and cryptsetup must derive the same master key from
/// the passphrase.
#[test]
fn luks2_cryptsetup_recognises_our_container() {
    skip_if_missing!("cryptsetup");
    let work = TempDir::new();
    let img_path = work.path().join("container.luks");
    let key_path = work.path().join("key.bin");
    fs::write(&key_path, b"interop-secret").unwrap(); // no trailing newline

    // Format with Argon2id (cryptsetup's default KDF) and 4096-byte sectors.
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&img_path)
        .unwrap();
    let res = luks::format_luks2(
        &mut f,
        b"interop-secret",
        &Luks2Params {
            kdf: Luks2Kdf::Argon2id {
                time: 4,
                memory: 32_768,
                cpus: 1,
            },
            sector_size: 4096,
            payload_align: 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    // A small encrypted payload so the file is a complete container.
    let plain = vec![0xa5u8; 8192];
    let end = res.payload_offset + plain.len() as u64;
    f.set_len(end).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut r = std::io::Cursor::new(&plain);
    luks::encrypt_payload(&mut f, &mut r, &res, plain.len() as u64).unwrap();
    f.sync_all().unwrap();
    drop(f);

    // cryptsetup must accept the header.
    let is_luks = Command::new("cryptsetup")
        .arg("isLuks")
        .arg(&img_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(
        is_luks.success(),
        "cryptsetup isLuks rejected our container"
    );

    // cryptsetup must derive the same master key we hold.
    let our_mk = {
        let data = fs::read(&img_path).unwrap();
        let vol = luks::open_luks2(std::io::Cursor::new(&data), b"interop-secret").unwrap();
        vol.master_key().to_vec()
    };
    let dump = Command::new("cryptsetup")
        .args(["luksDump", "--dump-master-key", "--key-file"])
        .arg(&key_path)
        .arg(&img_path)
        .output()
        .unwrap();
    assert!(
        dump.status.success(),
        "cryptsetup luksDump --dump-master-key failed: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
    let out = String::from_utf8_lossy(&dump.stdout);
    // Parse the "MK dump:" hex bytes from cryptsetup's output.
    let mk_hex: String = out
        .split("MK dump:")
        .nth(1)
        .unwrap()
        .lines()
        .take(4)
        .flat_map(|l| l.split_whitespace())
        .collect();
    let cryptsetup_mk = hex::decode(&mk_hex).unwrap();
    assert_eq!(cryptsetup_mk, our_mk, "master key mismatch with cryptsetup");
}

/// End-to-end: build a config with a LUKS-encrypted ext4 partition, install it
/// to a disk image, then decrypt the partition and verify the ext4 superblock
/// is present in the cleartext.
#[test]
fn installs_luks_encrypted_ext4() {
    let work = TempDir::new();
    let rootfs = work.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc")).unwrap();
    fs::write(rootfs.join("etc").join("hostname"), b"luks-test\n").unwrap();
    fs::write(rootfs.join("hello.txt"), b"hello luks\n").unwrap();

    let key_path = work.path().join("key.bin");
    fs::write(&key_path, b"install-secret").unwrap();

    let output = work.path().join("output");
    let temp = work.path().join("temp");
    let config = format!(
        r#"
name: lukstest
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
        - destination: "etc/hostname"
          input: etc/hostname
        - destination: "hello.txt"
          input: hello.txt
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = work.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // The LUKS block sizeMin must account for the 1 MiB payload offset plus the
    // ext4 content.
    let root = &manifest.manifest.disk["root"];
    use sysimage::model::manifest::ManifestBlock;
    if let ManifestBlock::Luks(l) = root {
        assert!(
            l.size_min > 1024 * 1024,
            "luks sizeMin {} should exceed the 1 MiB payload offset",
            l.size_min
        );
        assert_eq!(l.cipher, "aes-xts-plain64");
        assert_eq!(l.key_size, 64);
        assert_eq!(l.sector_size, 512);
        assert_eq!(l.name, "root");
    } else {
        panic!("expected a Luks block, got {:?}", root);
    }

    let disk_image = work.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "root".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: [("root".to_string(), key_path.clone())].into(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    // The whole disk image is the LUKS container. Decrypt it and check the ext4
    // superblock magic (0xEF53 at byte offset 1080) appears in the cleartext.
    let data = fs::read(&disk_image).unwrap();
    let mut vol = luks::open_luks2(std::io::Cursor::new(&data), b"install-secret")
        .expect("decrypt with the passphrase");
    let mut head = vec![0u8; 4096];
    vol.read_at(0, &mut head).unwrap();
    let magic = u16::from_le_bytes(head[1080..1082].try_into().unwrap());
    assert_eq!(
        magic, 0xEF53,
        "decrypted payload is not an ext4 filesystem (magic={:#x})",
        magic
    );

    // And cryptsetup (if available) must accept the installed container.
    if common::tool_or_skip("cryptsetup") {
        let status = Command::new("cryptsetup")
            .arg("isLuks")
            .arg(&disk_image)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "cryptsetup isLuks rejected the installed container"
        );
    }
}

/// A UUID specified in `Luks2Params::uuid` is written into the container header
/// and is the one reported back by `luks-core` when the container is opened.
#[test]
fn luks2_configured_uuid_is_honoured() {
    use sysimage::uuid::parse_uuid;
    let plain: Vec<u8> = vec![0x11u8; 4096];
    let mut img: Vec<u8> = Vec::new();
    let chosen = "11111111-2222-3333-4444-555555555555";
    let res = {
        use std::io::Cursor;
        let mut w = Cursor::new(&mut img);
        let res = luks::format_luks2(
            &mut w,
            b"uuid-pass",
            &Luks2Params {
                kdf: Luks2Kdf::Pbkdf2 {
                    hash: "sha256".to_string(),
                    iterations: 1000,
                },
                sector_size: 512,
                payload_align: 512,
                uuid: Some(chosen.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let end = res.payload_offset + plain.len() as u64;
        w.seek(SeekFrom::Start(end)).unwrap();
        res
    };
    let mut r = std::io::Cursor::new(&plain);
    let mut w = std::io::Cursor::new(&mut img);
    w.seek(SeekFrom::Start(0)).unwrap();
    luks::encrypt_payload(&mut w, &mut r, &res, plain.len() as u64).unwrap();

    // The container must still round-trip via luks-core with the same passphrase.
    let mut vol = luks::open_luks2(std::io::Cursor::new(&img), b"uuid-pass").unwrap();
    let mut got = vec![0u8; plain.len()];
    vol.read_at(0, &mut got).unwrap();
    assert_eq!(got, plain);

    // The header's on-disk UUID field (offset 168, 40 bytes, NUL-padded) must
    // hold the canonical string form of the chosen UUID.
    let on_disk = std::str::from_utf8(&img[168..168 + 36]).unwrap();
    assert_eq!(on_disk, chosen);
    assert_eq!(parse_uuid(on_disk), parse_uuid(chosen));
}

/// A UUID specified in the LUKS config block flows through to the manifest and
/// is written into the installed container's header.
#[test]
fn configured_uuid_flows_through_build_and_install() {
    use sysimage::model::manifest::ManifestBlock;
    let work = TempDir::new();
    let rootfs = work.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc")).unwrap();
    fs::write(
        rootfs.join("etc").join("hostname"),
        b"uuid-flow
",
    )
    .unwrap();

    let key_path = work.path().join("key.bin");
    fs::write(&key_path, b"flow-secret").unwrap();

    let output = work.path().join("output");
    let temp = work.path().join("temp");
    let chosen = "deadbeef-1234-5678-9abc-def012345678";
    let config = format!(
        r#"
name: uuidflow
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
disk:
  root:
    type: luks
    name: root
    uuid: {chosen}
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
        - destination: "etc/hostname"
          input: etc/hostname
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
        chosen = chosen,
    );
    let config_path = work.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    build_from_file(&config_path).expect("build should succeed");

    let manifest = read_manifest(ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    let root = &manifest.manifest.disk["root"];
    let l = match root {
        ManifestBlock::Luks(l) => l,
        other => panic!("expected a Luks block, got {other:?}"),
    };
    assert_eq!(
        l.uuid.as_ref().map(|g| g.to_string()).as_deref(),
        Some(chosen)
    );

    let disk_image = work.path().join("disk.img");
    install(InstallConfig {
        manifest,
        disk: [(
            "root".to_string(),
            disk_image.to_string_lossy().into_owned(),
        )]
        .into(),
        key: std::collections::BTreeMap::new(),
        key_file: [("root".to_string(), key_path.clone())].into(),
        force: false,
        wipe: true,
    })
    .expect("install should succeed");

    let data = fs::read(&disk_image).unwrap();
    let on_disk = std::str::from_utf8(&data[168..168 + 36]).unwrap();
    assert_eq!(on_disk, chosen);
}

/// Extract the container UUID reported by `cryptsetup luksDump`.
fn luks_dump_uuid(path: &Path) -> String {
    let out = Command::new("cryptsetup")
        .arg("luksDump")
        .arg(path)
        .output()
        .expect("run cryptsetup luksDump");
    assert!(out.status.success(), "cryptsetup luksDump failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("UUID:"))
        .map(|s| s.trim().to_string())
        .expect("no UUID line in luksDump output")
}

/// Re-formatting a `cryptsetup`-created container in place (what `--wipe` does)
/// must rewrite *both* metadata copies so the new container outranks the stale
/// backup header. Before the fix, cryptsetup kept reading the old secondary
/// header — whose keyslot had just been overwritten — so the new key file did
/// not work even though our own reader (primary only) was happy.
#[test]
fn reformat_over_cryptsetup_container_resets_keyslots() {
    skip_if_missing!("cryptsetup");

    let work = TempDir::new();
    let img_path = work.path().join("reformat.luks");
    let old_key = work.path().join("old.key");
    let new_key = work.path().join("new.key");
    fs::write(&old_key, b"old-secret").unwrap();
    fs::write(&new_key, b"new-secret").unwrap();

    // A real cryptsetup LUKS2 container (writes both metadata copies).
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&img_path)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let status = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--key-file",
        ])
        .arg(&old_key)
        .arg(&img_path)
        .status()
        .unwrap();
    assert!(status.success(), "cryptsetup luksFormat failed");
    let old_uuid = luks_dump_uuid(&img_path);

    // Reformat in place with our writer, exactly like a `--wipe` fresh LUKS.
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&img_path)
        .unwrap();
    let res = luks::format_luks2(
        &mut f,
        b"new-secret",
        &Luks2Params {
            kdf: Luks2Kdf::Pbkdf2 {
                hash: "sha256".to_string(),
                iterations: 1000,
            },
            sector_size: 512,
            payload_align: 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    let plain = vec![0x5au8; 8192];
    f.seek(SeekFrom::Start(0)).unwrap();
    let mut r = std::io::Cursor::new(&plain);
    luks::encrypt_payload(&mut f, &mut r, &res, plain.len() as u64).unwrap();
    f.sync_all().unwrap();
    drop(f);

    // cryptsetup must now see the new header (pbkdf2, not the old argon2id) ...
    let dump = Command::new("cryptsetup")
        .arg("luksDump")
        .arg(&img_path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&dump.stdout);
    assert!(
        text.contains("pbkdf2"),
        "cryptsetup did not see the new header:\n{text}"
    );
    assert!(
        !text.contains("argon2id"),
        "cryptsetup still reports the stale argon2id header:\n{text}"
    );
    // ... with a fresh UUID, ...
    assert_ne!(luks_dump_uuid(&img_path), old_uuid);
    // ... and the new key file must unlock it.
    let dump = Command::new("cryptsetup")
        .args(["luksDump", "--dump-master-key", "--key-file"])
        .arg(&new_key)
        .arg(&img_path)
        .output()
        .unwrap();
    assert!(
        dump.status.success(),
        "cryptsetup could not derive a key with the new key file: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
}
