//! dm-verity: compare the pure-Rust formatter against `veritysetup`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sysimage::dmverity::{verity_format, verity_verify};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-verity-{}-{n}", std::process::id()));
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

fn veritysetup_root(
    data: &Path,
    hash: &Path,
    dbs: u32,
    hbs: u32,
    db: u64,
    salt: &str,
    uuid: &str,
) -> String {
    let out = Command::new("veritysetup")
        .args([
            "format",
            &data.to_string_lossy(),
            &hash.to_string_lossy(),
            &format!("--data-block-size={dbs}"),
            &format!("--data-blocks={db}"),
            &format!("--hash-block-size={hbs}"),
            "--salt",
            salt,
            "--uuid",
            uuid,
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Root hash:") {
            return rest.trim().to_string();
        }
    }
    panic!("no root hash in veritysetup output: {s}");
}

#[test]
fn matches_veritysetup_300_blocks() {
    skip_if_missing!("veritysetup");
    let dir = TempDir::new();
    let dbs = 4096u32;
    let hbs = 4096u32;
    let db = 300u64;
    let salt_hex = "0102030405";
    let uuid_hex = "aabbccdd112233445566778899001122";
    let uuid_str = "aabbccdd-1122-3344-5566-778899001122";

    let mut data = vec![0u8; (dbs as usize) * (db as usize)];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let data_path = dir.path().join("data.bin");
    fs::write(&data_path, &data).unwrap();

    // veritysetup reference.
    let ref_hash_path = dir.path().join("ref.hash");
    let ref_root = veritysetup_root(&data_path, &ref_hash_path, dbs, hbs, db, salt_hex, uuid_str);
    let ref_hash = fs::read(&ref_hash_path).unwrap();

    // Our formatter.
    let salt = hex::decode(salt_hex).unwrap();
    let uuid = hex::decode(uuid_hex).unwrap();
    let mut image = data.clone();
    let res = verity_format(&mut image, &salt, dbs, hbs, uuid.try_into().unwrap()).unwrap();
    assert_eq!(
        res.root_hash, ref_root,
        "root hash differs from veritysetup"
    );
    assert_eq!(res.hash_offset, (dbs as u64) * db);

    // The appended hash area (from hash_offset onward) must match veritysetup's
    // hash file byte-for-byte.
    let hash_area = &image[res.hash_offset as usize..];
    assert_eq!(
        hash_area,
        ref_hash.as_slice(),
        "hash area differs from veritysetup"
    );

    // Verify round-trips.
    verity_verify(&image, res.hash_offset, &salt, dbs, hbs, &res.root_hash).unwrap();
}

#[test]
fn matches_veritysetup_small_512() {
    skip_if_missing!("veritysetup");
    let dir = TempDir::new();
    let dbs = 512u32;
    let hbs = 1024u32;
    let db = 5u64;
    let salt_hex = "aabbccdd";
    let uuid_hex = "112233445566778899aabbccddeeff00";
    let uuid_str = "11223344-5566-7788-99aa-bbccddeeff00";

    // The TS pads the image to max(dbs, hbs) before formatting; replicate that
    // so both veritysetup and our formatter see the same padded data + block count.
    let align = std::cmp::max(dbs as usize, hbs as usize);
    let raw_len = (dbs as usize) * (db as usize);
    let padded_len = raw_len.div_ceil(align) * align;
    let mut data = vec![0u8; padded_len];
    for (i, b) in data.iter_mut().enumerate() {
        if i < raw_len {
            *b = (i as u8).wrapping_mul(7);
        }
    }
    let data_blocks_padded = (padded_len / dbs as usize) as u64;
    let data_path = dir.path().join("d.bin");
    fs::write(&data_path, &data).unwrap();
    let ref_hash_path = dir.path().join("r.hash");
    let ref_root = veritysetup_root(
        &data_path,
        &ref_hash_path,
        dbs,
        hbs,
        data_blocks_padded,
        salt_hex,
        uuid_str,
    );
    let ref_hash = fs::read(&ref_hash_path).unwrap();

    let salt = hex::decode(salt_hex).unwrap();
    let uuid = hex::decode(uuid_hex).unwrap();
    let mut image = data.clone();
    let res = verity_format(&mut image, &salt, dbs, hbs, uuid.try_into().unwrap()).unwrap();
    assert_eq!(res.root_hash, ref_root);
    let hash_area = &image[res.hash_offset as usize..];
    assert_eq!(hash_area, ref_hash.as_slice());
}
