//! dm-verity hash-tree formatting.
//!
//! Pure-Rust implementation of the verity hash tree (SHA-256 + salt) and the
//! cryptsetup/`veritysetup` on-disk superblock — a drop-in replacement for
//! `veritysetup format`. Output is byte-for-byte identical to `veritysetup`
//! for sha256 (verified against veritysetup 2.8.7).

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Superblock magic ("verity\0\0").
const VERITY_MAGIC: &[u8; 8] = b"verity\0\0";
/// Superblock version.
const VERITY_VERSION: u32 = 1;
/// Hash type (native verity).
const VERITY_HASH_TYPE: u32 = 1;
/// SHA-256 digest size.
const DIGEST_SIZE: usize = 32;

/// A formatted verity hash tree ready to append after the data area, plus the
/// root hash and the byte offset where the hash area begins.
pub struct VerityFormatResult {
    /// Hex-encoded SHA-256 root hash.
    pub root_hash: String,
    /// Byte offset of the (padded) data area end / hash area start.
    pub hash_offset: u64,
}

/// Compute the verity hash tree for `data` (the filesystem image) and append the
/// superblock + hash tree to `image` in place. `image` is padded to a multiple
/// of `max(data_block_size, hash_block_size)` first.
///
/// `uuid` is the 16 raw UUID bytes (stored in string order, as `veritysetup`
/// does). Returns the root hash and the hash offset.
pub fn verity_format(
    image: &mut Vec<u8>,
    salt: &[u8],
    data_block_size: u32,
    hash_block_size: u32,
    uuid: [u8; 16],
) -> Result<VerityFormatResult> {
    if salt.len() > 256 {
        return Err(Error::msg("verity salt longer than 256 bytes"));
    }
    let dbs = data_block_size as usize;
    let hbs = hash_block_size as usize;
    if dbs == 0 || hbs == 0 {
        return Err(Error::msg("verity block size is zero"));
    }

    // 1. Pad the data area to a multiple of max(dbs, hbs).
    let align = std::cmp::max(dbs, hbs);
    let rem = image.len() % align;
    if rem != 0 {
        image.resize(image.len() + (align - rem), 0);
    }
    let hash_offset = image.len() as u64;
    let data_blocks = hash_offset as usize / dbs;
    if !(hash_offset as usize).is_multiple_of(dbs) {
        return Err(Error::msg(
            "verity data size is not a multiple of the data block size",
        ));
    }

    // 2. Level 0: hash each data block (SHA-256 of salt || block).
    let mut current: Vec<Vec<u8>> = Vec::with_capacity(data_blocks);
    for i in 0..data_blocks {
        let block = &image[i * dbs..(i + 1) * dbs];
        current.push(hash_block(salt, block));
    }

    // 3. Build the tree levels (each level packed into hbs-sized blocks, padded
    //    with zeros). The top level is a single block.
    let mut levels: Vec<Vec<u8>> = Vec::new();
    loop {
        let flat = flatten(&current);
        let nblocks = flat.len().div_ceil(hbs);
        let mut level_bytes = flat;
        level_bytes.resize(nblocks * hbs, 0);
        levels.push(level_bytes);
        if nblocks <= 1 {
            break;
        }
        let mut next: Vec<Vec<u8>> = Vec::with_capacity(nblocks);
        for j in 0..nblocks {
            let blk = &levels.last().unwrap()[j * hbs..(j + 1) * hbs];
            next.push(hash_block(salt, blk));
        }
        current = next;
    }

    // 4. Root hash = hash of the single top-level block.
    let root_hash = hash_block(salt, levels.last().unwrap());
    let root_hash_hex = hex::encode(&root_hash);

    // 5. Build the superblock (one hash block).
    let mut sb = vec![0u8; hbs];
    sb[0..8].copy_from_slice(VERITY_MAGIC);
    sb[8..12].copy_from_slice(&VERITY_VERSION.to_le_bytes());
    sb[12..16].copy_from_slice(&VERITY_HASH_TYPE.to_le_bytes());
    sb[0x10..0x20].copy_from_slice(&uuid);
    let algo = b"sha256";
    sb[0x20..0x20 + algo.len()].copy_from_slice(algo);
    sb[0x40..0x44].copy_from_slice(&(data_block_size.to_le_bytes()));
    sb[0x44..0x48].copy_from_slice(&(hash_block_size.to_le_bytes()));
    sb[0x48..0x50].copy_from_slice(&(data_blocks as u64).to_le_bytes());
    sb[0x50..0x58].copy_from_slice(&(salt.len() as u64).to_le_bytes());
    sb[0x58..0x58 + salt.len()].copy_from_slice(salt);

    // 6. Append superblock + tree levels (top-first).
    image.extend_from_slice(&sb);
    for level in levels.iter().rev() {
        image.extend_from_slice(level);
    }

    Ok(VerityFormatResult {
        root_hash: root_hash_hex,
        hash_offset,
    })
}

/// SHA-256(salt || block).
fn hash_block(salt: &[u8], block: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(block);
    hasher.finalize().to_vec()
}

fn flatten(hashes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hashes.len() * DIGEST_SIZE);
    for h in hashes {
        out.extend_from_slice(h);
    }
    out
}

/// Verify a verity-protected image in memory: recompute the root hash from the
/// data area and compare it to `expected_root_hash` (hex).
pub fn verity_verify(
    image: &[u8],
    hash_offset: u64,
    salt: &[u8],
    data_block_size: u32,
    hash_block_size: u32,
    expected_root_hash: &str,
) -> Result<()> {
    let dbs = data_block_size as usize;
    let hbs = hash_block_size as usize;
    let hash_offset = hash_offset as usize;
    if !hash_offset.is_multiple_of(dbs) {
        return Err(Error::msg("hash offset not a multiple of data block size"));
    }
    let data_blocks = hash_offset / dbs;
    let mut current: Vec<Vec<u8>> = Vec::with_capacity(data_blocks);
    for i in 0..data_blocks {
        current.push(hash_block(salt, &image[i * dbs..(i + 1) * dbs]));
    }
    loop {
        let flat = flatten(&current);
        let nblocks = flat.len().div_ceil(hbs);
        let mut level_bytes = flat;
        level_bytes.resize(nblocks * hbs, 0);
        if nblocks <= 1 {
            let root = hash_block(salt, &level_bytes);
            let got = hex::encode(&root);
            if got.eq_ignore_ascii_case(expected_root_hash) {
                return Ok(());
            }
            return Err(Error::msg(format!(
                "verity root hash mismatch: expected {expected_root_hash}, got {got}"
            )));
        }
        current = (0..nblocks)
            .map(|j| hash_block(salt, &level_bytes[j * hbs..(j + 1) * hbs]))
            .collect();
    }
}
