//! SHA-256 helpers.

use sha2::{Digest, Sha256};

/// SHA-256 digest of a file's contents, streamed in chunks.
pub fn hash_file(path: &std::path::Path) -> crate::error::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

/// SHA-256 digest of the concatenation of the given byte slices.
pub fn hash_content(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// SHA-256 digest of a reader's contents, streamed in chunks.
pub fn hash_reader(r: &mut dyn std::io::Read) -> crate::error::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

/// Encode a digest as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
