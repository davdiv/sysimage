//! SENC device-bound AEAD envelope (core implementation).
//!
//! This crate is the single audited implementation of the "SENC" format used
//! by the `sysimage` `encrypt` build artifact and by the standalone `senc`
//! helper. It is deliberately dependency-pure (no serde/schemars/config code)
//! so the helper binary links only the crypto crates and stays small enough
//! for an initramfs.
//!
//! # Envelope format (version 1)
//!
//! ```text
//! offset 0   : magic      4 bytes   b"SENC"
//! offset 4   : version    1 byte    = 1
//! offset 5   : algorithm  1 byte    (1 = aes-256-gcm)
//! offset 6   : nonce      12 bytes  deterministic (see below)
//! offset 18  : ciphertext N bytes   AES-256-GCM (AAD = header[0..6])
//! offset 18+N: tag        16 bytes  (appended by AES-GCM)
//! ```
//!
//! # Deterministic nonce
//!
//! The 12-byte nonce is derived as
//! `HMAC-SHA256(key, b"sysimage-devicekey-nonce" || plaintext)[0..12]` so that
//! rebuilding the same image with the same key and input yields a
//! byte-identical artifact (and therefore a stable content hash). This is safe
//! because the nonce is a pure function of (key, plaintext): different
//! plaintexts under the same key produce different nonces, and the same
//! (key, plaintext) pair always produces the same nonce — exactly the AEAD
//! requirement that a (key, nonce) pair is never reused with *different*
//! messages.
//!
//! # Key derivation
//!
//! [`derive_key`] turns an ordered list of key components (raw file bytes) into
//! the 32-byte envelope key using HKDF-SHA256 (RFC 5869):
//!
//! ```text
//! combined = concat(part) over all parts           (in order)
//! IKM      = u64-BE(len(combined)) || combined     (length of the whole)
//! salt     = b"sysimage-senc"
//! info     = b"sysimage-devicekey-v1"
//! key      = HKDF-SHA256(salt, IKM, info, 32)
//! ```
//!
//! Components are concatenated in order and the result is prefixed once with
//! its total length. This makes repeated key options **concatenable**: `-k a
//! -k b` derives exactly the same key as `-k ab` (where `ab` is the
//! concatenation of the two components), and a single component's derivation is
//! unchanged by the shared length prefix. The derivation stays
//! order-sensitive (`("a","bc")` differs from `("bc","a")`). At least one
//! component is required. Key components are used **exactly as read** — no
//! trailing-newline stripping.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Envelope magic bytes.
pub const MAGIC: [u8; 4] = *b"SENC";
/// Envelope format version.
pub const VERSION: u8 = 1;
/// Nonce length in bytes (96 bits, the standard GCM nonce size).
pub const NONCE_LEN: usize = 12;
/// GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Fixed header length: magic (4) + version (1) + algorithm (1).
pub const HEADER_LEN: usize = 6;
/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

/// Domain-separation label for the deterministic nonce derivation.
const NONCE_LABEL: &[u8] = b"sysimage-devicekey-nonce";
/// HKDF salt for key derivation.
const KDF_SALT: &[u8] = b"sysimage-senc";
/// HKDF info/context for key derivation.
const KDF_INFO: &[u8] = b"sysimage-devicekey-v1";

/// Errors produced by the SENC core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The envelope is too short to contain a header, nonce, and tag.
    #[error("senc: envelope too short ({0} bytes; minimum {1})")]
    EnvelopeTooShort(usize, usize),
    /// The envelope does not begin with the `SENC` magic.
    #[error("senc: bad envelope magic (expected \"SENC\")")]
    BadMagic,
    /// The envelope version is not supported.
    #[error("senc: unsupported envelope version {0}; only version 1 is supported")]
    UnsupportedVersion(u8),
    /// The algorithm byte is not recognized.
    #[error("senc: unsupported algorithm byte: {0}")]
    UnsupportedAlgorithm(u8),
    /// The algorithm name is not recognized.
    #[error("senc: unknown algorithm name: {0}")]
    UnknownAlgorithmName(String),
    /// The key is not the length required by the algorithm.
    #[error("senc: {algorithm} requires a {expected}-byte key, got {got} bytes")]
    WrongKeyLength {
        algorithm: &'static str,
        expected: usize,
        got: usize,
    },
    /// AES-256-GCM encryption failed (only possible on length overflow).
    #[error("senc: AES-256-GCM encryption failed")]
    EncryptionFailed,
    /// Authentication failed: wrong key or corrupted/tampered data.
    #[error("senc: authentication failed (bad key or corrupted data)")]
    AuthenticationFailed,
    /// No key components were supplied to `derive_key`.
    #[error("senc: at least one key component is required")]
    NoKeyParts,
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// The AEAD algorithm used by a SENC envelope.
///
/// Only `aes-256-gcm` is supported initially; the enum is designed so more
/// AEADs can be added later without changing the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// AES-256 in GCM mode (32-byte key, 12-byte nonce, 16-byte tag).
    #[default]
    Aes256Gcm,
}

impl Algorithm {
    /// The on-wire algorithm byte for this algorithm.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
        }
    }

    /// Parse an on-wire algorithm byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Aes256Gcm),
            other => Err(Error::UnsupportedAlgorithm(other)),
        }
    }

    /// Parse an algorithm name (as used by the CLI `--algorithm` flag).
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            other => Err(Error::UnknownAlgorithmName(other.to_string())),
        }
    }

    /// The required key length in bytes for this algorithm.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256Gcm => KEY_LEN,
        }
    }

    /// Human-readable algorithm name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// Derive the deterministic 12-byte nonce for an encryption operation:
/// `HMAC-SHA256(key, NONCE_LABEL || plaintext)[0..12]`.
fn derive_nonce(key: &[u8], plaintext: &[u8]) -> [u8; NONCE_LEN] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(NONCE_LABEL);
    mac.update(plaintext);
    let digest = mac.finalize().into_bytes();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

/// Derive the 32-byte envelope key from an ordered list of key components
/// (each typically the exact bytes of a key file) using HKDF-SHA256.
///
/// The components are concatenated in order and the concatenation is prefixed
/// once with its `u64` big-endian length. This makes repeated components
/// **concatenable** — `["a", "b"]` derives the same key as `["ab"]` — and keeps
/// a single component's derivation identical to a standalone one. The mapping
/// from the list of components to the key is order-sensitive. At least one
/// component is required.
pub fn derive_key(parts: &[&[u8]]) -> Result<[u8; KEY_LEN]> {
    if parts.is_empty() {
        return Err(Error::NoKeyParts);
    }

    // Concatenate all components in order, prefixed once with the total
    // length. Held in a zeroizing buffer so the raw key material is scrubbed
    // on drop.
    let total: u64 = parts.iter().map(|p| p.len() as u64).sum();
    let mut ikm = Zeroizing::new(Vec::with_capacity(8 + total as usize));
    ikm.extend_from_slice(&total.to_be_bytes());
    for part in parts {
        ikm.extend_from_slice(part);
    }

    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), ikm.as_slice());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(KDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    Ok(okm)
}

/// Encrypt `plaintext` into a SENC envelope using `key` and `algorithm`.
///
/// The output is deterministic: the same (key, plaintext, algorithm) triple
/// always produces the same bytes (see the module docs for the nonce
/// derivation). The local key copy is scrubbed after use (the cipher also
/// self-zeroizes on drop); the caller owns and should scrub the plaintext
/// buffer.
pub fn encrypt(plaintext: &[u8], key: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
    let expected_key_len = algorithm.key_len();
    if key.len() != expected_key_len {
        return Err(Error::WrongKeyLength {
            algorithm: algorithm.name(),
            expected: expected_key_len,
            got: key.len(),
        });
    }

    // Build the fixed header (used as AAD).
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = algorithm.to_byte();

    // Derive the deterministic nonce.
    let nonce_bytes = derive_nonce(key, plaintext);

    // Encrypt with AES-256-GCM, AAD = header.
    let mut key_arr: Key<Aes256Gcm> =
        (*<&[u8; KEY_LEN]>::try_from(key).map_err(|_| Error::WrongKeyLength {
            algorithm: algorithm.name(),
            expected: expected_key_len,
            got: key.len(),
        })?)
        .into();
    let cipher = Aes256Gcm::new(&key_arr);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| Error::EncryptionFailed)?;
    let payload = Payload {
        msg: plaintext,
        aad: &header,
    };
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| Error::EncryptionFailed)?;

    // Scrub our local copy of the key (the cipher also self-zeroizes on drop).
    key_arr.zeroize();

    // Assemble: header || nonce || ciphertext+tag
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext_with_tag.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext_with_tag);

    Ok(out)
}

/// Decrypt a SENC envelope produced by [`encrypt`].
///
/// Verifies the magic, version, algorithm byte, and the GCM authentication
/// tag (with the same AAD as encryption). Returns the plaintext.
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::EnvelopeTooShort(
            data.len(),
            HEADER_LEN + NONCE_LEN + TAG_LEN,
        ));
    }
    if data[..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    let version = data[4];
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let algorithm = Algorithm::from_byte(data[5])?;
    let expected_key_len = algorithm.key_len();
    if key.len() != expected_key_len {
        return Err(Error::WrongKeyLength {
            algorithm: algorithm.name(),
            expected: expected_key_len,
            got: key.len(),
        });
    }

    let aad = &data[..HEADER_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&data[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let ciphertext_with_tag = &data[HEADER_LEN + NONCE_LEN..];

    let mut key_arr: Key<Aes256Gcm> =
        (*<&[u8; KEY_LEN]>::try_from(key).map_err(|_| Error::WrongKeyLength {
            algorithm: algorithm.name(),
            expected: expected_key_len,
            got: key.len(),
        })?)
        .into();
    let cipher = Aes256Gcm::new(&key_arr);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| Error::AuthenticationFailed)?;
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };
    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::AuthenticationFailed)?;

    // Scrub our local copy of the key (the cipher also self-zeroizes on drop).
    key_arr.zeroize();

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        // A simple, well-known 32-byte key for our own round-trip tests.
        // (Not a NIST vector — just a fixed key.)
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn test_plaintext() -> Vec<u8> {
        // A simple test plaintext (64 bytes of recognizable content).
        (0u8..64)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let plaintext = test_plaintext();
        let envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        let decrypted = decrypt(&envelope, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn deterministic_output() {
        let key = test_key();
        let plaintext = test_plaintext();
        let e1 = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        let e2 = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(e1, e2, "same input must produce byte-identical envelopes");
    }

    #[test]
    fn different_plaintext_different_envelope() {
        let key = test_key();
        let e1 = encrypt(b"hello world", &key, Algorithm::Aes256Gcm).unwrap();
        let e2 = encrypt(b"hello worle", &key, Algorithm::Aes256Gcm).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn different_key_different_envelope() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 1;
        let plaintext = test_plaintext();
        let e1 = encrypt(&plaintext, &key1, Algorithm::Aes256Gcm).unwrap();
        let e2 = encrypt(&plaintext, &key2, Algorithm::Aes256Gcm).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let key = test_key();
        let mut wrong_key = test_key();
        wrong_key[0] ^= 1;
        let plaintext = test_plaintext();
        let envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        let result = decrypt(&envelope, &wrong_key);
        assert!(result.is_err(), "decryption with wrong key must fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authentication failed"),
            "error should mention authentication failure"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = test_plaintext();
        let mut envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        // Flip a bit in the ciphertext region.
        let ct_offset = HEADER_LEN + NONCE_LEN;
        envelope[ct_offset] ^= 1;
        assert!(decrypt(&envelope, &key).is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let key = test_key();
        let plaintext = test_plaintext();
        let mut envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        // Tamper with the algorithm byte (part of the AAD).
        envelope[5] = 99;
        // Either the algorithm parse fails or the GCM tag check fails.
        assert!(decrypt(&envelope, &key).is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let short_key = [0u8; 31];
        let result = encrypt(b"test", &short_key, Algorithm::Aes256Gcm);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("31 bytes"));
    }

    #[test]
    fn envelope_too_short_rejected() {
        let result = decrypt(&[0u8; 10], &test_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn bad_magic_rejected() {
        let key = test_key();
        let mut envelope = encrypt(&test_plaintext(), &key, Algorithm::Aes256Gcm).unwrap();
        envelope[0] = b'X';
        let result = decrypt(&envelope, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn unsupported_version_rejected() {
        let key = test_key();
        let mut envelope = encrypt(&test_plaintext(), &key, Algorithm::Aes256Gcm).unwrap();
        envelope[4] = 99;
        let result = decrypt(&envelope, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn envelope_structure() {
        let key = test_key();
        let plaintext = test_plaintext();
        let envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(&envelope[..4], b"SENC");
        assert_eq!(envelope[4], 1);
        assert_eq!(envelope[5], 1);
        assert_eq!(
            envelope.len(),
            HEADER_LEN + NONCE_LEN + plaintext.len() + TAG_LEN
        );
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = test_key();
        let plaintext: Vec<u8> = vec![];
        let envelope = encrypt(&plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        assert_eq!(
            envelope.len(),
            HEADER_LEN + NONCE_LEN + TAG_LEN,
            "empty plaintext should produce header + nonce + tag only"
        );
        assert_eq!(decrypt(&envelope, &key).unwrap(), plaintext);
    }

    // --- key derivation -----------------------------------------------------

    #[test]
    fn derive_key_deterministic() {
        let a = derive_key(&[b"one", b"two"]).unwrap();
        let b = derive_key(&[b"one", b"two"]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_order_sensitive() {
        let a = derive_key(&[b"one", b"two"]).unwrap();
        let b = derive_key(&[b"two", b"one"]).unwrap();
        assert_ne!(a, b, "component order must affect the derived key");
    }

    #[test]
    fn derive_key_concatenates_components() {
        // Repeated components are concatenated in order, so the boundaries
        // between them do not affect the derived key: `["a", "bc"]` and
        // `["ab", "c"]` (and a single `["abc"]`) all agree. This is what makes
        // `-k a -k b` equivalent to `-k ab` in the CLI.
        let a = derive_key(&[b"a", b"bc"]).unwrap();
        let b = derive_key(&[b"ab", b"c"]).unwrap();
        let c = derive_key(&[b"abc"]).unwrap();
        assert_eq!(a, b, "component boundaries must not affect the derived key");
        assert_eq!(
            a, c,
            "concatenated components must equal a single component"
        );
    }

    #[test]
    fn derive_key_single_component_unchanged_by_concatenation() {
        // A single component derives the same key as that component split into
        // arbitrarily many pieces.
        let whole = derive_key(&[b"the-whole-key"]).unwrap();
        let pieces = derive_key(&[b"the-", b"whole-", b"key"]).unwrap();
        assert_eq!(whole, pieces);
    }

    #[test]
    fn derive_key_rejects_empty_list() {
        assert!(matches!(derive_key(&[]), Err(Error::NoKeyParts)));
    }

    #[test]
    fn derive_key_round_trips_through_envelope() {
        let key = derive_key(&[b"file-a", b"file-b"]).unwrap();
        let plaintext = b"secret payload";
        let envelope = encrypt(plaintext, &key, Algorithm::Aes256Gcm).unwrap();
        // Same components -> same key -> decrypts.
        let key2 = derive_key(&[b"file-a", b"file-b"]).unwrap();
        assert_eq!(decrypt(&envelope, &key2).unwrap(), plaintext);
        // Different components -> different key -> fails.
        let key3 = derive_key(&[b"file-b", b"file-a"]).unwrap();
        assert!(decrypt(&envelope, &key3).is_err());
    }

    /// Cross-check against the NIST GCM test vector (test case 14) to validate
    /// our AES-256-GCM usage independently of our own round-trip.
    #[test]
    fn nist_gcm_test_vector_core() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // NIST GCM test case 14: AES-256, with AAD, 60-byte plaintext.
        let mut key_bytes = [0u8; 32];
        hex::decode_to_slice(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            &mut key_bytes,
        )
        .unwrap();
        let key: Key<Aes256Gcm> = key_bytes.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce_bytes = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let plaintext = hex::decode(concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39",
        ))
        .unwrap();
        assert_eq!(plaintext.len(), 60);
        let payload = Payload {
            msg: &plaintext,
            aad: &aad,
        };
        let ct_with_tag = cipher.encrypt(&nonce, payload).unwrap();
        let expected = hex::decode(concat!(
            "522dc1f099567d07f47f37a32a84427d",
            "643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838",
            "c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ))
        .unwrap();
        assert_eq!(
            ct_with_tag.as_slice(),
            expected.as_slice(),
            "AES-256-GCM output must match NIST test case 14"
        );
    }
}
