//! Device-bound encrypted credential envelope ("SENC" format).
//!
//! The `encrypt` build artifact wraps a plaintext input into a
//! self-describing, authenticated-encryption envelope so the ciphertext can
//! be placed into an initramfs or filesystem without the key ever entering
//! the generated image or the config. Conversely, the `decrypt` build artifact
//! unwraps such an envelope back into plaintext at build time, and the
//! `reencrypt` build artifact rotates an envelope from one set of key
//! components to another (decrypt then encrypt) without materializing the
//! plaintext. The key components are supplied
//! out-of-band via the existing `--key` / `--key-file` machinery (they land in
//! [`crate::build::BuildContext::build_keys`]); key *derivation* (e.g. from
//! SMBIOS) is done by an external helper and is out of scope here.
//!
//! The envelope format, the deterministic-nonce derivation, and the key
//! derivation are implemented once in the [`senc`] crate (shared with the
//! standalone `senc` helper). This module is the config-facing surface: it
//! re-exports the core API under the historical names and provides the
//! serde/JSON-schema `EncryptAlgorithm` enum used by the config.
//!
//! See [`senc`] for the byte-level format and the HKDF-SHA256 key derivation.

use crate::error::{Error, Result};

pub use senc::{Algorithm, HEADER_LEN, KEY_LEN, MAGIC, NONCE_LEN, TAG_LEN, VERSION};

/// The AEAD algorithm used by an
/// [`encrypt`](crate::model::config::ConfigArtifactEncrypt) artifact. Only
/// `aes-256-gcm` is supported initially; the enum is designed so more AEADs
/// can be added later.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptAlgorithm {
    /// AES-256 in GCM mode (32-byte key, 12-byte nonce, 16-byte tag).
    #[default]
    Aes256Gcm,
}

impl EncryptAlgorithm {
    /// Map to the core [`senc::Algorithm`].
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::Aes256Gcm => Algorithm::Aes256Gcm,
        }
    }

    /// The required key length in bytes for this algorithm.
    pub const fn key_len(self) -> usize {
        self.algorithm().key_len()
    }
}

/// Derive the 32-byte envelope key from ordered key components using
/// HKDF-SHA256 (see [`senc::derive_key`]).
pub fn derive_key(parts: &[&[u8]]) -> Result<[u8; KEY_LEN]> {
    senc::derive_key(parts).map_err(|e| Error::msg(e.to_string()))
}

/// Encrypt `plaintext` into a SENC envelope using `key` and `algorithm`.
///
/// The output is deterministic: the same (key, plaintext, algorithm) triple
/// always produces the same bytes.
pub fn encrypt_envelope(
    plaintext: &[u8],
    key: &[u8],
    algorithm: EncryptAlgorithm,
) -> Result<Vec<u8>> {
    senc::encrypt(plaintext, key, algorithm.algorithm()).map_err(|e| Error::msg(e.to_string()))
}

/// Decrypt a SENC envelope produced by [`encrypt_envelope`].
///
/// Verifies the magic, version, algorithm byte, and the GCM authentication
/// tag (with the same AAD as encryption). Returns the plaintext.
pub fn decrypt_envelope(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    senc::decrypt(data, key).map_err(|e| Error::msg(e.to_string()))
}
