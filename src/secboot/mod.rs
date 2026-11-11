//! Secure Boot key generation and PE signing.
//!
//! This module provides CLI-facing capabilities around Secure Boot:
//!
//! - [`generate::sbkey_generate`]: generate a full Secure Boot key set (PK,
//!   KEK, db) — each as a PEM private key + self-signed X.509 cert, an EFI
//!   Signature List (`.esl`) and an authenticated-variable update (`.auth`)
//!   — with the signing chain PK←self, KEK←PK, db←KEK. With
//!   [`generate::sbkey_generate_with_passphrase`] each private key is written
//!   as a SENC envelope (see [`crate::secboot::x509::encrypt_private_key`])
//!   instead of plaintext; [`crate::secboot::x509::load_private_key`] reads
//!   either form.
//! - [`authenticode::sign_pe`]: the pure-Rust Authenticode PKCS#7 signer used
//!   by the `build:efisign:` artifact step to sign `.efi` binaries at build
//!   time.
//!
//! Everything is pure Rust: X.509 certs, Authenticode PKCS#7, EFI Signature
//! Lists and authenticated variables are hand-encoded DER (see [`der`]).
//! PE signatures match what `sbsigntools` produces byte-for-byte; the
//! `.auth` signatures follow `sbctl` (a bare `SignedData` with
//! `contentType`/`signingTime`/`messageDigest` authenticated attributes).

pub mod authenticode;
pub mod der;
pub mod esl;
pub mod generate;
pub mod x509;
