//! X.509 self-signed certificate generation (hand-encoded DER) plus PEM and
//! RSA signing helpers shared by the Secure Boot modules.
//!
//! Only what Secure Boot needs is built: a self-signed RSA-2048 v3 cert with
//! BasicConstraints(cA), KeyUsage(keyCertSign+cRLSign) and SKI/AKI extensions.
//! The cert DER is byte-compatible with what `openssl`/`sbsign` produce and
//! verifies with `sbverify`.

use base64::Engine;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use sha1::{Digest as Sha1Digest, Sha1};
use zeroize::Zeroizing;

use crate::encrypt;
use crate::error::{Error, Result};

use super::der::{
    self, append, bit_string, boolean, explicit, implicit_primitive, integer_bytes_be,
    octet_string, seq, set, utf8_string,
};

/// Which role a self-signed cert plays in the Secure Boot hierarchy.
///
/// `Ca` certs (PK, KEK) are CA certificates (`cA=TRUE`, `keyCertSign`) used to
/// sign authenticated-variable updates. `CodeSigning` certs (db) are leaf
/// end-entity certificates (`cA=FALSE`, `digitalSignature`, `codeSigning` EKU)
/// used to sign EFI binaries — this shape is what `sbverify`/`PKCS7_verify`
/// accept as a valid signing certificate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    Ca,
    CodeSigning,
}

/// Generate a fresh RSA-2048 private key.
pub fn generate_rsa_key() -> Result<rsa::RsaPrivateKey> {
    rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| Error::msg(format!("RSA keygen: {e}")))
}

/// Load an RSA private key from a PKCS#8 PEM string.
pub fn load_private_key_pem(pem: &str) -> Result<rsa::RsaPrivateKey> {
    rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| Error::msg(format!("load key: {e}")))
}

/// Load an RSA private key from key-file bytes, transparently handling a
/// SENC-encrypted key produced by [`encrypt_private_key`].
///
/// When `bytes` begins with the SENC magic, `passphrase` is required (its
/// exact bytes are the single key component used to derive the envelope key)
/// and the decrypted PKCS#8 DER is parsed. Otherwise the bytes are parsed as a
/// plaintext PKCS#8 PEM block, exactly like [`load_private_key_pem`].
pub fn load_private_key(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<rsa::RsaPrivateKey> {
    if bytes.starts_with(&encrypt::MAGIC) {
        let passphrase = passphrase.ok_or_else(|| {
            Error::msg("encrypted private key: a passphrase is required to decrypt it")
        })?;
        let key = Zeroizing::new(encrypt::derive_key(&[passphrase])?);
        let der = Zeroizing::new(encrypt::decrypt_envelope(bytes, &key[..])?);
        return rsa::RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|e| Error::msg(format!("load key: {e}")));
    }
    let pem = std::str::from_utf8(bytes).map_err(|e| Error::msg(format!("load key: {e}")))?;
    load_private_key_pem(pem)
}

/// Encrypt a private key into a SENC envelope (AES-256-GCM) whose key is
/// derived with HKDF-SHA256 from the exact bytes of `passphrase`.
///
/// The plaintext is the PKCS#8 DER form of `key`. The resulting bytes can be
/// read back with [`load_private_key`] (given the same passphrase) or with the
/// standalone `senc decrypt` helper (`--key-file <passphrase>`).
pub fn encrypt_private_key(key: &rsa::RsaPrivateKey, passphrase: &[u8]) -> Result<Vec<u8>> {
    let der = Zeroizing::new(private_key_pkcs8_der(key)?);
    let envelope_key = Zeroizing::new(encrypt::derive_key(&[passphrase])?);
    encrypt::encrypt_envelope(
        &der[..],
        &envelope_key[..],
        encrypt::EncryptAlgorithm::Aes256Gcm,
    )
}

/// PKCS#8 private-key DER for `key`.
pub fn private_key_pkcs8_der(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    key.to_pkcs8_der()
        .map(|v| v.as_bytes().to_vec())
        .map_err(|e| Error::msg(format!("pkcs8: {e}")))
}

/// SubjectPublicKeyInfo DER (the bytes embedded in the X.509 cert) for `key`.
pub fn public_key_spki_der(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    rsa::RsaPublicKey::from(key)
        .to_public_key_der()
        .map(|v| v.as_ref().to_vec())
        .map_err(|e| Error::msg(format!("spki: {e}")))
}

/// PKCS#1 RSAPublicKey DER (used to compute the SubjectKeyIdentifier).
pub fn public_key_pkcs1_der(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    rsa::RsaPublicKey::from(key)
        .to_pkcs1_der()
        .map(|v| v.as_ref().to_vec())
        .map_err(|e| Error::msg(format!("pkcs1: {e}")))
}

/// RSA-PKCS1v1.5-SHA256 signature over `msg` (the message is hashed with
/// SHA-256 internally, matching Authenticode / X.509 signing).
pub fn rsa_sign_sha256(key: &rsa::RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let sig = signing_key.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

// --------------------------------------------------------------------------
// PEM helpers
// --------------------------------------------------------------------------

/// Wrap a DER blob as a single PEM block with the given label, base64-encoded
/// with 64-character line wrapping.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Parse the first PEM block with `label` from `text`, returning the DER.
pub fn from_pem(label: &str, text: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| Error::msg(format!("PEM: missing {label}")))?;
    let rest = &text[start + begin.len()..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| Error::msg(format!("PEM: missing {label} end")))?;
    let b64: String = rest[..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| Error::msg(format!("PEM base64: {e}")))?;
    Ok(der)
}

pub fn cert_to_pem(cert_der: &[u8]) -> String {
    to_pem("CERTIFICATE", cert_der)
}

pub fn private_key_to_pem(key: &rsa::RsaPrivateKey) -> Result<String> {
    let der = private_key_pkcs8_der(key)?;
    Ok(to_pem("PRIVATE KEY", &der))
}

/// Parse a `CERTIFICATE` PEM block into DER.
pub fn cert_pem_to_der(pem: &str) -> Result<Vec<u8>> {
    from_pem("CERTIFICATE", pem)
}

// --------------------------------------------------------------------------
// Distinguished Name + validity
// --------------------------------------------------------------------------

/// Build a Name (Distinguished Name) with a single commonName attribute:
/// `SEQUENCE OF SET OF SEQUENCE { OID(commonName), UTF8String(cn) }`.
fn name(cn: &str) -> Vec<u8> {
    let mut atv = Vec::new();
    append(&mut atv, &der::oid(der::OID_COMMON_NAME));
    append(&mut atv, &utf8_string(cn));
    let atv = seq(atv);
    let rdn = set(atv);
    seq(rdn)
}

/// Build a self-signed X.509 v3 certificate.
///
/// `serial` is the raw serial bytes (big-endian); `not_before` / `not_after`
/// are `YYMMDDHHMMSSZ` UTCTime strings. Returns the full Certificate DER.
pub fn build_self_signed_cert(
    key: &rsa::RsaPrivateKey,
    subject_cn: &str,
    serial_be: &[u8],
    not_before: &str,
    not_after: &str,
    kind: CertKind,
) -> Result<Vec<u8>> {
    let spki = public_key_spki_der(key)?;
    let pkcs1 = public_key_pkcs1_der(key)?;

    // SubjectKeyIdentifier = SHA-1 of the DER-encoded RSAPublicKey.
    let mut ski_hasher = Sha1::new();
    ski_hasher.update(&pkcs1);
    let ski = ski_hasher.finalize();

    // --- extensions ---
    let mut exts = Vec::new();

    // BasicConstraints (critical). CA certs get cA=TRUE; leaf certs get an
    // empty SEQUENCE (cA=FALSE).
    let bc_value = match kind {
        CertKind::Ca => seq(boolean(true)),
        CertKind::CodeSigning => seq(Vec::new()),
    };
    let mut bc = Vec::new();
    append(&mut bc, &der::oid(der::OID_BASIC_CONSTRAINTS));
    append(&mut bc, &boolean(true)); // critical
    append(&mut bc, &octet_string(&bc_value));
    append(&mut exts, &seq(bc));

    // KeyUsage (critical). CA: keyCertSign|cRLSign. Leaf: digitalSignature.
    let ku_value = match kind {
        CertKind::Ca => bit_string(&[0x06], 1), // keyCertSign(5) | cRLSign(6)
        CertKind::CodeSigning => bit_string(&[0x80], 7), // digitalSignature(0)
    };
    let mut ku = Vec::new();
    append(&mut ku, &der::oid(der::OID_KEY_USAGE));
    append(&mut ku, &boolean(true)); // critical
    append(&mut ku, &octet_string(&ku_value));
    append(&mut exts, &seq(ku));

    // SubjectKeyIdentifier: OCTET STRING(SHA-1)
    let mut skid = Vec::new();
    append(&mut skid, &der::oid(der::OID_SUBJECT_KEY_ID));
    append(&mut skid, &octet_string(&octet_string(&ski)));
    append(&mut exts, &seq(skid));

    if kind == CertKind::Ca {
        // AuthorityKeyIdentifier: SEQUENCE { [0] IMPLICIT OCTET STRING(SHA-1) }
        let aki_inner = implicit_primitive(0, octet_string(&ski).to_vec());
        let aki_value = seq(aki_inner);
        let mut aki = Vec::new();
        append(&mut aki, &der::oid(der::OID_AUTHORITY_KEY_ID));
        append(&mut aki, &octet_string(&aki_value));
        append(&mut exts, &seq(aki));
    } else {
        // ExtendedKeyUsage (non-critical): codeSigning — required for a leaf
        // signing-cert to be accepted by PKCS7_verify/sbverify.
        let eku_value = seq(der::oid(der::OID_EKU_CODE_SIGNING));
        let mut eku = Vec::new();
        append(&mut eku, &der::oid(der::OID_EXT_KEY_USAGE));
        append(&mut eku, &octet_string(&eku_value));
        append(&mut exts, &seq(eku));
    }

    let extensions = explicit(3, seq(exts));

    // --- TBSCertificate ---
    let name_dn = name(subject_cn);
    let validity_seq = {
        let mut v = Vec::new();
        append(&mut v, &der::utc_time(not_before));
        append(&mut v, &der::utc_time(not_after));
        seq(v)
    };

    let mut tbs = Vec::new();
    // version [0] EXPLICIT INTEGER v3 (2)
    append(&mut tbs, &explicit(0, der::integer_u64(2)));
    // serialNumber
    append(&mut tbs, &integer_bytes_be(serial_be));
    // signature AlgorithmIdentifier (sha256WithRSAEncryption)
    append(&mut tbs, &der::alg_id_sha256_rsa());
    // issuer = subject (self-signed)
    append(&mut tbs, &name_dn);
    // validity
    append(&mut tbs, &validity_seq);
    // subject
    append(&mut tbs, &name_dn);
    // subjectPublicKeyInfo (embed the rsa SPKI verbatim)
    append(&mut tbs, &spki);
    // extensions [3] EXPLICIT
    append(&mut tbs, &extensions);
    let tbs = seq(tbs);

    // --- signature ---
    let sig = rsa_sign_sha256(key, &tbs)?;
    let sig_bitstring = bit_string(&sig, 0);

    let mut cert = Vec::new();
    append(&mut cert, &tbs);
    append(&mut cert, &der::alg_id_sha256_rsa());
    append(&mut cert, &sig_bitstring);
    Ok(seq(cert))
}

// --------------------------------------------------------------------------
// Validity timestamps
// --------------------------------------------------------------------------

/// Build a UTCTime `YYMMDDHHMMSSZ` string from a UTC moment.
pub fn utc_time_string(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%y%m%d%H%M%SZ").to_string()
}

/// Convenience: not-before = now, not-after = now + `years`.
pub fn validity_strings(years: i32) -> (String, String) {
    let now = chrono::Utc::now();
    let later = now + chrono::Duration::days(years as i64 * 365);
    (utc_time_string(now), utc_time_string(later))
}

// --------------------------------------------------------------------------
// Re-export the issuer/serial parser for callers that load an existing cert.
// --------------------------------------------------------------------------

pub fn parse_issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    der::parse_issuer_and_serial(cert_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_and_cert_roundtrip() {
        let key = generate_rsa_key().unwrap();
        let (nb, na) = validity_strings(10);
        let cert =
            build_self_signed_cert(&key, "sysimage test", &[1, 2, 3], &nb, &na, CertKind::Ca)
                .unwrap();
        let pem = cert_to_pem(&cert);
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        let der2 = cert_pem_to_der(&pem).unwrap();
        assert_eq!(der2, cert);
        let (issuer, serial) = parse_issuer_and_serial(&cert).unwrap();
        assert_eq!(issuer[0], 0x30);
        assert_eq!(serial[0], 0x02);
    }
}
