//! `sbkey-generate`: emit a complete Secure Boot key set.
//!
//! For each of PK, KEK and db this writes:
//!
//! - `<name>.key`  — PKCS#8 private key (PEM), or a SENC envelope of its
//!   PKCS#8 DER when a passphrase is supplied
//! - `<name>.crt`  — self-signed X.509 cert (PEM)
//! - `<name>.der`  — the same self-signed X.509 cert (DER)
//! - `<name>.esl`  — EFI Signature List wrapping the cert
//! - `<name>.auth` — authenticated-variable update signed by the parent key
//!
//! The signing chain is PK←self, KEK←PK, db←KEK, matching the UEFI update
//! hierarchy.

use std::path::Path;

use crate::error::Result;

use super::esl::{self, DEFAULT_VAR_ATTRS, GUID_GLOBAL_VARIABLE, GUID_IMAGE_SECURITY_DATABASE};
use super::x509::{
    CertKind, build_self_signed_cert, cert_to_pem, encrypt_private_key, generate_rsa_key,
    parse_issuer_and_serial, private_key_to_pem, validity_strings,
};

/// Per-key material generated for one role (PK / KEK / db).
struct Key {
    key: rsa::RsaPrivateKey,
    cert_der: Vec<u8>,
    issuer_der: Vec<u8>,
    serial_der: Vec<u8>,
}

impl Key {
    fn new(cn: &str, kind: CertKind) -> Result<Self> {
        let key = generate_rsa_key()?;
        let (nb, na) = validity_strings(20);
        // A random-ish serial (timestamp-based) avoids collisions across runs.
        let serial_be = (chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128)
            .to_be_bytes()
            .to_vec();
        let cert_der = build_self_signed_cert(&key, cn, &serial_be, &nb, &na, kind)?;
        let (issuer_der, serial_der) = parse_issuer_and_serial(&cert_der)?;
        Ok(Self {
            key,
            cert_der,
            issuer_der,
            serial_der,
        })
    }
}

/// One role in the Secure Boot hierarchy.
struct Role {
    name: &'static str,
    cn: &'static str,
    /// EFI variable vendor GUID (canonical string).
    var_guid: &'static str,
}

const PK: Role = Role {
    name: "PK",
    cn: "sysimage Platform Key",
    var_guid: GUID_GLOBAL_VARIABLE,
};
const KEK: Role = Role {
    name: "KEK",
    cn: "sysimage Key Exchange Key",
    var_guid: GUID_GLOBAL_VARIABLE,
};
const DB: Role = Role {
    name: "db",
    cn: "sysimage Signature Database",
    var_guid: GUID_IMAGE_SECURITY_DATABASE,
};

/// Generate a full PK/KEK/db key set into `output_dir`, with plaintext
/// (unencrypted) private keys.
pub fn sbkey_generate(output_dir: &Path) -> Result<()> {
    sbkey_generate_with_passphrase(output_dir, None)
}

/// Generate a full PK/KEK/db key set into `output_dir`.
///
/// When `passphrase` is `Some`, every `<name>.key` is written as a
/// SENC-encrypted envelope (see [`encrypt_private_key`]) keyed by those exact
/// bytes instead of a plaintext PKCS#8 PEM block. The certificates, ESLs and
/// authenticated-variable updates are unaffected.
pub fn sbkey_generate_with_passphrase(output_dir: &Path, passphrase: Option<&[u8]>) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let pk = Key::new(PK.cn, CertKind::Ca)?;
    let kek = Key::new(KEK.cn, CertKind::Ca)?;
    let db = Key::new(DB.cn, CertKind::CodeSigning)?;

    let (pk_owner, _) = esl::random_guid()?;
    let (kek_owner, _) = esl::random_guid()?;
    let (db_owner, _) = esl::random_guid()?;

    let timestamp = esl::efi_time_now();

    write_key_files(output_dir, PK.name, &pk, passphrase)?;
    write_key_files(output_dir, KEK.name, &kek, passphrase)?;
    write_key_files(output_dir, DB.name, &db, passphrase)?;

    // ESLs.
    let pk_esl = esl::build_esl(&pk.cert_der, &pk_owner)?;
    let kek_esl = esl::build_esl(&kek.cert_der, &kek_owner)?;
    let db_esl = esl::build_esl(&db.cert_der, &db_owner)?;
    std::fs::write(output_dir.join(format!("{}.esl", PK.name)), &pk_esl)?;
    std::fs::write(output_dir.join(format!("{}.esl", KEK.name)), &kek_esl)?;
    std::fs::write(output_dir.join(format!("{}.esl", DB.name)), &db_esl)?;

    let pk_guid = esl::guid_to_bytes(PK.var_guid)?;
    let db_guid = esl::guid_to_bytes(GUID_IMAGE_SECURITY_DATABASE)?;

    // PK.auth signed by PK itself (self).
    let pk_auth = esl::build_auth(
        PK.name,
        &pk_guid,
        DEFAULT_VAR_ATTRS,
        &timestamp,
        &pk_esl,
        &pk.cert_der,
        &pk.issuer_der,
        &pk.serial_der,
        &pk.key,
    )?;
    // KEK.auth signed by PK.
    let kek_auth = esl::build_auth(
        KEK.name,
        &pk_guid,
        DEFAULT_VAR_ATTRS,
        &timestamp,
        &kek_esl,
        &pk.cert_der,
        &pk.issuer_der,
        &pk.serial_der,
        &pk.key,
    )?;
    // db.auth signed by KEK (db lives in the image-security-database vendor GUID).
    let db_auth = esl::build_auth(
        DB.name,
        &db_guid,
        DEFAULT_VAR_ATTRS,
        &timestamp,
        &db_esl,
        &kek.cert_der,
        &kek.issuer_der,
        &kek.serial_der,
        &kek.key,
    )?;

    std::fs::write(output_dir.join(format!("{}.auth", PK.name)), &pk_auth)?;
    std::fs::write(output_dir.join(format!("{}.auth", KEK.name)), &kek_auth)?;
    std::fs::write(output_dir.join(format!("{}.auth", DB.name)), &db_auth)?;

    Ok(())
}

fn write_key_files(dir: &Path, name: &str, k: &Key, passphrase: Option<&[u8]>) -> Result<()> {
    let key_bytes = match passphrase {
        Some(p) => encrypt_private_key(&k.key, p)?,
        None => private_key_to_pem(&k.key)?.into_bytes(),
    };
    std::fs::write(dir.join(format!("{name}.key")), &key_bytes)?;
    std::fs::write(dir.join(format!("{name}.crt")), cert_to_pem(&k.cert_der))?;
    std::fs::write(dir.join(format!("{name}.der")), &k.cert_der)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("sbkeys-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generate_writes_full_keyset() {
        let dir = TempDir::new();
        sbkey_generate(dir.path()).unwrap();
        for name in ["PK", "KEK", "db"] {
            assert!(dir.path().join(format!("{name}.key")).exists());
            assert!(dir.path().join(format!("{name}.crt")).exists());
            assert!(dir.path().join(format!("{name}.der")).exists());
            assert!(dir.path().join(format!("{name}.esl")).exists());
            assert!(dir.path().join(format!("{name}.auth")).exists());
        }
    }

    #[test]
    fn encrypted_keys_round_trip() {
        use crate::secboot::x509::{load_private_key, public_key_pkcs1_der};

        let dir = TempDir::new();
        let passphrase = b"correct horse battery staple";
        sbkey_generate_with_passphrase(dir.path(), Some(passphrase)).unwrap();

        for name in ["PK", "KEK", "db"] {
            let bytes = std::fs::read(dir.path().join(format!("{name}.key"))).unwrap();
            assert_eq!(&bytes[..4], b"SENC", "{name}.key must be a SENC envelope");
            // The SENC envelope is not a plaintext PEM key.
            assert!(!bytes.starts_with(b"-----BEGIN"));

            let key = load_private_key(&bytes, Some(passphrase)).unwrap();
            // The recovered private key exposes a usable public key.
            assert!(!public_key_pkcs1_der(&key).unwrap().is_empty());
        }
    }

    #[test]
    fn encrypted_key_needs_passphrase() {
        use crate::secboot::x509::load_private_key;

        let dir = TempDir::new();
        sbkey_generate_with_passphrase(dir.path(), Some(b"hunter2")).unwrap();
        let bytes = std::fs::read(dir.path().join("db.key")).unwrap();

        // Missing passphrase.
        assert!(load_private_key(&bytes, None).is_err());
        // Wrong passphrase (authentication failure).
        assert!(load_private_key(&bytes, Some(b"wrong")).is_err());
        // Correct passphrase.
        assert!(load_private_key(&bytes, Some(b"hunter2")).is_ok());
    }

    #[test]
    fn plaintext_key_still_loads_without_passphrase() {
        use crate::secboot::x509::load_private_key;

        let dir = TempDir::new();
        sbkey_generate(dir.path()).unwrap();
        let bytes = std::fs::read(dir.path().join("PK.key")).unwrap();
        assert!(bytes.starts_with(b"-----BEGIN"));
        assert!(load_private_key(&bytes, None).is_ok());
    }

    #[test]
    fn load_cert_pem() {
        use crate::secboot::x509::cert_pem_to_der;
        let dir = TempDir::new();
        sbkey_generate(dir.path()).unwrap();
        let crt = std::fs::read_to_string(dir.path().join("PK.crt")).unwrap();
        let der = cert_pem_to_der(&crt).unwrap();
        assert_eq!(der[0], 0x30);
        let (issuer, serial) = parse_issuer_and_serial(&der).unwrap();
        assert_eq!(issuer[0], 0x30);
        assert_eq!(serial[0], 0x02);
        // The `.der` sidecar must be byte-identical to the PEM-decoded cert.
        let der_file = std::fs::read(dir.path().join("PK.der")).unwrap();
        assert_eq!(der_file, der);
    }
}
