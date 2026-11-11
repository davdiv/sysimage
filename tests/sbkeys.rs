//! Integration tests for the Secure Boot key generation and PE signing.
//!
//! The signing tests shell out to `sbverify`/`sbsign` (sbsigntools) and
//! `openssl`. Tests that depend on these tools declare them with
//! `skip_if_missing!` (see `tests/common/mod.rs`) and are skipped explicitly
//! — with a visible notice — when a tool is not on `PATH`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use sysimage::secboot::authenticode::sign_pe;
use sysimage::secboot::esl;
use sysimage::secboot::generate::{sbkey_generate, sbkey_generate_with_passphrase};
use sysimage::secboot::x509::{
    CertKind, build_self_signed_cert, cert_to_pem, generate_rsa_key, load_private_key,
    parse_issuer_and_serial, private_key_to_pem, validity_strings,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-sbkeys-{}-{n}", std::process::id()));
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

fn sample_efi(dir: &Path) -> PathBuf {
    // A hermetic minimal PE32 fixture — no dependency on a host-installed .efi.
    let p = dir.join("sample.efi");
    fs::write(&p, common::synthetic_pe()).unwrap();
    p
}

#[test]
fn sbkey_generate_writes_full_keyset() {
    let dir = TempDir::new();
    sbkey_generate(dir.path()).unwrap();

    for name in &["PK", "KEK", "db"] {
        for ext in &["key", "crt", "der", "esl", "auth"] {
            let f = dir.path().join(format!("{name}.{ext}"));
            assert!(f.exists(), "missing {}", f.display());
            assert!(
                fs::metadata(&f).map(|m| m.len() > 0).unwrap_or(false),
                "empty {}",
                f.display()
            );
        }
    }
}

#[test]
fn sbkey_generate_encrypts_private_keys() {
    let dir = TempDir::new();
    let passphrase = b"correct horse battery staple";
    sbkey_generate_with_passphrase(dir.path(), Some(passphrase)).unwrap();

    for name in ["PK", "KEK", "db"] {
        let bytes = fs::read(dir.path().join(format!("{name}.key"))).unwrap();
        assert_eq!(&bytes[..4], b"SENC", "{name}.key must be a SENC envelope");
        // The certificate sidecar is still a plaintext PEM cert.
        let crt = fs::read_to_string(dir.path().join(format!("{name}.crt"))).unwrap();
        assert!(crt.contains("BEGIN CERTIFICATE"));
    }

    // The recovered private key must be loadable and usable.
    let bytes = fs::read(dir.path().join("db.key")).unwrap();
    let key = load_private_key(&bytes, Some(passphrase)).unwrap();
    let pem = private_key_to_pem(&key).unwrap();
    assert!(pem.contains("BEGIN PRIVATE KEY"));
    // Wrong passphrase must fail (GCM authentication).
    assert!(load_private_key(&bytes, Some(b"wrong")).is_err());
}

#[test]
fn encrypted_key_decrypts_to_openssl_usable_pem() {
    skip_if_missing!("openssl");
    let dir = TempDir::new();
    let passphrase = b"openssl-interop";
    sbkey_generate_with_passphrase(dir.path(), Some(passphrase)).unwrap();

    let bytes = fs::read(dir.path().join("db.key")).unwrap();
    let key = load_private_key(&bytes, Some(passphrase)).unwrap();
    let pem = private_key_to_pem(&key).unwrap();
    let pem_path = dir.path().join("decrypted.key");
    fs::write(&pem_path, &pem).unwrap();

    // OpenSSL must accept the recovered PKCS#8 key and agree it is consistent.
    let out = Command::new("openssl")
        .args(["rsa", "-in"])
        .arg(&pem_path)
        .args(["-check", "-noout"])
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "openssl rejected the decrypted key: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn esl_sizes_match_reference() {
    let dir = TempDir::new();
    sbkey_generate(dir.path()).unwrap();
    let cert_pem = fs::read_to_string(dir.path().join("db.crt")).unwrap();
    let der = sysimage::secboot::x509::cert_pem_to_der(&cert_pem).unwrap();
    let (owner, _) = esl::random_guid().unwrap();
    let esl = esl::build_esl(&der, &owner).unwrap();
    // SignatureListSize = 44 + cert_der_len (28-byte list header + 16-byte
    // signature data header + cert_der).
    assert_eq!(esl.len(), 44 + der.len());
}

#[test]
fn auth_blob_has_efi_time_prefix() {
    let dir = TempDir::new();
    sbkey_generate(dir.path()).unwrap();
    let auth = fs::read(dir.path().join("PK.auth")).unwrap();
    // EFI_TIME is the first 16 bytes; year should be a plausible 4-digit value
    // stored little-endian in the first two bytes.
    let year = u16::from_le_bytes([auth[0], auth[1]]);
    assert!((2024..=2100).contains(&year), "implausible year {year}");
}

/// Split an `.auth` blob into `(timestamp, PKCS#7 CertData, variable payload)`.
fn split_auth(auth: &[u8]) -> (&[u8], &[u8], &[u8]) {
    // EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME (16) + WIN_CERTIFICATE_UEFI_GUID.
    // The WIN_CERTIFICATE header's dwLength covers the 24-byte
    // WIN_CERTIFICATE_UEFI_GUID header (8-byte WIN_CERTIFICATE + 16-byte
    // CertType GUID) plus the CertData.
    let dw_len = u32::from_le_bytes(auth[16..20].try_into().unwrap()) as usize;
    let cert_len = dw_len - 24;
    let certdata = &auth[40..40 + cert_len];
    let payload = &auth[40 + cert_len..];
    (&auth[..16], certdata, payload)
}

/// The detached buffer an `.auth` signature covers:
/// `name(UTF-16LE) || guid || attrs || timestamp || payload`.
fn auth_signed_buffer(name: &str, guid: &str, timestamp: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in name.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&esl::guid_to_bytes(guid).unwrap());
    out.extend_from_slice(&esl::DEFAULT_VAR_ATTRS.to_le_bytes());
    out.extend_from_slice(timestamp);
    out.extend_from_slice(payload);
    out
}

/// Read one DER TLV at `off`, returning
/// `(tag, offset of content, content length, offset just past the TLV)`.
fn der_tlv(buf: &[u8], off: usize) -> (u8, usize, usize, usize) {
    let tag = buf[off];
    let first = buf[off + 1];
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[off + 2 + i] as usize;
        }
        (len, 2 + n)
    };
    (tag, off + hdr, len, off + hdr + len)
}

/// The TLVs directly contained in `buf[start..end]`.
fn der_fields(buf: &[u8], start: usize, end: usize) -> Vec<(u8, usize, usize)> {
    let mut fields = Vec::new();
    let mut off = start;
    while off < end {
        let (tag, content, len, next) = der_tlv(buf, off);
        fields.push((tag, content, len));
        off = next;
    }
    fields
}

/// Wrap `content` in a DER TLV with `tag`.
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n > 0x7f {
        let mut bytes = Vec::new();
        let mut v = n;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        out.push(0x80 | bytes.len() as u8);
        bytes.reverse();
        out.extend_from_slice(&bytes);
    } else {
        out.push(n as u8);
    }
    out.extend_from_slice(content);
    out
}

/// The `.auth` signature must match `sbctl`'s: a bare PKCS#7 `SignedData`
/// (no `ContentInfo` wrapper) whose `SignerInfo` carries the
/// `contentType`/`signingTime`/`messageDigest` authenticated attributes, with
/// `VariableAttributes = 0x27`. `sbvarsign` instead uses `PKCS7_NOATTR`;
/// firmware that verifies the PK signature (e.g. OVH's) rejects that with
/// `EFI_SECURITY_VIOLATION`. Regression test for `sbkey-generate`'s `.auth`
/// files.
#[test]
fn auth_matches_sbctl_signed_data() {
    // Authenticated-attribute OIDs, in the order sbctl emits them.
    const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
    const OID_SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
    const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

    // sbctl sets the variable attributes without APPEND_WRITE.
    assert_eq!(
        esl::DEFAULT_VAR_ATTRS,
        0x27,
        "VariableAttributes must match sbctl"
    );

    let dir = TempDir::new();
    sbkey_generate(dir.path()).unwrap();

    let roles = [
        ("PK", "PK", esl::GUID_GLOBAL_VARIABLE, "PK.crt"),
        ("KEK", "KEK", esl::GUID_GLOBAL_VARIABLE, "PK.crt"),
        ("db", "db", esl::GUID_IMAGE_SECURITY_DATABASE, "KEK.crt"),
    ];

    let openssl = common::tool_or_skip("openssl");

    for (role, var_name, guid, signer) in roles {
        let auth = fs::read(dir.path().join(format!("{role}.auth"))).unwrap();
        let (timestamp, certdata, payload) = split_auth(&auth);
        let dw_len = u32::from_le_bytes(auth[16..20].try_into().unwrap()) as usize;
        assert_eq!(dw_len, certdata.len() + 24, "{role}.auth dwLength mismatch");

        // SignedData must be bare: its first field is the version INTEGER, not
        // a ContentInfo signedData OID.
        let (sd_tag, sd_content, sd_len, _) = der_tlv(certdata, 0);
        assert_eq!(sd_tag, 0x30, "{role}.auth CertData is not a SEQUENCE");
        let sd_fields = der_fields(certdata, sd_content, sd_content + sd_len);
        assert_eq!(
            sd_fields[0].0, 0x02,
            "{role}.auth CertData must be a bare SignedData (no ContentInfo wrapper)"
        );

        // SignerInfo's authenticatedAttributes ([0]).
        let (_, si_set, _) = sd_fields[4]; // signerInfos SET
        let (_, si_content, si_len, _) = der_tlv(certdata, si_set);
        let si_fields = der_fields(certdata, si_content, si_content + si_len);
        let (_, attrs_off, attrs_len) = *si_fields
            .iter()
            .find(|f| f.0 == 0xa0)
            .unwrap_or_else(|| panic!("{role}.auth is missing authenticatedAttributes"));

        // Attribute OIDs, in order, plus the messageDigest value.
        let attr_fields = der_fields(certdata, attrs_off, attrs_off + attrs_len);
        let mut oids = Vec::new();
        let mut message_digest = None;
        for (_, attr, _) in &attr_fields {
            let (_, oid_off, oid_len, oid_next) = der_tlv(certdata, *attr);
            let oid = certdata[oid_off..oid_off + oid_len].to_vec();
            if oid == OID_MESSAGE_DIGEST {
                let (_, set_off, _, _) = der_tlv(certdata, oid_next);
                let (_, md_off, md_len, _) = der_tlv(certdata, set_off);
                message_digest = Some(certdata[md_off..md_off + md_len].to_vec());
            }
            oids.push(oid);
        }
        assert_eq!(
            oids,
            vec![
                OID_CONTENT_TYPE.to_vec(),
                OID_SIGNING_TIME.to_vec(),
                OID_MESSAGE_DIGEST.to_vec()
            ],
            "{role}.auth authenticated attributes do not match sbctl"
        );

        // messageDigest must be SHA-256 of the signed buffer with attrs 0x27.
        let expected = Sha256::digest(auth_signed_buffer(var_name, guid, timestamp, payload));
        assert_eq!(
            message_digest.as_deref(),
            Some(expected.as_slice()),
            "{role}.auth messageDigest does not cover the signed buffer"
        );

        if !openssl {
            continue;
        }
        // Independently verify the signature over the DER SET of attributes
        // (`openssl cms` cannot parse a bare SignedData, so use `dgst`).
        let set_der = der_wrap(0x31, &certdata[attrs_off..attrs_off + attrs_len]);
        let (_, sig_off, sig_len) = *si_fields.last().unwrap(); // encryptedDigest
        let set_path = dir.path().join(format!("{role}.set.der"));
        let sig_path = dir.path().join(format!("{role}.sig"));
        let pub_path = dir.path().join(format!("{role}.pub.pem"));
        fs::write(&set_path, &set_der).unwrap();
        fs::write(&sig_path, &certdata[sig_off..sig_off + sig_len]).unwrap();
        let pub_out = Command::new("openssl")
            .args(["x509", "-in"])
            .arg(dir.path().join(signer))
            .args(["-pubkey", "-noout"])
            .output()
            .expect("openssl");
        fs::write(&pub_path, &pub_out.stdout).unwrap();
        let out = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pub_path)
            .arg("-signature")
            .arg(&sig_path)
            .arg(&set_path)
            .output()
            .expect("openssl");
        assert!(
            out.status.success(),
            "openssl rejected {role}.auth signature: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn sign_pe_verifies_with_sbverify() {
    skip_if_missing!("sbverify");
    let dir = TempDir::new();
    let efi = sample_efi(dir.path());

    sbkey_generate(dir.path()).unwrap();
    let key_pem = fs::read_to_string(dir.path().join("db.key")).unwrap();
    let cert_pem = fs::read_to_string(dir.path().join("db.crt")).unwrap();
    let key = sysimage::secboot::x509::load_private_key_pem(&key_pem).unwrap();
    let cert_der = sysimage::secboot::x509::cert_pem_to_der(&cert_pem).unwrap();
    let (issuer, serial) = parse_issuer_and_serial(&cert_der).unwrap();

    let pe = fs::read(&efi).unwrap();
    let signed = sign_pe(&pe, &cert_der, &issuer, &serial, &key).unwrap();

    let signed_path = dir.path().join("signed.efi");
    let cert_path = dir.path().join("db.crt");
    fs::write(&signed_path, &signed).unwrap();

    // sbverify must accept our pure-Rust signature.
    let out = Command::new("sbverify")
        .arg("--cert")
        .arg(&cert_path)
        .arg(&signed_path)
        .output()
        .expect("sbverify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() || !stdout.contains("Signature verification OK") {
        panic!("sbverify rejected our signature:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }
}

#[test]
fn sign_pe_matches_sbsign_structure() {
    // Cross-check: our signer and sbsign produce signatures that sbverify
    // accepts against the same cert — a structural equivalence check.
    // This cross-check needs openssl (to mint a key/cert for sbsign) as well as
    // sbsign/sbverify themselves.
    skip_if_missing!("sbsign", "sbverify", "openssl");
    let dir = TempDir::new();
    let efi = sample_efi(dir.path());

    // Generate a key/cert with openssl so sbsign can use it, then sign the
    // same .efi with both sbsign and our signer and verify both.
    let key_path = dir.path().join("ossl.key");
    let cert_path = dir.path().join("ossl.crt");
    let st = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .args(["-days", "365", "-nodes", "-subj", "/CN=sysimage test"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl");
    assert!(st.success(), "openssl req failed");

    let key_pem = fs::read_to_string(&key_path).unwrap();
    let cert_pem = fs::read_to_string(&cert_path).unwrap();
    let key = sysimage::secboot::x509::load_private_key_pem(&key_pem).unwrap();
    let cert_der = sysimage::secboot::x509::cert_pem_to_der(&cert_pem).unwrap();
    let (issuer, serial) = parse_issuer_and_serial(&cert_der).unwrap();

    let pe = fs::read(&efi).unwrap();

    // Our signer.
    let ours_signed = sign_pe(&pe, &cert_der, &issuer, &serial, &key).unwrap();
    let ours_path = dir.path().join("ours.efi");
    fs::write(&ours_path, &ours_signed).unwrap();

    let out = Command::new("sbverify")
        .arg("--cert")
        .arg(&cert_path)
        .arg(&ours_path)
        .output()
        .expect("sbverify");
    assert!(
        out.status.success(),
        "sbverify rejected our signature (openssl cert):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // sbsign reference, then verify with the same cert.
    let sbsign_path = dir.path().join("sbsigned.efi");
    let out = Command::new("sbsign")
        .args([
            "--key",
            &key_path.to_string_lossy(),
            "--cert",
            &cert_path.to_string_lossy(),
        ])
        .arg(&efi)
        .arg("--output")
        .arg(&sbsign_path)
        .output()
        .expect("sbsign");
    assert!(
        out.status.success(),
        "sbsign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new("sbverify")
        .arg("--cert")
        .arg(&cert_path)
        .arg(&sbsign_path)
        .output()
        .expect("sbverify");
    assert!(out.status.success(), "sbverify rejected sbsign reference");
}

#[test]
fn self_signed_cert_is_valid_x509() {
    let key = generate_rsa_key().unwrap();
    let (nb, na) = validity_strings(10);
    let cert = build_self_signed_cert(
        &key,
        "sysimage test",
        &[1, 2, 3],
        &nb,
        &na,
        CertKind::CodeSigning,
    )
    .unwrap();
    let pem = cert_to_pem(&cert);
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));

    skip_if_missing!("openssl");
    let dir = TempDir::new();
    let p = dir.path().join("cert.pem");
    fs::write(&p, &pem).unwrap();
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(&p)
        .arg("-noout")
        .arg("-subject")
        .output()
        .expect("openssl");
    assert!(
        out.status.success(),
        "openssl x509 rejected our cert: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let subj = String::from_utf8_lossy(&out.stdout);
    assert!(subj.contains("sysimage test"), "unexpected subject: {subj}");
}
