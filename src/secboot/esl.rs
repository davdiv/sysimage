//! EFI Signature Lists (`.esl`) and authenticated-variable updates (`.auth`).
//!
//! Formats follow `sbsigntools`, except for the authenticated-variable
//! signature, which follows `sbctl`: the `.auth` `CertData` is a bare PKCS#7
//! `SignedData` whose `SignerInfo` carries
//! `contentType`/`signingTime`/`messageDigest` authenticated attributes
//! (sbsigntools uses `PKCS7_NOATTR` instead).
//!
//! - An `.esl` is `EFI_SIGNATURE_LIST` (28-byte header: SignatureType GUID +
//!   SignatureListSize + SignatureHeaderSize + SignatureSize) followed by one
//!   `EFI_SIGNATURE_DATA` (SignatureOwner GUID + the x509 cert DER).
//! - An `.auth` is `EFI_VARIABLE_AUTHENTICATION_2`: a 16-byte `EFI_TIME`
//!   stamp, a `WIN_CERTIFICATE_UEFI_GUID` (8-byte WIN_CERTIFICATE header +
//!   16-byte CertType GUID + the PKCS#7 SignedData), then the variable
//!   payload (the `.esl`).

use crate::error::{Error, Result};

use super::authenticode::build_detached_signed_data;

// --------------------------------------------------------------------------
// EFI GUIDs (mixed-endian: Data1 u32 LE, Data2/Data3 u16 LE, Data4 raw 8)
// --------------------------------------------------------------------------

/// Canonical GUID strings used by UEFI Secure Boot.
pub const GUID_IMAGE_SECURITY_DATABASE: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";
pub const GUID_GLOBAL_VARIABLE: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const GUID_CERT_TYPE_PKCS7: &str = "4aafd29d-68df-49ee-8aa9-347d375665a7";
const GUID_CERT_X509: &str = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072";

/// Encode a canonical GUID string (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) as
/// the 16-byte EFI mixed-endian representation.
pub fn guid_to_bytes(canonical: &str) -> Result<[u8; 16]> {
    let hex: String = canonical.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(Error::msg(format!("invalid GUID \"{canonical}\"")));
    }
    let bytes = hex::decode(&hex).map_err(|e| Error::msg(format!("GUID hex: {e}")))?;
    let d1 = u32::from_be_bytes(bytes[0..4].try_into().unwrap()); // string is big-endian
    let d2 = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    let d3 = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&d1.to_le_bytes());
    out[4..6].copy_from_slice(&d2.to_le_bytes());
    out[6..8].copy_from_slice(&d3.to_le_bytes());
    out[8..16].copy_from_slice(&bytes[8..16]);
    Ok(out)
}

/// Generate a random v4 GUID and return it as 16 EFI bytes plus its canonical
/// string form.
pub fn random_guid() -> Result<([u8; 16], String)> {
    let mut bytes = [0u8; 16];
    use rand::Rng;
    rand::rng().fill_bytes(&mut bytes);
    // RFC 4122 v4: version 4 (high nibble of byte 6 = 0x40), variant 10 (byte 8).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let canonical = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0], // Data1 (stored LE) back to canonical BE
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    // `bytes` is already in EFI mixed-endian order (Data1 LE etc.), which is
    // exactly what we wrote above from a fresh random buffer.
    Ok((bytes, canonical))
}

// --------------------------------------------------------------------------
// EFI_TIME
// --------------------------------------------------------------------------

/// Build a 16-byte `EFI_TIME` from the current UTC moment.
pub fn efi_time_now() -> [u8; 16] {
    use chrono::{Datelike, Timelike};
    let now = chrono::Utc::now();
    let mut t = [0u8; 16];
    t[0..2].copy_from_slice(&(now.year() as u16).to_le_bytes());
    t[2] = now.month() as u8;
    t[3] = now.day() as u8;
    t[4] = now.hour() as u8;
    t[5] = now.minute() as u8;
    t[6] = now.second() as u8;
    // t[7] Pad1, t[8..12] Nanosecond, t[12..14] TimeZone, t[14] Daylight, t[15] Pad2 — all zero.
    t
}

// --------------------------------------------------------------------------
// .esl
// --------------------------------------------------------------------------

/// Default EFI variable attributes: NON_VOLATILE | BOOTSERVICE_ACCESS |
/// RUNTIME_ACCESS | TIME_BASED_AUTHENTICATED_WRITE_ACCESS (`0x27`).
///
/// This is what `sbctl` signs into its `.auth` files, and it deliberately
/// omits `APPEND_WRITE` (`0x40`, which `sbvarsign` includes): PK/KEK are set
/// (not appended), and firmware that verifies the PK signature (e.g. OVH's)
/// computes it over the exact attribute set passed to `SetVariable`, so an
/// extra `APPEND_WRITE` bit breaks verification.
pub const DEFAULT_VAR_ATTRS: u32 = 0x07 | 0x20;

/// Build an EFI Signature List containing a single x509 certificate.
pub fn build_esl(cert_der: &[u8], owner_guid: &[u8; 16]) -> Result<Vec<u8>> {
    let sig_type = guid_to_bytes(GUID_CERT_X509)?;
    let sig_size = 16 + cert_der.len() as u32;
    let list_size = 28 + sig_size; // 28-byte header + one signature data
    let mut out = Vec::with_capacity(list_size as usize);
    out.extend_from_slice(&sig_type);
    out.extend_from_slice(&list_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
    out.extend_from_slice(&sig_size.to_le_bytes());
    out.extend_from_slice(owner_guid);
    out.extend_from_slice(cert_der);
    Ok(out)
}

// --------------------------------------------------------------------------
// .auth
// --------------------------------------------------------------------------

/// Format a 16-byte `EFI_TIME` as an X.509 UTCTime string (`YYMMDDHHMMSSZ`).
///
/// The PKCS#7 `signingTime` authenticated attribute records the same instant
/// as the `EFI_VARIABLE_AUTHENTICATION_2` timestamp, matching `sbctl`.
fn efi_time_to_utc(t: &[u8; 16]) -> String {
    let year = u16::from_le_bytes([t[0], t[1]]) % 100;
    format!(
        "{year:02}{:02}{:02}{:02}{:02}{:02}Z",
        t[2], t[3], t[4], t[5], t[6]
    )
}

/// Build a full authenticated-variable update (`.auth`).
///
/// `var_name` is the EFI variable name (e.g. `"PK"`, `"KEK"`, `"db"`), encoded
/// as UTF-16LE without a NUL terminator. `var_guid` is the variable's vendor
/// GUID (16 EFI bytes). `data` is the payload (typically an `.esl`). The
/// detached PKCS#7 `messageDigest` attribute covers the concatenation
/// `var_name(UTF-16LE) || var_guid || var_attrs || timestamp || data`.
// The parameters mirror the fields of the EFI authenticated-variable update,
// so keeping them explicit is clearer than grouping them into structs.
#[allow(clippy::too_many_arguments)]
pub fn build_auth(
    var_name: &str,
    var_guid: &[u8; 16],
    var_attrs: u32,
    timestamp: &[u8; 16],
    data: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
    priv_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>> {
    // Variable name as UTF-16LE (no NUL).
    let mut var_name_utf16 = Vec::with_capacity(var_name.len() * 2);
    for c in var_name.encode_utf16() {
        var_name_utf16.extend_from_slice(&c.to_le_bytes());
    }

    // Signed data (the eContent the verifier hashes): name || guid || attrs ||
    // timestamp || data.
    let mut external = Vec::new();
    external.extend_from_slice(&var_name_utf16);
    external.extend_from_slice(var_guid);
    external.extend_from_slice(&var_attrs.to_le_bytes());
    external.extend_from_slice(timestamp);
    external.extend_from_slice(data);

    let signed_data = build_detached_signed_data(
        cert_der,
        issuer_der,
        serial_der,
        priv_key,
        &external,
        &efi_time_to_utc(timestamp),
    )?;

    let pkcs7_guid = guid_to_bytes(GUID_CERT_TYPE_PKCS7)?;
    // dwLength = SignedData + sizeof(WIN_CERTIFICATE_UEFI_GUID) = signed_data + 24.
    let dw_length = (signed_data.len() + 24) as u32;

    let mut out = Vec::new();
    // EFI_VARIABLE_AUTHENTICATION_2.TimeStamp (16 bytes).
    out.extend_from_slice(timestamp);
    // WIN_CERTIFICATE header: dwLength, wRevision=0x0200, wCertificateType=0x0EF1.
    out.extend_from_slice(&dw_length.to_le_bytes());
    out.extend_from_slice(&0x0200u16.to_le_bytes());
    out.extend_from_slice(&0x0EF1u16.to_le_bytes());
    // CertType GUID (PKCS7).
    out.extend_from_slice(&pkcs7_guid);
    // CertData = the SignedData DER.
    out.extend_from_slice(&signed_data);
    // Then the variable payload.
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip() {
        let bytes = guid_to_bytes(GUID_GLOBAL_VARIABLE).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0..4], 0x8be4df61u32.to_le_bytes());
    }

    #[test]
    fn esl_layout() {
        let cert = vec![0xAA; 100];
        let owner = [0u8; 16];
        let esl = build_esl(&cert, &owner).unwrap();
        let list_size = u32::from_le_bytes(esl[16..20].try_into().unwrap());
        let sig_size = u32::from_le_bytes(esl[24..28].try_into().unwrap());
        assert_eq!(list_size as usize, esl.len());
        assert_eq!(sig_size as usize, 16 + 100);
        assert_eq!(esl.len(), 28 + 16 + 100);
    }
}
