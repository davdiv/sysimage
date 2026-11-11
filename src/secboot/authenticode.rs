//! Authenticode signing: PE image hashing, the SPC Indirect Data Content
//! (IDC), the PKCS#7 SignedData that wraps it, and the WIN_CERTIFICATE entry
//! appended to the PE.
//!
//! The DER layout mirrors what `sbsigntools` (sbsign) produces, validated
//! against `sbverify`.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::der::{
    self, append, bit_string, explicit, implicit_constructed, integer_u64, octet_string, oid, seq,
    set,
};
use super::x509::rsa_sign_sha256;

// --------------------------------------------------------------------------
// PE image hashing
// --------------------------------------------------------------------------

/// A contiguous byte region of the PE that participates in the Authenticode
/// hash.
struct Region {
    offset: u64,
    size: u64,
}

fn u16le(buf: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        buf.get(off..off + 2)
            .ok_or_else(|| Error::msg("PE: truncated reading u16"))?
            .try_into()
            .unwrap(),
    ))
}

fn u32le(buf: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        buf.get(off..off + 4)
            .ok_or_else(|| Error::msg("PE: truncated reading u32"))?
            .try_into()
            .unwrap(),
    ))
}

/// Compute the Authenticode SHA-256 image hash of a PE/COFF binary.
///
/// This follows the Authenticode image-hashing rules used by `sbsigntools`:
/// the hash covers the whole file except the PE checksum (4 bytes), the
/// certificate-table data-directory entry (8 bytes) and any existing embedded
/// signature (the trailing `WIN_CERTIFICATE`).
pub fn pe_image_hash(pe: &[u8]) -> Result<Vec<u8>> {
    if pe.len() < 0x40 {
        return Err(Error::msg("PE: too small for DOS header"));
    }
    let e_lfanew = u32le(pe, 0x3c)? as usize;
    if e_lfanew + 24 > pe.len() {
        return Err(Error::msg("PE: e_lfanew out of range"));
    }
    if u32le(pe, e_lfanew)? != 0x0000_4550 {
        return Err(Error::msg("PE: missing PE signature"));
    }
    let file_header = e_lfanew + 4;
    let num_sections = u16le(pe, file_header + 2)? as usize;
    let size_of_opt_header = u16le(pe, file_header + 16)? as usize;
    let opt_header = e_lfanew + 24;
    if opt_header + 64 > pe.len() {
        return Err(Error::msg("PE: truncated optional header"));
    }
    let magic = u16le(pe, opt_header)?;
    let data_dir_start = match magic {
        0x10b => opt_header + 96,
        0x20b => opt_header + 112,
        _ => {
            return Err(Error::msg(format!(
                "PE: unknown optional header magic 0x{magic:04x}"
            )));
        }
    };
    // Security directory is data-dir index 4 (8 bytes each): address + size.
    let sec_dir_offset = data_dir_start + 4 * 8;
    let checksum_offset = opt_header + 64;
    let header_size = u32le(pe, opt_header + 60)? as usize;
    if sec_dir_offset + 8 > pe.len() {
        return Err(Error::msg("PE: truncated data directories"));
    }
    let cert_table_size = u32le(pe, sec_dir_offset + 4)? as usize;

    let mut regions = Vec::new();
    regions.push(Region {
        offset: 0,
        size: checksum_offset as u64,
    });
    regions.push(Region {
        offset: (checksum_offset + 4) as u64,
        size: (sec_dir_offset - (checksum_offset + 4)) as u64,
    });
    regions.push(Region {
        offset: (sec_dir_offset + 8) as u64,
        size: (header_size.saturating_sub(sec_dir_offset + 8)) as u64,
    });

    let section_table = file_header + 20 + size_of_opt_header;
    for i in 0..num_sections {
        let s = section_table + i * 40;
        if s + 40 > pe.len() {
            return Err(Error::msg("PE: truncated section header"));
        }
        let size_of_raw_data = u32le(pe, s + 16)? as u64;
        let pointer_to_raw_data = u32le(pe, s + 20)? as u64;
        if size_of_raw_data == 0 {
            continue;
        }
        regions.push(Region {
            offset: pointer_to_raw_data,
            size: size_of_raw_data,
        });
    }

    // sbsigntools sorts the checksum regions (begin->cksum, cksum->datadir,
    // datadir->headers, COFF sections) by offset before hashing.
    regions.sort_by_key(|r| r.offset);

    // `bytes` is the running byte count sbsigntools maintains: the sum of all
    // region sizes PLUS the two skipped fixed-size fields (the 4-byte PE
    // checksum and the 8-byte Security data-directory entry). For a
    // well-formed header those skips plus the three header regions exactly
    // span [0, header_size), so bytes == header_size + Σsection sizes.
    let bytes: u64 = regions.iter().map(|r| r.size).sum::<u64>() + 4 + 8;
    // sbsigntools pads the image up to an 8-byte boundary (data_size) before
    // hashing, so the messageDigest covers the trailing zero pad. Use that
    // padded length as the effective file size.
    let file_size = align_up(pe.len(), 8) as u64;
    // endjunk is appended *after* the sort, so it is always hashed last.
    if bytes + (cert_table_size as u64) < file_size {
        let endjunk = file_size - bytes - cert_table_size as u64;
        regions.push(Region {
            offset: bytes,
            size: endjunk,
        });
    }

    let mut hasher = Sha256::new();
    let real_len = pe.len() as u64;
    let zeros = [0u8; 8];
    for r in regions {
        let start = r.offset as usize;
        let end = start + r.size as usize;
        if end <= pe.len() {
            hasher.update(
                pe.get(start..end)
                    .ok_or_else(|| Error::msg("PE: hash region out of range"))?,
            );
        } else {
            // Only the trailing endjunk region can extend past the real bytes;
            // the excess is the 8-byte-alignment zero pad.
            if start < pe.len() {
                hasher.update(&pe[start..]);
            }
            let pad = end - pe.len();
            hasher.update(&zeros[..pad]);
            let _ = real_len;
        }
    }
    Ok(hasher.finalize().to_vec())
}

// --------------------------------------------------------------------------
// IDC (SPC Indirect Data Content)
// --------------------------------------------------------------------------

/// The "<<<Obsolete>>>" banner sbsign embeds, UTF-16BE.
const OBSOLETE_UTF16BE: &[u8] = &[
    0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c,
    0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e,
];

/// Build the IDC `SEQUENCE { data, digest }` and return both its full DER
/// (with outer TL — used as the encapContentInfo eContent) and its content
/// (without the outer TL — the bytes the messageDigest attribute hashes).
fn build_idc(image_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // PE image data: SEQUENCE{ OID(SPC_PE_IMAGE_DATA), PEID }
    let mut peid_content = Vec::new();
    // flags: BIT STRING(0 unused bits, empty) — `03 01 00`.
    append(&mut peid_content, &bit_string(&[], 0));
    // file: [0] EXPLICIT { [2] EXPLICIT { [0] IMPLICIT BMPSTRING } }.
    let bmp = der::bmp_string(OBSOLETE_UTF16BE);
    // [0] IMPLICIT primitive wrapping the BMP string's content bytes.
    let inner0 = der::implicit_primitive(0, bmp[2..].to_vec());
    let exp2 = explicit(2, inner0);
    let exp0 = explicit(0, exp2);
    append(&mut peid_content, &exp0);
    let peid = seq(peid_content);

    let mut data_content = Vec::new();
    append(&mut data_content, &oid(der::OID_SPC_PE_IMAGE_DATA));
    append(&mut data_content, &peid);
    let data = seq(data_content);

    // digest: SEQUENCE{ AlgId(sha256), OCTET STRING(image_hash) }
    let mut digest_content = Vec::new();
    append(&mut digest_content, &der::alg_id_sha256());
    append(&mut digest_content, &octet_string(image_hash));
    let digest = seq(digest_content);

    let mut idc_content = Vec::new();
    append(&mut idc_content, &data);
    append(&mut idc_content, &digest);
    let idc_full = seq(idc_content.clone());
    (idc_full, idc_content)
}

// --------------------------------------------------------------------------
// PKCS#7 SignedData
// --------------------------------------------------------------------------

/// Build the full PKCS#7 ContentInfo (outer `SEQUENCE{ OID(signedData), [0]
/// SignedData }`) used as the embedded PE signature.
///
/// Authenticated attributes are the minimal `{ contentType, messageDigest }`
/// pair (RFC 5652 mandates exactly those for Authenticode). The signature
/// covers the authenticated attributes encoded as a SET (tag 0x31), while the
/// stored form uses the `[0]` IMPLICIT tag (0xA0) — same content, different
/// leading tag.
pub fn build_pkcs7_content_info(
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
    priv_key: &rsa::RsaPrivateKey,
    image_hash: &[u8],
) -> Result<Vec<u8>> {
    let (idc_full, idc_content) = build_idc(image_hash);

    // messageDigest = SHA-256 of the IDC content (without its outer TL).
    let mut md_hasher = Sha256::new();
    md_hasher.update(&idc_content);
    let message_digest = md_hasher.finalize();

    // Authenticated attributes (stored + signed order): contentType, messageDigest.
    let mut auth_attrs = Vec::new();
    // contentType: SEQUENCE{ OID(pkcs9-contentType), SET{ OID(SPC_INDIRECT_DATA) } }
    let content_type_attr = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS9_CONTENT_TYPE));
        append(&mut c, &set(oid(der::OID_SPC_INDIRECT_DATA)));
        seq(c)
    };
    append(&mut auth_attrs, &content_type_attr);
    // messageDigest: SEQUENCE{ OID(pkcs9-messageDigest), SET{ OCTET STRING(digest) } }
    let message_digest_attr = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS9_MESSAGE_DIGEST));
        append(&mut c, &set(octet_string(&message_digest)));
        seq(c)
    };
    append(&mut auth_attrs, &message_digest_attr);

    // The signature is over the authenticated attributes as a SET (0x31).
    let signed_set = set(auth_attrs.clone());
    let encrypted_digest = rsa_sign_sha256(priv_key, &signed_set)?;
    // Stored form: [0] IMPLICIT CONSTRUCTED (0xA0) wrapping the same content.
    let stored_auth_attrs = implicit_constructed(0, auth_attrs);

    // encapContentInfo: SEQUENCE{ OID(SPC_INDIRECT_DATA), [0] EXPLICIT{ IDC } }
    let encap = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_SPC_INDIRECT_DATA));
        append(&mut c, &explicit(0, idc_full));
        seq(c)
    };

    // certificates: [0] IMPLICIT CertificateSet — for a single cert this is
    // `A0 <len> <full cert DER>` (the cert keeps its 0x30 SEQUENCE tag).
    let certificates = implicit_constructed(0, cert_der.to_vec());

    // SignerInfo
    let issuer_and_serial = {
        let mut c = Vec::new();
        append(&mut c, issuer_der);
        append(&mut c, serial_der);
        seq(c)
    };
    let signer_info = {
        let mut c = Vec::new();
        append(&mut c, &integer_u64(1));
        append(&mut c, &issuer_and_serial);
        append(&mut c, &der::alg_id_sha256());
        append(&mut c, &stored_auth_attrs);
        append(&mut c, &der::alg_id_rsa());
        append(&mut c, &octet_string(&encrypted_digest));
        seq(c)
    };

    // SignedData
    let signed_data = {
        let mut c = Vec::new();
        append(&mut c, &integer_u64(1)); // version
        append(&mut c, &set(der::alg_id_sha256())); // digestAlgorithms
        append(&mut c, &encap);
        append(&mut c, &certificates);
        append(&mut c, &set(signer_info)); // signerInfos
        seq(c)
    };

    // ContentInfo: SEQUENCE{ OID(pkcs7-signedData), [0] EXPLICIT{ SignedData } }
    let mut content_info = Vec::new();
    append(&mut content_info, &oid(der::OID_PKCS7_SIGNED_DATA));
    append(&mut content_info, &explicit(0, signed_data));
    Ok(seq(content_info))
}

/// Build a *detached* PKCS#7 SignedData for an EFI authenticated variable
/// (`.auth`), matching the `CertData` that `sbctl` produces (and that strict
/// firmware, e.g. OVH's, accepts).
///
/// The output is a bare `SignedData` SEQUENCE — *not* wrapped in a PKCS#7
/// `ContentInfo` (that is what `sbvarsign`'s `i2d_PKCS7_SIGNED` emits and what
/// firmware expects here). Unlike `sbvarsign`'s `PKCS7_NOATTR` signing, the
/// `SignerInfo` carries authenticated attributes in the order `contentType`,
/// `signingTime`, `messageDigest`; the RSA-PKCS1v1.5-SHA256 signature is then
/// over the DER SET of those attributes, and `messageDigest` holds the
/// SHA-256 of `external_content`.
///
/// `signing_time` is the X.509 UTCTime (`YYMMDDHHMMSSZ`) to record.
pub fn build_detached_signed_data(
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
    priv_key: &rsa::RsaPrivateKey,
    external_content: &[u8],
    signing_time: &str,
) -> Result<Vec<u8>> {
    // messageDigest = SHA-256 of the detached content.
    let mut md_hasher = Sha256::new();
    md_hasher.update(external_content);
    let message_digest = md_hasher.finalize();

    // Authenticated attributes, in the order `sbctl` emits them.
    let mut auth_attrs = Vec::new();
    // contentType: SEQUENCE{ OID(pkcs9-contentType), SET{ OID(pkcs7-data) } }
    let content_type_attr = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS9_CONTENT_TYPE));
        append(&mut c, &set(oid(der::OID_PKCS7_DATA)));
        seq(c)
    };
    append(&mut auth_attrs, &content_type_attr);
    // signingTime: SEQUENCE{ OID(pkcs9-signingTime), SET{ UTCTime } }
    let signing_time_attr = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS9_SIGNING_TIME));
        append(&mut c, &set(der::utc_time(signing_time)));
        seq(c)
    };
    append(&mut auth_attrs, &signing_time_attr);
    // messageDigest: SEQUENCE{ OID(pkcs9-messageDigest), SET{ OCTET STRING } }
    let message_digest_attr = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS9_MESSAGE_DIGEST));
        append(&mut c, &set(octet_string(&message_digest)));
        seq(c)
    };
    append(&mut auth_attrs, &message_digest_attr);

    // The signature is over the attributes as a SET (tag 0x31).
    let signed_set = set(auth_attrs.clone());
    let encrypted_digest = rsa_sign_sha256(priv_key, &signed_set)?;
    // Stored form: [0] IMPLICIT CONSTRUCTED (0xA0) wrapping the same content.
    let stored_auth_attrs = implicit_constructed(0, auth_attrs);

    // encapContentInfo: SEQUENCE{ OID(pkcs7-data) } — eContent absent (detached).
    let encap = {
        let mut c = Vec::new();
        append(&mut c, &oid(der::OID_PKCS7_DATA));
        seq(c)
    };

    let certificates = implicit_constructed(0, cert_der.to_vec());

    let issuer_and_serial = {
        let mut c = Vec::new();
        append(&mut c, issuer_der);
        append(&mut c, serial_der);
        seq(c)
    };
    let signer_info = {
        let mut c = Vec::new();
        append(&mut c, &integer_u64(1));
        append(&mut c, &issuer_and_serial);
        append(&mut c, &der::alg_id_sha256());
        append(&mut c, &stored_auth_attrs);
        append(&mut c, &der::alg_id_rsa());
        append(&mut c, &octet_string(&encrypted_digest));
        seq(c)
    };

    let signed_data = {
        let mut c = Vec::new();
        append(&mut c, &integer_u64(1));
        append(&mut c, &set(der::alg_id_sha256()));
        append(&mut c, &encap);
        append(&mut c, &certificates);
        append(&mut c, &set(signer_info));
        seq(c)
    };
    Ok(signed_data)
}

// --------------------------------------------------------------------------
// PE signing (append WIN_CERTIFICATE)
// --------------------------------------------------------------------------

fn align_up(v: usize, to: usize) -> usize {
    v.div_ceil(to) * to
}

/// Sign `pe` and return the signed binary with an appended WIN_CERTIFICATE
/// PKCS#7 entry, byte-compatible with `sbsign`.
pub fn sign_pe(
    pe: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    serial_der: &[u8],
    priv_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>> {
    let image_hash = pe_image_hash(pe)?;
    let pkcs7 = build_pkcs7_content_info(cert_der, issuer_der, serial_der, priv_key, &image_hash)?;

    // Re-derive the offsets we need to patch the Security data directory.
    let e_lfanew = u32le(pe, 0x3c)? as usize;
    let opt_header = e_lfanew + 24;
    let magic = u16le(pe, opt_header)?;
    let data_dir_start = match magic {
        0x10b => opt_header + 96,
        0x20b => opt_header + 112,
        _ => return Err(Error::msg("PE: unknown optional header magic")),
    };
    let sec_dir_offset = data_dir_start + 4 * 8;

    // data_size = 8-aligned end of the last hashed region (where the cert table
    // starts). For an unsigned PE this is the file size aligned up to 8.
    let file_size = pe.len();
    let data_size = align_up(file_size, 8);

    let tot_size = pkcs7.len() + 8;
    let aligned_size = align_up(tot_size, 8);

    let mut out = Vec::with_capacity(data_size + aligned_size);
    out.extend_from_slice(&pe[..file_size]);
    // Pad to data_size with zeros (covers the rare case where the file is not
    // already 8-aligned, and also drops any pre-existing trailing signature).
    if data_size > file_size {
        out.resize(data_size, 0);
    }
    // WIN_CERTIFICATE header: dwLength=tot_size, wRevision=0x0200, wCertificateType=0x0002.
    out.extend_from_slice(&(tot_size as u32).to_le_bytes());
    out.extend_from_slice(&0x0200u16.to_le_bytes());
    out.extend_from_slice(&0x0002u16.to_le_bytes());
    out.extend_from_slice(&pkcs7);
    // Zero-pad the cert table to the 8-aligned size.
    out.resize(data_size + aligned_size, 0);

    // Patch the Security data directory: address = data_size, size = aligned_size.
    let out_mut = out.as_mut_slice();
    out_mut[sec_dir_offset..sec_dir_offset + 4].copy_from_slice(&(data_size as u32).to_le_bytes());
    out_mut[sec_dir_offset + 4..sec_dir_offset + 8]
        .copy_from_slice(&(aligned_size as u32).to_le_bytes());

    // Zero the PE checksum (Authenticode excludes it; 0 is always acceptable).
    let checksum_offset = opt_header + 64;
    out_mut[checksum_offset..checksum_offset + 4].copy_from_slice(&[0, 0, 0, 0]);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secboot::x509::{
        CertKind, build_self_signed_cert, generate_rsa_key, validity_strings,
    };

    #[test]
    fn idc_sizes_match_reference() {
        let image_hash = [0u8; 32];
        let (idc_full, idc_content) = build_idc(&image_hash);
        // Full IDC: 30 68 <104> = 106 bytes; content (without outer TLV) = 104 bytes.
        assert_eq!(idc_full.len(), 106);
        assert_eq!(idc_content.len(), 104);
        assert_eq!(idc_full[0], 0x30);
        assert_eq!(idc_full[1], 0x68);
    }

    #[test]
    fn sign_pe_produces_valid_structure() {
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
        let (issuer, serial) = crate::secboot::x509::parse_issuer_and_serial(&cert).unwrap();

        // Sign a hermetic minimal PE fixture instead of a host-installed .efi.
        let pe = synthetic_pe();
        let signed = sign_pe(&pe, &cert, &issuer, &serial, &key).unwrap();
        assert!(signed.len() > pe.len());
        // The Security data directory should now point past the original file.
        let e_lfanew = u32le(&signed, 0x3c).unwrap() as usize;
        let opt_header = e_lfanew + 24;
        let magic = u16le(&signed, opt_header).unwrap();
        let data_dir_start = if magic == 0x10b {
            opt_header + 96
        } else {
            opt_header + 112
        };
        let sec_dir = data_dir_start + 32;
        let cert_addr = u32le(&signed, sec_dir).unwrap() as usize;
        let cert_size = u32le(&signed, sec_dir + 4).unwrap() as usize;
        assert!(cert_addr >= pe.len());
        assert!(cert_addr + cert_size <= signed.len());
    }

    /// Build a minimal, structurally-valid PE32 binary in memory — a hermetic
    /// stand-in for a real `.efi` so tests don't depend on a sample binary from
    /// outside the repository. See `tests/common/mod.rs::synthetic_pe` for the
    /// same builder used by the integration tests.
    fn synthetic_pe() -> Vec<u8> {
        const FILE_ALIGNMENT: usize = 0x200;
        const SECTION_ALIGNMENT: u32 = 0x1000;
        let payload: &[u8] = &[0xCC; 16];

        let e_lfanew: usize = 64;
        let opt_header = e_lfanew + 4 + 20; // 0x58
        let size_of_opt_header: u16 = 224;
        let section_table = opt_header + size_of_opt_header as usize; // 0x138
        let headers_unpadded = section_table + 40; // 0x160
        let size_of_headers = (headers_unpadded + FILE_ALIGNMENT - 1) & !(FILE_ALIGNMENT - 1);
        let pointer_to_raw_data = size_of_headers;
        let size_of_raw_data = (payload.len() + FILE_ALIGNMENT - 1) & !(FILE_ALIGNMENT - 1);
        let file_size = pointer_to_raw_data + size_of_raw_data;

        let mut buf = vec![0u8; file_size];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        buf[e_lfanew..e_lfanew + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

        let coff = e_lfanew + 4;
        buf[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&size_of_opt_header.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

        buf[opt_header..opt_header + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        buf[opt_header + 4..opt_header + 8]
            .copy_from_slice(&(size_of_raw_data as u32).to_le_bytes());
        buf[opt_header + 16..opt_header + 20].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        buf[opt_header + 20..opt_header + 24].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        buf[opt_header + 24..opt_header + 28].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        buf[opt_header + 28..opt_header + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_header + 32..opt_header + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        buf[opt_header + 36..opt_header + 40]
            .copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
        buf[opt_header + 56..opt_header + 60]
            .copy_from_slice(&(2 * SECTION_ALIGNMENT).to_le_bytes());
        buf[opt_header + 60..opt_header + 64]
            .copy_from_slice(&(size_of_headers as u32).to_le_bytes());
        buf[opt_header + 68..opt_header + 70].copy_from_slice(&10u16.to_le_bytes());
        buf[opt_header + 92..opt_header + 96].copy_from_slice(&16u32.to_le_bytes());

        let s = section_table;
        buf[s..s + 8].copy_from_slice(b".text\0\0\0");
        buf[s + 8..s + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        buf[s + 12..s + 16].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        buf[s + 16..s + 20].copy_from_slice(&(size_of_raw_data as u32).to_le_bytes());
        buf[s + 20..s + 24].copy_from_slice(&(pointer_to_raw_data as u32).to_le_bytes());

        buf[pointer_to_raw_data..pointer_to_raw_data + payload.len()].copy_from_slice(payload);
        buf
    }
}
