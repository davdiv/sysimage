//! Minimal DER (Distinguished Encoding Rules) TLV builder and reader.
//!
//! Hand-encoding avoids pulling in the fragile `x509-cert` builder crate. Only
//! the small subset of ASN.1 needed by Secure Boot (X.509 self-signed certs,
//! Authenticode PKCS#7 SignedData, EFI Signature Lists, authenticated
//! variables) is implemented here.

use crate::error::{Error, Result};

// --------------------------------------------------------------------------
// OID byte constants (DER-encoded, without the leading 0x06 tag/length).
// --------------------------------------------------------------------------

/// SHA-256 (2.16.840.1.101.3.4.2.1)
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// rsaEncryption (1.2.840.113549.1.1.1)
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// pkcs7-data (1.2.840.113549.1.7.1)
pub const OID_PKCS7_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// pkcs7-signedData (1.2.840.113549.1.7.2)
pub const OID_PKCS7_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// SPC Indirect Data Content (1.3.6.1.4.1.311.2.1.4)
pub const OID_SPC_INDIRECT_DATA: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
/// SPC PE Image Data (1.3.6.1.4.1.311.2.1.15)
pub const OID_SPC_PE_IMAGE_DATA: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F];
/// pkcs9-contentType (1.2.840.113549.1.9.3)
pub const OID_PKCS9_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// pkcs9-messageDigest (1.2.840.113549.1.9.4)
pub const OID_PKCS9_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// pkcs9-signingTime (1.2.840.113549.1.9.5)
pub const OID_PKCS9_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
/// commonName (2.5.4.3)
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// BasicConstraints (2.5.29.19)
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// KeyUsage (2.5.29.15)
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// SubjectKeyIdentifier (2.5.29.14)
pub const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1D, 0x0E];
/// AuthorityKeyIdentifier (2.5.29.35)
pub const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1D, 0x23];
/// ExtendedKeyUsage (2.5.29.37)
pub const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// id-kp-codeSigning (1.3.6.1.5.5.7.3.3)
pub const OID_EKU_CODE_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

// --------------------------------------------------------------------------
// Length encoding
// --------------------------------------------------------------------------

/// Encode a DER length, appending it to `out`.
pub fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut tmp = len;
        let mut bytes = Vec::new();
        while tmp > 0 {
            bytes.push((tmp & 0xff) as u8);
            tmp >>= 8;
        }
        out.push(0x80 | bytes.len() as u8);
        bytes.reverse();
        out.extend_from_slice(&bytes);
    }
}

/// Prepend a tag and the encoded length before `content`, returning a new
/// `Vec<u8>`. `content` is consumed.
pub fn tlv(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    encode_len(&mut out, content.len());
    out.extend_from_slice(&content);
    out
}

/// Explicit context tag (constructed, `[n] EXPLICIT`) wrapping `content`.
pub fn explicit(tag_num: u8, content: Vec<u8>) -> Vec<u8> {
    tlv(0xa0 | (tag_num & 0x1f), content)
}

/// Constructed implicit tag (replacing the original tag with `[n]` constructed).
pub fn implicit_constructed(tag_num: u8, content: Vec<u8>) -> Vec<u8> {
    tlv(0xa0 | (tag_num & 0x1f), content)
}

/// Primitive implicit tag (`[n]` primitive).
pub fn implicit_primitive(tag_num: u8, content: Vec<u8>) -> Vec<u8> {
    tlv(0x80 | (tag_num & 0x1f), content)
}

/// SEQUENCE (constructed, tag 0x30).
pub fn seq(content: Vec<u8>) -> Vec<u8> {
    tlv(0x30, content)
}

/// SET (constructed, tag 0x31).
pub fn set(content: Vec<u8>) -> Vec<u8> {
    tlv(0x31, content)
}

/// Append one DER element (already a complete TLV) to a content buffer.
pub fn append(content: &mut Vec<u8>, element: &[u8]) {
    content.extend_from_slice(element);
}

// --------------------------------------------------------------------------
// Primitive value encoders (return complete TLVs)
// --------------------------------------------------------------------------

pub fn oid(bytes: &[u8]) -> Vec<u8> {
    tlv(0x06, bytes.to_vec())
}

/// INTEGER from a u64. Minimal encoding, with a leading 0x00 added when the
/// high bit would be set (X.509 serials are unsigned).
pub fn integer_u64(value: u64) -> Vec<u8> {
    let mut bytes = if value == 0 {
        vec![0]
    } else {
        let mut v = value;
        let mut tmp = Vec::new();
        while v > 0 {
            tmp.push((v & 0xff) as u8);
            v >>= 8;
        }
        tmp.reverse();
        tmp
    };
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, bytes)
}

/// INTEGER from an arbitrary big-endian byte buffer. A leading 0x00 is
/// prepended if the high bit is set, keeping it non-negative.
pub fn integer_bytes_be(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if !v.is_empty() && v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, v)
}

/// NULL (tag 0x05, length 0).
pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// BOOLEAN.
pub fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, vec![if value { 0xff } else { 0x00 }])
}

/// OCTET STRING.
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes.to_vec())
}

/// BIT STRING. A leading `unused_bits` byte is inserted per DER.
pub fn bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut content = Vec::with_capacity(1 + bytes.len());
    content.push(unused_bits);
    content.extend_from_slice(bytes);
    tlv(0x03, content)
}

pub fn printable_string(s: &str) -> Vec<u8> {
    tlv(0x13, s.as_bytes().to_vec())
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes().to_vec())
}

/// BMPString (UTF-16BE). Content must already be big-endian UTF-16.
pub fn bmp_string(utf16be: &[u8]) -> Vec<u8> {
    tlv(0x1e, utf16be.to_vec())
}

/// UTCTime: `YYMMDDHHMMSSZ`.
pub fn utc_time(yymmddhhmmss: &str) -> Vec<u8> {
    tlv(0x17, yymmddhhmmss.as_bytes().to_vec())
}

/// GeneralizedTime: `YYYYMMDDHHMMSSZ`.
pub fn generalized_time(yyyymmddhhmmss: &str) -> Vec<u8> {
    tlv(0x18, yyyymmddhhmmss.as_bytes().to_vec())
}

/// AlgorithmIdentifier: `SEQUENCE { OID(sha256), NULL }`.
pub fn alg_id_sha256() -> Vec<u8> {
    let mut content = Vec::new();
    append(&mut content, &oid(OID_SHA256));
    append(&mut content, &null());
    seq(content)
}

/// AlgorithmIdentifier for rsaEncryption (with NULL params).
pub fn alg_id_rsa() -> Vec<u8> {
    let mut content = Vec::new();
    append(&mut content, &oid(OID_RSA_ENCRYPTION));
    append(&mut content, &null());
    seq(content)
}

/// AlgorithmIdentifier for sha256WithRSAEncryption (with NULL params).
pub fn alg_id_sha256_rsa() -> Vec<u8> {
    let mut content = Vec::new();
    append(&mut content, &oid(OID_SHA256_WITH_RSA));
    append(&mut content, &null());
    seq(content)
}

// --------------------------------------------------------------------------
// DER reader (cursor) — for parsing an existing cert's issuer/serial.
// --------------------------------------------------------------------------

/// A minimal DER cursor.
pub struct DerCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A read TLV: tag + raw content slice.
pub struct DerElement<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// Start offset of the whole TLV (tag byte), relative to the cursor's buffer.
    pub start: usize,
    /// End offset (exclusive) of the whole TLV, relative to the cursor's buffer.
    pub end: usize,
    /// The complete TLV bytes (tag + length + content).
    pub full: &'a [u8],
}

impl<'a> DerCursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> bool {
        self.pos < self.buf.len()
    }

    /// Read the next TLV element.
    pub fn read(&mut self) -> Result<DerElement<'a>> {
        if self.pos >= self.buf.len() {
            return Err(Error::msg("DER: unexpected end of input"));
        }
        let start = self.pos;
        let tag = self.buf[self.pos];
        self.pos += 1;
        if self.pos >= self.buf.len() {
            return Err(Error::msg("DER: truncated length"));
        }
        let first_len = self.buf[self.pos];
        self.pos += 1;
        let len = if first_len < 0x80 {
            first_len as usize
        } else {
            let n = (first_len & 0x7f) as usize;
            if n == 0 || n > 8 {
                return Err(Error::msg("DER: invalid length"));
            }
            if self.pos + n > self.buf.len() {
                return Err(Error::msg("DER: truncated multi-byte length"));
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | self.buf[self.pos] as usize;
                self.pos += 1;
            }
            l
        };
        let content_end = self.pos + len;
        if content_end > self.buf.len() {
            return Err(Error::msg("DER: content overruns buffer"));
        }
        let content = &self.buf[self.pos..content_end];
        let full = &self.buf[start..content_end];
        self.pos = content_end;
        Ok(DerElement {
            tag,
            content,
            start,
            end: content_end,
            full,
        })
    }

    /// Read a TLV and assert it has the expected tag.
    pub fn read_expect(&mut self, tag: u8) -> Result<DerElement<'a>> {
        let el = self.read()?;
        if el.tag != tag {
            return Err(Error::msg(format!(
                "DER: expected tag 0x{tag:02x}, got 0x{:02x}",
                el.tag
            )));
        }
        Ok(el)
    }

    /// Build a sub-cursor over an element's content.
    pub fn sub(el: &DerElement<'a>) -> Self {
        Self::new(el.content)
    }
}

/// Extract the full DER bytes (tag+length+content) of the issuer Name and the
/// serialNumber INTEGER from an X.509 Certificate.
///
/// Returns `(issuer_der, serial_der)` as owned TLV buffers.
pub fn parse_issuer_and_serial(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut cur = DerCursor::new(cert_der);
    let cert = cur.read_expect(0x30)?;
    // tbsCertificate ::= SEQUENCE { [0] version?, serialNumber, signature, issuer, ... }
    let mut tbs = DerCursor::sub(&cert);
    let tbs_seq = tbs.read_expect(0x30)?;
    let mut inner = DerCursor::sub(&tbs_seq);
    // Optional explicit [0] version.
    let mut el = inner.read()?;
    if el.tag == 0xa0 {
        el = inner.read()?;
    }
    // el should now be serialNumber (INTEGER 0x02).
    if el.tag != 0x02 {
        return Err(Error::msg(format!(
            "DER: expected serialNumber INTEGER, got tag 0x{:02x}",
            el.tag
        )));
    }
    let serial_der = el.full.to_vec();
    // signatureAlgorithm (SEQUENCE)
    let _sig_alg = inner.read_expect(0x30)?;
    // issuer (SEQUENCE)
    let issuer = inner.read_expect(0x30)?;
    let issuer_der = issuer.full.to_vec();
    Ok((issuer_der, serial_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_len() {
        let mut out = Vec::new();
        encode_len(&mut out, 5);
        assert_eq!(out, vec![5]);
        let mut out = Vec::new();
        encode_len(&mut out, 0x80);
        assert_eq!(out, vec![0x81, 0x80]);
        let mut out = Vec::new();
        encode_len(&mut out, 256);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn integer_encoding() {
        assert_eq!(integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(integer_u64(255), vec![0x02, 0x02, 0x00, 0xff]);
        assert_eq!(integer_u64(256), vec![0x02, 0x02, 0x01, 0x00]);
    }
}
