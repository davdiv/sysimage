//! LUKS2 container support — pure-Rust writer (format + encrypt) and reader
//! (decrypt, via the `luks-core` crate).
//!
//! This module implements the subset of the *LUKS2 On-Disk Format
//! Specification* needed to **create** a LUKS2 container that real
//! `cryptsetup` can open, and to **read** one back:
//!
//! 1. [`format_luks2`] — writes the binary header + JSON metadata + the
//!    anti-forensic keyslot material (Argon2id or PBKDF2 KDF, AES-XTS-plain64).
//! 2. [`encrypt_payload`] — encrypts a plaintext payload into the data segment
//!    with the recovered master key.
//! 3. [`open_luks2`] — unlocks an existing container with a passphrase and
//!    returns a decrypting reader (delegated to `luks-core`).
//!
//! The on-disk layout (binary header checksum, JSON structure, keyslot area
//! placement, XTS-plain64 tweak scheme) mirrors what `cryptsetup luksFormat
//! --type luks2` produces; containers written here are byte-compatible enough
//! for `cryptsetup open` to unlock them, and containers produced by cryptsetup
//! can be read back here.

use std::io::{Read, Seek, SeekFrom, Write};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes128, Aes256};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use rand::Rng;
use sha2::Digest;
use xts_mode::Xts128;

use crate::error::{Error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ===========================================================================
// Constants / on-disk layout
// ===========================================================================

/// LUKS magic signature (`"LUKS\xba\xbe"`).
const LUKS_MAGIC: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];
/// Magic of the *secondary* (backup) metadata copy (`"SKUL\xba\xbe"`): the ASCII
/// part is reversed while the trailing `0xba 0xbe` is kept, matching cryptsetup.
const LUKS_SECONDARY_MAGIC: [u8; 6] = [b'S', b'K', b'U', b'L', 0xba, 0xbe];

/// LUKS2 binary header length (first 4096 bytes of the header region).
const BIN_HDR_LEN: usize = 4096;
/// Size of the JSON metadata area that follows the binary header. Matches
/// cryptsetup's default (`config.json_size`).
const JSON_AREA_SIZE: usize = 12_288;
/// Total header size = binary header + JSON area. This is the `hdr_size` field
/// and the region covered by the header checksum.
const HDR_SIZE: u64 = (BIN_HDR_LEN + JSON_AREA_SIZE) as u64;
/// Offset of the first keyslot's AF area. cryptsetup aligns the keyslots area
/// to `2 * hdr_size`; we match so the layout is identical.
pub const FIRST_KEYSLOT_OFFSET: u64 = 32_768;
/// Sequence id written by a fresh format. `seqid` is a monotonic version counter
/// for the two metadata copies, but a container we format carries no history:
/// it always starts here rather than deriving a value from whatever happened to
/// be on the target before (`--wipe` metadata must not depend on prior content).
const INITIAL_SEQID: u64 = 1;
/// Default AF stripe count (cryptsetup's `AF_stripes`).
pub const DEFAULT_AF_STRIPES: u32 = 4000;
/// Default AF hash.
pub const DEFAULT_AF_HASH: &str = "sha256";
/// Default digest (master-key verifier): PBKDF2-HMAC-SHA256, 1000 iterations.
const DIGEST_ITERATIONS: u32 = 1000;
/// Default data-segment payload alignment (16 MiB, matching `cryptsetup
/// luksFormat`'s default `--align-payload`).
pub const DEFAULT_PAYLOAD_ALIGN: u64 = 16 * 1024 * 1024;

/// Byte offset of the header checksum field within the binary header.
const CSUM_OFFSET: usize = 448;

// ===========================================================================
// Parameters
// ===========================================================================

/// Key-derivation function parameters for a LUKS2 keyslot (no salt — the salt
/// is generated at format time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum Luks2Kdf {
    /// Argon2id (the LUKS2 default).
    #[serde(rename = "argon2id")]
    Argon2id {
        /// Time cost (iterations).
        time: u32,
        /// Memory cost in KiB.
        memory: u32,
        /// Parallelism (lanes).
        cpus: u32,
    },
    /// PBKDF2 (legacy / converted volumes).
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        /// Hash spec (`sha256`, …).
        hash: String,
        /// Iteration count.
        iterations: u32,
    },
}

impl Luks2Kdf {
    /// The cryptsetup default KDF: Argon2id.
    pub fn default_argon2id() -> Self {
        Self::Argon2id {
            time: 4,
            memory: 1_048_576,
            cpus: 4,
        }
    }
}

/// All parameters needed to format a LUKS2 container.
#[derive(Debug, Clone)]
pub struct Luks2Params {
    /// Cipher + mode, e.g. `aes-xts-plain64` (the only supported value).
    pub cipher: String,
    /// Master-key length in bytes (32 for AES-128-XTS, 64 for AES-256-XTS).
    pub key_size: u32,
    /// Encryption sector size in bytes (512 or 4096).
    pub sector_size: u32,
    /// IV tweak base added to the plain64 sector number.
    pub iv_tweak: u128,
    /// Key-derivation function for the passphrase keyslot.
    pub kdf: Luks2Kdf,
    /// Anti-forensic stripe count.
    pub af_stripes: u32,
    /// Anti-forensic hash (`sha256`).
    pub af_hash: String,
    /// Alignment of the data-segment (payload) start, in bytes.
    pub payload_align: u64,
    /// Optional container UUID (canonical string). When `None` a random
    /// v4 UUID is generated at format time.
    pub uuid: Option<String>,
}

impl Default for Luks2Params {
    fn default() -> Self {
        Self {
            cipher: "aes-xts-plain64".to_string(),
            key_size: 64,
            sector_size: 4096,
            iv_tweak: 0,
            kdf: Luks2Kdf::default_argon2id(),
            af_stripes: DEFAULT_AF_STRIPES,
            af_hash: DEFAULT_AF_HASH.to_string(),
            payload_align: DEFAULT_PAYLOAD_ALIGN,
            uuid: None,
        }
    }
}

/// Result of formatting a LUKS2 header: where the encrypted payload begins and
/// the master key used to encrypt it.
#[derive(Debug, Clone)]
pub struct Luks2FormatResult {
    /// Absolute byte offset where the data segment (encrypted payload) starts.
    pub payload_offset: u64,
    /// The recovered master key (sensitive).
    pub master_key: Vec<u8>,
    /// Encryption sector size in bytes.
    pub sector_size: u32,
    /// Cipher mode (the part after the cipher name, e.g. `xts-plain64`).
    pub cipher_mode: String,
    /// IV tweak base.
    pub iv_tweak: u128,
}

// ===========================================================================
// Writing: format the header + keyslot
// ===========================================================================

/// Format a LUKS2 container into `writer`: writes both metadata copies (the
/// primary header at offset 0 and the secondary/backup header at `hdr_size`),
/// each with its binary header, SHA-256 checksum and JSON metadata, plus the
/// encrypted anti-forensic keyslot material for `passphrase`. The data segment
/// (payload) is left untouched — encrypt plaintext into it afterwards with
/// [`encrypt_payload`].
///
/// The resulting metadata is **independent of whatever was previously on the
/// target**. Both metadata copies are rewritten with the fixed
/// [`INITIAL_SEQID`], so a stale header (e.g. a leftover `cryptsetup` backup
/// header pointing at the old keyslot) cannot survive to be preferred.
///
/// `writer` must be seekable and start at the container origin (offset 0).
pub fn format_luks2<W: Read + Write + Seek>(
    writer: &mut W,
    passphrase: &[u8],
    params: &Luks2Params,
) -> Result<Luks2FormatResult> {
    if params.cipher != "aes-xts-plain64" {
        return Err(Error::msg(format!(
            "Unsupported LUKS2 cipher \"{}\" (only aes-xts-plain64 is supported)",
            params.cipher
        )));
    }
    if !matches!(params.key_size, 32 | 64) {
        return Err(Error::msg(format!(
            "Unsupported LUKS2 key size {} (32 or 64 supported)",
            params.key_size
        )));
    }
    if !matches!(params.sector_size, 512 | 4096) {
        return Err(Error::msg(format!(
            "Unsupported LUKS2 sector size {} (512 or 4096 supported)",
            params.sector_size
        )));
    }

    let key_size = params.key_size as usize;

    // 1. Generate the master key and the per-keyslot/digest salts.
    let master_key = random_bytes(key_size);
    let kdf_salt = random_bytes(32);
    let digest_salt = random_bytes(32);
    let header_salt = random_bytes(64);
    let uuid_bytes = match &params.uuid {
        Some(u) => crate::uuid::parse_uuid(u).ok_or_else(|| {
            Error::msg(format!(
                "Invalid LUKS UUID \"{u}\" (expected a canonical UUID string)"
            ))
        })?,
        None => random_uuid_v4(),
    };

    // 2. Derive the keyslot key from the passphrase.
    let slot_key = derive_kdf(&params.kdf, passphrase, &kdf_salt, key_size)?;

    // 3. Anti-forensic split of the master key, then XTS-encrypt the keyslot
    //    area with the slot key (512-byte data units, tweak 0).
    let af_material = af_split(
        &params.af_hash,
        &master_key,
        key_size,
        params.af_stripes as usize,
    )?;
    let af_area_size = round_up(af_material.len() as u64, 4096) as usize;
    let mut af_area = vec![0u8; af_area_size];
    af_area[..af_material.len()].copy_from_slice(&af_material);
    xts_encrypt_area("xts-plain64", &slot_key, &mut af_area, 512, 0)?;

    // 4. Compute the master-key digest (PBKDF2-HMAC-SHA256).
    let digest = pbkdf2_sha256(&master_key, &digest_salt, DIGEST_ITERATIONS, 32);

    // 5. Lay out the data segment.
    let keyslot_end = FIRST_KEYSLOT_OFFSET + af_area_size as u64;
    let payload_offset = round_up(
        keyslot_end,
        params.payload_align.max(params.sector_size as u64),
    );
    let keyslots_size = payload_offset - FIRST_KEYSLOT_OFFSET;

    // 6. Build the JSON metadata (matches cryptsetup's structure).
    let json = build_json(
        key_size,
        params.af_stripes,
        &params.af_hash,
        FIRST_KEYSLOT_OFFSET,
        af_area_size as u64,
        &params.kdf,
        &kdf_salt,
        payload_offset,
        params.sector_size,
        params.iv_tweak,
        &digest_salt,
        &digest,
        keyslots_size,
    );
    let json_bytes = json.as_bytes();
    if json_bytes.len() > JSON_AREA_SIZE {
        return Err(Error::msg(format!(
            "LUKS2 JSON metadata ({} bytes) does not fit in the {}-byte JSON area",
            json_bytes.len(),
            JSON_AREA_SIZE
        )));
    }

    // 7. Build the full header region (binary header + JSON), then compute the
    //    SHA-256 checksum over it with the csum field zeroed. The `seqid` is a
    //    fixed initial value: a freshly formatted container carries no history,
    //    so its metadata does not depend on any header previously on the target.
    let mut header = vec![0u8; HDR_SIZE as usize];
    // Binary header fields (big-endian).
    header[0..6].copy_from_slice(&LUKS_MAGIC);
    header[6..8].copy_from_slice(&2u16.to_be_bytes());
    header[8..16].copy_from_slice(&HDR_SIZE.to_be_bytes());
    header[16..24].copy_from_slice(&INITIAL_SEQID.to_be_bytes());
    // label[48] at 24..72: empty
    write_cstr(&mut header[72..104], "sha256"); // csum_alg
    header[104..168].copy_from_slice(&header_salt); // salt[64]
    write_cstr(
        &mut header[168..208],
        &crate::uuid::format_uuid(&uuid_bytes),
    ); // uuid[40]
    // subsystem[48] at 208..256: empty
    header[256..264].copy_from_slice(&0u64.to_be_bytes()); // hdr_offset (primary = 0)
    // padding[184] at 264..448: zero
    // csum[32] at 448..480: zero (filled below)
    // JSON area:
    header[BIN_HDR_LEN..BIN_HDR_LEN + json_bytes.len()].copy_from_slice(json_bytes);

    let csum = sha256_with_csum_zeroed(&header);
    header[CSUM_OFFSET..CSUM_OFFSET + 32].copy_from_slice(&csum);

    // 8. Write both metadata copies. The secondary differs only in its magic
    //    (reversed ASCII) and `hdr_offset` (== hdr_size); its checksum covers
    //    those bytes, so it is rebuilt rather than copied. Together the two
    //    writes cover the whole metadata area (`2 * hdr_size`), so any header
    //    previously at either offset is replaced and the result is independent
    //    of prior content.
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(&header)?;

    let mut secondary = header.clone();
    secondary[0..6].copy_from_slice(&LUKS_SECONDARY_MAGIC);
    secondary[256..264].copy_from_slice(&HDR_SIZE.to_be_bytes());
    let csum = sha256_with_csum_zeroed(&secondary);
    secondary[CSUM_OFFSET..CSUM_OFFSET + 32].copy_from_slice(&csum);
    writer.seek(SeekFrom::Start(HDR_SIZE))?;
    writer.write_all(&secondary)?;

    // 9. Write the encrypted keyslot material. The gap between the header end
    //    and the keyslot offset stays zero (on a fresh region) or is left as
    //    the caller left it.
    writer.seek(SeekFrom::Start(FIRST_KEYSLOT_OFFSET))?;
    writer.write_all(&af_area)?;

    Ok(Luks2FormatResult {
        payload_offset,
        master_key,
        sector_size: params.sector_size,
        cipher_mode: "xts-plain64".to_string(),
        iv_tweak: params.iv_tweak,
    })
}

/// Encrypt `payload_size` bytes of plaintext from `reader` into `writer`
/// starting at `result.payload_offset`, using the master key. The plaintext is
/// read sequentially; `writer` must be seekable and start at the container
/// origin. `payload_size` is rounded up to a multiple of the sector size (the
/// tail is zero-padded) and the encrypted bytes are written in place.
pub fn encrypt_payload<W: Write + Seek, R: Read>(
    writer: &mut W,
    reader: &mut R,
    result: &Luks2FormatResult,
    payload_size: u64,
) -> Result<()> {
    let sector_size = result.sector_size as u64;
    let aligned = round_up(payload_size, sector_size);
    let step = (result.sector_size as u128 / 512).max(1);

    writer.seek(SeekFrom::Start(result.payload_offset))?;
    let mut buf = vec![0u8; sector_size as usize];
    let mut written: u64 = 0;
    let mut unit: u128 = 0;
    while written < aligned {
        // Read up to one sector; zero-fill the remainder (EOF or short reads).
        let to_read = (sector_size as usize).min((aligned - written) as usize);
        let mut filled = 0usize;
        while filled < to_read {
            match reader.read(&mut buf[filled..to_read]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::from(e)),
            }
        }
        for b in &mut buf[filled..sector_size as usize] {
            *b = 0;
        }
        let tweak = (result.iv_tweak + unit * step).to_le_bytes();
        xts_encrypt_sector(&result.cipher_mode, &result.master_key, &mut buf, &tweak)?;
        writer.write_all(&buf[..sector_size as usize])?;
        written += sector_size;
        unit += 1;
    }
    Ok(())
}

// ===========================================================================
// Reading: unlock + decrypt (delegated to luks-core)
// ===========================================================================

/// Open an existing LUKS2 (or LUKS1) container and recover the master key from
/// `passphrase`. Returns a decrypting reader over the payload.
///
/// This is a thin wrapper around `luks-core`'s `LuksVolume::unlock_with_passphrase`,
/// which auto-detects the version and verifies the key against the digest.
pub fn open_luks2<R: Read + Seek>(
    reader: R,
    passphrase: &[u8],
) -> Result<luks_core::DecryptedPayload<R>> {
    luks_core::LuksVolume::unlock_with_passphrase(reader, passphrase)
        .map_err(|e| Error::msg(format!("luks: {e}")))
}

/// Parsed LUKS2 data-segment parameters, read from an existing container's
/// JSON metadata. Used to re-encrypt a reused container's payload in place
/// (the header and keyslots are left untouched) with the recovered master key.
#[derive(Debug, Clone)]
pub struct LuksSegmentInfo {
    /// Absolute byte offset where the encrypted payload starts.
    pub payload_offset: u64,
    /// Encryption sector size in bytes (512 or 4096).
    pub sector_size: u32,
    /// Cipher mode, e.g. `xts-plain64`.
    pub cipher_mode: String,
    /// IV tweak base (plain64 sector-number base).
    pub iv_tweak: u128,
}

/// Probe `reader` for a LUKS2 header and, if present, read the first data
/// segment's parameters from the JSON metadata area.
///
/// Returns `Ok(None)` when the reader does not begin with a valid LUKS2 binary
/// header (so callers can decide to *create* a fresh container instead of
/// reusing). Returns `Ok(Some(info))` for a valid LUKS2 container.
///
/// `reader` is seeked back to the start after probing.
pub fn read_luks2_segment_info<R: Read + Seek>(reader: &mut R) -> Result<Option<LuksSegmentInfo>> {
    // Binary header: magic (6) + version (2, big-endian).
    let mut hdr = [0u8; 8];
    reader.seek(SeekFrom::Start(0))?;
    match reader.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            reader.seek(SeekFrom::Start(0))?;
            return Ok(None);
        }
        Err(e) => return Err(Error::from(e)),
    };
    if hdr[0..6] != LUKS_MAGIC {
        reader.seek(SeekFrom::Start(0))?;
        return Ok(None);
    }
    let version = u16::from_be_bytes([hdr[6], hdr[7]]);
    if version != 2 {
        reader.seek(SeekFrom::Start(0))?;
        return Ok(None);
    }

    // JSON metadata area starts right after the 4096-byte binary header.
    let mut json_buf = vec![0u8; JSON_AREA_SIZE];
    reader.seek(SeekFrom::Start(BIN_HDR_LEN as u64))?;
    let read = read_until_nul(reader, &mut json_buf)?;
    let json_bytes = &json_buf[..read];
    let value: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| Error::msg(format!("luks2: invalid JSON metadata: {e}")))?;

    let segments = value
        .get("segments")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Error::msg("luks2: JSON metadata has no 'segments'"))?;
    // Segment "0" is the single data segment for containers we create.
    let seg = segments
        .get("0")
        .ok_or_else(|| Error::msg("luks2: JSON metadata has no segment '0'"))?;

    let offset_str = seg
        .get("offset")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("luks2: segment '0' has no 'offset'"))?;
    let payload_offset: u64 = offset_str
        .parse()
        .map_err(|_| Error::msg(format!("luks2: invalid segment offset \"{offset_str}\"")))?;

    let iv_tweak_str = seg
        .get("iv_tweak")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::msg("luks2: segment '0' has no 'iv_tweak'"))?;
    let iv_tweak: u128 = iv_tweak_str
        .parse()
        .map_err(|_| Error::msg(format!("luks2: invalid iv_tweak \"{iv_tweak_str}\"")))?;

    let sector_size = seg
        .get("sector_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(512) as u32;

    let encryption = seg
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("aes-xts-plain64")
        .to_string();
    // The on-disk `encryption` is the full "cipher-mode" string (e.g.
    // "aes-xts-plain64"); the re-encrypt path wants only the mode part
    // ("xts-plain64"), matching what `format_luks2` records.
    let cipher_mode = encryption
        .split_once('-')
        .map(|(_, mode)| mode.to_string())
        .unwrap_or(encryption);

    reader.seek(SeekFrom::Start(0))?;
    Ok(Some(LuksSegmentInfo {
        payload_offset,
        sector_size,
        cipher_mode,
        iv_tweak,
    }))
}

/// Read from `reader` into `buf` until a NUL byte is encountered or the buffer
/// is full, returning the number of bytes read (excluding the NUL). The NUL
/// (if hit) is consumed.
fn read_until_nul<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut one = [0u8; 1];
        match reader.read(&mut one)? {
            0 => break,
            _ => {
                if one[0] == 0 {
                    break;
                }
                buf[filled] = one[0];
                filled += 1;
            }
        }
    }
    Ok(filled)
}

// ===========================================================================
// Internals: KDF, AF split, XTS, JSON, checksum
// ===========================================================================

fn derive_kdf(kdf: &Luks2Kdf, passphrase: &[u8], salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    match kdf {
        Luks2Kdf::Argon2id { time, memory, cpus } => {
            let params = Params::new(*memory, *time, *cpus, Some(key_len))
                .map_err(|e| Error::msg(format!("argon2 params: {e}")))?;
            let mut out = vec![0u8; key_len];
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(passphrase, salt, &mut out)
                .map_err(|e| Error::msg(format!("argon2: {e}")))?;
            Ok(out)
        }
        Luks2Kdf::Pbkdf2 { hash, iterations } => {
            pbkdf2(hash, passphrase, salt, *iterations, key_len)
        }
    }
}

fn pbkdf2(hash: &str, pw: &[u8], salt: &[u8], iterations: u32, len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    let iters = iterations.max(1);
    match hash {
        "sha1" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw, salt, iters, &mut out),
        "sha256" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, iters, &mut out),
        "sha512" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw, salt, iters, &mut out),
        other => return Err(Error::msg(format!("Unsupported PBKDF2 hash \"{other}\""))),
    }
    Ok(out)
}

fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, iterations.max(1), &mut out);
    out
}

/// Anti-forensic split: the inverse of `luks_core::af_merge`. Produces
/// `stripes * block_size` bytes (the master key scattered across `stripes`
/// blocks so that erasing any block destroys it).
fn af_split(hash: &str, master: &[u8], block_size: usize, stripes: usize) -> Result<Vec<u8>> {
    if stripes == 0 {
        return Err(Error::msg("AF stripes must be > 0"));
    }
    // Random filler for the first stripes-1 blocks.
    let mut material = random_bytes(block_size * stripes);
    let mut acc = vec![0u8; block_size];
    for i in 0..stripes - 1 {
        let start = i * block_size;
        xor_into(&mut acc, &material[start..start + block_size]);
        acc = diffuse(hash, &acc)?;
    }
    let last = (stripes - 1) * block_size;
    for (j, b) in acc.iter().enumerate() {
        material[last + j] = master[j] ^ b;
    }
    Ok(material)
}

fn diffuse(hash: &str, data: &[u8]) -> Result<Vec<u8>> {
    match hash {
        "sha1" => Ok(diffuse_generic::<sha1::Sha1>(data)),
        "sha256" => Ok(diffuse_generic::<sha2::Sha256>(data)),
        "sha512" => Ok(diffuse_generic::<sha2::Sha512>(data)),
        other => Err(Error::msg(format!("Unsupported AF hash \"{other}\""))),
    }
}

fn diffuse_generic<D: Digest>(data: &[u8]) -> Vec<u8> {
    let digest_size = <D as Digest>::output_size();
    let mut out = vec![0u8; data.len()];
    let mut i = 0u32;
    let mut offset = 0usize;
    while offset < data.len() {
        let take = digest_size.min(data.len() - offset);
        let mut hasher = D::new();
        hasher.update(i.to_be_bytes());
        hasher.update(&data[offset..offset + take]);
        let h = hasher.finalize();
        out[offset..offset + take].copy_from_slice(&h[..take]);
        offset += take;
        i += 1;
    }
    out
}

fn xor_into(acc: &mut [u8], other: &[u8]) {
    for (a, b) in acc.iter_mut().zip(other) {
        *a ^= b;
    }
}

/// XTS-encrypt `buffer` in place, split into `unit_size`-byte data units. Data
/// unit `u` uses the plain64 tweak `base_sector + u * (unit_size/512)` — the
/// 512-sector number of the unit's first byte, matching dm-crypt's default
/// (non-`iv_large_sectors`) IV even for 4096-byte sectors. This is the encrypt
/// inverse of `luks_core::crypto::xts_decrypt_area`.
fn xts_encrypt_area(
    cipher_mode: &str,
    key: &[u8],
    buffer: &mut [u8],
    unit_size: usize,
    base_sector: u128,
) -> Result<()> {
    if cipher_mode != "xts-plain64" {
        return Err(Error::msg(format!(
            "Unsupported cipher mode \"{cipher_mode}\""
        )));
    }
    let step = (unit_size / 512).max(1) as u128;
    match key.len() {
        32 => {
            let (k1, k2) = key.split_at(16);
            let xts = Xts128::<Aes128>::new(
                Aes128::new(&k1.try_into().unwrap()),
                Aes128::new(&k2.try_into().unwrap()),
            );
            encrypt_units(&xts, buffer, unit_size, base_sector, step);
        }
        64 => {
            let (k1, k2) = key.split_at(32);
            let xts = Xts128::<Aes256>::new(
                Aes256::new(&k1.try_into().unwrap()),
                Aes256::new(&k2.try_into().unwrap()),
            );
            encrypt_units(&xts, buffer, unit_size, base_sector, step);
        }
        n => {
            return Err(Error::msg(format!(
                "Unsupported XTS key size ({n} bytes; 32 or 64 supported)"
            )));
        }
    }
    Ok(())
}

pub(crate) fn xts_encrypt_sector(
    cipher_mode: &str,
    key: &[u8],
    buffer: &mut [u8],
    tweak: &[u8; 16],
) -> Result<()> {
    if cipher_mode != "xts-plain64" {
        return Err(Error::msg(format!(
            "Unsupported cipher mode \"{cipher_mode}\""
        )));
    }
    if buffer.len() < 16 {
        return Err(Error::msg("XTS sector smaller than one block (16 bytes)"));
    }
    match key.len() {
        32 => {
            let (k1, k2) = key.split_at(16);
            let xts = Xts128::<Aes128>::new(
                Aes128::new(&k1.try_into().unwrap()),
                Aes128::new(&k2.try_into().unwrap()),
            );
            xts.encrypt_sector(buffer, (*tweak).into());
        }
        64 => {
            let (k1, k2) = key.split_at(32);
            let xts = Xts128::<Aes256>::new(
                Aes256::new(&k1.try_into().unwrap()),
                Aes256::new(&k2.try_into().unwrap()),
            );
            xts.encrypt_sector(buffer, (*tweak).into());
        }
        n => {
            return Err(Error::msg(format!(
                "Unsupported XTS key size ({n} bytes; 32 or 64 supported)"
            )));
        }
    }
    Ok(())
}

pub(crate) fn xts_decrypt_sector(
    cipher_mode: &str,
    key: &[u8],
    buffer: &mut [u8],
    tweak: &[u8; 16],
) -> Result<()> {
    if cipher_mode != "xts-plain64" {
        return Err(Error::msg(format!(
            "Unsupported cipher mode \"{cipher_mode}\""
        )));
    }
    if buffer.len() < 16 {
        return Err(Error::msg("XTS sector smaller than one block (16 bytes)"));
    }
    match key.len() {
        32 => {
            let (k1, k2) = key.split_at(16);
            let xts = Xts128::<Aes128>::new(
                Aes128::new(&k1.try_into().unwrap()),
                Aes128::new(&k2.try_into().unwrap()),
            );
            xts.decrypt_sector(buffer, (*tweak).into());
        }
        64 => {
            let (k1, k2) = key.split_at(32);
            let xts = Xts128::<Aes256>::new(
                Aes256::new(&k1.try_into().unwrap()),
                Aes256::new(&k2.try_into().unwrap()),
            );
            xts.decrypt_sector(buffer, (*tweak).into());
        }
        n => {
            return Err(Error::msg(format!(
                "Unsupported XTS key size ({n} bytes; 32 or 64 supported)"
            )));
        }
    }
    Ok(())
}

fn encrypt_units<C>(xts: &Xts128<C>, buffer: &mut [u8], unit_size: usize, base: u128, step: u128)
where
    C: BlockCipherEncrypt
        + BlockCipherDecrypt
        + BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    for (u, chunk) in buffer.chunks_mut(unit_size).enumerate() {
        if chunk.len() < 16 {
            continue;
        }
        let tweak = (base + u as u128 * step).to_le_bytes();
        xts.encrypt_sector(chunk, tweak.into());
    }
}

/// Build the LUKS2 JSON metadata document, matching cryptsetup's structure.
#[allow(clippy::too_many_arguments)]
fn build_json(
    key_size: usize,
    af_stripes: u32,
    af_hash: &str,
    area_offset: u64,
    area_size: u64,
    kdf: &Luks2Kdf,
    kdf_salt: &[u8],
    payload_offset: u64,
    sector_size: u32,
    iv_tweak: u128,
    digest_salt: &[u8],
    digest: &[u8],
    keyslots_size: u64,
) -> String {
    use serde_json::json;
    let b64 = base64::engine::general_purpose::STANDARD;

    let kdf_obj = match kdf {
        Luks2Kdf::Argon2id { time, memory, cpus } => json!({
            "type": "argon2id",
            "time": time,
            "memory": memory,
            "cpus": cpus,
            "salt": b64.encode(kdf_salt),
        }),
        Luks2Kdf::Pbkdf2 { hash, iterations } => json!({
            "type": "pbkdf2",
            "hash": hash,
            "iterations": iterations,
            "salt": b64.encode(kdf_salt),
        }),
    };

    let root = json!({
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": key_size,
                "af": {
                    "type": "luks1",
                    "stripes": af_stripes,
                    "hash": af_hash,
                },
                "area": {
                    "type": "raw",
                    "offset": area_offset.to_string(),
                    "size": area_size.to_string(),
                    "encryption": "aes-xts-plain64",
                    "key_size": key_size,
                },
                "kdf": kdf_obj,
            },
        },
        "tokens": {},
        "segments": {
            "0": {
                "type": "crypt",
                "offset": payload_offset.to_string(),
                "size": "dynamic",
                "iv_tweak": iv_tweak.to_string(),
                "encryption": "aes-xts-plain64",
                "sector_size": sector_size,
            },
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": DIGEST_ITERATIONS,
                "salt": b64.encode(digest_salt),
                "digest": b64.encode(digest),
            },
        },
        "config": {
            "json_size": JSON_AREA_SIZE.to_string(),
            "keyslots_size": keyslots_size.to_string(),
        },
    });

    // serde_json serializes with the insertion order of `serde_json::Map` (which
    // preserves insertion order when the `preserve_order` feature is *not* on —
    // it uses BTreeMap, i.e. alphabetical). Field order is irrelevant to both
    // cryptsetup and luks-core; the checksum is computed over these exact bytes.
    serde_json::to_string(&root).expect("serializing LUKS2 JSON")
}

/// SHA-256 over `header` with the csum field (`[CSUM_OFFSET, CSUM_OFFSET+32)`)
/// zeroed — cryptsetup's header checksum.
fn sha256_with_csum_zeroed(header: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(&header[..CSUM_OFFSET]);
    hasher.update([0u8; 32]);
    let after = CSUM_OFFSET + 32;
    if after < header.len() {
        hasher.update(&header[after..]);
    }
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

fn write_cstr(buf: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(buf.len());
    buf[..n].copy_from_slice(&b[..n]);
}

fn round_up(v: u64, align: u64) -> u64 {
    if align == 0 {
        return v;
    }
    let r = v % align;
    if r == 0 { v } else { v + (align - r) }
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand::Rng;
    let mut out = vec![0u8; n];
    rand::rng().fill_bytes(&mut out);
    out
}

/// A random RFC-4122 version-4 UUID (16 raw bytes, string order).
fn random_uuid_v4() -> [u8; 16] {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    // Set version (4) and variant (10xx).
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Formatting must not let prior on-disk metadata leak into the result: both
    /// copies are fully rewritten with a fixed initial `seqid`, regardless of
    /// what was there before. (Two different prior seqids are used to show the
    /// output does not depend on them.)
    #[test]
    fn reformat_is_independent_of_prior_metadata() {
        let params = Luks2Params {
            kdf: Luks2Kdf::Pbkdf2 {
                hash: "sha256".to_string(),
                iterations: 1000,
            },
            sector_size: 512,
            payload_align: 512,
            ..Default::default()
        };

        for prior_seqid in [7u64, 999] {
            // Pre-fill both metadata slots with a "stale" header carrying a high
            // seqid, plus a sentinel byte everywhere the new header writes
            // structural zeros, as a previous cryptsetup format would leave.
            let mut img = vec![0u8; HDR_SIZE as usize * 2 + 64 * 1024];
            for (off, magic) in [(0u64, LUKS_MAGIC), (HDR_SIZE, LUKS_SECONDARY_MAGIC)] {
                let o = off as usize;
                img[o..o + 6].copy_from_slice(&magic);
                img[o + 6..o + 8].copy_from_slice(&2u16.to_be_bytes());
                img[o + 8..o + 16].copy_from_slice(&HDR_SIZE.to_be_bytes());
                img[o + 16..o + 24].copy_from_slice(&prior_seqid.to_be_bytes());
                for b in &mut img[o + 24..o + HDR_SIZE as usize] {
                    *b = 0xab;
                }
            }

            let mut cursor = Cursor::new(img);
            format_luks2(&mut cursor, b"newpass", &params).unwrap();
            let img = cursor.into_inner();
            let sec = HDR_SIZE as usize;

            // Both copies are ours, with the fixed initial seqid — the prior
            // seqid had no effect.
            assert_eq!(&img[0..6], &LUKS_MAGIC);
            assert_eq!(&img[sec..sec + 6], &LUKS_SECONDARY_MAGIC);
            for off in [0usize, sec] {
                assert_eq!(
                    u64::from_be_bytes(img[off + 16..off + 24].try_into().unwrap()),
                    INITIAL_SEQID,
                    "prior seqid {prior_seqid} leaked into the new header at {off}",
                );
                assert_eq!(
                    u64::from_be_bytes(img[off + 256..off + 264].try_into().unwrap()),
                    if off == 0 { 0 } else { HDR_SIZE },
                    "hdr_offset at {off}",
                );
                // No sentinel filler survives where the header writes zeros
                // (label[48] at 24..72 and subsystem[48] at 208..256).
                assert!(img[off + 24..off + 72].iter().all(|&b| b == 0));
                assert!(img[off + 208..off + 256].iter().all(|&b| b == 0));
                // The stored checksum must match the (recomputed) header contents.
                let hdr = &img[off..off + HDR_SIZE as usize];
                let expected = sha256_with_csum_zeroed(hdr);
                assert_eq!(&hdr[CSUM_OFFSET..CSUM_OFFSET + 32], &expected[..]);
            }

            // The container still unlocks (our reader uses the primary).
            assert!(open_luks2(Cursor::new(&img), b"newpass").is_ok());
        }
    }

    /// Format a tiny container in memory and round-trip it through luks-core.
    #[test]
    fn format_then_open_roundtrips_via_luks_core() {
        let params = Luks2Params {
            kdf: Luks2Kdf::Pbkdf2 {
                hash: "sha256".to_string(),
                iterations: 1000,
            },
            sector_size: 512,
            payload_align: 512,
            ..Default::default()
        };
        let mut img = Cursor::new(Vec::new());
        let res = format_luks2(&mut img, b"pw", &params).unwrap();
        // Some plaintext payload.
        let plain: Vec<u8> = (0..8192u32).map(|i| (i as u8).wrapping_mul(7)).collect();
        let mut r = Cursor::new(plain.clone());
        encrypt_payload(&mut img, &mut r, &res, plain.len() as u64).unwrap();

        let img = img.into_inner();
        let mut vol = open_luks2(Cursor::new(&img), b"pw").unwrap();
        assert_eq!(vol.info().version, 2);
        assert_eq!(vol.info().cipher_mode, "xts-plain64");
        assert_eq!(vol.info().key_bytes, 64);
        assert_eq!(vol.info().sector_size, 512);
        let mut got = vec![0u8; plain.len()];
        vol.read_at(0, &mut got).unwrap();
        assert_eq!(got, plain);
    }

    /// A wrong passphrase must fail to unlock.
    #[test]
    fn wrong_passphrase_fails() {
        let params = Luks2Params {
            kdf: Luks2Kdf::Pbkdf2 {
                hash: "sha256".to_string(),
                iterations: 1000,
            },
            sector_size: 512,
            payload_align: 512,
            ..Default::default()
        };
        let mut img = Cursor::new(Vec::new());
        format_luks2(&mut img, b"pw", &params).unwrap();
        let img = img.into_inner();
        assert!(open_luks2(Cursor::new(&img), b"wrong").is_err());
    }
}
