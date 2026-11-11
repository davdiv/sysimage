//! Generic block-device region used by the install pipeline.
//!
//! [`BlockFile`] is the sysimage-internal abstraction over "a contiguous
//! `[base, base + size)` byte range that we install something into". Today
//! it is backed by a local `std::fs::File` (a disk image, a `/dev` block node,
//! or a sub-region of either), but it is deliberately trait-shaped: a future
//! NBD / remote backing store can expose the same region interface without
//! the install code changing.
//!
//! A single `BlockFile` exposes two complementary views of the same region:
//!
//! * [`fs_ext4::block_io::BlockDevice`] — offset-based (`read_at` / `write_at`
//!   / `size_bytes`), `&self`, used by the ext4 mkfs/mount path.
//! * [`std::io::Read`] + [`Write`] + [`Seek`] — cursor-based, `&mut self`,
//!   used by the GPT writer, the FAT formatter, and raw image copies.
//!
//! Sub-regions (GPT partitions, LVM logical volumes, …) are obtained via
//! [`BlockFile::open_region`]; they share the underlying file handle so they
//! stay cheap and never copy bytes around — which is what lets the install
//! functions format a filesystem directly into a partition region instead of
//! staging it in a standalone temp image first.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use fs_ext4::block_io::BlockDevice;
use fs_ext4::error::{Error as Ext4Error, Result as Ext4Result};

/// A writable view of the byte range `[base, base + size)` of a backing file.
///
/// Cloning is cheap: the underlying file is shared via an `Arc<Mutex<File>>`.
/// [`BlockFile::open_region`] likewise shares the file and just shifts the
/// window, so descending the block tree (disk → partition → LV → …) allocates
/// no extra storage and performs no byte copies.
pub struct BlockFile {
    file: Arc<Mutex<File>>,
    base: u64,
    size: u64,
    /// Cursor for the `Read`/`Write`/`Seek` view, relative to `base`.
    cursor: u64,
}

impl BlockFile {
    /// Open `path` read/write and expose `[base, base + size)`.
    pub fn open(path: &Path, base: u64, size: u64) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            base,
            size,
            cursor: 0,
        })
    }

    /// Wrap an already-open file (used by tests).
    pub fn from_file(file: File, base: u64, size: u64) -> Self {
        Self {
            file: Arc::new(Mutex::new(file)),
            base,
            size,
            cursor: 0,
        }
    }

    /// Absolute byte offset of the start of this region within the backing file.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Return a fresh view of the sub-range `[offset, offset + size)` of this
    /// region. Shares the backing file; the new view starts at cursor 0.
    pub fn open_region(&self, offset: u64, size: u64) -> Self {
        let end = offset.checked_add(size);
        assert!(
            end.is_some_and(|e| e <= self.size),
            "open_region([{offset}, {offset}+{size})) is out of bounds for region of size {}",
            self.size,
        );
        Self {
            file: Arc::clone(&self.file),
            base: self.base + offset,
            size,
            cursor: 0,
        }
    }

    /// Synchronize the backing file to stable storage.
    pub fn sync(&self) -> io::Result<()> {
        let mut f = self.file.lock().unwrap();
        f.flush()?;
        f.sync_data()?;
        Ok(())
    }

    fn clamp_cursor(&self, pos: u64) -> u64 {
        pos.min(self.size)
    }
}

impl Clone for BlockFile {
    fn clone(&self) -> Self {
        // A fresh clone starts at cursor 0; the backing file is shared.
        Self {
            file: Arc::clone(&self.file),
            base: self.base,
            size: self.size,
            cursor: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor-based view (std::io) — GPT writer, FAT formatter, raw copies.
// All positions are relative to the start of this region (`base`).
// ---------------------------------------------------------------------------

impl Read for BlockFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.size {
            return Ok(0);
        }
        let remaining = (self.size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(self.base + self.cursor))?;
        let n = f.read(&mut buf[..to_read])?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for BlockFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.size.saturating_sub(self.cursor) as usize;
        let to_write = buf.len().min(remaining);
        if to_write == 0 {
            return Ok(0);
        }
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(self.base + self.cursor))?;
        let n = f.write(&buf[..to_write])?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().unwrap().flush()
    }
}

impl Seek for BlockFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(d) => self.cursor as i64 + d,
            SeekFrom::End(d) => self.size as i64 + d,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }
        self.cursor = self.clamp_cursor(new as u64);
        Ok(self.cursor)
    }
}

// ---------------------------------------------------------------------------
// Offset-based view (fs_ext4 BlockDevice) — ext4 mkfs + mount.
// Offsets are relative to the start of this region (`base`).
// ---------------------------------------------------------------------------

impl BlockDevice for BlockFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(self.base + offset))?;
        f.read_exact(buf)?;
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(self.base + offset))?;
        f.write_all(buf)?;
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn flush(&self) -> Ext4Result<()> {
        let mut f = self.file.lock().unwrap();
        f.flush()?;
        f.sync_data()?;
        Ok(())
    }

    fn is_writable(&self) -> bool {
        true
    }
}

/// A generic, installable block region — the trait the install pipeline is
/// generic over.
///
/// A region represents the contiguous byte range that some block (a whole
/// disk, a GPT partition, an LVM logical volume, …) is installed into. Today
/// only [`BlockFile`] (a local file / block device / sub-region) implements
/// it, but the design is shaped so that a future NBD / remote backing store
/// can implement it the same way and be installed through the identical
/// pipeline — no install code changes required.
///
/// A region is usable two ways at once:
///
/// * as an offset-based block device (ext4 mkfs/mount), via the
///   [`fs_ext4::block_io::BlockDevice`] supertrait;
/// * as a cursor-based stream (the GPT writer and the FAT formatter take
///   `Read + Write + Seek`), via the `std::io` supertraits.
///
/// Sub-regions are produced by [`BlockRegion::open_region`]; they share the
/// backing store so descending the block tree allocates no extra storage.
pub trait BlockRegion:
    fs_ext4::block_io::BlockDevice
    + std::io::Read
    + std::io::Write
    + std::io::Seek
    + Clone
    + Send
    + Sync
    + 'static
{
    /// A fresh view of the sub-range `[offset, offset + size)` of this region.
    fn open_region(&self, offset: u64, size: u64) -> Self;

    /// Size of this region in bytes.
    fn region_size(&self) -> u64;

    /// Absolute byte offset of the region's start within the backing store
    /// (used only to reject nested GPTs, which install at the store origin).
    fn region_base(&self) -> u64;

    /// Flush the region to stable storage.
    fn sync_region(&self) -> std::io::Result<()>;

    /// Write a run of chunks at the current cursor, advancing it by their total
    /// length, and return only once they are on the backing store.
    ///
    /// The default writes the chunks one at a time via [`std::io::Write`].
    /// Backends that pay a per-request round-trip (a remote [`crate::nbd::NbdRegion`])
    /// override this to send the requests back-to-back before waiting for any
    /// reply, overlapping the link latency. Chunks are disjoint sequential
    /// ranges in the order given.
    fn write_chunks(&mut self, chunks: &[&[u8]]) -> std::io::Result<()> {
        for &chunk in chunks {
            self.write_all(chunk)?;
        }
        Ok(())
    }

    /// Like [`Self::write_chunks`], but invoke `on_written` with each chunk's
    /// length once it is durably accepted, so a caller's progress bar advances
    /// as data lands rather than in one jump per batch.
    ///
    /// The default writes the whole run and then reports the total once.
    /// Backends that complete chunks independently — notably a remote
    /// [`crate::nbd::NbdRegion`], whose pipelined replies arrive per chunk —
    /// override this to report each chunk as its reply arrives.
    fn write_chunks_progress(
        &mut self,
        chunks: &[&[u8]],
        on_written: &mut dyn FnMut(u64),
    ) -> std::io::Result<()> {
        self.write_chunks(chunks)?;
        on_written(chunks.iter().map(|c| c.len() as u64).sum());
        Ok(())
    }

    /// Best-effort SHA-256 of the first `size` bytes of this region.
    ///
    /// This powers the `image`-block fast path in the install pipeline: when
    /// the target region already contains the expected bytes, the (potentially
    /// large) copy is skipped. Returns `Ok(None)` when computing the digest
    /// would be at least as expensive as copying — notably for a remote NBD
    /// export reached over a plain `nbd://` URL, where hashing would transfer
    /// the whole region over the network and gain nothing. Returns
    /// `Ok(Some(digest))` when the bytes live on the same machine as the
    /// caller (a local file/device) and can be hashed cheaply, or when a
    /// remote backend supplies a side channel to hash on the device's host
    /// (e.g. `ssh-install` running `sha256sum` over SSH, so only the 32-byte
    /// digest crosses the network).
    ///
    /// The default returns `Ok(None)` (no cheap digest available); local
    /// backends override it to hash in place.
    fn region_digest(&self, _size: u64) -> std::io::Result<Option<[u8; 32]>> {
        Ok(None)
    }
}

impl BlockRegion for BlockFile {
    fn open_region(&self, offset: u64, size: u64) -> Self {
        BlockFile::open_region(self, offset, size)
    }
    fn region_size(&self) -> u64 {
        self.size()
    }
    fn region_base(&self) -> u64 {
        self.base()
    }
    fn sync_region(&self) -> std::io::Result<()> {
        self.sync()
    }

    fn region_digest(&self, size: u64) -> std::io::Result<Option<[u8; 32]>> {
        // The bytes live on the same machine as the caller, so hashing the
        // region in place is cheap relative to rewriting it — and lets the
        // image-block fast path skip the copy when the content is unchanged.
        let size = size.min(self.size);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut off = 0u64;
        while off < size {
            let n = (size - off).min(buf.len() as u64) as usize;
            self.read_at(off, &mut buf[..n])
                .map_err(|e| io::Error::other(e.to_string()))?;
            hasher.update(&buf[..n]);
            off += n as u64;
        }
        Ok(Some(hasher.finalize().into()))
    }
}

// ===========================================================================
// LuksRegion — a transparent decrypting/encrypting view over a LUKS2 data
// segment. Implements [`BlockRegion`], so the install pipeline can format /
// populate a filesystem (or GPT, LVM, …) *directly* into an encrypted
// partition region instead of decrypting the whole payload to a temp file and
// re-encrypting it afterwards.
// ===========================================================================

/// A transparent decrypting/encrypting view over a LUKS2 data segment.
///
/// Wraps a *type-erased* encrypted backing block device ([`Arc<dyn BlockDevice>`])
/// that holds the LUKS2 container (header + keyslots + data segment) and
/// exposes the *plaintext* payload as a [`BlockRegion`]. Reads XTS-decrypt
/// sectors on demand; writes XTS-encrypt on demand, with read-modify-write for
/// sub-sector writes. No plaintext is ever materialized on disk — only the
/// single in-flight sector buffer lives in memory.
///
/// `LuksRegion` is deliberately **non-generic**: the encrypted backing is kept
/// behind `dyn BlockDevice` (which is object-safe) rather than a type
/// parameter. This is what lets LUKS nest (LUKS inside LUKS, LUKS inside a
/// partition inside LUKS, …) without the install pipeline monomorphizing into
/// infinitely many region types — every nesting level erases back to the same
/// concrete `LuksRegion`, so the recursive `Plan`/`install_block_fresh` types
/// reach a fixed point and terminate.
///
/// This matches how dm-crypt works at runtime: every block read is decrypted,
/// every block written is encrypted, and blocks that are never touched stay
/// in their on-disk (encrypted) form. For a freshly created container the
/// untouched data-segment bytes are sparse zeros — exactly what real
/// `cryptsetup` leaves behind — so the resulting image is byte-compatible with
/// a container produced and mounted by `cryptsetup`.
pub struct LuksRegion {
    /// The encrypted backing block device (header + keyslots + data segment).
    /// Shared cheaply across clones via `Arc`. May itself be a `LuksRegion`
    /// (nested encryption) — erased here so nesting does not grow the type.
    backing: Arc<dyn BlockDevice>,
    /// Absolute byte offset of the data segment within the backing device.
    payload_offset: u64,
    /// Logical byte offset of this view within the payload (for `open_region`).
    logical_base: u64,
    /// Plaintext size of this view (≤ the payload size).
    size: u64,
    /// The recovered master key (shared across clones).
    master_key: Arc<Vec<u8>>,
    /// Encryption sector size in bytes (512 or 4096).
    sector_size: u32,
    /// Cipher mode (`xts-plain64`).
    cipher_mode: String,
    /// IV tweak base (plain64 sector-number base).
    iv_tweak: u128,
    /// Cursor for the `Read`/`Write`/`Seek` view, relative to `logical_base`.
    cursor: u64,
}

impl LuksRegion {
    /// Build a decrypting/encrypting view of the whole data segment.
    ///
    /// `backing` is the block device holding the LUKS2 container (its first
    /// bytes are the LUKS2 header). `payload_offset` is where the data segment
    /// begins (absolute, within `backing`), and `payload_size` is the plaintext
    /// size to expose (usually `backing.size_bytes() - payload_offset`,
    /// sector-aligned).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backing: Arc<dyn BlockDevice>,
        payload_offset: u64,
        payload_size: u64,
        master_key: Vec<u8>,
        sector_size: u32,
        cipher_mode: String,
        iv_tweak: u128,
    ) -> Self {
        Self {
            backing,
            payload_offset,
            logical_base: 0,
            size: payload_size,
            master_key: Arc::new(master_key),
            sector_size,
            cipher_mode,
            iv_tweak,
            cursor: 0,
        }
    }

    /// Plain64 tweak step per 512-byte sector for one data unit.
    fn step(&self) -> u128 {
        ((self.sector_size as u128) / 512).max(1)
    }

    /// Absolute payload-relative byte position for a logical `local_offset`.
    fn abs_pos(&self, local_offset: u64) -> u64 {
        self.logical_base + local_offset
    }

    /// XTS-decrypt the sectors covering `[offset, offset+len)` of the plaintext
    /// into `buf`. `offset` is relative to this view's logical origin.
    fn read_range(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let ss = self.sector_size as u64;
        let step = self.step();
        let mut done = 0u64;
        while done < buf.len() as u64 {
            let pos = self.abs_pos(offset + done);
            let unit = pos / ss;
            let within = (pos % ss) as usize;
            let physical = self.payload_offset + unit * ss;
            let mut sector = vec![0u8; ss as usize];
            self.backing
                .read_at(physical, &mut sector)
                .map_err(io_err)?;
            let tweak = (self.iv_tweak + unit as u128 * step).to_le_bytes();
            crate::luks::xts_decrypt_sector(
                &self.cipher_mode,
                &self.master_key,
                &mut sector,
                &tweak,
            )
            .map_err(io_err)?;
            let take = (ss as usize - within).min(buf.len() - done as usize);
            buf[done as usize..done as usize + take]
                .copy_from_slice(&sector[within..within + take]);
            done += take as u64;
        }
        Ok(())
    }

    /// XTS-encrypt `buf` into the backing store at logical `offset`. Full,
    /// sector-aligned writes encrypt in place; partial writes do an encrypted
    /// read-modify-write of the affected sector(s).
    fn write_range(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let ss = self.sector_size as u64;
        let step = self.step();
        let mut done = 0u64;
        while done < buf.len() as u64 {
            let pos = self.abs_pos(offset + done);
            let unit = pos / ss;
            let within = (pos % ss) as usize;
            let physical = self.payload_offset + unit * ss;
            let take = (ss as usize - within).min(buf.len() - done as usize);
            let tweak = (self.iv_tweak + unit as u128 * step).to_le_bytes();
            if within == 0 && take == ss as usize {
                // Full data unit: encrypt directly from the input.
                let mut sector = buf[done as usize..done as usize + take].to_vec();
                crate::luks::xts_encrypt_sector(
                    &self.cipher_mode,
                    &self.master_key,
                    &mut sector,
                    &tweak,
                )
                .map_err(io_err)?;
                self.backing.write_at(physical, &sector).map_err(io_err)?;
            } else {
                // Partial data unit: read, decrypt, overlay, re-encrypt, write.
                let mut sector = vec![0u8; ss as usize];
                self.backing
                    .read_at(physical, &mut sector)
                    .map_err(io_err)?;
                crate::luks::xts_decrypt_sector(
                    &self.cipher_mode,
                    &self.master_key,
                    &mut sector,
                    &tweak,
                )
                .map_err(io_err)?;
                sector[within..within + take]
                    .copy_from_slice(&buf[done as usize..done as usize + take]);
                crate::luks::xts_encrypt_sector(
                    &self.cipher_mode,
                    &self.master_key,
                    &mut sector,
                    &tweak,
                )
                .map_err(io_err)?;
                self.backing.write_at(physical, &sector).map_err(io_err)?;
            }
            done += take as u64;
        }
        Ok(())
    }
}

impl Clone for LuksRegion {
    fn clone(&self) -> Self {
        Self {
            backing: Arc::clone(&self.backing),
            payload_offset: self.payload_offset,
            logical_base: self.logical_base,
            size: self.size,
            master_key: Arc::clone(&self.master_key),
            sector_size: self.sector_size,
            cipher_mode: self.cipher_mode.clone(),
            iv_tweak: self.iv_tweak,
            cursor: 0,
        }
    }
}

impl BlockDevice for LuksRegion {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        self.read_range(offset, buf).map_err(Ext4Error::Io)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        self.write_range(offset, buf).map_err(Ext4Error::Io)
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn flush(&self) -> Ext4Result<()> {
        self.backing.flush()
    }

    fn is_writable(&self) -> bool {
        true
    }
}

impl Read for LuksRegion {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.size {
            return Ok(0);
        }
        let remaining = (self.size - self.cursor) as usize;
        let n = buf.len().min(remaining);
        self.read_range(self.cursor, &mut buf[..n])?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for LuksRegion {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.size.saturating_sub(self.cursor) as usize;
        let n = buf.len().min(remaining);
        if n == 0 {
            return Ok(0);
        }
        self.write_range(self.cursor, &buf[..n])?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.backing.flush().map_err(io_err)
    }
}

impl Seek for LuksRegion {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(d) => self.cursor as i64 + d,
            SeekFrom::End(d) => self.size as i64 + d,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }
        self.cursor = (new as u64).min(self.size);
        Ok(self.cursor)
    }
}

impl BlockRegion for LuksRegion {
    fn open_region(&self, offset: u64, size: u64) -> Self {
        assert!(
            offset.checked_add(size).is_some_and(|e| e <= self.size),
            "open_region([{offset}, {offset}+{size})) is out of bounds for LuksRegion of size {}",
            self.size,
        );
        Self {
            backing: Arc::clone(&self.backing),
            payload_offset: self.payload_offset,
            logical_base: self.logical_base + offset,
            size,
            master_key: Arc::clone(&self.master_key),
            sector_size: self.sector_size,
            cipher_mode: self.cipher_mode.clone(),
            iv_tweak: self.iv_tweak,
            cursor: 0,
        }
    }

    fn region_size(&self) -> u64 {
        self.size
    }

    fn region_base(&self) -> u64 {
        // The payload's logical origin is 0 for the top-level view; a sub-view
        // (a partition inside a LUKS-contained GPT) reports its non-zero
        // logical base so nested-GPT rejection works just like for BlockFile.
        self.logical_base
    }

    fn sync_region(&self) -> io::Result<()> {
        self.backing.flush().map_err(io_err)
    }
}

/// Map any Display-able error into an `io::Error` (used to bridge the ext4
/// `BlockDevice` error type and the `luks` crate error into `std::io`).
fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use sha2::{Digest, Sha256};

    fn tmp_file(name: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("sysimg-blockfile-{}-{name}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        p
    }

    #[test]
    fn region_digest_hashes_first_n_bytes_locally() {
        let p = tmp_file("digest.bin");
        let bytes: Vec<u8> = (0u8..=255).collect();
        std::fs::write(&p, &bytes).unwrap();
        let bf = BlockFile::open(&p, 0, bytes.len() as u64).unwrap();

        // Full region: digest matches hash_file of the whole file.
        let d = bf.region_digest(bytes.len() as u64).unwrap().unwrap();
        assert_eq!(hex::encode(d), hex::encode(hash::hash_file(&p).unwrap()));

        // Partial: only the first N bytes are hashed, not the whole file.
        let n = 10u64;
        let d = bf.region_digest(n).unwrap().unwrap();
        let mut h = Sha256::new();
        Digest::update(&mut h, &bytes[..n as usize]);
        let expected: [u8; 32] = Digest::finalize(h).into();
        assert_eq!(d, expected);

        // size > region is clamped to the region size.
        let d = bf.region_digest(1 << 20).unwrap().unwrap();
        assert_eq!(hex::encode(d), hex::encode(hash::hash_file(&p).unwrap()));

        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn region_digest_uses_subregion_offset() {
        // A sub-region's digest must cover [offset, offset+size) of the
        // backing file, mirroring how an image partition sub-region is hashed.
        let p = tmp_file("sub.bin");
        let bytes: Vec<u8> = (0u8..200).collect();
        std::fs::write(&p, &bytes).unwrap();
        let bf = BlockFile::open(&p, 0, bytes.len() as u64).unwrap();
        let sub = bf.open_region(50, 100);
        let d = sub.region_digest(100).unwrap().unwrap();
        let mut h = Sha256::new();
        Digest::update(&mut h, &bytes[50..150]);
        let expected: [u8; 32] = Digest::finalize(h).into();
        assert_eq!(d, expected);

        std::fs::remove_file(&p).ok();
    }
}
