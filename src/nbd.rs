//! NBD (Network Block Device) client backend.
//!
//! [`NbdRegion`] exposes a remote NBD export as a [`crate::blockfile::BlockRegion`],
//! so the install pipeline can write a built system directly onto a remote
//! block device over the network (or a Unix-domain NBD socket) using an
//! `nbd:` URL as the `--disk` target — instead of a local file or `/dev` node.
//!
//! This is a minimal, pure-Rust NBD *client*. It speaks the newstyle fixed
//! negotiation with `NBD_OPT_GO` and the simple (un-structured) transmission
//! reply format. Only the commands the install pipeline needs are
//! implemented: read, write, flush and (on disconnect) a best-effort
//! `NBD_CMD_DISC`.
//!
//! [`NbdRegion`] is generic over the byte stream `S` so it is not tied to a
//! single transport: the default `S = Stream` covers TCP and Unix-domain NBD
//! servers (opened from an `nbd:` URL via [`NbdRegion::open`]), while any
//! `Read + Write + Send` pair — for instance an in-memory loopback used in
//! tests — can be wrapped with [`NbdRegion::from_stream`].
//!
//! The whole export is exposed as one region (base 0); sub-regions (GPT
//! partitions, LVM logical volumes, …) are produced by
//! [`NbdRegion::open_region`] and share the single connection via an
//! `Arc<Mutex<…>>`, exactly mirroring how [`crate::blockfile::BlockFile`]
//! shares a file handle. Ordinary requests are serialized by the mutex, so the
//! pipeline has at most one in-flight request — correct and a match for the
//! single-threaded install flow. Two optimizations avoid paying the link
//! round-trip per small request:
//!
//! * Filesystem writes that arrive as adjacent `write_at` calls (ext4's
//!   block-buffer commit, the FAT allocator) are coalesced into one request per
//!   up to 1 MiB — see [`NbdConn::buffered_write`]. A read of a buffered range,
//!   a flush, or a non-adjacent write drains the buffer first.
//! * Bulk copies opt into pipelining: see
//!   [`crate::blockfile::BlockRegion::write_chunks`], which sends a run of
//!   disjoint sequential writes back-to-back before collecting their replies so
//!   the link round-trip is overlapped instead of paid per chunk.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fs_ext4::block_io::BlockDevice;
use fs_ext4::error::{Error as Ext4Error, Result as Ext4Result};

use crate::blockfile::BlockRegion;
use crate::error::{Error, Result};
use crate::url::percent_decode;

/// A side channel to hash a byte range of the backing device *on the same host
/// as the device*, returning the SHA-256 without transferring the bytes over
/// NBD.
///
/// `ssh-install` supplies one (running `sha256sum` over SSH) so the
/// image-block fast path can skip shipping an unchanged image over the
/// network. A plain `nbd://` URL has none: hashing there would read the whole
/// region over NBD and gain nothing over copying, so [`NbdRegion::region_digest`]
/// returns `None` instead.
///
/// Arguments are the absolute byte offset and length within the backing device
/// (i.e. relative to the NBD export origin, which for `ssh-install` is the
/// whole device). Return `Ok(None)` to fall back to copying.
pub(crate) type NbdRemoteDigest =
    dyn Fn(u64, u64) -> io::Result<Option<[u8; 32]>> + Send + Sync + 'static;

// ---- NBD protocol constants -----------------------------------------------

/// Server option magic ("IHAVEOPT").
const NBD_OPTS_MAGIC: u64 = 0x4948_4156_454F_5054;
/// Option-reply magic.
const NBD_REP_MAGIC: u64 = 0x0003_E889_0455_65A9;
/// Transmission-phase request magic.
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
/// Simple reply magic.
const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

// Handshake flags (server → client).
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;
// Handshake flags (client → server).
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 1 << 0;
const NBD_FLAG_C_NO_ZEROES: u32 = 1 << 1;

// Options.
const NBD_OPT_GO: u32 = 7;

// Option reply types.
const NBD_REP_ACK: u32 = 1;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_BASE: u32 = 1 << 31;

// Info types.
const NBD_INFO_EXPORT: u16 = 0;

// Transmission flags.
const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;

// Commands.
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;

/// Default NBD TCP port.
const NBD_DEFAULT_PORT: u16 = 10809;

// ---- URL parsing ----------------------------------------------------------

/// A parsed `nbd:` target.
#[derive(Debug, Clone)]
enum NbdTarget {
    /// `nbd://host[:port]/export` (or `nbd+tcp://…`) — TCP transport.
    Tcp {
        host: String,
        port: u16,
        export: String,
    },
    /// `nbd+unix://[export]?socket=/path/to/sock` — Unix-domain transport.
    Unix { socket: PathBuf, export: String },
}

impl NbdTarget {
    fn export_name(&self) -> &str {
        match self {
            NbdTarget::Tcp { export, .. } => export,
            NbdTarget::Unix { export, .. } => export,
        }
    }
}

/// Parse an `nbd:`, `nbd+tcp:` or `nbd+unix:` URL.
///
/// Supported forms:
/// * `nbd://host[:port]/export`         (default port 10809, default export "")
/// * `nbd+tcp://host[:port]/export`
/// * `nbd+unix:///export?socket=/path`   (default export "")
fn parse_nbd_url(s: &str) -> Result<NbdTarget> {
    if let Some(rest) = s.strip_prefix("nbd+unix://") {
        // With no network authority, the path is the export name. A leading
        // '/' (the path separator after the empty authority in
        // `nbd+unix:///export`) is stripped so the form matches the TCP
        // `nbd://host:port/export` convention.
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let export = percent_decode(path.strip_prefix('/').unwrap_or(path));
        let socket = query
            .split('&')
            .filter_map(|kv| kv.strip_prefix("socket=").map(percent_decode))
            .next()
            .ok_or_else(|| {
                Error::msg(format!(
                    "nbd+unix URL \"{s}\" is missing a socket= query parameter"
                ))
            })?;
        Ok(NbdTarget::Unix {
            socket: PathBuf::from(socket),
            export,
        })
    } else if let Some(rest) = s
        .strip_prefix("nbd://")
        .or_else(|| s.strip_prefix("nbd+tcp://"))
    {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority)?;
        let export = percent_decode(path);
        Ok(NbdTarget::Tcp { host, port, export })
    } else {
        Err(Error::msg(format!(
            "\"{s}\" is not an nbd: URL (expected nbd://host[:port]/export or \
             nbd+unix://?socket=path)"
        )))
    }
}

/// Split a `host[:port]` authority (with IPv6-literal `[…]:port` support).
fn split_host_port(authority: &str) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::msg(format!("bad IPv6 literal in \"{authority}\"")))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| Error::msg(format!("bad port \"{p}\"")))?,
            None => NBD_DEFAULT_PORT,
        };
        Ok((host.to_string(), port))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => Ok((
                h.to_string(),
                p.parse()
                    .map_err(|_| Error::msg(format!("bad port \"{p}\"")))?,
            )),
            None => Ok((authority.to_string(), NBD_DEFAULT_PORT)),
        }
    }
}

// ---- Connection -----------------------------------------------------------

/// The underlying byte stream for the default (network) backend: either a TCP
/// or a Unix-domain socket. Any `Read + Write + Send` type can be used instead
/// via [`NbdRegion::from_stream`].
pub enum Stream {
    /// TCP transport.
    Tcp(TcpStream),
    /// Unix-domain transport.
    Unix(UnixStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            Stream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            Stream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            Stream::Unix(s) => s.flush(),
        }
    }
}

/// Largest run of adjacent writes coalesced into a single NBD request.
///
/// Filesystem writers (ext4's block-buffer commit, the FAT allocator) issue a
/// `write_at` per on-disk block — 4 KiB each — and those blocks are usually
/// part of one large, contiguous file run. Sending a 28-byte request header
/// and waiting for a reply per 4 KiB turns a remote install into a
/// latency-bound walk: at 30 ms per round-trip that is ~130 KiB/s regardless of
/// link bandwidth. Buffering adjacent writes into one request up to this cap
/// cuts the request count (and so the round-trips) by ~256×.
///
/// Kept at 1 MiB, well under what common servers accept (qemu-nbd advertises
/// a 32 MiB maximum), so no `NBD_INFO_BLOCK_SIZE` negotiation is required.
const WRITE_COALESCE_MAX: usize = 1024 * 1024;

/// A single contiguous run of writes queued for one NBD request.
///
/// Absorbing a write either extends the run (adjacent offset), patches it in
/// place (fully contained rewrite), or evicts it and starts a new run. Keeping
/// the policy pure makes it directly testable; [`NbdConn::buffered_write`] does
/// the I/O around it.
#[derive(Default)]
struct WriteBehind {
    /// Absolute offset of the first buffered byte.
    start: u64,
    /// Buffered bytes (`start..start + data.len()`); at most `WRITE_COALESCE_MAX`.
    data: Vec<u8>,
}

impl WriteBehind {
    /// True if the buffered run intersects `[offset, offset + len)`.
    fn overlaps(&self, offset: u64, len: u64) -> bool {
        !self.data.is_empty()
            && offset < self.start + self.data.len() as u64
            && self.start < offset + len
    }

    /// Remove and return the buffered run, if any.
    fn take(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.data.is_empty() {
            None
        } else {
            Some((self.start, std::mem::take(&mut self.data)))
        }
    }

    /// Fold a non-empty `buf` at `offset` into the run.
    ///
    /// Returns `(evicted, absorbed)`: `evicted` is a run that must be written
    /// before any data written after this call (the caller flushes it), and
    /// `absorbed` is how many leading bytes of `buf` were folded in (always
    /// greater than 0 for a non-empty `buf`). Callers loop over `buf`, flushing
    /// evicted runs in between, until every byte has been absorbed.
    fn absorb(&mut self, offset: u64, buf: &[u8]) -> (Option<(u64, Vec<u8>)>, usize) {
        debug_assert!(!buf.is_empty());
        let end = self.start + self.data.len() as u64;
        // Fully contained rewrite: patch in place, no eviction needed.
        if offset >= self.start && offset + buf.len() as u64 <= end {
            let at = (offset - self.start) as usize;
            self.data[at..at + buf.len()].copy_from_slice(buf);
            return (None, buf.len());
        }
        // Adjacent append while the run still has room.
        if offset == end && self.data.len() < WRITE_COALESCE_MAX {
            let take = (WRITE_COALESCE_MAX - self.data.len()).min(buf.len());
            self.data.extend_from_slice(&buf[..take]);
            if self.data.len() >= WRITE_COALESCE_MAX {
                return (Some((self.start, std::mem::take(&mut self.data))), take);
            }
            return (None, take);
        }
        // Disjoint / overlapping-but-not-contained, or the run is full: the old
        // run must go out first. Start a fresh one and absorb as much as fits.
        let evicted = if self.data.is_empty() {
            None
        } else {
            Some((self.start, std::mem::take(&mut self.data)))
        };
        self.start = offset;
        let take = buf.len().min(WRITE_COALESCE_MAX);
        self.data.extend_from_slice(&buf[..take]);
        (evicted, take)
    }
}

/// A live NBD connection owning the negotiated byte stream.
struct NbdConn<S: Read + Write> {
    stream: S,
    next_handle: u64,
    /// Write-behind run shared by every sub-region clone (the connection is
    /// behind an `Arc<Mutex<…>>`), so coalescing works across a whole install,
    /// not per region.
    pending: WriteBehind,
}

impl<S: Read + Write> NbdConn<S> {
    fn next_handle(&mut self) -> u64 {
        self.next_handle = self.next_handle.wrapping_add(1);
        self.next_handle
    }

    /// Send a transmission-phase request. For writes, `data` carries the
    /// payload that follows the fixed 28-byte header.
    fn send_request(
        &mut self,
        flags: u16,
        cmd: u16,
        handle: u64,
        offset: u64,
        length: u32,
        data: Option<&[u8]>,
    ) -> Result<()> {
        let mut header = [0u8; 28];
        header[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        header[4..6].copy_from_slice(&flags.to_be_bytes());
        header[6..8].copy_from_slice(&cmd.to_be_bytes());
        header[8..16].copy_from_slice(&handle.to_be_bytes());
        header[16..24].copy_from_slice(&offset.to_be_bytes());
        header[24..28].copy_from_slice(&length.to_be_bytes());
        self.stream
            .write_all(&header)
            .map_err(|e| Error::msg(format!("NBD: write request failed: {e}")))?;
        if let Some(d) = data {
            self.stream
                .write_all(d)
                .map_err(|e| Error::msg(format!("NBD: write request data failed: {e}")))?;
        }
        Ok(())
    }

    /// Read one simple-reply header. Returns `(handle, errno)`; the caller
    /// matches the handle. Reply order is not assumed: with several requests
    /// in flight the server may complete them out of order.
    fn read_reply(&mut self) -> Result<(u64, u32)> {
        let mut header = [0u8; 16];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| Error::msg(format!("NBD: short reply: {e}")))?;
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != NBD_SIMPLE_REPLY_MAGIC {
            return Err(Error::msg(format!(
                "NBD: reply magic mismatch 0x{magic:08x} (expected 0x{NBD_SIMPLE_REPLY_MAGIC:08x})"
            )));
        }
        let error = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let handle = u64::from_be_bytes(header[8..16].try_into().unwrap());
        Ok((handle, error))
    }

    /// Read a simple-reply header and validate its handle. Returns the
    /// server-reported errno (0 = success).
    fn read_reply_header(&mut self, expected_handle: u64) -> Result<u32> {
        let (handle, error) = self.read_reply()?;
        if handle != expected_handle {
            return Err(Error::msg("NBD: reply handle mismatch"));
        }
        Ok(error)
    }

    /// Read a range of the export.
    ///
    /// Any buffered write intersecting `[offset, offset + buf.len())` is
    /// flushed first so the read observes the latest bytes (read-after-write,
    /// which the filesystem writers rely on).
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if self.pending.overlaps(offset, buf.len() as u64) {
            self.flush_pending()?;
        }
        if buf.is_empty() {
            return Ok(());
        }
        let handle = self.next_handle();
        self.send_request(0, NBD_CMD_READ, handle, offset, buf.len() as u32, None)?;
        let error = self.read_reply_header(handle)?;
        if error != 0 {
            return Err(nbd_errno(error, "read"));
        }
        self.stream
            .read_exact(buf)
            .map_err(|e| Error::msg(format!("NBD: short read data: {e}")))?;
        Ok(())
    }

    /// Send a single write immediately, bypassing the coalescing buffer.
    fn write_raw(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let handle = self.next_handle();
        self.send_request(
            0,
            NBD_CMD_WRITE,
            handle,
            offset,
            buf.len() as u32,
            Some(buf),
        )?;
        let error = self.read_reply_header(handle)?;
        if error != 0 {
            return Err(nbd_errno(error, "write"));
        }
        Ok(())
    }

    /// Queue `buf` at `offset` into the coalescing buffer, sending a request
    /// only when a run is evicted or reaches [`WRITE_COALESCE_MAX`]. Adjacent
    /// filesystem-block writes merge into one large request, so the link pays
    /// one round-trip per ~1 MiB instead of one per block.
    fn buffered_write(&mut self, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let (evicted, absorbed) = self.pending.absorb(offset, buf);
            if let Some((at, run)) = evicted {
                self.write_raw(at, &run)?;
            }
            offset += absorbed as u64;
            buf = &buf[absorbed..];
        }
        Ok(())
    }

    /// Send the buffered run (if any) immediately.
    fn flush_pending(&mut self) -> Result<()> {
        if let Some((offset, run)) = self.pending.take() {
            self.write_raw(offset, &run)?;
        }
        Ok(())
    }

    /// Write a run of chunks back-to-back without waiting for each reply, then
    /// collect every reply, invoking `on_written` with each chunk's length as
    /// its (successful) reply arrives.
    ///
    /// Sending all requests before reading any reply is what hides the link
    /// round-trip: the server can process several writes concurrently instead
    /// of the client stopping at each chunk. Chunks are written at consecutive
    /// offsets starting at `base`, in the order given. They must be *disjoint
    /// sequential* ranges (which is exactly what a bulk copy produces): NBD does
    /// not guarantee the server preserves ordering between concurrent requests,
    /// so overlapping writes would be unsafe here.
    fn write_batch_progress(
        &mut self,
        base: u64,
        chunks: &[&[u8]],
        on_written: &mut dyn FnMut(u64),
    ) -> Result<()> {
        self.flush_pending()?;
        let non_empty: Vec<&[u8]> = chunks.iter().copied().filter(|c| !c.is_empty()).collect();
        if non_empty.is_empty() {
            return Ok(());
        }
        // Fire every request (header + payload) before reading a single reply.
        let mut outstanding: Vec<(u64, u64)> = Vec::with_capacity(non_empty.len());
        let mut offset = base;
        for &chunk in &non_empty {
            let handle = self.next_handle();
            self.send_request(
                0,
                NBD_CMD_WRITE,
                handle,
                offset,
                chunk.len() as u32,
                Some(chunk),
            )?;
            outstanding.push((handle, chunk.len() as u64));
            offset += chunk.len() as u64;
        }
        // Drain all replies, matching by handle (order is not guaranteed).
        // Keep reading even after a failure so the connection is left in a
        // consistent state, then report the first error.
        let mut first_err: Option<Error> = None;
        while !outstanding.is_empty() {
            let (handle, error) = self.read_reply()?;
            let Some(pos) = outstanding.iter().position(|(h, _)| *h == handle) else {
                return Err(Error::msg("NBD: unexpected reply handle in batch"));
            };
            let (_, len) = outstanding.swap_remove(pos);
            if error != 0 {
                if first_err.is_none() {
                    first_err = Some(nbd_errno(error, "write"));
                }
            } else {
                on_written(len);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn write_batch(&mut self, base: u64, chunks: &[&[u8]]) -> Result<()> {
        self.write_batch_progress(base, chunks, &mut |_| {})
    }

    /// Flush buffered writes, then ask the server to persist them.
    fn flush(&mut self) -> Result<()> {
        self.flush_pending()?;
        let handle = self.next_handle();
        self.send_request(0, NBD_CMD_FLUSH, handle, 0, 0, None)?;
        let error = self.read_reply_header(handle)?;
        if error != 0 {
            return Err(nbd_errno(error, "flush"));
        }
        Ok(())
    }

    /// Best-effort graceful disconnect (ignored on failure).
    fn disconnect(&mut self) {
        let handle = self.next_handle();
        let _ = self.send_request(0, NBD_CMD_DISC, handle, 0, 0, None);
    }
}

impl<S: Read + Write> Drop for NbdConn<S> {
    fn drop(&mut self) {
        // Never silently lose a buffered write: try to get it on the wire
        // before disconnecting (errors are ignored during teardown).
        let _ = self.flush_pending();
        self.disconnect();
    }
}

/// Turn a server-reported (Linux) errno into an [`Error`].
fn nbd_errno(error: u32, op: &str) -> Error {
    match error {
        1 => Error::msg(format!("NBD {op} failed: EPERM (operation not permitted)")),
        5 => Error::msg(format!("NBD {op} failed: EIO")),
        13 => Error::msg(format!("NBD {op} failed: EACCES (permission denied)")),
        22 => Error::msg(format!("NBD {op} failed: EINVAL (invalid argument)")),
        28 => Error::msg(format!("NBD {op} failed: ENOSPC (no space left on device)")),
        30 => Error::msg(format!("NBD {op} failed: EROFS (read-only)")),
        _ => Error::msg(format!("NBD {op} failed: server error {error}")),
    }
}

// ---- Region ---------------------------------------------------------------

/// A writable view of the byte range `[base, base + size)` of a remote NBD
/// export. Cloning is cheap: the connection is shared via an `Arc<Mutex<…>>`
/// and a fresh clone starts at cursor 0, exactly like [`BlockFile`].
///
/// The default type parameter `S = Stream` selects the network transport
/// (TCP/Unix, opened from an `nbd:` URL); any other `Read + Write + Send`
/// stream can be wrapped with [`NbdRegion::from_stream`].
pub struct NbdRegion<S = Stream>
where
    S: Read + Write,
{
    conn: Arc<Mutex<NbdConn<S>>>,
    base: u64,
    size: u64,
    cursor: u64,
    read_only: bool,
    can_flush: bool,
    /// Optional side channel to hash a range of the backing device on the
    /// device's own host (see [`NbdRemoteDigest`]). `None` for a plain
    /// `nbd://` URL. Sub-regions share it by cloning the `Arc`, and call it
    /// with their absolute `base` so a partition sub-region hashes the right
    /// byte range of the underlying device.
    remote_digest: Option<Arc<NbdRemoteDigest>>,
}

/// Network backend: open a remote NBD export from an `nbd:` URL.
impl NbdRegion<Stream> {
    /// Connect to an NBD export described by an `nbd:` URL and return a region
    /// covering the whole export (base 0, size = the export size).
    pub fn open(url: &str) -> Result<Self> {
        let target = parse_nbd_url(url)?;
        let export = target.export_name();
        let mut stream = connect(&target)?;
        let (size, read_only, can_flush) = negotiate(&mut stream, export)?;
        Ok(Self::from_stream(stream, size, read_only, can_flush))
    }
}

impl<S: Read + Write + Send + 'static> NbdRegion<S> {
    /// Wrap an already-connected, already-negotiated byte stream as an NBD
    /// region covering `[0, size)`. Used by [`NbdRegion::open`] for the network
    /// backend and available directly to plug in custom transports (or for
    /// tests driving an in-memory loopback).
    pub fn from_stream(stream: S, size: u64, read_only: bool, can_flush: bool) -> Self {
        Self {
            conn: Arc::new(Mutex::new(NbdConn {
                stream,
                next_handle: 0,
                pending: WriteBehind::default(),
            })),
            base: 0,
            size,
            cursor: 0,
            read_only,
            can_flush,
            remote_digest: None,
        }
    }

    /// Perform the newstyle fixed NBD handshake over an already-connected
    /// byte stream and return a region covering the negotiated export. This
    /// is the transport-agnostic core of [`NbdRegion::open`]: `open` does the
    /// TCP/Unix `connect` and then delegates here. Use it to plug in a custom
    /// transport (TLS, an SSH tunnel, an in-memory loopback, …) while still
    /// running the real client-side negotiation.
    pub fn open_handshake(mut stream: S, export: &str) -> Result<Self> {
        let (size, read_only, can_flush) = negotiate(&mut stream, export)?;
        Ok(Self::from_stream(stream, size, read_only, can_flush))
    }

    /// Attach a side channel that hashes a byte range of the backing device on
    /// the device's own host (see [`NbdRemoteDigest`]). Enables the
    /// image-block fast path for remote backends such as `ssh-install`, where
    /// the bytes never need to cross the network to be checked.
    pub fn with_remote_digest(
        mut self,
        f: impl Fn(u64, u64) -> io::Result<Option<[u8; 32]>> + Send + Sync + 'static,
    ) -> Self {
        self.remote_digest = Some(Arc::new(f));
        self
    }
}

impl<S: Read + Write> Clone for NbdRegion<S> {
    fn clone(&self) -> Self {
        // A fresh clone starts at cursor 0; the connection is shared.
        Self {
            conn: Arc::clone(&self.conn),
            base: self.base,
            size: self.size,
            cursor: 0,
            read_only: self.read_only,
            can_flush: self.can_flush,
            remote_digest: self.remote_digest.clone(),
        }
    }
}

// --- Offset-based view (fs_ext4 BlockDevice) — ext4 mkfs + mount. ----------

impl<S: Read + Write + Send + 'static> BlockDevice for NbdRegion<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        let mut conn = self.conn.lock().unwrap();
        conn.read(self.base + offset, buf).map_err(map_nbd_err)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Ext4Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(Ext4Error::OutOfBounds);
        }
        if self.read_only {
            return Err(Ext4Error::ReadOnly);
        }
        let mut conn = self.conn.lock().unwrap();
        conn.buffered_write(self.base + offset, buf)
            .map_err(map_nbd_err)
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn flush(&self) -> Ext4Result<()> {
        let mut conn = self.conn.lock().unwrap();
        // Always drain the write-behind buffer (it holds real WRITE requests);
        // only the server-side persistence barrier is optional.
        if self.can_flush {
            conn.flush().map_err(map_nbd_err)
        } else {
            conn.flush_pending().map_err(map_nbd_err)
        }
    }

    fn is_writable(&self) -> bool {
        !self.read_only
    }
}

fn map_nbd_err(e: Error) -> Ext4Error {
    Ext4Error::Io(io::Error::other(e.to_string()))
}

// --- Cursor-based view (std::io) — GPT writer, FAT formatter, raw copies. ---

impl<S: Read + Write + Send + 'static> Read for NbdRegion<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.size {
            return Ok(0);
        }
        let remaining = (self.size - self.cursor) as usize;
        let to_read = buf.len().min(remaining);
        let mut conn = self.conn.lock().unwrap();
        conn.read(self.base + self.cursor, &mut buf[..to_read])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.cursor += to_read as u64;
        Ok(to_read)
    }
}

impl<S: Read + Write + Send + 'static> Write for NbdRegion<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NBD export is read-only",
            ));
        }
        let remaining = self.size.saturating_sub(self.cursor) as usize;
        let to_write = buf.len().min(remaining);
        if to_write == 0 {
            return Ok(0);
        }
        let mut conn = self.conn.lock().unwrap();
        conn.buffered_write(self.base + self.cursor, &buf[..to_write])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.cursor += to_write as u64;
        Ok(to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        // Drain the write-behind buffer regardless; the NBD FLUSH is optional.
        if self.can_flush {
            conn.flush().map_err(|e| io::Error::other(e.to_string()))
        } else {
            conn.flush_pending()
                .map_err(|e| io::Error::other(e.to_string()))
        }
    }
}

impl<S: Read + Write + Send + 'static> Seek for NbdRegion<S> {
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

// --- BlockRegion trait -----------------------------------------------------

impl<S: Read + Write + Send + 'static> BlockRegion for NbdRegion<S> {
    fn open_region(&self, offset: u64, size: u64) -> Self {
        let end = offset.checked_add(size);
        assert!(
            end.is_some_and(|e| e <= self.size),
            "open_region([{offset}, {offset}+{size})) is out of bounds for region of size {}",
            self.size,
        );
        Self {
            conn: Arc::clone(&self.conn),
            base: self.base + offset,
            size,
            cursor: 0,
            read_only: self.read_only,
            can_flush: self.can_flush,
            remote_digest: self.remote_digest.clone(),
        }
    }

    fn region_size(&self) -> u64 {
        self.size
    }

    fn region_base(&self) -> u64 {
        self.base
    }

    fn sync_region(&self) -> io::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        // Always drain the write-behind buffer (it holds real WRITE requests);
        // only the server-side persistence barrier is optional.
        if self.can_flush {
            conn.flush().map_err(|e| io::Error::other(e.to_string()))?;
        } else {
            conn.flush_pending()
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    /// Pipeline the chunks: send them all, then collect the replies. This is
    /// the whole point of the batch API — a bulk image copy issues one request
    /// per chunk, and over SSH/NBD each would otherwise cost a full
    /// round-trip (`write_chunks` default). Sending them before waiting lets the
    /// remote server work on several at once and keeps the link saturated.
    fn write_chunks(&mut self, chunks: &[&[u8]]) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NBD export is read-only",
            ));
        }
        let total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        if total == 0 {
            return Ok(());
        }
        let remaining = self.size.saturating_sub(self.cursor);
        if total > remaining {
            // Past the end of the region: fall back to per-chunk `write_all`
            // so the caller sees the same `WriteZero` error as before.
            for &chunk in chunks {
                self.write_all(chunk)?;
            }
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        conn.write_batch(self.base + self.cursor, chunks)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.cursor += total;
        Ok(())
    }

    /// Like [`Self::write_chunks`], but report each chunk as its reply arrives
    /// so a progress bar advances continuously instead of jumping once per
    /// batch. See [`NbdConn::write_batch_progress`].
    fn write_chunks_progress(
        &mut self,
        chunks: &[&[u8]],
        on_written: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "NBD export is read-only",
            ));
        }
        let total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        if total == 0 {
            return Ok(());
        }
        let remaining = self.size.saturating_sub(self.cursor);
        if total > remaining {
            // Past the end of the region: keep the same per-chunk behavior (and
            // `WriteZero` error) as the default, reporting each written chunk.
            for &chunk in chunks {
                self.write_all(chunk)?;
                on_written(chunk.len() as u64);
            }
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        conn.write_batch_progress(self.base + self.cursor, chunks, on_written)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.cursor += total;
        Ok(())
    }

    fn region_digest(&self, size: u64) -> io::Result<Option<[u8; 32]>> {
        // Hash the range on the device's own host when a side channel is
        // available; otherwise return None — reading the whole region over
        // NBD just to hash it would be no cheaper than copying.
        match &self.remote_digest {
            Some(f) => {
                // The side channel reads the device directly (over SSH),
                // bypassing NBD, so drain any write-behind bytes first — they
                // are real WRITE requests that must be visible to the digest.
                {
                    let mut conn = self.conn.lock().unwrap();
                    conn.flush_pending()
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
                f(self.base, size)
            }
            None => Ok(None),
        }
    }
}

// ---- Negotiation ----------------------------------------------------------

fn connect(target: &NbdTarget) -> Result<Stream> {
    match target {
        NbdTarget::Tcp { host, port, .. } => {
            let stream = TcpStream::connect((host.as_str(), *port))
                .map_err(|e| Error::msg(format!("NBD: cannot connect to {host}:{port}: {e}")))?;
            // Disable Nagle: install issues many small control + I/O writes;
            // we want them on the wire promptly rather than coalesced.
            let _ = stream.set_nodelay(true);
            Ok(Stream::Tcp(stream))
        }
        NbdTarget::Unix { socket, .. } => {
            let stream = UnixStream::connect(socket).map_err(|e| {
                Error::msg(format!(
                    "NBD: cannot connect to unix socket {}: {e}",
                    socket.display()
                ))
            })?;
            Ok(Stream::Unix(stream))
        }
    }
}

/// Perform the newstyle fixed negotiation with `NBD_OPT_GO`.
///
/// Returns `(export_size, read_only, can_flush)`.
fn negotiate(stream: &mut (impl Read + Write), export: &str) -> Result<(u64, bool, bool)> {
    // Server greeting: NBDMAGIC + IHAVEOPT + 2-byte handshake flags.
    let mut greeting = [0u8; 18];
    stream
        .read_exact(&mut greeting)
        .map_err(|e| Error::msg(format!("NBD: short greeting: {e}")))?;
    if &greeting[0..8] != b"NBDMAGIC" {
        return Err(Error::msg(
            "NBD: bad server greeting magic (expected NBDMAGIC)",
        ));
    }
    if &greeting[8..16] != b"IHAVEOPT" {
        return Err(Error::msg(
            "NBD: server is not newstyle (expected IHAVEOPT)",
        ));
    }
    let hflags = u16::from_be_bytes([greeting[16], greeting[17]]);
    if hflags & NBD_FLAG_FIXED_NEWSTYLE == 0 {
        return Err(Error::msg(
            "NBD: server does not support fixed newstyle negotiation",
        ));
    }
    let no_zeroes = hflags & NBD_FLAG_NO_ZEROES != 0;
    let mut cflags = NBD_FLAG_C_FIXED_NEWSTYLE;
    if no_zeroes {
        cflags |= NBD_FLAG_C_NO_ZEROES;
    }
    stream
        .write_all(&cflags.to_be_bytes())
        .map_err(|e| Error::msg(format!("NBD: write client flags: {e}")))?;

    // NBD_OPT_GO payload (per the newstyle spec): name length (u32), name
    // bytes, then number of info requests (u16) = 0 (request the default set).
    // There is no leading "count of exports" field — OPT_GO selects exactly
    // one export by name; an extra u32 here skews qemu's parse and surfaces
    // as NBD_REP_ERR_INVALID ("Unexpected embedded NUL in option go").
    let name = export.as_bytes();
    let mut opt = Vec::with_capacity(4 + name.len() + 2);
    opt.extend_from_slice(&(name.len() as u32).to_be_bytes());
    opt.extend_from_slice(name);
    opt.extend_from_slice(&0u16.to_be_bytes());
    stream
        .write_all(&NBD_OPTS_MAGIC.to_be_bytes())
        .map_err(|e| Error::msg(format!("NBD: write option header: {e}")))?;
    stream
        .write_all(&NBD_OPT_GO.to_be_bytes())
        .map_err(|e| Error::msg(format!("NBD: write option header: {e}")))?;
    stream
        .write_all(&(opt.len() as u32).to_be_bytes())
        .map_err(|e| Error::msg(format!("NBD: write option header: {e}")))?;
    stream
        .write_all(&opt)
        .map_err(|e| Error::msg(format!("NBD: write option data: {e}")))?;

    // Read option replies until NBD_REP_ACK (or an error).
    let mut size = 0u64;
    let mut trans_flags = 0u16;
    loop {
        let (_opt_id, reply_type, data) = read_option_reply(stream)?;
        match reply_type {
            NBD_REP_INFO => {
                if data.len() < 2 {
                    return Err(Error::msg("NBD: short INFO reply"));
                }
                let info_type = u16::from_be_bytes([data[0], data[1]]);
                if info_type == NBD_INFO_EXPORT {
                    if data.len() < 2 + 8 + 2 {
                        return Err(Error::msg("NBD: short INFO_EXPORT reply"));
                    }
                    size = u64::from_be_bytes(data[2..10].try_into().unwrap());
                    trans_flags = u16::from_be_bytes([data[10], data[11]]);
                }
                // Other info types (name, block-size, …) are ignored — we only
                // need the export size and transmission flags.
            }
            NBD_REP_ACK => break,
            err if err >= NBD_REP_ERR_BASE => {
                let msg = String::from_utf8_lossy(&data);
                return Err(Error::msg(format!(
                    "NBD: server rejected export \"{export}\" (error {err}): {msg}"
                )));
            }
            _ => {
                // Unknown informational reply — tolerate it.
            }
        }
    }
    if size == 0 {
        return Err(Error::msg(format!("NBD: export \"{export}\" has size 0")));
    }
    let read_only = trans_flags & NBD_FLAG_READ_ONLY != 0;
    let can_flush = trans_flags & NBD_FLAG_SEND_FLUSH != 0;
    Ok((size, read_only, can_flush))
}

fn read_option_reply(stream: &mut (impl Read + Write)) -> Result<(u32, u32, Vec<u8>)> {
    let mut header = [0u8; 20];
    stream
        .read_exact(&mut header)
        .map_err(|e| Error::msg(format!("NBD: short option reply: {e}")))?;
    let magic = u64::from_be_bytes(header[0..8].try_into().unwrap());
    if magic != NBD_REP_MAGIC {
        return Err(Error::msg(format!(
            "NBD: bad option-reply magic 0x{magic:016x}"
        )));
    }
    let opt = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let reply_type = u32::from_be_bytes(header[12..16].try_into().unwrap());
    let len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    let mut data = vec![0u8; len];
    stream
        .read_exact(&mut data)
        .map_err(|e| Error::msg(format!("NBD: short option reply data: {e}")))?;
    Ok((opt, reply_type, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockfile::BlockRegion;
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;

    // A minimal blocking in-memory duplex (no sockets) for protocol tests.
    struct Chan {
        buf: Mutex<VecDeque<u8>>,
        closed: Mutex<bool>,
        cv: Condvar,
    }
    struct Half {
        rx: Arc<Chan>,
        tx: Arc<Chan>,
    }
    fn pair() -> (Half, Half) {
        let ab = Arc::new(Chan {
            buf: Mutex::new(VecDeque::new()),
            closed: Mutex::new(false),
            cv: Condvar::new(),
        });
        let ba = Arc::new(Chan {
            buf: Mutex::new(VecDeque::new()),
            closed: Mutex::new(false),
            cv: Condvar::new(),
        });
        (
            Half {
                rx: ba.clone(),
                tx: ab.clone(),
            },
            Half { rx: ab, tx: ba },
        )
    }
    impl Read for Half {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let mut g = self.rx.buf.lock().unwrap();
            while g.is_empty() {
                if *self.rx.closed.lock().unwrap() {
                    return Ok(0);
                }
                g = self.rx.cv.wait(g).unwrap();
            }
            let n = b.len().min(g.len());
            for s in b.iter_mut().take(n) {
                *s = g.pop_front().unwrap();
            }
            Ok(n)
        }
    }
    impl Write for Half {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.tx.buf.lock().unwrap().extend(b.iter().copied());
            self.tx.cv.notify_all();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for Half {
        fn drop(&mut self) {
            *self.tx.closed.lock().unwrap() = true;
            self.tx.cv.notify_all();
        }
    }

    /// Drives the server side of a handshake + one WRITE + one READ, then
    /// waits for the client's DISC. Asserts the framing of each request.
    fn run_mini_server(mut server: Half) {
        // greeting
        let mut g = [0u8; 18];
        g[0..8].copy_from_slice(b"NBDMAGIC");
        g[8..16].copy_from_slice(b"IHAVEOPT");
        g[16..18].copy_from_slice(&1u16.to_be_bytes()); // FIXED_NEWSTYLE
        server.write_all(&g).unwrap();

        // client flags
        let mut cf = [0u8; 4];
        server.read_exact(&mut cf).unwrap();

        // NBD_OPT_GO option header + data
        let mut h = [0u8; 16];
        server.read_exact(&mut h).unwrap();
        assert_eq!(
            u64::from_be_bytes(h[0..8].try_into().unwrap()),
            NBD_OPTS_MAGIC
        );
        assert_eq!(u32::from_be_bytes(h[8..12].try_into().unwrap()), NBD_OPT_GO);
        let len = u32::from_be_bytes(h[12..16].try_into().unwrap()) as usize;
        let mut d = vec![0u8; len];
        server.read_exact(&mut d).unwrap();
        // Validate the NBD_OPT_GO payload framing per spec:
        //   u32 name_len, name[name_len], u16 nr_info_requests.
        // (No leading export count — regression guard against the
        // NBD_REP_ERR_INVALID "Unexpected embedded NUL" bug.)
        assert!(d.len() >= 6, "OPT_GO payload too short: {} bytes", d.len());
        let nlen = u32::from_be_bytes(d[0..4].try_into().unwrap()) as usize;
        assert_eq!(nlen, 6, "export name length in OPT_GO");
        assert_eq!(&d[4..4 + nlen], b"export", "export name in OPT_GO");
        assert_eq!(
            u16::from_be_bytes(d[4 + nlen..6 + nlen].try_into().unwrap()),
            0,
            "number of info requests in OPT_GO"
        );
        assert_eq!(d.len(), 4 + nlen + 2, "no trailing bytes in OPT_GO payload");

        // NBD_REP_INFO (NBD_INFO_EXPORT) + NBD_REP_ACK
        let size: u64 = 4096 * 16;
        let trans_flags: u16 = (1 << 0) | (1 << 2); // HAS_FLAGS | SEND_FLUSH
        let mut info = Vec::new();
        info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        info.extend_from_slice(&size.to_be_bytes());
        info.extend_from_slice(&trans_flags.to_be_bytes());
        let mut r = Vec::new();
        r.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        r.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        r.extend_from_slice(&NBD_REP_INFO.to_be_bytes());
        r.extend_from_slice(&(info.len() as u32).to_be_bytes());
        r.extend_from_slice(&info);
        server.write_all(&r).unwrap();
        let mut ack = Vec::new();
        ack.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        ack.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        ack.extend_from_slice(&NBD_REP_ACK.to_be_bytes());
        ack.extend_from_slice(&0u32.to_be_bytes());
        server.write_all(&ack).unwrap();

        // one WRITE of "hello" at offset 100
        let mut req = [0u8; 28];
        server.read_exact(&mut req).unwrap();
        assert_eq!(
            u32::from_be_bytes(req[0..4].try_into().unwrap()),
            NBD_REQUEST_MAGIC
        );
        assert_eq!(
            u16::from_be_bytes(req[6..8].try_into().unwrap()),
            NBD_CMD_WRITE
        );
        let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        assert_eq!(u64::from_be_bytes(req[16..24].try_into().unwrap()), 100);
        assert_eq!(u32::from_be_bytes(req[24..28].try_into().unwrap()), 5);
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"hello");
        let mut rep = Vec::new();
        rep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        rep.extend_from_slice(&0u32.to_be_bytes());
        rep.extend_from_slice(&handle.to_be_bytes());
        server.write_all(&rep).unwrap();

        // one READ of 5 bytes at offset 100 — echo back "hello"
        server.read_exact(&mut req).unwrap();
        assert_eq!(
            u16::from_be_bytes(req[6..8].try_into().unwrap()),
            NBD_CMD_READ
        );
        let handle2 = u64::from_be_bytes(req[8..16].try_into().unwrap());
        assert_eq!(u32::from_be_bytes(req[24..28].try_into().unwrap()), 5);
        let mut rrep = Vec::new();
        rrep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        rrep.extend_from_slice(&0u32.to_be_bytes());
        rrep.extend_from_slice(&handle2.to_be_bytes());
        rrep.extend_from_slice(b"hello");
        server.write_all(&rrep).unwrap();

        // wait for the client's DISC (or EOF) so the thread can finish
        let _ = server.read_exact(&mut req);
    }

    /// Handshake, then read three WRITE requests and their payloads *before*
    /// replying at all — proving the client sent the whole batch up front. The
    /// replies are emitted in reverse order to exercise handle matching.
    fn run_batch_server(mut server: Half) {
        // greeting
        let mut g = [0u8; 18];
        g[0..8].copy_from_slice(b"NBDMAGIC");
        g[8..16].copy_from_slice(b"IHAVEOPT");
        g[16..18].copy_from_slice(&1u16.to_be_bytes());
        server.write_all(&g).unwrap();

        // client flags
        let mut cf = [0u8; 4];
        server.read_exact(&mut cf).unwrap();

        // NBD_OPT_GO option header + data
        let mut h = [0u8; 16];
        server.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes(h[12..16].try_into().unwrap()) as usize;
        let mut d = vec![0u8; len];
        server.read_exact(&mut d).unwrap();

        // NBD_REP_INFO (EXPORT) + ACK
        let size: u64 = 1 << 20;
        let trans_flags: u16 = (1 << 0) | (1 << 2);
        let mut info = Vec::new();
        info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        info.extend_from_slice(&size.to_be_bytes());
        info.extend_from_slice(&trans_flags.to_be_bytes());
        let mut r = Vec::new();
        r.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        r.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        r.extend_from_slice(&NBD_REP_INFO.to_be_bytes());
        r.extend_from_slice(&(info.len() as u32).to_be_bytes());
        r.extend_from_slice(&info);
        server.write_all(&r).unwrap();
        let mut ack = Vec::new();
        ack.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        ack.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        ack.extend_from_slice(&NBD_REP_ACK.to_be_bytes());
        ack.extend_from_slice(&0u32.to_be_bytes());
        server.write_all(&ack).unwrap();

        // Read all three WRITEs and their payloads before replying.
        let chunks: [&[u8]; 3] = [b"aaa", b"bbbb", b"c"];
        let mut handles = Vec::new();
        let mut offset = 0u64;
        for expected in chunks {
            let mut req = [0u8; 28];
            server.read_exact(&mut req).unwrap();
            assert_eq!(
                u16::from_be_bytes(req[6..8].try_into().unwrap()),
                NBD_CMD_WRITE
            );
            let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
            assert_eq!(u64::from_be_bytes(req[16..24].try_into().unwrap()), offset);
            assert_eq!(
                u32::from_be_bytes(req[24..28].try_into().unwrap()) as usize,
                expected.len()
            );
            let mut payload = vec![0u8; expected.len()];
            server.read_exact(&mut payload).unwrap();
            assert_eq!(&payload[..], expected);
            offset += expected.len() as u64;
            handles.push(handle);
        }

        // Reply out of order (reversed) — the client must match handles.
        for handle in handles.iter().rev() {
            let mut rep = Vec::new();
            rep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
            rep.extend_from_slice(&0u32.to_be_bytes());
            rep.extend_from_slice(&handle.to_be_bytes());
            server.write_all(&rep).unwrap();
        }

        // wait for the client's DISC (or EOF) so the thread can finish
        let mut req = [0u8; 28];
        let _ = server.read_exact(&mut req);
    }

    #[test]
    fn write_batch_pipelines_and_handles_out_of_order_replies() {
        let (mut client, server) = pair();
        let srv = thread::spawn(move || run_batch_server(server));

        let (size, read_only, can_flush) = negotiate(&mut client, "export").unwrap();
        let mut region: NbdRegion<Half> =
            NbdRegion::from_stream(client, size, read_only, can_flush);
        let chunks: [&[u8]; 3] = [b"aaa", b"bbbb", b"c"];
        region.write_chunks(&chunks).unwrap();

        // Drop first so NbdConn::drop sends DISC and the server can finish.
        drop(region);
        srv.join().unwrap();
    }

    /// Handshake, then expect exactly one coalesced WRITE of `"aaabbccc"` at
    /// offset 0 (the client folded three adjacent `write_at` calls into it),
    /// followed by a READ that must observe that data. Finally consume DISC.
    fn run_coalesce_server(mut server: Half) {
        // greeting
        let mut g = [0u8; 18];
        g[0..8].copy_from_slice(b"NBDMAGIC");
        g[8..16].copy_from_slice(b"IHAVEOPT");
        g[16..18].copy_from_slice(&1u16.to_be_bytes());
        server.write_all(&g).unwrap();

        // client flags
        let mut cf = [0u8; 4];
        server.read_exact(&mut cf).unwrap();

        // NBD_OPT_GO option header + data
        let mut h = [0u8; 16];
        server.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes(h[12..16].try_into().unwrap()) as usize;
        let mut d = vec![0u8; len];
        server.read_exact(&mut d).unwrap();

        // NBD_REP_INFO (EXPORT) + ACK
        let size: u64 = 4096;
        let trans_flags: u16 = (1 << 0) | (1 << 2);
        let mut info = Vec::new();
        info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        info.extend_from_slice(&size.to_be_bytes());
        info.extend_from_slice(&trans_flags.to_be_bytes());
        let mut r = Vec::new();
        r.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        r.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        r.extend_from_slice(&NBD_REP_INFO.to_be_bytes());
        r.extend_from_slice(&(info.len() as u32).to_be_bytes());
        r.extend_from_slice(&info);
        server.write_all(&r).unwrap();
        let mut ack = Vec::new();
        ack.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        ack.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        ack.extend_from_slice(&NBD_REP_ACK.to_be_bytes());
        ack.extend_from_slice(&0u32.to_be_bytes());
        server.write_all(&ack).unwrap();

        // Exactly one WRITE: the three adjacent writes coalesced.
        let mut req = [0u8; 28];
        server.read_exact(&mut req).unwrap();
        assert_eq!(
            u16::from_be_bytes(req[6..8].try_into().unwrap()),
            NBD_CMD_WRITE
        );
        let write_handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        assert_eq!(u64::from_be_bytes(req[16..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(req[24..28].try_into().unwrap()), 8);
        let mut payload = [0u8; 8];
        server.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"aaabbccc");
        let mut rep = Vec::new();
        rep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        rep.extend_from_slice(&0u32.to_be_bytes());
        rep.extend_from_slice(&write_handle.to_be_bytes());
        server.write_all(&rep).unwrap();

        // A READ of the same range must see the coalesced bytes.
        server.read_exact(&mut req).unwrap();
        assert_eq!(
            u16::from_be_bytes(req[6..8].try_into().unwrap()),
            NBD_CMD_READ
        );
        let read_handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        assert_eq!(u64::from_be_bytes(req[16..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(req[24..28].try_into().unwrap()), 8);
        let mut rrep = Vec::new();
        rrep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        rrep.extend_from_slice(&0u32.to_be_bytes());
        rrep.extend_from_slice(&read_handle.to_be_bytes());
        rrep.extend_from_slice(b"aaabbccc");
        server.write_all(&rrep).unwrap();

        // wait for DISC (or EOF)
        let _ = server.read_exact(&mut req);
    }

    #[test]
    fn write_at_coalesces_adjacent_blocks_and_read_flushes_them() {
        let (mut client, server) = pair();
        let srv = thread::spawn(move || run_coalesce_server(server));

        let (size, read_only, can_flush) = negotiate(&mut client, "export").unwrap();
        let region: NbdRegion<Half> = NbdRegion::from_stream(client, size, read_only, can_flush);
        // Three adjacent 4 KiB-block-sized writes must become one request...
        region.write_at(0, b"aaa").unwrap();
        region.write_at(3, b"bb").unwrap();
        region.write_at(5, b"ccc").unwrap();
        // ...and a read of the same range must flush it first, then see it.
        let mut out = [0u8; 8];
        region.read_at(0, &mut out).unwrap();
        assert_eq!(&out, b"aaabbccc");

        // Drop first so NbdConn::drop sends DISC and the server can finish.
        drop(region);
        srv.join().unwrap();
    }

    /// Handshake advertising no `SEND_FLUSH`, then expect the buffered write to
    /// be delivered by `sync_region` anyway, followed by DISC.
    fn run_noflush_server(mut server: Half) {
        let mut g = [0u8; 18];
        g[0..8].copy_from_slice(b"NBDMAGIC");
        g[8..16].copy_from_slice(b"IHAVEOPT");
        g[16..18].copy_from_slice(&1u16.to_be_bytes());
        server.write_all(&g).unwrap();

        let mut cf = [0u8; 4];
        server.read_exact(&mut cf).unwrap();

        let mut h = [0u8; 16];
        server.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes(h[12..16].try_into().unwrap()) as usize;
        let mut d = vec![0u8; len];
        server.read_exact(&mut d).unwrap();

        // No SEND_FLUSH: only HAS_FLAGS.
        let size: u64 = 4096;
        let trans_flags: u16 = 1 << 0;
        let mut info = Vec::new();
        info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        info.extend_from_slice(&size.to_be_bytes());
        info.extend_from_slice(&trans_flags.to_be_bytes());
        let mut r = Vec::new();
        r.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        r.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        r.extend_from_slice(&NBD_REP_INFO.to_be_bytes());
        r.extend_from_slice(&(info.len() as u32).to_be_bytes());
        r.extend_from_slice(&info);
        server.write_all(&r).unwrap();
        let mut ack = Vec::new();
        ack.extend_from_slice(&NBD_REP_MAGIC.to_be_bytes());
        ack.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        ack.extend_from_slice(&NBD_REP_ACK.to_be_bytes());
        ack.extend_from_slice(&0u32.to_be_bytes());
        server.write_all(&ack).unwrap();

        // The buffered write must still arrive, even though the export cannot
        // FLUSH.
        let mut req = [0u8; 28];
        server.read_exact(&mut req).unwrap();
        assert_eq!(
            u16::from_be_bytes(req[6..8].try_into().unwrap()),
            NBD_CMD_WRITE
        );
        let handle = u64::from_be_bytes(req[8..16].try_into().unwrap());
        assert_eq!(u64::from_be_bytes(req[16..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(req[24..28].try_into().unwrap()), 2);
        let mut payload = [0u8; 2];
        server.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"hi");
        let mut rep = Vec::new();
        rep.extend_from_slice(&NBD_SIMPLE_REPLY_MAGIC.to_be_bytes());
        rep.extend_from_slice(&0u32.to_be_bytes());
        rep.extend_from_slice(&handle.to_be_bytes());
        server.write_all(&rep).unwrap();

        let _ = server.read_exact(&mut req); // DISC
    }

    #[test]
    fn sync_region_drains_write_behind_without_server_flush_support() {
        let (mut client, server) = pair();
        let srv = thread::spawn(move || run_noflush_server(server));

        let (size, read_only, can_flush) = negotiate(&mut client, "export").unwrap();
        assert!(!can_flush);
        let region: NbdRegion<Half> = NbdRegion::from_stream(client, size, read_only, can_flush);
        region.write_at(0, b"hi").unwrap();
        region.sync_region().unwrap();

        drop(region);
        srv.join().unwrap();
    }

    #[test]
    fn write_behind_coalesces_adjacent_and_evicts_disjoint() {
        let mut wb = WriteBehind::default();
        // First write starts a run.
        let (ev, n) = wb.absorb(100, b"abc");
        assert!(ev.is_none());
        assert_eq!(n, 3);
        // Adjacent writes extend it without eviction.
        let (ev, n) = wb.absorb(103, b"de");
        assert!(ev.is_none());
        assert_eq!(n, 2);
        // A fully contained rewrite patches the run in place.
        let (ev, n) = wb.absorb(101, b"XY");
        assert!(ev.is_none());
        assert_eq!(n, 2);
        assert_eq!(wb.start, 100);
        assert_eq!(&wb.data, b"aXYde");
        // A disjoint write evicts the old run and starts a new one.
        let (ev, n) = wb.absorb(500, b"zz");
        assert_eq!(
            ev.as_ref().map(|(o, d)| (*o, d.clone())),
            Some((100, b"aXYde".to_vec()))
        );
        assert_eq!(n, 2);
        assert_eq!(wb.start, 500);
        assert_eq!(&wb.data, b"zz");
    }

    #[test]
    fn write_behind_evicts_a_full_run() {
        let mut wb = WriteBehind::default();
        let big = vec![7u8; WRITE_COALESCE_MAX];
        let (ev, n) = wb.absorb(0, &big);
        assert_eq!(n, WRITE_COALESCE_MAX);
        assert_eq!(
            ev.as_ref().map(|(o, d)| (*o, d.len())),
            Some((0, WRITE_COALESCE_MAX))
        );
        assert!(wb.data.is_empty());
    }

    #[test]
    fn write_behind_overlap_detection() {
        let mut wb = WriteBehind::default();
        assert!(!wb.overlaps(0, 1)); // empty never overlaps
        wb.absorb(100, b"abcd");
        assert!(wb.overlaps(100, 1));
        assert!(wb.overlaps(99, 2)); // touches the start
        assert!(wb.overlaps(103, 10)); // past the end
        assert!(!wb.overlaps(104, 10)); // immediately after
        assert!(!wb.overlaps(0, 100)); // immediately before
    }

    #[test]
    fn negotiates_handshake_and_roundtrips() {
        let (mut client, server) = pair();
        let srv = thread::spawn(move || run_mini_server(server));

        let (size, read_only, can_flush) = negotiate(&mut client, "export").unwrap();
        assert_eq!(size, 4096 * 16);
        assert!(!read_only);
        assert!(can_flush);

        let region: NbdRegion<Half> = NbdRegion::from_stream(client, size, read_only, can_flush);
        region.write_at(100, b"hello").unwrap();
        let mut out = [0u8; 5];
        region.read_at(100, &mut out).unwrap();
        assert_eq!(&out, b"hello");

        // Drop first so NbdConn::drop sends DISC and the server can finish.
        drop(region);
        srv.join().unwrap();
    }

    #[test]
    fn read_only_region_rejects_writes() {
        // A read-only region refuses writes without touching the network: the
        // check lives in the `BlockDevice::write_at` / `Write::write` impls.
        let (client, _server) = pair();
        let region: NbdRegion<Half> = NbdRegion::from_stream(client, 4096, true, false);
        assert!(!region.is_writable());
        let err = region.write_at(0, b"x").unwrap_err();
        assert!(matches!(err, fs_ext4::error::Error::ReadOnly), "{err:?}");
    }

    #[test]
    fn region_digest_is_none_without_side_channel() {
        // A plain NBD region has no cheap way to hash: reading the whole range
        // over the network would defeat the purpose, so region_digest returns
        // None and the install pipeline copies unconditionally.
        let (client, _server) = pair();
        let region: NbdRegion<Half> = NbdRegion::from_stream(client, 4096, false, false);
        assert_eq!(region.region_digest(4096).unwrap(), None);
    }

    #[test]
    fn region_digest_uses_side_channel_with_absolute_base() {
        // With a remote-digest side channel (ssh-install), region_digest
        // delegates to it — without touching the NBD connection — passing the
        // region's absolute base so a partition sub-region hashes the right
        // byte range of the underlying device.
        let (client, _server) = pair();
        let region: NbdRegion<Half> = NbdRegion::from_stream(client, 1 << 20, false, false)
            .with_remote_digest(|offset, size| {
                Ok(Some([
                    offset as u8,
                    (offset >> 8) as u8,
                    size as u8,
                    (size >> 8) as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    99,
                ]))
            });
        // Whole-export region: base 0.
        let d = region.region_digest(512).unwrap().unwrap();
        assert_eq!(d[0..4], [0, 0, 0, 2]); // offset=0, size=512
        assert_eq!(d[31], 99);

        // A sub-region at offset 4096 of size 8192 must hash that exact range.
        let sub = region.open_region(4096, 8192);
        let d = sub.region_digest(8192).unwrap().unwrap();
        assert_eq!(d[0..4], [0, 16, 0, 32]); // offset=4096 (0x1000), size=8192 (0x2000)
    }

    #[test]
    fn region_digest_side_channel_none_falls_back() {
        let (client, _server) = pair();
        let region: NbdRegion<Half> =
            NbdRegion::from_stream(client, 4096, false, false).with_remote_digest(|_, _| Ok(None));
        assert_eq!(region.region_digest(4096).unwrap(), None);
    }

    #[test]
    fn parses_tcp_urls() {
        let NbdTarget::Tcp { host, port, export } = parse_nbd_url("nbd://example.com/").unwrap()
        else {
            panic!("expected Tcp");
        };
        assert_eq!(host, "example.com");
        assert_eq!(port, 10809);
        assert_eq!(export, "");

        let NbdTarget::Tcp { host, port, export } =
            parse_nbd_url("nbd://example.com:10809/root").unwrap()
        else {
            panic!("expected Tcp");
        };
        assert_eq!(host, "example.com");
        assert_eq!(port, 10809);
        assert_eq!(export, "root");

        let NbdTarget::Tcp { export, .. } = parse_nbd_url("nbd+tcp://h:1234/a/b").unwrap() else {
            panic!("expected Tcp");
        };
        assert_eq!(export, "a/b");
    }

    #[test]
    fn parses_unix_urls() {
        let NbdTarget::Unix { socket, export } =
            parse_nbd_url("nbd+unix:///root?socket=/run/nbd.sock").unwrap()
        else {
            panic!("expected Unix");
        };
        assert_eq!(socket, PathBuf::from("/run/nbd.sock"));
        assert_eq!(export, "root");

        let NbdTarget::Unix { socket, export } =
            parse_nbd_url("nbd+unix://?socket=/tmp/nbd.sock").unwrap()
        else {
            panic!("expected Unix");
        };
        assert_eq!(socket, PathBuf::from("/tmp/nbd.sock"));
        assert_eq!(export, "");
    }

    #[test]
    fn percent_decodes_export_names() {
        let NbdTarget::Tcp { export, .. } =
            parse_nbd_url("nbd://h/with%20space/and%2Fslash").unwrap()
        else {
            panic!("expected Tcp");
        };
        assert_eq!(export, "with space/and/slash");
    }
}
