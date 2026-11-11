//! Real `qemu-nbd` integration tests for the pure-Rust NBD client
//! ([`sysimage::nbd::NbdRegion`]).
//!
//! These tests spawn an actual `qemu-nbd` server on a Unix-domain socket and
//! drive the client handshake + I/O against it, exercising the same code path
//! a user gets with `--disk boot=nbd+unix://…`. They are skipped automatically
//! when `qemu-nbd` is not on `PATH`, so they run in dev/CI environments that
//! have QEMU installed but don't break bare `cargo test` elsewhere.
//!
//! Why a real server (on top of the in-memory loopback test in `install.rs`):
//! the in-memory server is a hand-rolled mirror of the protocol and can drift
//! from a real implementation. Pointing the client at `qemu-nbd` validates the
//! exact newstyle-fixed handshake framing (`NBD_OPT_GO` payload, client flags,
//! simple-reply transmission phase) against the reference NBD server — and
//! guards against the class of "works against our fake, fails against qemu"
//! regressions.

mod common;

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sysimage::blockfile::BlockRegion;
use sysimage::nbd::NbdRegion;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-nbdqemu-{}-{n}", std::process::id()));
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

/// A running `qemu-nbd` server plus the temp files it owns. Killed and cleaned
/// up on drop so a panicking test never leaves a stale server bound to a
/// socket (which would shadow later runs).
struct QemuNbd {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
    image: PathBuf,
    log: PathBuf,
}

impl QemuNbd {
    /// Start `qemu-nbd` serving `image` (a pre-created raw file of `image_size`
    /// bytes) over a fresh Unix socket, optionally under a named export
    /// (`--export-name`); `None` selects the default empty-name export.
    ///
    /// `--persistent` keeps the server up across the (single) client connection
    /// so we always own a live process to kill on drop; `--fork` is *not* used
    /// so the [`Child`] handle is the server itself.
    fn start(export_name: Option<&str>, image_size: u64) -> Option<Self> {
        // The server owns its own temp dir (kept alive until the server is
        // dropped) so the socket and image are *not* removed the instant this
        // constructor returns — a plain auto-cleaning TempDir would unlink them
        // before the client connects.
        let dir = {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("sysimg-nbdqemu-server-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            p
        };
        let socket = dir.join("nbd.sock");
        let image = dir.join("disk.img");
        let log = dir.join("qemu-nbd.log");

        // Pre-create a sparse raw image of the requested size.
        let f = fs::File::create(&image).unwrap();
        f.set_len(image_size).unwrap();
        drop(f);

        let log_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log)
            .unwrap();

        let mut cmd = Command::new("qemu-nbd");
        cmd.arg("--socket")
            .arg(&socket)
            .arg("--persistent")
            .arg("-f")
            .arg("raw")
            .arg(&image);
        if let Some(name) = export_name {
            cmd.arg("--export-name").arg(name);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file);

        let child = cmd.spawn().ok()?;
        let mut server = Self {
            child,
            dir,
            socket,
            image,
            log,
        };

        // Wait for the socket to appear (qemu-nbd binds it before serving).
        let started = server.wait_for_socket(Duration::from_secs(5));
        if !started {
            let _ = server.child.kill();
            let _ = server.child.wait();
            // Surface qemu-nbd's own diagnostic if it failed to bind.
            let log_contents = fs::read_to_string(&server.log).unwrap_or_default();
            panic!(
                "qemu-nbd did not create socket within 5s.\n--- qemu-nbd log ---\n{log_contents}"
            );
        }
        Some(server)
    }

    /// Poll until the Unix socket file exists.
    fn wait_for_socket(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if fs::metadata(&self.socket)
                .map(|m| {
                    use std::os::unix::fs::FileTypeExt;
                    m.file_type().is_socket()
                })
                .unwrap_or(false)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Build an `nbd+unix:` URL selecting this socket. An empty `export` requests
    /// the default (empty-name) export; a non-empty one selects `--export-name`.
    fn url(&self, export: &str) -> String {
        if export.is_empty() {
            format!("nbd+unix://?socket={}", self.socket.display())
        } else {
            format!("nbd+unix:///{export}?socket={}", self.socket.display())
        }
    }
}

impl Drop for QemuNbd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Remove the whole temp tree (socket, image, log) — best effort.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Open the export, optionally retrying briefly: on a loaded machine the
/// server may not be accepting connections the instant the socket file exists.
fn open_nbd(server: &QemuNbd, export: &str) -> NbdRegion {
    let url = server.url(export);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match NbdRegion::open(&url) {
            Ok(region) => return region,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("NbdRegion::open({url}) failed: {e}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[test]
fn nbd_qemu_roundtrip_default_export() {
    skip_if_missing!("qemu-nbd");
    let server = QemuNbd::start(None, 4 * 1024 * 1024).expect("qemu-nbd started");

    let mut region = open_nbd(&server, "");

    // Writes at a non-zero offset (the common case for the install pipeline).
    region.seek(SeekFrom::Start(100)).unwrap();
    region.write_all(b"hello qemu-nbd").unwrap();
    region.flush().unwrap();

    region.seek(SeekFrom::Start(100)).unwrap();
    let mut buf = vec![0u8; b"hello qemu-nbd".len()];
    region.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello qemu-nbd");

    // Writes at offset 0 (block 0) — GPT protective MBR territory. qemu-nbd
    // with `-f raw` must allow and persist these (regression guard).
    region.seek(SeekFrom::Start(0)).unwrap();
    region.write_all(b"EFI PART").unwrap();
    region.flush().unwrap();
    region.seek(SeekFrom::Start(0)).unwrap();
    let mut sig = [0u8; 8];
    region.read_exact(&mut sig).unwrap();
    assert_eq!(&sig, b"EFI PART");

    // The reported export size matches the image we created.
    let size = region.region_size();
    assert_eq!(size, 4 * 1024 * 1024);

    // Dropping the region sends NBD_CMD_DISC; qemu-nbd (--persistent) keeps
    // serving, so the Drop guard still has a live process to kill.
    drop(region);
}

#[test]
fn nbd_qemu_roundtrip_named_export() {
    skip_if_missing!("qemu-nbd");
    // Serve under the named export "root" — the form a user gets with
    // `qemu-nbd -x root …` and connects to via `nbd+unix:///root?socket=…`.
    let server = QemuNbd::start(Some("root"), 4 * 1024 * 1024).expect("qemu-nbd started");

    let mut region = open_nbd(&server, "root");
    region.seek(SeekFrom::Start(2048)).unwrap();
    region.write_all(b"named-export-works").unwrap();
    region.flush().unwrap();

    region.seek(SeekFrom::Start(2048)).unwrap();
    let mut buf = vec![0u8; b"named-export-works".len()];
    region.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"named-export-works");
}

#[test]
fn nbd_qemu_unknown_export_is_rejected() {
    skip_if_missing!("qemu-nbd");
    // Server only exposes the named export "root"; asking for the default
    // (empty-name) export must fail fast with NBD_REP_ERR_UNKNOWN
    // ("export '' not present") rather than hanging. This is exactly the
    // failure mode a user hits when they run `qemu-nbd -x image …` but connect
    // with a bare `nbd://host:port` (no export name) — so the test both
    // documents the cause and pins the error message.
    let server = QemuNbd::start(Some("root"), 4 * 1024 * 1024).expect("qemu-nbd started");

    let url = server.url("");
    let err = NbdRegion::open(&url)
        .err()
        .expect("connecting to a missing export should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("not present") || msg.contains("unknown") || msg.contains("rejected"),
        "expected an export-not-present error, got: {msg}"
    );
}

#[test]
fn installs_gpt_over_qemu_nbd() {
    skip_if_missing!("qemu-nbd");

    let workdir = TempDir::new();
    let rootfs = workdir.path().join("rootfs");
    fs::create_dir_all(rootfs.join("etc")).unwrap();
    fs::write(
        rootfs.join("etc").join("passwd"),
        "root:x:0:0:root:/root:/bin/sh\n",
    )
    .unwrap();
    fs::write(rootfs.join("hello.txt"), "hello install\n").unwrap();
    let output = workdir.path().join("output");
    let temp = workdir.path().join("temp");

    let config = format!(
        r#"
name: nbdqemu
version: "1"
arch: x86_64
input: {rootfs}
outputDirectory: {output}
tempDirectory: {temp}
build:
  erofs:
    rootfs:
      input:
        - destination: ""
          input: "."
  veritytab:
    default: {{}}
disk:
  boot:
    type: gpt
    partitions:
      - name: root
        type: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        content:
          type: image
          input: build:erofs:rootfs
erofs:
  blockSize: 4096
  timestamp: 1700000000000
dmVerity:
  dataBlockSize: 4096
  hashBlockSize: 4096
  salt: 0102030405
"#,
        rootfs = rootfs.display(),
        output = output.display(),
        temp = temp.display(),
    );
    let config_path = workdir.path().join("sysimage.config.yml");
    fs::write(&config_path, &config).unwrap();

    sysimage::build::build_from_file(&config_path).expect("build should succeed");

    let manifest = sysimage::manifest::read_manifest(sysimage::manifest::ReadManifestConfig {
        config: &config_path,
        manifest: None,
    })
    .expect("read manifest");

    // 16 MiB is comfortably larger than this single-partition disk's minimum.
    const EXPORT_SIZE: u64 = 16 * 1024 * 1024;
    let server = QemuNbd::start(Some("root"), EXPORT_SIZE).expect("qemu-nbd started");

    // Run the generic install pipeline over the real NBD export. The pipeline
    // only needs a `BlockRegion`; `NbdRegion` is one, so the whole GPT write +
    // EROFS image copy happens over the network exactly as `--disk
    // boot=nbd+unix:///root?socket=…` would do from the CLI.
    let region = open_nbd(&server, "root");

    let mut ctx = sysimage::install::InstallContext::new(
        manifest.manifest.clone(),
        manifest.manifest_directory.clone(),
        true,
        std::collections::BTreeMap::new(),
    );
    let regions: std::collections::BTreeMap<String, NbdRegion> =
        std::collections::BTreeMap::from([("boot".to_string(), region)]);
    let fresh_disks = std::collections::BTreeMap::new();
    sysimage::install::install_regions(&mut ctx, regions, fresh_disks)
        .expect("install over qemu-nbd should succeed");

    // The export's backing file now holds the installed disk. Re-open the raw
    // image directly (qemu-nbd wrote through to it) and verify the GPT.
    let mut f = fs::File::open(&server.image).unwrap();
    let mut sig = [0u8; 8];
    f.seek(SeekFrom::Start(512)).unwrap();
    f.read_exact(&mut sig).unwrap();
    assert_eq!(
        &sig, b"EFI PART",
        "GPT signature missing in qemu-nbd backing file"
    );

    let mut header = [0u8; 92];
    f.seek(SeekFrom::Start(512)).unwrap();
    f.read_exact(&mut header).unwrap();
    let first_usable = u64::from_le_bytes(header[40..48].try_into().unwrap());
    let root_offset = first_usable * 512;
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::Start(root_offset + 1024)).unwrap();
    f.read_exact(&mut magic).unwrap();
    assert_eq!(
        u32::from_le_bytes(magic),
        0xe0f5e1e2,
        "root partition is not an EROFS image after install over qemu-nbd"
    );
}
