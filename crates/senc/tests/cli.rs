//! Integration tests for the standalone `senc` binary.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("senc-cli-{}-{n}", std::process::id()));
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

fn senc() -> &'static str {
    env!("CARGO_BIN_EXE_senc")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

/// Run the binary, optionally feeding `stdin`, returning (exit code, stdout, stderr).
fn run(args: &[&str], stdin: Option<&[u8]>) -> (i32, Vec<u8>, Vec<u8>) {
    let mut child = Command::new(senc())
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn senc");
    if let Some(data) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait senc");
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

#[test]
fn file_round_trip() {
    let dir = TempDir::new();
    let plaintext = b"top-secret-key-material".as_slice();
    write(dir.path(), "plain", plaintext);
    write(dir.path(), "k1", b"component-one");
    write(dir.path(), "k2", b"component-two");
    let enc = dir.path().join("cred.enc");

    let (code, _, err) = run(
        &[
            "encrypt",
            "-k",
            dir.path().join("k1").to_str().unwrap(),
            "-k",
            dir.path().join("k2").to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));
    let envelope = fs::read(&enc).unwrap();
    assert_eq!(&envelope[..4], b"SENC");

    let (code, out, err) = run(
        &[
            "decrypt",
            "-k",
            dir.path().join("k1").to_str().unwrap(),
            "-k",
            dir.path().join("k2").to_str().unwrap(),
            enc.to_str().unwrap(),
            "-",
        ],
        None,
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(out, plaintext);
}

#[test]
fn stdin_stdout_round_trip() {
    let dir = TempDir::new();
    write(dir.path(), "k1", b"aaa");
    write(dir.path(), "k2", b"bbb");
    let k1 = dir.path().join("k1");
    let k2 = dir.path().join("k2");
    let plaintext = b"piped plaintext\nwith two lines";

    let (code, ciphertext, err) = run(
        &[
            "encrypt",
            "-k",
            k1.to_str().unwrap(),
            "-k",
            k2.to_str().unwrap(),
            "-",
            "-",
        ],
        Some(plaintext),
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(&ciphertext[..4], b"SENC");

    let (code, out, err) = run(
        &[
            "decrypt",
            "-k",
            k1.to_str().unwrap(),
            "-k",
            k2.to_str().unwrap(),
            "-",
            "-",
        ],
        Some(&ciphertext),
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(out, plaintext);
}

#[test]
fn repeated_key_files_concatenate() {
    // `-k a -k b` must be equivalent to a single `-k ab` whose bytes are the
    // concatenation of the two: an envelope made with two key files decrypts
    // with one file holding their concatenation, and vice versa.
    let dir = TempDir::new();
    write(dir.path(), "plain", b"concatenated-secret");
    let a = write(dir.path(), "a", b"aaa");
    let b = write(dir.path(), "b", b"bbb");
    let ab = write(dir.path(), "ab", b"aaabbb");
    let enc = dir.path().join("e");

    let (code, _, err) = run(
        &[
            "encrypt",
            "-k",
            a.to_str().unwrap(),
            "-k",
            b.to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));

    let (code, out, err) = run(
        &[
            "decrypt",
            "-k",
            ab.to_str().unwrap(),
            enc.to_str().unwrap(),
            "-",
        ],
        None,
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(out, b"concatenated-secret");
}

#[test]
fn key_order_matters_and_wrong_key_exits_2() {
    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret");
    write(dir.path(), "k1", b"one");
    write(dir.path(), "k2", b"two");
    let k1 = dir.path().join("k1");
    let k2 = dir.path().join("k2");
    let enc = dir.path().join("e");

    let (code, _, err) = run(
        &[
            "encrypt",
            "-k",
            k1.to_str().unwrap(),
            "-k",
            k2.to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));

    // Reversed component order must fail authentication (exit code 2).
    let (code, _, err) = run(
        &[
            "decrypt",
            "-k",
            k2.to_str().unwrap(),
            "-k",
            k1.to_str().unwrap(),
            enc.to_str().unwrap(),
            "-",
        ],
        None,
    );
    assert_eq!(
        code,
        2,
        "wrong key order must exit 2: {}",
        String::from_utf8_lossy(&err)
    );
}

#[test]
fn missing_key_is_a_usage_error() {
    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret");
    let (code, _, err) = run(
        &["encrypt", dir.path().join("plain").to_str().unwrap(), "-"],
        None,
    );
    assert_eq!(code, 1);
    assert!(
        String::from_utf8_lossy(&err).contains("key component"),
        "stderr should explain the missing key"
    );
}

#[test]
fn version_prints_name() {
    let (code, out, _) = run(&["--version"], None);
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&out).starts_with("senc "));
}

#[test]
fn key_fd_reads_a_component_from_an_open_fd() {
    // `--key-fd 0` reads one key component from stdin (fd 0).
    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret-data");
    write(dir.path(), "k2", b"second");
    let k2 = dir.path().join("k2");
    let enc = dir.path().join("e");

    let (code, _, err) = run(
        &[
            "encrypt",
            "--key-fd",
            "0",
            "-k",
            k2.to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        Some(b"first"),
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(&fs::read(&enc).unwrap()[..4], b"SENC");

    let (code, out, err) = run(
        &[
            "decrypt",
            "--key-fd",
            "0",
            "-k",
            k2.to_str().unwrap(),
            enc.to_str().unwrap(),
            "-",
        ],
        Some(b"first"),
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(out, b"secret-data");
}

#[cfg(unix)]
#[test]
fn decrypt_output_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret");
    write(dir.path(), "k", b"key");
    let k = dir.path().join("k");
    let enc = dir.path().join("e");
    let out = dir.path().join("out");

    let (code, _, _) = run(
        &[
            "encrypt",
            "-k",
            k.to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0);

    let (code, _, err) = run(
        &[
            "decrypt",
            "-k",
            k.to_str().unwrap(),
            enc.to_str().unwrap(),
            out.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(fs::read(&out).unwrap(), b"secret");
    let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "decrypted plaintext must be mode 0600");
}

#[cfg(unix)]
#[test]
fn encrypt_output_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret");
    write(dir.path(), "k", b"key");
    let enc = dir.path().join("e");

    let (code, _, err) = run(
        &[
            "encrypt",
            "-k",
            dir.path().join("k").to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));
    let mode = fs::metadata(&enc).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "encrypted envelope must be mode 0600");
}

#[test]
fn creates_missing_parent_directories() {
    let dir = TempDir::new();
    write(dir.path(), "plain", b"secret");
    write(dir.path(), "k", b"key");
    let k = dir.path().join("k");
    // Neither `nested/` nor its children exist yet.
    let enc = dir.path().join("nested/a/b/out.enc");
    let out = dir.path().join("nested/a/b/out.plain");

    let (code, _, err) = run(
        &[
            "encrypt",
            "-k",
            k.to_str().unwrap(),
            dir.path().join("plain").to_str().unwrap(),
            enc.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(&fs::read(&enc).unwrap()[..4], b"SENC");

    let (code, _, err) = run(
        &[
            "decrypt",
            "-k",
            k.to_str().unwrap(),
            enc.to_str().unwrap(),
            out.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, 0, "decrypt failed: {}", String::from_utf8_lossy(&err));
    assert_eq!(fs::read(&out).unwrap(), b"secret");
}
