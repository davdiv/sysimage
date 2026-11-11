//! Tiny `senc` CLI: encrypt and decrypt SENC envelopes.
//!
//! Usage mirrors `systemd-creds encrypt|decrypt` so it composes well with
//! systemd units: positional `INPUT`/`OUTPUT`, `-` meaning stdin/stdout, and
//! no interactive prompts. Key components are supplied in order via
//! `--key-file`, `--key-fd`, or `--key-hex` and combined with HKDF-SHA256
//! (see [`senc::derive_key`]). Repeated key options are **concatenated** in
//! order, so `-k a -k b` is equivalent to `-k ab`.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use lexopt::Arg;
use lexopt::prelude::*;
use zeroize::Zeroizing;

/// Exit code for a usage or I/O failure.
const EXIT_FAILURE: u8 = 1;
/// Exit code for an authentication failure (wrong key / corrupt data).
const EXIT_AUTH: u8 = 2;

/// A fatal error with the process exit code to use.
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_FAILURE,
            message: message.into(),
        }
    }

    fn io(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_FAILURE,
            message: message.into(),
        }
    }

    fn auth(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_AUTH,
            message: message.into(),
        }
    }
}

/// Map a SENC core error onto the CLI failure taxonomy.
fn from_senc(err: senc::Error) -> Failure {
    match err {
        senc::Error::AuthenticationFailed => Failure::auth(err.to_string()),
        other => Failure::io(other.to_string()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

/// One ordered key component source.
enum KeySource {
    /// Raw file bytes, used exactly as read (`-` = stdin).
    File(PathBuf),
    /// Bytes read from an already-open file descriptor (systemd-friendly).
    Fd(i32),
    /// Inline hex-encoded bytes (tests/CI).
    Hex(Vec<u8>),
}

struct Args {
    mode: Mode,
    input: OsString,
    output: OsString,
    keys: Vec<KeySource>,
    algorithm: senc::Algorithm,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("error: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

fn run() -> Result<(), Failure> {
    let args = parse_args()?;

    let input_is_stdin = args.input.as_os_str() == OsStr::new("-");
    let key_uses_stdin = args
        .keys
        .iter()
        .any(|k| matches!(k, KeySource::File(p) if p.as_os_str() == OsStr::new("-")));
    if input_is_stdin && key_uses_stdin {
        return Err(Failure::usage(
            "stdin cannot be both the input and a key component; use --key-fd 0",
        ));
    }

    // Resolve the ordered key components (raw bytes, exactly as read).
    if args.keys.is_empty() {
        return Err(Failure::usage(
            "at least one key component is required (--key-file/--key-fd/--key-hex)",
        ));
    }
    let mut parts: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(args.keys.len());
    let mut stdin_consumed = false;
    for source in &args.keys {
        let bytes = match source {
            KeySource::File(path) if path.as_os_str() == OsStr::new("-") => {
                if stdin_consumed {
                    return Err(Failure::usage("stdin can supply at most one key component"));
                }
                stdin_consumed = true;
                read_stdin()?
            }
            KeySource::File(path) => read_file(path)?,
            KeySource::Fd(fd) => read_fd(*fd)?,
            KeySource::Hex(bytes) => bytes.clone(),
        };
        parts.push(Zeroizing::new(bytes));
    }

    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let key = Zeroizing::new(senc::derive_key(&refs).map_err(from_senc)?);

    // Read the input (plaintext when encrypting, envelope when decrypting).
    // Treated as potentially sensitive in both directions and scrubbed.
    let input = if input_is_stdin {
        Zeroizing::new(read_stdin()?)
    } else {
        Zeroizing::new(read_file(Path::new(&args.input))?)
    };

    match args.mode {
        Mode::Encrypt => {
            let envelope =
                senc::encrypt(&input[..], &key[..], args.algorithm).map_err(from_senc)?;
            write_output(&args.output, &envelope)
        }
        Mode::Decrypt => {
            // Keep the plaintext in a zeroizing buffer: it is scrubbed after
            // it has been written out.
            let plaintext = Zeroizing::new(senc::decrypt(&input[..], &key[..]).map_err(from_senc)?);
            write_output(&args.output, &plaintext[..])
        }
    }
}

fn parse_args() -> Result<Args, Failure> {
    let mut parser = lexopt::Parser::from_env();

    // The first argument must be the subcommand.
    let mode = match parser.next().map_err(parse_err)? {
        Some(Arg::Value(v)) => match v.to_str() {
            Some("encrypt") => Mode::Encrypt,
            Some("decrypt") => Mode::Decrypt,
            _ => {
                return Err(Failure::usage(format!(
                    "expected subcommand `encrypt` or `decrypt`, got {}",
                    v.to_string_lossy()
                )));
            }
        },
        Some(Arg::Short('h')) | Some(Arg::Long("help")) => {
            print_help();
            std::process::exit(0);
        }
        Some(Arg::Short('V')) | Some(Arg::Long("version")) => {
            print_version();
            std::process::exit(0);
        }
        _ => return Err(Failure::usage("expected subcommand `encrypt` or `decrypt`")),
    };

    let mut keys: Vec<KeySource> = Vec::new();
    let mut algorithm = senc::Algorithm::Aes256Gcm;
    let mut output_flag: Option<OsString> = None;
    let mut positionals: Vec<OsString> = Vec::new();

    while let Some(arg) = parser.next().map_err(parse_err)? {
        match arg {
            Short('k') | Long("key-file") => {
                keys.push(KeySource::File(PathBuf::from(
                    parser.value().map_err(parse_err)?,
                )));
            }
            Long("key-fd") => {
                let v = parser.value().map_err(parse_err)?;
                let fd: i32 = v
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Failure::usage("--key-fd expects an integer file descriptor"))?;
                keys.push(KeySource::Fd(fd));
            }
            Long("key-hex") => {
                let v = parser.value().map_err(parse_err)?;
                let bytes = hex_decode(&v.to_string_lossy())
                    .map_err(|e| Failure::usage(format!("invalid --key-hex: {e}")))?;
                keys.push(KeySource::Hex(bytes));
            }
            Short('o') | Long("output") => {
                output_flag = Some(parser.value().map_err(parse_err)?);
            }
            Long("algorithm") => {
                let v = parser.value().map_err(parse_err)?;
                algorithm = senc::Algorithm::parse(&v.to_string_lossy())
                    .map_err(|e| Failure::usage(e.to_string()))?;
            }
            Short('h') | Long("help") => {
                print_help();
                std::process::exit(0);
            }
            Short('V') | Long("version") => {
                print_version();
                std::process::exit(0);
            }
            Value(v) => positionals.push(v),
            other => return Err(Failure::usage(other.unexpected().to_string())),
        }
    }

    let mut input = OsString::from("-");
    let mut output = OsString::from("-");
    match positionals.len() {
        0 => {
            if let Some(o) = output_flag {
                output = o;
            }
        }
        1 => {
            input = positionals.remove(0);
            if let Some(o) = output_flag {
                output = o;
            }
        }
        2 => {
            if output_flag.is_some() {
                return Err(Failure::usage(
                    "output given both as a positional argument and --output",
                ));
            }
            input = positionals[0].clone();
            output = positionals[1].clone();
        }
        _ => return Err(Failure::usage("too many positional arguments")),
    }

    Ok(Args {
        mode,
        input,
        output,
        keys,
        algorithm,
    })
}

fn parse_err(err: lexopt::Error) -> Failure {
    Failure::usage(err.to_string())
}

fn read_stdin() -> Result<Vec<u8>, Failure> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| Failure::io(format!("failed to read stdin: {e}")))?;
    Ok(buf)
}

fn read_file(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| Failure::io(format!("failed to read {}: {e}", path.display())))
}

#[cfg(unix)]
fn read_fd(fd: i32) -> Result<Vec<u8>, Failure> {
    // Read through the fd symlink so we borrow (never close) the descriptor.
    // systemd images normally have /dev/fd; fall back to /proc/self/fd.
    match std::fs::read(format!("/dev/fd/{fd}")) {
        Ok(bytes) => Ok(bytes),
        Err(_) => std::fs::read(format!("/proc/self/fd/{fd}"))
            .map_err(|e| Failure::io(format!("failed to read fd {fd}: {e}"))),
    }
}

#[cfg(not(unix))]
fn read_fd(_fd: i32) -> Result<Vec<u8>, Failure> {
    Err(Failure::io("--key-fd is only supported on unix"))
}

/// Counter for unique temporary output file names.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` (or stdout when `path` is `-`).
///
/// The destination is always created with mode `0600` (readable and writable
/// only by the current user, for both encrypted envelopes and decrypted
/// plaintext) and the write is atomic (temp file + rename in the same
/// directory) so a partial or world-readable secret never lands. Missing
/// parent directories are created as needed.
fn write_output(path: &OsStr, data: &[u8]) -> Result<(), Failure> {
    if path == OsStr::new("-") {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(data)
            .and_then(|()| stdout.flush())
            .map_err(|e| Failure::io(format!("failed to write stdout: {e}")))?;
        return Ok(());
    }

    let path = Path::new(path);
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    create_output_dir(dir)?;

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".senc-{}-{n}.tmp", std::process::id()));

        let write_res = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_res {
            let _ = std::fs::remove_file(&tmp);
            return Err(Failure::io(format!(
                "failed to write {}: {e}",
                path.display()
            )));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Failure::io(format!(
                "failed to write {}: {e}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .map_err(|e| Failure::io(format!("failed to write {}: {e}", path.display())))?;
    }
    Ok(())
}

/// Create the output directory `dir` and any missing ancestors.
///
/// Newly created directories are owner-only (`0700`) on unix so the path to a
/// secret is not world-traversable; existing directories are left untouched.
fn create_output_dir(dir: &Path) -> Result<(), Failure> {
    if dir.as_os_str().is_empty() || dir == Path::new(".") {
        return Ok(());
    }

    #[cfg(unix)]
    let result = {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    };
    #[cfg(not(unix))]
    let result = std::fs::create_dir_all(dir);

    result.map_err(|e| {
        Failure::io(format!(
            "failed to create output directory {}: {e}",
            dir.display()
        ))
    })
}

fn print_version() {
    println!("senc {}", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    println!(
        "senc {version} - encrypt/decrypt SENC device-bound envelopes

USAGE:
    senc encrypt [OPTIONS] [INPUT] [OUTPUT]
    senc decrypt [OPTIONS] [INPUT] [OUTPUT]

    INPUT is the plaintext (encrypt) or envelope (decrypt); \"-\" means stdin
    (the default). OUTPUT is the envelope (encrypt) or plaintext (decrypt);
    \"-\" means stdout (the default). Missing parent directories of OUTPUT are
    created, and a file OUTPUT is always created with mode 0600 (owner-only).

KEY OPTIONS (repeatable; at least one required):
    -k, --key-file PATH   Use the exact bytes of PATH as a key component.
                          \"-\" reads one component from stdin.
        --key-fd FD       Use the bytes of an already-open file descriptor.
        --key-hex HEX     Use inline hex-decoded bytes (tests/CI).

OTHER OPTIONS:
        --algorithm NAME  AEAD algorithm (default: aes-256-gcm).
    -o, --output PATH     Output path (alternative to the positional OUTPUT).
    -h, --help            Print this help and exit.
    -V, --version         Print version and exit.

Key components are concatenated in order and combined with HKDF-SHA256 into the
32-byte envelope key, so repeated options are concatenable: `-k a -k b` is
equivalent to `-k ab` (the concatenation of the two components).

EXIT STATUS:
    0  success
    1  usage or I/O error
    2  authentication failure (wrong key or corrupted data)",
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Decode a hex string (whitespace around it is ignored).
fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let s = input.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or_else(|| format!("invalid hex digit at byte {i}"))?;
        let lo =
            hex_val(bytes[i + 1]).ok_or_else(|| format!("invalid hex digit at byte {}", i + 1))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
