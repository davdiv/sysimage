//! External-process helper.
//!
//! Logs the command line, streams stdout and stderr to the console live as the
//! process runs, and returns trimmed stdout. Non-zero exit becomes an error.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use crate::error::{Error, Result};

/// Run `args[0]` with `args[1..]`, returning trimmed stdout.
pub fn exec(args: &[&str]) -> Result<String> {
    exec_in(args, None, None)
}

/// Run a command with an optional working directory and stdin.
///
/// Both stdout and stderr are tee'd to the console in real time so that
/// long-running commands (e.g. `podman build`) are visible as they run. stdout
/// is also captured so callers that need the program's output (mount paths,
/// image IDs, device sizes, …) still get it back.
pub fn exec_in(args: &[&str], cwd: Option<&Path>, stdin: Option<&[u8]>) -> Result<String> {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    cmd.stdin(match stdin {
        Some(_) => Stdio::piped(),
        None => Stdio::null(),
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    println!("[cmd] $ {}", args.join(" "));
    let _ = std::io::stdout().flush();
    let mut child = cmd.spawn()?;
    if let Some(data) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| Error::msg("could not open stdin"))?
            .write_all(data)?;
    }

    // Stream stdout and stderr to the console live, while capturing stdout so we
    // can return it. Each pipe is drained on its own thread; the captured bytes
    // are sent back over a channel.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // Two slots: 0 = stdout, 1 = stderr. Each pipe is drained on its own thread,
    // tee'd to the console live, and captured so we can both return stdout and
    // include stderr in any error message.
    let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>();
    let stdout_tx = tx.clone();
    let stdout_handle = stdout.map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut captured = Vec::new();
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = std::io::stdout().write_all(&buf[..n]);
                        let _ = std::io::stdout().flush();
                        captured.extend_from_slice(&buf[..n]);
                    }
                    Err(_) => break,
                }
            }
            let _ = stdout_tx.send((0, captured));
        })
    });
    let stderr_tx = tx.clone();
    let stderr_handle = stderr.map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut captured = Vec::new();
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = std::io::stderr().write_all(&buf[..n]);
                        let _ = std::io::stderr().flush();
                        captured.extend_from_slice(&buf[..n]);
                    }
                    Err(_) => break,
                }
            }
            let _ = stderr_tx.send((1, captured));
        })
    });
    drop(tx);

    let status = child.wait()?;
    if let Some(h) = stdout_handle {
        let _ = h.join();
    }
    if let Some(h) = stderr_handle {
        let _ = h.join();
    }

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    for (slot, data) in rx.iter() {
        match slot {
            0 => stdout_buf = data,
            1 => stderr_buf = data,
            _ => {}
        }
    }

    if !status.success() {
        let msg = if stderr_buf.is_empty() {
            String::from_utf8_lossy(&stdout_buf).trim().to_string()
        } else {
            String::from_utf8_lossy(&stderr_buf).trim().to_string()
        };
        return Err(Error::msg(format!(
            "Process exited with {}: {}",
            status, msg
        )));
    }
    Ok(String::from_utf8_lossy(&stdout_buf).trim().to_string())
}
