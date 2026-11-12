//! Build script: embed the git commit SHA so `sysimage version` can report it.
//!
//! The SHA is exposed to the crate as the `SYSIMAGE_GIT_SHA` environment
//! variable (read with `option_env!` in `src/main.rs`). Outside a git checkout
//! (e.g. a packaged tarball) the variable is set to `"unknown"` so the build
//! never fails just because `git` or `.git` is unavailable.

use std::path::PathBuf;
use std::process::Command;

/// Run `git <args>` and return its trimmed stdout, or `None` on failure.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!stdout.is_empty()).then_some(stdout)
}

fn main() {
    // Re-run the script when the commit-ish can have moved. `.git/HEAD` covers
    // checkouts (it holds either a raw SHA or `ref: refs/heads/…`); the
    // checked-out branch's ref file covers *commits* on that branch, which do
    // not touch HEAD at all; `packed-refs` covers the rare repack. A ref path
    // that does not exist yet (e.g. a branch ref that is still packed) makes
    // Cargo re-run on every build, which is correct — never stale — at the
    // cost of one cheap `git` call per build.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed=.git/{reference}");
        }
    }
    if PathBuf::from(".git/packed-refs").is_file() {
        println!("cargo:rerun-if-changed=.git/packed-refs");
    }

    let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SYSIMAGE_GIT_SHA={sha}");
}
