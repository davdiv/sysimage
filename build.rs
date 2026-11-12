//! Build script: embed the git commit SHA so `sysimage version` can report it.
//!
//! The SHA is exposed to the crate as the `SYSIMAGE_GIT_SHA` environment
//! variable (read with `option_env!` in `src/main.rs`). It is only taken when
//! this package's directory is the root of its own git checkout — an unpacked
//! source archive sitting inside an unrelated git repository would otherwise
//! silently report that repository's HEAD. Outside such a checkout (crates.io
//! tarball, `git archive`, no `git` on PATH, …) the variable is set to
//! `"unknown"` so the build never fails.

use std::env;
use std::fs;
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

/// Canonicalized `(package directory, git toplevel)` when this package *is*
/// the root of its own git checkout, `None` otherwise.
///
/// Build scripts run with the package root as their working directory, so a
/// bare `git rev-parse` would otherwise walk up and happily answer for any
/// enclosing repository.
fn own_checkout() -> Option<(PathBuf, PathBuf)> {
    let package_dir = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)?;
    let toplevel = git(&["rev-parse", "--show-toplevel"]).map(PathBuf::from)?;
    let package_dir = fs::canonicalize(package_dir).ok()?;
    let toplevel = fs::canonicalize(toplevel).ok()?;
    (package_dir == toplevel).then_some((package_dir, toplevel))
}

fn main() {
    if let Some((package_dir, _)) = own_checkout() {
        // Re-run the script when the commit-ish can have moved. `.git/HEAD`
        // covers checkouts (it holds either a raw SHA or
        // `ref: refs/heads/…`); the checked-out branch's ref file covers
        // *commits* on that branch, which do not touch HEAD at all;
        // `packed-refs` covers the rare repack. A ref path that does not
        // exist yet (e.g. a branch ref that is still packed) makes Cargo
        // re-run on every build, which is correct — never stale — at the
        // cost of one cheap `git` call per build.
        println!("cargo:rerun-if-changed=.git/HEAD");
        if let Ok(head) = fs::read_to_string(package_dir.join(".git/HEAD"))
            && let Some(reference) = head.trim().strip_prefix("ref: ")
        {
            println!("cargo:rerun-if-changed=.git/{reference}");
        }
        if package_dir.join(".git/packed-refs").is_file() {
            println!("cargo:rerun-if-changed=.git/packed-refs");
        }

        match git(&["rev-parse", "--short", "HEAD"]) {
            Some(sha) => println!("cargo:rustc-env=SYSIMAGE_GIT_SHA={sha}"),
            None => println!("cargo:rustc-env=SYSIMAGE_GIT_SHA=unknown"),
        }
    } else {
        println!("cargo:rustc-env=SYSIMAGE_GIT_SHA=unknown");
    }
}
