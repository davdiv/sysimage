//! Build script: embed the git commit SHA so `sysimage version` can report it.
//!
//! The SHA is exposed to the crate as the `SYSIMAGE_GIT_SHA` environment
//! variable (read with `option_env!` in `src/main.rs`). Outside a git checkout
//! (e.g. a packaged tarball) the variable is set to `"unknown"` so the build
//! never fails just because `git` or `.git` is unavailable.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves so the embedded SHA stays fresh across commits.
    println!("cargo:rerun-if-changed=.git/HEAD");

    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=SYSIMAGE_GIT_SHA={sha}");
}
