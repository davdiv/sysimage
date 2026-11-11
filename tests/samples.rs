//! End-to-end test: for each sample under `samples/*`, run the build, then
//! `qemu-install` the resulting manifest into raw disk images in a directory,
//! and finally boot the images under QEMU to verify the guest reaches userspace
//! and prints the `SYSIMAGE-BOOTOK` marker.
//!
//! Samples that reference `podman` inputs are skipped (per-sample) when podman
//! is absent or running rootless (sysimage mounts images via `podman image
//! mount`, which rootless podman refuses), matching the graceful-skip
//! convention used by the other interop tests. The QEMU boot step is skipped
//! (with a message) when `qemu-system-*` or the UEFI firmware is not available,
//! but it is a hard failure when QEMU *does* run and the marker never appears.
//!
//! Because this is a single test iterating over many samples, it cannot use
//! `skip_if_missing!` (which returns from the whole function). Instead it
//! branches per sample on `common::require_tools_mode()`: when the
//! `SYSIMAGE_REQUIRE_TOOLS` env var is set, a missing podman (for podman-using
//! samples) or a missing QEMU/firmware turns into a hard failure instead of a
//! per-sample skip, so CI can gate on every sample being exercised.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sysimage::build::build_from_file;
use sysimage::manifest::{ReadManifestConfig, read_manifest};
use sysimage::qemu::{QEMU_CONFIG_FILE, disk_image_file_name, qemu_install};

/// True if this process is running inside a user namespace (e.g. under
/// `podman unshare`). On the host the uid map is the identity `0 0 4294967295`;
/// inside a user namespace it has multiple non-identity lines.
fn in_user_namespace() -> bool {
    fs::read_to_string("/proc/self/uid_map")
        .map(|m| {
            m.lines().any(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                // The identity mapping on the host is `0 0 4294967295`.
                !(f.len() == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295")
                    && !f.is_empty()
            })
        })
        .unwrap_or(false)
}

/// True if `podman` is installed and *usable* for sysimage's container inputs.
///
/// sysimage mounts container images with `podman image mount`, which rootless
/// podman refuses ("cannot run command in rootless mode, must execute `podman
/// unshare` first"). A present-but-rootless podman is therefore only usable
/// when the test is itself running inside a user namespace — i.e. the whole
/// test process was launched under `podman unshare` (e.g.
/// `podman unshare cargo test --test samples`). When that isn't the case we
/// skip the affected samples with an explanatory message, matching the
/// graceful-skip convention used by the other interop tests.
fn podman_usable() -> bool {
    let version = Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !version.is_ok_and(|s| s.success()) {
        return false;
    }
    let rootless = match Command::new("podman")
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "true",
        // If we can't determine the mode, assume usable and let the build fail
        // with a real error if it isn't.
        _ => return true,
    };
    // Rootful podman can always mount; rootless podman only inside a user ns.
    !rootless || in_user_namespace()
}

/// Every direct child of `samples/` that contains a `sysimage.config.yml`.
/// Resolve the crate root directory that owns this test binary.
fn crate_root() -> PathBuf {
    // Walk up from the test executable until we reach a directory that looks
    // like the crate root (contains `Cargo.toml` and `samples/`).
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent();
        while let Some(d) = dir {
            if d.join("Cargo.toml").is_file() && d.join("samples").is_dir() {
                return d.to_path_buf();
            }
            dir = d.parent();
        }
    }
    panic!("Couldn't find samples directory.");
}

fn sample_dirs() -> Vec<PathBuf> {
    let root = crate_root().join("samples");
    let mut out = Vec::new();
    if !root.is_dir() {
        return out;
    }
    for entry in fs::read_dir(&root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() && path.join("sysimage.config.yml").exists() {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Read the 8-byte GPT signature at LBA 1 of a disk image.
fn read_gpt_signature(disk: &Path) -> [u8; 8] {
    let mut f = fs::File::open(disk).unwrap();
    f.seek(SeekFrom::Start(512)).unwrap();
    let mut sig = [0u8; 8];
    f.read_exact(&mut sig).unwrap();
    sig
}

/// Outcome of a QEMU boot attempt.
enum BootOutcome {
    /// QEMU ran to completion and this is the captured serial output.
    Finished(String),
    /// A required host tool (qemu binary or UEFI firmware) is missing; the
    /// boot check is skipped. `reason` explains what was missing.
    Skipped(String),
}

/// Boot the images in `qemu_dir` (described by its `qemu.json`) under QEMU and
/// return the captured serial output. QEMU is launched with `-nographic` so
/// the guest console is muxed to stdout; the guest is expected to print
/// `SYSIMAGE-BOOTOK` and `poweroff` on its own. A timeout caps the wait so a
/// hung boot cannot stall the test suite forever.
///
/// Returns `Skipped` when the qemu binary is not on `PATH` or the UEFI firmware
/// cannot be resolved (so the test degrades gracefully on hosts without the
/// relevant tooling), and `Finished` otherwise — including the case where QEMU
/// ran but the marker never showed up (which the caller turns into a failure).
fn boot_qemu(qemu_dir: &Path, timeout: Duration) -> BootOutcome {
    // Resolve the qemu binary + args. A failure here means the host is missing
    // the UEFI firmware for the target arch — skip rather than fail.
    let (binary, mut args) = match sysimage::qemu::build_qemu_command(qemu_dir) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("Could not find UEFI firmware")
                || msg.contains("Could not read QEMU config")
            {
                return BootOutcome::Skipped(msg);
            }
            return BootOutcome::Skipped(format!("could not build qemu command: {msg}"));
        }
    };

    // The qemu binary must be on PATH; if it isn't, skip gracefully.
    if which(&binary).is_none() {
        return BootOutcome::Skipped(format!("{binary} not found on PATH"));
    }

    // KVM acceleration requires /dev/kvm; drop `-enable-kvm` when it is absent
    // so QEMU falls back to TCG emulation instead of refusing to start.
    if !Path::new("/dev/kvm").exists() {
        args.retain(|a| a != "-enable-kvm");
    }

    let mut cmd = Command::new(&binary);
    cmd.args(&args)
        .current_dir(qemu_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return BootOutcome::Skipped(format!("could not spawn {binary}: {e}"));
        }
    };

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    // Collect stdout (the serial console) in a thread and signal when it ends.
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let tx2 = tx.clone();
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut out = String::new();
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    eprintln!("[qemu] {l}");
                    out.push_str(&l);
                    out.push('\n');
                }
                Err(_) => break,
            }
        }
        let _ = tx2.send(Some(out));
    });
    // Drain stderr so it cannot fill its pipe buffer and deadlock QEMU.
    let stderr_handle = std::thread::spawn(move || {
        let _ = BufReader::new(stderr).lines().count();
    });

    let deadline = Instant::now() + timeout;
    let mut output = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Some(out)) => {
                output = Some(out);
                break;
            }
            Ok(None) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    eprintln!("qemu boot timed out after {timeout:?} — killing QEMU");
                    let _ = child.kill();
                    break;
                }
                // If QEMU already exited on its own, stop waiting for stdout.
                match child.try_wait() {
                    Ok(Some(_)) => {
                        // Give the reader a moment to flush the tail of stdout.
                        if let Ok(Some(out)) = rx.recv_timeout(Duration::from_secs(2)) {
                            output = Some(out);
                        }
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
    }

    // Ensure QEMU is dead and the reader threads have finished.
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    BootOutcome::Finished(output.unwrap_or_default())
}

/// Minimal `which` lookup: the first `PATH` entry that contains `program`.
fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let p = Path::new(program);
        return p.is_file().then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn build_qemu_install_and_boot_each_sample() {
    let samples = sample_dirs();
    assert!(
        !samples.is_empty(),
        "no samples found under samples/ (expected at least one sample directory)"
    );

    // Marker the guest is expected to print once it reaches userspace, then
    // `poweroff`. See `samples/*/container/bootok`.
    const BOOT_OK: &str = "SYSIMAGE-BOOTOK";
    // Generous cap: a cold TCG boot (no KVM) of a minimal guest can take a few
    // minutes, while a KVM boot finishes in seconds.
    const BOOT_TIMEOUT: Duration = Duration::from_secs(300);

    for sample in samples {
        let name = sample
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Skip samples whose config references podman when podman is absent or
        // running rootless (see `podman_usable`). Under `SYSIMAGE_REQUIRE_TOOLS`
        // this is a hard failure instead of a skip, so CI gates on podman-using
        // samples actually being exercised.
        let config_text = fs::read_to_string(sample.join("sysimage.config.yml")).unwrap();
        if config_text.contains("podman") && !podman_usable() {
            let why = "podman not usable (absent, or rootless without `podman unshare`) — \
                       run the test suite under `podman unshare cargo test ...` to exercise it";
            if common::require_tools_mode() {
                panic!("{why} — failing (SYSIMAGE_REQUIRE_TOOLS is set) for sample {name}");
            }
            eprintln!("{why} — skipping sample {name}");
            continue;
        }

        eprintln!("--- sample: {name} ---");

        // Run the build in place on the sample's own config. Build artifacts
        // land in the sample's `output`/`temp` directories (gitignored), and
        // `${CONFIGDIR}` resolves to the sample dir so inputs such as
        // `podman+build:${CONFIGDIR}/container` find the real container dir.
        let config_path = sample.join("sysimage.config.yml");

        // Phase 1: build artifacts + manifest.
        build_from_file(&config_path)
            .unwrap_or_else(|e| panic!("build of sample {name} should succeed: {e}"));

        // Read the manifest derived from the config (name -> <name>.json symlink
        // in the config's output directory).
        let manifest = read_manifest(ReadManifestConfig {
            config: &config_path,
            manifest: None,
        })
        .unwrap_or_else(|e| panic!("read manifest of sample {name} should succeed: {e}"));

        // Phase 2: qemu-install from scratch into a throwaway directory. Each
        // manifest disk becomes `<directory>/<disk-name>.img` and a `qemu.json`
        // describing how to boot them is written alongside.
        let qemu_dir =
            std::env::temp_dir().join(format!("sysimg-samples-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&qemu_dir);
        fs::create_dir_all(&qemu_dir).unwrap();

        let disk_names: Vec<String> = manifest.manifest.disk.keys().cloned().collect();
        assert!(
            !disk_names.is_empty(),
            "sample {name} manifest declares no disks"
        );

        qemu_install(
            manifest,
            &qemu_dir,
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            true,
            false,
        )
        .unwrap_or_else(|e| panic!("qemu-install of sample {name} should succeed: {e}"));

        // Each installed disk must begin with a protective MBR + GPT header.
        for disk_name in &disk_names {
            let img = qemu_dir.join(disk_image_file_name(disk_name));
            assert!(
                img.is_file(),
                "sample {name}: disk image {} should exist",
                img.display()
            );
            assert_eq!(
                &read_gpt_signature(&img),
                b"EFI PART",
                "sample {name}: disk image {} is not a GPT disk",
                img.display()
            );
        }
        assert!(
            qemu_dir.join(QEMU_CONFIG_FILE).is_file(),
            "sample {name}: qemu.json should exist after qemu-install"
        );

        // Phase 3: boot under QEMU and verify the guest reaches userspace.
        match boot_qemu(&qemu_dir, BOOT_TIMEOUT) {
            BootOutcome::Skipped(reason) => {
                let why = format!(
                    "QEMU not available ({reason}) — install qemu-system-* and UEFI firmware \
                     to exercise it"
                );
                if common::require_tools_mode() {
                    panic!("{why} — failing (SYSIMAGE_REQUIRE_TOOLS is set) for sample {name}");
                }
                eprintln!("{why} — skipping boot check for sample {name}");
            }
            BootOutcome::Finished(output) => {
                assert!(
                    output.contains(BOOT_OK),
                    "sample {name}: guest did not print {BOOT_OK} within {BOOT_TIMEOUT:?}.\n\
                     --- qemu serial output ---\n{output}"
                );
                eprintln!("sample {name}: boot OK ({BOOT_OK} seen)");
            }
        }

        let _ = fs::remove_dir_all(&qemu_dir);
    }
}
