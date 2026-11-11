//! QEMU configuration for `sysimage qemu-install` / `sysimage qemu-run`.
//!
//! `qemu-install` installs the system into raw image files inside a directory
//! (one `<disk-name>.img` per manifest disk) and writes a `qemu.json` config
//! file describing how to boot those images under QEMU. `qemu-run` reads that
//! JSON config, resolves the UEFI firmware for the target architecture, and
//! launches `qemu-system-*`.
//!
//! Disks declared only under `qemu.disks` (with an `input` and no matching
//! manifest disk) are not installed: their content-addressed artifacts are
//! hard-linked to `<disk-name>.img` when possible (copying as a fallback) and
//! attached read-only. This lets a config with no installed disks boot an
//! existing EROFS image directly.
//!
//! QEMU itself cannot consume a JSON config file (`-readconfig` expects a
//! keyval/INI-style file), so the JSON is our own portable description and
//! `qemu-run` is the command that turns it into a `qemu-system-*` invocation.
//! The firmware "vars" file is copied into the directory on first run so the
//! image is bootable out of the box and persistent NVRAM state stays local.
//!
//! The portable launch settings (everything but the architecture and the disk
//! images — see [`crate::model::qemu::ConfigQemuSettings`]) can be supplied in
//! `sysimage.config.yml` as an optional `qemu` section and are carried through
//! the manifest. `qemu-install` copies those settings and adds the
//! architecture-specific pieces (the `arch` name and the `qemu-system-*`
//! binary) plus the disk images generated from the manifest's disk names.
//! Unspecified settings fall back to per-architecture defaults derived from
//! the firmware table (see [`default_qemu_settings`]).
//!
//! The type definitions live in [`crate::model::qemu`]; this module contains
//! the implementation (the `qemu-install` / `qemu-run` pipeline, firmware
//! resolution, swtpm management, etc.).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use crate::arch::{ArchInfo, get_arch};
use crate::bail_msg;
use crate::error::{Error, Result};
use crate::install::{self, InstallConfig};
use crate::manifest::ManifestWithDirectory;
use crate::model::manifest::ManifestBuild;
use crate::model::qemu::{ConfigQemuFirmware, ConfigQemuSettings, ConfigQemuTpm};
pub use crate::model::qemu::{QemuConfig, QemuFirmware, QemuRunConfig, QemuTpmDevice};

/// Name of the QEMU config file written into the directory.
pub const QEMU_CONFIG_FILE: &str = "qemu.json";

/// Extension used for the raw disk images inside the directory.
pub const DISK_IMAGE_EXT: &str = "img";

/// Local file name used for an explicit firmware code ROM materialized into
/// the QEMU directory by `qemu-install` (read-only pflash unit 0).
pub const FIRMWARE_CODE_FILE: &str = "firmware-code.fd";
/// Local file name used for an explicit firmware vars file copied into the
/// QEMU directory by `qemu-install` (writable pflash unit 1, persistent).
pub const FIRMWARE_VARS_FILE: &str = "firmware-vars.fd";

/// Local file name used for an explicit kernel image materialized into the
/// QEMU directory by `qemu-install` (used with `-kernel`).
pub const KERNEL_FILE: &str = "kernel";
/// Local file name used for an explicit shim image materialized into the QEMU
/// directory by `qemu-install` (used with `-shim`).
pub const SHIM_FILE: &str = "shim";
/// Local file name used for an explicit initrd image materialized into the
/// QEMU directory by `qemu-install` (used with `-initrd`).
pub const INITRD_FILE: &str = "initrd";
/// Local file name used for an explicit device tree blob materialized into the
/// QEMU directory by `qemu-install` (used with `-dtb`).
pub const DTB_FILE: &str = "dtb";

/// Build the raw-image file name used for a manifest disk.
pub fn disk_image_file_name(disk_name: &str) -> String {
    format!("{disk_name}.{DISK_IMAGE_EXT}")
}

/// Materialize an immutable content-addressed file into `dst`.
///
/// Hard-links are preferred so the QEMU directory does not consume another copy
/// of the artifact. When the filesystem does not support hard-linking (for
/// example, `src` and `dst` are on different filesystems), fall back to a copy
/// and print a notice. Callers handling mutable files (such as firmware vars)
/// must not use this helper.
fn materialize_read_only(src: &Path, dst: &Path, label: &str) -> Result<()> {
    remove_existing_materialization(dst, label)?;
    match std::fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(link_err) => {
            eprintln!("  {label}: hard link failed ({link_err}); copying instead.");
            std::fs::copy(src, dst).map_err(|copy_err| {
                Error::msg(format!(
                    "Failed to materialize {label} from {} to {}: hard link failed \
                     ({link_err}); copy failed ({copy_err})",
                    src.display(),
                    dst.display()
                ))
            })?;
            Ok(())
        }
    }
}

/// Remove a previous materialization at `dst` so a link/copy can replace it.
/// Directories are rejected rather than deleted.
fn remove_existing_materialization(dst: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(dst) {
        Ok(meta) => {
            if meta.file_type().is_dir() {
                return Err(Error::msg(format!(
                    "Cannot materialize {label}: {} is a directory",
                    dst.display()
                )));
            }
            std::fs::remove_file(dst).map_err(|e| {
                Error::msg(format!(
                    "Failed to replace {label} at {}: {e}",
                    dst.display()
                ))
            })?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Return the QEMU-only disks in `manifest.qemu.disks`, mapped to their
/// content-addressed artifact hash file name.
///
/// A QEMU-only disk is an entry whose name is not present in `manifest.disk`.
/// It must have an `input` (resolved to a hash file name at build time), and
/// it is attached read-only: its backing file is shared and content-addressed.
fn external_qemu_disks(manifest: &ManifestBuild) -> Result<BTreeMap<String, String>> {
    let Some(disks) = manifest.qemu.as_ref().and_then(|q| q.disks.as_ref()) else {
        return Ok(BTreeMap::new());
    };

    let mut out = BTreeMap::new();
    for (name, options) in disks {
        if manifest.disk.contains_key(name) {
            if options.contains_key("input") {
                bail_msg!(
                    "qemu.disks.{name}.input is only valid for disks not declared under disk:"
                );
            }
            continue;
        }

        let hash = options.get("input").ok_or_else(|| {
            Error::msg(format!(
                "qemu.disks.{name} is a QEMU-only disk (not declared under disk:) and \
                 requires an `input`"
            ))
        })?;
        if !manifest.file.contains_key(hash) {
            bail_msg!("Manifest has no file entry for QEMU disk \"{name}\" input \"{hash}\"");
        }
        if let Some(readonly) = options.get("readonly") {
            let value = readonly.to_ascii_lowercase();
            if matches!(value.as_str(), "off" | "false" | "0" | "no") {
                bail_msg!(
                    "qemu.disks.{name}.readonly must not be disabled: QEMU-only disks are \
                     backed by shared content-addressed artifacts"
                );
            }
        }

        out.insert(name.clone(), hash.clone());
    }
    Ok(out)
}

/// Link each QEMU-only disk's content-addressed artifact into the QEMU
/// directory under `<disk-name>.img`, so `qemu.json` can reference a stable
/// local file name without copying the image in the normal case.
fn link_external_disks(manifest: &ManifestWithDirectory, dir: &Path) -> Result<()> {
    for (name, hash) in external_qemu_disks(&manifest.manifest)? {
        let src = manifest.manifest_directory.join(&hash);
        if !src.is_file() {
            return Err(Error::msg(format!(
                "QEMU disk \"{name}\" artifact \"{hash}\" is not present in {}",
                manifest.manifest_directory.display()
            )));
        }
        let dst = dir.join(disk_image_file_name(&name));
        materialize_read_only(&src, &dst, &format!("QEMU disk \"{name}\""))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// qemu-install
// ---------------------------------------------------------------------------

/// Run a `qemu-install`: install the manifest into raw image files inside
/// `directory` (one `<disk-name>.img` per manifest disk, created/reused as
/// needed) and write a `qemu.json` QEMU launch config into the directory.
///
/// Disks declared only under `qemu.disks` (with an `input`) are not installed;
/// their content-addressed artifacts are hard-linked (or copied as a fallback)
/// to `<disk-name>.img` and attached read-only.
///
/// `directory` is created if it does not exist. Existing image files are reused
/// and reconciled against (unless `wipe` is set), exactly like `install`.
///
/// `force` is forwarded to [`install`]; it has no effect here because qemu
/// image files are never kernel-managed (so never detected as in-use).
pub fn qemu_install(
    manifest: ManifestWithDirectory,
    directory: &Path,
    key: std::collections::BTreeMap<String, String>,
    key_file: std::collections::BTreeMap<String, PathBuf>,
    wipe: bool,
    force: bool,
) -> Result<()> {
    // Map each manifest disk to `<directory>/<disk-name>.img`.
    let mut disk_map = std::collections::BTreeMap::new();
    for disk_name in manifest.manifest.disk.keys() {
        let img = directory.join(disk_image_file_name(disk_name));
        disk_map.insert(disk_name.clone(), img.to_string_lossy().into_owned());
    }

    // Materialise the directory up-front so missing image files can be created
    // by the installer with a clearer error path.
    std::fs::create_dir_all(directory)?;

    install::install(InstallConfig {
        manifest: manifest.clone(),
        disk: disk_map,
        key,
        key_file,
        wipe,
        force,
    })?;
    // Link QEMU-only disks (content-addressed artifacts that are not installed)
    // into the QEMU directory under stable local names.
    link_external_disks(&manifest, directory)?;
    // Materialize any explicit firmware files (content-addressed in the
    // manifest directory) into the QEMU directory under stable local names, so
    // `qemu-run` can attach them as pflash devices without needing the build
    // output directory. The code file is read-only and always refreshed; the
    // vars file is writable and must be copied (not linked).
    copy_firmware_files(&manifest, directory, wipe)?;
    // Materialize any explicit kernel/shim/initrd/dtb files
    // (content-addressed in the manifest directory) into the QEMU directory
    // under stable local names.
    copy_qemu_input_files(&manifest, directory)?;
    write_config(directory, &manifest.manifest)
}

/// Materialize explicit firmware files from the manifest directory into the
/// QEMU directory under the stable names [`FIRMWARE_CODE_FILE`] /
/// [`FIRMWARE_VARS_FILE`]. No-op unless the manifest carries a `Files` firmware
/// config.
///
/// The code ROM is immutable and is hard-linked when possible (falling back to
/// a copy). The vars file is guest NVRAM state: it must always be copied, and
/// is preserved when already present and `wipe` is false.
fn copy_firmware_files(manifest: &ManifestWithDirectory, dir: &Path, wipe: bool) -> Result<()> {
    let Some(q) = &manifest.manifest.qemu else {
        return Ok(());
    };
    let Some(ConfigQemuFirmware::Files(f)) = &q.firmware else {
        return Ok(());
    };

    // Verify the content-addressed files are recorded in the manifest.
    let source_for = |hash_name: &str| -> Result<PathBuf> {
        manifest.manifest.file.get(hash_name).ok_or_else(|| {
            Error::msg(format!(
                "Manifest has no file entry for firmware file \"{hash_name}\""
            ))
        })?;
        Ok(manifest.manifest_directory.join(hash_name))
    };

    // The code ROM is read-only content; refresh it (same content → same bytes).
    let code_src = source_for(&f.code)?;
    materialize_read_only(&code_src, &dir.join(FIRMWARE_CODE_FILE), "firmware code")?;

    // Preserve an existing vars file so guest NVRAM state survives
    // re-installs, unless the caller asked for a fresh install (`wipe`).
    let vars_dst = dir.join(FIRMWARE_VARS_FILE);
    if !wipe && vars_dst.exists() {
        return Ok(());
    }
    let vars_src = source_for(&f.vars)?;
    std::fs::copy(&vars_src, &vars_dst).map_err(|e| {
        Error::msg(format!(
            "Failed to copy firmware vars from {} to {}: {e}",
            vars_src.display(),
            vars_dst.display()
        ))
    })?;
    Ok(())
}

/// Materialize explicit kernel/shim/initrd/dtb files from the manifest
/// directory into the QEMU directory under the stable names [`KERNEL_FILE`] /
/// [`SHIM_FILE`] / [`INITRD_FILE`] / [`DTB_FILE`].
///
/// Each file is immutable and is hard-linked when possible (falling back to a
/// copy). No-op unless the corresponding field is set in the manifest's `qemu`
/// section.
fn copy_qemu_input_files(manifest: &ManifestWithDirectory, dir: &Path) -> Result<()> {
    let Some(q) = &manifest.manifest.qemu else {
        return Ok(());
    };

    let materialize_hash = |hash_name: &str, dest: &str, label: &str| -> Result<()> {
        manifest.manifest.file.get(hash_name).ok_or_else(|| {
            Error::msg(format!(
                "Manifest has no file entry for QEMU file \"{hash_name}\""
            ))
        })?;
        let src = manifest.manifest_directory.join(hash_name);
        materialize_read_only(&src, &dir.join(dest), label)
    };

    if let Some(hash_name) = &q.kernel {
        materialize_hash(hash_name, KERNEL_FILE, "QEMU kernel")?;
    }
    if let Some(hash_name) = &q.shim {
        materialize_hash(hash_name, SHIM_FILE, "QEMU shim")?;
    }
    if let Some(initrd) = &q.initrd {
        let hash_name = initrd.as_single().ok_or_else(|| {
            Error::msg(
                "Manifest qemu.initrd must contain a single resolved initrd hash; rebuild the image",
            )
        })?;
        materialize_hash(hash_name, INITRD_FILE, "QEMU initrd")?;
    }
    if let Some(hash_name) = &q.dtb {
        materialize_hash(hash_name, DTB_FILE, "QEMU dtb")?;
    }
    Ok(())
}

/// Build and write the `qemu.json` config for `manifest` into `dir`.
pub fn write_config(dir: &Path, manifest: &ManifestBuild) -> Result<()> {
    let config = build_config(manifest)?;
    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write(dir.join(QEMU_CONFIG_FILE), json)?;
    Ok(())
}

/// Build the full `qemu.json` launch config for `manifest`.
///
/// The portable QEMU settings are copied from the manifest (which carries them
/// from the user config at build time); the architecture-specific pieces — the
/// `arch` name and the `qemu-system-*` binary — are added here, and the disk
/// entries are generated from the manifest's disk names plus any QEMU-only
/// disks declared under `qemu.disks`.
fn build_config(manifest: &ManifestBuild) -> Result<QemuConfig> {
    let arch = get_arch(&manifest.arch)?;
    let default_settings = default_qemu_settings(arch);

    let settings = manifest.qemu.clone().unwrap_or_default();
    let firmware = resolve_firmware_setting(&settings);

    // QEMU-only disks (entries with `input` and no matching manifest disk) are
    // attached directly; installed disks keep the existing behaviour.
    let external_disks = external_qemu_disks(manifest)?;
    let mut disks = BTreeMap::new();
    for name in manifest.disk.keys() {
        let mut opts = settings
            .disks
            .as_ref()
            .and_then(|d| d.get(name))
            .cloned()
            .unwrap_or_default();
        opts.insert("file".to_string(), disk_image_file_name(name));
        opts.entry("if".to_string())
            .or_insert_with(|| "virtio".to_string());
        disks.insert(name.clone(), opts);
    }
    for name in external_disks.keys() {
        let mut opts = settings
            .disks
            .as_ref()
            .and_then(|d| d.get(name))
            .cloned()
            .unwrap_or_default();
        // `input` is a sysimage-only key; QEMU must never see it.
        opts.remove("input");
        opts.insert("file".to_string(), disk_image_file_name(name));
        opts.entry("if".to_string())
            .or_insert_with(|| "virtio".to_string());
        opts.entry("readonly".to_string())
            .or_insert_with(|| "on".to_string());
        disks.insert(name.clone(), opts);
    }

    Ok(QemuConfig {
        arch: arch.rust.to_string(),
        machine: settings.machine.unwrap_or(default_settings.machine),
        cpu: settings.cpu.unwrap_or(default_settings.cpu),
        smp: settings.smp.unwrap_or(default_settings.smp),
        memory: settings.memory.unwrap_or(default_settings.memory),
        extra_args: settings.extra_args.unwrap_or(default_settings.extra_args),
        disks,
        tpms: resolve_tpms(arch, settings.tpms.as_ref())?,
        firmware,
        kernel: settings.kernel.as_ref().map(|_| KERNEL_FILE.to_string()),
        shim: settings.shim.as_ref().map(|_| SHIM_FILE.to_string()),
        initrd: settings.initrd.as_ref().map(|_| INITRD_FILE.to_string()),
        dtb: settings.dtb.as_ref().map(|_| DTB_FILE.to_string()),
        append: settings.append.clone(),
    })
}

/// Map the manifest's (partial) firmware setting to the resolved
/// [`QemuFirmware`] stored in `qemu.json`. Explicit firmware files are
/// referenced by their stable local names (the actual files are copied into
/// the QEMU directory by `qemu-install`).
fn resolve_firmware_setting(settings: &ConfigQemuSettings) -> QemuFirmware {
    match &settings.firmware {
        None | Some(ConfigQemuFirmware::Bool(true)) => QemuFirmware::Default,
        Some(ConfigQemuFirmware::Bool(false)) => QemuFirmware::Disabled,
        Some(ConfigQemuFirmware::Files(_)) => QemuFirmware::Files {
            code: FIRMWARE_CODE_FILE.to_string(),
            vars: FIRMWARE_VARS_FILE.to_string(),
        },
    }
}

/// Resolve the user's partial TPM config into fully-specified [`QemuTpmDevice`]s
/// with per-architecture default models and a stable index-derived id.
fn resolve_tpms(
    arch: ArchInfo,
    tpms: Option<&BTreeMap<String, ConfigQemuTpm>>,
) -> Result<BTreeMap<String, QemuTpmDevice>> {
    let mut out = BTreeMap::new();
    if let Some(m) = tpms {
        for (i, (name, t)) in m.iter().enumerate() {
            let version = t.version.clone().unwrap_or_else(|| "2.0".to_string());
            if version != "2.0" && version != "1.2" {
                bail_msg!("TPM '{name}' has unsupported version '{version}' (expected 2.0 or 1.2)");
            }
            out.insert(
                name.clone(),
                QemuTpmDevice {
                    id: format!("tpm{i}"),
                    model: t
                        .model
                        .clone()
                        .unwrap_or_else(|| default_tpm_model(arch).to_string()),
                    version,
                    swtpm_args: t.swtpm_args.clone().unwrap_or_default(),
                },
            );
        }
    }
    Ok(out)
}

/// Per-architecture default TPM frontend device model.
fn default_tpm_model(arch: ArchInfo) -> &'static str {
    match arch.rust {
        "aarch64" | "arm" => "tpm-tis-device",
        _ => "tpm-tis",
    }
}

/// Architecture-derived default QEMU settings (machine, cpu, firmware-vars
/// file from the per-arch firmware table; `smp`/`memory` from fixed defaults).
pub fn default_qemu_settings(arch: ArchInfo) -> QemuConfig {
    let firmware = Firmware::for_arch(arch);
    QemuConfig {
        arch: arch.rust.to_string(),
        machine: firmware.machine.to_string(),
        cpu: firmware.cpu.to_string(),
        smp: 2,
        memory: "4G".to_string(),
        extra_args: firmware
            .machine_extra
            .iter()
            .map(|s| s.to_string())
            .collect(),
        disks: BTreeMap::new(),
        tpms: BTreeMap::new(),
        firmware: QemuFirmware::Default,
        kernel: None,
        shim: None,
        initrd: None,
        dtb: None,
        append: None,
    }
}

// ---------------------------------------------------------------------------
// qemu-run
// ---------------------------------------------------------------------------

/// Resolve `dir` to an absolute path. QEMU is launched with `dir` as its
/// working directory, while `swtpm` is launched from this process's working
/// directory; if `dir` were relative, a socket path computed from it would
/// resolve to different locations for the two processes. Canonicalising once
/// here makes every derived path absolute and cwd-independent.
fn absolute_dir(dir: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(dir).map_err(|e| {
        Error::msg(format!(
            "Could not resolve QEMU directory {}: {e}",
            dir.display()
        ))
    })
}

/// Read `qemu.json` from `directory` and launch QEMU (or print the command when
/// `print` is set).
pub fn run_config(opts: QemuRunConfig) -> Result<()> {
    // Canonicalise so the swtpm socket path passed to QEMU (which runs with
    // `dir` as its cwd) matches the path `swtpm` actually binds (run from this
    // process's cwd), regardless of how `directory` was specified.
    let dir = absolute_dir(&opts.directory)?;
    let config = read_qemu_config(&dir)?;
    let arch = get_arch(&config.arch)?;
    let qemu = format!("qemu-system-{}", arch.qemu);
    let args = build_qemu_args_with_extra(&dir, &config, &opts.extra_args)?;
    let command = render_command_line(&qemu, &args);

    if opts.print {
        println!("{command}");
        return Ok(());
    }

    eprintln!("[qemu] $ {command}");

    // Start an `swtpm` instance for each TPM device before launching QEMU; the
    // instances self-terminate (`--ctrl ...,terminate`) when QEMU disconnects.
    let swtpm = start_swtpm_backends(&dir, &config)?;
    let result = launch_qemu(&dir, &qemu, &args);
    // Always clean up swtpm backends — whether QEMU succeeded, failed, or could
    // not even start — so no orphaned swtpm process is left behind.
    stop_swtpm_backends(swtpm);
    let status = result?;
    // Propagate QEMU's own exit code (or signal) so callers see the same result
    // as if QEMU had replaced this process (the previous `exec()` behaviour).
    if status.success() {
        Ok(())
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                std::process::exit(128 + sig);
            }
        }
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Read and parse the `qemu.json` launch config from `dir`.
pub fn read_qemu_config(dir: &Path) -> Result<QemuConfig> {
    let config_path = dir.join(QEMU_CONFIG_FILE);
    let text = std::fs::read_to_string(&config_path).map_err(|e| {
        Error::msg(format!(
            "Could not read QEMU config {}: {e}",
            config_path.display()
        ))
    })?;
    serde_json::from_str(&text).map_err(|e| {
        Error::msg(format!(
            "Could not parse QEMU config {}: {e}",
            config_path.display()
        ))
    })
}

/// Read `qemu.json` from `dir`, resolve firmware, and return the QEMU binary
/// name plus the full resolved argument list (without launching). This is the
/// shared core used both by `build_command_line` (for `--print`) and by tests
/// that need to spawn QEMU themselves with captured output.
pub fn build_qemu_command(dir: &Path) -> Result<(String, Vec<String>)> {
    build_qemu_command_with_extra_args(dir, &[])
}

/// Like [`build_qemu_command`], but appends `extra_args` after the generated
/// QEMU arguments. The extra arguments are not validated; they are passed to
/// QEMU verbatim (and appear in the `--print` output).
pub fn build_qemu_command_with_extra_args(
    dir: &Path,
    extra_args: &[String],
) -> Result<(String, Vec<String>)> {
    let dir = absolute_dir(dir)?;
    let config = read_qemu_config(&dir)?;
    let arch = get_arch(&config.arch)?;
    let args = build_qemu_args_with_extra(&dir, &config, extra_args)?;
    Ok((format!("qemu-system-{}", arch.qemu), args))
}

/// Read `qemu.json` from `dir`, resolve firmware, and return the full resolved
/// `qemu-system-*` command line as a shell-quoted string (without launching).
pub fn build_command_line(dir: &Path) -> Result<String> {
    build_command_line_with_extra_args(dir, &[])
}

/// Like [`build_command_line`], but appends `extra_args` after the generated
/// QEMU arguments.
pub fn build_command_line_with_extra_args(dir: &Path, extra_args: &[String]) -> Result<String> {
    let (binary, args) = build_qemu_command_with_extra_args(dir, extra_args)?;
    Ok(render_command_line(&binary, &args))
}

/// Assemble `config`'s QEMU arguments and append the CLI-supplied
/// `extra_args` after them. Appending last lets QEMU's last-value-wins
/// behaviour apply when a user overrides a generated option.
fn build_qemu_args_with_extra(
    dir: &Path,
    config: &QemuConfig,
    extra_args: &[String],
) -> Result<Vec<String>> {
    let mut args = build_qemu_args(dir, config)?;
    args.extend_from_slice(extra_args);
    Ok(args)
}

/// Resolve firmware + assemble the full qemu argument list (without the binary
/// name) for `config`, rooted at `dir`.
fn build_qemu_args(dir: &Path, config: &QemuConfig) -> Result<Vec<String>> {
    let arch = get_arch(&config.arch)?;

    let mut args = Vec::new();
    // Prefer hardware virtualisation (KVM) when the host supports it, falling
    // back to TCG transparently when it does not. The `accel` machine property
    // accepts a colon-separated list tried in order, so `kvm:tcg` makes QEMU
    // use KVM first and silently fall back to TCG otherwise — `qemu-run` never
    // fails just because KVM is unavailable (e.g. no `/dev/kvm`, running in a
    // nested VM without virtualisation extensions, or a cross-architecture
    // guest). Appended to `-machine` rather than `-accel` because the latter
    // takes a single accelerator and cannot express a fallback. A user-supplied
    // `accel=...` already present in `machine` takes precedence.
    let machine = if config.machine.contains("accel=") {
        config.machine.clone()
    } else {
        format!("{},accel=kvm:tcg", config.machine)
    };
    args.push("-machine".to_string());
    args.push(machine);
    args.push("-cpu".to_string());
    args.push(config.cpu.clone());
    args.push("-smp".to_string());
    args.push(config.smp.to_string());
    args.push("-m".to_string());
    args.push(config.memory.clone());
    for extra in &config.extra_args {
        args.push(extra.clone());
    }

    // UEFI firmware as pflash devices (code read-only, vars writable). The
    // exact drives depend on the resolved firmware mode:
    // - `Default`: resolve the per-architecture firmware from the host search
    //   paths and materialise a writable vars copy (`vars.fd`) on first run.
    // - `Disabled`: no pflash devices (QEMU falls back to SeaBIOS).
    // - `Files`: use the explicit firmware files already copied into `dir` by
    //   `qemu-install` (code read-only, vars writable and persistent).
    match &config.firmware {
        QemuFirmware::Default => {
            let firmware = Firmware::for_arch(arch);
            let code = resolve_firmware(firmware.code_candidates, "code ROM", arch)?;
            let vars_path = dir.join(FIRMWARE_VARS_FILE);
            if !vars_path.exists() {
                let template = resolve_firmware(firmware.vars_candidates, "vars file", arch)?;
                std::fs::copy(&template, &vars_path).map_err(|e| {
                    Error::msg(format!(
                        "Failed to copy firmware vars from {} to {}: {e}",
                        template.display(),
                        vars_path.display()
                    ))
                })?;
            }
            args.push("-drive".to_string());
            args.push(format!(
                "if=pflash,format=raw,unit=0,file={},readonly=on",
                code.display()
            ));
            args.push("-drive".to_string());
            args.push(format!(
                "if=pflash,format=raw,unit=1,file={}",
                FIRMWARE_VARS_FILE
            ));
        }
        QemuFirmware::Disabled => {
            // No UEFI firmware; QEMU boots via SeaBIOS.
        }
        QemuFirmware::Files { code, vars } => {
            let code_path = dir.join(code);
            if !code_path.is_file() {
                return Err(Error::msg(format!(
                    "Firmware code file \"{code}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                    dir.display()
                )));
            }
            args.push("-drive".to_string());
            args.push(format!(
                "if=pflash,format=raw,unit=0,file={code},readonly=on"
            ));

            let vars_path = dir.join(vars);
            if !vars_path.is_file() {
                return Err(Error::msg(format!(
                    "Firmware vars file \"{vars}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                    dir.display()
                )));
            }
            args.push("-drive".to_string());
            args.push(format!("if=pflash,format=raw,unit=1,file={vars}"));
        }
    }

    // Attach each disk image as a virtio-blk drive.
    for disk in config.disks.values() {
        let mut opts = disk
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>();
        opts.push("format=raw".to_string());
        args.push("-drive".to_string());
        args.push(opts.join(","));
    }

    // Attach each TPM device (backend started separately as `swtpm`).
    for (name, tpm) in &config.tpms {
        let socket = swtpm_socket_path(dir, name);
        args.push("-chardev".to_string());
        args.push(format!("socket,id=chr{},path={}", tpm.id, socket.display()));
        args.push("-tpmdev".to_string());
        args.push(format!("emulator,id={},chardev=chr{}", tpm.id, tpm.id));
        args.push("-device".to_string());
        args.push(format!("{},tpmdev={}", tpm.model, tpm.id));
    }

    // Direct kernel boot: kernel, shim, initrd, device tree blob, and kernel
    // command line. These files are copied into the QEMU directory by
    // `qemu-install` under stable local names.
    if let Some(kernel) = &config.kernel {
        let kernel_path = dir.join(kernel);
        if !kernel_path.is_file() {
            return Err(Error::msg(format!(
                "Kernel file \"{kernel}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                dir.display()
            )));
        }
        args.push("-kernel".to_string());
        args.push(kernel.clone());
    }
    if let Some(shim) = &config.shim {
        let shim_path = dir.join(shim);
        if !shim_path.is_file() {
            return Err(Error::msg(format!(
                "Shim file \"{shim}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                dir.display()
            )));
        }
        args.push("-shim".to_string());
        args.push(shim.clone());
    }
    if let Some(initrd) = &config.initrd {
        let initrd_path = dir.join(initrd);
        if !initrd_path.is_file() {
            return Err(Error::msg(format!(
                "Initrd file \"{initrd}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                dir.display()
            )));
        }
        args.push("-initrd".to_string());
        args.push(initrd.clone());
    }
    if let Some(dtb) = &config.dtb {
        let dtb_path = dir.join(dtb);
        if !dtb_path.is_file() {
            return Err(Error::msg(format!(
                "DTB file \"{dtb}\" is not present in {} (run `sysimage qemu-install` to copy it)",
                dir.display()
            )));
        }
        args.push("-dtb".to_string());
        args.push(dtb.clone());
    }
    if let Some(append) = &config.append {
        args.push("-append".to_string());
        args.push(append.clone());
    }

    Ok(args)
}

// ---------------------------------------------------------------------------
// swtpm backend management
// ---------------------------------------------------------------------------

/// File name of the `swtpm` control-channel unix socket for `name` in `dir`.
fn swtpm_socket_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("swtpm-{name}.sock"))
}

/// Directory holding the persistent `swtpm` state for `name` in `dir`.
fn swtpm_state_dir(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("swtpm-{name}"))
}

/// A running `swtpm` child process backing one TPM device.
struct SwtpmChild {
    child: Child,
    socket: PathBuf,
}

/// Start one `swtpm socket` instance per TPM device in `config`, creating the
/// persistent state directories and waiting for each control socket to appear.
///
/// Each instance is started with `--ctrl ...,terminate` so it self-terminates
/// when QEMU disconnects (exits). On error, any already-started instances are
/// killed before returning.
fn start_swtpm_backends(dir: &Path, config: &QemuConfig) -> Result<Vec<SwtpmChild>> {
    let mut children = Vec::new();
    for (name, tpm) in &config.tpms {
        match start_one_swtpm(dir, name, tpm) {
            Ok(c) => children.push(c),
            Err(e) => {
                stop_swtpm_backends(children);
                return Err(e);
            }
        }
    }
    Ok(children)
}

fn start_one_swtpm(dir: &Path, name: &str, tpm: &QemuTpmDevice) -> Result<SwtpmChild> {
    let socket = swtpm_socket_path(dir, name);
    let state_dir = swtpm_state_dir(dir, name);
    std::fs::create_dir_all(&state_dir)?;
    // Remove a stale socket from a previous run before re-binding.
    let _ = std::fs::remove_file(&socket);

    let mut cmd = Command::new("swtpm");
    cmd.current_dir(dir)
        .arg("socket")
        .arg("--tpmstate")
        .arg(format!("dir={}", state_dir.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={},terminate", socket.display()));
    // swtpm defaults to TPM 1.2; `--tpm2` selects TPM 2.0.
    if tpm.version == "2.0" {
        cmd.arg("--tpm2");
    }
    for a in &tpm.swtpm_args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    eprintln!(
        "[swtpm] $ {} (TPM '{name}', state {})",
        cmd.get_program().to_string_lossy(),
        state_dir.display()
    );
    let mut child = cmd.spawn().map_err(|e| {
        Error::msg(format!(
            "Failed to start swtpm for TPM '{name}' (is swtpm installed?): {e}"
        ))
    })?;

    wait_for_socket(&socket, name, &mut child)?;
    Ok(SwtpmChild { child, socket })
}

/// Poll for `socket` to appear (swtpm binds before accepting), up to ~5s.
///
/// Also watches `child` for an early exit so a swtpm that crashes during
/// startup is reported immediately instead of waiting for the full timeout.
fn wait_for_socket(socket: &Path, name: &str, child: &mut Child) -> Result<()> {
    for _ in 0..250 {
        // Detect an early swtpm crash rather than waiting the full timeout.
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(Error::msg(format!(
                    "swtpm for TPM '{name}' exited unexpectedly during startup with {status}"
                )));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(Error::msg(format!(
                    "Failed to poll swtpm for TPM '{name}': {e}"
                )));
            }
        }
        if socket.exists() {
            // Verify it's a real unix socket, not a leftover regular file.
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if std::fs::metadata(socket)
                    .map(|m| m.file_type().is_socket())
                    .unwrap_or(false)
                {
                    return Ok(());
                }
            }
            #[cfg(not(unix))]
            {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(Error::msg(format!(
        "swtpm for TPM '{name}' did not create control socket {} within 5s",
        socket.display()
    )))
}

/// Kill and reap any started `swtpm` instances and remove their sockets.
fn stop_swtpm_backends(mut children: Vec<SwtpmChild>) {
    for mut c in children.drain(..) {
        let _ = c.child.kill();
        let _ = c.child.wait();
        let _ = std::fs::remove_file(&c.socket);
    }
}

/// Search `candidates` (absolute paths) for the first existing firmware file.
fn resolve_firmware(candidates: &[&str], what: &str, arch: ArchInfo) -> Result<PathBuf> {
    for c in candidates {
        let p = Path::new(c);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }
    Err(Error::msg(format!(
        "Could not find UEFI firmware {what} for {}. Tried:\n{}",
        arch.rust,
        candidates
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )))
}

fn launch_qemu(dir: &Path, binary: &str, args: &[String]) -> Result<ExitStatus> {
    let mut cmd = Command::new(binary);
    cmd.args(args).current_dir(dir);
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::msg(format!("Failed to start {binary}: {e}")))?;
    child
        .wait()
        .map_err(|e| Error::msg(format!("Failed to wait for {binary}: {e}")))
}

/// Render a shell-quoted command line for display.
fn render_command_line(binary: &str, args: &[String]) -> String {
    let mut parts = vec![shell_quote(binary)];
    for a in args {
        parts.push(shell_quote(a));
    }
    parts.join(" ")
}

/// Quote a single argument for a POSIX shell, only when it contains characters
/// that would otherwise be split or interpreted.
fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.' | ',' | '='))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ---------------------------------------------------------------------------
// Per-architecture firmware tables
// ---------------------------------------------------------------------------

struct Firmware {
    machine: &'static str,
    machine_extra: &'static [&'static str],
    cpu: &'static str,
    code_candidates: &'static [&'static str],
    vars_candidates: &'static [&'static str],
}

impl Firmware {
    fn for_arch(arch: ArchInfo) -> &'static Firmware {
        match arch.rust {
            "x86_64" => &FIRMWARE_X64,
            "x86" => &FIRMWARE_IA32,
            "aarch64" => &FIRMWARE_ARM64,
            "arm" => &FIRMWARE_ARM,
            _ => &FIRMWARE_X64,
        }
    }
}

static FIRMWARE_X64: Firmware = Firmware {
    machine: "q35,smm=on",
    machine_extra: &["-global", "driver=cfi.pflash01,property=secure,value=on"],
    cpu: "qemu64",
    code_candidates: &[
        "/usr/share/ovmf/x64/OVMF_CODE.secboot.4m.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.4m.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.4m.fd",
        "/usr/share/ovmf/x64/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    ],
    vars_candidates: &[
        "/usr/share/ovmf/x64/OVMF_VARS.4m.fd",
        "/usr/share/OVMF/OVMF_VARS.4m.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.4m.fd",
        "/usr/share/ovmf/x64/OVMF_VARS_4M.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    ],
};

static FIRMWARE_IA32: Firmware = Firmware {
    machine: "q35,smm=on",
    machine_extra: &["-global", "driver=cfi.pflash01,property=secure,value=on"],
    cpu: "qemu32",
    code_candidates: &[
        "/usr/share/ovmf/ia32/OVMF_CODE.secboot.4m.fd",
        "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.4m.fd",
        "/usr/share/ovmf/ia32/OVMF_CODE_4M.fd",
    ],
    vars_candidates: &[
        "/usr/share/ovmf/ia32/OVMF_VARS.4m.fd",
        "/usr/share/edk2/ovmf-ia32/OVMF_VARS.4m.fd",
        "/usr/share/ovmf/ia32/OVMF_VARS_4M.fd",
    ],
};

static FIRMWARE_ARM64: Firmware = Firmware {
    machine: "virt",
    machine_extra: &[],
    cpu: "cortex-a72",
    code_candidates: &[
        "/usr/share/AAVMF/QEMU_EFI-pflash.raw",
        "/usr/share/AAVMF/QEMU_EFI-silent-pflash.raw",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw",
        "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw",
    ],
    vars_candidates: &[
        "/usr/share/AAVMF/QEMU_VARS-pflash.raw",
        "/usr/share/AAVMF/QEMU_VARS.fd",
        "/usr/share/edk2/aarch64/QEMU_VARS-pflash.raw",
        "/usr/share/edk2/aarch64/QEMU_VARS.fd",
    ],
};

static FIRMWARE_ARM: Firmware = Firmware {
    machine: "virt",
    machine_extra: &[],
    cpu: "cortex-a15",
    code_candidates: &[
        "/usr/share/AAVMF/QEMU_EFI-pflash.raw",
        "/usr/share/edk2/arm/QEMU_EFI-pflash.raw",
    ],
    vars_candidates: &[
        "/usr/share/AAVMF/QEMU_VARS-pflash.raw",
        "/usr/share/edk2/arm/QEMU_VARS-pflash.raw",
    ],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::manifest::{ManifestBlock, ManifestBlockImage, ManifestBuild};
    use crate::model::qemu::ConfigQemuInitrd;
    use std::collections::BTreeMap;

    fn manifest_with_arch(arch: &str, disks: &[&str]) -> ManifestBuild {
        let mut disk = BTreeMap::new();
        for name in disks {
            disk.insert(
                (*name).to_string(),
                ManifestBlock::Image(ManifestBlockImage {
                    size_min: 1024,
                    file: "x".to_string(),
                }),
            );
        }
        ManifestBuild {
            schema: None,
            name: "test".to_string(),
            version: "1".to_string(),
            arch: arch.to_string(),
            file: BTreeMap::new(),
            disk,
            lvm: BTreeMap::new(),
            qemu: None,
            netboot: None,
        }
    }

    #[test]
    fn disk_image_file_name_uses_img_extension() {
        assert_eq!(disk_image_file_name("bootdisk"), "bootdisk.img");
    }

    #[test]
    fn build_config_x64_lists_all_disks() {
        let manifest = manifest_with_arch("x86_64", &["bootdisk", "data"]);
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.arch, "x86_64");
        assert_eq!(config.machine, "q35,smm=on");
        assert_eq!(config.disks.len(), 2);
        assert_eq!(config.disks["bootdisk"]["file"], "bootdisk.img");
        assert_eq!(config.disks["data"]["file"], "data.img");
        assert_eq!(config.disks["bootdisk"]["if"], "virtio");
        assert_eq!(config.disks["data"]["if"], "virtio");
        // secure-boot pflash global is present as extra args.
        assert!(config.extra_args.contains(&"-global".to_string()));
    }

    #[test]
    fn build_config_defaults_if_virtio_and_preserves_override() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk", "data"]);
        manifest.qemu = Some(ConfigQemuSettings {
            disks: Some(BTreeMap::from([(
                "bootdisk".to_string(),
                BTreeMap::from([("if".to_string(), "ide".to_string())]),
            )])),
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.disks["bootdisk"]["if"], "ide");
        assert_eq!(config.disks["data"]["if"], "virtio");
    }

    #[test]
    fn build_config_arm64_uses_virt_machine() {
        let manifest = manifest_with_arch("aarch64", &["bootdisk"]);
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.arch, "aarch64");
        assert_eq!(config.machine, "virt");
        assert_eq!(config.cpu, "cortex-a72");
    }

    #[test]
    fn build_config_uses_manifest_qemu_settings_when_present() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        manifest.qemu = Some(ConfigQemuSettings {
            machine: Some("virt".to_string()),
            cpu: Some("max".to_string()),
            smp: Some(4),
            memory: Some("8G".to_string()),
            extra_args: Some(vec!["-foo".to_string()]),
            disks: None,
            tpms: None,
            firmware: None,
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        // Arch is still derived from the manifest arch.
        assert_eq!(config.arch, "x86_64");
        // But the portable settings come from the manifest verbatim.
        assert_eq!(config.machine, "virt");
        assert_eq!(config.cpu, "max");
        assert_eq!(config.smp, 4);
        assert_eq!(config.memory, "8G");
        assert_eq!(config.extra_args, vec!["-foo".to_string()]);
    }

    #[test]
    fn build_config_maps_qemu_input_files_to_local_names() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        manifest.qemu = Some(ConfigQemuSettings {
            kernel: Some("abc123.bin".to_string()),
            shim: Some("def456.bin".to_string()),
            initrd: Some(ConfigQemuInitrd::One("ghi789.bin".to_string())),
            dtb: Some("jkl012.bin".to_string()),
            append: Some("root=/dev/sda2 console=ttyS0".to_string()),
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.kernel.as_deref(), Some(KERNEL_FILE));
        assert_eq!(config.shim.as_deref(), Some(SHIM_FILE));
        assert_eq!(config.initrd.as_deref(), Some(INITRD_FILE));
        assert_eq!(config.dtb.as_deref(), Some(DTB_FILE));
        assert_eq!(
            config.append.as_deref(),
            Some("root=/dev/sda2 console=ttyS0")
        );
    }

    #[test]
    fn build_config_leaves_qemu_input_files_unset_when_not_configured() {
        let manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.kernel, None);
        assert_eq!(config.shim, None);
        assert_eq!(config.initrd, None);
        assert_eq!(config.dtb, None);
        assert_eq!(config.append, None);
    }

    #[test]
    fn build_qemu_args_includes_kernel_initrd_dtb_append() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemukernel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Create the local files so the existence checks pass.
        std::fs::write(dir.join(KERNEL_FILE), "kernel-blob").unwrap();
        std::fs::write(dir.join(SHIM_FILE), "shim-blob").unwrap();
        std::fs::write(dir.join(INITRD_FILE), "initrd-blob").unwrap();
        std::fs::write(dir.join(DTB_FILE), "dtb-blob").unwrap();

        let config = QemuConfig {
            arch: "x86_64".to_string(),
            machine: "q35".to_string(),
            cpu: "qemu64".to_string(),
            smp: 1,
            memory: "256M".to_string(),
            extra_args: Vec::new(),
            disks: BTreeMap::new(),
            tpms: BTreeMap::new(),
            firmware: QemuFirmware::Disabled,
            kernel: Some(KERNEL_FILE.to_string()),
            shim: Some(SHIM_FILE.to_string()),
            initrd: Some(INITRD_FILE.to_string()),
            dtb: Some(DTB_FILE.to_string()),
            append: Some("console=ttyS0".to_string()),
        };
        let args = build_qemu_args(&dir, &config).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("-kernel kernel"), "{joined}");
        assert!(joined.contains("-shim shim"), "{joined}");
        assert!(joined.contains("-initrd initrd"), "{joined}");
        assert!(joined.contains("-dtb dtb"), "{joined}");
        assert!(joined.contains("-append console=ttyS0"), "{joined}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_qemu_args_errors_when_kernel_file_missing() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemukernel-missing-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = QemuConfig {
            arch: "x86_64".to_string(),
            machine: "q35".to_string(),
            cpu: "qemu64".to_string(),
            smp: 1,
            memory: "256M".to_string(),
            extra_args: Vec::new(),
            disks: BTreeMap::new(),
            tpms: BTreeMap::new(),
            firmware: QemuFirmware::Disabled,
            kernel: Some(KERNEL_FILE.to_string()),
            shim: None,
            initrd: None,
            dtb: None,
            append: None,
        };
        let err = build_qemu_args(&dir, &config).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Kernel file") && msg.contains("qemu-install"),
            "unexpected error: {msg}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_config_round_trips_json() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemucfg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        write_config(&dir, &manifest).unwrap();
        let text = std::fs::read_to_string(dir.join(QEMU_CONFIG_FILE)).unwrap();
        let config: QemuConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(config.arch, "x86_64");
        assert_eq!(config.disks["bootdisk"]["file"], "bootdisk.img");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_qemu_args_prefers_kvm_with_tcg_fallback() {
        let manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let config = build_config(&manifest).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemuaccel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        if let Ok(args) = build_qemu_args(&dir, &config) {
            let machine = args
                .windows(2)
                .find(|w| w[0] == "-machine")
                .map(|w| w[1].as_str());
            assert_eq!(machine, Some("q35,smm=on,accel=kvm:tcg"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_qemu_args_respects_user_machine_accel() {
        // A user who already specifies `accel=` in their machine string keeps
        // it verbatim — we do not append our own fallback.
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        manifest.qemu = Some(ConfigQemuSettings {
            machine: Some("q35,smm=on,accel=tcg".to_string()),
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: None,
            firmware: None,
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemuaccel2-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        if let Ok(args) = build_qemu_args(&dir, &config) {
            let machine = args
                .windows(2)
                .find(|w| w[0] == "-machine")
                .map(|w| w[1].as_str());
            assert_eq!(machine, Some("q35,smm=on,accel=tcg"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_qemu_args_includes_firmware_and_disks() {
        let manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let config = build_config(&manifest).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemuargs-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // build_qemu_args needs the firmware code ROM to exist on the host; if
        // it is missing we only assert the error is the expected "not found".
        match build_qemu_args(&dir, &config) {
            Ok(args) => {
                assert!(args.iter().any(|a| a.contains("bootdisk.img")));
                assert!(args.iter().any(|a| a.contains("format=raw")));
                assert!(
                    args.iter()
                        .any(|a| a.contains("if=pflash,format=raw,unit=0"))
                );
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("Could not find UEFI firmware"),
                    "unexpected error: {msg}"
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_qemu_args_appends_extra_args_last() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemuextra-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = QemuConfig {
            arch: "x86_64".to_string(),
            machine: "q35".to_string(),
            cpu: "qemu64".to_string(),
            smp: 1,
            memory: "256M".to_string(),
            extra_args: Vec::new(),
            disks: BTreeMap::new(),
            tpms: BTreeMap::new(),
            firmware: QemuFirmware::Disabled,
            kernel: None,
            shim: None,
            initrd: None,
            dtb: None,
            append: None,
        };
        let extra = vec![
            "-serial".to_string(),
            "stdio".to_string(),
            "-display".to_string(),
            "none".to_string(),
        ];
        let args = build_qemu_args_with_extra(&dir, &config, &extra).unwrap();
        assert_eq!(args[0], "-machine");
        assert_eq!(&args[args.len() - extra.len()..], extra.as_slice());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_command_line_with_extra_args_quotes_extras() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemuextracmd-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = QemuConfig {
            arch: "x86_64".to_string(),
            machine: "q35".to_string(),
            cpu: "qemu64".to_string(),
            smp: 1,
            memory: "256M".to_string(),
            extra_args: Vec::new(),
            disks: BTreeMap::new(),
            tpms: BTreeMap::new(),
            firmware: QemuFirmware::Disabled,
            kernel: None,
            shim: None,
            initrd: None,
            dtb: None,
            append: None,
        };
        std::fs::write(
            dir.join(QEMU_CONFIG_FILE),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
        let extra = vec![
            "-serial".to_string(),
            "stdio".to_string(),
            "-fw_cfg".to_string(),
            "name=opt/foo,string=hello world".to_string(),
        ];
        let command = build_command_line_with_extra_args(&dir, &extra).unwrap();
        assert!(
            command.ends_with("-serial stdio -fw_cfg 'name=opt/foo,string=hello world'"),
            "command line: {command}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shell_quote_escapes_spaces() {
        assert_eq!(shell_quote("plain"), "plain");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn build_config_resolves_tpms_with_defaults() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let mut tpms = BTreeMap::new();
        tpms.insert(
            "tpm0".to_string(),
            ConfigQemuTpm {
                model: None,
                version: None,
                swtpm_args: Some(vec!["--log".to_string(), "level=20".to_string()]),
            },
        );
        tpms.insert(
            "firmware".to_string(),
            ConfigQemuTpm {
                model: Some("tpm-crb".to_string()),
                version: Some("1.2".to_string()),
                swtpm_args: None,
            },
        );
        manifest.qemu = Some(ConfigQemuSettings {
            machine: None,
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: Some(tpms),
            firmware: None,
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        // Two TPMs, in sorted-name order; ids are index-derived. "firmware"
        // sorts before "tpm0" in a BTreeMap, so it gets tpm0.
        let t0 = &config.tpms["firmware"];
        assert_eq!(t0.id, "tpm0");
        assert_eq!(t0.model, "tpm-crb"); // user override
        assert_eq!(t0.version, "1.2");
        assert!(t0.swtpm_args.is_empty());
        let t1 = &config.tpms["tpm0"];
        assert_eq!(t1.id, "tpm1");
        assert_eq!(t1.model, "tpm-tis"); // x86 default
        assert_eq!(t1.version, "2.0"); // default
        assert_eq!(
            t1.swtpm_args,
            vec!["--log".to_string(), "level=20".to_string()]
        );
    }

    #[test]
    fn build_config_arm64_default_tpm_model() {
        let mut manifest = manifest_with_arch("aarch64", &["bootdisk"]);
        let mut tpms = BTreeMap::new();
        tpms.insert("tpm0".to_string(), ConfigQemuTpm::default());
        manifest.qemu = Some(ConfigQemuSettings {
            machine: None,
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: Some(tpms),
            firmware: None,
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        assert_eq!(config.tpms["tpm0"].model, "tpm-tis-device");
    }

    #[test]
    fn build_config_rejects_bad_tpm_version() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let mut tpms = BTreeMap::new();
        tpms.insert(
            "tpm0".to_string(),
            ConfigQemuTpm {
                version: Some("3.0".to_string()),
                ..Default::default()
            },
        );
        manifest.qemu = Some(ConfigQemuSettings {
            machine: None,
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: Some(tpms),
            firmware: None,
            ..Default::default()
        });
        let err = build_config(&manifest).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unsupported version") && msg.contains("tpm0"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn build_qemu_args_includes_tpm_devices() {
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let mut tpms = BTreeMap::new();
        tpms.insert(
            "tpm0".to_string(),
            ConfigQemuTpm {
                model: None,
                version: None,
                swtpm_args: None,
            },
        );
        manifest.qemu = Some(ConfigQemuSettings {
            machine: None,
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: Some(tpms),
            firmware: None,
            ..Default::default()
        });
        let config = build_config(&manifest).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemutpm-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        match build_qemu_args(&dir, &config) {
            Ok(args) => {
                let joined = args.join(" ");
                assert!(
                    joined.contains("-chardev socket,id=chrtpm0,path="),
                    "{joined}"
                );
                assert!(joined.contains("swtpm-tpm0.sock"), "{joined}");
                assert!(
                    joined.contains("-tpmdev emulator,id=tpm0,chardev=chrtpm0"),
                    "{joined}"
                );
                assert!(joined.contains("-device tpm-tis,tpmdev=tpm0"), "{joined}");
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("Could not find UEFI firmware"),
                    "unexpected error: {msg}"
                );
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_config_round_trips_tpms() {
        let dir = std::env::temp_dir().join(format!(
            "sysimg-qemucfg-tpm-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut manifest = manifest_with_arch("x86_64", &["bootdisk"]);
        let mut tpms = BTreeMap::new();
        tpms.insert(
            "tpm0".to_string(),
            ConfigQemuTpm {
                model: Some("tpm-crb".to_string()),
                version: Some("2.0".to_string()),
                swtpm_args: Some(vec!["--log".to_string(), "level=20".to_string()]),
            },
        );
        manifest.qemu = Some(ConfigQemuSettings {
            machine: None,
            cpu: None,
            smp: None,
            memory: None,
            extra_args: None,
            disks: None,
            tpms: Some(tpms),
            firmware: None,
            ..Default::default()
        });
        write_config(&dir, &manifest).unwrap();
        let text = std::fs::read_to_string(dir.join(QEMU_CONFIG_FILE)).unwrap();
        let config: QemuConfig = serde_json::from_str(&text).unwrap();
        let tpm = &config.tpms["tpm0"];
        assert_eq!(tpm.id, "tpm0");
        assert_eq!(tpm.model, "tpm-crb");
        assert_eq!(tpm.version, "2.0");
        assert_eq!(
            tpm.swtpm_args,
            vec!["--log".to_string(), "level=20".to_string()]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `swtpm` is on PATH and runnable in socket mode.
    fn swtpm_available() -> bool {
        std::process::Command::new("swtpm")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn swtpm_backend_starts_and_self_terminates() {
        if !swtpm_available() {
            eprintln!("swtpm not available — skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "sysimg-swtpm-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut tpms = BTreeMap::new();
        tpms.insert(
            "tpm0".to_string(),
            QemuTpmDevice {
                id: "tpm0".to_string(),
                model: "tpm-tis".to_string(),
                version: "2.0".to_string(),
                swtpm_args: Vec::new(),
            },
        );
        let config = QemuConfig {
            arch: "x86_64".to_string(),
            machine: "q35".to_string(),
            cpu: "qemu64".to_string(),
            smp: 1,
            memory: "256M".to_string(),
            extra_args: Vec::new(),
            disks: BTreeMap::new(),
            tpms,
            firmware: QemuFirmware::Default,
            kernel: None,
            shim: None,
            initrd: None,
            dtb: None,
            append: None,
        };
        let socket = swtpm_socket_path(&dir, "tpm0");
        let state_dir = swtpm_state_dir(&dir, "tpm0");
        let mut children = start_swtpm_backends(&dir, &config).expect("swtpm should start");
        assert!(socket.exists(), "control socket should exist");
        assert!(state_dir.is_dir(), "state dir should exist");
        // Each child should still be alive (blocked waiting for a connection).
        for c in &mut children {
            match c.child.try_wait() {
                Ok(Some(status)) => panic!("swtpm exited unexpectedly: {status}"),
                Ok(None) => {}
                Err(e) => panic!("try_wait failed: {e}"),
            }
        }
        stop_swtpm_backends(children);
        assert!(!socket.exists(), "socket should be removed on stop");
        std::fs::remove_dir_all(&dir).ok();
    }
}
