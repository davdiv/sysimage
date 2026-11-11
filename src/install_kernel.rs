//! Kernel-mediated install path, shared by the local `install` and `ssh-install`.
//!
//! The standard [`crate::install`] pipeline writes a target with raw block I/O,
//! bypassing the OS kernel. That is safe and fast for a device the kernel is not
//! using, but destructive for one that *is* — a mounted filesystem, an open LUKS
//! container, an active LVM volume group: rewriting such a device behind the
//! kernel's back corrupts its cached view of the data.
//!
//! This module implements the alternative **kernel-mediated** path used when a
//! target device (or any structure on it) is detected to be in use. Instead of
//! writing raw, it drives the kernel's own block subsystems:
//!
//! * **GPT** — the existing table is reused (matched by partition name); missing
//!   partitions are added with `sgdisk`. Mounted/open/active partitions are
//!   driven through the kernel on their partition device; unmounted/inactive
//!   partitions are still installed raw (the kernel holds no cached pages for
//!   them). `--wipe` is refused for an in-use device, unless `--force` is given.
//! * **LUKS** — the container is treated as open if `/dev/mapper/<name>` exists
//!   **or** a dm-crypt mapper is stacked on the backing device: the mapper name is
//!   chosen at open time (`crypttab` / `cryptsetup open`) and need not match the
//!   manifest's container name. When open, the decrypted mapper device is written
//!   raw (the kernel does the crypto); when genuinely closed, the backing device is
//!   written raw with on-the-fly crypto (the container is **not** opened with
//!   `cryptsetup luksOpen`). If the backing device is held by a kernel block
//!   subsystem but no mapper can be resolved, the install is refused rather than
//!   writing raw behind the kernel's back.
//! * **LVM** — if the PV belongs to a VG the kernel knows about, the VG is driven
//!   through `lvm`: existing LVs are reused, missing ones created with
//!   `lvcreate`, and each LV's content installed (raw, or through the kernel if
//!   the LV is mounted). Otherwise the PV is treated as inactive and written raw.
//! * **Filesystem** — if the device is mounted, it is ensured read-write and the
//!   content archive is streamed straight into the mountpoint (`tar`/`cpio`),
//!   merging with the existing tree. If it is not mounted, the raw format/merge
//!   path is used.
//!
//! Everything here is generic over a [`Host`] transport, so the local install
//! (commands run directly, raw regions are local [`BlockFile`]s) and the SSH
//! install (commands run over SSH, raw regions are NBD tunnels) share one
//! implementation. [`install_with_kernel`] is the shared entry point that probes
//! each device, refuses `--wipe` for in-use ones (unless `--force` overrides it),
//! routes free devices through the raw [`install`] pipeline and in-use devices
//! through the kernel path.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;

use crate::blockfile::{BlockFile, BlockRegion};
use crate::error::{Error, Result};
use crate::install::{
    BLOCK_SIZE, DiskRegion, GPT_SECTOR_SIZE, InstallContext, compute_min_disk_size,
    gpt_name_string, install_block_subtree, install_regions, is_nbd_url, open_disk,
    resolve_archive, resolve_luks_keys,
};
use crate::manifest::ManifestWithDirectory;
use crate::model::config::ArchiveFormat;
use crate::model::manifest::{
    ManifestBlock, ManifestBlockFs, ManifestBlockGpt, ManifestBuild, ManifestGptPartition,
};
use crate::size::compute_partition_sizes;
use hadris_part::gpt::GptPartitionEntry;
use hadris_part::scheme::GptDisk;
use hadris_part::scheme_io::GptDiskReadExt;

// ===========================================================================
// Host trait — transport abstraction
// ===========================================================================

/// Abstraction over the command execution + raw-region transport used by the
/// kernel-mediated install path.
///
/// The local install implements this with direct process spawns and local
/// [`BlockFile`] regions; the SSH install implements it by running commands over
/// `ssh` and exposing remote devices as NBD tunnels. The kernel-mediated logic
/// in this module is written solely in terms of this trait, so both backends
/// share one implementation.
pub trait Host {
    /// Guard that keeps a raw region's backing transport alive for as long as
    /// the region is held. For an SSH NBD tunnel this owns the `ssh` child; for
    /// a local device it is `()` (a `BlockFile` is self-contained).
    type RawGuard;

    /// Short label used as a prefix for log messages (e.g. `"install"`,
    /// `"ssh-install"`).
    fn label(&self) -> &str;

    /// Run a command, returning trimmed stdout. Non-zero exit is an error.
    fn exec(&self, cmd: &[&str]) -> Result<String>;

    /// Run a command, returning `Some(trimmed stdout)` on success and `None` on
    /// failure. Used for best-effort probes.
    fn exec_optional(&self, cmd: &[&str]) -> Option<String>;

    /// Run a command, returning `true` on exit 0.
    fn exec_ok(&self, cmd: &[&str]) -> bool {
        self.exec(cmd).is_ok()
    }

    /// Stream `input` to `sh -c <cmd>`'s stdin. Non-zero exit is an error.
    fn pipe(&self, cmd: &str, input: &mut dyn Read) -> Result<()>;

    /// Open `device` as a sized top-level region for the raw pipeline, returning
    /// the region, a `fresh` flag (the region was just created by us and is safe
    /// to install from scratch without `--wipe`), and a guard that must outlive
    /// the region.
    fn open_disk_region(
        &self,
        device: &str,
        min_size: u64,
    ) -> Result<(DiskRegion, bool, Self::RawGuard)>;

    /// Open `device` (a sub-device in the kernel path: a partition, LV, mapper
    /// node, …) for raw block I/O, returning a region and a guard that must
    /// outlive it.
    fn open_raw_region(&self, device: &str) -> Result<(DiskRegion, Self::RawGuard)>;

    /// Return `true` if `device` (or any structure on it) is currently in use
    /// (mounted, held by `dm-crypt`, registered as an LVM PV, …). The default
    /// probes with `lsblk`/`pvs` via [`probe_in_use`]; a backend may override
    /// this to skip probing for targets that cannot be in use (e.g. a local
    /// image file or NBD URL).
    fn device_in_use(&self, device: &str) -> Result<bool>
    where
        Self: Sized,
    {
        probe_in_use(self, device)
    }
}

/// A local [`Host`]: commands run directly on this machine and raw regions are
/// local [`BlockFile`]s.
pub struct LocalHost;

impl Host for LocalHost {
    type RawGuard = ();

    fn label(&self) -> &str {
        "install"
    }

    fn exec(&self, cmd: &[&str]) -> Result<String> {
        crate::exec::exec(cmd)
    }

    fn exec_optional(&self, cmd: &[&str]) -> Option<String> {
        match crate::exec::exec(cmd) {
            Ok(out) => Some(out),
            Err(e) => {
                eprintln!("install: (skipping probe) {e}");
                None
            }
        }
    }

    fn pipe(&self, cmd: &str, input: &mut dyn Read) -> Result<()> {
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|e| Error::msg(format!("Failed to start sh -c: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            std::io::copy(input, &mut stdin).map_err(|e| Error::msg(format!("pipe copy: {e}")))?;
        }
        let status = child
            .wait()
            .map_err(|e| Error::msg(format!("pipe wait: {e}")))?;
        if !status.success() {
            return Err(Error::msg(format!(
                "Extraction command failed (exit {status}): {cmd}"
            )));
        }
        Ok(())
    }

    fn open_disk_region(
        &self,
        device: &str,
        min_size: u64,
    ) -> Result<(DiskRegion, bool, Self::RawGuard)> {
        let (region, fresh) = open_disk(device, min_size)?;
        Ok((region, fresh, ()))
    }

    fn open_raw_region(&self, device: &str) -> Result<(DiskRegion, Self::RawGuard)> {
        // Sub-devices in the kernel path are always existing block nodes; open
        // the whole device for raw I/O.
        let path = PathBuf::from(device);
        let size = local_device_size(&path)?;
        let bf = BlockFile::open(&path, 0, size)?;
        Ok((DiskRegion::File(bf), ()))
    }

    fn device_in_use(&self, device: &str) -> Result<bool> {
        // Only real local block devices can be in use; image files and NBD URLs
        // are never kernel-managed, so skip the probe for them.
        if is_nbd_url(device) {
            return Ok(false);
        }
        let path = PathBuf::from(device);
        match std::fs::metadata(&path) {
            Ok(info) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if !info.file_type().is_block_device() {
                        return Ok(false);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = info;
                    return Ok(false);
                }
                probe_in_use(self, device)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::from(e)),
        }
    }
}

/// Size in bytes of a local block device (or file), via `blockdev --getsize64`
/// for block devices and the file length otherwise.
fn local_device_size(path: &PathBuf) -> Result<u64> {
    let info = std::fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if info.file_type().is_block_device() {
            let out = crate::exec::exec(&["blockdev", "--getsize64", &path.to_string_lossy()])?;
            return Ok(out.trim().parse::<u64>().unwrap_or(0));
        }
    }
    Ok(info.len())
}

// ===========================================================================
// Shared entry point
// ===========================================================================

/// Install a built system onto the devices described by the manifest, probing
/// each device for in-use state and routing free devices through the raw
/// [`install`] pipeline and in-use devices through the kernel-mediated path.
///
/// This is the shared entry point used by both the local `install` (with
/// [`LocalHost`]) and `ssh-install` (with its own [`Host`] implementation):
///
/// * every device that is **not** in use is installed via the standard raw
///   pipeline ([`install_regions`]) against a manifest filtered to just the free
///   disks — preserving cross-disk volume-group handling among them;
/// * every device that **is** in use is driven through the kernel via
///   [`install_disk_kernel`];
/// * `--wipe` is refused for any in-use device, unless `force` is set — then the
///   in-use device is force-wiped from scratch via the raw pipeline, bypassing
///   the kernel-mediated path.
pub fn install_with_kernel<H: Host>(
    host: &H,
    manifest: ManifestWithDirectory,
    disk: BTreeMap<String, String>,
    key: BTreeMap<String, String>,
    key_file: BTreeMap<String, PathBuf>,
    wipe: bool,
    force: bool,
) -> Result<()> {
    let manifest_directory = manifest.manifest_directory.clone();

    // Validate that every manifest disk has a target configured, before probing
    // or prompting for any LUKS passphrases.
    for disk_name in manifest.manifest.disk.keys() {
        if !disk.contains_key(disk_name) {
            return Err(Error::msg(format!(
                "No target configured for disk \"{disk_name}\".                      \
                 Pass it with --disk {disk_name}=<path>"
            )));
        }
    }

    // Probe each device once, partitioning disks into free vs. in-use.
    let mut free_disks: BTreeSet<String> = BTreeSet::new();
    let mut in_use_disks: BTreeSet<String> = BTreeSet::new();
    for (disk_name, device) in &disk {
        eprintln!(
            "{}: probing {} (disk \"{disk_name}\")...",
            host.label(),
            device
        );
        if host.device_in_use(device)? {
            in_use_disks.insert(disk_name.clone());
            eprintln!(
                "{}: {device} is in use → kernel-mediated path.",
                host.label()
            );
        } else {
            free_disks.insert(disk_name.clone());
            eprintln!("{}: {device} is free → raw path.", host.label());
        }
    }

    // Apply the --wipe/--force safety policy: without --force, refuse --wipe for
    // any in-use disk; with --force, move every in-use disk to the free set so it
    // is force-wiped from scratch by the raw pipeline (repartition/format),
    // bypassing the kernel-mediated reconcile path.
    let forced = apply_wipe_policy(&disk, &mut free_disks, &mut in_use_disks, wipe, force)?;
    for disk_name in &forced {
        eprintln!(
            "{}: --force: force-wiping in-use disk \"{disk_name}\" ({}) from scratch.",
            host.label(),
            disk[disk_name]
        );
    }

    // Resolve LUKS passphrases once for the whole install.
    let keys = resolve_luks_keys(&manifest.manifest, &key, &key_file)?;

    // Detect cross-disk VGs that span the raw/kernel boundary: a VG referenced
    // by both a free and an in-use disk cannot be installed half by the raw
    // pipeline and half by the kernel handler.
    let free_vgs = vg_names_for_disks(&manifest.manifest, &free_disks);
    let inuse_vgs = vg_names_for_disks(&manifest.manifest, &in_use_disks);
    if let Some(vg) = free_vgs.intersection(&inuse_vgs).next() {
        return Err(Error::msg(format!(
            "LVM volume group \"{vg}\" is referenced by both a not-in-use disk (raw path) and an \
             in-use disk (kernel path). It cannot be driven across that boundary. Deactivate the \
             VG on the in-use disk so it is treated as raw, or activate it on every disk that \
             participates."
        )));
    }

    // Free disks: install via the raw pipeline against a manifest filtered to
    // exactly those disks (and their VGs).
    if !free_disks.is_empty() {
        let filtered = filter_manifest(&manifest.manifest, &free_disks);
        let mut free_ctx =
            InstallContext::new(filtered, manifest_directory.clone(), wipe, keys.clone());
        let mut regions: BTreeMap<String, DiskRegion> = BTreeMap::new();
        let mut fresh: BTreeMap<String, bool> = BTreeMap::new();
        // Keep the raw-region guards alive for the whole install_regions call.
        let mut _guards: Vec<H::RawGuard> = Vec::new();
        for disk_name in &free_disks {
            let device = &disk[disk_name];
            let min_size = compute_min_disk_size(&manifest.manifest.disk[disk_name]);
            eprintln!(
                "{}: installing disk \"{disk_name}\" to {device} ...",
                host.label()
            );
            let (region, created, guard) = host.open_disk_region(device, min_size)?;
            if created {
                eprintln!("  Target is a newly created/empty image — treating as fresh.");
            }
            regions.insert(disk_name.clone(), region);
            fresh.insert(disk_name.clone(), created);
            _guards.push(guard);
        }
        eprintln!(
            "{}: installing not-in-use disks via raw pipeline...",
            host.label()
        );
        install_regions(&mut free_ctx, regions, fresh)?;
        // guards dropped here.
    }

    // In-use disks: drive each through the kernel.
    if !in_use_disks.is_empty() {
        let mut ctx =
            InstallContext::new(manifest.manifest.clone(), manifest_directory, wipe, keys);
        for disk_name in &in_use_disks {
            let device = &disk[disk_name];
            let block = ctx.manifest.disk[disk_name].clone();
            eprintln!(
                "{}: installing in-use disk \"{disk_name}\" ({device}) via kernel...",
                host.label()
            );
            install_disk_kernel(host, &mut ctx, &block, device)?;
        }
    }

    eprintln!("{}: complete.", host.label());
    Ok(())
}

/// Apply the `--wipe`/`--force` safety policy to the probed disk sets.
///
/// `free` and `in_use` are the results of probing each configured disk. Without
/// `wipe` the sets are returned unchanged and `force` has no effect. With `wipe`
/// and `force`, every in-use disk is moved from `in_use` to `free` (returned as
/// the list of disk names to log) so it is force-wiped from scratch by the raw
/// pipeline. With `wipe` and no `force`, an in-use disk is an error.
fn apply_wipe_policy(
    disk: &BTreeMap<String, String>,
    free: &mut BTreeSet<String>,
    in_use: &mut BTreeSet<String>,
    wipe: bool,
    force: bool,
) -> Result<Vec<String>> {
    if !wipe {
        return Ok(Vec::new());
    }
    if force {
        let forced: Vec<String> = std::mem::take(in_use).into_iter().collect();
        for name in &forced {
            free.insert(name.clone());
        }
        return Ok(forced);
    }
    if let Some(disk_name) = in_use.iter().next() {
        let device = &disk[disk_name];
        return Err(Error::msg(format!(
            "Device {device} (disk \"{disk_name}\") is currently in use. --wipe cannot be used \
             on an in-use device: it would destroy mounted or active data. Deactivate the \
             structures (unmount / close LUKS / deactivate VG) first, or pass --force to wipe \
             it anyway, or drop --wipe to reconcile."
        )));
    }
    Ok(Vec::new())
}

// ===========================================================================
// In-use detection
// ===========================================================================

/// Probe whether `device` (or any of its partitions) is mounted, held by another
/// block subsystem, or registered as an LVM physical volume, using `lsblk` and
/// `pvs` through `host`.
fn probe_in_use<H: Host>(host: &H, device: &str) -> Result<bool> {
    // lsblk gives the mountpoints of the device and all its partitions in one
    // shot, as JSON so the empty value is unambiguous (`mountpoints: [null]` for
    // an unmounted node). `lsblk` has no `HOLDERS` output column (holders are
    // only available via the inverse dependency tree), so kernel holders are
    // detected separately from sysfs below.
    let lsblk_out = host
        .exec(&["lsblk", "--json", "-b", "-o", "NAME,MOUNTPOINTS", device])
        .map_err(|e| {
            Error::msg(format!(
                "Failed to probe device {device}: {e}. Check that the device path exists."
            ))
        })?;
    let v: serde_json::Value = serde_json::from_str(&lsblk_out)
        .map_err(|e| Error::msg(format!("Could not parse lsblk output for {device}: {e}")))?;
    let mut device_paths: Vec<String> = Vec::new();
    if any_in_use(&v, &mut device_paths) {
        return Ok(true);
    }

    // Kernel holders (dm-crypt, md, …): a non-empty `/sys/class/block/<name>/
    // holders/` directory means a subsystem is holding the device, so it is in
    // use and must not be repartitioned/formatted out from under it.
    if any_sysfs_holders(host, &device_paths) {
        return Ok(true);
    }

    // LVM PVs: `pvs` lists physical volumes by device path. A PV with no active
    // LV still shows no kernel holder, but repartitioning it would corrupt the
    // VG, so treat any matching PV as in use.
    if let Some(pvs_out) = host.exec_optional(&["pvs", "--noheadings", "-o", "pv_name"]) {
        let pv_set: BTreeSet<&str> = pvs_out
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        for path in &device_paths {
            if pv_set.contains(path.as_str()) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Detect kernel holders via sysfs. `device_paths` are the `/dev/<name>`
/// entries collected from the lsblk tree; a non-empty
/// `/sys/class/block/<name>/holders/` directory means a kernel subsystem
/// (dm-crypt, md, …) is holding the device, so it is in use.
fn any_sysfs_holders<H: Host>(host: &H, device_paths: &[String]) -> bool {
    let names: Vec<&str> = device_paths
        .iter()
        .filter_map(|p| p.strip_prefix("/dev/"))
        .collect();
    if names.is_empty() {
        return false;
    }
    let script = "for n in \"$@\"; do d=\"/sys/class/block/$n/holders\"; \
                  [ -d \"$d\" ] && [ \"$(ls -A \"$d\" 2>/dev/null)\" ] && exit 0; done; exit 1";
    let mut args: Vec<&str> = Vec::with_capacity(names.len() + 4);
    args.extend(["sh", "-c", script, "sh"]);
    args.extend(names);
    host.exec_ok(&args)
}

/// Recursively walk the `blockdevices` tree from `lsblk --json`, collecting the
/// `/dev/<name>` path of every visited node into `paths`. Returns `true` if any
/// node has a non-empty `mountpoints` array (a non-null entry). Kernel holders
/// are detected separately from sysfs by [`any_sysfs_holders`].
fn any_in_use(v: &serde_json::Value, paths: &mut Vec<String>) -> bool {
    let Some(nodes) = v.get("blockdevices").and_then(|d| d.as_array()) else {
        return false;
    };
    any_in_use_nodes(nodes, paths)
}

/// Walk one level of `lsblk` nodes — the top-level `blockdevices` array or a
/// node's `children` array — collecting each node's `/dev/<name>` path and
/// recursing into its children. Returns `true` as soon as a node is mounted.
///
/// The recursion must operate on the bare array: `children` is a JSON array,
/// so it has no `blockdevices` key. Passing it back through [`any_in_use`]
/// would silently terminate the walk at the first level, hiding every mounted
/// filesystem and kernel holder on the disk's partitions (see the `/dev/sda`
/// root-disk incident this guards against).
fn any_in_use_nodes(nodes: &[serde_json::Value], paths: &mut Vec<String>) -> bool {
    for node in nodes {
        if let Some(name) = node.get("name").and_then(|n| n.as_str()) {
            paths.push(format!("/dev/{name}"));
        }
        if has_nonempty_array(node, "mountpoints") {
            return true;
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array())
            && any_in_use_nodes(children, paths)
        {
            return true;
        }
    }
    false
}

/// `lsblk` emits `mountpoints: [null]` for an unmounted node; a mounted one is
/// `["/mnt"]`. Treat any non-null element as "in use".
fn has_nonempty_array(node: &serde_json::Value, key: &str) -> bool {
    node.get(key)
        .and_then(|a| a.as_array())
        .is_some_and(|a| a.iter().any(|e| !e.is_null()))
}

/// Walk the `blockdevices` tree from `lsblk --json`, returning the `/dev`
/// mapper path of the first `crypt` (dm-crypt) node found, if any.
///
/// A LUKS backing device exposes its dm-crypt mapper as a child in `lsblk`.
/// The mapper's name is chosen when the container is opened (by `crypttab` or
/// `cryptsetup open`) and need not match the manifest's container `name`, so
/// this — not `test -b /dev/mapper/<name>` — is what determines whether the
/// container is actually open. Without this check an open, in-use container is
/// misclassified as closed and the raw path writes behind the kernel's back.
fn first_crypt_child(v: &serde_json::Value) -> Option<String> {
    let nodes = v.get("blockdevices").and_then(|d| d.as_array())?;
    first_crypt_node(nodes)
}

/// One level of [`first_crypt_child`]'s recursion.
fn first_crypt_node(nodes: &[serde_json::Value]) -> Option<String> {
    for node in nodes {
        let is_crypt = node.get("type").and_then(|t| t.as_str()) == Some("crypt");
        if is_crypt && let Some(name) = node.get("name").and_then(|n| n.as_str()) {
            // `lsblk` names dm devices by their mapper name (`cryptlvm`), which
            // is a symlink under `/dev/mapper`; fall back to `/dev/dm-N` if it
            // ever reports the kernel node name instead.
            return Some(if name.starts_with("dm-") {
                format!("/dev/{name}")
            } else {
                format!("/dev/mapper/{name}")
            });
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array())
            && let Some(found) = first_crypt_node(children)
        {
            return Some(found);
        }
    }
    None
}

// ===========================================================================
// Phase 2 — kernel-mediated operations for in-use devices
// ===========================================================================

/// Install an in-use disk through the kernel.
///
/// Only a GPT block gets the kernel-mediated partition handler; any other
/// top-level block (a raw LUKS/LVM/FS/image device) is dispatched directly to
/// the recursive [`install_block_kernel`].
fn install_disk_kernel<H: Host>(
    host: &H,
    ctx: &mut InstallContext,
    block: &ManifestBlock,
    device: &str,
) -> Result<()> {
    match block {
        ManifestBlock::Gpt(b) => {
            if b.mbr.is_some() {
                Err(Error::msg(
                    "Kernel-mediated install of in-use hybrid MBR disks is not supported. \
                     Deactivate the disk (unmount partitions, close LUKS, deactivate VGs) \
                     or use --wipe --force to wipe it from scratch.",
                ))
            } else {
                gpt_kernel_handler(host, ctx, b, device)
            }
        }
        ManifestBlock::Mbr(_) => Err(Error::msg(
            "Kernel-mediated install of in-use MBR disks is not supported. \
             Deactivate the disk (unmount partitions, close LUKS, deactivate VGs) \
             or use --wipe --force to wipe it from scratch.",
        )),
        other => install_block_kernel(host, ctx, other, device, false),
    }
}

/// Recursively install `block` into `device`, choosing per node between a raw
/// path (for inactive/closed structures) and a kernel-mediated path (for
/// mounted/open/active structures).
///
/// `fresh` selects from-scratch vs. reconcile for the raw path; the kernel path
/// always reconciles (it reuses existing structures).
fn install_block_kernel<H: Host>(
    host: &H,
    ctx: &mut InstallContext,
    block: &ManifestBlock,
    device: &str,
    fresh: bool,
) -> Result<()> {
    match block {
        ManifestBlock::Luks(b) => {
            if let Some(mapper) = resolve_luks_mapper(host, device, &b.name)? {
                // Already open — under the manifest name, or (commonly) under a
                // crypttab-chosen name that differs from it. Recurse into the
                // decrypted mapper device. The kernel does the crypto; we never
                // `cryptsetup luksOpen` here.
                eprintln!(
                    "{}: LUKS \"{}\" is open → recursing into {mapper}",
                    host.label(),
                    b.name
                );
                if let Some(content) = &b.content {
                    install_block_kernel(host, ctx, content, &mapper, false)
                } else {
                    Ok(())
                }
            } else {
                // Genuinely closed: raw-write the backing device and use the
                // standard on-the-fly-crypto path (no `cryptsetup luksOpen`).
                eprintln!(
                    "{}: LUKS \"{}\" is closed → raw + on-the-fly crypto on {device}",
                    host.label(),
                    b.name
                );
                let (mut region, guard) = host.open_raw_region(device)?;
                let r = install_block_subtree(ctx, block, &mut region, fresh);
                drop(guard);
                r
            }
        }
        ManifestBlock::Lvm(b) => {
            if let Some(vg) = &b.vg
                && host_vg_for_pv(host, device).as_deref() == Some(vg.as_str())
            {
                // The kernel manages this VG: drive LVs through it.
                eprintln!(
                    "{}: PV {device} belongs to active VG \"{vg}\" → kernel path",
                    host.label()
                );
                lvm_kernel_handler(host, ctx, vg, device)
            } else {
                // Inactive PV: raw-write and let the standard pipeline write LVM
                // metadata + LV content.
                eprintln!("{}: PV {device} is inactive → raw", host.label());
                let (mut region, guard) = host.open_raw_region(device)?;
                let r = install_block_subtree(ctx, block, &mut region, fresh);
                drop(guard);
                r
            }
        }
        ManifestBlock::Ext4(b) | ManifestBlock::Fat(b) => {
            if let Some(mnt) = host_mountpoint(host, device) {
                eprintln!(
                    "{}: {device} mounted at {mnt} → streaming extract",
                    host.label()
                );
                fs_kernel_extract(host, ctx, b, device, &mnt)
            } else {
                eprintln!("{}: {device} not mounted → raw", host.label());
                let (mut region, guard) = host.open_raw_region(device)?;
                let r = install_block_subtree(ctx, block, &mut region, fresh);
                drop(guard);
                r
            }
        }
        ManifestBlock::Image(_) => {
            eprintln!("{}: image block on {device} → raw", host.label());
            let (mut region, guard) = host.open_raw_region(device)?;
            let r = install_block_subtree(ctx, block, &mut region, fresh);
            drop(guard);
            r
        }
        ManifestBlock::Gpt(_) | ManifestBlock::Mbr(_) => {
            // No kernel handler for a nested partition table: write it (and its
            // nested content) directly via byte-offset sub-regions of the
            // inner device. The inner partitions are not exposed as kernel
            // devices, so the raw path is the correct one.
            eprintln!("{}: nested partition table on {device} → raw", host.label());
            let (mut region, guard) = host.open_raw_region(device)?;
            let r = install_block_subtree(ctx, block, &mut region, fresh);
            drop(guard);
            r
        }
    }
}

/// Kernel-mediated GPT handler for an in-use whole disk.
///
/// Reads the existing GPT through a whole-disk raw region, reuses manifest
/// partitions by name, creates missing partitions with `sgdisk` (never rewriting
/// the table wholesale), then dispatches each partition's content:
/// mounted/open/active partitions go through [`install_block_kernel`] on their
/// partition device path; unmounted/inactive partitions are installed raw via a
/// sub-region of the whole-disk region (safe — the kernel has no cached pages
/// for them).
fn gpt_kernel_handler<H: Host>(
    host: &H,
    ctx: &mut InstallContext,
    block: &ManifestBlockGpt,
    device: &str,
) -> Result<()> {
    eprintln!(
        "{}: GPT on in-use disk {device} → kernel handler",
        host.label()
    );
    // One whole-disk raw region for the whole operation: GPT read + raw
    // partition installs (via offset sub-regions) for unmounted partitions.
    let (mut whole, whole_guard) = host.open_raw_region(device)?;

    // Read the existing GPT.
    let existing = GptDisk::read_from(&mut whole, GPT_SECTOR_SIZE as u32)
        .map_err(|e| Error::msg(format!("reading GPT on {device}: {e}")))?;
    let preserved: Vec<GptPartitionEntry> = existing
        .entries
        .iter()
        .filter(|e| !e.is_unused())
        .cloned()
        .collect();

    // Match manifest partitions against the existing table by name.
    let mut is_new: Vec<bool> = vec![false; block.partitions.len()];
    let mut offsets: Vec<u64> = vec![0; block.partitions.len()];
    let mut sizes: Vec<u64> = vec![0; block.partitions.len()];
    let mut new_indices: Vec<usize> = Vec::new();
    let mut new_specs: Vec<crate::model::manifest::ManifestPartitionSize> = Vec::new();
    for (i, p) in block.partitions.iter().enumerate() {
        if let Some(entry) = preserved.iter().find(|e| gpt_name_string(e) == p.name) {
            offsets[i] = entry.first_lba.to_ne() * GPT_SECTOR_SIZE;
            sizes[i] = entry.size_sectors() * GPT_SECTOR_SIZE;
            if sizes[i] < p.size.size_min {
                return Err(Error::msg(format!(
                    "Existing GPT partition \"{}\" is {} bytes, smaller than the manifest \
                     minimum ({}).",
                    p.name, sizes[i], p.size.size_min
                )));
            }
        } else {
            is_new[i] = true;
            new_indices.push(i);
            new_specs.push(p.size.clone());
        }
    }

    // Create the missing partitions with sgdisk, placing them in the free space
    // after the last existing entry (aligned to BLOCK_SIZE).
    if !new_indices.is_empty() {
        let first_usable = existing.primary_header.first_usable_lba.to_ne();
        let last_usable = existing.primary_header.last_usable_lba.to_ne();
        let max_end = preserved
            .iter()
            .map(|e| e.last_lba.to_ne())
            .max()
            .unwrap_or(first_usable.saturating_sub(1));
        let align_sectors = BLOCK_SIZE / GPT_SECTOR_SIZE;
        let first_free = {
            let start = (max_end + 1).max(first_usable);
            start.div_ceil(align_sectors) * align_sectors
        }
        .max(first_usable);
        if first_free > last_usable {
            return Err(Error::msg(format!(
                "No free space on disk {device} for new GPT partitions"
            )));
        }
        let available = (last_usable + 1 - first_free) * GPT_SECTOR_SIZE;
        let mut size_specs = new_specs.clone();
        if let Some(empty) = &block.empty_space {
            size_specs.push(empty.clone());
        }
        let computed = compute_partition_sizes(&size_specs, available, BLOCK_SIZE)?;
        let new_sizes = &computed[..new_specs.len()];

        // sgdisk partition numbers are 1-based; use the next slot after the last
        // used entry.
        let max_slot = existing
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_unused())
            .map(|(i, _)| i as u32 + 1)
            .max()
            .unwrap_or(0);
        let base_partnum = max_slot + 1;
        let mut current = first_free;
        for (k, &i) in new_indices.iter().enumerate() {
            let p = &block.partitions[i];
            let psize = new_sizes[k];
            let sectors = psize / GPT_SECTOR_SIZE;
            let first_lba = current;
            let last_lba = first_lba + sectors - 1;
            offsets[i] = first_lba * GPT_SECTOR_SIZE;
            sizes[i] = psize;
            let partnum = base_partnum + k as u32;
            sgdisk_create(host, device, partnum, first_lba, last_lba, p)?;
            eprintln!(
                "{}: created partition \"{}\" (#{partnum}, offset={}, size={}) on {device}",
                host.label(),
                p.name,
                offsets[i],
                sizes[i]
            );
            current = last_lba + 1;
        }
    }

    // Map partition name → device path via lsblk PARTLABEL.
    let partlabel_map = lsblk_partlabel(host, device);

    // Dispatch each manifest partition's content.
    for (i, p) in block.partitions.iter().enumerate() {
        let Some(content) = &p.content else { continue };
        let fresh = is_new[i];
        let part_device = partlabel_map.get(&p.name);
        let active = part_device
            .map(|d| host.device_in_use(d).unwrap_or(false))
            .unwrap_or(false);
        if active {
            // Mounted/open/active: drive through the kernel on the partition device.
            let part_device = part_device.ok_or_else(|| {
                Error::msg(format!(
                    "Partition \"{}\" on {device} is active but could not be resolved to a \
                     device path (lsblk PARTLABEL map).",
                    p.name
                ))
            })?;
            eprintln!(
                "{}: partition \"{}\" ({part_device}) is active → kernel path",
                host.label(),
                p.name
            );
            install_block_kernel(host, ctx, content, part_device, fresh)?;
        } else {
            // Inactive: install raw via a sub-region of the whole-disk region.
            eprintln!(
                "{}: partition \"{}\" is inactive → raw (offset={}, size={})",
                host.label(),
                p.name,
                offsets[i],
                sizes[i]
            );
            let mut sub = whole.open_region(offsets[i], sizes[i]);
            install_block_subtree(ctx, content, &mut sub, fresh)?;
        }
    }
    drop(whole_guard);
    Ok(())
}

/// Kernel-mediated handler for an active (kernel-managed) LVM VG.
///
/// Reuses existing LVs by name, creates missing ones with `lvcreate`, and
/// installs each LV's content via [`install_block_kernel`] (raw for an inactive
/// LV, kernel path for a mounted/open one). The LVM metadata is owned by the
/// kernel/lvm; we never write it ourselves.
fn lvm_kernel_handler<H: Host>(
    host: &H,
    ctx: &mut InstallContext,
    vg: &str,
    _pv_device: &str,
) -> Result<()> {
    let vg_manifest = ctx.manifest.lvm.get(vg).cloned().ok_or_else(|| {
        Error::msg(format!(
            "No LVM volume group \"{vg}\" in manifest but a PV references it"
        ))
    })?;

    let existing_lvs = lvs_list(host, vg);
    let (free_bytes, pe_size) = vgs_info(host, vg);

    // Plan new LV sizes (in extents) for the missing ones.
    let mut new_indices: Vec<usize> = Vec::new();
    let mut new_specs: Vec<crate::model::manifest::ManifestPartitionSize> = Vec::new();
    for (i, p) in vg_manifest.partitions.iter().enumerate() {
        if !existing_lvs.contains_key(&p.name) {
            new_indices.push(i);
            new_specs.push(p.size.clone());
        }
    }
    if !new_indices.is_empty() {
        let mut size_specs = new_specs.clone();
        if let Some(empty) = &vg_manifest.empty_space {
            size_specs.push(empty.clone());
        }
        let computed = compute_partition_sizes(&size_specs, free_bytes, pe_size)?;
        let new_sizes = &computed[..new_specs.len()];
        for (k, &i) in new_indices.iter().enumerate() {
            let p = &vg_manifest.partitions[i];
            let size = new_sizes[k];
            let extents = size / pe_size;
            if extents == 0 {
                return Err(Error::msg(format!(
                    "New LVM volume \"{}\" is smaller than one extent ({pe_size} bytes)",
                    p.name
                )));
            }
            lvcreate(host, vg, &p.name, extents)?;
            eprintln!(
                "{}: created LV \"{}\" ({extents} extents) in VG \"{vg}\"",
                host.label(),
                p.name
            );
        }
    }

    // Install each LV's content.
    for p in &vg_manifest.partitions {
        let Some(content) = &p.content else { continue };
        let lv_device = format!("/dev/{vg}/{}", p.name);
        // Best-effort activation of reused LVs.
        if existing_lvs.contains_key(&p.name) {
            let _ = host.exec_optional(&["lvchange", "-ay", &lv_device]);
        }
        let fresh = !existing_lvs.contains_key(&p.name);
        // For a reused LV, check it is large enough.
        if let Some(existing_size) = existing_lvs.get(&p.name)
            && *existing_size < p.size.size_min
        {
            return Err(Error::msg(format!(
                "Existing LV \"{lv_device}\" is {existing_size} bytes, smaller than the manifest \
                 minimum ({}).",
                p.size.size_min
            )));
        }
        eprintln!(
            "{}: LV \"{lv_device}\" (fresh={fresh}) → installing content",
            host.label()
        );
        install_block_kernel(host, ctx, content, &lv_device, fresh)?;
    }
    Ok(())
}

/// Stream a filesystem content archive straight into a mountpoint (kernel
/// path). The archive is decompressed locally (zstd) and piped to a `tar`/`cpio`
/// extractor that merges it into the existing mounted tree. No formatting is
/// done — the filesystem is already mounted and reused as-is.
fn fs_kernel_extract<H: Host>(
    host: &H,
    ctx: &InstallContext,
    block: &ManifestBlockFs,
    device: &str,
    mountpoint: &str,
) -> Result<()> {
    let Some(archive) = &block.archive else {
        eprintln!(
            "{}: {device} mounted at {mountpoint}, no archive to extract",
            host.label()
        );
        return Ok(());
    };
    ensure_rw(host, device, mountpoint)?;
    let archive_path = resolve_archive(ctx, archive)?;
    eprintln!(
        "{}: streaming {:?} archive into {mountpoint} on {device}...",
        host.label(),
        archive.format
    );
    let compressed = std::fs::File::open(&archive_path)?;
    let mut decoder =
        zstd::Decoder::new(compressed).map_err(|e| Error::msg(format!("zstd: {e}")))?;
    let quoted = shell_quote(mountpoint);
    match archive.format {
        ArchiveFormat::Tar => host.pipe(&format!("tar -C {quoted} -xpf -"), &mut decoder),
        ArchiveFormat::Cpio => {
            host.pipe(&format!("cd {quoted} && cpio -idm --quiet"), &mut decoder)
        }
    }
}

// ---------------------------------------------------------------------------
// Host command helpers (Phase 2)
// ---------------------------------------------------------------------------

/// `test -b <path>` through `host`.
fn host_test_b<H: Host>(host: &H, path: &str) -> Result<bool> {
    Ok(host.exec_ok(&["test", "-b", path]))
}

/// Resolve the mapper device for a LUKS container whose backing device is
/// `device`, or `None` if the container is genuinely closed.
///
/// The manifest's container `name` is only a key-lookup label; the dm-crypt
/// mapper is named when the container is opened (`crypttab`, `cryptsetup
/// open`) and may differ — e.g. manifest `luks` vs. live `cryptlvm`. Relying on
/// `/dev/mapper/<name>` alone therefore misclassifies an *open, in-use*
/// container as closed, and the raw on-the-fly-crypto path would then write
/// behind the kernel's back, corrupting the live device.
///
/// Returns an error if the backing device is held by a kernel block subsystem
/// but no mapper could be resolved: writing raw would be unsafe.
fn resolve_luks_mapper<H: Host>(host: &H, device: &str, name: &str) -> Result<Option<String>> {
    // Fast path: the manifest name happens to match the mapper name.
    let by_name = format!("/dev/mapper/{name}");
    if host_test_b(host, &by_name)? {
        return Ok(Some(by_name));
    }

    // The container may be open under a different name; find any dm-crypt
    // mapper stacked on the backing device.
    if let Some(mapper) = crypt_mapper_for_backing(host, device) {
        return Ok(Some(mapper));
    }

    // Not mapped under any name we can see. If the backing device is
    // nevertheless held by a kernel subsystem, the raw path (which writes
    // behind the kernel's back) must not run.
    if any_sysfs_holders(host, &[device.to_string()]) {
        return Err(Error::msg(format!(
            "LUKS container \"{name}\" is not mapped at /dev/mapper/{name}, but its backing \
             device {device} is held by a kernel block subsystem (it appears to be open under a \
             different mapper name). Refusing to write raw to an in-use device. Close the \
             container, or map it as /dev/mapper/{name}."
        )));
    }

    Ok(None)
}

/// The mapper path of a dm-crypt device stacked on `device`, as reported by
/// `lsblk`, if any.
fn crypt_mapper_for_backing<H: Host>(host: &H, device: &str) -> Option<String> {
    let out = host.exec_optional(&["lsblk", "--json", "-b", "-o", "NAME,TYPE", device])?;
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    first_crypt_child(&v)
}

/// Mountpoint of `device`, or `None` if not mounted. Uses `findmnt -S` which
/// exits non-zero (1) when the device is not mounted.
fn host_mountpoint<H: Host>(host: &H, device: &str) -> Option<String> {
    let out = host.exec_optional(&["findmnt", "-n", "-o", "TARGET", "-S", device])?;
    let t = out.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Ensure `device` is mounted read-write; remount rw if currently ro.
fn ensure_rw<H: Host>(host: &H, device: &str, mountpoint: &str) -> Result<()> {
    let opts = host
        .exec_optional(&["findmnt", "-n", "-o", "OPTIONS", "-S", device])
        .unwrap_or_default();
    if opts.split(',').any(|o| o.trim() == "ro") {
        eprintln!(
            "{}: {device} is mounted read-only; remounting rw...",
            host.label()
        );
        host.exec(&["mount", "-o", "remount,rw", mountpoint])?;
    }
    Ok(())
}

/// VG name that the kernel associates with `pv_device`, if any.
fn host_vg_for_pv<H: Host>(host: &H, pv_device: &str) -> Option<String> {
    let out = host.exec_optional(&["pvs", pv_device, "--noheadings", "-o", "vg_name"])?;
    let t = out.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// `lvs` of `vg`: name → size in bytes.
fn lvs_list<H: Host>(host: &H, vg: &str) -> BTreeMap<String, u64> {
    let out = host.exec_optional(&[
        "lvs",
        vg,
        "--noheadings",
        "--nosuffix",
        "--units",
        "b",
        "-o",
        "lv_name,lv_size",
    ]);
    let mut map = BTreeMap::new();
    if let Some(out) = out {
        for line in out.lines() {
            let mut it = line.split_whitespace();
            if let (Some(name), Some(size)) = (it.next(), it.last())
                && let Ok(b) = size.trim_end_matches('B').parse::<u64>()
            {
                map.insert(name.to_string(), b);
            }
        }
    }
    map
}

/// `vgs` of `vg`: (free bytes, extent size bytes).
fn vgs_info<H: Host>(host: &H, vg: &str) -> (u64, u64) {
    let out = host.exec_optional(&[
        "vgs",
        vg,
        "--noheadings",
        "--nosuffix",
        "--units",
        "b",
        "-o",
        "vg_free,vg_extent_size",
    ]);
    let parse = |s: &str| s.trim().trim_end_matches('B').parse::<u64>().unwrap_or(0);
    if let Some(out) = out {
        let mut it = out.split_whitespace();
        let free = it.next().map(parse).unwrap_or(0);
        let pe = it.last().map(parse).unwrap_or(0);
        (free, pe)
    } else {
        (0, 0)
    }
}

/// Create a partition on `disk` with `sgdisk`.
fn sgdisk_create<H: Host>(
    host: &H,
    disk: &str,
    partnum: u32,
    first_lba: u64,
    last_lba: u64,
    p: &ManifestGptPartition,
) -> Result<()> {
    let n = format!("{partnum}:{first_lba}:{last_lba}");
    let c = format!("{partnum}:{}", p.name);
    let t = format!("{partnum}:{}", p.type_guid);
    host.exec(&["sgdisk", "-n", &n, "-c", &c, "-t", &t, disk])
        .map(|_| ())
        .map_err(|e| {
            Error::msg(format!(
                "sgdisk create partition \"{}\" on {disk}: {e}",
                p.name
            ))
        })
}

/// `lvcreate -l <extents> -n <name> <vg>`.
fn lvcreate<H: Host>(host: &H, vg: &str, name: &str, extents: u64) -> Result<()> {
    let l = format!("{extents}");
    host.exec(&["lvcreate", "-l", &l, "-n", name, vg])
        .map(|_| ())
        .map_err(|e| Error::msg(format!("lvcreate \"{name}\" in VG \"{vg}\": {e}")))
}

/// Partition-name (PARTLABEL) → `/dev/<name>` map for a disk.
fn lsblk_partlabel<H: Host>(host: &H, disk: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let out = host.exec_optional(&["lsblk", "-n", "-l", "-o", "NAME,PARTLABEL", disk]);
    if let Some(out) = out {
        for line in out.lines() {
            let mut it = line.split_whitespace();
            let Some(name) = it.next() else { continue };
            let label = it.next().unwrap_or("");
            if !label.is_empty() {
                map.insert(label.to_string(), format!("/dev/{name}"));
            }
        }
    }
    map
}

/// Single-quote a string for a POSIX shell argument.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ---------------------------------------------------------------------------
// Manifest filtering for the mixed raw/kernel path
// ---------------------------------------------------------------------------

/// Names of all LVM volume groups referenced (transitively) by the given set of
/// disks in the manifest.
fn vg_names_for_disks(manifest: &ManifestBuild, disks: &BTreeSet<String>) -> BTreeSet<String> {
    let mut vgs = BTreeSet::new();
    for dn in disks {
        if let Some(block) = manifest.disk.get(dn) {
            collect_vg_names_block(block, &mut vgs);
        }
    }
    vgs
}

/// Recursively collect VG names referenced by a block tree.
fn collect_vg_names_block(block: &ManifestBlock, vgs: &mut BTreeSet<String>) {
    match block {
        ManifestBlock::Lvm(b) => {
            if let Some(vg) = &b.vg {
                vgs.insert(vg.clone());
            }
        }
        ManifestBlock::Gpt(b) => {
            for p in &b.partitions {
                if let Some(content) = &p.content {
                    collect_vg_names_block(content, vgs);
                }
            }
        }
        ManifestBlock::Luks(b) => {
            if let Some(content) = &b.content {
                collect_vg_names_block(content, vgs);
            }
        }
        ManifestBlock::Ext4(_) | ManifestBlock::Fat(_) | ManifestBlock::Image(_) => {}
        ManifestBlock::Mbr(b) => {
            for p in &b.partitions {
                if let Some(content) = &p.content {
                    collect_vg_names_block(content, vgs);
                }
            }
        }
    }
}

/// Build a manifest restricted to `keep_disks` (and the VGs they reference).
fn filter_manifest(manifest: &ManifestBuild, keep_disks: &BTreeSet<String>) -> ManifestBuild {
    let mut filtered = manifest.clone();
    filtered.disk.retain(|name, _| keep_disks.contains(name));
    let keep_vgs = vg_names_for_disks(manifest, keep_disks);
    filtered.lvm.retain(|name, _| keep_vgs.contains(name));
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `/dev/sda` from the incident: an encrypted LVM root, where the
    /// mounted filesystems (`/`, `/etc`, `/var`) sit several levels below the
    /// top-level disk and every ancestor's own `mountpoints` is empty.
    const NESTED_ROOT_DISK: &str = r#"{
        "blockdevices": [
            {
                "name": "sda",
                "mountpoints": [],
                "children": [
                    { "name": "sda1", "mountpoints": [] },
                    {
                        "name": "sda2",
                        "mountpoints": [],
                        "children": [
                            {
                                "name": "cryptlvm",
                                "mountpoints": [],
                                "children": [
                                    {
                                        "name": "system-rootfs--k8jPeuq6rwg",
                                        "mountpoints": [],
                                        "children": [
                                            { "name": "rootfs", "mountpoints": ["/"] }
                                        ]
                                    },
                                    {
                                        "name": "system-etcfs--Um4eCu6hUUk",
                                        "mountpoints": [],
                                        "children": [
                                            { "name": "etcfs", "mountpoints": ["/etc"] }
                                        ]
                                    },
                                    { "name": "system-var", "mountpoints": ["/var"] }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    /// An unmounted disk with several levels of nesting (plain partitions plus
    /// a dm/LVM-like stack). Every node here must be collected so the
    /// sysfs-holders probe can inspect each one.
    const FREE_NESTED_DISK: &str = r#"{
        "blockdevices": [
            {
                "name": "sdb",
                "mountpoints": [null],
                "children": [
                    { "name": "sdb1", "mountpoints": [null] },
                    {
                        "name": "sdb2",
                        "mountpoints": [null],
                        "children": [
                            {
                                "name": "cryptfree",
                                "mountpoints": [null],
                                "children": [
                                    { "name": "freefs", "mountpoints": [null] }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    #[test]
    fn detects_mount_nested_under_ancestors() {
        let v: serde_json::Value = serde_json::from_str(NESTED_ROOT_DISK).unwrap();
        let mut paths = Vec::new();
        assert!(
            any_in_use(&v, &mut paths),
            "a mountpoint buried under the disk's descendants must mark it in use"
        );
    }

    #[test]
    fn collects_every_descendant_path() {
        let v: serde_json::Value = serde_json::from_str(FREE_NESTED_DISK).unwrap();
        let mut paths = Vec::new();
        let _ = any_in_use(&v, &mut paths);
        // Every node, at every depth, must be handed to the sysfs-holders probe;
        // otherwise a dm-crypt/LVM holder on a partition goes unnoticed.
        for expected in [
            "/dev/sdb",
            "/dev/sdb1",
            "/dev/sdb2",
            "/dev/cryptfree",
            "/dev/freefs",
        ] {
            assert!(
                paths.iter().any(|p| p == expected),
                "missing {expected}: {paths:?}"
            );
        }
    }

    #[test]
    fn free_disk_is_not_in_use() {
        let v: serde_json::Value = serde_json::from_str(FREE_NESTED_DISK).unwrap();
        let mut paths = Vec::new();
        assert!(!any_in_use(&v, &mut paths));
        assert_eq!(
            paths,
            [
                "/dev/sdb",
                "/dev/sdb1",
                "/dev/sdb2",
                "/dev/cryptfree",
                "/dev/freefs"
            ]
        );
    }

    /// `disk` map plus initial free/in-use sets for the policy tests below.
    fn policy_fixture() -> (
        std::collections::BTreeMap<String, String>,
        BTreeSet<String>,
        BTreeSet<String>,
    ) {
        let mut disk = std::collections::BTreeMap::new();
        disk.insert("free".to_string(), "/dev/sda".to_string());
        disk.insert("busy".to_string(), "/dev/sdb".to_string());
        (
            disk,
            BTreeSet::from(["free".to_string()]),
            BTreeSet::from(["busy".to_string()]),
        )
    }

    #[test]
    fn wipe_without_force_refuses_in_use_disk() {
        let (disk, mut free, mut in_use) = policy_fixture();
        let err = apply_wipe_policy(&disk, &mut free, &mut in_use, true, false)
            .expect_err("--wipe on an in-use disk must be refused without --force");
        let msg = format!("{err}");
        assert!(msg.contains("currently in use"), "message: {msg}");
        assert!(msg.contains("--force"), "message: {msg}");
        // The sets are left untouched so nothing is written.
        assert_eq!(free, BTreeSet::from(["free".to_string()]));
        assert_eq!(in_use, BTreeSet::from(["busy".to_string()]));
    }

    #[test]
    fn wipe_with_force_moves_in_use_to_free() {
        let (disk, mut free, mut in_use) = policy_fixture();
        let forced = apply_wipe_policy(&disk, &mut free, &mut in_use, true, true)
            .expect("--wipe --force must be allowed on an in-use disk");
        assert_eq!(forced, vec!["busy".to_string()]);
        assert_eq!(
            free,
            BTreeSet::from(["free".to_string(), "busy".to_string()])
        );
        assert!(in_use.is_empty(), "in-use set should be drained");
    }

    #[test]
    fn force_without_wipe_is_a_noop() {
        let (disk, mut free, mut in_use) = policy_fixture();
        let forced = apply_wipe_policy(&disk, &mut free, &mut in_use, false, true)
            .expect("--force without --wipe is accepted");
        assert!(forced.is_empty());
        assert_eq!(free, BTreeSet::from(["free".to_string()]));
        assert_eq!(in_use, BTreeSet::from(["busy".to_string()]));
    }

    #[test]
    fn wipe_with_force_and_no_in_use_is_ok() {
        let (disk, mut free, _) = policy_fixture();
        let mut in_use = BTreeSet::new();
        let forced = apply_wipe_policy(&disk, &mut free, &mut in_use, true, true)
            .expect("no in-use disk means nothing to force");
        assert!(forced.is_empty());
        assert_eq!(free, BTreeSet::from(["free".to_string()]));
    }

    // -----------------------------------------------------------------------
    // LUKS open/closed detection (the `luks` vs. `cryptlvm` regression)
    // -----------------------------------------------------------------------

    /// A [`Host`] with canned probe responses, for exercising the kernel-path
    /// probing logic without a real machine.
    struct MockHost {
        /// `lsblk --json -b -o NAME,TYPE <device>` output, if the command
        /// succeeds. `None` makes the probe fail (older `lsblk`, no mapping).
        lsblk_type: Option<String>,
        /// Whether `test -b /dev/mapper/<name>` succeeds.
        opener_exists: bool,
        /// Whether the sysfs-holders probe reports a holder on the device.
        has_holders: bool,
    }

    impl Host for MockHost {
        type RawGuard = ();

        fn label(&self) -> &str {
            "mock"
        }

        fn exec(&self, cmd: &[&str]) -> Result<String> {
            match cmd.first().copied() {
                Some("test") => {
                    if self.opener_exists {
                        Ok(String::new())
                    } else {
                        Err(Error::msg("mock: mapper absent"))
                    }
                }
                Some("lsblk") => self
                    .lsblk_type
                    .clone()
                    .ok_or_else(|| Error::msg("mock: lsblk unavailable")),
                Some("sh") => {
                    if self.has_holders {
                        Ok("dm-0".to_string())
                    } else {
                        Err(Error::msg("mock: no holders"))
                    }
                }
                _ => Err(Error::msg(format!("mock: unexpected command {cmd:?}"))),
            }
        }

        fn exec_optional(&self, cmd: &[&str]) -> Option<String> {
            self.exec(cmd).ok()
        }

        fn pipe(&self, _cmd: &str, _input: &mut dyn Read) -> Result<()> {
            unimplemented!("mock pipe")
        }

        fn open_disk_region(
            &self,
            _device: &str,
            _min_size: u64,
        ) -> Result<(DiskRegion, bool, Self::RawGuard)> {
            unimplemented!("mock open_disk_region")
        }

        fn open_raw_region(&self, _device: &str) -> Result<(DiskRegion, Self::RawGuard)> {
            unimplemented!("mock open_raw_region")
        }
    }

    /// What `lsblk` reports for the incident's backing partition: the LUKS
    /// container is open under the mapper name `cryptlvm` (chosen by `crypttab`),
    /// not the manifest's `luks`.
    const LUKS_MAPPER_LSBLK: &str = r#"{
        "blockdevices": [
            {
                "name": "sda2",
                "type": "part",
                "children": [
                    { "name": "cryptlvm", "type": "crypt", "children": [] }
                ]
            }
        ]
    }"#;

    /// The regression: an open, in-use LUKS container mapped under a name that
    /// differs from the manifest's container name must not be treated as closed
    /// (which would send the install down the raw, behind-the-kernel path).
    #[test]
    fn open_luks_under_a_different_mapper_name_is_detected() {
        let host = MockHost {
            lsblk_type: Some(LUKS_MAPPER_LSBLK.to_string()),
            opener_exists: false,
            has_holders: false,
        };
        let mapper =
            resolve_luks_mapper(&host, "/dev/sda2", "luks").expect("resolution should succeed");
        assert_eq!(
            mapper.as_deref(),
            Some("/dev/mapper/cryptlvm"),
            "LUKS \"luks\" is open as /dev/mapper/cryptlvm; it must resolve to the live \
             mapper, not be reported as closed"
        );
    }

    /// When the manifest name does match the mapper, resolve it directly.
    #[test]
    fn open_luks_under_the_manifest_name_is_detected() {
        let host = MockHost {
            lsblk_type: None,
            opener_exists: true,
            has_holders: false,
        };
        let mapper = resolve_luks_mapper(&host, "/dev/sda2", "luks").unwrap();
        assert_eq!(mapper.as_deref(), Some("/dev/mapper/luks"));
    }

    /// A genuinely closed container (no mapper, no holders) is still "closed",
    /// so the normal raw + on-the-fly-crypto path runs.
    #[test]
    fn closed_luks_is_not_mistaken_for_open() {
        let host = MockHost {
            lsblk_type: Some(r#"{"blockdevices":[{"name":"sda2","type":"part"}]}"#.to_string()),
            opener_exists: false,
            has_holders: false,
        };
        let mapper = resolve_luks_mapper(&host, "/dev/sda2", "luks").unwrap();
        assert_eq!(mapper, None);
    }

    /// If the backing device is held by the kernel but no mapper resolves, the
    /// install must be refused rather than writing raw behind the kernel's back.
    #[test]
    fn in_use_backing_without_resolvable_mapper_is_refused() {
        let host = MockHost {
            lsblk_type: Some(r#"{"blockdevices":[{"name":"sda2","type":"part"}]}"#.to_string()),
            opener_exists: false,
            has_holders: true,
        };
        let err = resolve_luks_mapper(&host, "/dev/sda2", "luks")
            .expect_err("must refuse to raw-write an in-use backing device");
        let msg = format!("{err}");
        assert!(msg.contains("/dev/sda2"), "message: {msg}");
    }

    #[test]
    fn first_crypt_child_finds_the_incident_mapper() {
        let v: serde_json::Value = serde_json::from_str(LUKS_MAPPER_LSBLK).unwrap();
        assert_eq!(
            first_crypt_child(&v).as_deref(),
            Some("/dev/mapper/cryptlvm")
        );
    }
}
