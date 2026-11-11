//! SSH-based install backend.
//!
//! `ssh-install` writes a built system onto block devices of a remote host
//! reached over SSH. Every remote device is exposed locally as an NBD export
//! tunnelled through SSH (`qemu-nbd` on the remote, `ssh -L` port forward), so
//! the generic [`crate::install`] pipeline writes over [`NbdRegion`] exactly as
//! it does for a local `--disk nbd://…` target.
//!
//! # In-use vs. not-in-use devices
//!
//! Before tunnelling a device, `ssh-install` probes the remote kernel (via
//! `lsblk`/`pvs`) to check whether the device — or any structure on it — is
//! currently in use (mounted, held by `dm-crypt`, registered as an LVM PV, …).
//!
//! * **Not in use** — the whole device is tunnelled and handed to the standard
//!   [`install`] pipeline, which repartitions / formats / populates it with raw
//!   block I/O. This is exactly the `nbd://` install path, just with the tunnel
//!   set up for you. Cross-disk volume groups work here as they do for `install`.
//!
//! * **In use** — the device is left under remote kernel control and the work is
//!   driven through the kernel instead of around it:
//!   * **GPT** — the existing table is reused (matched by partition name);
//!     missing partitions are added with `sgdisk`. The table is never rewritten
//!     wholesale, so mounted partitions on the same disk are untouched. Content
//!     of an *unmounted* partition is installed raw via the whole-disk tunnel
//!     (offset sub-region); content of a *mounted*/active/open partition is
//!     routed through the kernel (see below). `--wipe` is refused for an
//!     in-use device unless `--force` is given.
//!   * **LUKS** — if the container is already open remotely (`/dev/mapper/<name>`
//!     exists, or a dm-crypt mapper is stacked on the backing device under any
//!     name), the decrypted mapper device is tunnelled and the content is installed
//!     into it raw (no crypto on our side). If it is *not* open, the backing device
//!     is tunnelled and the standard on-the-fly-crypto path is used (the container is
//!     **not** opened with `cryptsetup luksOpen`). If the backing device is held by
//!     a kernel subsystem but no mapper can be resolved, the install is refused
//!     rather than writing raw behind the remote kernel's back.
//!   * **LVM** — if the PV belongs to a VG the remote kernel knows about
//!     (`pvs` reports a VG name), the VG is driven remotely: existing LVs are
//!     reused, missing LVs are created with `lvcreate`, and each LV's content
//!     is installed (raw via a per-LV tunnel, or through the kernel if the LV is
//!     mounted). Otherwise the PV is treated as inactive and installed raw.
//!   * **Filesystem** — if the device is mounted, it is ensured read-write
//!     (remounted if needed) and the content archive is streamed straight into
//!     the mountpoint (`tar`/`cpio` over SSH), merging with the existing tree.
//!     If it is not mounted, the standard raw format/merge path is used.
//!
//! Raw subtrees (a partition's unmounted content, a closed LUKS container, an
//! inactive PV) reuse the tested [`install`] pipeline via
//! [`install::install_block_subtree`], so only the genuinely kernel-mediated
//! operations are implemented in the shared [`crate::install_kernel`] module
//! (generic over the [`Host`] transport implemented here).
//!
//! # Root / sudo
//!
//! Raw block access to a `/dev` node on the remote, and kernel-mediated
//! operations (`sgdisk`, `lvcreate`, `mount`, …), require root (or the
//! appropriate capabilities). Pass `--remote-sudo` to prefix every remote
//! command with `sudo -n` (passwordless). Without it, `ssh-install` assumes
//! the SSH user can already perform these operations directly (e.g. an SSH
//! login as root).

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::install::DiskRegion;
use crate::install_kernel::{Host, install_with_kernel};
use crate::manifest::ManifestWithDirectory;
use crate::nbd::NbdRegion;

/// Default remote NBD server command template. `{port}`, `{device}` and
/// `{readonly}` are substituted before the command is run via `sh -c`.
const DEFAULT_NBD_SERVER: &str = "qemu-nbd --persistent {readonly} -b 127.0.0.1 -p {port} {device}";

/// How long to wait for a tunnelled NBD export to become reachable.
const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(20);

/// How many times to (re)bind a fresh local port and retry an NBD tunnel before
/// giving up (the local port is released after allocation, so a transient bind
/// race with the `ssh -L` forward is retried on a new port).
const NBD_TUNNEL_ATTEMPTS: usize = 4;

/// An `ssh-install` request.
pub struct SshInstallConfig {
    pub manifest: ManifestWithDirectory,
    /// `user@host`.
    pub ssh: String,
    /// `name -> /dev/remoteDevice`.
    pub disk: BTreeMap<String, String>,
    /// LUKS passphrases keyed by container name.
    pub key: BTreeMap<String, String>,
    /// LUKS key-file paths keyed by container name.
    pub key_file: BTreeMap<String, PathBuf>,
    pub wipe: bool,
    /// Allow `--wipe` to force-wipe in-use remote devices from scratch instead
    /// of refusing. Only meaningful together with `wipe`.
    pub force: bool,
    /// Prefix every remote command with `sudo -n`.
    pub remote_sudo: bool,
    /// Override the remote NBD server command (a `sh -c` template with
    /// `{port}`, `{device}` and `{readonly}` placeholders). Defaults to
    /// [`DEFAULT_NBD_SERVER`].
    pub nbd_server_command: Option<String>,
}

/// Run an SSH install.
///
/// Probes each remote device for in-use state, then delegates to the shared
/// [`install_with_kernel`] entry point with an [`SshHost`] transport: free
/// devices are installed via the raw NBD-tunnel pipeline, in-use devices are
/// driven through the remote kernel. `--wipe` is refused for in-use devices
/// unless `--force` is set, in which case they are force-wiped from scratch.
pub fn ssh_install(config: SshInstallConfig) -> Result<()> {
    let template = config
        .nbd_server_command
        .clone()
        .unwrap_or_else(|| DEFAULT_NBD_SERVER.to_string());
    let host = SshHost {
        ssh: config.ssh,
        sudo: config.remote_sudo,
        template,
    };
    install_with_kernel(
        &host,
        config.manifest,
        config.disk,
        config.key,
        config.key_file,
        config.wipe,
        config.force,
    )
}

/// [`Host`] implementation for `ssh-install`: commands run over SSH and raw
/// regions are NBD exports tunnelled back from the remote.
struct SshHost {
    ssh: String,
    sudo: bool,
    template: String,
}

/// A live SSH tunnel exposing a remote device as a local NBD export. The
/// `ssh` child (and the remote `qemu-nbd` it runs) is killed when this is
/// dropped — which keeps the export alive for as long as a region holds it.
struct NbdTunnel {
    child: Child,
    port: u16,
}

impl Drop for NbdTunnel {
    fn drop(&mut self) {
        // Best-effort: stop the SSH session; the remote qemu-nbd receives
        // SIGHUP / EOF and exits.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Host for SshHost {
    type RawGuard = NbdTunnel;

    fn label(&self) -> &str {
        "ssh-install"
    }

    fn exec(&self, cmd: &[&str]) -> Result<String> {
        ssh_exec(&self.ssh, self.sudo, cmd)
    }

    fn exec_optional(&self, cmd: &[&str]) -> Option<String> {
        match ssh_exec(&self.ssh, self.sudo, cmd) {
            Ok(out) => Some(out),
            Err(e) => {
                eprintln!("ssh-install: (skipping probe) {e}");
                None
            }
        }
    }

    fn pipe(&self, cmd: &str, input: &mut dyn Read) -> Result<()> {
        ssh_pipe(&self.ssh, self.sudo, cmd, input)
    }

    fn open_disk_region(
        &self,
        device: &str,
        _min_size: u64,
    ) -> Result<(DiskRegion, bool, Self::RawGuard)> {
        // Phase 1 always writes (install formats/partitions the device), so the
        // export is writable. A remote device is never "created by us".
        // `start_nbd_tunnel` logs the device and port it is exporting.
        let tunnel = start_nbd_tunnel(&self.ssh, self.sudo, device, &self.template)?;
        let url = format!("nbd://127.0.0.1:{}/", tunnel.port);
        let region = NbdRegion::open(&url)?.with_remote_digest(remote_digest_closure(
            self.ssh.clone(),
            self.sudo,
            device.to_string(),
        ));
        Ok((DiskRegion::Nbd(region), false, tunnel))
    }

    fn open_raw_region(&self, device: &str) -> Result<(DiskRegion, Self::RawGuard)> {
        let (tunnel, region) = open_tunnel_region(&self.ssh, self.sudo, device, &self.template)?;
        let region = region.with_remote_digest(remote_digest_closure(
            self.ssh.clone(),
            self.sudo,
            device.to_string(),
        ));
        Ok((DiskRegion::Nbd(region), tunnel))
    }
}

// ---------------------------------------------------------------------------
// Remote command execution
// ---------------------------------------------------------------------------

/// Common SSH options applied to every remote command: batch mode (no
/// interactive password prompts — fail instead of hanging) and accept-new host
/// keys.
const SSH_OPTS: [&str; 4] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
];

/// Assemble one remote command string from `argv`, shell-quoting every element
/// and prefixing `sudo -n` when requested.
///
/// This matters because OpenSSH joins the remote command's arguments with
/// spaces and the remote login shell re-parses the result — argument
/// boundaries are **not** preserved. A command shaped like `sh -c <script>`
/// would therefore arrive as `sh -c <first-word> <rest…>`, running only the
/// first word as the script (which is exactly what broke the NBD tunnel:
/// `qemu-nbd` was invoked with no arguments and exited immediately). Quoting
/// each element makes the remote shell reconstruct the original `argv`.
fn assemble_remote_command(sudo: bool, argv: &[&str]) -> String {
    let mut cmd = String::new();
    if sudo {
        cmd.push_str("sudo -n ");
    }
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            cmd.push(' ');
        }
        cmd.push_str(&shell_quote(arg));
    }
    cmd
}

/// Run a remote command via `ssh`, returning trimmed stdout (non-zero → error).
fn ssh_exec(ssh: &str, sudo: bool, remote: &[&str]) -> Result<String> {
    let remote_cmd = assemble_remote_command(sudo, remote);
    let mut args = vec!["ssh"];
    args.extend(SSH_OPTS.iter().copied());
    args.push(ssh);
    args.push(remote_cmd.as_str());
    crate::exec::exec(&args)
}

/// Stream `input` to a remote `sh -c <cmd>` over SSH stdin.
fn ssh_pipe(ssh: &str, sudo: bool, cmd: &str, mut input: impl Read) -> Result<()> {
    let remote_cmd = assemble_remote_command(sudo, &["sh", "-c", cmd]);

    let mut child = Command::new("ssh")
        .args(SSH_OPTS.iter().copied())
        .arg(ssh)
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::msg(format!("Failed to start ssh for pipe: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        std::io::copy(&mut input, &mut stdin)
            .map_err(|e| Error::msg(format!("ssh pipe copy: {e}")))?;
    }
    let status = child
        .wait()
        .map_err(|e| Error::msg(format!("ssh pipe wait: {e}")))?;
    if !status.success() {
        return Err(Error::msg(format!(
            "Remote extraction command failed (exit {status}): {cmd}"
        )));
    }
    Ok(())
}

/// Start an NBD server on the remote (over SSH, with a `-L` port forward) for
/// `device`, and return the local port to connect to. Retries a few times on a
/// transient bind failure of the forwarded port.
fn start_nbd_tunnel(ssh: &str, sudo: bool, device: &str, template: &str) -> Result<NbdTunnel> {
    // Phase 1 always writes (install formats/partitions the device), so the
    // export is writable.
    let remote_sh = template
        .replace("{readonly}", "")
        .replace("{device}", device);

    // Wall-clock start of the whole tunnel sequence, used to report how long we
    // actually waited. `wait_tunnel_ready` returns early the moment the ssh
    // child dies (e.g. `qemu-nbd: command not found`), so the elapsed time is
    // usually far below the per-attempt cap — reporting the cap as if it were
    // the wait is misleading.
    let started = Instant::now();

    for attempt in 0..NBD_TUNNEL_ATTEMPTS {
        let port = alloc_local_port()?;
        let remote_sh = remote_sh.replace("{port}", &port.to_string());
        let forward = format!("{port}:127.0.0.1:{port}");

        // Name the device (and the port in use) up front: the tunnel is the only
        // step that reaches the remote's raw device, so the log must make clear
        // *which* device is being exported, especially across retries.
        eprintln!(
            "ssh-install: starting NBD tunnel for {device} on {ssh} \
             (attempt {}/{NBD_TUNNEL_ATTEMPTS}, local port {port})...",
            attempt + 1
        );

        // Pass the entire `sh -c <snippet>` as a single ssh argument. OpenSSH
        // space-joins remote arguments and the remote shell re-parses them, so
        // sending `sh`, `-c`, `<snippet>` as separate args would make the remote
        // run `sh -c <first-word> <rest…>` — i.e. `qemu-nbd` with no arguments.
        let remote_cmd = assemble_remote_command(sudo, &["sh", "-c", remote_sh.as_str()]);

        let mut cmd = Command::new("ssh");
        cmd.args(SSH_OPTS.iter().copied()).args([
            "-o",
            "ExitOnForwardFailure=yes",
            "-L",
            &forward,
            ssh,
        ]);
        cmd.arg(&remote_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::msg(format!("Failed to start ssh for NBD tunnel: {e}")))?;
        let url = format!("nbd://127.0.0.1:{port}/");
        match wait_tunnel_ready(&url, &mut child) {
            Ok(()) => {
                eprintln!("ssh-install: NBD tunnel for {device} on {ssh} ready at {url}");
                return Ok(NbdTunnel { child, port });
            }
            Err(e) => {
                // If ssh has already died, drain its stderr so the real remote
                // failure (missing qemu-nbd, permission denied, sudo password
                // required, …) is reported instead of a bare "connection
                // refused".
                let remote_detail = drain_dead_child_stderr(&mut child);
                // Drop the child to stop the failed attempt before retrying.
                drop(NbdTunnel { child, port });
                if attempt + 1 == NBD_TUNNEL_ATTEMPTS {
                    let mut msg = format!(
                        "Could not reach the NBD export for {device} on {ssh} after {:?} \
                         across {NBD_TUNNEL_ATTEMPTS} attempts (up to {TUNNEL_READY_TIMEOUT:?} each; \
                         last tried local port {port}). \
                         Verify that the remote NBD server command (`qemu-nbd` by default) is installed \
                         and that the SSH user can open {device}. Original error: {e}",
                        started.elapsed()
                    );
                    if !remote_detail.is_empty() {
                        msg.push_str(&format!("\nRemote command reported: {remote_detail}"));
                    }
                    return Err(Error::msg(msg));
                }
                if remote_detail.is_empty() {
                    eprintln!(
                        "ssh-install: NBD tunnel for {device} on {ssh} not ready on local port {port} \
                         yet, retrying on a new port..."
                    );
                } else {
                    eprintln!(
                        "ssh-install: NBD tunnel for {device} on {ssh} not ready on local port {port} \
                         ({remote_detail}), retrying on a new port..."
                    );
                }
            }
        }
    }
    unreachable!()
}

/// Bind `127.0.0.1:0` to let the OS pick a free local port, then immediately
/// release it. There is a tiny race window before `ssh -L` rebinds it; the
/// caller retries on failure.
fn alloc_local_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Repeatedly open the NBD export at `url` until the handshake succeeds or the
/// timeout elapses. A successful open proves the whole path is up: the SSH
/// forward, the remote `qemu-nbd`, and the NBD newstyle handshake. The opened
/// region is dropped immediately (the export uses `--persistent`, so the
/// install pipeline opens its own fresh connection next).
///
/// The ssh child is checked on every iteration: if it has exited, the forward
/// is gone for good and there is no point waiting out the rest of the timeout.
fn wait_tunnel_ready(url: &str, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + TUNNEL_READY_TIMEOUT;
    loop {
        match NbdRegion::open(url) {
            Ok(_region) => return Ok(()),
            Err(e) => {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(Error::msg(format!("{e} (ssh session exited: {status})")));
                }
                if Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }
}

/// If the ssh child has already exited, read whatever it wrote to stderr so the
/// caller can report the real remote failure. Returns an empty string while the
/// child is still running — reading its stderr then would block.
fn drain_dead_child_stderr(child: &mut Child) -> String {
    if !matches!(child.try_wait(), Ok(Some(_))) {
        return String::new();
    }
    let mut detail = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut detail);
    }
    detail.trim().to_string()
}

/// Start an NBD tunnel for `device` and open a [`NbdRegion`] onto it. The
/// returned `NbdTunnel` must outlive the region (it owns the ssh child keeping
/// the export alive).
fn open_tunnel_region(
    ssh: &str,
    sudo: bool,
    device: &str,
    template: &str,
) -> Result<(NbdTunnel, NbdRegion)> {
    let tunnel = start_nbd_tunnel(ssh, sudo, device, template)?;
    let url = format!("nbd://127.0.0.1:{}/", tunnel.port);
    let region = NbdRegion::open(&url)?;
    Ok((tunnel, region))
}

/// Single-quote a string for a POSIX shell argument.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the side channel that hashes `[offset, offset + size)` of `device` on
/// the remote host (where the device physically lives), returning the SHA-256
/// without shipping the bytes back over the NBD tunnel. Used by the
/// image-block fast path to skip transferring an unchanged image over the
/// network.
///
/// The closure returns `Ok(None)` on any failure (ssh error, missing tool,
/// unparsable output) so the install falls back to copying rather than
/// aborting.
fn remote_digest_closure(
    ssh: String,
    sudo: bool,
    device: String,
) -> impl Fn(u64, u64) -> std::io::Result<Option<[u8; 32]>> + Send + Sync + 'static {
    move |offset: u64, size: u64| {
        // `iflag=skip_bytes,count_bytes` (GNU coreutils) makes skip/count
        // byte-accurate regardless of `bs`, so arbitrary partition offsets and
        // image sizes work without slow `bs=1`. `status=none` keeps dd quiet;
        // stderr is discarded so a too-short read does not spam the log (the
        // resulting digest simply will not match and we fall back to copying).
        let cmd = format!(
            "dd if={device} bs=1M iflag=skip_bytes,count_bytes skip={offset} \
             count={size} status=none 2>/dev/null | sha256sum",
            device = shell_quote(&device),
        );
        match ssh_exec(&ssh, sudo, &["sh", "-c", &cmd]) {
            Ok(out) => {
                let h = out.split_whitespace().next().unwrap_or("");
                match hex::decode(h) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Ok(Some(arr))
                    }
                    _ => {
                        eprintln!(
                            "ssh-install: remote digest of {device} returned \
                             unparsable output ({out:?}) — falling back to copy"
                        );
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "ssh-install: remote digest of {device} failed ({e}) — \
                     falling back to copy"
                );
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::assemble_remote_command;

    #[test]
    fn quotes_every_argument() {
        assert_eq!(
            assemble_remote_command(
                false,
                &["lsblk", "-b", "-o", "NAME,MOUNTPOINTS", "/dev/sda"]
            ),
            r"'lsblk' '-b' '-o' 'NAME,MOUNTPOINTS' '/dev/sda'"
        );
    }

    #[test]
    fn keeps_sh_c_script_intact() {
        // The script must survive as one word, not be split at its first space.
        assert_eq!(
            assemble_remote_command(
                false,
                &["sh", "-c", "qemu-nbd -b 127.0.0.1 -p 1234 /dev/sda"]
            ),
            r"'sh' '-c' 'qemu-nbd -b 127.0.0.1 -p 1234 /dev/sda'"
        );
    }

    #[test]
    fn prefixes_sudo() {
        assert_eq!(
            assemble_remote_command(true, &["qemu-nbd", "/dev/sda"]),
            r"sudo -n 'qemu-nbd' '/dev/sda'"
        );
    }

    #[test]
    fn escapes_embedded_single_quotes() {
        assert_eq!(
            assemble_remote_command(false, &["sh", "-c", r"echo 'hi'"]),
            r"'sh' '-c' 'echo '\''hi'\'''"
        );
    }
}
