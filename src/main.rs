//! `sysimage` CLI.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "sysimage", about = "Declarative system image builder")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build
    Build {
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
        /// Passphrase for a LUKS container used inside a `build:block:` block,
        /// or a key component for an `encrypt`/`decrypt`/`reencrypt` build
        /// artifact, as `name=passphrase`. Repeatable, once per name. An
        /// `encrypt`, `decrypt` or `reencrypt` artifact may name several
        /// components; they are combined in config order with HKDF-SHA256.
        #[arg(long, value_name = "name=passphrase", num_args = 1)]
        key: Vec<String>,
        /// Path to a key file for a LUKS container used inside a `build:block:`
        /// block, or a key component for an `encrypt`/`decrypt`/`reencrypt`
        /// build artifact, as `name=path`. Repeatable, once per name. The file
        /// is used exactly as read; no trailing newline is stripped.
        #[arg(long, value_name = "name=path", num_args = 1)]
        key_file: Vec<String>,
        /// Signing-key directory for an `efisign` build artifact, as
        /// `name=directory`. The directory must contain `db.key` and `db.crt`
        /// (as produced by `sysimage sbkey-generate`). Repeatable, once per
        /// signing key name. When a key named by an `efisign` artifact is not
        /// supplied here, that EFI is left unsigned.
        #[arg(long, value_name = "name=directory", num_args = 1)]
        sign: Vec<String>,
        /// Passphrase file for a SENC-encrypted `db.key` inside a `--sign`
        /// directory, as `name=path`. Use `-` to read the passphrase from
        /// stdin (at most one entry may). The file is used exactly as read; no
        /// trailing newline is stripped.
        #[arg(long, value_name = "name=path", num_args = 1)]
        sign_key_file: Vec<String>,
        /// A build parameter, as `name=value`. Repeatable, once per name.
        /// Parameters must be declared under `parameters` in the config;
        /// supplying an undeclared name is an error. A declared parameter with
        /// no default is mandatory. Values are substituted as `${name}`
        /// anywhere the built-in variables (such as `${CONFIGDIR}`) apply.
        #[arg(short = 'p', long = "param", value_name = "name=value", num_args = 1)]
        param: Vec<String>,
        /// Override the config's `name` (used for `${NAME}`, the manifest's
        /// `name`, and the `<name>-<hash>.json` output file). Because the
        /// stable `<name>.json` symlink honors this override, a later
        /// `install`/`netboot` on the config must pass
        /// `-m <outputDirectory>/<name>.json` explicitly.
        #[arg(long, value_name = "name")]
        name: Option<String>,
        /// Override the config's `version` (used for `${VERSION}` and the
        /// manifest's `version` field).
        #[arg(long, value_name = "version")]
        version: Option<String>,
    },
    /// Scaffold a build config
    Init {
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
    },
    /// Install the system from a manifest
    Install {
        #[arg(short = 'm', long)]
        manifest: Option<PathBuf>,
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
        /// Target for a disk, as `name=target`. The target is a local file or
        /// block-device path, or an NBD URL: `nbd://host[:port]/export`,
        /// `nbd+tcp://host[:port]/export` or
        /// `nbd+unix:///export?socket=/path/to/sock`. Repeatable, once per
        /// disk. The backend is chosen per disk from the target string, so
        /// a single install may freely mix local paths and NBD URLs.
        #[arg(short = 'd', long, value_name = "name=path", num_args = 1)]
        disk: Vec<String>,
        /// Passphrase for a LUKS container, as `name=passphrase`. Repeatable,
        /// once per LUKS container name. Containers not covered here or by
        /// `--key-file` are prompted for interactively.
        #[arg(long, value_name = "name=passphrase", num_args = 1)]
        key: Vec<String>,
        /// Path to a key file for a LUKS container, as `name=path`. Repeatable,
        /// once per LUKS container name. The file is used exactly as read; no
        /// trailing newline is stripped.
        #[arg(long, value_name = "name=path", num_args = 1)]
        key_file: Vec<String>,
        #[arg(long)]
        wipe: bool,
        /// Force wiping an in-use target device. Without this, `--wipe` is
        /// refused for a target that is mounted or held by another kernel
        /// subsystem (mounted filesystem, open LUKS, active LVM). Only
        /// meaningful together with `--wipe`.
        #[arg(long)]
        force: bool,
    },
    /// Install into raw image files in a directory and write a QEMU config.
    ///
    /// This is a shortcut for `install` with the `--disk` targets already
    /// filled in: each manifest disk is installed into `<directory>/<disk>.img`.
    /// Disks declared only under `qemu.disks` with an `input` are not installed;
    /// their artifacts are hard-linked (or copied as a fallback) to
    /// `<disk>.img` and attached read-only. The directory is created if it does
    /// not exist; existing image files are reused and reconciled against (just
    /// like `install` without `--wipe`). A `qemu.json` config describing how to
    /// boot the images under QEMU is written into the directory; launch it with
    /// `sysimage qemu-run`.
    QemuInstall {
        #[arg(short = 'm', long)]
        manifest: Option<PathBuf>,
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
        /// Directory to hold the raw disk images and `qemu.json`. Created if
        /// it does not exist. Defaults to `qemu`.
        #[arg(short = 'd', long, default_value = "qemu")]
        directory: PathBuf,
        /// Passphrase for a LUKS container, as `name=passphrase`. Repeatable.
        #[arg(long, value_name = "name=passphrase", num_args = 1)]
        key: Vec<String>,
        /// Path to a key file for a LUKS container, as `name=path`. Repeatable.
        #[arg(long, value_name = "name=path", num_args = 1)]
        key_file: Vec<String>,
        #[arg(long)]
        wipe: bool,
        /// Force wiping an in-use target device. Only meaningful together with
        /// `--wipe`; qemu image files are never in use, so this has no effect.
        #[arg(long)]
        force: bool,
    },
    /// Launch QEMU from a `qemu.json` config (written by `qemu-install`).
    ///
    /// Resolves the UEFI firmware for the configured architecture, materialises
    /// a writable firmware-vars copy in the directory on first run, and launches
    /// `qemu-system-*` with the disk images attached as virtio-blk drives.
    QemuRun {
        /// Directory containing the `qemu.json` config and disk images.
        /// Defaults to `qemu`.
        #[arg(short = 'd', long, default_value = "qemu")]
        directory: PathBuf,
        /// Print the resolved `qemu-system-*` command line instead of launching.
        #[arg(long)]
        print: bool,
        /// Extra arguments appended to the generated `qemu-system-*` command
        /// line. Pass them after `--`, e.g.
        /// `sysimage qemu-run -d qemu -- -serial stdio`.
        #[arg(last = true, value_name = "ARG")]
        extra_args: Vec<String>,
    },
    /// Install the system from a manifest over SSH.
    ///
    /// Like `install`, but each `--disk name=/dev/remoteDevice` is a *remote*
    /// block device on `--ssh user@host`. Devices that are **not** in use on
    /// the remote are served by an NBD server (`qemu-nbd` by default) tunnelled
    /// back over SSH, so the standard install pipeline writes them as if local.
    /// Devices that **are** in use (mounted filesystems, open LUKS, active LVM)
    /// are handled through the remote kernel instead: mounted filesystems are
    /// extracted in place, open LUKS containers are written through their dm
    /// device, and active LVM volume groups are driven with `lvm`/`sgdisk`
    /// over SSH. A disk may mix both styles. `--wipe` is refused for in-use
    /// disks, unless `--force` is given to force-wipe them anyway.
    SshInstall {
        #[arg(short = 'm', long)]
        manifest: Option<PathBuf>,
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
        /// SSH destination, e.g. `user@host`.
        #[arg(long, value_name = "user@host")]
        ssh: String,
        /// Remote device for a disk, as `name=/dev/remoteDevice`. Repeatable,
        /// once per disk.
        #[arg(short = 'd', long, value_name = "name=device", num_args = 1)]
        disk: Vec<String>,
        /// Passphrase for a LUKS container, as `name=passphrase`. Repeatable.
        #[arg(long, value_name = "name=passphrase", num_args = 1)]
        key: Vec<String>,
        /// Path to a key file for a LUKS container, as `name=path`. Repeatable.
        #[arg(long, value_name = "name=path", num_args = 1)]
        key_file: Vec<String>,
        #[arg(long)]
        wipe: bool,
        /// Force wiping an in-use remote device. Without this, `--wipe` is
        /// refused for a device that is mounted or held by another remote kernel
        /// subsystem. Only meaningful together with `--wipe`.
        #[arg(long)]
        force: bool,
        /// Prefix every remote command with `sudo -n` (passwordless). Use this
        /// when the SSH user is not root but may run privileged commands.
        #[arg(long)]
        remote_sudo: bool,
        /// Override the remote NBD server command. A `sh -c` template with
        /// `{port}`, `{device}` and `{readonly}` placeholders. Defaults to
        /// `qemu-nbd --persistent {readonly} -b 127.0.0.1 -p {port} {device}`.
        #[arg(long, value_name = "cmd")]
        nbd_server_command: Option<String>,
    },
    /// Serve built artifacts over the network for PXE/UEFI boot.
    ///
    /// Resolves a manifest (through the config, like `install`) and starts the
    /// DHCP, TFTP and/or HTTP servers configured in the manifest's `netboot`
    /// section (each independently optional). TFTP and HTTP serve the
    /// content-addressed `.bin` files referenced by the manifest; the DHCP
    /// server operates as a PXE proxy DHCP server (it does not assign IP
    /// addresses — another DHCP server on the network handles that) and points
    /// clients at the boot file. The servers run until interrupted (Ctrl-C).
    ///
    /// The `${NETBOOT_IP}` variable used in the `netboot` section is resolved
    /// from the network interface the server is bound to: `--interface <name>`
    /// picks that interface's IPv4, `--bind-ip <ip>` uses an explicit IPv4, and
    /// with neither flag the default-route source IPv4 is auto-detected.
    Netboot {
        #[arg(short = 'm', long)]
        manifest: Option<PathBuf>,
        #[arg(short = 'c', long, default_value = "sysimage.config.yml")]
        config: PathBuf,
        /// Network interface whose IPv4 address is used as `${NETBOOT_IP}` and
        /// the default bind address for the servers.
        #[arg(long, value_name = "name")]
        interface: Option<String>,
        /// Explicit IPv4 address used as `${NETBOOT_IP}` and the default bind
        /// address for the servers. Takes precedence over `--interface`.
        #[arg(long, value_name = "ip")]
        bind_ip: Option<String>,
    },
    /// Generate the JSON schemas for the config, manifest, and QEMU documents.
    ///
    /// Writes `sysimage.config.schema.json`, `sysimage.manifest.schema.json`,
    /// and `sysimage.qemu.schema.json` into the output directory (the current
    /// directory by default).
    Schema {
        #[arg(short = 'o', long, default_value = ".")]
        output: PathBuf,
    },
    /// Build a Unified Kernel Image (UKI) from a stub, kernel and initrds.
    ///
    /// Stitches `.linux`, `.initrd`, `.cmdline`, `.splash` and (optionally)
    /// `.osrel` sections onto a `systemd-stub` PE, producing a UKI bootable
    /// by systemd-boot. This is the same pure-Rust pipeline used internally
    /// by `sysimage build` for `uki` artifacts, exposed as a standalone
    /// command.
    BuildUki {
        /// The EFI stub PE to stitch sections onto (e.g. `systemd-stub.efi`).
        #[arg(short = 's', long)]
        stub: PathBuf,
        /// The kernel image to embed in the `.linux` section.
        #[arg(short = 'k', long)]
        kernel: PathBuf,
        /// An initrd to concatenate into the `.initrd` section. Repeatable,
        /// in order; each is padded to 4-byte alignment.
        #[arg(short = 'i', long, value_name = "path")]
        initrd: Vec<PathBuf>,
        /// Kernel command line for the `.cmdline` section.
        #[arg(long)]
        cmdline: Option<String>,
        /// An `os-release` file whose contents become the `.osrel` section.
        /// systemd-boot requires `.osrel` to recognise the image as a UKI.
        #[arg(long)]
        osrel: Option<PathBuf>,
        /// A splash image (BMP) whose contents become the `.splash` section,
        /// displayed by systemd-stub during boot.
        #[arg(long)]
        splash: Option<PathBuf>,
        /// Output UKI path to write.
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// Target architecture (rust name: `x86_64`, `aarch64`, `x86`,
        /// `arm`). Defaults to the host architecture.
        #[arg(short = 'a', long, value_name = "name")]
        arch: Option<String>,
    },
    /// Show version number and commit sha
    Version,
    /// Generate a Secure Boot key set (PK/KEK/db) into a directory.
    SbkeyGenerate {
        /// Output directory for the keys (default `sbkeys`).
        #[arg(short = 'o', long, default_value = "sbkeys")]
        output: PathBuf,
        /// Encrypt each `<name>.key` as a SENC envelope keyed by the exact
        /// bytes of this passphrase file (as produced by `sysimage
        /// sbkey-generate --passphrase-file`). `-` reads the passphrase from
        /// stdin. The file is used exactly as read; no trailing newline is
        /// stripped.
        #[arg(long, value_name = "path")]
        passphrase_file: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> sysimage::error::Result<()> {
    match cli.command {
        Commands::Build {
            config,
            key,
            key_file,
            sign,
            sign_key_file,
            param,
            name,
            version,
        } => {
            let mut key_map = std::collections::BTreeMap::new();
            for entry in key {
                let (name, pass) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key value \"{entry}\": expected name=passphrase"
                    ))
                })?;
                key_map.insert(name.to_string(), pass.to_string());
            }
            let mut key_file_map = std::collections::BTreeMap::new();
            for entry in key_file {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key-file value \"{entry}\": expected name=path"
                    ))
                })?;
                key_file_map.insert(name.to_string(), PathBuf::from(path));
            }
            let mut sign_map = std::collections::BTreeMap::new();
            for entry in sign {
                let (name, dir) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --sign value \"{entry}\": expected name=directory"
                    ))
                })?;
                sign_map.insert(name.to_string(), PathBuf::from(dir));
            }
            let mut sign_key_file_map = std::collections::BTreeMap::new();
            for entry in sign_key_file {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --sign-key-file value \"{entry}\": expected name=path"
                    ))
                })?;
                sign_key_file_map.insert(name.to_string(), PathBuf::from(path));
            }
            let mut param_map = std::collections::BTreeMap::new();
            for entry in param {
                let (name, value) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --param value \"{entry}\": expected name=value"
                    ))
                })?;
                param_map.insert(name.to_string(), value.to_string());
            }
            sysimage::build::build_from_file_with_sign_keys(
                &config,
                &key_map,
                &key_file_map,
                &sign_map,
                &sign_key_file_map,
                &param_map,
                &sysimage::build::BuildOverrides { name, version },
            )
            .map(|_| ())
        }
        Commands::Init { config } => sysimage::init::write_default_config(&config),
        Commands::Install {
            manifest,
            config,
            disk,
            key,
            key_file,
            wipe,
            force,
        } => {
            let manifest =
                sysimage::manifest::read_manifest(sysimage::manifest::ReadManifestConfig {
                    config: &config,
                    manifest: manifest.as_deref(),
                })?;
            let mut disk_map = std::collections::BTreeMap::new();
            for entry in disk {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --disk value \"{entry}\": expected name=path"
                    ))
                })?;
                disk_map.insert(name.to_string(), path.to_string());
            }
            let mut key_map = std::collections::BTreeMap::new();
            for entry in key {
                let (name, pass) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key value \"{entry}\": expected name=passphrase"
                    ))
                })?;
                key_map.insert(name.to_string(), pass.to_string());
            }
            let mut key_file_map = std::collections::BTreeMap::new();
            for entry in key_file {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key-file value \"{entry}\": expected name=path"
                    ))
                })?;
                key_file_map.insert(name.to_string(), std::path::PathBuf::from(path));
            }
            sysimage::install::install(sysimage::install::InstallConfig {
                manifest,
                disk: disk_map,
                key: key_map,
                key_file: key_file_map,
                wipe,
                force,
            })
        }
        Commands::SshInstall {
            manifest,
            config,
            ssh,
            disk,
            key,
            key_file,
            wipe,
            force,
            remote_sudo,
            nbd_server_command,
        } => {
            let manifest =
                sysimage::manifest::read_manifest(sysimage::manifest::ReadManifestConfig {
                    config: &config,
                    manifest: manifest.as_deref(),
                })?;
            let mut disk_map = std::collections::BTreeMap::new();
            for entry in disk {
                let (name, device) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --disk value \"{entry}\": expected name=/dev/remoteDevice"
                    ))
                })?;
                disk_map.insert(name.to_string(), device.to_string());
            }
            let mut key_map = std::collections::BTreeMap::new();
            for entry in key {
                let (name, pass) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key value \"{entry}\": expected name=passphrase"
                    ))
                })?;
                key_map.insert(name.to_string(), pass.to_string());
            }
            let mut key_file_map = std::collections::BTreeMap::new();
            for entry in key_file {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key-file value \"{entry}\": expected name=path"
                    ))
                })?;
                key_file_map.insert(name.to_string(), std::path::PathBuf::from(path));
            }
            sysimage::ssh::ssh_install(sysimage::ssh::SshInstallConfig {
                manifest,
                ssh,
                disk: disk_map,
                key: key_map,
                key_file: key_file_map,
                wipe,
                force,
                remote_sudo,
                nbd_server_command,
            })
        }
        Commands::QemuInstall {
            manifest,
            config,
            directory,
            key,
            key_file,
            wipe,
            force,
        } => {
            let manifest =
                sysimage::manifest::read_manifest(sysimage::manifest::ReadManifestConfig {
                    config: &config,
                    manifest: manifest.as_deref(),
                })?;
            let mut key_map = std::collections::BTreeMap::new();
            for entry in key {
                let (name, pass) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key value \"{entry}\": expected name=passphrase"
                    ))
                })?;
                key_map.insert(name.to_string(), pass.to_string());
            }
            let mut key_file_map = std::collections::BTreeMap::new();
            for entry in key_file {
                let (name, path) = entry.split_once('=').ok_or_else(|| {
                    sysimage::error::Error::msg(format!(
                        "Invalid --key-file value \"{entry}\": expected name=path"
                    ))
                })?;
                key_file_map.insert(name.to_string(), std::path::PathBuf::from(path));
            }
            sysimage::qemu::qemu_install(manifest, &directory, key_map, key_file_map, wipe, force)?;
            println!(
                "Wrote QEMU config to {}",
                directory.join(sysimage::qemu::QEMU_CONFIG_FILE).display(),
            );
            println!("Launch with: sysimage qemu-run -d {}", directory.display());
            Ok(())
        }
        Commands::QemuRun {
            directory,
            print,
            extra_args,
        } => sysimage::qemu::run_config(sysimage::qemu::QemuRunConfig {
            directory,
            print,
            extra_args,
        }),
        Commands::Schema { output } => {
            std::fs::create_dir_all(&output)?;
            let config_schema = sysimage::model::schema::config_schema();
            std::fs::write(
                output.join(sysimage::model::schema::CONFIG_SCHEMA_FILE),
                serde_json::to_string_pretty(&config_schema)?,
            )?;
            let manifest_schema = sysimage::model::schema::manifest_schema();
            std::fs::write(
                output.join(sysimage::model::schema::MANIFEST_SCHEMA_FILE),
                serde_json::to_string_pretty(&manifest_schema)?,
            )?;
            let qemu_schema = sysimage::model::schema::qemu_schema();
            std::fs::write(
                output.join(sysimage::model::schema::QEMU_SCHEMA_FILE),
                serde_json::to_string_pretty(&qemu_schema)?,
            )?;
            println!(
                "Wrote {}, {} and {} to {}",
                sysimage::model::schema::CONFIG_SCHEMA_FILE,
                sysimage::model::schema::MANIFEST_SCHEMA_FILE,
                sysimage::model::schema::QEMU_SCHEMA_FILE,
                output.display(),
            );
            Ok(())
        }
        Commands::Version => {
            println!("sysimage {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Commands::Netboot {
            manifest,
            config,
            interface,
            bind_ip,
        } => {
            let m = sysimage::manifest::read_manifest(sysimage::manifest::ReadManifestConfig {
                config: &config,
                manifest: manifest.as_deref(),
            })?;
            sysimage::netboot::run_netboot(sysimage::netboot::NetbootConfig {
                manifest: m,
                interface,
                bind_ip,
            })
        }
        Commands::BuildUki {
            stub,
            kernel,
            initrd,
            cmdline,
            osrel,
            splash,
            output,
            arch,
        } => {
            let arch_name = match arch.as_deref() {
                Some(a) => a,
                None => std::env::consts::ARCH,
            };
            let arch_info = sysimage::arch::get_arch(arch_name)?;
            sysimage::ukify::ukify_build(&sysimage::ukify::UkifyConfig {
                stub,
                kernel,
                initrd,
                cmdline,
                osrel,
                splash,
                output,
                arch: arch_info,
            })?;
            Ok(())
        }
        Commands::SbkeyGenerate {
            output,
            passphrase_file,
        } => {
            let passphrase = match passphrase_file {
                Some(path) if path.as_os_str() == std::ffi::OsStr::new("-") => {
                    use std::io::Read as _;
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf).map_err(|e| {
                        sysimage::error::Error::msg(format!(
                            "Failed to read passphrase from stdin: {e}"
                        ))
                    })?;
                    Some(buf)
                }
                Some(path) => Some(std::fs::read(&path).map_err(|e| {
                    sysimage::error::Error::msg(format!(
                        "Failed to read passphrase file {}: {e}",
                        path.display()
                    ))
                })?),
                None => None,
            };
            sysimage::secboot::generate::sbkey_generate_with_passphrase(
                &output,
                passphrase.as_deref(),
            )?;
            println!(
                "Generated PK/KEK/db keys{} in {}",
                if passphrase.is_some() {
                    " (encrypted)"
                } else {
                    ""
                },
                output.display()
            );
            Ok(())
        }
    }
}
