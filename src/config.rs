//! Config reading, expansion, and MBR type-code parsing.
//!
//! The type definitions live in [`crate::model::config`]; this module holds
//! the implementation: reading a YAML config from disk, expanding a partial
//! config over the built-in defaults, and parsing MBR partition type codes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::arch::{ArchInfo, ArchName};
use crate::model::config::{ConfigBuild, ConfigParameters, ExpandedConfigBuild};

/// A raw config paired with the directory it was loaded from.
#[derive(Debug, Clone)]
pub struct ConfigWithDirectory {
    pub config: ConfigBuild,
    pub config_directory: PathBuf,
}

/// Read and parse a YAML/JSON config from `path`.
pub fn read_config(path: &Path) -> crate::error::Result<ConfigWithDirectory> {
    let full = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let directory = full
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let text = std::fs::read_to_string(&full)?;
    let value: serde_json::Value = serde_yaml::from_str(&text)?;
    crate::validate::validate(&value, &crate::model::schema::config_schema())?;
    let config: ConfigBuild = serde_yaml::from_str(&text)?;
    Ok(ConfigWithDirectory {
        config,
        config_directory: directory,
    })
}

/// A fully-expanded config plus resolved directories and arch info.
#[derive(Debug, Clone)]
pub struct ExpandedConfigWithDirectories {
    pub arch: ArchInfo,
    pub config: ExpandedConfigBuild,
    pub config_directory: PathBuf,
    pub temp_directory: PathBuf,
    pub output_directory: PathBuf,
}

/// Validate and expand a config, resolving the temp/output directories
/// relative to the config directory.
pub fn validate_and_expand_config(
    with_dir: &ConfigWithDirectory,
) -> crate::error::Result<ExpandedConfigWithDirectories> {
    let config = expand_config(&with_dir.config)?;
    let arch = config.arch.info()?;
    let temp_directory = with_dir.config_directory.join(&config.temp_directory);
    let output_directory = with_dir.config_directory.join(&config.output_directory);
    Ok(ExpandedConfigWithDirectories {
        arch,
        config,
        config_directory: with_dir.config_directory.clone(),
        temp_directory,
        output_directory,
    })
}

fn f2(n: u32) -> String {
    if n < 10 {
        format!("0{n}")
    } else {
        n.to_string()
    }
}

// ---------------------------------------------------------------------------
// Build parameters
// ---------------------------------------------------------------------------

/// Reserved variable names that build parameters may not shadow.
pub const RESERVED_PARAMETER_NAMES: &[&str] = &[
    "NAME",
    "VERSION",
    "ARCH",
    "CONFIGDIR",
    "EFIARCH",
    "OCIARCH",
    "CONTENTHASH",
    "NETBOOT_IP",
];

/// Resolve build parameters: merge command-line values over the config's
/// declared defaults.
///
/// `declared` is the config's `parameters` map. `supplied` maps parameter names
/// passed on the command line (`--param name=value`) to their values.
///
/// Fails when:
/// - a supplied name is not declared in the config;
/// - a declared parameter has no default and was not supplied (mandatory);
/// - a declared parameter name is not a valid `${...}` variable name, or
///   collides with a reserved built-in variable.
///
/// The returned map contains one entry per declared parameter, with the
/// supplied value taking precedence over the default.
pub fn resolve_parameters(
    declared: &ConfigParameters,
    supplied: &BTreeMap<String, String>,
) -> crate::error::Result<BTreeMap<String, String>> {
    let valid_name = regex::Regex::new(r"^\w+$").unwrap();

    for name in declared.keys() {
        if !valid_name.is_match(name) {
            return Err(crate::error::Error::msg(format!(
                "Invalid build parameter name \"{name}\": must match `[A-Za-z0-9_]+`"
            )));
        }
        if RESERVED_PARAMETER_NAMES.contains(&name.as_str()) {
            return Err(crate::error::Error::msg(format!(
                "Build parameter \"{name}\" collides with a reserved variable"
            )));
        }
    }

    for name in supplied.keys() {
        if !declared.contains_key(name) {
            return Err(crate::error::Error::msg(format!(
                "Unknown build parameter \"{name}\": not declared under `parameters` in the config"
            )));
        }
    }

    let mut resolved = BTreeMap::new();
    for (name, spec) in declared {
        match supplied.get(name).or(spec.default.as_ref()) {
            Some(value) => {
                resolved.insert(name.clone(), value.clone());
            }
            None => {
                return Err(crate::error::Error::msg(format!(
                    "Missing mandatory build parameter \"{name}\": no default is declared; pass it with `--param {name}=<value>`"
                )));
            }
        }
    }
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Config expansion
// ---------------------------------------------------------------------------

/// Built-in defaults.
/// Dynamic fields (version, arch, erofs.timestamp, dm_verity.salt) are filled
/// in by [`default_expanded`].
const DEFAULT_YAML: &str = include_str!("model/default_config.yml");

/// Build the default fully-expanded config, filling dynamic fields (version,
/// host arch, current timestamp, random verity salt).
pub fn default_expanded() -> crate::error::Result<ExpandedConfigBuild> {
    let mut cfg: ExpandedConfigBuild = serde_yaml::from_str(DEFAULT_YAML)?;
    cfg.version = default_version();
    cfg.arch = ArchName(std::env::consts::ARCH.to_string());
    cfg.erofs.timestamp = now_millis();
    cfg.dm_verity.salt = random_salt_hex();
    Ok(cfg)
}

/// Merge a partial [`ConfigBuild`] over the built-in defaults, producing a
/// fully-expanded config.
pub fn expand_config(input: &ConfigBuild) -> crate::error::Result<ExpandedConfigBuild> {
    let mut cfg = default_expanded()?;

    if let Some(v) = &input.schema {
        cfg.schema = Some(v.clone());
    }
    if let Some(v) = &input.name {
        cfg.name = v.clone();
    }
    if let Some(v) = &input.version {
        cfg.version = v.clone();
    }
    if let Some(v) = &input.arch {
        cfg.arch = v.clone();
    }
    if let Some(v) = &input.input {
        cfg.input = v.clone();
    }
    if let Some(v) = &input.output_directory {
        cfg.output_directory = v.clone();
    }
    if let Some(v) = &input.temp_directory {
        cfg.temp_directory = v.clone();
    }
    if let Some(v) = &input.disk {
        cfg.disk = v.clone();
    }
    if let Some(v) = &input.lvm {
        cfg.lvm = v.clone();
    }

    if let Some(b) = &input.build {
        if let Some(x) = &b.erofs {
            cfg.build.erofs = x.clone();
        }
        if let Some(x) = &b.cpio {
            cfg.build.cpio = x.clone();
        }
        if let Some(x) = &b.uki {
            cfg.build.uki = x.clone();
        }
        if let Some(x) = &b.veritytab {
            cfg.build.veritytab = x.clone();
        }
        if let Some(x) = &b.efisign {
            cfg.build.efisign = x.clone();
        }
        if let Some(x) = &b.block {
            cfg.build.block = x.clone();
        }
        if let Some(x) = &b.encrypt {
            cfg.build.encrypt = x.clone();
        }
        if let Some(x) = &b.decrypt {
            cfg.build.decrypt = x.clone();
        }
        if let Some(x) = &b.reencrypt {
            cfg.build.reencrypt = x.clone();
        }
    }

    if let Some(e) = &input.erofs {
        if let Some(x) = e.timestamp {
            cfg.erofs.timestamp = x;
        }
        if let Some(x) = e.block_size {
            cfg.erofs.block_size = x;
        }
    }
    if let Some(d) = &input.dm_verity {
        if let Some(x) = &d.salt {
            cfg.dm_verity.salt = x.clone();
        }
        if let Some(x) = d.hash_block_size {
            cfg.dm_verity.hash_block_size = x;
        }
        if let Some(x) = d.data_block_size {
            cfg.dm_verity.data_block_size = x;
        }
    }
    if let Some(c) = &input.cpio {
        cfg.cpio = c.clone();
    }
    if let Some(u) = &input.uki {
        if let Some(x) = &u.stub {
            cfg.uki.stub = x.clone();
        }
        if let Some(x) = &u.kernel {
            cfg.uki.kernel = x.clone();
        }
        if let Some(x) = &u.initrd {
            cfg.uki.initrd = x.clone();
        }
        if let Some(x) = &u.cmdline {
            cfg.uki.cmdline = x.clone();
        }
        if let Some(x) = &u.osrel {
            cfg.uki.osrel = Some(x.clone());
        }
        if let Some(x) = &u.splash {
            cfg.uki.splash = Some(x.clone());
        }
    }

    if let Some(q) = &input.qemu {
        if let Some(x) = &q.machine {
            cfg.qemu.machine = Some(x.clone());
        }
        if let Some(x) = &q.cpu {
            cfg.qemu.cpu = Some(x.clone());
        }
        if let Some(x) = q.smp {
            cfg.qemu.smp = Some(x);
        }
        if let Some(x) = &q.memory {
            cfg.qemu.memory = Some(x.clone());
        }
        if let Some(x) = &q.extra_args {
            cfg.qemu.extra_args = Some(x.clone());
        }
        if let Some(x) = &q.disks {
            cfg.qemu.disks = Some(x.clone());
        }
        if let Some(x) = &q.tpms {
            cfg.qemu.tpms = Some(x.clone());
        }
        if let Some(x) = &q.firmware {
            cfg.qemu.firmware = Some(x.clone());
        }
        if let Some(x) = &q.kernel {
            cfg.qemu.kernel = Some(x.clone());
        }
        if let Some(x) = &q.shim {
            cfg.qemu.shim = Some(x.clone());
        }
        if let Some(x) = &q.initrd {
            cfg.qemu.initrd = Some(x.clone());
        }
        if let Some(x) = &q.dtb {
            cfg.qemu.dtb = Some(x.clone());
        }
        if let Some(x) = &q.append {
            cfg.qemu.append = Some(x.clone());
        }
    }

    if let Some(n) = &input.netboot {
        cfg.netboot = Some(n.clone());
    }
    if let Some(p) = &input.parameters {
        cfg.parameters = p.clone();
    }

    // Validate the chosen architecture is supported.
    cfg.arch.info()?;
    Ok(cfg)
}

/// Default version: `YYYYMMDDHHmmss` in local time.
fn default_version() -> String {
    use chrono::{Datelike, Local, Timelike};
    let now = Local::now();
    format!(
        "{}{}{}{}{}{}",
        now.year(),
        f2(now.month()),
        f2(now.day()),
        f2(now.hour()),
        f2(now.minute()),
        f2(now.second()),
    )
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 32 random bytes as a lowercase hex string (the verity salt).
fn random_salt_hex() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// MBR partition type code parsing
// ---------------------------------------------------------------------------

/// Parse an MBR partition type code into its raw byte value.
///
/// Accepts a known name (case-insensitive) or a `"0xNN"`/`"NN"` hex byte.
pub fn parse_mbr_type(code: &str) -> crate::error::Result<u8> {
    let lower = code.trim().to_ascii_lowercase();
    let val = match lower.as_str() {
        "empty" | "free" => 0x00,
        "fat12" => 0x01,
        "fat16" => 0x04,
        "extended" => 0x05,
        "fat16lba" => 0x06,
        "ntfs" => 0x07,
        "fat32" => 0x0b,
        "fat32lba" => 0x0c,
        "extendedlba" => 0x0f,
        "iso9660" => 0x17,
        "swap" | "linuxswap" => 0x82,
        "linux" | "linuxnative" => 0x83,
        "lvm" | "linuxlvm" => 0x8e,
        "raid" | "linuxraid" => 0xfd,
        "efi" | "efisystem" | "esp" => 0xef,
        // "protective" (0xEE) is reserved for the protective MBR and rejected
        // here — it is never a user partition type.
        _ => {
            let s = lower.strip_prefix("0x").unwrap_or(&lower);
            u8::from_str_radix(s, 16).map_err(|_| {
                crate::error::Error::msg(format!("Invalid MBR partition type: {code}"))
            })?
        }
    };
    if val == 0xEE {
        return Err(crate::error::Error::msg(
            "MBR partition type 0xEE (protective) is reserved for GPT protective MBR",
        ));
    }
    Ok(val)
}
