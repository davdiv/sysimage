//! Build pipeline: config → artifacts + manifest.
//!
//! The [`BuildContext`] holds the in-progress manifest
//! (disk/file/lvm/verity maps), memoizes artifact builds, and content-addresses
//! output files.

mod artifacts;
pub(crate) mod block;
mod context;

pub use context::OutputFileEntry;
pub use context::{BuildContext, VerityMetadata};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::{ExpandedConfigWithDirectories, read_config, validate_and_expand_config};
use crate::error::{Error, Result};
use crate::input::InputManager;
use crate::manifest::ManifestWithDirectory;

/// Build a system image from a config file (no LUKS keys — `build:block:`
/// subtrees containing a `luks` block cannot be rendered this way).
pub fn build_from_file(config_path: &Path) -> Result<()> {
    build_from_file_with_keys(
        config_path,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .map(|_| ())
}

/// Build a system image from a config file, supplying LUKS passphrases for any
/// `build:block:` subtree that contains a `luks` block.
///
/// `key` maps a LUKS container name to an inline passphrase; `key_file` maps a
/// name to a key-file path (read from disk and used **exactly as-is** — no
/// trailing-newline stripping). A name present in both is taken from `key`.
/// Names not supplied here are not needed unless a `build:block:` block
/// actually contains a matching `luks` block, in which case the build will
/// error asking for the key.
///
/// `sign_keys` maps an `efisign` artifact's `key` name to a signing-key
/// directory (containing `db.key` + `db.crt`, as produced by
/// `sbkey-generate`); `efisign` artifacts whose `key` is absent here are left
/// unsigned.
pub fn build_from_file_with_keys(
    config_path: &Path,
    key: &BTreeMap<String, String>,
    key_file: &BTreeMap<String, PathBuf>,
    sign_keys: &BTreeMap<String, PathBuf>,
) -> Result<ManifestWithDirectory> {
    build_from_file_with_options(
        config_path,
        key,
        key_file,
        sign_keys,
        &BTreeMap::new(),
        &BuildOverrides::default(),
    )
}

/// Command-line overrides applied on top of the config when building.
///
/// A `Some` field replaces the corresponding config value (or the built-in
/// default, when the config omits it) for the whole build: it feeds
/// `${NAME}`/`${VERSION}` substitution, the manifest's `name`/`version`
/// fields, and the `<name>-<hash>.json` / `<name>.json` output names.
#[derive(Debug, Default, Clone)]
pub struct BuildOverrides {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Build a system image from a config file, supplying LUKS keys, build
/// parameter values, and command-line overrides.
///
/// `parameters` maps each declared parameter name to the value supplied on the
/// command line (`sysimage build --param name=value`). Values override the
/// config's declared defaults; a declared parameter without a default must be
/// present, and a name not declared under `parameters` in the config is an
/// error (see [`crate::config::resolve_parameters`]).
///
/// `overrides` carries the `--name`/`--version` command-line values, applied on
/// top of the config before expansion (see [`BuildOverrides`]).
///
/// This is a convenience wrapper over [`build_from_file_with_sign_keys`] with
/// no encrypted (`--sign-key-file`) signing keys.
pub fn build_from_file_with_options(
    config_path: &Path,
    key: &BTreeMap<String, String>,
    key_file: &BTreeMap<String, PathBuf>,
    sign_keys: &BTreeMap<String, PathBuf>,
    parameters: &BTreeMap<String, String>,
    overrides: &BuildOverrides,
) -> Result<ManifestWithDirectory> {
    build_from_file_with_sign_keys(
        config_path,
        key,
        key_file,
        sign_keys,
        &BTreeMap::new(),
        parameters,
        overrides,
    )
}

/// Build a system image from a config file, additionally supplying passphrases
/// for SENC-encrypted `db.key` signing keys.
///
/// `sign_key_files` maps an `efisign` artifact's `key` name to a passphrase
/// file whose **exact bytes** derive the SENC envelope key (as produced by
/// `sysimage sbkey-generate --passphrase-file`). A path of `-` reads the
/// passphrase from stdin; at most one entry may do so. Names absent here must
/// name a plaintext PKCS#8 PEM `db.key`, matching the behaviour of
/// [`build_from_file_with_options`].
pub fn build_from_file_with_sign_keys(
    config_path: &Path,
    key: &BTreeMap<String, String>,
    key_file: &BTreeMap<String, PathBuf>,
    sign_keys: &BTreeMap<String, PathBuf>,
    sign_key_files: &BTreeMap<String, PathBuf>,
    parameters: &BTreeMap<String, String>,
    overrides: &BuildOverrides,
) -> Result<ManifestWithDirectory> {
    let mut with_dir = read_config(config_path)?;
    if let Some(name) = &overrides.name {
        if name.is_empty() {
            return Err(Error::msg("--name must not be empty"));
        }
        with_dir.config.name = Some(name.clone());
    }
    if let Some(version) = &overrides.version {
        if version.is_empty() {
            return Err(Error::msg("--version must not be empty"));
        }
        with_dir.config.version = Some(version.clone());
    }
    let expanded = validate_and_expand_config(&with_dir)?;
    let build_keys = resolve_build_keys(key, key_file)?;
    let sign_key_passphrases = resolve_sign_key_passphrases(sign_key_files)?;
    build_expanded_full(
        expanded,
        build_keys,
        sign_keys.clone(),
        sign_key_passphrases,
        parameters.clone(),
    )
}

/// Run the build pipeline from an already-loaded config (no LUKS keys).
pub fn build(arg: crate::config::ConfigWithDirectory) -> Result<ManifestWithDirectory> {
    let expanded = validate_and_expand_config(&arg)?;
    build_expanded(expanded)
}

/// Build from a fully-expanded config (no LUKS keys).
pub fn build_expanded(expanded: ExpandedConfigWithDirectories) -> Result<ManifestWithDirectory> {
    build_expanded_with_keys(expanded, BTreeMap::new(), BTreeMap::new())
}

/// Build from a fully-expanded config with LUKS passphrases for `build:block:`.
pub fn build_expanded_with_keys(
    expanded: ExpandedConfigWithDirectories,
    build_keys: BTreeMap<String, Vec<u8>>,
    sign_keys: BTreeMap<String, PathBuf>,
) -> Result<ManifestWithDirectory> {
    build_expanded_with_options(expanded, build_keys, sign_keys, BTreeMap::new())
}

/// Build from a fully-expanded config with LUKS passphrases and build parameter
/// values. See [`build_from_file_with_options`] for the parameter semantics.
///
/// This is a convenience wrapper over [`build_expanded_full`] with no encrypted
/// (`--sign-key-file`) signing keys.
pub fn build_expanded_with_options(
    expanded: ExpandedConfigWithDirectories,
    build_keys: BTreeMap<String, Vec<u8>>,
    sign_keys: BTreeMap<String, PathBuf>,
    parameters: BTreeMap<String, String>,
) -> Result<ManifestWithDirectory> {
    build_expanded_full(expanded, build_keys, sign_keys, BTreeMap::new(), parameters)
}

/// Build from a fully-expanded config, additionally supplying passphrases for
/// SENC-encrypted `db.key` signing keys (keyed by `--sign` name).
fn build_expanded_full(
    expanded: ExpandedConfigWithDirectories,
    build_keys: BTreeMap<String, Vec<u8>>,
    sign_keys: BTreeMap<String, PathBuf>,
    sign_key_passphrases: BTreeMap<String, Vec<u8>>,
    parameters: BTreeMap<String, String>,
) -> Result<ManifestWithDirectory> {
    let arch = expanded.arch;
    let config = expanded.config.clone();
    let config_directory = expanded.config_directory.clone();

    // Resolve build parameters (command-line values over declared defaults).
    // Must happen before any `${VAR}` substitution.
    let parameters = crate::config::resolve_parameters(&config.parameters, &parameters)?;

    // Environment variables for ${VAR} substitution.
    let mut env = std::collections::BTreeMap::new();
    env.insert("NAME".to_string(), config.name.clone());
    env.insert("VERSION".to_string(), config.version.clone());
    env.insert("ARCH".to_string(), config.arch.0.clone());
    env.insert(
        "CONFIGDIR".to_string(),
        config_directory.to_string_lossy().into_owned(),
    );
    env.insert("EFIARCH".to_string(), arch.efi.to_string());
    env.insert("OCIARCH".to_string(), arch.oci.to_string());
    // User-declared build parameters, usable anywhere the built-in variables
    // are (e.g. `${CONFIGDIR}`). Names colliding with built-ins are rejected by
    // `resolve_parameters`, so this cannot shadow an existing entry.
    env.extend(parameters);

    let input_manager = InputManager::new(arch);
    // The root input directory: resolve config.input relative to the config dir.
    let input_directory = input_manager.resolve_input(
        &crate::variables::substitute_string(&config.input, &|n: &str| env.get(n).cloned())?,
        &config_directory,
    )?;

    std::fs::create_dir_all(&expanded.temp_directory)?;
    let build_temp_directory = mkdtemp(&expanded.temp_directory, "sysimage-")?;
    std::fs::create_dir_all(&expanded.output_directory)?;

    let ctx = BuildContext::new(
        expanded,
        input_directory,
        build_temp_directory,
        input_manager,
        env,
        build_keys,
        sign_keys,
        sign_key_passphrases,
    );

    for (disk_name, disk_config) in &ctx.config.disk {
        eprintln!("Processing disk: {disk_name} ...");
        let manifest_block = block::process_block(&ctx, disk_config)?;
        ctx.set_disk(disk_name, manifest_block);
    }

    let res = ctx.write_output()?;

    // Create the `${name}.json` symlink to the manifest, replacing an existing
    // symlink (but never a regular file).
    let manifest_symlink = ctx
        .output_directory
        .join(format!("{}.json", ctx.config.name));
    #[cfg(unix)]
    {
        if std::fs::symlink_metadata(&manifest_symlink)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            let _ = std::fs::remove_file(&manifest_symlink);
        }
        if !manifest_symlink.exists() {
            std::os::unix::fs::symlink(&res.manifest_file_name, &manifest_symlink)?;
        }
    }
    let _ = arch;
    Ok(res)
}

/// Create a unique temporary directory under `base` with the given prefix.
fn mkdtemp(base: &Path, prefix: &str) -> Result<PathBuf> {
    use rand::RngExt;
    let n = hex::encode(rand::rng().random::<[u8; 8]>());
    let dir = base.join(format!("{prefix}{n}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Resolve the LUKS passphrases supplied to `sysimage build` (inline via `key`
/// or from files via `key_file`) into a `name → passphrase bytes` map. Key
/// files are used exactly as read (no trailing-newline stripping). Unlike
/// the install path, there is no manifest to enumerate the required LUKS names
/// from yet, so every supplied entry is resolved eagerly; a name supplied via
/// both `key` and `key_file` is taken from `key`.
fn resolve_build_keys(
    key: &BTreeMap<String, String>,
    key_file: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut resolved: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, pass) in key {
        resolved.insert(name.clone(), pass.as_bytes().to_vec());
    }
    for (name, path) in key_file {
        if resolved.contains_key(name) {
            continue;
        }
        let data = std::fs::read(path)
            .map_err(|e| Error::msg(format!("Failed to read key file for \"{name}\": {e}")))?;
        resolved.insert(name.clone(), data);
    }
    Ok(resolved)
}

/// Resolve the `--sign-key-file name=path` passphrases for SENC-encrypted
/// `db.key` signing keys into a `name → passphrase bytes` map. Files are used
/// exactly as read (no trailing-newline stripping). A path of `-` reads the
/// passphrase from stdin; at most one entry may do so.
fn resolve_sign_key_passphrases(
    sign_key_files: &BTreeMap<String, PathBuf>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    use std::io::Read as _;

    let mut resolved: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stdin_consumed = false;
    for (name, path) in sign_key_files {
        let bytes = if path.as_os_str() == std::ffi::OsStr::new("-") {
            if stdin_consumed {
                return Err(Error::msg(
                    "at most one --sign-key-file may read from stdin (`-`)",
                ));
            }
            stdin_consumed = true;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| Error::msg(format!("Failed to read passphrase from stdin: {e}")))?;
            buf
        } else {
            std::fs::read(path).map_err(|e| {
                Error::msg(format!(
                    "Failed to read passphrase file for \"{name}\": {e}"
                ))
            })?
        };
        resolved.insert(name.clone(), bytes);
    }
    Ok(resolved)
}
