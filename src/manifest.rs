//! Manifest reading.

use std::path::{Path, PathBuf};

use crate::config::{read_config, validate_and_expand_config};
use crate::model::manifest::ManifestBuild;

/// Options for locating a manifest.
pub struct ReadManifestConfig<'a> {
    pub config: &'a Path,
    pub manifest: Option<&'a Path>,
}

/// A loaded manifest paired with its directory and file name.
#[derive(Debug, Clone)]
pub struct ManifestWithDirectory {
    pub manifest: ManifestBuild,
    pub manifest_directory: PathBuf,
    pub manifest_file_name: String,
}

/// Read a manifest, either from an explicit path or by deriving its location
/// from the config's `outputDirectory` and `name`.
pub fn read_manifest(opts: ReadManifestConfig<'_>) -> crate::error::Result<ManifestWithDirectory> {
    let (manifest_directory, manifest_file_name, manifest_path) = match opts.manifest {
        Some(p) => {
            let full = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
            let dir = full
                .parent()
                .map(|x| x.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            let name = full
                .file_name()
                .map(|x| x.to_string_lossy().into_owned())
                .unwrap_or_default();
            (dir, name, full)
        }
        None => {
            let expanded = validate_and_expand_config(&read_config(opts.config)?);
            let expanded = expanded?;
            let dir = expanded.output_directory;
            let name = format!("{}.json", expanded.config.name);
            (dir.clone(), name.clone(), dir.join(&name))
        }
    };

    let text = std::fs::read_to_string(&manifest_path)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    crate::validate::validate(&value, &crate::model::schema::manifest_schema())?;
    let manifest: ManifestBuild = serde_json::from_str(&text)?;
    Ok(ManifestWithDirectory {
        manifest,
        manifest_directory,
        manifest_file_name,
    })
}
