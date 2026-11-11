//! Default-config scaffolding.

use std::path::Path;

use crate::error::Result;
use crate::model::config::ExpandedConfigBuild;
use crate::model::schema::{CONFIG_SCHEMA_FILE, config_schema};

/// Build the default fully-expanded config (with dynamic version/timestamp/salt).
pub fn init_config() -> Result<ExpandedConfigBuild> {
    let mut cfg = crate::config::default_expanded()?;
    // Reference the config schema so editors/tools validate the scaffolded file.
    cfg.schema = Some(CONFIG_SCHEMA_FILE.to_string());
    Ok(cfg)
}

/// Write a freshly-scaffolded config to `path` (fails if it already exists),
/// alongside the config JSON schema in the same directory.
pub fn write_default_config(path: &Path) -> Result<()> {
    let cfg = init_config()?;
    let yaml = serde_yaml::to_string(&cfg)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    std::fs::write(path, yaml)?;

    // Write the config schema into the same directory.
    let dir = path.parent().unwrap_or_else(|| Path::new(""));
    let config_schema = config_schema();
    std::fs::write(
        dir.join(CONFIG_SCHEMA_FILE),
        serde_json::to_string_pretty(&config_schema)?,
    )?;

    Ok(())
}
