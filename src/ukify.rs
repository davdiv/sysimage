//! Unified Kernel Image building (pure-Rust).
//!
//! A UKI is a PE binary composed of a `systemd-stub` plus extra sections
//! (`.linux`, `.initrd`, `.cmdline`, …).  Instead of shelling out to the
//! `ukify` tool from systemd, we stitch the sections onto the stub directly
//! using [`crate::pe`].

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::pe::{self, PeSection};

/// Build a UKI from a stub, kernel and initrds.
pub struct UkifyConfig {
    pub stub: PathBuf,
    pub kernel: PathBuf,
    pub initrd: Vec<PathBuf>,
    pub cmdline: Option<String>,
    /// Optional `os-release` file whose contents become the `.osrel` section.
    /// systemd-boot requires `.osrel` to recognise the image as a UKI.
    pub osrel: Option<PathBuf>,
    /// Optional splash image (BMP) whose contents become the `.splash` section,
    /// displayed by systemd-stub during boot.
    pub splash: Option<PathBuf>,
    pub output: PathBuf,
    pub arch: crate::arch::ArchInfo,
}

/// Build a Unified Kernel Image by stitching `.linux`, `.initrd`, and
/// (optionally) `.cmdline` sections onto the stub PE.
pub fn ukify_build(cfg: &UkifyConfig) -> Result<()> {
    let stub_data = fs::read(&cfg.stub)
        .map_err(|e| Error::msg(format!("failed to read stub {}: {e}", cfg.stub.display())))?;
    let kernel_data = fs::read(&cfg.kernel).map_err(|e| {
        Error::msg(format!(
            "failed to read kernel {}: {e}",
            cfg.kernel.display()
        ))
    })?;

    let mut sections: Vec<PeSection> = Vec::new();

    // `.osrel` — the OS identification (from /etc/os-release).  systemd-boot
    // requires this section to recognise the PE as a UKI, so it is added first.
    if let Some(osrel) = &cfg.osrel {
        let data = fs::read(osrel)
            .map_err(|e| Error::msg(format!("failed to read osrel {}: {e}", osrel.display())))?;
        sections.push(PeSection {
            name: ".osrel",
            data,
            is_code: false,
        });
    }

    // `.cmdline` — the kernel command line (before `.linux`, matching ukify).
    if let Some(cmdline) = &cfg.cmdline {
        sections.push(PeSection {
            name: ".cmdline",
            data: cmdline.as_bytes().to_vec(),
            is_code: false,
        });
    }

    // `.linux` — the kernel image.
    sections.push(PeSection {
        name: ".linux",
        data: kernel_data,
        is_code: true,
    });

    // `.initrd` — initrds are concatenated with 4-byte alignment padding.
    let initrd_data = join_initrds(&cfg.initrd)?;
    if !initrd_data.is_empty() {
        sections.push(PeSection {
            name: ".initrd",
            data: initrd_data,
            is_code: false,
        });
    }

    // `.splash` — boot splash image (BMP) shown by systemd-stub.
    if let Some(splash) = &cfg.splash {
        let data = fs::read(splash)
            .map_err(|e| Error::msg(format!("failed to read splash {}: {e}", splash.display())))?;
        sections.push(PeSection {
            name: ".splash",
            data,
            is_code: false,
        });
    }

    let output_data = pe::add_sections(&stub_data, &sections)?;
    fs::write(&cfg.output, &output_data)?;
    Ok(())
}

/// Inspect a UKI, returning the section table as parsed JSON.
pub fn ukify_inspect(input: &std::path::Path) -> Result<Value> {
    let data = fs::read(input)
        .map_err(|e| Error::msg(format!("failed to read {}: {e}", input.display())))?;
    let raw_sections = pe::list_sections(&data)?;

    // Text sections are decoded as UTF-8; binary sections are hex-encoded.
    const TEXT_SECTIONS: &[&str] = &[
        ".cmdline", ".osrel", ".uname", ".pcrpkey", ".pcrsig", ".sbat", ".profile",
    ];

    let mut map = serde_json::Map::new();
    for (name, virtual_size, _raw_size, _offset, payload) in raw_sections {
        let usable = &payload[..(virtual_size as usize).min(payload.len())];
        let value = if TEXT_SECTIONS.contains(&name.as_str()) {
            let text = String::from_utf8_lossy(usable)
                .trim_end_matches('\0')
                .to_string();
            Value::String(text)
        } else {
            Value::String(hex::encode(usable))
        };
        map.insert(name, value);
    }
    Ok(json!(map))
}

// --- helpers ------------------------------------------------------------

/// Concatenate initrd files, padding each to 4-byte alignment (matching ukify).
pub(crate) fn join_initrds(initrds: &[PathBuf]) -> Result<Vec<u8>> {
    if initrds.is_empty() {
        return Ok(Vec::new());
    }
    if initrds.len() == 1 {
        return Ok(fs::read(&initrds[0])?);
    }
    let mut out = Vec::new();
    for path in initrds {
        let data = fs::read(path)?;
        out.extend_from_slice(&data);
        let pad = (4 - (data.len() % 4)) % 4;
        out.resize(out.len() + pad, 0);
    }
    Ok(out)
}
