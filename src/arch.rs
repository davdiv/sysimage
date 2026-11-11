//! Architecture metadata.
//!
//! Each supported architecture maps to its UEFI removable-media name, the PE
//! machine type, the QEMU/OCI names, and the rust `std::env::consts::ARCH`
//! identifier (stored in the manifest).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One supported architecture's cross-toolchain identifiers.
#[derive(Debug, Clone, Copy)]
pub struct ArchInfo {
    /// UEFI removable-media suffix, e.g. `x64`, `aa64`.
    pub efi: &'static str,
    /// PE/COFF machine type, e.g. `0x8664` for x86_64.
    pub efi_pe: u16,
    /// QEMU `-M`/`-cpu` style name.
    pub qemu: &'static str,
    /// OCI image architecture.
    pub oci: &'static str,
    /// rust std::env::consts::ARCH identifier
    pub rust: &'static str,
}

/// Supported architectures
pub const ARCHITECTURES: [ArchInfo; 4] = [
    ArchInfo {
        efi: "ia32",
        efi_pe: 0x014c,
        qemu: "i386",
        oci: "386",
        rust: "x86",
    },
    ArchInfo {
        efi: "x64",
        efi_pe: 0x8664,
        qemu: "x86_64",
        oci: "amd64",
        rust: "x86_64",
    },
    ArchInfo {
        efi: "arm",
        efi_pe: 0x01c2,
        qemu: "arm",
        oci: "arm",
        rust: "arm",
    },
    ArchInfo {
        efi: "aa64",
        efi_pe: 0xaa64,
        qemu: "aarch64",
        oci: "arm64",
        rust: "aarch64",
    },
];

/// Look up the architecture info for a rust arch name.
pub fn get_arch(arch: &str) -> crate::error::Result<ArchInfo> {
    for info in ARCHITECTURES {
        if info.rust == arch {
            return Ok(info);
        }
    }
    Err(crate::error::Error::msg(format!(
        "Unsupported architecture: {arch}"
    )))
}

/// Serde-friendly architecture, represented as its rust arch name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ArchName(pub String);

impl ArchName {
    /// Resolve to the full [`ArchInfo`].
    pub fn info(&self) -> crate::error::Result<ArchInfo> {
        get_arch(&self.0)
    }
}
