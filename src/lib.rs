//! sysimage — declarative system image builder.
//!
//! Pipeline: config (YAML) → build artifacts + manifest → install onto a disk
//! image or block device. Pure-Rust filesystem/partition backends (hadris for
//! GPT/cpio/FAT, rust-fs-erofs for EROFS, rust-fs-ext4 for ext4).

pub mod arch;
pub mod archive;
pub mod blockfile;
pub mod build;
pub mod config;
pub mod dmverity;
pub mod encrypt;
pub mod erofs;
pub mod error;
pub mod exec;
pub mod hash;
pub mod init;
pub mod input;
pub mod install;
pub mod install_kernel;
pub mod luks;
pub mod lvm;
pub mod manifest;
pub mod model;
pub mod nbd;
pub mod netboot;
pub mod pe;
pub mod qemu;
pub mod secboot;
pub mod size;
pub mod ssh;
pub mod ukify;
mod url;
pub mod uuid;
pub mod validate;
pub mod variables;
