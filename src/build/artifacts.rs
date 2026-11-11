//! Artifact builders (erofs/cpio/uki/veritytab).

use std::path::PathBuf;

use base64::Engine;
use serde_json::json;

use super::BuildContext;
use crate::archive::{build_archive, collect_tree};
use crate::dmverity::verity_format;
use crate::erofs::{ErofsCompression, build_erofs_image_owned, erofs_set_uuid};
use crate::error::{Error, Result};
use crate::hash;
use crate::input::{ResolvedFileEntry, ResolvedFilesSet, ResolvedSource};
use crate::model::config::{
    ArchiveFormat, ConfigArtifactCpio, ConfigArtifactEfiSign, ConfigArtifactErofs,
    ConfigArtifactUkiPartial, ConfigFileEntry, ConfigFilesSet, ConfigVeritytabEntry,
};
use crate::ukify::ukify_build;
use zeroize::Zeroize;

/// Build the artifact referenced by a `build:type:name` URL.
pub fn build_artifact(ctx: &BuildContext, url: &str) -> Result<PathBuf> {
    let rest = url
        .strip_prefix("build:")
        .ok_or_else(|| Error::msg(format!("Invalid build URL: {url}")))?;
    let (kind, name) = rest
        .split_once(':')
        .ok_or_else(|| Error::msg(format!("Invalid build URL: {url}")))?;
    match kind {
        "erofs" => build_erofs_artifact(ctx, name),
        "cpio" => build_cpio_artifact_named(ctx, name),
        "uki" => build_uki_artifact(ctx, name),
        "veritytab" => build_veritytab_artifact(ctx, name),
        "efisign" => build_efisign_artifact(ctx, name),
        "block" => build_block_artifact(ctx, name),
        "encrypt" => build_encrypt_artifact(ctx, name),
        "decrypt" => build_decrypt_artifact(ctx, name),
        "reencrypt" => build_reencrypt_artifact(ctx, name),
        other => Err(Error::msg(format!("Unknown type of artifact: {other}"))),
    }
}

/// Resolve an `erofs` artifact config by name.
fn erofs_config<'a>(ctx: &'a BuildContext, name: &str) -> Result<&'a ConfigArtifactErofs> {
    ctx.config
        .build
        .erofs
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: erofs:{name}")))
}

fn uki_partial<'a>(ctx: &'a BuildContext, name: &str) -> Result<&'a ConfigArtifactUkiPartial> {
    ctx.config
        .build
        .uki
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: uki:{name}")))
}

fn cpio_config<'a>(ctx: &'a BuildContext, name: &str) -> Result<&'a ConfigArtifactCpio> {
    ctx.config
        .build
        .cpio
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: cpio:{name}")))
}

fn veritytab_config<'a>(
    ctx: &'a BuildContext,
    name: &str,
) -> Result<&'a crate::model::config::ConfigVeritytabArtifact> {
    ctx.config
        .build
        .veritytab
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: veritytab:{name}")))
}

/// Build an EROFS image (with dm-verity) and capture the verity metadata.
fn build_erofs_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = erofs_config(ctx, name)?;
    let erofs = merge_erofs(ctx, cfg);
    let dm_verity = merge_dm_verity(ctx, cfg);
    let resolved = resolve_files_set(ctx, &cfg.input)?;
    eprintln!(
        "  EROFS \"{name}\": collecting {} input(s) ...",
        cfg.input.len()
    );
    let root = collect_tree(&resolved)?;
    // The file set is no longer needed once the tree is in memory. Dropping it
    // early also releases any virtual-tree sources held by `in:` inputs.
    drop(resolved);
    eprintln!("  EROFS \"{name}\": building image ...");

    let mut image = build_erofs_image_owned(
        root,
        erofs.block_size,
        erofs.timestamp,
        ErofsCompression::Lz4,
    )?;

    // Pad to the verity block alignment before hashing (matches `alignFileSize`).
    let align = std::cmp::max(dm_verity.data_block_size, dm_verity.hash_block_size) as usize;
    let rem = image.len() % align;
    if rem != 0 {
        image.resize(image.len() + (align - rem), 0);
    }

    let content_hash = hash::hash_content(&[&image]);
    let salt_bytes = hex::decode(&dm_verity.salt)
        .map_err(|e| Error::msg(format!("invalid dm-verity salt: {e}")))?;
    let uuid_input = hash::hash_content(&[
        &content_hash,
        json!({ "dataBlockSize": dm_verity.data_block_size, "hashBlockSize": dm_verity.hash_block_size }).to_string().as_bytes(),
        &salt_bytes,
    ]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&uuid_input[..16]);
    let uuid_str = erofs_set_uuid(&mut image, uuid)?;

    let res = verity_format(
        &mut image,
        &salt_bytes,
        dm_verity.data_block_size,
        dm_verity.hash_block_size,
        uuid,
    )?;

    ctx.set_verity(
        name,
        crate::build::VerityMetadata {
            root_hash: res.root_hash,
            hash_offset: res.hash_offset,
            uuid: uuid_str,
            data_block_size: dm_verity.data_block_size,
            hash_block_size: dm_verity.hash_block_size,
            salt: dm_verity.salt.clone(),
        },
    );

    let output_file = ctx.create_temp_file();
    std::fs::write(&output_file, &image)?;
    Ok(output_file)
}

/// Merge the top-level erofs settings with the artifact's overrides.
fn merge_erofs(
    ctx: &BuildContext,
    cfg: &ConfigArtifactErofs,
) -> crate::model::config::ConfigErofsSettings {
    let base = ctx.config.erofs.clone();
    let o = cfg.erofs.clone().unwrap_or_default();
    crate::model::config::ConfigErofsSettings {
        timestamp: o.timestamp.unwrap_or(base.timestamp),
        block_size: o.block_size.unwrap_or(base.block_size),
    }
}

/// Merge the top-level dm-verity settings with the artifact's overrides.
fn merge_dm_verity(
    ctx: &BuildContext,
    cfg: &ConfigArtifactErofs,
) -> crate::model::config::ConfigDmVeritySettings {
    let base = ctx.config.dm_verity.clone();
    let o = cfg.dm_verity.clone().unwrap_or_default();
    crate::model::config::ConfigDmVeritySettings {
        salt: o.salt.unwrap_or(base.salt),
        hash_block_size: o.hash_block_size.unwrap_or(base.hash_block_size),
        data_block_size: o.data_block_size.unwrap_or(base.data_block_size),
    }
}

/// Resolve a files set's inputs: each `input` is resolved (with `${VAR}`
/// substitution, `build:` dispatch, and `in:` descent), and
/// `${CONTENTHASH}` / `${VAR}` in the destination names are substituted. The
/// returned set carries resolved sources (local paths, virtual files, or
/// virtual trees) and can be passed directly to [`build_archive`] or
/// [`compute_content_sizes`](crate::archive::compute_content_sizes).
pub fn resolve_files_set(ctx: &BuildContext, input: &ConfigFilesSet) -> Result<ResolvedFilesSet> {
    let mut resolved: ResolvedFilesSet = Vec::with_capacity(input.len());
    for entry in input {
        let rinput = ctx.resolve_input(&entry.input)?;
        let mut name = entry.destination.clone();
        if name.contains("${CONTENTHASH}") {
            let digest = match &rinput {
                crate::input::ResolvedInput::Path(p) => hash::hash_file(p)?,
                crate::input::ResolvedInput::File(vf) => {
                    let mut r = (vf.open)()?;
                    hash::hash_reader(&mut r)?
                }
                crate::input::ResolvedInput::Tree(_) => {
                    return Err(Error::msg(format!(
                        "${{CONTENTHASH}} is not supported for directory-tree inputs: {input}",
                        input = entry.input
                    )));
                }
            };
            let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..8]);
            name = name.replace("${CONTENTHASH}", &h);
        }
        name = ctx.replace_vars(&name);
        let source = match rinput {
            crate::input::ResolvedInput::Path(p) => ResolvedSource::Path(p),
            crate::input::ResolvedInput::File(vf) => ResolvedSource::File(vf),
            crate::input::ResolvedInput::Tree(t) => ResolvedSource::Tree(t),
        };
        resolved.push(ResolvedFileEntry {
            destination: name,
            source,
            include_pattern: entry.include_pattern.clone(),
            exclude_patterns: entry.exclude_patterns.clone(),
        });
    }
    Ok(resolved)
}

/// Build a cpio/tar archive from a files set. `compression_level` and `format`
/// override the top-level cpio settings when `Some`.
pub fn build_cpio_artifact(
    ctx: &BuildContext,
    input: ConfigFilesSet,
    format: Option<ArchiveFormat>,
    compression_level: Option<i32>,
) -> Result<PathBuf> {
    let fmt = format
        .or(ctx.config.cpio.format)
        .unwrap_or(ArchiveFormat::Cpio);
    let level = compression_level.unwrap_or(ctx.config.cpio.compression_level);

    let resolved = resolve_files_set(ctx, &input)?;

    let output_file = ctx.create_temp_file();
    build_archive(&resolved, fmt, &output_file, level)?;
    Ok(output_file)
}

/// The `cpio` artifact type: merge the top-level cpio settings with the named
/// artifact's config, then build the archive.
fn build_cpio_artifact_named(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = cpio_config(ctx, name)?;
    build_cpio_artifact(ctx, cfg.input.clone(), cfg.format, cfg.compression_level)
}

/// If `input` resolves to a directory (or a virtual tree inside an image),
/// pack it into a cpio archive; otherwise return a local file path.
///
/// This is deliberately generic — there is no special case for encrypted
/// credentials. An `encrypt` artifact that must land at a particular
/// in-initramfs path is wrapped by an explicit `cpio` artifact (its file set
/// names the desired `destination`, its `input` is the `build:encrypt:<name>`
/// URL), and that `build:cpio:<name>` is what gets listed in `uki.initrd`. This
/// keeps the placement decision in the config instead of baking an arbitrary
/// path into the builder.
pub(crate) fn file_or_cpio_directory(ctx: &BuildContext, input: &str) -> Result<PathBuf> {
    let rinput = ctx.resolve_input(input)?;
    match rinput {
        crate::input::ResolvedInput::Path(p) => {
            if p.is_dir() {
                let files: ConfigFilesSet = vec![ConfigFileEntry {
                    destination: String::new(),
                    input: p.to_string_lossy().into_owned(),
                    include_pattern: None,
                    exclude_patterns: None,
                }];
                build_cpio_artifact(ctx, files, None, None)
            } else {
                Ok(p)
            }
        }
        crate::input::ResolvedInput::File(vf) => {
            // A single virtual file → stream to a temp path for the consumer.
            let tmp = ctx.create_temp_file();
            let mut r = (vf.open)()?;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| Error::msg(format!("Cannot create temp {tmp:?}: {e}")))?;
            std::io::copy(&mut r, &mut f)
                .map_err(|e| Error::msg(format!("Cannot stream input to temp: {e}")))?;
            Ok(tmp)
        }
        crate::input::ResolvedInput::Tree(tree) => {
            // A virtual directory tree → pack into a cpio archive.
            let resolved: ResolvedFilesSet = vec![ResolvedFileEntry {
                destination: String::new(),
                source: ResolvedSource::Tree(tree),
                include_pattern: None,
                exclude_patterns: None,
            }];
            let output_file = ctx.create_temp_file();
            build_archive(
                &resolved,
                ctx.config.cpio.format.unwrap_or(ArchiveFormat::Cpio),
                &output_file,
                ctx.config.cpio.compression_level,
            )?;
            Ok(output_file)
        }
    }
}

/// Build a Unified Kernel Image.
fn build_uki_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let partial = uki_partial(ctx, name)?;
    let base = &ctx.config.uki;
    let stub = partial.stub.clone().unwrap_or_else(|| base.stub.clone());
    let kernel = partial
        .kernel
        .clone()
        .unwrap_or_else(|| base.kernel.clone());
    let initrd = partial
        .initrd
        .clone()
        .unwrap_or_else(|| base.initrd.clone());
    let cmdline = partial
        .cmdline
        .clone()
        .unwrap_or_else(|| base.cmdline.clone());
    let osrel = partial.osrel.clone().or_else(|| base.osrel.clone());
    let splash = partial.splash.clone().or_else(|| base.splash.clone());

    let mut initrd_files: Vec<PathBuf> = Vec::with_capacity(initrd.len());
    for input in &initrd {
        initrd_files.push(file_or_cpio_directory(ctx, input)?);
    }

    let output_file = ctx.create_temp_file();
    ukify_build(&crate::ukify::UkifyConfig {
        stub: ctx.resolve_input_path(&stub)?,
        kernel: ctx.resolve_input_path(&kernel)?,
        initrd: initrd_files,
        cmdline,
        osrel: match osrel {
            Some(input) => Some(ctx.resolve_input_path(&input)?),
            None => None,
        },
        splash: match splash {
            Some(input) => Some(ctx.resolve_input_path(&input)?),
            None => None,
        },
        output: output_file.clone(),
        arch: ctx.arch,
    })?;
    Ok(output_file)
}

/// Build the `etc/veritytab` cpio artifact.
fn build_veritytab_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = veritytab_config(ctx, name)?;
    let entries: Vec<ConfigVeritytabEntry> = match &cfg.entries {
        Some(e) => e.clone(),
        None => ctx
            .config
            .build
            .erofs
            .keys()
            .map(|k| ConfigVeritytabEntry {
                volume: None,
                device: None,
                erofs_config: k.clone(),
            })
            .collect(),
    };

    let mut lines: Vec<String> = Vec::new();
    for entry in &entries {
        ctx.build_artifact(&format!("build:erofs:{}", entry.erofs_config))?;
        let metadata = ctx.get_verity(&entry.erofs_config).ok_or_else(|| {
            Error::msg(format!(
                "No verity metadata for erofs artifact: {}",
                entry.erofs_config
            ))
        })?;
        let device = entry
            .device
            .clone()
            .unwrap_or_else(|| format!("/dev/disk/by-uuid/{}", metadata.uuid));
        let data_blocks = metadata.hash_offset / metadata.data_block_size as u64;
        let options = format!(
            "format=1,hash=sha256,data-blocks={data_blocks},hash-offset={},data-block-size={},hash-block-size={},salt={}",
            metadata.hash_offset, metadata.data_block_size, metadata.hash_block_size, metadata.salt
        );
        let volume = entry
            .volume
            .clone()
            .unwrap_or_else(|| entry.erofs_config.clone());
        lines.push(format!(
            "{volume} {device} {device} {} {options}",
            metadata.root_hash
        ));
    }

    let veritytab_file = ctx.create_temp_file();
    std::fs::write(&veritytab_file, format!("{}\n", lines.join("\n")))?;

    let files: ConfigFilesSet = vec![ConfigFileEntry {
        destination: "etc/veritytab".to_string(),
        input: veritytab_file.to_string_lossy().into_owned(),
        include_pattern: None,
        exclude_patterns: None,
    }];
    build_cpio_artifact(ctx, files, None, None)
}

/// Resolve a `block` artifact config by name.
fn block_config<'a>(
    ctx: &'a BuildContext,
    name: &str,
) -> Result<&'a crate::model::config::ConfigBlock> {
    ctx.config
        .build
        .block
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: block:{name}")))
}

/// Resolve an `efisign` artifact config by name.
fn efisign_config<'a>(ctx: &'a BuildContext, name: &str) -> Result<&'a ConfigArtifactEfiSign> {
    ctx.config
        .build
        .efisign
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: efisign:{name}")))
}

/// Render a named block (`build:block:name`) into a standalone image file at
/// build time.
///
/// Unlike disk blocks — which are only *described* at build time (size
/// computation + content addressing) and rendered at install time — a
/// `build:block:` artifact runs the install fresh-render path *now*, into a
/// temp file, producing a self-contained image (a partitioned disk, a
/// filesystem, a LUKS container, an LVM PV, …) that can be referenced as an
/// input anywhere a `build:` URL is accepted (e.g. an `image` block's
/// `input`).
///
/// The block is first converted to a [`ManifestBlock`] via
/// [`process_block`](super::block::process_block) (which content-addresses all
/// nested archives/images). The fresh install then writes partition tables,
/// formats filesystems and writes LUKS/LVM metadata directly into the temp
/// file. Content-addressed files are resolved back to the build context's temp
/// files via the `file_resolver` override, so nothing is materialized twice.
fn build_block_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = block_config(ctx, name)?;

    // Build-time rendering: FS blocks should store their in-memory tree
    // instead of building an archive, so the mini-install below can write
    // the tree directly into the filesystem — skipping the compress/decompress
    // round-trip.
    let prev_render = ctx.set_build_time_render(true);

    // Convert the config block to a manifest block: this computes sizeMin
    // bottom-up and content-addresses every nested archive/image, recording
    // them in `ctx.file` / `ctx.hash_to_source`.
    let manifest_block = super::block::process_block(ctx, cfg)?;

    // Snapshot the in-memory trees before restoring the flag (nested
    // `build:block:` references may have added more trees).
    let trees = ctx.tree_snapshot();
    ctx.set_build_time_render(prev_render);

    let min_size = crate::install::compute_min_disk_size(&manifest_block);
    if min_size == 0 {
        return Err(Error::msg(format!(
            "build:block:{name} has a zero minimum size; cannot render an empty block"
        )));
    }

    // Create and size the backing file (sparse), then open it as a region.
    let output_file = ctx.create_temp_file();
    {
        use std::fs::OpenOptions;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_file)?;
        f.set_len(min_size)?;
    }
    let mut region = crate::blockfile::BlockFile::open(&output_file, 0, min_size)?;

    // Build a minimal install context carrying just this block's subtree plus
    // the content-addressed files / LVM volume groups it may reference. The
    // `file_resolver` closure resolves hash file names straight back to the
    // build context's temp files (which have not been copied to the output
    // directory yet — that happens in `write_output`).
    let partial_manifest = crate::model::manifest::ManifestBuild {
        schema: None,
        name: ctx.config.name.clone(),
        version: ctx.config.version.clone(),
        arch: ctx.arch.rust.to_string(),
        file: ctx.file_map(),
        disk: std::collections::BTreeMap::new(),
        lvm: ctx.lvm_map(),
        qemu: None,
        netboot: None,
    };
    let mut install_ctx = crate::install::InstallContext::new(
        partial_manifest,
        PathBuf::new(),
        true, // always fresh at build time
        ctx.build_keys.clone(),
    );
    install_ctx.file_resolver = Some(Box::new({
        // Snapshot the hash→source map so the resolver owns its data and the
        // closure is `'static` (no borrow on `ctx`).
        let hash_to_source = ctx.hash_to_source_snapshot();
        move |hash: &str| {
            hash_to_source.get(hash).cloned().ok_or_else(|| {
                Error::msg(format!(
                    "No content-addressed source file for \"{hash}\" in build context"
                ))
            })
        }
    }));
    if !trees.is_empty() {
        install_ctx.tree_resolver = Some(Box::new(move |key: &str| {
            trees
                .get(key)
                .cloned()
                .ok_or_else(|| Error::msg(format!("No in-memory tree for key \"{key}\"")))
        }));
    }

    crate::install::install_block_subtree(&mut install_ctx, &manifest_block, &mut region, true)?;

    Ok(output_file)
}

/// Sign an EFI binary with a Secure Boot key (`build:efisign:<name>`).
///
/// The artifact's `input` resolves to the EFI file to sign. When the artifact's
/// `key` name is present in [`BuildContext::sign_keys`] (i.e. a matching
/// `--sign name=directory` was passed to `sysimage build`), the input is signed
/// with the `db.key` + `db.crt` files from that directory using the pure-Rust
/// Authenticode signer. When no matching
/// signing key was supplied, the unsigned input file is passed through
/// unchanged — so the same config builds with or without signing.
fn build_efisign_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = efisign_config(ctx, name)?;
    let input_path = ctx.resolve_input_path(&cfg.input)?;

    let Some(key_dir) = ctx.sign_keys.get(&cfg.key) else {
        // No signing key supplied for this name — use the unsigned input.
        return Ok(input_path);
    };

    let key_path = key_dir.join("db.key");
    let cert_path = key_dir.join("db.crt");
    if !key_path.exists() {
        return Err(Error::msg(format!(
            "efisign:{name}: signing key \"{}\" was supplied but {} is missing",
            cfg.key,
            key_path.display()
        )));
    }
    if !cert_path.exists() {
        return Err(Error::msg(format!(
            "efisign:{name}: signing key \"{}\" was supplied but {} is missing",
            cfg.key,
            cert_path.display()
        )));
    }

    let key_bytes = std::fs::read(&key_path).map_err(|e| {
        Error::msg(format!(
            "Cannot read signing key {}: {e}",
            key_path.display()
        ))
    })?;
    let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| {
        Error::msg(format!(
            "Cannot read signing cert {}: {e}",
            cert_path.display()
        ))
    })?;

    let passphrase = ctx.sign_key_passphrases.get(&cfg.key).map(Vec::as_slice);
    let key = crate::secboot::x509::load_private_key(&key_bytes, passphrase).map_err(|e| {
        Error::msg(format!(
            "efisign:{name}: cannot load signing key \"{}\": {e}",
            cfg.key
        ))
    })?;
    let cert_der = crate::secboot::x509::cert_pem_to_der(&cert_pem)?;
    let (issuer_der, serial_der) = crate::secboot::x509::parse_issuer_and_serial(&cert_der)?;

    let pe = std::fs::read(&input_path).map_err(|e| {
        Error::msg(format!(
            "Cannot read EFI input {}: {e}",
            input_path.display()
        ))
    })?;
    let signed =
        crate::secboot::authenticode::sign_pe(&pe, &cert_der, &issuer_der, &serial_der, &key)?;

    let output_file = ctx.create_temp_file();
    std::fs::write(&output_file, &signed)?;
    Ok(output_file)
}

/// Resolve an `encrypt` artifact config by name.
fn encrypt_config<'a>(
    ctx: &'a BuildContext,
    name: &str,
) -> Result<&'a crate::model::config::ConfigArtifactEncrypt> {
    ctx.config
        .build
        .encrypt
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: encrypt:{name}")))
}

/// Build an `encrypt` artifact: wrap the plaintext `input` into a
/// device-bound, authenticated-encryption envelope (the "SENC" format; see
/// [`crate::encrypt`]).
///
/// The key is looked up by name in [`BuildContext::build_keys`] (supplied via
/// `sysimage build --key name=…` / `--key-file name=…`). If the named key is
/// not supplied, the build **fails** — the plaintext is never passed through.
///
/// The output is a deterministic SENC envelope: the same input and key always
/// produce byte-identical bytes (the nonce is derived from
/// `HMAC-SHA256(key, plaintext)`), so content-addressed artifact hashes are
/// stable across rebuilds.
fn build_encrypt_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = encrypt_config(ctx, name)?;
    let algorithm = cfg.algorithm.unwrap_or_default();

    // Combine the ordered key components into the 32-byte envelope key.
    let mut key = resolve_envelope_key(ctx, &format!("encrypt:{name}"), &cfg.key)?;

    // Resolve and read the plaintext input (any input specifier).
    let plaintext = ctx.resolve_input_bytes(&cfg.input)?;

    // Encrypt into the SENC envelope.
    let envelope = crate::encrypt::encrypt_envelope(&plaintext, &key, algorithm)?;

    // Zeroize the derived key and the plaintext copy we read into memory.
    key.zeroize();
    let mut plaintext = plaintext;
    plaintext.zeroize();

    let output_file = ctx.create_temp_file();
    std::fs::write(&output_file, &envelope)?;
    Ok(output_file)
}

/// Resolve the ordered key components named by an `encrypt`/`decrypt`/
/// `reencrypt` artifact into the 32-byte SENC envelope key.
///
/// The components are looked up by name in [`BuildContext::build_keys`]
/// (supplied via `sysimage build --key name=…` / `--key-file name=…`) and
/// concatenated **in order**, then combined with HKDF-SHA256. A named component
/// that was not supplied — or an empty component list — is an error, so a
/// missing key never silently passes the input through. `label` (e.g.
/// `"encrypt:cred"` or `"reencrypt:rot (encryptKey)"`) is only used to make the
/// error actionable.
fn resolve_envelope_key(
    ctx: &BuildContext,
    label: &str,
    key: &crate::model::config::ConfigEncryptKey,
) -> Result<[u8; crate::encrypt::KEY_LEN]> {
    let names = key.names();
    if names.is_empty() {
        return Err(Error::msg(format!(
            "{label}: at least one key component is required"
        )));
    }
    let mut components: Vec<&[u8]> = Vec::with_capacity(names.len());
    for key_name in names {
        let bytes = ctx.build_keys.get(key_name).ok_or_else(|| {
            Error::msg(format!(
                "{label}: key \"{key_name}\" was not supplied. \
                 Pass it on the command line with `--key {key_name}=<passphrase>` or \
                 `--key-file {key_name}=<path>`."
            ))
        })?;
        components.push(bytes.as_slice());
    }
    crate::encrypt::derive_key(&components)
}

/// Resolve a `decrypt` artifact config by name.
fn decrypt_config<'a>(
    ctx: &'a BuildContext,
    name: &str,
) -> Result<&'a crate::model::config::ConfigArtifactDecrypt> {
    ctx.config
        .build
        .decrypt
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: decrypt:{name}")))
}

/// Build a `decrypt` artifact: unwrap the SENC envelope `input` back into
/// plaintext (see [`crate::encrypt`]). The inverse of
/// [`build_encrypt_artifact`].
///
/// The key is looked up by name in [`BuildContext::build_keys`] (supplied via
/// `sysimage build --key name=…` / `--key-file name=…`), exactly as for
/// `encrypt`; if a named key is not supplied the build **fails** and the
/// ciphertext is never passed through. The AEAD algorithm is read from the
/// envelope header.
///
/// The plaintext output is content-addressed into the output directory (when
/// reachable) like any other built artifact, so it can feed a later build step.
fn build_decrypt_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = decrypt_config(ctx, name)?;

    // Combine the ordered key components into the 32-byte envelope key.
    let mut key = resolve_envelope_key(ctx, &format!("decrypt:{name}"), &cfg.key)?;

    // Resolve and read the envelope input (any input specifier), then decrypt.
    let mut envelope = ctx.resolve_input_bytes(&cfg.input)?;
    let mut plaintext = crate::encrypt::decrypt_envelope(&envelope, &key)?;

    // Zeroize the derived key and the envelope/plaintext buffers we read into
    // memory. The output copy is written to disk (it is the artifact's whole
    // point) and is therefore not scrubbed.
    key.zeroize();
    envelope.zeroize();

    let output_file = ctx.create_temp_file();
    std::fs::write(&output_file, &plaintext)?;
    plaintext.zeroize();
    Ok(output_file)
}

/// Resolve a `reencrypt` artifact config by name.
fn reencrypt_config<'a>(
    ctx: &'a BuildContext,
    name: &str,
) -> Result<&'a crate::model::config::ConfigArtifactReencrypt> {
    ctx.config
        .build
        .reencrypt
        .get(name)
        .ok_or_else(|| Error::msg(format!("Unknown name of artifact: reencrypt:{name}")))
}

/// Build a `reencrypt` artifact: decrypt the SENC envelope `input` with
/// `decryptKey`'s components and re-encrypt the plaintext under `encryptKey`'s
/// components (see [`crate::encrypt`]). This is `decrypt` followed by `encrypt`
/// in a single step, so the intermediate plaintext is never materialized as a
/// standalone artifact.
///
/// Both key sets are looked up by name in [`BuildContext::build_keys`]
/// (supplied via `sysimage build --key name=…` / `--key-file name=…`); if a
/// named component is not supplied the build **fails** and nothing is passed
/// through. The AEAD algorithm of the input is read from its envelope header;
/// the output uses `algorithm` (default `aes-256-gcm`).
///
/// The output is a SENC envelope under the new key, with the same deterministic
/// nonce scheme as `encrypt`, so it is byte-stable across rebuilds.
fn build_reencrypt_artifact(ctx: &BuildContext, name: &str) -> Result<PathBuf> {
    let cfg = reencrypt_config(ctx, name)?;
    let algorithm = cfg.algorithm.unwrap_or_default();

    // Derive both envelope keys (input-decryption and output-encryption).
    let mut decrypt_key = resolve_envelope_key(
        ctx,
        &format!("reencrypt:{name} (decryptKey)"),
        &cfg.decrypt_key,
    )?;
    let mut encrypt_key = resolve_envelope_key(
        ctx,
        &format!("reencrypt:{name} (encryptKey)"),
        &cfg.encrypt_key,
    )?;

    // Decrypt the input envelope, then re-encrypt the plaintext under the new
    // key. Both key material and the intermediate plaintext are scrubbed.
    let mut envelope = ctx.resolve_input_bytes(&cfg.input)?;
    let mut plaintext = crate::encrypt::decrypt_envelope(&envelope, &decrypt_key)?;
    let new_envelope = crate::encrypt::encrypt_envelope(&plaintext, &encrypt_key, algorithm)?;

    decrypt_key.zeroize();
    encrypt_key.zeroize();
    envelope.zeroize();
    plaintext.zeroize();

    let output_file = ctx.create_temp_file();
    std::fs::write(&output_file, &new_envelope)?;
    Ok(output_file)
}
