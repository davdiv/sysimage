//! The build context: holds the in-progress manifest, memoizes artifact
//! builds, and content-addresses output files.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::Engine;

use crate::arch::ArchInfo;
use crate::config::ExpandedConfigWithDirectories;
use crate::error::{Error, Result};
use crate::hash;
use crate::input::{InputManager, find_one_file_matching};
use crate::manifest::ManifestWithDirectory;
use crate::model::manifest::{ManifestBlock, ManifestBuild, ManifestFile, ManifestLvmVg};
use crate::model::netboot::{ConfigNetbootDhcpMatch, ConfigNetbootDhcpProfile};
use crate::model::qemu::{ConfigQemuFirmware, ConfigQemuInitrd};
use crate::variables::substitute_string;
use crate::{bail_msg, input::ResolvedInput};

/// Encode a list of DHCP option-93 architecture codes as a [`DhcpOptionValue`]:
/// a single code becomes a `u16`, multiple codes become an `array` of `u16`s.
/// Both encode to the same big-endian u16 byte sequence on the wire.
fn arch_codes_value(archs: &[u16]) -> crate::model::netboot::DhcpOptionValue {
    use crate::model::netboot::DhcpOptionValue;
    if archs.len() == 1 {
        DhcpOptionValue::U16 { value: archs[0] }
    } else {
        DhcpOptionValue::Array {
            value: archs
                .iter()
                .map(|&c| DhcpOptionValue::U16 { value: c })
                .collect(),
        }
    }
}

/// Add a vendor-class (option 60) match criterion to a profile's `match`
/// filter, so the preset only answers clients advertising that vendor class.
/// If the profile already has a non-empty `vendor_class` list, the user has
/// made an explicit choice and it is left untouched.
fn add_match_vendor_class(p: &mut ConfigNetbootDhcpProfile, vendor_class: String) {
    let m = p
        .r#match
        .get_or_insert_with(ConfigNetbootDhcpMatch::default);
    if m.vendor_class.is_empty() {
        m.vendor_class.push(vendor_class);
    }
}

/// dm-verity metadata captured while building an EROFS artifact.
#[derive(Debug, Clone)]
pub struct VerityMetadata {
    pub root_hash: String,
    pub hash_offset: u64,
    pub uuid: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    /// Hex-encoded verity salt (lowercase, no `0x` prefix).
    pub salt: String,
}

/// A content-addressed output file: its source path, hash file name, and
/// manifest entry.
#[derive(Clone)]
pub struct OutputFileEntry {
    pub source_file: PathBuf,
    pub hash_file_name: String,
    pub manifest: ManifestFile,
}

/// Memoization states for a build namespace.
enum CacheState<T> {
    InProgress,
    Done(T),
}

/// The build context. All mutation goes through interior mutability so that
/// artifact builders (which recurse via `build:` inputs) can borrow `&self`
/// without conflicting borrows.
pub struct BuildContext {
    pub arch: ArchInfo,
    pub config: crate::model::config::ExpandedConfigBuild,
    pub build_temp_directory: PathBuf,
    pub output_directory: PathBuf,
    pub config_directory: PathBuf,
    pub input_directory: PathBuf,
    pub input_manager: InputManager,
    pub env: BTreeMap<String, String>,
    /// LUKS passphrases for `build:block:` subtrees that contain a `luks`
    /// block, keyed by container name. Supplied at build time via
    /// `sysimage build --key name=…` / `--key-file name=…`.
    pub build_keys: BTreeMap<String, Vec<u8>>,
    /// Signing-key directories for `efisign` build artifacts, keyed by the
    /// name referenced in the artifact's `key` field. Supplied at build time
    /// via `sysimage build --sign name=directory`. Each directory must contain
    /// `db.key` + `db.crt` (as produced by `sbkey-generate`). The same map also
    /// backs `sign:<name>` input URLs (see [`Self::resolve_input`]), which
    /// resolve to the supplied directory — handy for copying auth/certificate
    /// enrollment files into an image. A name not supplied via `--sign` resolves
    /// to an empty directory rather than erroring.
    pub sign_keys: BTreeMap<String, PathBuf>,
    /// Passphrases for SENC-encrypted `db.key` files in [`Self::sign_keys`],
    /// keyed by the same `--sign` name. Supplied at build time via
    /// `sysimage build --sign-key-file name=path`; the file bytes are used
    /// exactly as read (no trailing-newline stripping). A name absent here
    /// means the corresponding `db.key` must be a plaintext PKCS#8 PEM.
    pub sign_key_passphrases: BTreeMap<String, Vec<u8>>,

    /// A single shared empty directory used to resolve `sign:<name>` inputs
    /// whose key was not supplied on the command line (`--sign name=…`).
    /// Lazily created under `build_temp_directory` on first use and reused for
    /// every unsupplied `sign:<name>` — an empty directory is name-agnostic.
    sign_empty_dir: RefCell<Option<PathBuf>>,

    disk: RefCell<BTreeMap<String, ManifestBlock>>,
    file: RefCell<BTreeMap<String, ManifestFile>>,
    lvm: RefCell<BTreeMap<String, ManifestLvmVg>>,
    verity: RefCell<BTreeMap<String, VerityMetadata>>,

    /// Reverse of `file`: hash file name → the source temp file path, so a
    /// build-time block renderer can fetch a content-addressed file's bytes
    /// *before* [`BuildContext::write_output`] copies them to the output
    /// directory as `<hash>.bin`.
    hash_to_source: RefCell<BTreeMap<String, PathBuf>>,

    /// In-memory file trees for `build:block:` FS blocks that skip archive
    /// creation. Keyed by a synthetic `"tree-N"` identifier stored in
    /// [`ManifestBlockFs::tree_key`].
    trees: RefCell<BTreeMap<String, crate::archive::TreeNode>>,

    /// `true` while `process_block` is running inside `build_block_artifact`.
    /// When set, `process_fs` stores the in-memory tree instead of building an
    /// archive, so the build-time mini-install can write it directly into the
    /// filesystem (skipping the compress/decompress round-trip).
    build_time_render: Cell<bool>,

    temp_counter: Cell<u64>,
    tree_counter: Cell<u64>,
    artifact_cache: RefCell<BTreeMap<String, CacheState<PathBuf>>>,
    output_cache: RefCell<BTreeMap<String, CacheState<OutputFileEntry>>>,
    lvm_cache: RefCell<BTreeMap<String, CacheState<ManifestLvmVg>>>,
}

impl BuildContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expanded: ExpandedConfigWithDirectories,
        input_directory: PathBuf,
        build_temp_directory: PathBuf,
        input_manager: InputManager,
        env: BTreeMap<String, String>,
        build_keys: BTreeMap<String, Vec<u8>>,
        sign_keys: BTreeMap<String, PathBuf>,
        sign_key_passphrases: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let arch = expanded.arch;
        let config = expanded.config.clone();
        let output_directory = expanded.output_directory.clone();
        let config_directory = expanded.config_directory.clone();
        BuildContext {
            arch,
            config,
            build_temp_directory,
            output_directory,
            config_directory,
            input_directory,
            input_manager,
            env,
            build_keys,
            sign_keys,
            sign_key_passphrases,
            sign_empty_dir: RefCell::new(None),
            disk: RefCell::new(BTreeMap::new()),
            file: RefCell::new(BTreeMap::new()),
            lvm: RefCell::new(BTreeMap::new()),
            verity: RefCell::new(BTreeMap::new()),
            hash_to_source: RefCell::new(BTreeMap::new()),
            trees: RefCell::new(BTreeMap::new()),
            build_time_render: Cell::new(false),
            temp_counter: Cell::new(0),
            tree_counter: Cell::new(0),
            artifact_cache: RefCell::new(BTreeMap::new()),
            output_cache: RefCell::new(BTreeMap::new()),
            lvm_cache: RefCell::new(BTreeMap::new()),
        }
    }

    /// Substitute `${VAR}` in a string using the build environment.
    pub fn replace_vars(&self, input: &str) -> String {
        substitute_string(input, &|n: &str| self.env.get(n).cloned())
            .unwrap_or_else(|_| input.to_string())
    }

    /// Allocate a unique temporary file path inside the build temp directory.
    pub fn create_temp_file(&self) -> PathBuf {
        let n = self.temp_counter.get() + 1;
        self.temp_counter.set(n);
        self.build_temp_directory.join(format!("temp{n}"))
    }

    /// Return the shared empty directory used to resolve `sign:<name>` inputs
    /// whose name was not supplied via `--sign`. Created lazily under the build
    /// temp directory on first use and reused thereafter.
    fn empty_sign_dir(&self) -> PathBuf {
        if let Some(p) = self.sign_empty_dir.borrow().clone() {
            return p;
        }
        use rand::RngExt;
        let n = hex::encode(rand::rng().random::<[u8; 8]>());
        let dir = self.build_temp_directory.join(format!("sign-empty-{n}"));
        // `create_dir_all` is idempotent; the dir is brand new and empty.
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("cannot create empty sign dir {}: {e}", dir.display()));
        *self.sign_empty_dir.borrow_mut() = Some(dir.clone());
        dir
    }

    /// Returns `true` while `process_block` is running inside a build-time
    /// mini-install (`build_block_artifact`). When set, FS blocks store their
    /// in-memory tree instead of building an archive.
    pub fn is_build_time_render(&self) -> bool {
        self.build_time_render.get()
    }

    /// Set the build-time render flag; returns the previous value so callers
    /// can restore it after their scope.
    pub fn set_build_time_render(&self, val: bool) -> bool {
        let prev = self.build_time_render.get();
        self.build_time_render.set(val);
        prev
    }

    /// Store an in-memory file tree and return a synthetic key that can be
    /// carried in [`ManifestBlockFs::tree_key`] for later retrieval.
    pub fn store_tree(&self, tree: crate::archive::TreeNode) -> String {
        let n = self.tree_counter.get() + 1;
        self.tree_counter.set(n);
        let key = format!("tree-{n}");
        self.trees.borrow_mut().insert(key.clone(), tree);
        key
    }

    /// Take a snapshot of all stored trees (cloned, for passing into the
    /// build-time mini-install's `InstallContext`).
    pub fn tree_snapshot(&self) -> BTreeMap<String, crate::archive::TreeNode> {
        self.trees.borrow().clone()
    }

    /// Resolve an input specifier (with `${VAR}` substitution) to either a local
    /// path or a virtual view obtained by descending into a (possibly nested)
    /// block image or archive via the `in:` scheme.
    ///
    /// - `file:` / `podman:` / `build:` / `sign:` / bare paths →
    ///   [`ResolvedInput::Path`]. `sign:<name>` resolves to the directory
    ///   supplied via `--sign name=directory`, or to a shared empty directory
    ///   when that name was not supplied (no error).
    /// - `in:<source>#<descent>` → a [`ResolvedInput::File`] (a single file
    ///   streamed on demand from inside the nested image) or a
    ///   [`ResolvedInput::Tree`] (a directory tree walked in-memory). No
    ///   intermediate layer is extracted to disk.
    pub fn resolve_input(&self, input: &str) -> Result<ResolvedInput> {
        let replaced = self.replace_vars(input);
        if let Some(rest) = replaced.strip_prefix("in:") {
            // Split on the *last* `#`: the source specifier (e.g. a podman
            // in-image path) may itself contain one `#`, while descent steps
            // never do.
            let (source, descent) = rest
                .rsplit_once('#')
                .ok_or_else(|| Error::msg(format!("`in:` input missing `#descent`: {input}")))?;
            let source_path = self.resolve_input_path_raw(source)?;
            let steps = crate::input::descent::parse_descent(descent)?;
            return crate::input::descent::descend(&source_path, &steps, &self.build_keys);
        }
        Ok(ResolvedInput::Path(self.resolve_input_path_raw(&replaced)?))
    }

    /// Resolve an input specifier to a local filesystem path. This is the
    /// legacy path used by callers that need an actual file on disk; it does
    /// **not** handle `in:` (use [`Self::resolve_input`] for that). `build:`
    /// inputs dispatch to artifact builders.
    fn resolve_input_path_raw(&self, input: &str) -> Result<PathBuf> {
        if let Some(name) = input.strip_prefix("sign:") {
            // `sign:<name>` resolves to the directory supplied via
            // `--sign name=directory`. A name not supplied on the command line
            // resolves to a single shared empty directory (lazily created),
            // so configs that reference enrollment material build
            // successfully even without it — `collect_tree` then copies
            // nothing. No `find_one_file_matching`: this is a controlled
            // directory path, not a glob.
            if let Some(dir) = self.sign_keys.get(name) {
                return Ok(dir.clone());
            }
            return Ok(self.empty_sign_dir());
        }
        if input.starts_with("build:") {
            // The full `build:type:name` URL is what the artifact cache is keyed
            // by; build_artifact expects the full URL including the scheme.
            return self.build_artifact(input);
        }
        let path = self
            .input_manager
            .resolve_input(input, &self.input_directory)?;
        find_one_file_matching(&path)
    }

    /// Resolve an input specifier to a content-addressed output file. A
    /// [`ResolvedInput::File`] (a virtual file inside an image/archive) is
    /// streamed once into the content-addressed output — no extraction of the
    /// intermediate layers. A [`ResolvedInput::Tree`] is rejected (use a files
    /// set for directory trees).
    pub fn resolve_input_file(&self, input: &str) -> Result<OutputFileEntry> {
        match self.resolve_input(input)? {
            ResolvedInput::Path(p) => self.add_output_file(&p),
            ResolvedInput::File(vf) => self.add_output_file_stream(&vf),
            ResolvedInput::Tree(_) => Err(Error::msg(format!(
                "input resolved to a directory tree, not a single file: {input}"
            ))),
        }
    }

    /// Resolve an input specifier to a local filesystem path a consumer can
    /// open. A [`ResolvedInput::File`] is streamed to a temp file (once) and
    /// the temp path returned; a [`ResolvedInput::Tree`] is rejected.
    pub fn resolve_input_path(&self, input: &str) -> Result<PathBuf> {
        match self.resolve_input(input)? {
            ResolvedInput::Path(p) => Ok(p),
            ResolvedInput::File(vf) => {
                let mut r = (vf.open)()?;
                let tmp = self.create_temp_file();
                let mut f = std::fs::File::create(&tmp)
                    .map_err(|e| Error::msg(format!("Cannot create temp {tmp:?}: {e}")))?;
                std::io::copy(&mut r, &mut f)
                    .map_err(|e| Error::msg(format!("Cannot stream input to temp: {e}")))?;
                Ok(tmp)
            }
            ResolvedInput::Tree(_) => Err(Error::msg(format!(
                "input resolved to a directory tree, not a single file: {input}"
            ))),
        }
    }

    /// Resolve an input specifier to its full bytes in memory. Intended for
    /// small files (e.g. bootcode). A [`ResolvedInput::Tree`] is rejected.
    pub fn resolve_input_bytes(&self, input: &str) -> Result<Vec<u8>> {
        match self.resolve_input(input)? {
            ResolvedInput::Path(p) => {
                std::fs::read(&p).map_err(|e| Error::msg(format!("Cannot read {p:?}: {e}")))
            }
            ResolvedInput::File(vf) => {
                use std::io::Read as _;
                let mut r = (vf.open)()?;
                let mut buf = Vec::with_capacity(vf.size as usize);
                r.read_to_end(&mut buf)
                    .map_err(|e| Error::msg(format!("Cannot read input: {e}")))?;
                Ok(buf)
            }
            ResolvedInput::Tree(_) => Err(Error::msg(format!(
                "input resolved to a directory tree, not a single file: {input}"
            ))),
        }
    }

    /// Stream a virtual file into a content-addressed output, reusing the
    /// existing hashing/manifest machinery. If the same content was already
    /// produced (by content hash), the existing entry is returned and the
    /// temp discarded — avoiding duplicate output files.
    fn add_output_file_stream(&self, vf: &crate::input::VirtualFile) -> Result<OutputFileEntry> {
        let tmp = self.create_temp_file();
        {
            let mut r = (vf.open)()?;
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| Error::msg(format!("Cannot create temp {tmp:?}: {e}")))?;
            std::io::copy(&mut r, &mut f)
                .map_err(|e| Error::msg(format!("Cannot stream input to temp: {e}")))?;
        }
        // Hash first, then dedup against any already-recorded content.
        let digest = hash::hash_file(&tmp)?;
        let hash_file_name = format!(
            "{}.bin",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest)
        );
        if let Some(existing_source) = self.hash_to_source.borrow().get(&hash_file_name).cloned() {
            // Same content already recorded — drop our temp and reuse it.
            let _ = std::fs::remove_file(&tmp);
            let manifest = self
                .file
                .borrow()
                .get(&hash_file_name)
                .cloned()
                .ok_or_else(|| Error::msg("hash_to_source/file map inconsistency"))?;
            return Ok(OutputFileEntry {
                source_file: existing_source,
                hash_file_name,
                manifest,
            });
        }
        // New content: record it exactly like `add_output_file`.
        let size = std::fs::metadata(&tmp)?.len();
        let manifest = ManifestFile {
            size,
            hash: hex::encode(&digest),
        };
        self.file
            .borrow_mut()
            .insert(hash_file_name.clone(), manifest.clone());
        self.hash_to_source
            .borrow_mut()
            .insert(hash_file_name.clone(), tmp.clone());
        Ok(OutputFileEntry {
            source_file: tmp,
            hash_file_name,
            manifest,
        })
    }

    /// Resolve the QEMU firmware config: `Bool`/unset variants pass through; a
    /// `Files` variant has its `code`/`vars` input specifiers resolved through
    /// the input manager and recorded as content-addressed output files, and
    /// the resolved hash file names are returned for storage in the manifest.
    fn resolve_qemu_firmware(&self) -> Result<Option<crate::model::qemu::ConfigQemuFirmware>> {
        use crate::model::qemu::{ConfigQemuFirmware, ConfigQemuFirmwareFiles};

        let Some(firmware) = self.config.qemu.firmware.clone() else {
            return Ok(None);
        };
        match firmware {
            ConfigQemuFirmware::Bool(_) => Ok(Some(firmware)),
            ConfigQemuFirmware::Files(f) => {
                let code_entry = self.resolve_input_file(&f.code)?;
                let ventry = self.resolve_input_file(&f.vars)?;
                Ok(Some(ConfigQemuFirmware::Files(ConfigQemuFirmwareFiles {
                    code: code_entry.hash_file_name.clone(),
                    vars: ventry.hash_file_name.clone(),
                })))
            }
        }
    }

    /// Resolve an optional single QEMU input specifier (kernel/shim/dtb) to a
    /// content-addressed output file, returning the hash file name for storage
    /// in the manifest. `None` passes through unchanged.
    fn resolve_qemu_input(&self, input: &Option<String>) -> Result<Option<String>> {
        match input {
            Some(spec) => {
                let entry = self.resolve_input_file(spec)?;
                Ok(Some(entry.hash_file_name.clone()))
            }
            None => Ok(None),
        }
    }

    /// Resolve the QEMU initrd input(s) to a single content-addressed output
    /// file, returning the hash file name for storage in the manifest.
    ///
    /// Multiple inputs are handled like `uki.initrd`: each is resolved through
    /// [`super::artifacts::file_or_cpio_directory`] (so directory inputs become
    /// cpio archives) and concatenated in order with 4-byte alignment padding.
    /// An empty list means no initrd, matching `uki.initrd: []`.
    fn resolve_qemu_initrd(
        &self,
        input: &Option<ConfigQemuInitrd>,
    ) -> Result<Option<ConfigQemuInitrd>> {
        let Some(input) = input else {
            return Ok(None);
        };
        let inputs = input.inputs();
        if inputs.is_empty() {
            return Ok(None);
        }

        let mut files = Vec::with_capacity(inputs.len());
        for spec in inputs {
            files.push(super::artifacts::file_or_cpio_directory(self, spec)?);
        }

        let entry = if let [file] = files.as_slice() {
            self.add_output_file(file)?
        } else {
            let data = crate::ukify::join_initrds(&files)?;
            let tmp = self.create_temp_file();
            std::fs::write(&tmp, &data)?;
            self.add_output_file(&tmp)?
        };
        Ok(Some(ConfigQemuInitrd::One(entry.hash_file_name)))
    }

    /// Resolve the `qemu.disks` map for storage in the manifest.
    ///
    /// Entries whose name matches a manifest disk keep their drive options
    /// unchanged; the sysimage-only `input` key is rejected for them because
    /// those disks are installed into `<name>.img`.
    ///
    /// Entries whose name is *not* a manifest disk are QEMU-only disks: they
    /// must have an `input`, which is resolved to a content-addressed output
    /// file (like `qemu.kernel`/`initrd`). They are attached directly and are
    /// read-only by default, because the backing file is shared and
    /// content-addressed.
    fn resolve_qemu_disks(&self) -> Result<Option<BTreeMap<String, BTreeMap<String, String>>>> {
        let Some(disks) = self.config.qemu.disks.as_ref() else {
            return Ok(None);
        };

        // Snapshot the manifest disk names before resolving inputs: building an
        // artifact can recurse through `self.disk`, so we must not hold the
        // `RefCell` borrow across `resolve_input_file`.
        let manifest_disks: BTreeSet<String> = self.disk.borrow().keys().cloned().collect();
        let mut resolved = BTreeMap::new();

        for (name, options) in disks {
            let mut options = options.clone();
            if manifest_disks.contains(name) {
                if options.contains_key("input") {
                    bail_msg!(
                        "qemu.disks.{name}.input is only valid for disks not declared under disk:"
                    );
                }
                resolved.insert(name.clone(), options);
                continue;
            }

            let input = options.get("input").cloned().ok_or_else(|| {
                Error::msg(format!(
                    "qemu.disks.{name} is a QEMU-only disk (not declared under disk:) and \
                     requires an `input`"
                ))
            })?;
            let entry = self.resolve_input_file(&input)?;
            options.insert("input".to_string(), entry.hash_file_name.clone());

            match options.get("readonly").map(|v| v.to_ascii_lowercase()) {
                Some(value) if matches!(value.as_str(), "off" | "false" | "0" | "no") => {
                    bail_msg!(
                        "qemu.disks.{name}.readonly must not be disabled: QEMU-only disks are \
                         backed by shared content-addressed artifacts"
                    );
                }
                Some(_) => {}
                None => {
                    options.insert("readonly".to_string(), "on".to_string());
                }
            }

            resolved.insert(name.clone(), options);
        }

        Ok(Some(resolved))
    }

    /// Resolve the netboot config (if present) into the form stored in the
    /// manifest:
    ///
    /// - The DHCP `profiles` are expanded: each profile's `pxeBoot`/`httpBoot`
    ///   preset is folded into that profile's `options` map (and the
    ///   `siaddr`/`bootFile` header fields), merging with any explicitly
    ///   configured profile `options` (explicit entries win). The presets are
    ///   then dropped from the manifest.
    /// - As a shorthand, a top-level `pxeBoot`/`httpBoot` (with no `dhcp`
    ///   section) expands into a single profile with a `match` on the
    ///   relevant vendor class (`PXEClient`/`HTTPClient`) so it only answers
    ///   clients booting via that method. Combining a top-level preset with a
    ///   `dhcp` section, or setting both top-level presets, is a build error
    ///   — use `dhcp.profiles` with a `match` per profile to serve multiple
    ///   boot kinds.
    /// - Each TFTP/HTTP `files` value (an input specifier in the config) is
    ///   resolved to a content-addressed output file and replaced by its hash
    ///   file name for storage in the manifest.
    /// - Each of `dhcp`/`tftp`/`http` is independently optional; a missing
    ///   sub-section is passed through as `None` and that server is not started.
    ///
    /// No `${VAR}` substitution runs here, so `${NETBOOT_IP}` (resolved at
    /// `sysimage netboot` time) survives into the manifest verbatim.
    fn resolve_netboot(&self) -> Result<Option<crate::model::netboot::ConfigNetboot>> {
        use crate::model::netboot::{
            ConfigNetboot, ConfigNetbootDhcp, ConfigNetbootDhcpProfile, ConfigNetbootHttp,
            ConfigNetbootHttpBoot, ConfigNetbootPxeBoot, ConfigNetbootTftp, DhcpOptionValue,
        };

        let Some(netboot) = self.config.netboot.clone() else {
            return Ok(None);
        };

        let resolve_files = |files: &BTreeMap<String, String>| -> Result<BTreeMap<String, String>> {
            let mut out = BTreeMap::new();
            for (name, spec) in files {
                let entry = self.resolve_input_file(spec)?;
                out.insert(name.clone(), entry.hash_file_name.clone());
            }
            Ok(out)
        };

        let tftp = netboot
            .tftp
            .map(|t| -> Result<ConfigNetbootTftp> {
                Ok(ConfigNetbootTftp {
                    listen: t.listen,
                    files: resolve_files(&t.files)?,
                })
            })
            .transpose()?;
        let http = netboot
            .http
            .map(|h| -> Result<ConfigNetbootHttp> {
                Ok(ConfigNetbootHttp {
                    listen: h.listen,
                    files: resolve_files(&h.files)?,
                })
            })
            .transpose()?;

        // Fold a pxeBoot preset into a profile (explicit profile fields win).
        let expand_pxe = |p: &mut ConfigNetbootDhcpProfile, preset: &ConfigNetbootPxeBoot| {
            let vendor_class = preset
                .vendor_class
                .clone()
                .unwrap_or_else(|| "PXEClient".to_string());
            // Only answer PXE clients (option 60 = "PXEClient…"). If the
            // profile already has a vendor_class filter, respect the user's
            // explicit choice.
            add_match_vendor_class(p, vendor_class.clone());

            // siaddr (next-server) — only set when the preset explicitly
            // provides one; otherwise build_proxy_dhcp_reply defaults it to
            // the server's own IP at runtime.
            if p.siaddr.is_none()
                && let Some(next_server) = preset.next_server.clone()
            {
                p.siaddr = Some(next_server.clone());
            }
            if p.boot_file.is_none() {
                p.boot_file = Some(preset.boot_file.clone());
            }
            // Option 60 (vendor class) — default "PXEClient".
            p.options
                .entry("60".to_string())
                .or_insert_with(|| DhcpOptionValue::String {
                    value: vendor_class,
                });
            // Option 66 (TFTP server name) — defaults to ${NETBOOT_IP}.
            p.options
                .entry("66".to_string())
                .or_insert_with(|| DhcpOptionValue::String {
                    value: preset
                        .next_server
                        .clone()
                        .unwrap_or_else(|| "${NETBOOT_IP}".to_string()),
                });
            // Option 67 (bootfile name).
            p.options
                .entry("67".to_string())
                .or_insert_with(|| DhcpOptionValue::String {
                    value: preset.boot_file.clone(),
                });
            // Option 93 (client architecture) — only if non-empty.
            if !preset.architectures.is_empty() {
                p.options
                    .entry("93".to_string())
                    .or_insert_with(|| arch_codes_value(&preset.architectures));
            }
        };

        // Fold an httpBoot preset into a profile.
        let expand_http = |p: &mut ConfigNetbootDhcpProfile, preset: &ConfigNetbootHttpBoot| {
            // Only answer UEFI HTTP-boot clients (option 60 = "HTTPClient…").
            // If the profile already has a vendor_class filter, respect the
            // user's explicit choice.
            add_match_vendor_class(p, "HTTPClient".to_string());

            // siaddr (next-server) is defaulted to the server's own IP at
            // runtime by build_proxy_dhcp_reply, so no need to set it here.
            // UEFI HTTP boot: option 60 = "HTTPClient".
            p.options
                .entry("60".to_string())
                .or_insert_with(|| DhcpOptionValue::String {
                    value: "HTTPClient".to_string(),
                });
            // Boot URL in the `file` header field. EDK2's HttpBootDxe reads
            // the boot URI from option 67, falling back to the `file`
            // header field (RFC 2132 §9.5). The field is 128 bytes; the
            // builder null-terminates at 127, so URLs longer than that are
            // truncated here but still delivered in full via option 67.
            if p.boot_file.is_none() {
                p.boot_file = Some(preset.boot_url.clone());
            }
            // Option 67 (bootfile name) = boot URL. This is the primary
            // delivery path for EDK2's HTTP boot: HttpBootParseDhcp4Packet
            // checks option 67 first, then the `file` header. Without
            // either, it rejects the offer as EFI_DEVICE_ERROR.
            p.options
                .entry("67".to_string())
                .or_insert_with(|| DhcpOptionValue::String {
                    value: preset.boot_url.clone(),
                });
            // Option 93 (client architecture) — only if non-empty.
            if !preset.architectures.is_empty() {
                p.options
                    .entry("93".to_string())
                    .or_insert_with(|| arch_codes_value(&preset.architectures));
            }
        };

        // Build the DHCP section from the explicit `dhcp` config, expanding
        // per-profile presets.
        let dhcp = match netboot.dhcp {
            Some(d) => {
                if d.profiles.is_empty() {
                    bail_msg!("netboot: `dhcp.profiles` must contain at least one profile");
                }
                let mut profiles = d.profiles;
                for p in profiles.iter_mut() {
                    if p.pxe_boot.is_some() && p.http_boot.is_some() {
                        bail_msg!(
                            "netboot: a dhcp profile may set at most one of pxeBoot/httpBoot"
                        );
                    }
                    if let Some(preset) = p.pxe_boot.take() {
                        expand_pxe(p, &preset);
                    }
                    if let Some(preset) = p.http_boot.take() {
                        expand_http(p, &preset);
                    }
                }
                Some(ConfigNetbootDhcp {
                    listen: d.listen,
                    profiles,
                })
            }
            None => None,
        };

        Ok(Some(ConfigNetboot { dhcp, tftp, http }))
    }
    /// Build (and memoize) the artifact referenced by a `build:type:name` URL.
    pub fn build_artifact(&self, url: &str) -> Result<PathBuf> {
        self.ensure(&self.artifact_cache, url, |ctx, name| {
            super::artifacts::build_artifact(ctx, name)
        })
    }

    /// Record a built file as a content-addressed output (memoized by source
    /// path). Returns the output entry.
    pub fn add_output_file(&self, file: &Path) -> Result<OutputFileEntry> {
        let key = file.to_string_lossy().into_owned();
        self.ensure(&self.output_cache, &key, |ctx, name| {
            let file = Path::new(name);
            let digest = hash::hash_file(file)?;
            let size = std::fs::metadata(file)?.len();
            let hash_file_name = format!(
                "{}.bin",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest)
            );
            let manifest = ManifestFile {
                size,
                hash: hex::encode(&digest),
            };
            ctx.file
                .borrow_mut()
                .insert(hash_file_name.clone(), manifest.clone());
            ctx.hash_to_source
                .borrow_mut()
                .insert(hash_file_name.clone(), file.to_path_buf());
            Ok(OutputFileEntry {
                source_file: file.to_path_buf(),
                hash_file_name,
                manifest,
            })
        })
    }

    /// Build (and memoize) an LVM volume group's manifest.
    pub fn ensure_lvm(&self, vg: &str) -> Result<ManifestLvmVg> {
        self.ensure(&self.lvm_cache, vg, |ctx, name| {
            super::block::process_lvm(ctx, name)
        })
    }

    /// Generic memoization with a recursion guard. The cache borrow is
    /// released before `f` runs, so `f` may recurse into any namespace.
    fn ensure<T: Clone, F>(
        &self,
        cache: &RefCell<BTreeMap<String, CacheState<T>>>,
        name: &str,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce(&BuildContext, &str) -> Result<T>,
    {
        {
            let mut c = cache.borrow_mut();
            if let Some(state) = c.get(name) {
                return match state {
                    CacheState::InProgress => {
                        Err(Error::msg(format!("Recursive or failed build of {name}")))
                    }
                    CacheState::Done(t) => return Ok(t.clone()),
                };
            }
            c.insert(name.to_string(), CacheState::InProgress);
        }
        let result = f(self, name)?;
        cache
            .borrow_mut()
            .insert(name.to_string(), CacheState::Done(result.clone()));
        Ok(result)
    }

    /// Record verity metadata for an EROFS artifact name.
    pub fn set_verity(&self, name: &str, meta: VerityMetadata) {
        self.verity.borrow_mut().insert(name.to_string(), meta);
    }

    /// Store a disk's manifest block.
    pub fn set_disk(&self, name: &str, block: ManifestBlock) {
        self.disk.borrow_mut().insert(name.to_string(), block);
    }

    /// Store an LVM volume group manifest (called by `process_lvm`).
    pub fn set_lvm(&self, vg: &str, manifest: ManifestLvmVg) {
        self.lvm.borrow_mut().insert(vg.to_string(), manifest);
    }

    /// Look up verity metadata for an EROFS artifact name.
    pub fn get_verity(&self, name: &str) -> Option<VerityMetadata> {
        self.verity.borrow().get(name).cloned()
    }

    /// Look up a built output file's manifest entry by hash file name.
    pub fn file_manifest(&self, hash_file_name: &str) -> Option<ManifestFile> {
        self.file.borrow().get(hash_file_name).cloned()
    }

    /// Look up the source temp file backing a content-addressed output, by hash
    /// file name. Returns `None` if the hash is unknown to this context.
    pub fn source_for_hash(&self, hash_file_name: &str) -> Option<PathBuf> {
        self.hash_to_source.borrow().get(hash_file_name).cloned()
    }

    /// Snapshot of the content-addressed file map (hash file name → manifest).
    pub(crate) fn file_map(&self) -> std::collections::BTreeMap<String, ManifestFile> {
        self.file.borrow().clone()
    }

    /// Snapshot of the LVM volume-group manifest map.
    pub(crate) fn lvm_map(&self) -> std::collections::BTreeMap<String, ManifestLvmVg> {
        self.lvm.borrow().clone()
    }

    /// Snapshot of the hash file name → source temp file map.
    pub(crate) fn hash_to_source_snapshot(&self) -> std::collections::BTreeMap<String, PathBuf> {
        self.hash_to_source.borrow().clone()
    }

    /// Write all output files to the output directory and emit the manifest.
    pub fn write_output(&self) -> Result<ManifestWithDirectory> {
        let output_directory = self.output_directory.clone();
        let build_temp_directory = self.build_temp_directory.clone();

        // Resolve explicit QEMU firmware inputs (if any) to content-addressed
        // output files before copying outputs, so the firmware files are
        // included in the output set and recorded in the manifest.
        let firmware = self.resolve_qemu_firmware()?;
        // Resolve explicit QEMU kernel/shim/dtb inputs (if any) to
        // content-addressed output files, the same way as firmware.
        let kernel = self.resolve_qemu_input(&self.config.qemu.kernel)?;
        let shim = self.resolve_qemu_input(&self.config.qemu.shim)?;
        // Initrds may be a list; they are concatenated into one output file.
        let initrd = self.resolve_qemu_initrd(&self.config.qemu.initrd)?;
        let dtb = self.resolve_qemu_input(&self.config.qemu.dtb)?;
        // Resolve QEMU-only disks (entries without a matching manifest disk).
        let qemu_disks = self.resolve_qemu_disks()?;
        // Resolve netboot TFTP/HTTP file inputs (if any) to content-addressed
        // output files before copying outputs, so the netboot files are
        // included in the output set and recorded in the manifest.
        let netboot = self.resolve_netboot()?;

        let mut qemu = self.config.qemu.clone();
        qemu.firmware = firmware;
        qemu.kernel = kernel;
        qemu.shim = shim;
        qemu.initrd = initrd;
        qemu.dtb = dtb;
        qemu.disks = qemu_disks;

        // Build the manifest with the *full* file/lvm maps (so build-time
        // resolution via `file_resolver` / `hash_to_source` still sees every
        // built artifact), then compute which files/volume-groups are actually
        // reachable from the manifest's external roots (top-level disks, QEMU,
        // netboot). Only the reachable subset is materialized into the output
        // directory and recorded in the serialized manifest; build-internal
        // artifacts (only referenced from `build:block:` subtrees, which are not
        // serialized) stay in the temp directory and out of the manifest.
        let manifest = ManifestBuild {
            schema: Some(crate::model::schema::MANIFEST_SCHEMA_FILE.to_string()),
            name: self.config.name.clone(),
            version: self.config.version.clone(),
            arch: self.arch.rust.to_string(),
            file: self.file.borrow().clone(),
            disk: self.disk.borrow().clone(),
            lvm: self.lvm.borrow().clone(),
            qemu: Some(qemu),
            netboot,
        };
        let (reachable_files, reachable_vgs) = collect_reachable(&manifest);

        // Materialize only the reachable content-addressed files into the
        // output directory. Non-reachable artifacts built into the temp dir are
        // deleted (they are build-internal); non-reachable local input files
        // are simply not copied.
        for state in self.output_cache.borrow().values() {
            if let CacheState::Done(entry) = state {
                if !reachable_files.contains(&entry.hash_file_name) {
                    if entry.source_file.starts_with(&build_temp_directory) {
                        let _ = std::fs::remove_file(&entry.source_file);
                    }
                    continue;
                }
                let destination = output_directory.join(&entry.hash_file_name);
                if entry.source_file.starts_with(&build_temp_directory) {
                    std::fs::rename(&entry.source_file, &destination)?;
                } else {
                    std::fs::copy(&entry.source_file, &destination)?;
                }
            }
        }

        // Emit the manifest schema next to the manifest so its `$schema`
        // reference resolves for consumers (install / editors).
        let schema_json = serde_json::to_string_pretty(&crate::model::schema::manifest_schema())?;
        std::fs::write(
            output_directory.join(crate::model::schema::MANIFEST_SCHEMA_FILE),
            &schema_json,
        )?;

        // Filter the file/lvm maps down to the reachable subset for the
        // serialized manifest.
        let mut manifest = manifest;
        manifest
            .file
            .retain(|hash, _| reachable_files.contains(hash));
        manifest.lvm.retain(|vg, _| reachable_vgs.contains(vg));

        let str_manifest = serde_json::to_string(&manifest)?;
        let manifest_hash = hash::hash_content(&[str_manifest.as_bytes()]);
        let manifest_file_name = format!(
            "{}-{}.json",
            self.config.name,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&manifest_hash[..8])
        );
        std::fs::write(output_directory.join(&manifest_file_name), &str_manifest)?;
        Ok(ManifestWithDirectory {
            manifest,
            manifest_directory: output_directory,
            manifest_file_name,
        })
    }
}

/// Collect the content-addressed file hashes and LVM volume-group names
/// reachable from the manifest's external roots: top-level disks, the QEMU
/// firmware/kernel/initrd/dtb inputs, QEMU-only disks, and the netboot
/// TFTP/HTTP files.
///
/// Build-internal artifacts (only referenced from `build:block:` subtrees,
/// which are not part of the manifest) are not reachable here and so are
/// neither copied to the output directory nor recorded in the serialized
/// manifest `file`/`lvm` maps.
pub(crate) fn collect_reachable(manifest: &ManifestBuild) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut files = BTreeSet::new();
    let mut vgs = BTreeSet::new();

    for block in manifest.disk.values() {
        walk_block(block, manifest, &mut files, &mut vgs);
    }

    if let Some(q) = &manifest.qemu {
        if let Some(ConfigQemuFirmware::Files(f)) = &q.firmware {
            files.insert(f.code.clone());
            files.insert(f.vars.clone());
        }
        for h in [&q.kernel, &q.shim, &q.dtb].into_iter().flatten() {
            files.insert(h.clone());
        }
        if let Some(initrd) = &q.initrd {
            for h in initrd.inputs() {
                files.insert(h.clone());
            }
        }
        if let Some(disks) = &q.disks {
            for options in disks.values() {
                if let Some(hash) = options.get("input") {
                    files.insert(hash.clone());
                }
            }
        }
    }

    if let Some(n) = &manifest.netboot {
        if let Some(t) = &n.tftp {
            for h in t.files.values() {
                files.insert(h.clone());
            }
        }
        if let Some(http) = &n.http {
            for h in http.files.values() {
                files.insert(h.clone());
            }
        }
    }

    (files, vgs)
}

/// Recursively walk a manifest block, adding every reachable content-addressed
/// file hash to `files` and every reachable LVM volume-group name to `vgs`.
/// Volume-group names are visited at most once (the `vgs` set doubles as the
/// visited set), preventing infinite recursion through nested VGs.
fn walk_block(
    block: &ManifestBlock,
    manifest: &ManifestBuild,
    files: &mut BTreeSet<String>,
    vgs: &mut BTreeSet<String>,
) {
    match block {
        ManifestBlock::Gpt(g) => {
            if let Some(b) = &g.bootcode {
                files.insert(b.clone());
            }
            for p in &g.partitions {
                if let Some(c) = &p.content {
                    walk_block(c, manifest, files, vgs);
                }
            }
        }
        ManifestBlock::Mbr(m) => {
            if let Some(b) = &m.bootcode {
                files.insert(b.clone());
            }
            for p in &m.partitions {
                if let Some(c) = &p.content {
                    walk_block(c, manifest, files, vgs);
                }
            }
        }
        ManifestBlock::Ext4(fs) | ManifestBlock::Fat(fs) => {
            if let Some(a) = &fs.archive {
                files.insert(a.file.clone());
            }
        }
        ManifestBlock::Luks(l) => {
            if let Some(c) = &l.content {
                walk_block(c, manifest, files, vgs);
            }
        }
        ManifestBlock::Lvm(v) => {
            if let Some(name) = &v.vg {
                // `insert` returns true only the first time, so each VG is
                // walked once — preventing cycles through nested VGs.
                if vgs.insert(name.clone())
                    && let Some(vg) = manifest.lvm.get(name)
                {
                    for p in &vg.partitions {
                        if let Some(c) = &p.content {
                            walk_block(c, manifest, files, vgs);
                        }
                    }
                }
            }
        }
        ManifestBlock::Image(i) => {
            files.insert(i.file.clone());
        }
    }
}
