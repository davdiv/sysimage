//! Input resolution.
//!
//! Resolves `file:`, `podman:` and `podman+build:` inputs to a filesystem
//! path. `build:` inputs are handled by the build context (which can dispatch
//! to artifact builders), so this manager does not need a build callback.
//!
//! The `in:` scheme — referencing files deep inside a (possibly nested) block
//! image or archive — is implemented in [`descent`] and dispatched by the
//! build context, which owns the artifact builders and LUKS keys.
//!
//! # `podman+build:` URLs
//!
//! A `podman+build:` input is a small URL: the build context (a local
//! directory, resolved relative to the config directory like other inputs)
//! followed by an optional query of build arguments and an optional `#`
//! fragment naming a path inside the built image:
//!
//! ```text
//! podman+build:<context>[?<key>=<value>&…][#<in-image-path>]
//! ```
//!
//! Every query parameter is forwarded to `podman build` as a `--build-arg`,
//! so `podman+build:${CONFIGDIR}/container?REL=42&DEBUG#etc/os-release` runs
//! `podman build … --build-arg REL=42 --build-arg DEBUG` and then resolves
//! `etc/os-release` inside the mounted image. A bare `<key>` (no `=`) is passed
//! through unchanged, letting podman take the value from its environment.
//! Because `&`, `#` and `=` are structural, a value containing one must be
//! percent-encoded (`%26`, `%23`, `%3D`); escapes are decoded before use.

pub mod descent;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::arch::ArchInfo;
use crate::error::{Error, Result};
use crate::exec;
use crate::url::percent_decode;

pub use descent::{ReadSeek, ResolvedInput, VirtualFile, VirtualTree, descend, parse_descent};

use crate::model::config::ConfigFilesSet;

/// Resolve a files set whose entries reference only local filesystem paths
/// (`file:` / bare paths). `build:`, `podman:` and `in:` inputs are rejected —
/// those need a [`crate::build::BuildContext`]. Intended for tests and simple
/// callers that don't run a full build pipeline.
pub fn resolve_files_set_paths(
    files: &ConfigFilesSet,
    base_dir: &Path,
) -> Result<ResolvedFilesSet> {
    let mut out: ResolvedFilesSet = Vec::with_capacity(files.len());
    for entry in files {
        let input: &str = &entry.input;
        if input.starts_with("build:") || input.starts_with("podman") || input.starts_with("in:") {
            return Err(Error::msg(format!(
                "resolve_files_set_paths only handles local `file:`/bare-path inputs, got: {input}"
            )));
        }
        let stripped = input.strip_prefix("file://").unwrap_or(input);
        let stripped = stripped.strip_prefix("file:").unwrap_or(stripped);
        out.push(ResolvedFileEntry {
            destination: entry.destination.clone(),
            source: ResolvedSource::Path(base_dir.join(stripped)),
            include_pattern: entry.include_pattern.clone(),
            exclude_patterns: entry.exclude_patterns.clone(),
        });
    }
    Ok(out)
}

/// The concrete source backing one entry of a resolved files set.
pub enum ResolvedSource {
    /// A real path on the local filesystem.
    Path(PathBuf),
    /// A single virtual file streamed from inside a (nested) image/archive.
    File(VirtualFile),
    /// A directory tree walked from inside a (nested) image/archive.
    Tree(VirtualTree),
}

/// One entry of a [`ResolvedFilesSet`]: a destination and its resolved source,
/// plus optional include/exclude globs (applied relative to the source root).
pub struct ResolvedFileEntry {
    pub destination: String,
    pub source: ResolvedSource,
    pub include_pattern: Option<Vec<String>>,
    pub exclude_patterns: Option<Vec<String>>,
}

/// A files set after its inputs have been resolved (paths, virtual files, or
/// virtual trees). Ready to be passed to [`crate::archive::collect_tree`] /
/// [`crate::archive::build_archive`] / [`crate::archive::compute_content_sizes`].
pub type ResolvedFilesSet = Vec<ResolvedFileEntry>;

/// Resolves non-`build:` input specifiers to filesystem paths.
pub struct InputManager {
    pub arch: ArchInfo,
    podman_mounts: Mutex<Vec<String>>,
}

impl InputManager {
    /// Create a new manager for the given target architecture.
    pub fn new(arch: ArchInfo) -> Self {
        Self {
            arch,
            podman_mounts: Mutex::new(Vec::new()),
        }
    }

    /// Resolve `input` relative to `base_dir` (a resolved absolute directory).
    /// `build:` inputs are not handled here — the caller resolves them.
    pub fn resolve_input(&self, input: &str, base_dir: &Path) -> Result<PathBuf> {
        if input.starts_with("build:") {
            return Err(Error::msg(format!(
                "build: URLs must be resolved by the build context, not the input manager: {input}"
            )));
        }
        if let Some(rest) = input.strip_prefix("podman+build:") {
            let spec = parse_podman_build(rest, base_dir);
            let mount = self.build_and_mount_podman(&spec.context, &spec.build_args)?;
            return Ok(join_in_image(&mount, &spec.in_image));
        }
        if let Some(rest) = input.strip_prefix("podman:") {
            let (image, in_image) = split_fragment(rest);
            let image = image.trim_start_matches("//");
            let mount = self.mount_podman(image)?;
            return Ok(join_in_image(&mount, &in_image));
        }
        let stripped = input.strip_prefix("file://").unwrap_or(input);
        let stripped = stripped.strip_prefix("file:").unwrap_or(stripped);
        Ok(base_dir.join(stripped))
    }

    /// Unmount any podman images mounted during this session.
    pub fn dispose(&self) -> Result<()> {
        let mut mounts = self.podman_mounts.lock().unwrap();
        if mounts.is_empty() {
            return Ok(());
        }
        let mut args = vec![
            "podman".to_string(),
            "image".to_string(),
            "unmount".to_string(),
        ];
        for m in mounts.drain(..) {
            args.push(m);
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        exec::exec(&refs)?;
        Ok(())
    }

    fn build_and_mount_podman(&self, build_path: &Path, build_args: &[String]) -> Result<PathBuf> {
        use rand::RngExt;
        let tag = format!(
            "localhost/{}:latest",
            hex::encode(rand::rng().random::<[u8; 8]>())
        );
        let mut argv = vec!["podman".to_string()];
        argv.extend(podman_build_argv(
            self.arch.oci,
            &tag,
            build_path,
            build_args,
        ));
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        exec::exec(&refs)?;
        let image_id = exec::exec(&["podman", "image", "inspect", &tag, "--format", "{{.ID}}"])?;
        let _ = exec::exec(&["podman", "image", "untag", &tag, &tag]);
        self.mount_podman(&image_id)
    }

    fn mount_podman(&self, image: &str) -> Result<PathBuf> {
        let out = exec::exec(&["podman", "image", "mount", image])?;
        let mut mounts = self.podman_mounts.lock().unwrap();
        if !mounts.iter().any(|m| m == image) {
            mounts.push(image.to_string());
        }
        Ok(PathBuf::from(out.trim()))
    }
}

/// A parsed `podman+build:` input URL (see the module docs).
#[derive(Debug, PartialEq, Eq)]
struct PodmanBuild {
    /// Local build context directory, resolved against the config directory.
    context: PathBuf,
    /// `--build-arg` operands (`KEY=VALUE`, or a bare `KEY`).
    build_args: Vec<String>,
    /// Path inside the built image (`.` for the mount root).
    in_image: String,
}

/// Parse a `podman+build:` body of the form
/// `<context>[?<key>=<value>&…][#<in-image>]`.
fn parse_podman_build(rest: &str, base_dir: &Path) -> PodmanBuild {
    // `#` terminates the URL (the in-image path), `?` starts the build-arg
    // query — in that order, so a `#` inside the query must be `%23`-encoded.
    let (main, in_image) = split_fragment(rest);
    let (context, query) = match main.split_once('?') {
        Some((c, q)) => (c, Some(q)),
        None => (main.as_str(), None),
    };
    PodmanBuild {
        context: resolve_podman_path(context, base_dir),
        build_args: query.map(parse_build_args).unwrap_or_default(),
        in_image,
    }
}

/// Turn a `podman+build:` query string into `--build-arg` operands. Each
/// `key=value` pair is split on the *first* `=`, so values may themselves
/// contain `=`; a key with no `=` is kept bare (podman then reads the value
/// from its environment). Keys and values are percent-decoded.
fn parse_build_args(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => {
                format!("{}={}", percent_decode(key), percent_decode(value))
            }
            None => percent_decode(pair),
        })
        .collect()
}

fn split_fragment(body: &str) -> (String, String) {
    match body.split_once('#') {
        Some((main, path)) => (
            main.to_string(),
            if path.is_empty() {
                ".".into()
            } else {
                path.to_string()
            },
        ),
        None => (body.to_string(), ".".to_string()),
    }
}

/// Resolve a `podman+build:` context to a local path: a `//`-prefixed context
/// is absolute (with the leading slash restored), anything else is relative to
/// the config's input directory.
fn resolve_podman_path(rest: &str, base_dir: &Path) -> PathBuf {
    if let Some(x) = rest.strip_prefix("//") {
        if x.starts_with('/') {
            PathBuf::from(x)
        } else {
            PathBuf::from(format!("/{x}"))
        }
    } else {
        base_dir.join(rest)
    }
}

/// The argv for `podman build` (without the leading `podman`): the target arch,
/// one `--build-arg` per build argument, a temporary tag, then the context.
fn podman_build_argv(arch: &str, tag: &str, context: &Path, build_args: &[String]) -> Vec<String> {
    let mut argv = vec!["build".to_string(), "--arch".to_string(), arch.to_string()];
    for arg in build_args {
        argv.push("--build-arg".to_string());
        argv.push(arg.clone());
    }
    argv.push("-t".to_string());
    argv.push(tag.to_string());
    argv.push(context.to_string_lossy().into_owned());
    argv
}

fn join_in_image(mount: &Path, in_image: &str) -> PathBuf {
    if in_image == "." {
        mount.to_path_buf()
    } else {
        mount.join(in_image)
    }
}

/// Glob a pattern (possibly containing shell glob chars) and require exactly
/// one match. A plain existing path (no globs) matches itself.
pub fn find_one_file_matching(pattern: &Path) -> Result<PathBuf> {
    let s = pattern.to_string_lossy();
    let pat = s.replace('\\', "/");
    let globs: Vec<PathBuf> = match glob::glob(&pat) {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    if globs.len() == 1 {
        return Ok(globs[0].clone());
    }
    if globs.is_empty() && pattern.exists() {
        return Ok(pattern.to_path_buf());
    }
    Err(Error::msg(format!(
        "Expected one file matching {pat}, found {}.",
        globs.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_build_args_and_in_image() {
        let spec = parse_podman_build(
            "ctx?REL=42&DEBUG&C=qux%20quux#etc/os-release",
            Path::new("/base"),
        );
        assert_eq!(spec.context, Path::new("/base").join("ctx"));
        assert_eq!(
            spec.build_args,
            vec![
                "REL=42".to_string(),
                "DEBUG".to_string(),
                "C=qux quux".to_string()
            ]
        );
        assert_eq!(spec.in_image, "etc/os-release");
    }

    #[test]
    fn context_only_has_no_args_and_root_in_image() {
        let spec = parse_podman_build("${CONFIGDIR}/container", Path::new("/base"));
        assert_eq!(spec.build_args, Vec::<String>::new());
        assert_eq!(spec.in_image, ".");
    }

    #[test]
    fn keeps_only_the_first_equals_and_explicit_empty_values() {
        let spec = parse_podman_build("ctx?TOKEN=YQ==&EMPTY=", Path::new("/base"));
        assert_eq!(
            spec.build_args,
            vec!["TOKEN=YQ==".to_string(), "EMPTY=".to_string()]
        );
    }

    #[test]
    fn decodes_escaped_separators() {
        let spec = parse_podman_build("ctx?A=a%26b%3Dc%23d", Path::new("/base"));
        assert_eq!(spec.build_args, vec!["A=a&b=c#d".to_string()]);
    }

    #[test]
    fn double_slash_context_is_absolute() {
        let spec = parse_podman_build("//srv/container?A=1", Path::new("/base"));
        assert_eq!(spec.context, Path::new("/srv/container"));
    }

    #[test]
    fn podman_build_argv_places_build_args_before_tag() {
        let argv = podman_build_argv(
            "amd64",
            "localhost/abc:latest",
            Path::new("/ctx"),
            &["A=1".to_string(), "B".to_string()],
        );
        assert_eq!(
            argv,
            vec![
                "build",
                "--arch",
                "amd64",
                "--build-arg",
                "A=1",
                "--build-arg",
                "B",
                "-t",
                "localhost/abc:latest",
                "/ctx",
            ]
        );
    }
}
