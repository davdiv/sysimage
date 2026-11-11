//! Shared helpers for the `tests/` integration-test crates.
//!
//! Many integration tests exercise interop with external tools
//! (`fsck.erofs`, `dump.erofs`, `veritysetup`, `cryptsetup`, `pvck`,
//! `qemu-nbd`, `sbsign`/`sbverify`, …). These tools are not installed in every
//! environment a developer might run `cargo test` in.
//!
//! Historically the test suite handled this inconsistently: some tests
//! silently skipped their external-tool checks (so a missing tool went
//! unnoticed), others *hard-failed* when the tool was absent (e.g. the EROFS
//! tests calling `fsck.erofs`), and each test file reimplemented its own
//! `*_available()` probe. This module provides a single, explicit mechanism
//! for declaring a test's external dependencies: the `skip_if_missing!` macro.
//! A test that depends on one or more external tools starts with
//!
//! ```ignore
//! mod common;
//!
//! #[test]
//! fn something() {
//!     skip_if_missing!("fsck.erofs", "dump.erofs");
//!     // … the actual test body, which may now assume both tools exist …
//! }
//! ```
//!
//! When any named tool is not on `PATH`, `skip_if_missing!` prints an explicit
//! `"<tools> not available — skipping test"` notice to stderr and returns from
//! the enclosing function — so the skip is *visible* in test output rather
//! than silent. Tests that only *optionally* validate against an external
//! tool (the validation is a bonus, not the point of the test) should instead
//! branch on [`has_tool`] so the rest of the test still runs.

use std::process::{Command, Stdio};

/// Build a minimal, structurally-valid PE32 binary in memory.
///
/// This is a hermetic stand-in for a real `.efi` application: it has a DOS
/// header, a PE signature, a COFF file header, a PE32 optional header with all
/// 16 data directories (the Security directory zeroed, as for an unsigned
/// image), and one `.text` section with a small payload. It is sufficient for
/// `sysimage::secboot::authenticode::sign_pe` / `pe_image_hash` (which only
/// parse the PE structure) and for `sbsign` / `sbverify`, both of which operate
/// on any well-formed PE — so tests need no sample `.efi` from outside the
/// repository.
#[allow(dead_code)] // Used only by the test targets that exercise PE handling.
pub fn synthetic_pe() -> Vec<u8> {
    const FILE_ALIGNMENT: usize = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    // A tiny section payload.
    let payload: &[u8] = &[0xCC; 16];

    // --- Header sizes ---
    // DOS header = 64; PE sig = 4; COFF header = 20; optional header (PE32) =
    // 96 standard + 16*8 data dirs = 224; one section header = 40.
    let e_lfanew: usize = 64;
    let opt_header = e_lfanew + 4 + 20; // == 88 (0x58)
    let size_of_opt_header: u16 = 224;
    let section_table = opt_header + size_of_opt_header as usize; // == 312 (0x138)
    let headers_unpadded = section_table + 40; // == 352 (0x160)
    let size_of_headers = align_up(headers_unpadded, FILE_ALIGNMENT); // 0x200

    // Section raw data is file-aligned and placed right after the headers.
    let pointer_to_raw_data = size_of_headers;
    let size_of_raw_data = align_up(payload.len(), FILE_ALIGNMENT);
    let file_size = pointer_to_raw_data + size_of_raw_data;

    let mut buf = vec![0u8; file_size];

    // --- DOS header ---
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    buf[e_lfanew..e_lfanew + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes()); // PE\0\0

    // --- COFF file header (at e_lfanew + 4) ---
    let coff = e_lfanew + 4;
    buf[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // Machine = i386
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    buf[coff + 16..coff + 18].copy_from_slice(&size_of_opt_header.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

    // --- Optional header (PE32) at opt_header ---
    buf[opt_header..opt_header + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // Magic
    // SizeOfCode @ +4
    buf[opt_header + 4..opt_header + 8].copy_from_slice(&(size_of_raw_data as u32).to_le_bytes());
    // AddressOfEntryPoint @ +16
    buf[opt_header + 16..opt_header + 20].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    // BaseOfCode @ +20
    buf[opt_header + 20..opt_header + 24].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    // BaseOfData @ +24 (PE32 only)
    buf[opt_header + 24..opt_header + 28].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    // ImageBase @ +28
    buf[opt_header + 28..opt_header + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    // SectionAlignment @ +32
    buf[opt_header + 32..opt_header + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    // FileAlignment @ +36
    buf[opt_header + 36..opt_header + 40].copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
    // SizeOfImage @ +56
    buf[opt_header + 56..opt_header + 60].copy_from_slice(&(2 * SECTION_ALIGNMENT).to_le_bytes());
    // SizeOfHeaders @ +60
    buf[opt_header + 60..opt_header + 64].copy_from_slice(&(size_of_headers as u32).to_le_bytes());
    // CheckSum @ +64 stays zero.
    // Subsystem @ +68 = 10 (EFI application)
    buf[opt_header + 68..opt_header + 70].copy_from_slice(&10u16.to_le_bytes());
    // NumberOfRvaAndSizes @ +92 = 16
    buf[opt_header + 92..opt_header + 96].copy_from_slice(&16u32.to_le_bytes());
    // Data directories @ +96 .. +96+128: all zero (Security dir index 4 zeroed).

    // --- Section header (.text) at section_table ---
    let s = section_table;
    buf[s..s + 8].copy_from_slice(b".text\0\0\0");
    // VirtualSize @ +8
    buf[s + 8..s + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    // VirtualAddress @ +12
    buf[s + 12..s + 16].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    // SizeOfRawData @ +16
    buf[s + 16..s + 20].copy_from_slice(&(size_of_raw_data as u32).to_le_bytes());
    // PointerToRawData @ +20
    buf[s + 20..s + 24].copy_from_slice(&(pointer_to_raw_data as u32).to_le_bytes());

    // --- Section payload ---
    buf[pointer_to_raw_data..pointer_to_raw_data + payload.len()].copy_from_slice(payload);

    buf
}

#[allow(dead_code)] // Only used by `synthetic_pe` in the test targets that need it.
fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

/// Name of the environment variable that switches the test suite from
/// *skipping* a test when an external tool is missing to *hard-failing*.
///
/// When set to a truthy value (anything other than `""`, `"0"`, `"false"` or
/// `"no"`, case-insensitive), [`skip_if_missing!`] and [`tool_or_skip`] panic
/// instead of returning early. This is meant for CI/gating runs where the
/// environment is expected to provide every interop tool, so a missing one is a
/// real failure rather than silently-reduced coverage. Locally, leave it unset
/// and the suite degrades gracefully with a visible notice.
pub const REQUIRE_TOOLS_ENV: &str = "SYSIMAGE_REQUIRE_TOOLS";

/// True when the suite is configured to *require* every external tool (i.e.
/// missing tools must hard-fail rather than be skipped).
pub fn require_tools_mode() -> bool {
    fn truthy(v: &str) -> bool {
        !v.is_empty()
            && !v.eq_ignore_ascii_case("0")
            && !v.eq_ignore_ascii_case("false")
            && !v.eq_ignore_ascii_case("no")
    }
    std::env::var(REQUIRE_TOOLS_ENV)
        .map(|v| truthy(&v))
        .unwrap_or(false)
}

/// True if `name` names an executable that can be launched from `PATH`.
///
/// This only checks that the binary can be *spawned*; it does not require the
/// invocation to succeed (some tools have no `--version`/help flag that exits
/// zero). We probe with `--version`, redirect all std streams to `/dev/null`,
/// and consider the tool present as long as the process could be started and
/// waited on — i.e. it was found and is executable. The probe is cheap and
/// only runs when a test asks for it.
///
/// `has_tool` is a *pure query* and is unaffected by [`require_tools_mode`]:
/// it always returns a plain `bool`, so it stays usable inside `if`/`else`
/// branches that provide their own fallback. For a probe that honors the
/// require-tools mode (skipping or panicking), use [`tool_or_skip`] for an
/// optional cross-check, or [`skip_if_missing!`] for a test that fully depends
/// on the tool.
pub fn has_tool(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Returns the subset of `tools` that is not available, joined with `", "`,
/// or `None` when every tool is present.
#[allow(dead_code)] // referenced by the `skip_if_missing!` macro; unused in crates that don't expand it
pub fn missing_tools(tools: &[&str]) -> Option<String> {
    let absent: Vec<&str> = tools.iter().copied().filter(|t| !has_tool(t)).collect();
    if absent.is_empty() {
        None
    } else {
        Some(absent.join(", "))
    }
}

/// For an *optional* external-tool cross-check: returns `true` when the tool is
/// present (so the caller may proceed with the cross-check), and otherwise
/// either prints a visible "skipping cross-check" notice and returns `false`,
/// or — when [`require_tools_mode`] is active — panics, so a missing tool is a
/// hard failure rather than reduced coverage.
///
/// Use this for bonus validation that is not the point of the test (the rest
/// of the test still runs when the tool is absent and require-mode is off).
/// For a test that *cannot run at all* without the tool, prefer
/// [`skip_if_missing!`] instead.
///
/// ```ignore
/// if common::tool_or_skip("pvck") {
///     // …pvck cross-check, guaranteed runnable here…
/// }
/// ```
#[allow(dead_code)] // only some test crates use this helper
pub fn tool_or_skip(name: &str) -> bool {
    if has_tool(name) {
        return true;
    }
    if require_tools_mode() {
        panic!(
            "{name} not available — failing ({} is set)",
            REQUIRE_TOOLS_ENV
        );
    }
    eprintln!("{name} not available — skipping cross-check");
    false
}

/// Skips the enclosing test when any of the named external tools is missing —
/// or, when [`common::require_tools_mode`] is active (the
/// `SYSIMAGE_REQUIRE_TOOLS` env var is set to a truthy value), *panics* so a
/// missing tool is a hard failure instead of silently-reduced coverage. This
/// lets CI gate on "every interop tool must be installed" while local dev runs
/// degrade gracefully with a visible notice.
///
/// When a tool is absent this prints an explicit notice to stderr (or panics)
/// and `return`s from the enclosing function, so it must be invoked from a
/// `#[test] fn` (or any function returning `()`). The skip is therefore
/// *visible* in the test output, never silent.
///
/// # Example
///
/// ```ignore
/// #[test]
/// fn erofs_round_trip() {
///     skip_if_missing!("fsck.erofs", "dump.erofs");
///     // …both tools are guaranteed present from here on…
/// }
/// ```
#[macro_export]
macro_rules! skip_if_missing {
    ($($tool:expr),+ $(,)?) => {
        if let Some(__missing) = $crate::common::missing_tools(&[$($tool),+]) {
            if $crate::common::require_tools_mode() {
                panic!(
                    "{__missing} not available — failing ({} is set)",
                    $crate::common::REQUIRE_TOOLS_ENV
                );
            }
            eprintln!("{__missing} not available — skipping test");
            return;
        }
    };
}
