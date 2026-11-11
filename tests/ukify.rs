//! Pure-Rust UKI building: stitch sections onto a synthetic PE stub and
//! verify the result.  This test is fully self-contained (no `ukify` binary).

use std::fs;
use std::path::{Path, PathBuf};

use sysimage::arch::get_arch;
use sysimage::ukify::{UkifyConfig, ukify_build, ukify_inspect};

// --- minimal synthetic PE stub -----------------------------------------

/// Build a minimal valid PE32+ (x86-64) stub with a single `.text` section.
///
/// The stub has enough header space (`SizeOfHeaders = 512`) to accept several
/// extra section headers, and a single code section so that `add_sections`
/// can compute the next `VirtualAddress`.
fn build_minimal_stub() -> Vec<u8> {
    const FILE_ALIGNMENT: u32 = 0x200; // 512
    const SECTION_ALIGNMENT: u32 = 0x1000; // 4096

    let e_lfanew: u32 = 64; // DOS header is 64 bytes

    // Optional header (PE32+): 116 standard/windows fields + 128 data dirs = 244
    let size_of_opt_header: u16 = 116 + 128;

    let file_header_off = e_lfanew as usize + 4;
    let opt_header_off = file_header_off + 20;
    let section_headers_off = opt_header_off + size_of_opt_header as usize;

    // One section header (40 bytes).
    let headers_end = section_headers_off + 40;
    let size_of_headers = round_up(headers_end as u32, FILE_ALIGNMENT);
    let text_raw_off = size_of_headers; // .text starts right after headers
    let text_raw_size = FILE_ALIGNMENT; // one file-alignment unit of code

    let image_base: u64 = 0x1_0000;
    let text_va: u32 = SECTION_ALIGNMENT;
    let entry_point: u32 = text_va; // entry at start of .text
    let size_of_image = round_up(text_va + text_raw_size, SECTION_ALIGNMENT);

    let total_size = text_raw_off as usize + text_raw_size as usize;
    let mut buf = vec![0u8; total_size];

    // --- DOS header ---
    write_u16(&mut buf, 0, 0x5A4D); // "MZ"
    write_u32(&mut buf, 0x3C, e_lfanew);

    // --- PE signature ---
    write_u32(&mut buf, e_lfanew as usize, 0x0000_4550); // "PE\0\0"

    // --- COFF file header ---
    let fh = file_header_off;
    write_u16(&mut buf, fh, 0x8664); // Machine = IMAGE_FILE_MACHINE_AMD64
    write_u16(&mut buf, fh + 2, 1); // NumberOfSections
    write_u32(&mut buf, fh + 8, 0); // PointerToSymbolTable
    write_u32(&mut buf, fh + 12, 0); // NumberOfSymbols
    write_u16(&mut buf, fh + 16, size_of_opt_header);
    write_u16(&mut buf, fh + 18, 0x0022); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // --- Optional header (PE32+) ---
    let oh = opt_header_off;
    write_u16(&mut buf, oh, 0x020B); // Magic = PE32+
    write_u8(&mut buf, oh + 2, 14); // MajorLinkerVersion
    write_u8(&mut buf, oh + 3, 0); // MinorLinkerVersion
    write_u32(&mut buf, oh + 4, text_raw_size); // SizeOfCode
    write_u32(&mut buf, oh + 8, 0); // SizeOfInitializedData
    write_u32(&mut buf, oh + 12, 0); // SizeOfUninitializedData
    write_u32(&mut buf, oh + 16, entry_point); // AddressOfEntryPoint
    write_u32(&mut buf, oh + 20, text_va); // BaseOfCode
    write_u64(&mut buf, oh + 24, image_base); // ImageBase
    write_u32(&mut buf, oh + 32, SECTION_ALIGNMENT); // SectionAlignment
    write_u32(&mut buf, oh + 36, FILE_ALIGNMENT); // FileAlignment
    write_u16(&mut buf, oh + 40, 6); // MajorOSVersion
    write_u16(&mut buf, oh + 42, 0); // MinorOSVersion
    write_u16(&mut buf, oh + 44, 0); // MajorImageVersion
    write_u16(&mut buf, oh + 46, 0); // MinorImageVersion
    write_u16(&mut buf, oh + 48, 6); // MajorSubsystemVersion
    write_u16(&mut buf, oh + 50, 2); // MinorSubsystemVersion
    write_u32(&mut buf, oh + 52, 0); // Win32VersionValue
    write_u32(&mut buf, oh + 56, size_of_image); // SizeOfImage
    write_u32(&mut buf, oh + 60, size_of_headers); // SizeOfHeaders
    write_u32(&mut buf, oh + 64, 0); // CheckSum
    write_u16(&mut buf, oh + 68, 10); // Subsystem = EFI_APPLICATION
    write_u16(&mut buf, oh + 70, 0x0160); // DllCharacteristics (NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA)
    write_u64(&mut buf, oh + 72, 0x100000); // SizeOfStackReserve
    write_u64(&mut buf, oh + 80, 0x1000); // SizeOfStackCommit
    write_u64(&mut buf, oh + 88, 0x100000); // SizeOfHeapReserve
    write_u64(&mut buf, oh + 96, 0x1000); // SizeOfHeapCommit
    write_u32(&mut buf, oh + 104, 0); // LoaderFlags
    write_u32(&mut buf, oh + 108, 16); // NumberOfRvaAndSizes
    // Data directories: 16 * 8 = 128 bytes, all zeros (already zeroed).

    // --- .text section header ---
    let sh = section_headers_off;
    buf[sh..sh + 5].copy_from_slice(b".text");
    write_u32(&mut buf, sh + 8, 16); // VirtualSize
    write_u32(&mut buf, sh + 12, text_va); // VirtualAddress
    write_u32(&mut buf, sh + 16, text_raw_size); // SizeOfRawData
    write_u32(&mut buf, sh + 20, text_raw_off); // PointerToRawData
    write_u32(&mut buf, sh + 36, 0x6000_0020); // Characteristics: CODE | EXECUTE | READ

    // .text content: a single `ret` (0xC3) at the entry point.
    buf[text_raw_off as usize] = 0xC3;

    buf
}

// --- helpers ------------------------------------------------------------

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}
fn write_u8(buf: &mut [u8], off: usize, val: u8) {
    buf[off] = val;
}

fn round_up(x: u32, align: u32) -> u32 {
    x.div_ceil(align) * align
}

// --- test struct (matches tests/build.rs) -------------------------------

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sysimg-ukify-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// --- tests --------------------------------------------------------------

#[test]
fn builds_uki_and_inspects_sections() {
    let workdir = TempDir::new();

    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();

    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"FAKE_KERNEL_PAYLOAD_1234567890").unwrap();

    let initrd_path = workdir.path().join("initrd.img");
    fs::write(&initrd_path, b"FAKE_INITRD").unwrap();

    let output_path = workdir.path().join("uki.efi");

    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![initrd_path],
        cmdline: Some("root=/dev/sda1 rw console=tty0".into()),
        osrel: None,
        splash: None,
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    assert!(output_path.exists(), "UKI output file was not created");

    let json = ukify_inspect(&output_path).unwrap();
    let obj = json.as_object().unwrap();

    // .text was in the original stub.
    assert!(obj.contains_key(".text"), "stub .text section missing");

    // .linux must contain our fake kernel payload.
    let linux_hex = obj.get(".linux").unwrap().as_str().unwrap();
    let linux_bytes = hex::decode(linux_hex).unwrap();
    assert_eq!(linux_bytes, b"FAKE_KERNEL_PAYLOAD_1234567890");

    // .initrd must contain our fake initrd.
    let initrd_hex = obj.get(".initrd").unwrap().as_str().unwrap();
    let initrd_bytes = hex::decode(initrd_hex).unwrap();
    assert_eq!(initrd_bytes, b"FAKE_INITRD");

    // .cmdline must be our command line.
    let cmdline = obj.get(".cmdline").unwrap().as_str().unwrap();
    assert_eq!(cmdline, "root=/dev/sda1 rw console=tty0");
}

#[test]
fn builds_uki_without_cmdline() {
    let workdir = TempDir::new();
    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();
    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"KERNEL").unwrap();
    let output_path = workdir.path().join("uki.efi");

    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![],
        cmdline: None,
        osrel: None,
        splash: None,
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    let json = ukify_inspect(&output_path).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key(".linux"));
    assert!(!obj.contains_key(".cmdline"));
    assert!(!obj.contains_key(".initrd"));
}

#[test]
fn joins_multiple_initrds_with_alignment() {
    let workdir = TempDir::new();
    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();

    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"KERNEL").unwrap();

    // initrd1 = 5 bytes, padded to 8; initrd2 = 3 bytes → total 11.
    let initrd1 = workdir.path().join("i1");
    fs::write(&initrd1, b"ABCDE").unwrap();
    let initrd2 = workdir.path().join("i2");
    fs::write(&initrd2, b"XYZ").unwrap();

    let output_path = workdir.path().join("uki.efi");
    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![initrd1, initrd2],
        cmdline: None,
        osrel: None,
        splash: None,
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    let json = ukify_inspect(&output_path).unwrap();
    let initrd_hex = json
        .as_object()
        .unwrap()
        .get(".initrd")
        .unwrap()
        .as_str()
        .unwrap();
    let initrd_bytes = hex::decode(initrd_hex).unwrap();
    // ABCDE + 3 padding zeros + XYZ + 1 padding zero = 12 bytes (ukify pads every initrd)
    assert_eq!(initrd_bytes, b"ABCDE\0\0\0XYZ\0");
}

#[test]
fn output_is_valid_pe_with_correct_section_count() {
    let workdir = TempDir::new();
    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();
    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"KERNEL").unwrap();
    let initrd_path = workdir.path().join("initrd");
    fs::write(&initrd_path, b"INITRD").unwrap();
    let output_path = workdir.path().join("uki.efi");

    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![initrd_path],
        cmdline: Some("quiet".into()),
        osrel: None,
        splash: None,
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    let data = fs::read(&output_path).unwrap();
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let fh = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([data[fh + 2], data[fh + 3]]);
    // 1 (.text) + 3 (.cmdline, .linux, .initrd) = 4
    assert_eq!(num_sections, 4);

    let size_of_image = u32::from_le_bytes([
        data[e_lfanew + 4 + 20 + 56],
        data[e_lfanew + 4 + 20 + 57],
        data[e_lfanew + 4 + 20 + 58],
        data[e_lfanew + 4 + 20 + 59],
    ]);
    assert!(
        size_of_image > 0 && size_of_image.is_multiple_of(0x1000),
        "SizeOfImage must be aligned to SectionAlignment, got {size_of_image:#x}"
    );

    let checksum = u32::from_le_bytes([
        data[e_lfanew + 4 + 20 + 64],
        data[e_lfanew + 4 + 20 + 65],
        data[e_lfanew + 4 + 20 + 66],
        data[e_lfanew + 4 + 20 + 67],
    ]);
    assert_eq!(checksum, 0, "checksum should be cleared");
}

#[test]
fn builds_uki_with_osrel_section() {
    // systemd-boot recognises a PE as a UKI only when *both* `.osrel` and
    // `.linux` sections are present.  Verify we emit `.osrel`.
    let workdir = TempDir::new();
    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();

    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"KERNEL").unwrap();

    let osrel_path = workdir.path().join("os-release");
    fs::write(&osrel_path, b"NAME=\"Test OS\"\nID=test\n").unwrap();

    let output_path = workdir.path().join("uki.efi");
    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![],
        cmdline: None,
        osrel: Some(osrel_path),
        splash: None,
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    let json = ukify_inspect(&output_path).unwrap();
    let obj = json.as_object().unwrap();

    // Both sections required by systemd-boot's pe_is_uki() must be present.
    assert!(obj.contains_key(".osrel"), ".osrel section missing");
    assert!(obj.contains_key(".linux"), ".linux section missing");

    let osrel = obj.get(".osrel").unwrap().as_str().unwrap();
    assert_eq!(osrel, "NAME=\"Test OS\"\nID=test\n");
}

#[test]
fn builds_uki_with_splash_section() {
    // The `.splash` section carries a boot splash image (BMP) shown by
    // systemd-stub.  Verify we emit it verbatim as a binary section.
    let workdir = TempDir::new();
    let stub_path = workdir.path().join("stub.efi");
    fs::write(&stub_path, build_minimal_stub()).unwrap();

    let kernel_path = workdir.path().join("vmlinuz");
    fs::write(&kernel_path, b"KERNEL").unwrap();

    let splash_path = workdir.path().join("splash.bmp");
    let splash_payload = b"BM\x00\x00FAKE_BMP_PAYLOAD";
    fs::write(&splash_path, splash_payload).unwrap();

    let output_path = workdir.path().join("uki.efi");
    ukify_build(&UkifyConfig {
        stub: stub_path,
        kernel: kernel_path,
        initrd: vec![],
        cmdline: None,
        osrel: None,
        splash: Some(splash_path),
        output: output_path.clone(),
        arch: get_arch("x86_64").unwrap(),
    })
    .unwrap();

    let json = ukify_inspect(&output_path).unwrap();
    let obj = json.as_object().unwrap();

    assert!(obj.contains_key(".splash"), ".splash section missing");
    let splash_hex = obj.get(".splash").unwrap().as_str().unwrap();
    let splash_bytes = hex::decode(splash_hex).unwrap();
    assert_eq!(splash_bytes, splash_payload);
}
