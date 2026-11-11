//! Minimal PE/COFF reader and section-adder for building Unified Kernel Images.
//!
//! A UKI is a PE binary: the `systemd-stub` provides the entry point and the
//! boot logic, and we append extra sections (`.linux`, `.initrd`, `.cmdline`,
//! …) that the stub consumes at boot.  This module implements just enough PE
//! manipulation to stitch those sections onto a stub — no external `ukify`
//! binary required.

use crate::error::{Error, Result};

// --- PE/COFF constants --------------------------------------------------

/// DOS-header magic (`MZ`).
const DOS_MAGIC: u16 = 0x5A4D;
/// PE signature (`PE\0\0`).
const PE_SIGNATURE: u32 = 0x0000_4550;
/// Optional-header magic for PE32+ (64-bit).
const PE32PLUS_MAGIC: u16 = 0x020B;

const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;

/// Offset of `e_lfanew` inside the DOS header.
const E_LFANEW_OFFSET: usize = 0x3C;

// Section characteristics
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

// Optional-header characteristics
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
// COFF-file Characteristics: "local symbols stripped"
const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0020;

// --- little-endian helpers ----------------------------------------------

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn write_u16(data: &mut [u8], offset: usize, val: u16) {
    data[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, val: u32) {
    data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn round_up(x: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two() || align > 0);
    x.div_ceil(align) * align
}

// --- section model ------------------------------------------------------

/// A section to append (or merge) into the PE image.
pub struct PeSection {
    /// Section name (max 8 ASCII bytes).
    pub name: &'static str,
    /// Raw section payload.
    pub data: Vec<u8>,
    /// `true` for `.linux` (code); `false` for data sections.
    pub is_code: bool,
}

/// PE section header fields (parsed).
struct SectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

impl SectionHeader {
    fn read(data: &[u8], offset: usize) -> Self {
        let name = data[offset..offset + 8]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        SectionHeader {
            name,
            virtual_size: read_u32(data, offset + 8),
            virtual_address: read_u32(data, offset + 12),
            size_of_raw_data: read_u32(data, offset + 16),
            pointer_to_raw_data: read_u32(data, offset + 20),
        }
    }
}

// --- header offsets -----------------------------------------------------

/// Parsed top-level PE layout.
struct PeLayout {
    file_header_off: usize,
    opt_header_off: usize,
    section_headers_off: usize,
}

impl PeLayout {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 64 || read_u16(data, 0) != DOS_MAGIC {
            return Err(Error::msg("not a PE file (missing MZ)"));
        }
        let e_lfanew = read_u32(data, E_LFANEW_OFFSET) as usize;
        if e_lfanew + 4 > data.len() || read_u32(data, e_lfanew) != PE_SIGNATURE {
            return Err(Error::msg("invalid PE signature"));
        }
        let file_header_off = e_lfanew + 4;
        if file_header_off + FILE_HEADER_SIZE > data.len() {
            return Err(Error::msg("truncated COFF file header"));
        }
        let size_of_opt_header = read_u16(data, file_header_off + 16) as usize;
        let opt_header_off = file_header_off + FILE_HEADER_SIZE;
        if opt_header_off + size_of_opt_header > data.len() {
            return Err(Error::msg("truncated optional header"));
        }
        let magic = read_u16(data, opt_header_off);
        if magic != PE32PLUS_MAGIC && magic != 0x010B {
            return Err(Error::msg(format!(
                "unknown PE optional header magic: 0x{magic:04x}"
            )));
        }
        let section_headers_off = opt_header_off + size_of_opt_header;
        Ok(PeLayout {
            file_header_off,
            opt_header_off,
            section_headers_off,
        })
    }

    /// Offset of `SizeOfInitializedData` in the optional header (same for PE32 / PE32+).
    const fn size_of_initialized_data_off(&self) -> usize {
        self.opt_header_off + 8
    }
    /// Offset of `SectionAlignment` (same for PE32 / PE32+).
    const fn section_alignment_off(&self) -> usize {
        self.opt_header_off + 32
    }
    /// Offset of `FileAlignment` (same for PE32 / PE32+).
    const fn file_alignment_off(&self) -> usize {
        self.opt_header_off + 36
    }
    /// Offset of `SizeOfImage`.
    const fn size_of_image_off(&self) -> usize {
        self.opt_header_off + 56
    }
    /// Offset of `SizeOfHeaders`.
    const fn size_of_headers_off(&self) -> usize {
        self.opt_header_off + 60
    }
    /// Offset of `CheckSum`.
    const fn checksum_off(&self) -> usize {
        self.opt_header_off + 64
    }
    /// Offset of `DllCharacteristics` (same for PE32 / PE32+).
    const fn dll_characteristics_off(&self) -> usize {
        self.opt_header_off + 70
    }
}

// --- inner PE NX-compat check -------------------------------------------

/// If `data` is a valid PE, return `Some(true)` when its
/// `DllCharacteristics` has `NX_COMPAT` set, `Some(false)` when it does not,
/// or `None` when `data` is not a parseable PE.
fn inner_pe_nx_compat(data: &[u8]) -> Option<bool> {
    if data.len() < E_LFANEW_OFFSET + 4 || read_u16(data, 0) != DOS_MAGIC {
        return None;
    }
    let e_lfanew = read_u32(data, E_LFANEW_OFFSET) as usize;
    if e_lfanew + 4 > data.len() || read_u32(data, e_lfanew) != PE_SIGNATURE {
        return None;
    }
    let fh = e_lfanew + 4;
    let size_of_opt = read_u16(data, fh + 16) as usize;
    let opt = fh + FILE_HEADER_SIZE;
    let dll_off = opt + 70;
    if dll_off + 2 > data.len() || opt + size_of_opt > data.len() {
        return None;
    }
    Some(read_u16(data, dll_off) & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0)
}

// --- public API ---------------------------------------------------------

/// Append (or merge) `sections` onto the PE `stub`, returning the new image.
///
/// This mirrors what `ukify build` does:
///
/// 1. Strip a trailing symbol/string table from the stub if present.
/// 2. Re-align any unaligned section raw-data pointers/sizes to
///    `FileAlignment` (old stubs may be stripped and unaligned).
/// 3. Round `SizeOfHeaders` up to `FileAlignment` to maximise header space.
/// 4. For each new section: if a section with the same name already exists in
///    the *original* stub, replace its data in place (must fit).  Otherwise
///    append a new section header + raw data.
/// 5. Fix up `NumberOfSections`, `SizeOfInitializedData`, `SizeOfImage`, and
///    clear the checksum.
///
/// For `.linux` (code) sections the `NX_COMPAT` flag on the outer PE is
/// cleared if the inner kernel PE does not set it, matching `ukify`.
pub fn add_sections(stub: &[u8], sections: &[PeSection]) -> Result<Vec<u8>> {
    let layout = PeLayout::parse(stub)?;
    let file_alignment = read_u32(stub, layout.file_alignment_off()) as u64;
    let section_alignment = read_u32(stub, layout.section_alignment_off()) as u64;
    if file_alignment == 0 || section_alignment == 0 {
        return Err(Error::msg("PE has zero FileAlignment or SectionAlignment"));
    }

    let num_sections = read_u16(stub, layout.file_header_off + 2) as usize;
    let pointer_to_symtab = read_u32(stub, layout.file_header_off + 8);
    let num_symbols = read_u32(stub, layout.file_header_off + 12);

    let mut data: Vec<u8> = stub.to_vec();

    // 1 — strip a trailing COFF symbol + string table.
    strip_symbol_table(&mut data, &layout, pointer_to_symtab, num_symbols);

    // 2 — fix up unaligned section raw data.
    fix_unaligned_sections(&mut data, &layout, num_sections, file_alignment);

    // 3 — round up SizeOfHeaders.
    let size_of_headers = read_u32(&data, layout.size_of_headers_off()) as u64;
    let new_size_of_headers = round_up(size_of_headers, file_alignment);
    if new_size_of_headers as usize > data.len() {
        data.resize(new_size_of_headers as usize, 0);
    }
    write_u32(
        &mut data,
        layout.size_of_headers_off(),
        new_size_of_headers as u32,
    );

    // 4 — add sections.
    let mut current_sections = num_sections;
    let mut size_of_init_data = read_u32(&data, layout.size_of_initialized_data_off()) as u64;

    for section in sections {
        let name_bytes = section.name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > 8 || !name_bytes.iter().all(|b| b.is_ascii())
        {
            return Err(Error::msg(format!(
                "invalid PE section name: {:?}",
                section.name
            )));
        }

        let characteristics = if section.is_code {
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ
        } else {
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        };

        // Look for a matching section among the *original* stub sections.
        let existing = find_original_section(&data, &layout, num_sections, section.name);

        if let Some((idx, _)) = &existing {
            let shdr_off = layout.section_headers_off + idx * SECTION_HEADER_SIZE;
            let hdr = SectionHeader::read(&data, shdr_off);
            let raw_size = hdr.size_of_raw_data as usize;
            let vsize = section.data.len();
            if vsize > raw_size {
                return Err(Error::msg(format!(
                    "section {} already exists but new data ({} bytes) is larger than existing raw size ({} bytes)",
                    section.name, vsize, raw_size
                )));
            }
            // Replace the section payload in place.
            let ptr = hdr.pointer_to_raw_data as usize;
            data[ptr..ptr + vsize].copy_from_slice(&section.data);
            for b in &mut data[ptr + vsize..ptr + raw_size] {
                *b = 0;
            }
            write_u32(&mut data, shdr_off + 8, vsize as u32); // VirtualSize
        // (characteristics / VirtualAddress unchanged)
        } else {
            // Append a brand-new section.
            let new_shdr_off = layout.section_headers_off + current_sections * SECTION_HEADER_SIZE;
            if new_shdr_off + SECTION_HEADER_SIZE > new_size_of_headers as usize {
                return Err(Error::msg(format!(
                    "not enough header space to add section {} (need {} bytes, headers cap {})",
                    section.name,
                    new_shdr_off + SECTION_HEADER_SIZE,
                    new_size_of_headers
                )));
            }

            // VirtualAddress: after the last section, aligned to SectionAlignment.
            let last_off =
                layout.section_headers_off + (current_sections - 1) * SECTION_HEADER_SIZE;
            let last_hdr = SectionHeader::read(&data, last_off);
            let new_va = round_up(
                last_hdr.virtual_address as u64 + last_hdr.virtual_size as u64,
                section_alignment,
            ) as u32;

            // PointerToRawData: end of file, aligned to FileAlignment.
            let new_ptr = round_up(data.len() as u64, file_alignment) as usize;
            if new_ptr > data.len() {
                data.resize(new_ptr, 0);
            }
            let raw_size = round_up(section.data.len() as u64, file_alignment) as usize;
            data.extend_from_slice(&section.data);
            data.resize(new_ptr + raw_size, 0);

            // Write the 40-byte section header.
            let mut name_field = [0u8; 8];
            name_field[..name_bytes.len()].copy_from_slice(name_bytes);
            data[new_shdr_off..new_shdr_off + 8].copy_from_slice(&name_field);
            write_u32(&mut data, new_shdr_off + 8, section.data.len() as u32); // VirtualSize
            write_u32(&mut data, new_shdr_off + 12, new_va); // VirtualAddress
            write_u32(&mut data, new_shdr_off + 16, raw_size as u32); // SizeOfRawData
            write_u32(&mut data, new_shdr_off + 20, new_ptr as u32); // PointerToRawData
            write_u32(&mut data, new_shdr_off + 24, 0); // PointerToRelocations
            write_u32(&mut data, new_shdr_off + 28, 0); // PointerToLinenumbers
            write_u16(&mut data, new_shdr_off + 32, 0); // NumberOfRelocations
            write_u16(&mut data, new_shdr_off + 34, 0); // NumberOfLinenumbers
            write_u32(&mut data, new_shdr_off + 36, characteristics); // Characteristics

            current_sections += 1;
            size_of_init_data += section.data.len() as u64;
        }

        // For `.linux`: sync NX_COMPAT between inner kernel PE and outer stub.
        if section.is_code
            && let Some(has_nx) = inner_pe_nx_compat(&section.data)
            && !has_nx
        {
            let dll = read_u16(&data, layout.dll_characteristics_off());
            write_u16(
                &mut data,
                layout.dll_characteristics_off(),
                dll & !IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            );
        }
    }

    // 5 — fix up header bookkeeping.
    write_u16(
        &mut data,
        layout.file_header_off + 2,
        current_sections as u16,
    );
    write_u32(
        &mut data,
        layout.size_of_initialized_data_off(),
        size_of_init_data as u32,
    );

    let last_off = layout.section_headers_off + (current_sections - 1) * SECTION_HEADER_SIZE;
    let last_hdr = SectionHeader::read(&data, last_off);
    let size_of_image = round_up(
        last_hdr.virtual_address as u64 + last_hdr.virtual_size as u64,
        section_alignment,
    ) as u32;
    write_u32(&mut data, layout.size_of_image_off(), size_of_image);

    write_u32(&mut data, layout.checksum_off(), 0);

    Ok(data)
}

/// A PE section read from an image:
/// `(name, virtual_size, raw_size, raw_offset, data)`.
pub type SectionInfo = (String, u32, u32, usize, Vec<u8>);

/// Enumerate all sections of a PE image.
pub fn list_sections(data: &[u8]) -> Result<Vec<SectionInfo>> {
    let layout = PeLayout::parse(data)?;
    let num_sections = read_u16(data, layout.file_header_off + 2) as usize;
    let mut out = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = layout.section_headers_off + i * SECTION_HEADER_SIZE;
        let hdr = SectionHeader::read(data, off);
        let raw_off = hdr.pointer_to_raw_data as usize;
        let raw_size = hdr.size_of_raw_data as usize;
        let payload = if raw_off + raw_size <= data.len() {
            data[raw_off..raw_off + raw_size].to_vec()
        } else {
            Vec::new()
        };
        out.push((
            hdr.name,
            hdr.virtual_size,
            hdr.size_of_raw_data,
            raw_off,
            payload,
        ));
    }
    Ok(out)
}

// --- internals ----------------------------------------------------------

/// Strip a trailing COFF symbol + string table, if it sits exactly at EOF.
fn strip_symbol_table(data: &mut Vec<u8>, layout: &PeLayout, sym_tab: u32, num_symbols: u32) {
    let sym_off = sym_tab as usize;
    if sym_off == 0 || num_symbols == 0 {
        return;
    }
    let sym_size = 18 * num_symbols as usize;
    let str_tab_off = sym_off + sym_size;
    let mut total = sym_size;
    if str_tab_off + 4 <= data.len() {
        // COFF string table: first 4 bytes are the total size (including those 4 bytes).
        total += read_u32(data, str_tab_off) as usize;
    }
    if sym_off + total == data.len() {
        data.truncate(sym_off);
        write_u32(data, layout.file_header_off + 8, 0); // PointerToSymbolTable
        write_u32(data, layout.file_header_off + 12, 0); // NumberOfSymbols
        let chars = read_u16(data, layout.file_header_off + 18);
        write_u16(
            data,
            layout.file_header_off + 18,
            chars | IMAGE_FILE_LOCAL_SYMS_STRIPPED,
        );
    }
}

/// Re-align unaligned `PointerToRawData` / `SizeOfRawData` to `FileAlignment`.
///
/// Old stripped stubs can have unaligned raw-data values.  We pad each section
/// to the alignment, shifting all later sections forward — matching `ukify`.
fn fix_unaligned_sections(
    data: &mut Vec<u8>,
    layout: &PeLayout,
    num_sections: usize,
    file_alignment: u64,
) {
    for i in 0..num_sections {
        let shdr = layout.section_headers_off + i * SECTION_HEADER_SIZE;
        let old_ptr = read_u32(data, shdr + 20) as usize;
        let old_size = read_u32(data, shdr + 16) as usize;
        let new_ptr = round_up(old_ptr as u64, file_alignment) as usize;
        let new_size = round_up(old_size as u64, file_alignment) as usize;
        if new_ptr == old_ptr && new_size == old_size {
            continue;
        }
        let padp = new_ptr - old_ptr;
        let padsz = new_size - old_size;

        // Shift later sections' PointerToRawData.
        for j in (i + 1)..num_sections {
            let later_off = layout.section_headers_off + j * SECTION_HEADER_SIZE + 20;
            let shifted = read_u32(data, later_off) as usize + padp + padsz;
            write_u32(data, later_off, shifted as u32);
        }

        // Rebuild the data buffer: before | pad | section | pad | after.
        let mut rebuilt = Vec::with_capacity(data.len() + padp + padsz);
        rebuilt.extend_from_slice(&data[..old_ptr]);
        rebuilt.resize(rebuilt.len() + padp, 0);
        rebuilt.extend_from_slice(&data[old_ptr..old_ptr + old_size]);
        rebuilt.resize(rebuilt.len() + padsz, 0);
        rebuilt.extend_from_slice(&data[old_ptr + old_size..]);
        *data = rebuilt;

        write_u32(data, shdr + 20, new_ptr as u32); // PointerToRawData
        write_u32(data, shdr + 16, new_size as u32); // SizeOfRawData
    }
}

/// Find a section among the *original* stub sections (not ones we just added)
/// whose name matches `name` (`.dtbauto` excluded — it's multi-instance).
fn find_original_section(
    data: &[u8],
    layout: &PeLayout,
    num_original: usize,
    name: &str,
) -> Option<(usize, SectionHeader)> {
    if name == ".dtbauto" {
        return None;
    }
    for i in 0..num_original {
        let off = layout.section_headers_off + i * SECTION_HEADER_SIZE;
        let hdr = SectionHeader::read(data, off);
        if hdr.name == name {
            return Some((i, hdr));
        }
    }
    None
}
