//! PE header parsing and address translation.
//!
//! Spec `06_TYPE_PLUGINS` §PE RVA / file offset; C++ `PEFile::Update`
//! (`PEFile.cpp:1320-1560`), `RVAToFA`, `FAToRVA`, `FAToVA`, `VAtoFA`,
//! `ConvertAddress`, `RVAToSectionIndex`, `TranslateFromFileOffset` /
//! `TranslateToFileOffset`.
//!
//! [`PeFile::parse_bytes`] is `Update()`: DOS header, `ImageNTHeaders32`
//! (and `ImageNTHeaders64` for `0x20B`), the section table (at
//! `e_lfanew + 4 + sizeof(FileHeader) + SizeOfOptionalHeader`),
//! `imageBase`, `computedSize` / `virtualComputedSize` /
//! `computedWithCertificate`, `hasOverlay` / `overlaySize` and the
//! diagnostics the C++ `errList` collects (invalid section count,
//! non-consecutive or duplicate section names, `SizeOfRawData = 0`
//! trick, truncation, `SizeOfImage`, entry point, data directories).
//! Imports / exports / resources / version / TLS / debug tables are
//! parsed by later tasks.
//!
//! Address rules, all with the C++ edge cases:
//!
//! - `RVAToFA`: invalid below the first section's RVA or without
//!   sections; otherwise the **last section whose RVA is not above**
//!   the address maps it (no upper bound: an RVA past the last section
//!   still maps into it, as in C++);
//! - `FAToRVA`: the section whose raw range contains the offset, with
//!   `VirtualAddress > 0` and the delta inside `VirtualSize`;
//! - `FAToVA` = `FAToRVA + imageBase`; `VAtoFA` requires the RVA to
//!   fall inside a section's virtual range;
//! - `ConvertAddress` (VA → *): `address > imageBase` strictly, so a VA
//!   equal to the image base is invalid — replicated.
//!
//! All reads are bounds-checked; a truncated header yields
//! [`PeError`] instead of a partial file, and a section header that
//! cannot be read is zero-filled like the C++ `memset`.

use gview_core::cache::DataCache;
use gview_view::buffer_viewer::dissasm_dialog::OffsetTranslate;

use crate::validate::{
    dos_header_lfanew, read_u16, read_u32, read_u64, IMAGE_FILE_HEADER_SIZE, IMAGE_NT_HEADERS32_SIZE,
    IMAGE_NT_HEADERS64_SIZE, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    IMAGE_NT_SIGNATURE, IMAGE_NUMBEROF_DIRECTORY_ENTRIES, IMAGE_SECTION_HEADER_SIZE,
    IMAGE_SIZEOF_SHORT_NAME,
};

/// C++ `PE_INVALID_ADDRESS`.
pub const PE_INVALID_ADDRESS: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// C++ `MAX_NR_SECTIONS`.
pub const MAX_NR_SECTIONS: usize = 256;
/// Data directories the C++ inspects (`for tr < 15`).
pub const INSPECTED_DIRECTORIES: usize = 15;
/// `IMAGE_DLLCHARACTERISTICS_APPCONTAINER`.
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
/// `__IMAGE_FILE_DLL`.
pub const IMAGE_FILE_DLL: u16 = 0x2000;
/// `__IMAGE_SCN_MEM_EXECUTE`.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `__IMAGE_SCN_MEM_READ`.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// `__IMAGE_SCN_MEM_WRITE`.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Bytes sampled at the entry point (`Get(filePoz, 16, false)`).
pub const ENTRY_POINT_SAMPLE: u32 = 16;

/// C++ `peDirsNames`.
pub const DIRECTORY_NAMES: [&str; INSPECTED_DIRECTORIES] = [
    "Export",
    "Import",
    "Resource",
    "Exceptions",
    "Security",
    "Base Reloc",
    "Debug",
    "Architecture",
    "Global Ptr",
    "TLS",
    "Load Config",
    "Bound Import",
    "IAT",
    "Delay Import Desc",
    "COM+ Runtime",
];

/// C++ `DirectoryType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DirectoryType {
    /// Export table.
    Export = 0,
    /// Import table.
    Import = 1,
    /// Resources.
    Resource = 2,
    /// Exception table.
    Exception = 3,
    /// Certificate table (file offset, not RVA).
    Security = 4,
    /// Base relocations.
    BaseRelloc = 5,
    /// Debug data.
    Debug = 6,
    /// Architecture.
    Architecture = 7,
    /// Global pointer.
    GlobalPtr = 8,
    /// TLS.
    Tls = 9,
    /// Load config.
    Config = 10,
    /// Bound imports.
    BoundImport = 11,
    /// Import address table.
    Iat = 12,
    /// Delay imports.
    DelayImport = 13,
    /// CLR header.
    ComDescriptor = 14,
}

impl DirectoryType {
    /// C++ `DirectoryIDToName`: empty for ids `>= 15`.
    #[must_use]
    pub fn name(id: u32) -> &'static str {
        DIRECTORY_NAMES.get(id as usize).copied().unwrap_or("")
    }
}

/// C++ `AddressType` (translation-list indices: 0 = file offset,
/// 1 = RVA, 2 = VA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// File offset.
    FileOffset = 0,
    /// Relative virtual address.
    Rva = 1,
    /// Virtual address (`imageBase + RVA`).
    Va = 2,
}

impl AddressType {
    /// Translation index → type (`static_cast<AddressType>`); unknown
    /// indices behave like an invalid conversion.
    #[must_use]
    pub const fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::FileOffset),
            1 => Some(Self::Rva),
            2 => Some(Self::Va),
            _ => None,
        }
    }
}

/// C++ `ImageDOSHeader` (only the fields the port uses; the rest is
/// reserved padding).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DosHeader {
    /// `e_magic`.
    pub e_magic: u16,
    /// `e_lfanew`.
    pub e_lfanew: u32,
}

/// C++ `ImageFileHeader`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileHeader {
    /// `Machine`.
    pub machine: u16,
    /// `NumberOfSections`.
    pub number_of_sections: u16,
    /// `TimeDateStamp`.
    pub time_date_stamp: u32,
    /// `PointerToSymbolTable`.
    pub pointer_to_symbol_table: u32,
    /// `NumberOfSymbols`.
    pub number_of_symbols: u32,
    /// `SizeOfOptionalHeader`.
    pub size_of_optional_header: u16,
    /// `Characteristics`.
    pub characteristics: u16,
}

/// C++ `ImageDataDirectory`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataDirectory {
    /// `VirtualAddress` (a file offset for `Security`).
    pub virtual_address: u32,
    /// `Size`.
    pub size: u32,
}

/// The fields common to `ImageOptionalHeader32` / `64` (widened to
/// 64 bits where PE32+ widens them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OptionalHeader {
    /// `Magic` (`0x10B` / `0x20B`).
    pub magic: u16,
    /// `MajorLinkerVersion`.
    pub major_linker_version: u8,
    /// `MinorLinkerVersion`.
    pub minor_linker_version: u8,
    /// `SizeOfCode`.
    pub size_of_code: u32,
    /// `SizeOfInitializedData`.
    pub size_of_initialized_data: u32,
    /// `SizeOfUninitializedData`.
    pub size_of_uninitialized_data: u32,
    /// `AddressOfEntryPoint`.
    pub address_of_entry_point: u32,
    /// `BaseOfCode`.
    pub base_of_code: u32,
    /// `BaseOfData` (PE32 only; 0 on PE32+).
    pub base_of_data: u32,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SectionAlignment`.
    pub section_alignment: u32,
    /// `FileAlignment`.
    pub file_alignment: u32,
    /// `MajorOperatingSystemVersion`.
    pub major_os_version: u16,
    /// `MinorOperatingSystemVersion`.
    pub minor_os_version: u16,
    /// `MajorImageVersion`.
    pub major_image_version: u16,
    /// `MinorImageVersion`.
    pub minor_image_version: u16,
    /// `MajorSubsystemVersion`.
    pub major_subsystem_version: u16,
    /// `MinorSubsystemVersion`.
    pub minor_subsystem_version: u16,
    /// `Win32VersionValue`.
    pub win32_version_value: u32,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `CheckSum`.
    pub checksum: u32,
    /// `Subsystem`.
    pub subsystem: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// `SizeOfStackReserve`.
    pub size_of_stack_reserve: u64,
    /// `SizeOfStackCommit`.
    pub size_of_stack_commit: u64,
    /// `SizeOfHeapReserve`.
    pub size_of_heap_reserve: u64,
    /// `SizeOfHeapCommit`.
    pub size_of_heap_commit: u64,
    /// `LoaderFlags`.
    pub loader_flags: u32,
    /// `NumberOfRvaAndSizes`.
    pub number_of_rva_and_sizes: u32,
    /// `DataDirectory[16]`.
    pub data_directory: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

/// C++ `ImageSectionHeader`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SectionHeader {
    /// `Name[8]` (not NUL-terminated when 8 chars long).
    pub name: [u8; IMAGE_SIZEOF_SHORT_NAME],
    /// `Misc.VirtualSize`.
    pub virtual_size: u32,
    /// `VirtualAddress`.
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub size_of_raw_data: u32,
    /// `PointerToRawData`.
    pub pointer_to_raw_data: u32,
    /// `PointerToRelocations`.
    pub pointer_to_relocations: u32,
    /// `PointerToLinenumbers`.
    pub pointer_to_linenumbers: u32,
    /// `NumberOfRelocations`.
    pub number_of_relocations: u16,
    /// `NumberOfLinenumbers`.
    pub number_of_linenumbers: u16,
    /// `Characteristics`.
    pub characteristics: u32,
}

impl SectionHeader {
    /// C++ `GetSectionName`: the name up to the first NUL (at most 8).
    #[must_use]
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
        String::from_utf8_lossy(self.name.get(..end).unwrap_or(&[])).into_owned()
    }

    /// Raw-data range `[PointerToRawData, PointerToRawData + SizeOfRawData)`.
    #[must_use]
    pub const fn raw_end(&self) -> u64 {
        (self.pointer_to_raw_data as u64).saturating_add(self.size_of_raw_data as u64)
    }

    /// Virtual range end `VirtualAddress + VirtualSize`.
    #[must_use]
    pub const fn virtual_end(&self) -> u64 {
        (self.virtual_address as u64).saturating_add(self.virtual_size as u64)
    }
}

/// C++ `SectionALIGN`.
#[must_use]
pub const fn section_align(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    if value == 0 {
        return align;
    }
    if value.is_multiple_of(align) {
        return value;
    }
    match value.checked_div(align) {
        Some(quotient) => quotient.saturating_add(1).saturating_mul(align),
        None => value,
    }
}

/// One `errList` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Diagnostic {
    /// `errList.AddError`.
    Error(String),
    /// `errList.AddWarning`.
    Warning(String),
}

/// Header-level failures (`Update()` returning `false`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeError {
    /// The DOS header could not be read or lacks `MZ`.
    DosHeader,
    /// `ImageNTHeaders32` could not be read at `e_lfanew`.
    NtHeaders,
    /// `PE\0\0` missing at `e_lfanew`.
    NtSignature,
    /// `ImageNTHeaders64` could not be read (PE32+).
    NtHeaders64,
    /// `OptionalHeader.Magic` is neither `0x10B` nor `0x20B`.
    UnsupportedOptionalHeader {
        /// The magic found.
        magic: u16,
    },
}

impl core::fmt::Display for PeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DosHeader => write!(f, "cannot read the DOS header"),
            Self::NtHeaders => write!(f, "cannot read the NT headers"),
            Self::NtSignature => write!(f, "missing PE signature"),
            Self::NtHeaders64 => write!(f, "cannot read the PE32+ headers"),
            Self::UnsupportedOptionalHeader { magic } => {
                write!(f, "unsupported optional header magic {magic:#x}")
            }
        }
    }
}

impl std::error::Error for PeError {}

/// Parsed PE headers (C++ `PEFile` header state after `Update()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeFile {
    /// DOS header.
    pub dos: DosHeader,
    /// COFF file header.
    pub file_header: FileHeader,
    /// Optional header (PE32 or PE32+).
    pub optional: OptionalHeader,
    /// `hdr64`: PE32+.
    pub is_pe64: bool,
    /// `sect[nrSections]` (zero-filled entries where unreadable).
    pub sections: Vec<SectionHeader>,
    /// `peStart` (`e_lfanew`).
    pub pe_start: u64,
    /// `sectStart`: file offset of the section table.
    pub section_table_offset: u64,
    /// `imageBase`.
    pub image_base: u64,
    /// `rvaEntryPoint`.
    pub entry_point_rva: u32,
    /// `fileAlign`.
    pub file_alignment: u32,
    /// `computedSize`: end of the last section's raw data (or the
    /// file size for the `SizeOfRawData = 0` trick).
    pub computed_size: u64,
    /// `virtualComputedSize`.
    pub virtual_computed_size: u64,
    /// `computedWithCertificate`.
    pub computed_with_certificate: u64,
    /// `hasOverlay`.
    pub has_overlay: bool,
    /// `overlaySize`.
    pub overlay_size: u64,
    /// `isMetroApp` (`AppContainer`).
    pub is_metro_app: bool,
    /// File size the headers were checked against.
    pub file_size: u64,
    /// `errList`.
    pub diagnostics: Vec<Diagnostic>,
}

fn read_file_header(buf: &[u8], at: usize) -> Option<FileHeader> {
    Some(FileHeader {
        machine: read_u16(buf, at)?,
        number_of_sections: read_u16(buf, at.checked_add(2)?)?,
        time_date_stamp: read_u32(buf, at.checked_add(4)?)?,
        pointer_to_symbol_table: read_u32(buf, at.checked_add(8)?)?,
        number_of_symbols: read_u32(buf, at.checked_add(12)?)?,
        size_of_optional_header: read_u16(buf, at.checked_add(16)?)?,
        characteristics: read_u16(buf, at.checked_add(18)?)?,
    })
}

fn read_directories(buf: &[u8], at: usize) -> Option<[DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES]> {
    let mut dirs = [DataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    for (i, dir) in dirs.iter_mut().enumerate() {
        let base = at.checked_add(i.checked_mul(8)?)?;
        dir.virtual_address = read_u32(buf, base)?;
        dir.size = read_u32(buf, base.checked_add(4)?)?;
    }
    Some(dirs)
}

/// Reads the optional header at `at`; `pe64` selects the PE32+ layout.
fn read_optional_header(buf: &[u8], at: usize, pe64: bool) -> Option<OptionalHeader> {
    let u16_at = |o: usize| read_u16(buf, at.checked_add(o)?);
    let u32_at = |o: usize| read_u32(buf, at.checked_add(o)?);
    let u64_at = |o: usize| read_u64(buf, at.checked_add(o)?);
    let mut h = OptionalHeader {
        magic: u16_at(0)?,
        major_linker_version: buf.get(at.checked_add(2)?).copied()?,
        minor_linker_version: buf.get(at.checked_add(3)?).copied()?,
        size_of_code: u32_at(4)?,
        size_of_initialized_data: u32_at(8)?,
        size_of_uninitialized_data: u32_at(12)?,
        address_of_entry_point: u32_at(16)?,
        base_of_code: u32_at(20)?,
        ..OptionalHeader::default()
    };
    if pe64 {
        h.image_base = u64_at(24)?;
        h.section_alignment = u32_at(32)?;
        h.file_alignment = u32_at(36)?;
        h.major_os_version = u16_at(40)?;
        h.minor_os_version = u16_at(42)?;
        h.major_image_version = u16_at(44)?;
        h.minor_image_version = u16_at(46)?;
        h.major_subsystem_version = u16_at(48)?;
        h.minor_subsystem_version = u16_at(50)?;
        h.win32_version_value = u32_at(52)?;
        h.size_of_image = u32_at(56)?;
        h.size_of_headers = u32_at(60)?;
        h.checksum = u32_at(64)?;
        h.subsystem = u16_at(68)?;
        h.dll_characteristics = u16_at(70)?;
        h.size_of_stack_reserve = u64_at(72)?;
        h.size_of_stack_commit = u64_at(80)?;
        h.size_of_heap_reserve = u64_at(88)?;
        h.size_of_heap_commit = u64_at(96)?;
        h.loader_flags = u32_at(104)?;
        h.number_of_rva_and_sizes = u32_at(108)?;
        h.data_directory = read_directories(buf, at.checked_add(112)?)?;
    } else {
        h.base_of_data = u32_at(24)?;
        h.image_base = u64::from(u32_at(28)?);
        h.section_alignment = u32_at(32)?;
        h.file_alignment = u32_at(36)?;
        h.major_os_version = u16_at(40)?;
        h.minor_os_version = u16_at(42)?;
        h.major_image_version = u16_at(44)?;
        h.minor_image_version = u16_at(46)?;
        h.major_subsystem_version = u16_at(48)?;
        h.minor_subsystem_version = u16_at(50)?;
        h.win32_version_value = u32_at(52)?;
        h.size_of_image = u32_at(56)?;
        h.size_of_headers = u32_at(60)?;
        h.checksum = u32_at(64)?;
        h.subsystem = u16_at(68)?;
        h.dll_characteristics = u16_at(70)?;
        h.size_of_stack_reserve = u64::from(u32_at(72)?);
        h.size_of_stack_commit = u64::from(u32_at(76)?);
        h.size_of_heap_reserve = u64::from(u32_at(80)?);
        h.size_of_heap_commit = u64::from(u32_at(84)?);
        h.loader_flags = u32_at(88)?;
        h.number_of_rva_and_sizes = u32_at(92)?;
        h.data_directory = read_directories(buf, at.checked_add(96)?)?;
    }
    Some(h)
}

fn read_section_header(buf: &[u8], at: usize) -> Option<SectionHeader> {
    let mut name = [0_u8; IMAGE_SIZEOF_SHORT_NAME];
    name.copy_from_slice(buf.get(at..at.checked_add(IMAGE_SIZEOF_SHORT_NAME)?)?);
    let u32_at = |o: usize| read_u32(buf, at.checked_add(o)?);
    let u16_at = |o: usize| read_u16(buf, at.checked_add(o)?);
    Some(SectionHeader {
        name,
        virtual_size: u32_at(8)?,
        virtual_address: u32_at(12)?,
        size_of_raw_data: u32_at(16)?,
        pointer_to_raw_data: u32_at(20)?,
        pointer_to_relocations: u32_at(24)?,
        pointer_to_linenumbers: u32_at(28)?,
        number_of_relocations: u16_at(32)?,
        number_of_linenumbers: u16_at(34)?,
        characteristics: u32_at(36)?,
    })
}

/// Reads `count` section headers at `offset` (unreadable ones are
/// zero-filled like the C++ `memset`); returns them with
/// `virtualComputedSize`.
fn read_section_table(bytes: &[u8], offset: u64, count: usize) -> (Vec<SectionHeader>, u64) {
    let mut sections = Vec::with_capacity(count);
    let mut virtual_computed_size = 0_u64;
    let mut at = offset;
    for _ in 0..count {
        let section = usize::try_from(at)
            .ok()
            .and_then(|a| read_section_header(bytes, a))
            .unwrap_or_default();
        if section.virtual_size > 0 && section.virtual_end() > virtual_computed_size {
            virtual_computed_size = section.virtual_end();
        }
        sections.push(section);
        at = at.saturating_add(IMAGE_SECTION_HEADER_SIZE as u64);
    }
    (sections, virtual_computed_size)
}

/// Consecutive-section and duplicate-name checks. Parity quirk: the
/// duplicate message numbers the *second* section as `tr + 1`, so two
/// equal first names read "Sections 2 and 3".
fn section_table_diagnostics(sections: &[SectionHeader], section_alignment: u32, diagnostics: &mut Vec<Diagnostic>) {
    for (i, section) in sections.iter().enumerate() {
        if let Some(next) = sections.get(i.saturating_add(1)) {
            let expected = u64::from(section.virtual_address)
                .saturating_add(u64::from(section_align(section.virtual_size, section_alignment)));
            if expected != u64::from(next.virtual_address) {
                diagnostics.push(Diagnostic::Error(format!(
                    "Section {} and {} are not consecutive.",
                    i.saturating_add(1),
                    i.saturating_add(2)
                )));
            }
        }
        if let Some(prev) = i.checked_sub(1).and_then(|p| sections.get(p)) {
            if prev.name == section.name {
                diagnostics.push(Diagnostic::Error(format!(
                    "Sections {} and {} have the same name: [{}]",
                    i.saturating_add(1),
                    i.saturating_add(2),
                    section.name_str()
                )));
            }
        }
    }
}

/// `computedWithCertificate` plus the "starts within the file" and
/// truncation diagnostics.
fn certificate_and_truncation(
    optional: &OptionalHeader,
    computed_size: u64,
    file_size: u64,
    diagnostics: &mut Vec<Diagnostic>,
) -> u64 {
    let mut computed_with_certificate = computed_size;
    let security = optional
        .data_directory
        .get(DirectoryType::Security as usize)
        .copied()
        .unwrap_or_default();
    if security.virtual_address > 0 && security.size > 0 {
        if u64::from(security.virtual_address) < computed_with_certificate {
            diagnostics.push(Diagnostic::Warning(String::from("Security certificate starts within the file")));
        }
        let cert_end = u64::from(security.virtual_address).saturating_add(u64::from(security.size));
        if cert_end > computed_with_certificate {
            computed_with_certificate = cert_end;
        }
    }
    if computed_size > file_size {
        let missing = computed_size.saturating_sub(file_size);
        let percent = missing.saturating_mul(100).checked_div(computed_size).unwrap_or(0);
        diagnostics.push(Diagnostic::Error(format!(
            "File is truncated. Missing {missing} bytes ({percent:3}%)"
        )));
    }
    computed_with_certificate
}

/// `SizeOfImage` validation against the last section's aligned end.
fn size_of_image_diagnostics(last: &SectionHeader, optional: &OptionalHeader, diagnostics: &mut Vec<Diagnostic>) {
    let align = optional.section_alignment;
    let mut tmp = last.virtual_end() as u32;
    if align > 0 {
        let rem = tmp.checked_rem(align).unwrap_or(0);
        let pad = align.wrapping_sub(rem).checked_rem(align).unwrap_or(0);
        tmp = tmp.wrapping_add(pad);
    }
    if tmp != optional.size_of_image {
        diagnostics.push(Diagnostic::Error(String::from("SizeOfImage is invalid")));
    } else if align > 0 && !optional.size_of_image.is_multiple_of(align) {
        diagnostics.push(Diagnostic::Warning(String::from("SizeOfImage unaligned")));
    }
}

impl PeFile {
    /// C++ `Update()` over the object's cache.
    ///
    /// # Errors
    ///
    /// [`PeError`] when the DOS / NT headers cannot be read or the
    /// optional header magic is unsupported (C++ `return false`).
    pub fn parse_cache(cache: &mut DataCache) -> Result<Self, PeError> {
        let file_size = cache.size();
        // Headers live in the first pages; read what is needed lazily.
        let lfanew = {
            let head = cache.copy_to_vec(0, 64, false).map_err(|_| PeError::DosHeader)?;
            dos_header_lfanew(&head).ok_or(PeError::DosHeader)?
        };
        let nt_end = u64::from(lfanew)
            .checked_add(IMAGE_NT_HEADERS64_SIZE as u64)
            .ok_or(PeError::NtHeaders)?;
        // Section table follows the optional header; read a generous
        // window (headers + up to 256 sections) and parse from bytes.
        let window = nt_end
            .saturating_add((MAX_NR_SECTIONS.saturating_mul(IMAGE_SECTION_HEADER_SIZE)) as u64)
            .min(file_size)
            .min(u64::from(u32::MAX));
        let bytes = cache
            .copy_to_vec(0, window as u32, false)
            .map_err(|_| PeError::NtHeaders)?;
        Self::parse_bytes(&bytes, file_size)
    }

    /// C++ `Update()` over the file's leading bytes (`bytes` must hold
    /// the headers and the section table; `file_size` is the whole
    /// object's size for the truncation / overlay checks).
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_bytes(bytes: &[u8], file_size: u64) -> Result<Self, PeError> {
        let lfanew = dos_header_lfanew(bytes).ok_or(PeError::DosHeader)?;
        let nt = lfanew as usize;
        let nt_end = nt.checked_add(IMAGE_NT_HEADERS32_SIZE).ok_or(PeError::NtHeaders)?;
        if nt_end > bytes.len() {
            return Err(PeError::NtHeaders);
        }
        if read_u32(bytes, nt) != Some(IMAGE_NT_SIGNATURE) {
            return Err(PeError::NtSignature);
        }
        let file_header = read_file_header(bytes, nt.checked_add(4).ok_or(PeError::NtHeaders)?).ok_or(PeError::NtHeaders)?;
        let opt_at = nt.checked_add(4 + IMAGE_FILE_HEADER_SIZE).ok_or(PeError::NtHeaders)?;
        let magic = read_u16(bytes, opt_at).ok_or(PeError::NtHeaders)?;
        let (optional, is_pe64) = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => (read_optional_header(bytes, opt_at, false).ok_or(PeError::NtHeaders)?, false),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let end64 = nt.checked_add(IMAGE_NT_HEADERS64_SIZE).ok_or(PeError::NtHeaders64)?;
                if end64 > bytes.len() {
                    return Err(PeError::NtHeaders64);
                }
                (read_optional_header(bytes, opt_at, true).ok_or(PeError::NtHeaders64)?, true)
            }
            other => return Err(PeError::UnsupportedOptionalHeader { magic: other }),
        };

        let mut diagnostics = Vec::new();
        let mut number_of_sections = usize::from(file_header.number_of_sections);
        if !(1..=MAX_NR_SECTIONS).contains(&number_of_sections) {
            diagnostics.push(Diagnostic::Error(format!(
                "Invalid number of sections ({number_of_sections})"
            )));
            number_of_sections = 0;
        }
        let is_metro_app = optional.dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0;
        if is_metro_app {
            diagnostics.push(Diagnostic::Warning(String::from("Image should execute in an AppContainer")));
        }

        // sectStart = e_lfanew + SizeOfOptionalHeader + 4 + sizeof(FileHeader)
        let section_table_offset = u64::from(lfanew)
            .saturating_add(u64::from(file_header.size_of_optional_header))
            .saturating_add(4)
            .saturating_add(IMAGE_FILE_HEADER_SIZE as u64);

        let (sections, virtual_computed_size) = read_section_table(bytes, section_table_offset, number_of_sections);
        section_table_diagnostics(&sections, optional.section_alignment, &mut diagnostics);

        // Recomputed from the last section (C++ "recalculez").
        let mut computed_size = 0_u64;
        if let Some(last) = sections.last() {
            computed_size = last.raw_end();
            if last.size_of_raw_data == 0 {
                computed_size = file_size;
                diagnostics.push(Diagnostic::Warning(String::from(
                    "File is using LastSection.SizeOfRawData = 0 trick",
                )));
            }
        }

        let computed_with_certificate = certificate_and_truncation(&optional, computed_size, file_size, &mut diagnostics);

        if let Some(last) = sections.last() {
            size_of_image_diagnostics(last, &optional, &mut diagnostics);
        }

        let mut pe = Self {
            dos: DosHeader {
                e_magic: read_u16(bytes, 0).unwrap_or_default(),
                e_lfanew: lfanew,
            },
            file_header,
            optional,
            is_pe64,
            sections,
            pe_start: u64::from(lfanew),
            section_table_offset,
            image_base: optional.image_base,
            entry_point_rva: optional.address_of_entry_point,
            file_alignment: optional.file_alignment,
            computed_size,
            virtual_computed_size,
            computed_with_certificate,
            has_overlay: false,
            overlay_size: 0,
            is_metro_app,
            file_size,
            diagnostics,
        };
        pe.check_entry_point(bytes);
        pe.check_directories();
        pe.has_overlay = pe.computed_size < file_size;
        pe.overlay_size = if pe.has_overlay {
            file_size.saturating_sub(pe.computed_size)
        } else {
            0
        };
        Ok(pe)
    }

    /// Entry-point diagnostics (`Update()` "EP" block).
    fn check_entry_point(&mut self, bytes: &[u8]) {
        let rva = self.entry_point_rva;
        let file_pos = self.rva_to_fa(u64::from(rva));
        if file_pos == PE_INVALID_ADDRESS {
            self.diagnostics
                .push(Diagnostic::Error(format!("Invalid Entry Point RVA (0x{rva:x})")));
            if u64::from(rva) < self.file_size {
                self.diagnostics
                    .push(Diagnostic::Warning(String::from("Entry Point is a File Address")));
            }
        } else if file_pos >= self.file_size {
            self.diagnostics.push(Diagnostic::Error(format!(
                "Entry Point is outside the file RVA=(0x{rva:x})"
            )));
        } else {
            let start = usize::try_from(file_pos).unwrap_or(usize::MAX);
            let sample = bytes
                .get(start..start.saturating_add(ENTRY_POINT_SAMPLE as usize).min(bytes.len()))
                .unwrap_or(&[]);
            if sample.is_empty() {
                // Beyond the parsed window but inside the file: the C++
                // reads from the cache; treat as unreadable here only
                // when past the file (handled above).
            } else if sample.iter().all(|&b| b == 0) {
                self.diagnostics.push(Diagnostic::Error(format!(
                    "Invalid code at Entry Point RVA=(0x{rva:x})"
                )));
            }
        }
        let ep_section = self.rva_to_section_index(u64::from(rva));
        if rva == 0 {
            self.diagnostics
                .push(Diagnostic::Warning(String::from("Posible executable resource file !")));
            if self.file_header.characteristics & IMAGE_FILE_DLL == 0 {
                self.diagnostics
                    .push(Diagnostic::Warning(String::from("NON-DLL file with EP RVA = 0")));
            }
        }
        match ep_section.and_then(|i| self.sections.get(i)) {
            None => {
                if rva > 0 {
                    self.diagnostics
                        .push(Diagnostic::Warning(String::from("EP is not inside any section")));
                }
            }
            Some(section) => {
                if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                    self.diagnostics.push(Diagnostic::Warning(String::from(
                        "EP section without Executable characteristic",
                    )));
                }
                if section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0 {
                    self.diagnostics.push(Diagnostic::Error(String::from(
                        "EP section cannot be executed (missing Write,Read and Executable attributes)",
                    )));
                }
            }
        }
    }

    /// Data-directory diagnostics (`Update()` "directoare" block).
    fn check_directories(&mut self) {
        let file_size = self.file_size;
        let dirs: Vec<DataDirectory> = self
            .optional
            .data_directory
            .iter()
            .take(INSPECTED_DIRECTORIES)
            .copied()
            .collect();
        for (i, dir) in dirs.iter().enumerate() {
            let name = DirectoryType::name(i as u32);
            if dir.virtual_address > 0 && dir.size > 0 {
                if u64::from(dir.size) > file_size {
                    self.diagnostics.push(Diagnostic::Warning(format!(
                        "Directory '{name}' (#{i}) has an invalid Size (0x{:08X})",
                        dir.size
                    )));
                }
                let file_pos = self.rva_to_fa(u64::from(dir.virtual_address));
                if file_pos == PE_INVALID_ADDRESS {
                    self.diagnostics.push(Diagnostic::Warning(format!(
                        "Directory '{name}' (#{i}) has an invalid RVA address (0x{:08X})",
                        dir.virtual_address
                    )));
                } else if file_pos.saturating_add(u64::from(dir.size)) > file_size {
                    self.diagnostics.push(Diagnostic::Warning(format!(
                        "Directory '{name}' (#{i}) extends outside the file (to: 0x{:08X})",
                        file_pos.saturating_add(u64::from(dir.size)) as u32
                    )));
                }
            }
            if dir.virtual_address == 0 && dir.size > 0 {
                self.diagnostics.push(Diagnostic::Warning(format!(
                    "Directory '{name}' (#{i}) has no address but size bigger than 0 ({} bytes)",
                    dir.size
                )));
            }
            if dir.virtual_address > 0 && dir.size == 0 {
                self.diagnostics.push(Diagnostic::Warning(format!(
                    "Directory '{name}' (#{i}) has size equal to 0 and a valid addrees (0x{:08X})",
                    dir.virtual_address
                )));
            }
        }
    }

    /// `nrSections`.
    #[must_use]
    pub const fn section_count(&self) -> u32 {
        self.sections.len() as u32
    }

    /// C++ `GetDirectory(type)`.
    #[must_use]
    pub fn directory(&self, kind: DirectoryType) -> DataDirectory {
        self.optional
            .data_directory
            .get(kind as usize)
            .copied()
            .unwrap_or_default()
    }

    /// C++ `RVAToSectionIndex`.
    #[must_use]
    pub fn rva_to_section_index(&self, rva: u64) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| rva >= u64::from(s.virtual_address) && rva < s.virtual_end())
    }

    /// C++ `RVAToFA`.
    #[must_use]
    pub fn rva_to_fa(&self, rva: u64) -> u64 {
        let Some(first) = self.sections.first() else {
            return PE_INVALID_ADDRESS;
        };
        if rva < u64::from(first.virtual_address) {
            return PE_INVALID_ADDRESS;
        }
        // The last section whose RVA does not exceed the address wins
        // (the C++ loop breaks at the first section *above* it).
        let mut chosen = first;
        for section in self.sections.iter().skip(1) {
            if rva < u64::from(section.virtual_address) {
                break;
            }
            chosen = section;
        }
        u64::from(chosen.pointer_to_raw_data).saturating_add(rva.saturating_sub(u64::from(chosen.virtual_address)))
    }

    /// C++ `FAToRVA`.
    #[must_use]
    pub fn fa_to_rva(&self, file_address: u64) -> u64 {
        for section in &self.sections {
            let raw_start = u64::from(section.pointer_to_raw_data);
            if file_address >= raw_start && file_address < section.raw_end() && section.virtual_address > 0 {
                let delta = file_address.saturating_sub(raw_start);
                if delta < u64::from(section.virtual_size) {
                    return delta.saturating_add(u64::from(section.virtual_address));
                }
            }
        }
        PE_INVALID_ADDRESS
    }

    /// C++ `FAToVA`.
    #[must_use]
    pub fn fa_to_va(&self, file_address: u64) -> u64 {
        match self.fa_to_rva(file_address) {
            PE_INVALID_ADDRESS => PE_INVALID_ADDRESS,
            rva => rva.saturating_add(self.image_base),
        }
    }

    /// C++ `VAtoFA`.
    #[must_use]
    pub fn va_to_fa(&self, va: u64) -> u64 {
        let rva = va.wrapping_sub(self.image_base);
        let Some(first) = self.sections.first() else {
            return PE_INVALID_ADDRESS;
        };
        if rva < u64::from(first.virtual_address) {
            return PE_INVALID_ADDRESS;
        }
        self.sections
            .iter()
            .find(|s| rva >= u64::from(s.virtual_address) && rva < s.virtual_end())
            .map_or(PE_INVALID_ADDRESS, |s| {
                rva.saturating_sub(u64::from(s.virtual_address))
                    .saturating_add(u64::from(s.pointer_to_raw_data))
            })
    }

    /// C++ `ConvertAddress`.
    #[must_use]
    pub fn convert_address(&self, address: u64, from: AddressType, to: AddressType) -> u64 {
        match (from, to) {
            (AddressType::FileOffset, AddressType::FileOffset)
            | (AddressType::Rva, AddressType::Rva)
            | (AddressType::Va, AddressType::Va) => address,
            (AddressType::FileOffset, AddressType::Va) => self.fa_to_va(address),
            (AddressType::FileOffset, AddressType::Rva) => self.fa_to_rva(address),
            (AddressType::Va, AddressType::FileOffset) => {
                if address > self.image_base {
                    self.rva_to_fa(address.wrapping_sub(self.image_base))
                } else {
                    PE_INVALID_ADDRESS
                }
            }
            (AddressType::Va, AddressType::Rva) => {
                if address > self.image_base {
                    address.wrapping_sub(self.image_base)
                } else {
                    PE_INVALID_ADDRESS
                }
            }
            (AddressType::Rva, AddressType::FileOffset) => self.rva_to_fa(address),
            (AddressType::Rva, AddressType::Va) => address.saturating_add(self.image_base),
        }
    }

    /// Errors only.
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.diagnostics.iter().filter_map(|d| match d {
            Diagnostic::Error(e) => Some(e.as_str()),
            Diagnostic::Warning(_) => None,
        })
    }

    /// Warnings only.
    pub fn warnings(&self) -> impl Iterator<Item = &str> {
        self.diagnostics.iter().filter_map(|d| match d {
            Diagnostic::Warning(w) => Some(w.as_str()),
            Diagnostic::Error(_) => None,
        })
    }
}

impl OffsetTranslate for PeFile {
    /// C++ `TranslateToFileOffset`: `ConvertAddress(value, from, FileOffset)`.
    fn translate_to_file_offset(&self, value: u64, from_translation_index: u32) -> u64 {
        AddressType::from_index(from_translation_index)
            .map_or(PE_INVALID_ADDRESS, |from| self.convert_address(value, from, AddressType::FileOffset))
    }

    /// C++ `TranslateFromFileOffset`: `ConvertAddress(value, FileOffset, to)`.
    fn translate_from_file_offset(&self, value: u64, to_translation_index: u32) -> u64 {
        AddressType::from_index(to_translation_index)
            .map_or(PE_INVALID_ADDRESS, |to| self.convert_address(value, AddressType::FileOffset, to))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub mod tests {
    use super::*;
    use crate::validate::{tests::minimal_pe, E_LFANEW_OFFSET, IMAGE_DOS_SIGNATURE};
    use gview_core::source::MemorySource;

    /// A section descriptor for [`build_image`].
    #[derive(Clone, Copy)]
    pub struct Sect {
        pub name: &'static [u8],
        pub va: u32,
        pub vsize: u32,
        pub raw: u32,
        pub rawsize: u32,
        pub chars: u32,
    }

    /// Builds a PE32 (or PE32+) image with the given sections, entry
    /// point RVA and image base; the file is padded to the end of the
    /// last section's raw data plus `overlay` bytes.
    ///
    /// # Panics
    ///
    /// When the generated headers do not parse (test fixture bug).
    #[must_use]
    pub fn build_image(pe64: bool, image_base: u64, entry_rva: u32, sections: &[Sect], overlay: usize) -> Vec<u8> {
        const LFANEW: u32 = 0x80;
        let magic = if pe64 { IMAGE_NT_OPTIONAL_HDR64_MAGIC } else { IMAGE_NT_OPTIONAL_HDR32_MAGIC };
        let mut image = minimal_pe(LFANEW, magic);
        if pe64 {
            image.resize(LFANEW as usize + IMAGE_NT_HEADERS64_SIZE, 0);
        }
        let nt = LFANEW as usize;
        let fh = nt + 4;
        image[fh..fh + 2].copy_from_slice(&0x014C_u16.to_le_bytes()); // I386
        image[fh + 2..fh + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        let opt_size: u16 = if pe64 { 240 } else { 224 };
        image[fh + 16..fh + 18].copy_from_slice(&opt_size.to_le_bytes());
        let opt = fh + IMAGE_FILE_HEADER_SIZE;
        image[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        if pe64 {
            image[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        } else {
            image[opt + 28..opt + 32].copy_from_slice(&(image_base as u32).to_le_bytes());
        }
        image[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes()); // SectionAlignment
        image[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes()); // FileAlignment
        let size_of_image = sections.last().map_or(0x1000, |s| {
            let end = s.va + s.vsize;
            (end + 0xFFF) & !0xFFF
        });
        image[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
        let sect_at = nt + 4 + IMAGE_FILE_HEADER_SIZE + opt_size as usize;
        let mut end = sect_at + sections.len() * IMAGE_SECTION_HEADER_SIZE;
        image.resize(end, 0);
        for (i, s) in sections.iter().enumerate() {
            let at = sect_at + i * IMAGE_SECTION_HEADER_SIZE;
            let mut name = [0_u8; 8];
            name[..s.name.len().min(8)].copy_from_slice(&s.name[..s.name.len().min(8)]);
            image[at..at + 8].copy_from_slice(&name);
            image[at + 8..at + 12].copy_from_slice(&s.vsize.to_le_bytes());
            image[at + 12..at + 16].copy_from_slice(&s.va.to_le_bytes());
            image[at + 16..at + 20].copy_from_slice(&s.rawsize.to_le_bytes());
            image[at + 20..at + 24].copy_from_slice(&s.raw.to_le_bytes());
            image[at + 36..at + 40].copy_from_slice(&s.chars.to_le_bytes());
            end = end.max((s.raw + s.rawsize) as usize);
        }
        image.resize(end + overlay, 0);
        // Non-zero code at the entry point.
        let mut pe = PeFile::parse_bytes(&image, image.len() as u64).expect("parse");
        pe.file_size = image.len() as u64;
        let ep = pe.rva_to_fa(u64::from(entry_rva));
        if ep != PE_INVALID_ADDRESS && (ep as usize) + 4 <= image.len() {
            image[ep as usize..ep as usize + 4].copy_from_slice(&[0x55, 0x8B, 0xEC, 0xC3]);
        }
        image
    }

    const TEXT: Sect = Sect {
        name: b".text",
        va: 0x1000,
        vsize: 0x800,
        raw: 0x400,
        rawsize: 0x800,
        chars: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    };
    const DATA: Sect = Sect {
        name: b".data",
        va: 0x2000,
        vsize: 0x300,
        raw: 0xC00,
        rawsize: 0x400,
        chars: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    };

    fn parse(image: &[u8]) -> PeFile {
        PeFile::parse_bytes(image, image.len() as u64).expect("parse")
    }

    #[test]
    fn parses_pe32_headers_sections_and_sizes() {
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let pe = parse(&image);
        assert!(!pe.is_pe64);
        assert_eq!(pe.dos.e_magic, IMAGE_DOS_SIGNATURE);
        assert_eq!(pe.dos.e_lfanew, 0x80);
        assert_eq!(pe.pe_start, 0x80);
        assert_eq!(pe.file_header.machine, 0x014C);
        assert_eq!(pe.section_count(), 2);
        assert_eq!(pe.section_table_offset, 0x80 + 4 + 20 + 224);
        assert_eq!(pe.image_base, 0x40_0000);
        assert_eq!(pe.entry_point_rva, 0x1010);
        assert_eq!(pe.file_alignment, 0x200);
        assert_eq!(pe.sections[0].name_str(), ".text");
        assert_eq!(pe.sections[1].name_str(), ".data");
        assert_eq!(pe.computed_size, 0xC00 + 0x400);
        assert_eq!(pe.virtual_computed_size, 0x2300);
        assert_eq!(pe.computed_with_certificate, pe.computed_size);
        assert!(!pe.has_overlay);
        assert_eq!(pe.overlay_size, 0);
        assert!(!pe.is_metro_app);
        assert_eq!(pe.errors().count(), 0, "{:?}", pe.diagnostics);
        assert_eq!(pe.directory(DirectoryType::Export), DataDirectory::default());
    }

    #[test]
    fn parses_pe64_image_base() {
        let image = build_image(true, 0x1_4000_0000, 0x1000, &[TEXT], 0);
        let pe = parse(&image);
        assert!(pe.is_pe64);
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.optional.magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        assert_eq!(pe.section_table_offset, 0x80 + 4 + 20 + 240);
        assert_eq!(pe.section_count(), 1);
    }

    #[test]
    fn rva_roundtrip_matches_cpp() {
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let pe = parse(&image);
        // Known RVA → file offset (spec `pe_rva_roundtrip`).
        assert_eq!(pe.rva_to_fa(0x1010), 0x410);
        assert_eq!(pe.rva_to_fa(0x2100), 0xD00);
        assert_eq!(pe.rva_to_fa(0x1000), 0x400);
        // Below the first section: invalid.
        assert_eq!(pe.rva_to_fa(0x800), PE_INVALID_ADDRESS);
        // Past the last section still maps into it (C++ quirk).
        assert_eq!(pe.rva_to_fa(0x9000), 0xC00 + 0x7000);
        // Gap between sections maps into the previous one (C++ quirk).
        assert_eq!(pe.rva_to_fa(0x1900), 0x400 + 0x900);

        assert_eq!(pe.fa_to_rva(0x410), 0x1010);
        assert_eq!(pe.fa_to_rva(0xD00), 0x2100);
        // Raw range beyond VirtualSize: invalid.
        assert_eq!(pe.fa_to_rva(0xC00 + 0x350), PE_INVALID_ADDRESS);
        assert_eq!(pe.fa_to_rva(0x100), PE_INVALID_ADDRESS);

        assert_eq!(pe.fa_to_va(0x410), 0x40_1010);
        assert_eq!(pe.fa_to_va(0x100), PE_INVALID_ADDRESS);
        assert_eq!(pe.va_to_fa(0x40_1010), 0x410);
        assert_eq!(pe.va_to_fa(0x40_0800), PE_INVALID_ADDRESS);
        assert_eq!(pe.va_to_fa(0x40_9000), PE_INVALID_ADDRESS, "VAtoFA needs a section");
        assert_eq!(pe.rva_to_section_index(0x1010), Some(0));
        assert_eq!(pe.rva_to_section_index(0x2000), Some(1));
        assert_eq!(pe.rva_to_section_index(0x2300), None);

        // ConvertAddress / translation list (0 = file offset, 1 = RVA, 2 = VA).
        assert_eq!(pe.translate_from_file_offset(0x410, 1), 0x1010);
        assert_eq!(pe.translate_from_file_offset(0x410, 2), 0x40_1010);
        assert_eq!(pe.translate_from_file_offset(0x410, 0), 0x410);
        assert_eq!(pe.translate_to_file_offset(0x1010, 1), 0x410);
        assert_eq!(pe.translate_to_file_offset(0x40_1010, 2), 0x410);
        assert_eq!(pe.translate_to_file_offset(0x410, 0), 0x410);
        assert_eq!(pe.translate_to_file_offset(0x410, 7), PE_INVALID_ADDRESS);
        // VA equal to the image base is rejected (strict `>`).
        assert_eq!(pe.convert_address(0x40_0000, AddressType::Va, AddressType::Rva), PE_INVALID_ADDRESS);
        assert_eq!(pe.convert_address(0x40_0000, AddressType::Va, AddressType::FileOffset), PE_INVALID_ADDRESS);
        assert_eq!(pe.convert_address(0x1010, AddressType::Rva, AddressType::Va), 0x40_1010);
        assert_eq!(pe.convert_address(0x40_2100, AddressType::Va, AddressType::Rva), 0x2100);
    }

    #[test]
    fn no_sections_makes_every_rva_invalid() {
        let image = build_image(false, 0x40_0000, 0, &[], 0);
        let pe = parse(&image);
        assert_eq!(pe.section_count(), 0);
        assert!(pe.errors().any(|e| e == "Invalid number of sections (0)"));
        assert_eq!(pe.rva_to_fa(0x1000), PE_INVALID_ADDRESS);
        assert_eq!(pe.va_to_fa(0x40_1000), PE_INVALID_ADDRESS);
        assert_eq!(pe.fa_to_rva(0), PE_INVALID_ADDRESS);
        assert!(pe.errors().any(|e| e.starts_with("Invalid Entry Point RVA")));
    }

    #[test]
    fn overlay_and_truncation_are_detected() {
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0x123);
        let pe = parse(&image);
        assert!(pe.has_overlay);
        assert_eq!(pe.overlay_size, 0x123);

        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let truncated = &image[..image.len() - 0x100];
        let pe = PeFile::parse_bytes(truncated, truncated.len() as u64).expect("parse");
        assert!(pe.errors().any(|e| e.starts_with("File is truncated. Missing 256 bytes")));
        assert!(!pe.has_overlay);
    }

    #[test]
    fn section_diagnostics_match_cpp() {
        // Non-consecutive + duplicate names + non-executable EP section.
        let dup = Sect {
            name: b".text",
            va: 0x3000,
            vsize: 0x100,
            raw: 0x1000,
            rawsize: 0x200,
            chars: 0,
        };
        let image = build_image(false, 0x40_0000, 0x3000, &[TEXT, dup], 0);
        let pe = parse(&image);
        let errors: Vec<&str> = pe.errors().collect();
        assert!(errors.contains(&"Section 1 and 2 are not consecutive."));
        // C++ numbers the second section as `tr + 1` here: "2 and 3".
        assert!(errors.contains(&"Sections 2 and 3 have the same name: [.text]"));
        assert!(errors.contains(&"EP section cannot be executed (missing Write,Read and Executable attributes)"));
        assert!(pe.warnings().any(|w| w == "EP section without Executable characteristic"));
        assert!(errors.contains(&"SizeOfImage is invalid") || pe.optional.size_of_image == 0x3100 + 0xF00);

        // SizeOfRawData = 0 trick on the last section.
        let trick = Sect {
            name: b".bss",
            va: 0x2000,
            vsize: 0x100,
            raw: 0,
            rawsize: 0,
            chars: IMAGE_SCN_MEM_READ,
        };
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, trick], 0x40);
        let pe = parse(&image);
        assert!(pe.warnings().any(|w| w == "File is using LastSection.SizeOfRawData = 0 trick"));
        assert_eq!(pe.computed_size, image.len() as u64);
        assert!(!pe.has_overlay);

        // Entry point zero on a non-DLL.
        let image = build_image(false, 0x40_0000, 0, &[TEXT], 0);
        let pe = parse(&image);
        assert!(pe.warnings().any(|w| w == "Posible executable resource file !"));
        assert!(pe.warnings().any(|w| w == "NON-DLL file with EP RVA = 0"));
        // RVA 0 is below the first section: invalid EP, and it is a file address.
        assert!(pe.errors().any(|e| e == "Invalid Entry Point RVA (0x0)"));
        assert!(pe.warnings().any(|w| w == "Entry Point is a File Address"));
    }

    #[test]
    fn directory_diagnostics_and_names() {
        let mut image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let opt = 0x80 + 4 + IMAGE_FILE_HEADER_SIZE;
        let dirs = opt + 96;
        // Export: valid RVA inside .data.
        image[dirs..dirs + 4].copy_from_slice(&0x2000_u32.to_le_bytes());
        image[dirs + 4..dirs + 8].copy_from_slice(&0x40_u32.to_le_bytes());
        // Import: no address but a size.
        image[dirs + 8 + 4..dirs + 16].copy_from_slice(&0x10_u32.to_le_bytes());
        // Resource: address, size 0.
        image[dirs + 16..dirs + 20].copy_from_slice(&0x2100_u32.to_le_bytes());
        // Exceptions: RVA below the first section (invalid), size huge.
        image[dirs + 24..dirs + 28].copy_from_slice(&0x10_u32.to_le_bytes());
        image[dirs + 28..dirs + 32].copy_from_slice(&0xFFFF_FFF0_u32.to_le_bytes());
        // Security: file offset past computed size → certificate grows the size.
        let sec = dirs + 4 * 8;
        image[sec..sec + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[sec + 4..sec + 8].copy_from_slice(&0x100_u32.to_le_bytes());
        let pe = parse(&image);
        let warnings: Vec<&str> = pe.warnings().collect();
        assert!(warnings.contains(&"Directory 'Import' (#1) has no address but size bigger than 0 (16 bytes)"));
        assert!(warnings.contains(&"Directory 'Resource' (#2) has size equal to 0 and a valid addrees (0x00002100)"));
        assert!(warnings.iter().any(|w| w.starts_with("Directory 'Exceptions' (#3) has an invalid Size")));
        assert!(warnings.contains(&"Directory 'Exceptions' (#3) has an invalid RVA address (0x00000010)"));
        assert_eq!(pe.computed_with_certificate, 0x1100);
        assert_eq!(pe.directory(DirectoryType::Export).size, 0x40);
        assert_eq!(DirectoryType::name(4), "Security");
        assert_eq!(DirectoryType::name(14), "COM+ Runtime");
        assert_eq!(DirectoryType::name(15), "");
        assert_eq!(DIRECTORY_NAMES.len(), 15);
    }

    #[test]
    fn header_errors_are_reported() {
        assert_eq!(PeFile::parse_bytes(b"", 0), Err(PeError::DosHeader));
        assert_eq!(PeFile::parse_bytes(&[0_u8; 64], 64), Err(PeError::DosHeader));
        let image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        assert_eq!(
            PeFile::parse_bytes(&image[..image.len() - 1], image.len() as u64 - 1),
            Err(PeError::NtHeaders)
        );
        let mut bad = image;
        bad[0x80] = b'X';
        assert_eq!(PeFile::parse_bytes(&bad, bad.len() as u64), Err(PeError::NtSignature));
        let rom = minimal_pe(0x80, 0x107);
        assert_eq!(
            PeFile::parse_bytes(&rom, rom.len() as u64),
            Err(PeError::UnsupportedOptionalHeader { magic: 0x107 })
        );
        let short64 = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        assert_eq!(PeFile::parse_bytes(&short64, short64.len() as u64), Err(PeError::NtHeaders64));
        let mut big = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        big[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(PeFile::parse_bytes(&big, big.len() as u64), Err(PeError::NtHeaders));
    }

    #[test]
    fn too_many_sections_are_rejected_and_unreadable_ones_zeroed() {
        let mut image = build_image(false, 0x40_0000, 0x1010, &[TEXT], 0);
        let fh = 0x80 + 4;
        image[fh + 2..fh + 4].copy_from_slice(&300_u16.to_le_bytes());
        let pe = parse(&image);
        assert_eq!(pe.section_count(), 0);
        assert!(pe.errors().any(|e| e == "Invalid number of sections (300)"));

        // Section table cut off: the unreadable header is zero-filled.
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let cut = 0x80 + 4 + 20 + 224 + 40 + 10;
        let pe = PeFile::parse_bytes(&image[..cut], image.len() as u64).expect("parse");
        assert_eq!(pe.section_count(), 2);
        assert_eq!(pe.sections[1], SectionHeader::default());
    }

    #[test]
    fn parse_from_cache_matches_parse_from_bytes() {
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0x10);
        let mut cache = DataCache::new(Box::new(MemorySource::from_slice(&image)), 0);
        let from_cache = PeFile::parse_cache(&mut cache).expect("cache");
        let from_bytes = parse(&image);
        assert_eq!(from_cache, from_bytes);
        let mut empty = DataCache::new(Box::new(MemorySource::from_slice(b"")), 0);
        assert_eq!(PeFile::parse_cache(&mut empty), Err(PeError::DosHeader));
    }

    #[test]
    fn section_align_and_name_helpers() {
        assert_eq!(section_align(0x800, 0x1000), 0x1000);
        assert_eq!(section_align(0x1000, 0x1000), 0x1000);
        assert_eq!(section_align(0x1001, 0x1000), 0x2000);
        assert_eq!(section_align(0, 0x1000), 0x1000);
        assert_eq!(section_align(0x123, 0), 0x123);
        let full = SectionHeader {
            name: *b"eightchr",
            ..SectionHeader::default()
        };
        assert_eq!(full.name_str(), "eightchr");
        assert_eq!(AddressType::from_index(3), None);
        assert_eq!(PE_INVALID_ADDRESS, u64::MAX);
        assert_eq!(MAX_NR_SECTIONS, 256);
    }
}
