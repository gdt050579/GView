//! ELF header parsing, tables and address translation.
//!
//! Spec `06_TYPE_PLUGINS` §ELF Header layout; C++ `ELFFile.cpp`
//! (`Update`, `ParseGoData`, `ParseSymbols`, `ConvertAddress`,
//! `FileOffsetToVA`, `VAToFileOffset`, `GetImageBase`,
//! `GetVirtualSize`, `HasPanel`) and `elf_types.hpp` layouts.
//!
//! [`ElfFile::parse_bytes`] / [`ElfFile::parse_cache`] are `Update()`:
//!
//! 1. `Elf32_Ehdr` at offset 0 (52 bytes); when `EI_CLASS` is not
//!    `ELFCLASS32` it must be `ELFCLASS64` and the 64-byte `Elf64_Ehdr`
//!    is read instead — anything else fails;
//! 2. the machine picks the `OpCodes` panel (Intel family);
//! 3. `e_phnum` program headers at `e_phoff`, each advancing by the
//!    **structure size** (not `e_phentsize`, as in C++); an entry that
//!    cannot be read fails the whole parse; `PF_X` segments feed
//!    `executable_zones`;
//! 4. `e_shnum` section headers at `e_shoff` (same rules); each section
//!    is mapped to the first segment with `p_vaddr != 0` that contains
//!    it (`sections_to_segments`);
//! 5. section names from `e_shstrndx` when it is neither `SHN_UNDEF`
//!    nor `>= SHN_LORESERVE` (the C++ leaves the `SHN_XINDEX` case as
//!    a `TODO`);
//! 6. `ParseGoData`: the **last** `PT_NOTE` segment's first note (Go
//!    build id / GNU build id) and the `.gopclntab` section (turns on
//!    the Go panels);
//! 7. `ParseSymbols`: `SHT_SYMTAB` / `SHT_DYNSYM` tables with names
//!    from `sh_link`.
//!
//! Parity notes:
//!
//! - all fields are read little-endian regardless of `EI_DATA`, exactly
//!   like the C++ `Copy<T>` into native structs (`is_little_endian` is
//!   recorded but never used for swapping);
//! - `FileOffsetToVA` / `VAToFileOffset` use an **inclusive** upper
//!   bound (`<= start + size`), replicated;
//! - `GetImageBase` returns `-1` (all bits set) without a `PT_LOAD`;
//! - the C++ reads section / symbol names with no bounds check and
//!   indexes `sections.at(sh_link)` (throws on a hostile file); here an
//!   out-of-range name yields an empty string and an out-of-range
//!   `sh_link` skips that symbol table;
//! - the Go `pclntab` decoder (`Golang::PcLnTab::Process`) is not
//!   ported yet: the section is located and the Go panels are enabled,
//!   but functions / files are not decoded; symbol names are stored
//!   undemangled (`GView::Utils::Demangle` has no Rust port yet).

use gview_core::cache::DataCache;
use gview_view::buffer_viewer::dissasm_dialog::OffsetTranslate;

/// `EI_NIDENT`.
pub const EI_NIDENT: usize = 16;
/// `EI_CLASS` index into `e_ident`.
pub const EI_CLASS: usize = 4;
/// `EI_DATA` index into `e_ident`.
pub const EI_DATA: usize = 5;
/// `EI_VERSION` index into `e_ident`.
pub const EI_VERSION: usize = 6;
/// `EI_OSABI` index into `e_ident`.
pub const EI_OSABI: usize = 7;
/// `EI_ABIVERSION` index into `e_ident`.
pub const EI_ABIVERSION: usize = 8;
/// `EI_PAD`: start of the `e_ident` padding bytes.
pub const EI_PAD: usize = 9;
/// `ELFCLASS32`.
pub const ELFCLASS32: u8 = 1;
/// `ELFCLASS64`.
pub const ELFCLASS64: u8 = 2;
/// `ELFDATA2LSB`.
pub const ELFDATA2LSB: u8 = 1;
/// `ELFDATA2MSB`.
pub const ELFDATA2MSB: u8 = 2;
/// `sizeof(Elf32_Ehdr)`.
pub const ELF32_EHDR_SIZE: usize = 52;
/// `sizeof(Elf64_Ehdr)`.
pub const ELF64_EHDR_SIZE: usize = 64;
/// `sizeof(Elf32_Phdr)`.
pub const ELF32_PHDR_SIZE: usize = 32;
/// `sizeof(Elf64_Phdr)`.
pub const ELF64_PHDR_SIZE: usize = 56;
/// `sizeof(Elf32_Shdr)`.
pub const ELF32_SHDR_SIZE: usize = 40;
/// `sizeof(Elf64_Shdr)`.
pub const ELF64_SHDR_SIZE: usize = 64;
/// `sizeof(Elf32_Sym)`.
pub const ELF32_SYM_SIZE: usize = 16;
/// `sizeof(Elf64_Sym)`.
pub const ELF64_SYM_SIZE: usize = 24;
/// `PT_LOAD`.
pub const PT_LOAD: u32 = 1;
/// `PT_NOTE`.
pub const PT_NOTE: u32 = 4;
/// `PF_X`.
pub const PF_X: u32 = 1;
/// `SHN_UNDEF`.
pub const SHN_UNDEF: u16 = 0;
/// `SHN_LORESERVE`.
pub const SHN_LORESERVE: u16 = 0xFF00;
/// `SHT_SYMTAB`.
pub const SHT_SYMTAB: u32 = 2;
/// `SHT_STRTAB`.
pub const SHT_STRTAB: u32 = 3;
/// `SHT_NOBITS`.
pub const SHT_NOBITS: u32 = 8;
/// `SHT_DYNSYM`.
pub const SHT_DYNSYM: u32 = 11;
/// C++ `ELF_INVALID_ADDRESS`.
pub const ELF_INVALID_ADDRESS: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// Minimal note header: `namesz`, `descsz`, `type`, 4 name bytes.
pub const NOTE_HEADER_SIZE: usize = 16;
/// `Golang::ELF_GO_BUILD_ID_TAG`.
pub const ELF_GO_BUILD_ID_TAG: u32 = 4;
/// `Golang::GNU_BUILD_ID_TAG`.
pub const GNU_BUILD_ID_TAG: u32 = 3;
/// `Golang::ELF_GO_NOTE` (`"Go\0\0"`).
pub const ELF_GO_NOTE: [u8; 4] = *b"Go\0\0";
/// `Golang::ELF_GNU_NOTE` (`"GNU\0"`).
pub const ELF_GNU_NOTE: [u8; 4] = *b"GNU\0";
/// The Go line table section.
pub const GOPCLNTAB_SECTION: &str = ".gopclntab";

/// `e_machine` values the plugin switches on (`elf_types.hpp`).
pub mod machine {
    /// `EM_386`.
    pub const EM_386: u16 = 3;
    /// `EM_486`.
    pub const EM_486: u16 = 6;
    /// `EM_860`.
    pub const EM_860: u16 = 7;
    /// `EM_960`.
    pub const EM_960: u16 = 19;
    /// `EM_ARM`.
    pub const EM_ARM: u16 = 40;
    /// `EM_X86_64`.
    pub const EM_X86_64: u16 = 62;
    /// `EM_8051`.
    pub const EM_8051: u16 = 165;
    /// `EM_AARCH64`.
    pub const EM_AARCH64: u16 = 183;
}

/// The Intel family that enables opcode colouring and the `OpCodes`
/// panel (`ELFFile::Update`, `elf.cpp` `CreateBufferView`).
#[must_use]
pub const fn is_intel_machine(machine: u16) -> bool {
    matches!(
        machine,
        machine::EM_386 | machine::EM_486 | machine::EM_860 | machine::EM_960 | machine::EM_8051 | machine::EM_X86_64
    )
}

/// C++ `Panels::IDs` (bit positions of `panelsMask`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PanelId {
    /// `Information`.
    Information = 0,
    /// `Segments`.
    Segments = 1,
    /// `Sections`.
    Sections = 2,
    /// `GoInformation` (also `GoFiles` and `GoFunctions`).
    GoInformation = 3,
    /// `StaticSymbols`.
    StaticSymbols = 4,
    /// `DynamicSymbols`.
    DynamicSymbols = 5,
    /// `OpCodes`.
    OpCodes = 6,
}

impl PanelId {
    /// Bit of this panel in the mask.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1_u64 << (self as u8)
    }
}

/// C++ `AddressType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// File offset.
    FileOffset = 0,
    /// Virtual address.
    VA = 1,
}

impl AddressType {
    /// `static_cast<AddressType>(index)`, bounded.
    #[must_use]
    pub const fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::FileOffset),
            1 => Some(Self::VA),
            _ => None,
        }
    }
}

/// `Elf32_Ehdr` / `Elf64_Ehdr` widened to 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ElfHeader {
    /// `e_ident`.
    pub ident: [u8; EI_NIDENT],
    /// `e_type`.
    pub e_type: u16,
    /// `e_machine`.
    pub machine: u16,
    /// `e_version`.
    pub version: u32,
    /// `e_entry`.
    pub entry: u64,
    /// `e_phoff`.
    pub phoff: u64,
    /// `e_shoff`.
    pub shoff: u64,
    /// `e_flags`.
    pub flags: u32,
    /// `e_ehsize`.
    pub ehsize: u16,
    /// `e_phentsize`.
    pub phentsize: u16,
    /// `e_phnum`.
    pub phnum: u16,
    /// `e_shentsize`.
    pub shentsize: u16,
    /// `e_shnum`.
    pub shnum: u16,
    /// `e_shstrndx`.
    pub shstrndx: u16,
}

/// `Elf32_Phdr` / `Elf64_Phdr` widened to 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    /// `p_type`.
    pub p_type: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`.
    pub offset: u64,
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_paddr`.
    pub paddr: u64,
    /// `p_filesz`.
    pub filesz: u64,
    /// `p_memsz`.
    pub memsz: u64,
    /// `p_align`.
    pub align: u64,
}

/// `Elf32_Shdr` / `Elf64_Shdr` widened to 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Section {
    /// `sh_name`.
    pub name: u32,
    /// `sh_type`.
    pub sh_type: u32,
    /// `sh_flags`.
    pub flags: u64,
    /// `sh_addr`.
    pub addr: u64,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// `sh_link`.
    pub link: u32,
    /// `sh_info`.
    pub info: u32,
    /// `sh_addralign`.
    pub addralign: u64,
    /// `sh_entsize`.
    pub entsize: u64,
}

/// `Elf32_Sym` / `Elf64_Sym` widened to 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Symbol {
    /// `st_name`.
    pub name: u32,
    /// `st_info`.
    pub info: u8,
    /// `st_other`.
    pub other: u8,
    /// `st_shndx`.
    pub shndx: u16,
    /// `st_value`.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
}

impl Symbol {
    /// `ELF_ST_BIND`.
    #[must_use]
    pub const fn bind(&self) -> u8 {
        self.info >> 4
    }

    /// `ELF_ST_TYPE`.
    #[must_use]
    pub const fn sym_type(&self) -> u8 {
        self.info & 0xF
    }
}

/// The first note of the last `PT_NOTE` segment (`ParseGoData`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoteInfo {
    /// `nameSize`.
    pub name_size: u32,
    /// `valSize`.
    pub val_size: u32,
    /// `tag`.
    pub tag: u32,
    /// `noteName` (the four name bytes, lossily decoded).
    pub note_name: String,
    /// Go build id (`ELF_GO_BUILD_ID_TAG` + `"Go\0\0"`).
    pub go_build_id: Option<String>,
    /// GNU build id bytes (`GNU_BUILD_ID_TAG` + `"GNU\0"`), C++ `gnuString`.
    pub gnu_build_id: Vec<u8>,
}

/// Failures of `Update()` (C++ `return false`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// The `Elf32_Ehdr` / `Elf64_Ehdr` cannot be read.
    Header,
    /// `EI_CLASS` is neither `ELFCLASS32` nor `ELFCLASS64`.
    UnsupportedClass(u8),
    /// Program header `index` cannot be read.
    ProgramHeader(u16),
    /// Section header `index` cannot be read.
    SectionHeader(u16),
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header => f.write_str("ELF header truncated"),
            Self::UnsupportedClass(c) => write!(f, "unsupported EI_CLASS {c}"),
            Self::ProgramHeader(i) => write!(f, "program header {i} truncated"),
            Self::SectionHeader(i) => write!(f, "section header {i} truncated"),
        }
    }
}

impl std::error::Error for ElfError {}

/// Where the parser reads from (`obj->GetData().Copy` /
/// `CopyToBuffer`): whole reads only, `None` when the range cannot be
/// served in full.
pub trait ElfSource {
    /// Reads exactly `size` bytes at `offset`.
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>>;
}

impl ElfSource for [u8] {
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(size as usize)?;
        self.get(start..end).map(<[u8]>::to_vec)
    }
}

impl ElfSource for DataCache {
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        self.copy_to_vec(offset, size, true).ok()
    }
}

// ---------------------------------------------------------------------------
// Little-endian field readers (C++ `Copy<T>` into native structs)
// ---------------------------------------------------------------------------

fn u8_at(buf: &[u8], at: usize) -> Option<u8> {
    buf.get(at).copied()
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    let lo = u32_at(buf, at)?;
    let hi = u32_at(buf, at.checked_add(4)?)?;
    Some(u64::from(lo) | (u64::from(hi) << 32))
}

/// `Elf32_Ehdr` (52 bytes).
fn read_ehdr32(buf: &[u8]) -> Option<ElfHeader> {
    let mut ident = [0_u8; EI_NIDENT];
    ident.copy_from_slice(buf.get(..EI_NIDENT)?);
    Some(ElfHeader {
        ident,
        e_type: u16_at(buf, 16)?,
        machine: u16_at(buf, 18)?,
        version: u32_at(buf, 20)?,
        entry: u64::from(u32_at(buf, 24)?),
        phoff: u64::from(u32_at(buf, 28)?),
        shoff: u64::from(u32_at(buf, 32)?),
        flags: u32_at(buf, 36)?,
        ehsize: u16_at(buf, 40)?,
        phentsize: u16_at(buf, 42)?,
        phnum: u16_at(buf, 44)?,
        shentsize: u16_at(buf, 46)?,
        shnum: u16_at(buf, 48)?,
        shstrndx: u16_at(buf, 50)?,
    })
}

/// `Elf64_Ehdr` (64 bytes).
fn read_ehdr64(buf: &[u8]) -> Option<ElfHeader> {
    let mut ident = [0_u8; EI_NIDENT];
    ident.copy_from_slice(buf.get(..EI_NIDENT)?);
    Some(ElfHeader {
        ident,
        e_type: u16_at(buf, 16)?,
        machine: u16_at(buf, 18)?,
        version: u32_at(buf, 20)?,
        entry: u64_at(buf, 24)?,
        phoff: u64_at(buf, 32)?,
        shoff: u64_at(buf, 40)?,
        flags: u32_at(buf, 48)?,
        ehsize: u16_at(buf, 52)?,
        phentsize: u16_at(buf, 54)?,
        phnum: u16_at(buf, 56)?,
        shentsize: u16_at(buf, 58)?,
        shnum: u16_at(buf, 60)?,
        shstrndx: u16_at(buf, 62)?,
    })
}

/// `Elf32_Phdr` (32 bytes) at `at`.
fn read_phdr32(buf: &[u8], at: usize) -> Option<Segment> {
    Some(Segment {
        p_type: u32_at(buf, at)?,
        offset: u64::from(u32_at(buf, at.checked_add(4)?)?),
        vaddr: u64::from(u32_at(buf, at.checked_add(8)?)?),
        paddr: u64::from(u32_at(buf, at.checked_add(12)?)?),
        filesz: u64::from(u32_at(buf, at.checked_add(16)?)?),
        memsz: u64::from(u32_at(buf, at.checked_add(20)?)?),
        flags: u32_at(buf, at.checked_add(24)?)?,
        align: u64::from(u32_at(buf, at.checked_add(28)?)?),
    })
}

/// `Elf64_Phdr` (56 bytes) at `at`.
fn read_phdr64(buf: &[u8], at: usize) -> Option<Segment> {
    Some(Segment {
        p_type: u32_at(buf, at)?,
        flags: u32_at(buf, at.checked_add(4)?)?,
        offset: u64_at(buf, at.checked_add(8)?)?,
        vaddr: u64_at(buf, at.checked_add(16)?)?,
        paddr: u64_at(buf, at.checked_add(24)?)?,
        filesz: u64_at(buf, at.checked_add(32)?)?,
        memsz: u64_at(buf, at.checked_add(40)?)?,
        align: u64_at(buf, at.checked_add(48)?)?,
    })
}

/// `Elf32_Shdr` (40 bytes) at `at`.
fn read_shdr32(buf: &[u8], at: usize) -> Option<Section> {
    Some(Section {
        name: u32_at(buf, at)?,
        sh_type: u32_at(buf, at.checked_add(4)?)?,
        flags: u64::from(u32_at(buf, at.checked_add(8)?)?),
        addr: u64::from(u32_at(buf, at.checked_add(12)?)?),
        offset: u64::from(u32_at(buf, at.checked_add(16)?)?),
        size: u64::from(u32_at(buf, at.checked_add(20)?)?),
        link: u32_at(buf, at.checked_add(24)?)?,
        info: u32_at(buf, at.checked_add(28)?)?,
        addralign: u64::from(u32_at(buf, at.checked_add(32)?)?),
        entsize: u64::from(u32_at(buf, at.checked_add(36)?)?),
    })
}

/// `Elf64_Shdr` (64 bytes) at `at`.
fn read_shdr64(buf: &[u8], at: usize) -> Option<Section> {
    Some(Section {
        name: u32_at(buf, at)?,
        sh_type: u32_at(buf, at.checked_add(4)?)?,
        flags: u64_at(buf, at.checked_add(8)?)?,
        addr: u64_at(buf, at.checked_add(16)?)?,
        offset: u64_at(buf, at.checked_add(24)?)?,
        size: u64_at(buf, at.checked_add(32)?)?,
        link: u32_at(buf, at.checked_add(40)?)?,
        info: u32_at(buf, at.checked_add(44)?)?,
        addralign: u64_at(buf, at.checked_add(48)?)?,
        entsize: u64_at(buf, at.checked_add(56)?)?,
    })
}

/// `Elf32_Sym` (16 bytes) at `at`.
fn read_sym32(buf: &[u8], at: usize) -> Option<Symbol> {
    Some(Symbol {
        name: u32_at(buf, at)?,
        value: u64::from(u32_at(buf, at.checked_add(4)?)?),
        size: u64::from(u32_at(buf, at.checked_add(8)?)?),
        info: u8_at(buf, at.checked_add(12)?)?,
        other: u8_at(buf, at.checked_add(13)?)?,
        shndx: u16_at(buf, at.checked_add(14)?)?,
    })
}

/// `Elf64_Sym` (24 bytes) at `at`.
fn read_sym64(buf: &[u8], at: usize) -> Option<Symbol> {
    Some(Symbol {
        name: u32_at(buf, at)?,
        info: u8_at(buf, at.checked_add(4)?)?,
        other: u8_at(buf, at.checked_add(5)?)?,
        shndx: u16_at(buf, at.checked_add(6)?)?,
        value: u64_at(buf, at.checked_add(8)?)?,
        size: u64_at(buf, at.checked_add(16)?)?,
    })
}

/// NUL-terminated string at `at` (bounded; empty when out of range).
fn cstr_at(buf: &[u8], at: u64) -> String {
    let Ok(start) = usize::try_from(at) else {
        return String::new();
    };
    buf.get(start..).map_or_else(String::new, |tail| {
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(tail.get(..end).unwrap_or(&[])).into_owned()
    })
}

/// Whole table read: `count * entry` bytes at `offset`, or `None` on
/// overflow / short read (the C++ fails on the first bad entry).
fn read_table<S: ElfSource + ?Sized>(source: &mut S, offset: u64, count: usize, entry: usize) -> Option<Vec<u8>> {
    let size = count.checked_mul(entry)?;
    if size == 0 {
        return Some(Vec::new());
    }
    let size = u32::try_from(size).ok()?;
    source.read_exact(offset, size)
}

/// C++ `ELFFile`: the parsed tables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElfFile {
    /// `is64`.
    pub is64: bool,
    /// `isLittleEndian` (`EI_DATA == ELFDATA2LSB`); informational.
    pub is_little_endian: bool,
    /// `header32` / `header64`.
    pub header: ElfHeader,
    /// `segments32` / `segments64`.
    pub segments: Vec<Segment>,
    /// `sections32` / `sections64`.
    pub sections: Vec<Section>,
    /// `sectionNames` (empty when the string table is unreadable).
    pub section_names: Vec<String>,
    /// `sectionsToSegments`: containing segment per section.
    pub sections_to_segments: Vec<Option<usize>>,
    /// `staticSymbols32` / `64`.
    pub static_symbols: Vec<Symbol>,
    /// `staticSymbolsNames`.
    pub static_symbol_names: Vec<String>,
    /// `dynamicSymbols32` / `64`.
    pub dynamic_symbols: Vec<Symbol>,
    /// `dynamicSymbolsNames`.
    pub dynamic_symbol_names: Vec<String>,
    /// `executableZonesFAs`: `[p_offset, p_offset + p_filesz)` of every
    /// `PF_X` segment.
    pub executable_zones: Vec<(u64, u64)>,
    /// `ParseGoData` note facts.
    pub note: NoteInfo,
    /// `.gopclntab` `(offset, size)` when present.
    pub go_pclntab: Option<(u64, u64)>,
    /// `panelsMask`.
    pub panels_mask: u64,
}

impl ElfFile {
    /// C++ `Update()` over the object's cache.
    ///
    /// # Errors
    ///
    /// [`ElfError`] when a header or table entry cannot be read.
    pub fn parse_cache(cache: &mut DataCache) -> Result<Self, ElfError> {
        Self::parse_source(cache)
    }

    /// C++ `Update()` over an in-memory image.
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, ElfError> {
        let mut bytes = bytes.to_vec();
        Self::parse_source(bytes.as_mut_slice())
    }

    /// `Update()` over any [`ElfSource`].
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_source<S: ElfSource + ?Sized>(source: &mut S) -> Result<Self, ElfError> {
        let mut elf = Self {
            panels_mask: PanelId::Information.bit() | PanelId::Segments.bit() | PanelId::Sections.bit(),
            ..Self::default()
        };

        // Elf32_Ehdr first; EI_CLASS decides whether to re-read as 64.
        let head32 = source.read_exact(0, ELF32_EHDR_SIZE as u32).ok_or(ElfError::Header)?;
        let header32 = read_ehdr32(&head32).ok_or(ElfError::Header)?;
        let class = header32.ident.get(EI_CLASS).copied().unwrap_or(0);
        if class == ELFCLASS32 {
            elf.header = header32;
        } else if class == ELFCLASS64 {
            let head64 = source.read_exact(0, ELF64_EHDR_SIZE as u32).ok_or(ElfError::Header)?;
            elf.header = read_ehdr64(&head64).ok_or(ElfError::Header)?;
            elf.is64 = true;
        } else {
            return Err(ElfError::UnsupportedClass(class));
        }

        if is_intel_machine(elf.header.machine) {
            elf.panels_mask |= PanelId::OpCodes.bit();
        }
        elf.is_little_endian = elf.header.ident.get(EI_DATA).copied() == Some(ELFDATA2LSB);

        elf.read_segments(source)?;
        elf.read_sections(source)?;
        elf.read_section_names(source);
        elf.parse_go_data(source);
        elf.parse_symbols(source);
        Ok(elf)
    }

    /// Program header table (`sizeof(entry)` stride, like the C++).
    fn read_segments<S: ElfSource + ?Sized>(&mut self, source: &mut S) -> Result<(), ElfError> {
        let count = usize::from(self.header.phnum);
        let entry = if self.is64 { ELF64_PHDR_SIZE } else { ELF32_PHDR_SIZE };
        let table = read_table(source, self.header.phoff, count, entry).ok_or(ElfError::ProgramHeader(0))?;
        self.segments.reserve(count);
        for i in 0..count {
            let at = i.checked_mul(entry).ok_or(ElfError::ProgramHeader(i as u16))?;
            let segment = if self.is64 { read_phdr64(&table, at) } else { read_phdr32(&table, at) };
            let segment = segment.ok_or(ElfError::ProgramHeader(i as u16))?;
            if segment.flags & PF_X == PF_X {
                self.executable_zones
                    .push((segment.offset, segment.offset.wrapping_add(segment.filesz)));
            }
            self.segments.push(segment);
        }
        Ok(())
    }

    /// Section header table plus the section → segment map.
    fn read_sections<S: ElfSource + ?Sized>(&mut self, source: &mut S) -> Result<(), ElfError> {
        let count = usize::from(self.header.shnum);
        let entry = if self.is64 { ELF64_SHDR_SIZE } else { ELF32_SHDR_SIZE };
        let table = read_table(source, self.header.shoff, count, entry).ok_or(ElfError::SectionHeader(0))?;
        self.sections.reserve(count);
        self.sections_to_segments.reserve(count);
        for i in 0..count {
            let at = i.checked_mul(entry).ok_or(ElfError::SectionHeader(i as u16))?;
            let section = if self.is64 { read_shdr64(&table, at) } else { read_shdr32(&table, at) };
            let section = section.ok_or(ElfError::SectionHeader(i as u16))?;
            let segment_index = self.segments.iter().position(|segment| {
                segment.vaddr != 0
                    && section.addr >= segment.vaddr
                    && section.addr.wrapping_add(section.size) <= segment.vaddr.wrapping_add(segment.filesz)
            });
            self.sections.push(section);
            self.sections_to_segments.push(segment_index);
        }
        Ok(())
    }

    /// Section names from `e_shstrndx` (skipped for `SHN_UNDEF`, for
    /// `>= SHN_LORESERVE` — C++ `TODO` — and for an index past the
    /// table, where the C++ `.at()` would throw).
    fn read_section_names<S: ElfSource + ?Sized>(&mut self, source: &mut S) {
        let index = self.header.shstrndx;
        if index == SHN_UNDEF || index >= SHN_LORESERVE {
            return;
        }
        let Some(shstrtab) = self.sections.get(usize::from(index)).copied() else {
            return;
        };
        let Some(buffer) = source.read_exact(shstrtab.offset, shstrtab.size as u32) else {
            return;
        };
        self.section_names = self
            .sections
            .iter()
            .map(|section| cstr_at(&buffer, u64::from(section.name)))
            .collect();
    }

    /// C++ `ParseGoData`: the last `PT_NOTE` segment's first note and
    /// the `.gopclntab` section.
    fn parse_go_data<S: ElfSource + ?Sized>(&mut self, source: &mut S) {
        let mut note_buffer: Option<Vec<u8>> = None;
        for segment in self.segments.iter().filter(|s| s.p_type == PT_NOTE) {
            // The C++ overwrites on every PT_NOTE (an unreadable one
            // clears the buffer).
            note_buffer = source.read_exact(segment.offset, segment.filesz as u32);
        }
        if let Some(buffer) = note_buffer.filter(|b| b.len() >= NOTE_HEADER_SIZE) {
            let name_size = u32_at(&buffer, 0).unwrap_or(0);
            let val_size = u32_at(&buffer, 4).unwrap_or(0);
            let tag = u32_at(&buffer, 8).unwrap_or(0);
            let name: [u8; 4] = buffer
                .get(12..16)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .unwrap_or([0; 4]);
            self.note.name_size = name_size;
            self.note.val_size = val_size;
            self.note.tag = tag;
            self.note.note_name = String::from_utf8_lossy(&name).into_owned();
            let value_end = (NOTE_HEADER_SIZE as u64).saturating_add(u64::from(val_size));
            let value = (name_size == 4 && value_end <= buffer.len() as u64)
                .then(|| buffer.get(NOTE_HEADER_SIZE..value_end as usize))
                .flatten();
            if let Some(value) = value {
                if tag == ELF_GO_BUILD_ID_TAG && name == ELF_GO_NOTE {
                    self.note.go_build_id = Some(String::from_utf8_lossy(value).into_owned());
                }
                if tag == GNU_BUILD_ID_TAG && name == ELF_GNU_NOTE {
                    self.note.gnu_build_id = value.to_vec();
                }
            }
        }

        let pclntab = self
            .section_names
            .iter()
            .position(|name| name == GOPCLNTAB_SECTION)
            .and_then(|i| self.sections.get(i))
            .map(|section| (section.offset, section.size));
        if let Some(pclntab) = pclntab {
            self.panels_mask |= PanelId::GoInformation.bit();
            self.go_pclntab = Some(pclntab);
        }
    }

    /// C++ `ParseSymbols`: `SHT_SYMTAB` → static, `SHT_DYNSYM` → dynamic.
    fn parse_symbols<S: ElfSource + ?Sized>(&mut self, source: &mut S) {
        let sym_size = if self.is64 { ELF64_SYM_SIZE } else { ELF32_SYM_SIZE };
        let sections = self.sections.clone();
        for section in &sections {
            let is_static = section.sh_type == SHT_SYMTAB;
            let is_dynamic = section.sh_type == SHT_DYNSYM;
            if !is_static && !is_dynamic {
                continue;
            }
            self.panels_mask |= if is_static {
                PanelId::StaticSymbols.bit()
            } else {
                PanelId::DynamicSymbols.bit()
            };
            let Some(strtab) = sections.get(section.link as usize) else {
                continue;
            };
            let Some(symbols) = source.read_exact(section.offset, section.size as u32) else {
                continue;
            };
            let names = source.read_exact(strtab.offset, strtab.size as u32).unwrap_or_default();
            let mut offset = 0_usize;
            while offset < symbols.len() {
                let symbol = if self.is64 { read_sym64(&symbols, offset) } else { read_sym32(&symbols, offset) };
                let Some(symbol) = symbol else {
                    break;
                };
                let name = cstr_at(&names, u64::from(symbol.name));
                if is_static {
                    self.static_symbols.push(symbol);
                    self.static_symbol_names.push(name);
                } else {
                    self.dynamic_symbols.push(symbol);
                    self.dynamic_symbol_names.push(name);
                }
                let Some(next) = offset.checked_add(sym_size) else {
                    break;
                };
                offset = next;
            }
        }
    }

    /// C++ `HasPanel`.
    #[must_use]
    pub const fn has_panel(&self, id: PanelId) -> bool {
        self.panels_mask & id.bit() != 0
    }

    /// Name of section `index` (empty when names were not read).
    #[must_use]
    pub fn section_name(&self, index: usize) -> &str {
        self.section_names.get(index).map_or("", String::as_str)
    }

    /// C++ `ConvertAddress`.
    #[must_use]
    pub fn convert_address(&self, address: u64, from: AddressType, to: AddressType) -> u64 {
        match (from, to) {
            (AddressType::FileOffset, AddressType::FileOffset) | (AddressType::VA, AddressType::VA) => address,
            (AddressType::FileOffset, AddressType::VA) => self.file_offset_to_va(address),
            (AddressType::VA, AddressType::FileOffset) => self.va_to_file_offset(address),
        }
    }

    /// C++ `FileOffsetToVA`: first section whose
    /// `[sh_offset, sh_offset + sh_size]` (inclusive) contains the offset.
    #[must_use]
    pub fn file_offset_to_va(&self, file_offset: u64) -> u64 {
        self.sections
            .iter()
            .find(|s| s.offset <= file_offset && file_offset <= s.offset.wrapping_add(s.size))
            .map_or(ELF_INVALID_ADDRESS, |s| {
                s.addr.wrapping_add(file_offset.wrapping_sub(s.offset))
            })
    }

    /// C++ `VAToFileOffset`: first section with `sh_addr != 0` whose
    /// `[sh_addr, sh_addr + sh_size]` (inclusive) contains the address.
    #[must_use]
    pub fn va_to_file_offset(&self, virtual_address: u64) -> u64 {
        self.sections
            .iter()
            .find(|s| s.addr != 0 && s.addr <= virtual_address && virtual_address <= s.addr.wrapping_add(s.size))
            .map_or(ELF_INVALID_ADDRESS, |s| {
                s.offset.wrapping_add(virtual_address.wrapping_sub(s.addr))
            })
    }

    /// C++ `GetImageBase`: `p_vaddr` of the first `PT_LOAD` (or `-1`).
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.segments
            .iter()
            .find(|s| s.p_type == PT_LOAD)
            .map_or(ELF_INVALID_ADDRESS, |s| s.vaddr)
    }

    /// C++ `GetVirtualSize`: sum of `p_memsz` over `PT_LOAD` segments.
    #[must_use]
    pub fn virtual_size(&self) -> u64 {
        self.segments
            .iter()
            .filter(|s| s.p_type == PT_LOAD)
            .fold(0_u64, |acc, s| acc.wrapping_add(s.memsz))
    }

    /// `elf.cpp` `CreateBufferView` entry point: the first segment with
    /// `p_vaddr <= e_entry < p_vaddr + p_memsz` maps it to a file
    /// offset; otherwise 0.
    #[must_use]
    pub fn entry_point_file_offset(&self) -> u64 {
        let entry = self.header.entry;
        self.segments
            .iter()
            .find(|s| s.vaddr <= entry && entry < s.vaddr.wrapping_add(s.memsz))
            .map_or(0, |s| entry.wrapping_sub(s.vaddr).wrapping_add(s.offset))
    }

    /// Whether `offset` lies in an executable segment
    /// (`executableZonesFAs` lookup of `GetColorForBuffer`).
    #[must_use]
    pub fn is_in_executable_zone(&self, offset: u64) -> bool {
        self.executable_zones
            .iter()
            .any(|&(start, end)| offset >= start && offset < end)
    }
}

impl OffsetTranslate for ElfFile {
    /// C++ `TranslateToFileOffset`.
    fn translate_to_file_offset(&self, value: u64, from_translation_index: u32) -> u64 {
        AddressType::from_index(from_translation_index)
            .map_or(ELF_INVALID_ADDRESS, |from| self.convert_address(value, from, AddressType::FileOffset))
    }

    /// C++ `TranslateFromFileOffset`.
    fn translate_from_file_offset(&self, value: u64, to_translation_index: u32) -> u64 {
        AddressType::from_index(to_translation_index)
            .map_or(ELF_INVALID_ADDRESS, |to| self.convert_address(value, AddressType::FileOffset, to))
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::branches_sharing_code,
    clippy::doc_markdown,
    clippy::redundant_clone
)]
pub mod tests {
    use super::*;
    use gview_core::object::Object;

    /// A section to lay out.
    #[derive(Clone)]
    pub struct SectionSpec {
        pub name: &'static str,
        pub sh_type: u32,
        pub addr: u64,
        pub data: Vec<u8>,
        pub link: u32,
        pub entsize: u64,
    }

    impl SectionSpec {
        pub fn new(name: &'static str, sh_type: u32, addr: u64, data: Vec<u8>) -> Self {
            Self {
                name,
                sh_type,
                addr,
                data,
                link: 0,
                entsize: 0,
            }
        }
    }

    /// A segment covering `sections` (contiguous, in order) with
    /// `flags`; `vaddr` is that of the first section.
    #[derive(Clone, Copy)]
    pub struct SegmentSpec {
        pub p_type: u32,
        pub flags: u32,
        pub first_section: usize,
        pub last_section: usize,
        pub extra_memsz: u64,
    }

    /// Builds an ELF image: header, section data in order (section 0
    /// is the mandatory NULL section, `.shstrtab` is appended last),
    /// then the program header table and the section header table.
    ///
    /// # Panics
    ///
    /// On an inconsistent spec (test fixture bug).
    #[must_use]
    pub fn build_elf(is64: bool, machine: u16, entry: u64, sections: &[SectionSpec], segments: &[SegmentSpec]) -> Vec<u8> {
        let ehsize = if is64 { ELF64_EHDR_SIZE } else { ELF32_EHDR_SIZE };
        let phsize = if is64 { ELF64_PHDR_SIZE } else { ELF32_PHDR_SIZE };
        let shsize = if is64 { ELF64_SHDR_SIZE } else { ELF32_SHDR_SIZE };
        let mut image = vec![0_u8; ehsize];

        // Section name string table.
        let mut shstrtab = vec![0_u8];
        let mut name_offsets = Vec::new();
        for s in sections {
            name_offsets.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(s.name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        // Section data.
        let mut layout: Vec<(u64, u64)> = vec![(0, 0)]; // NULL section
        for s in sections {
            let offset = image.len() as u64;
            image.extend_from_slice(&s.data);
            layout.push((offset, s.data.len() as u64));
            while image.len() % 8 != 0 {
                image.push(0);
            }
        }
        let shstrtab_offset = image.len() as u64;
        image.extend_from_slice(&shstrtab);
        while image.len() % 8 != 0 {
            image.push(0);
        }

        // Program headers.
        let phoff = image.len() as u64;
        for seg in segments {
            let (first_off, _) = layout[seg.first_section + 1];
            let (last_off, last_size) = layout[seg.last_section + 1];
            let filesz = last_off + last_size - first_off;
            let vaddr = sections[seg.first_section].addr;
            let mut ph = vec![0_u8; phsize];
            if is64 {
                ph[0..4].copy_from_slice(&seg.p_type.to_le_bytes());
                ph[4..8].copy_from_slice(&seg.flags.to_le_bytes());
                ph[8..16].copy_from_slice(&first_off.to_le_bytes());
                ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
                ph[24..32].copy_from_slice(&vaddr.to_le_bytes());
                ph[32..40].copy_from_slice(&filesz.to_le_bytes());
                ph[40..48].copy_from_slice(&(filesz + seg.extra_memsz).to_le_bytes());
                ph[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
            } else {
                ph[0..4].copy_from_slice(&seg.p_type.to_le_bytes());
                ph[4..8].copy_from_slice(&(first_off as u32).to_le_bytes());
                ph[8..12].copy_from_slice(&(vaddr as u32).to_le_bytes());
                ph[12..16].copy_from_slice(&(vaddr as u32).to_le_bytes());
                ph[16..20].copy_from_slice(&(filesz as u32).to_le_bytes());
                ph[20..24].copy_from_slice(&((filesz + seg.extra_memsz) as u32).to_le_bytes());
                ph[24..28].copy_from_slice(&seg.flags.to_le_bytes());
                ph[28..32].copy_from_slice(&0x1000_u32.to_le_bytes());
            }
            image.extend_from_slice(&ph);
        }

        // Section headers: NULL, the specs, .shstrtab.
        let shoff = image.len() as u64;
        let mut all: Vec<(u32, u32, u64, u64, u64, u32, u64)> = vec![(0, 0, 0, 0, 0, 0, 0)];
        for (i, s) in sections.iter().enumerate() {
            let (off, size) = layout[i + 1];
            all.push((name_offsets[i], s.sh_type, s.addr, off, size, s.link, s.entsize));
        }
        all.push((shstrtab_name, SHT_STRTAB, 0, shstrtab_offset, shstrtab.len() as u64, 0, 0));
        for (name, sh_type, addr, off, size, link, entsize) in &all {
            let mut sh = vec![0_u8; shsize];
            if is64 {
                sh[0..4].copy_from_slice(&name.to_le_bytes());
                sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
                sh[16..24].copy_from_slice(&addr.to_le_bytes());
                sh[24..32].copy_from_slice(&off.to_le_bytes());
                sh[32..40].copy_from_slice(&size.to_le_bytes());
                sh[40..44].copy_from_slice(&link.to_le_bytes());
                sh[56..64].copy_from_slice(&entsize.to_le_bytes());
            } else {
                sh[0..4].copy_from_slice(&name.to_le_bytes());
                sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
                sh[12..16].copy_from_slice(&(*addr as u32).to_le_bytes());
                sh[16..20].copy_from_slice(&(*off as u32).to_le_bytes());
                sh[20..24].copy_from_slice(&(*size as u32).to_le_bytes());
                sh[24..28].copy_from_slice(&link.to_le_bytes());
                sh[36..40].copy_from_slice(&(*entsize as u32).to_le_bytes());
            }
            image.extend_from_slice(&sh);
        }

        // Header.
        image[0..4].copy_from_slice(b"\x7fELF");
        image[EI_CLASS] = if is64 { ELFCLASS64 } else { ELFCLASS32 };
        image[EI_DATA] = ELFDATA2LSB;
        image[6] = 1;
        image[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
        image[18..20].copy_from_slice(&machine.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        let shnum = all.len() as u16;
        let shstrndx = shnum - 1;
        if is64 {
            image[24..32].copy_from_slice(&entry.to_le_bytes());
            image[32..40].copy_from_slice(&phoff.to_le_bytes());
            image[40..48].copy_from_slice(&shoff.to_le_bytes());
            image[52..54].copy_from_slice(&(ehsize as u16).to_le_bytes());
            image[54..56].copy_from_slice(&(phsize as u16).to_le_bytes());
            image[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
            image[58..60].copy_from_slice(&(shsize as u16).to_le_bytes());
            image[60..62].copy_from_slice(&shnum.to_le_bytes());
            image[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        } else {
            image[24..28].copy_from_slice(&(entry as u32).to_le_bytes());
            image[28..32].copy_from_slice(&(phoff as u32).to_le_bytes());
            image[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
            image[40..42].copy_from_slice(&(ehsize as u16).to_le_bytes());
            image[42..44].copy_from_slice(&(phsize as u16).to_le_bytes());
            image[44..46].copy_from_slice(&(segments.len() as u16).to_le_bytes());
            image[46..48].copy_from_slice(&(shsize as u16).to_le_bytes());
            image[48..50].copy_from_slice(&shnum.to_le_bytes());
            image[50..52].copy_from_slice(&shstrndx.to_le_bytes());
        }
        image
    }

    /// `Elf_Sym` bytes.
    pub fn sym(is64: bool, name: u32, value: u64, size: u64, info: u8, shndx: u16) -> Vec<u8> {
        if is64 {
            let mut s = vec![0_u8; ELF64_SYM_SIZE];
            s[0..4].copy_from_slice(&name.to_le_bytes());
            s[4] = info;
            s[6..8].copy_from_slice(&shndx.to_le_bytes());
            s[8..16].copy_from_slice(&value.to_le_bytes());
            s[16..24].copy_from_slice(&size.to_le_bytes());
            s
        } else {
            let mut s = vec![0_u8; ELF32_SYM_SIZE];
            s[0..4].copy_from_slice(&name.to_le_bytes());
            s[4..8].copy_from_slice(&(value as u32).to_le_bytes());
            s[8..12].copy_from_slice(&(size as u32).to_le_bytes());
            s[12] = info;
            s[14..16].copy_from_slice(&shndx.to_le_bytes());
            s
        }
    }

    /// A note: `namesz`, `descsz`, `type`, name (4 bytes), desc.
    pub fn note(tag: u32, name: &[u8; 4], desc: &[u8]) -> Vec<u8> {
        let mut n = Vec::new();
        n.extend_from_slice(&4_u32.to_le_bytes());
        n.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        n.extend_from_slice(&tag.to_le_bytes());
        n.extend_from_slice(name);
        n.extend_from_slice(desc);
        n
    }

    /// A typical executable: `.text` (exec, at VA 0x40_1000), `.data`,
    /// `.symtab` + `.strtab`, `.dynsym` + `.dynstr`, `.note` in a
    /// `PT_NOTE` segment.
    pub fn typical(is64: bool, machine: u16) -> Vec<u8> {
        let strtab = b"\0main\0helper\0".to_vec();
        let mut symtab = sym(is64, 0, 0, 0, 0, 0);
        symtab.extend(sym(is64, 1, 0x40_1000, 0x20, 0x12, 1));
        symtab.extend(sym(is64, 6, 0x40_1020, 0x10, 0x12, 1));
        let dynstr = b"\0puts\0".to_vec();
        let mut dynsym = sym(is64, 0, 0, 0, 0, 0);
        dynsym.extend(sym(is64, 1, 0, 0, 0x12, 0));
        let sections = vec![
            SectionSpec::new(".text", 1, 0x40_1000, vec![0x90; 0x100]),
            SectionSpec::new(".data", 1, 0x40_2000, vec![0xAA; 0x40]),
            SectionSpec {
                link: 4,
                entsize: if is64 { 24 } else { 16 },
                ..SectionSpec::new(".symtab", SHT_SYMTAB, 0, symtab)
            },
            SectionSpec::new(".strtab", SHT_STRTAB, 0, strtab),
            SectionSpec {
                link: 6,
                entsize: if is64 { 24 } else { 16 },
                ..SectionSpec::new(".dynsym", SHT_DYNSYM, 0x40_0300, dynsym)
            },
            SectionSpec::new(".dynstr", SHT_STRTAB, 0x40_0340, dynstr),
            SectionSpec::new(".note.go.buildid", 7, 0x40_0200, note(ELF_GO_BUILD_ID_TAG, &ELF_GO_NOTE, b"abc/def")),
        ];
        let segments = vec![
            SegmentSpec {
                p_type: PT_LOAD,
                flags: 5,
                first_section: 0,
                last_section: 0,
                extra_memsz: 0x100,
            },
            SegmentSpec {
                p_type: PT_LOAD,
                flags: 6,
                first_section: 1,
                last_section: 1,
                extra_memsz: 0,
            },
            SegmentSpec {
                p_type: PT_NOTE,
                flags: 4,
                first_section: 6,
                last_section: 6,
                extra_memsz: 0,
            },
        ];
        build_elf(is64, machine, 0x40_1010, &sections, &segments)
    }

    #[test]
    fn parses_header_tables_names_and_symbols_for_both_classes() {
        for is64 in [false, true] {
            let image = typical(is64, machine::EM_X86_64);
            let elf = ElfFile::parse_bytes(&image).expect("parse");
            assert_eq!(elf.is64, is64);
            assert!(elf.is_little_endian);
            assert_eq!(elf.header.machine, machine::EM_X86_64);
            assert_eq!(elf.header.entry, 0x40_1010);
            assert_eq!(elf.header.phnum, 3);
            assert_eq!(elf.header.shnum, 9);
            assert_eq!(elf.header.ehsize as usize, if is64 { ELF64_EHDR_SIZE } else { ELF32_EHDR_SIZE });
            assert_eq!(elf.segments.len(), 3);
            assert_eq!(elf.sections.len(), 9);
            assert_eq!(
                elf.section_names,
                ["", ".text", ".data", ".symtab", ".strtab", ".dynsym", ".dynstr", ".note.go.buildid", ".shstrtab"]
            );
            // .text is in segment 0; .data in segment 1; others unmapped.
            assert_eq!(elf.sections_to_segments[1], Some(0));
            assert_eq!(elf.sections_to_segments[2], Some(1));
            assert_eq!(elf.sections_to_segments[3], None);
            // Executable zones: the PF_X segment only.
            let text = elf.sections[1];
            assert_eq!(elf.executable_zones, [(text.offset, text.offset + text.size)]);
            assert!(elf.is_in_executable_zone(text.offset));
            assert!(!elf.is_in_executable_zone(text.offset + text.size));
            // Symbols.
            assert_eq!(elf.static_symbol_names, ["", "main", "helper"]);
            assert_eq!(elf.static_symbols[1].value, 0x40_1000);
            assert_eq!(elf.static_symbols[2].size, 0x10);
            assert_eq!(elf.static_symbols[1].bind(), 1);
            assert_eq!(elf.static_symbols[1].sym_type(), 2);
            assert_eq!(elf.static_symbols[1].shndx, 1);
            assert_eq!(elf.dynamic_symbol_names, ["", "puts"]);
            // Note.
            assert_eq!(elf.note.name_size, 4);
            assert_eq!(elf.note.val_size, 7);
            assert_eq!(elf.note.tag, ELF_GO_BUILD_ID_TAG);
            assert_eq!(elf.note.note_name, "Go\0\0");
            assert_eq!(elf.note.go_build_id.as_deref(), Some("abc/def"));
            assert!(elf.note.gnu_build_id.is_empty());
            assert!(elf.go_pclntab.is_none());
            // Panels: Information, Segments, Sections, OpCodes (x86_64), symbols.
            for id in [
                PanelId::Information,
                PanelId::Segments,
                PanelId::Sections,
                PanelId::OpCodes,
                PanelId::StaticSymbols,
                PanelId::DynamicSymbols,
            ] {
                assert!(elf.has_panel(id), "{id:?}");
            }
            assert!(!elf.has_panel(PanelId::GoInformation));
            // Image base & virtual size.
            assert_eq!(elf.image_base(), 0x40_1000);
            assert_eq!(elf.virtual_size(), 0x100 + 0x100 + 0x40);
            // Entry point → file offset.
            assert_eq!(elf.entry_point_file_offset(), text.offset + 0x10);
        }
    }

    #[test]
    fn cache_and_bytes_paths_agree() {
        let image = typical(true, machine::EM_386);
        let mut object = Object::from_buffer(&image, "a.out", 0);
        let from_cache = ElfFile::parse_cache(object.data_mut()).expect("cache");
        let from_bytes = ElfFile::parse_bytes(&image).expect("bytes");
        assert_eq!(from_cache, from_bytes);
    }

    #[test]
    fn address_translation_matches_cpp_inclusive_bounds() {
        let image = typical(true, machine::EM_X86_64);
        let elf = ElfFile::parse_bytes(&image).expect("parse");
        let text = elf.sections[1];
        let data = elf.sections[2];
        assert_eq!(elf.file_offset_to_va(text.offset + 0x10), 0x40_1010);
        assert_eq!(elf.va_to_file_offset(0x40_1010), text.offset + 0x10);
        // Inclusive end (C++ `<=`).
        assert_eq!(elf.va_to_file_offset(0x40_1000 + 0x100), text.offset + 0x100);
        assert_eq!(elf.file_offset_to_va(data.offset + 0x40), 0x40_2040);
        // Offset 0 is inside the NULL section (offset 0, size 0) → VA 0.
        assert_eq!(elf.file_offset_to_va(0), 0);
        // Beyond everything.
        assert_eq!(elf.va_to_file_offset(0x9000_0000), ELF_INVALID_ADDRESS);
        assert_eq!(elf.file_offset_to_va(0xFFFF_FFF0), ELF_INVALID_ADDRESS);
        // Sections with sh_addr 0 never match a VA.
        let symtab = elf.sections[3];
        assert_eq!(elf.va_to_file_offset(symtab.offset), ELF_INVALID_ADDRESS);
        // convert_address identities and the OffsetTranslate wiring.
        assert_eq!(elf.convert_address(77, AddressType::FileOffset, AddressType::FileOffset), 77);
        assert_eq!(elf.convert_address(77, AddressType::VA, AddressType::VA), 77);
        assert_eq!(elf.translate_from_file_offset(text.offset, 1), 0x40_1000);
        assert_eq!(elf.translate_to_file_offset(0x40_1000, 1), text.offset);
        assert_eq!(elf.translate_to_file_offset(5, 0), 5);
        assert_eq!(elf.translate_from_file_offset(5, 7), ELF_INVALID_ADDRESS);
        assert_eq!(AddressType::from_index(1), Some(AddressType::VA));
        assert_eq!(AddressType::from_index(2), None);
    }

    #[test]
    fn go_pclntab_and_gnu_note_enable_panels() {
        let mut sections = vec![
            SectionSpec::new(".text", 1, 0x1000, vec![0xC3; 8]),
            SectionSpec::new(".gopclntab", 1, 0x2000, vec![0xFB, 0xFF, 0xFF, 0xFF, 0, 0, 1, 8]),
            SectionSpec::new(".note.gnu.build-id", 7, 0x3000, note(GNU_BUILD_ID_TAG, &ELF_GNU_NOTE, &[1, 2, 3, 4])),
        ];
        let segments = vec![SegmentSpec {
            p_type: PT_NOTE,
            flags: 4,
            first_section: 2,
            last_section: 2,
            extra_memsz: 0,
        }];
        let image = build_elf(false, machine::EM_ARM, 0x1000, &sections, &segments);
        let elf = ElfFile::parse_bytes(&image).expect("parse");
        assert!(elf.has_panel(PanelId::GoInformation));
        assert!(!elf.has_panel(PanelId::OpCodes), "ARM has no opcode panel");
        assert_eq!(elf.go_pclntab, Some((elf.sections[2].offset, 8)));
        assert_eq!(elf.note.gnu_build_id, [1, 2, 3, 4]);
        assert_eq!(elf.note.go_build_id, None);
        assert_eq!(elf.note.note_name, "GNU\0");
        // No PT_LOAD: image base is -1, virtual size 0, entry FA 0.
        assert_eq!(elf.image_base(), ELF_INVALID_ADDRESS);
        assert_eq!(elf.virtual_size(), 0);
        assert_eq!(elf.entry_point_file_offset(), 0);
        // A note whose descsz overruns the buffer is ignored.
        sections[2].data = {
            let mut n = note(GNU_BUILD_ID_TAG, &ELF_GNU_NOTE, &[9; 4]);
            n[4..8].copy_from_slice(&0x100_u32.to_le_bytes());
            n
        };
        let image = build_elf(false, machine::EM_ARM, 0x1000, &sections, &segments);
        let elf = ElfFile::parse_bytes(&image).expect("parse");
        assert!(elf.note.gnu_build_id.is_empty());
        assert_eq!(elf.note.val_size, 0x100);
        // Last PT_NOTE wins (an unreadable one clears the buffer).
        let mut twice = segments.clone();
        twice.push(SegmentSpec {
            p_type: PT_NOTE,
            flags: 4,
            first_section: 0,
            last_section: 0,
            extra_memsz: 0,
        });
        let image = build_elf(false, machine::EM_ARM, 0x1000, &sections, &twice);
        let elf = ElfFile::parse_bytes(&image).expect("parse");
        assert_eq!(elf.note, NoteInfo::default());
    }

    #[test]
    fn truncated_and_malformed_images_fail_or_degrade_safely() {
        assert_eq!(ElfFile::parse_bytes(b"\x7fELF\x01"), Err(ElfError::Header));
        let image = typical(false, machine::EM_386);
        // Header only: tables unreadable → ProgramHeader error.
        assert_eq!(ElfFile::parse_bytes(&image[..ELF32_EHDR_SIZE]), Err(ElfError::ProgramHeader(0)));
        // Class 3: unsupported.
        let mut bad_class = image.clone();
        bad_class[EI_CLASS] = 3;
        assert_eq!(ElfFile::parse_bytes(&bad_class), Err(ElfError::UnsupportedClass(3)));
        // 64-bit class on a 32-bit layout still reads (garbage fields),
        // then fails on the tables — never panics.
        let mut wrong_class = image.clone();
        wrong_class[EI_CLASS] = ELFCLASS64;
        assert!(ElfFile::parse_bytes(&wrong_class).is_err());
        // Cut inside the section header table → SectionHeader error.
        let cut = image.len() - 10;
        assert_eq!(ElfFile::parse_bytes(&image[..cut]), Err(ElfError::SectionHeader(0)));
        // Bad shstrndx (past the table): no names, no crash, Go panel off.
        let mut bad_strndx = image.clone();
        bad_strndx[50..52].copy_from_slice(&200_u16.to_le_bytes());
        let elf = ElfFile::parse_bytes(&bad_strndx).expect("parse");
        assert!(elf.section_names.is_empty());
        assert_eq!(elf.section_name(1), "");
        // SHN_XINDEX-style index: skipped like the C++ TODO.
        bad_strndx[50..52].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        assert!(ElfFile::parse_bytes(&bad_strndx).expect("parse").section_names.is_empty());
        // Huge phnum with a valid phoff: the table read fails cleanly.
        let mut huge = image.clone();
        huge[44..46].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        assert_eq!(ElfFile::parse_bytes(&huge), Err(ElfError::ProgramHeader(0)));
        // Big-endian flag: read little-endian anyway (C++ parity).
        let mut be = image.clone();
        be[EI_DATA] = ELFDATA2MSB;
        let elf = ElfFile::parse_bytes(&be).expect("parse");
        assert!(!elf.is_little_endian);
        assert_eq!(elf.header.machine, machine::EM_386);
    }

    #[test]
    fn symbol_tables_with_bad_links_or_names_are_bounded() {
        let is64 = true;
        let mut symtab = sym(is64, 0, 0, 0, 0, 0);
        symtab.extend(sym(is64, 0xFFFF, 0x10, 0, 0, 0)); // name past strtab
        symtab.extend_from_slice(&[1, 2, 3]); // trailing partial entry
        let sections = vec![
            SectionSpec {
                link: 2,
                ..SectionSpec::new(".symtab", SHT_SYMTAB, 0, symtab.clone())
            },
            SectionSpec::new(".strtab", SHT_STRTAB, 0, b"\0x\0".to_vec()),
            SectionSpec {
                link: 99, // out of range → skipped
                ..SectionSpec::new(".dynsym", SHT_DYNSYM, 0, symtab)
            },
        ];
        let image = build_elf(is64, machine::EM_AARCH64, 0, &sections, &[]);
        let elf = ElfFile::parse_bytes(&image).expect("parse");
        assert_eq!(elf.static_symbols.len(), 2);
        assert_eq!(elf.static_symbol_names, ["", ""]);
        assert!(elf.dynamic_symbols.is_empty());
        // The panel bits are set before the link check, like the C++.
        assert!(elf.has_panel(PanelId::StaticSymbols));
        assert!(elf.has_panel(PanelId::DynamicSymbols));
        assert!(!elf.has_panel(PanelId::OpCodes));
        assert!(elf.segments.is_empty());
        assert!(elf.executable_zones.is_empty());
    }

    #[test]
    fn constants_and_helpers() {
        assert!(is_intel_machine(machine::EM_386));
        assert!(is_intel_machine(machine::EM_8051));
        assert!(!is_intel_machine(machine::EM_ARM));
        assert_eq!(PanelId::OpCodes.bit(), 1 << 6);
        assert_eq!(ELF_GO_NOTE, *b"Go\0\0");
        assert_eq!(ELF_GNU_NOTE, *b"GNU\0");
        assert_eq!(ElfError::SectionHeader(3).to_string(), "section header 3 truncated");
        assert_eq!(ElfError::UnsupportedClass(9).to_string(), "unsupported EI_CLASS 9");
        assert_eq!(cstr_at(b"ab\0cd", 3), "cd");
        assert_eq!(cstr_at(b"ab\0cd", 5), "");
        assert_eq!(cstr_at(b"ab\0cd", u64::MAX), "");
        assert_eq!(cstr_at(b"abc", 0), "abc");
        let mut empty: [u8; 0] = [];
        assert_eq!(read_table(&mut empty[..], 0, 0, 8), Some(Vec::new()));
        assert_eq!(read_table(&mut empty[..], 0, usize::MAX, 8), None);
        assert_eq!(u64_at(&[1, 0, 0, 0, 2, 0, 0, 0], 0), Some(0x2_0000_0001));
        assert_eq!(u64_at(&[1, 0, 0, 0], 0), None);
    }
}
