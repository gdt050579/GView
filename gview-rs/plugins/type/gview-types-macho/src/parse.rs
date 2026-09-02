//! Mach-O header, load commands and fat-archive parsing.
//!
//! Spec `06_TYPE_PLUGINS` §Mach-O Load commands; C++ `MachOFile.cpp`
//! (`Update`, `SetHeaderInfo`, `SetHeader`, `SetLoadCommands`,
//! `SetSegmentsAndTheirSections`, `SetExecutableZones`, `SetDyldInfo`,
//! `SetIdDylibs`, `SetMain`, `SetSymbols`, `SetSourceVersion`,
//! `SetUUID`, `SetLinkEditData`, `SetVersionMin`, `ParseGoData`,
//! `ParseGoBuild`, `ParseGoBuildInfo`, `VAtoFA`), `Mac.hpp` layouts,
//! `Swap.hpp`, `Utils.hpp` `GetArchInfoFromCPUTypeAndSubtype`,
//! `NameMapping.hpp` `ArchInfoTable`.
//!
//! [`MachoFile::parse_bytes`] / [`MachoFile::parse_cache`] are `Update()`:
//!
//! 1. `SetHeaderInfo`: the magic classifies the file (thin / fat,
//!    32 / 64-bit, byte-swapped);
//! 2. thin: `mach_header` (28 or 32 bytes), then `ncmds` load commands
//!    walked by `cmdsize`, then every `Set*` stage over the command
//!    list — segments with their sections, executable zones
//!    (`initprot & EXECUTE`), `LC_DYLD_INFO(_ONLY)`, the dylib family,
//!    `LC_MAIN` / `LC_UNIXTHREAD` entry point, `LC_SYMTAB` symbols,
//!    `LC_SOURCE_VERSION`, `LC_UUID`, the `linkedit_data_command`
//!    family, `LC_VERSION_MIN_*`, the Go build id / build info and
//!    `__gopclntab`; the panel mask follows what was found;
//! 3. fat: `fat_header` then `nfat_arch` `fat_arch` / `fat_arch64`
//!    entries, each with the `mach_header` at its offset for the file
//!    type and the `ArchInfoTable` lookup.
//!
//! Every `Set*` stage in the C++ returns `bool` and `Update` ignores
//! it, so a stage that cannot read its data leaves partial state and
//! the rest continues; this port does the same. The C++ `throw`s
//! (duplicate `LC_MAIN` / `LC_DYLD_INFO` / `LC_SYMTAB` / `LC_UUID` /
//! `LC_SOURCE_VERSION` / `LC_VERSION_MIN_*`, an `LC_UNIXTHREAD` on a
//! CPU other than i386 / x86-64 / PowerPC, a big-endian Go build info)
//! become [`MachoError`]s.
//!
//! Parity notes and discrepancies:
//!
//! - all fields are read little-endian and byte-swapped when the
//!   magic is a `CIGAM` variant, exactly as `Swap.hpp` does — except
//!   that the C++ `SwapEndianInplace` over `char segname[16]`,
//!   `char sectname[16]` and `uint8 uuid[16]` **reverses** those byte
//!   arrays; that is not replicated (names and UUIDs keep their
//!   on-disk order);
//! - the load-command walk stops at a `cmdsize` below the 8-byte
//!   `load_command` header (the C++ would re-read the same offset
//!   `ncmds` times) and after [`MAX_LOAD_COMMANDS`] entries;
//! - dylib names are read at byte 24 of the command (the C++ pointer
//!   arithmetic), bounded to `cmdsize`;
//! - `VAtoFA` uses the inclusive `vmaddr + filesize - 1` upper bound
//!   with wrapping arithmetic and skips `__PAGEZERO`, as in C++;
//! - symbol names are stored undemangled (`GView::Utils::Demangle` has
//!   no Rust port yet) and the Go `pclntab` is located but not decoded.

use gview_core::cache::DataCache;

// ---------------------------------------------------------------------------
// Constants (`Mac.hpp`)
// ---------------------------------------------------------------------------

/// `MH_MAGIC`.
pub const MH_MAGIC: u32 = 0xFEED_FACE;
/// `MH_CIGAM`.
pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
/// `MH_MAGIC_64`.
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `MH_CIGAM_64`.
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
/// `FAT_MAGIC`.
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
/// `FAT_CIGAM`.
pub const FAT_CIGAM: u32 = 0xBEBA_FECA;
/// `FAT_MAGIC_64`.
pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// `FAT_CIGAM_64`.
pub const FAT_CIGAM_64: u32 = 0xBFBA_FECA;
/// `sizeof(fat_header)`.
pub const FAT_HEADER_SIZE: usize = 8;
/// `sizeof(fat_arch)`.
pub const FAT_ARCH_SIZE: usize = 20;
/// `sizeof(fat_arch64)`.
pub const FAT_ARCH64_SIZE: usize = 32;
/// `sizeof(mach_header)` without the 64-bit `reserved` field.
pub const MACH_HEADER_SIZE: usize = 28;
/// `sizeof(mach_header)` with `reserved` (64-bit).
pub const MACH_HEADER_64_SIZE: usize = 32;
/// `sizeof(load_command)`.
pub const LOAD_COMMAND_SIZE: usize = 8;
/// `sizeof(segment_command)`.
pub const SEGMENT_COMMAND_SIZE: usize = 56;
/// `sizeof(segment_command_64)`.
pub const SEGMENT_COMMAND_64_SIZE: usize = 72;
/// `sizeof(section)`.
pub const SECTION_SIZE: usize = 68;
/// `sizeof(section_64)`.
pub const SECTION_64_SIZE: usize = 80;
/// `sizeof(dyld_info_command)`.
pub const DYLD_INFO_COMMAND_SIZE: usize = 48;
/// Bytes the C++ walks before the dylib name (`cmd`, `cmdsize`,
/// `name.ptr` as u64, then `timestamp`, `current_version`,
/// `compatibility_version` — 4 + 4 + 4 + 4 + 4 + 4).
pub const DYLIB_NAME_OFFSET: usize = 24;
/// `sizeof(entry_point_command)`.
pub const ENTRY_POINT_COMMAND_SIZE: usize = 24;
/// `sizeof(symtab_command)`.
pub const SYMTAB_COMMAND_SIZE: usize = 24;
/// `sizeof(nlist)`.
pub const NLIST_SIZE: usize = 12;
/// `sizeof(nlist_64)`.
pub const NLIST_64_SIZE: usize = 16;
/// `sizeof(source_version_command)`.
pub const SOURCE_VERSION_COMMAND_SIZE: usize = 16;
/// `sizeof(uuid_command)`.
pub const UUID_COMMAND_SIZE: usize = 24;
/// `sizeof(linkedit_data_command)`.
pub const LINKEDIT_DATA_COMMAND_SIZE: usize = 16;
/// `sizeof(version_min_command)`.
pub const VERSION_MIN_COMMAND_SIZE: usize = 16;
/// Thread state starts 16 bytes into `LC_UNIXTHREAD` (`cmd`,
/// `cmdsize`, `flavor`, `count`).
pub const THREAD_STATE_OFFSET: usize = 16;
/// `i386_thread_state_t.eip` offset inside the state (11th `u32`).
pub const I386_EIP_OFFSET: usize = 40;
/// `x86_thread_state64_t.rip` offset inside the state (17th `u64`).
pub const X86_64_RIP_OFFSET: usize = 128;
/// `ppc_thread_state_t.srr0` / `ppc_thread_state64_t.srr0` offset.
pub const PPC_SRR0_OFFSET: usize = 0;
/// Hostile-input bound on the load-command walk (the C++ has none).
pub const MAX_LOAD_COMMANDS: u32 = 0x1_0000;
/// `CPU_ARCH_ABI64`.
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000;
/// `CPU_ARCH_ABI64_32`.
pub const CPU_ARCH_ABI64_32: i32 = 0x0200_0000;
/// `CPU_TYPE_ANY`.
pub const CPU_TYPE_ANY: i32 = -1;
/// `CPU_TYPE_MC680x0`.
pub const CPU_TYPE_MC680X0: i32 = 6;
/// `CPU_TYPE_I386`.
pub const CPU_TYPE_I386: i32 = 7;
/// `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_I386 | CPU_ARCH_ABI64;
/// `CPU_TYPE_HPPA`.
pub const CPU_TYPE_HPPA: i32 = 11;
/// `CPU_TYPE_ARM`.
pub const CPU_TYPE_ARM: i32 = 12;
/// `CPU_TYPE_MC88000`.
pub const CPU_TYPE_MC88000: i32 = 13;
/// `CPU_TYPE_SPARC`.
pub const CPU_TYPE_SPARC: i32 = 14;
/// `CPU_TYPE_I860`.
pub const CPU_TYPE_I860: i32 = 15;
/// `CPU_TYPE_POWERPC`.
pub const CPU_TYPE_POWERPC: i32 = 18;
/// `CPU_TYPE_POWERPC64`.
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
/// `CPU_TYPE_VEO`.
pub const CPU_TYPE_VEO: i32 = 255;
/// `CPU_TYPE_ARM64`.
pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
/// `CPU_SUBTYPE_MASK`.
pub const CPU_SUBTYPE_MASK: u32 = 0xFF00_0000;
/// `CPU_SUBTYPE_MULTIPLE`.
pub const CPU_SUBTYPE_MULTIPLE: i32 = -1;
/// `VMProtectionFlags::EXECUTE`.
pub const VM_PROT_EXECUTE: u32 = 0x4;
/// `VMProtectionFlags::READ | WRITE` (the `RW = 3` of `ParseGoBuildInfo`).
pub const VM_PROT_RW: u32 = 0x3;
/// `Golang` build id prefix inside `__TEXT`.
pub const GO_BUILD_ID_PREFIX: &[u8] = b"\xff Go build ID: \"";
/// `Golang` build id terminator.
pub const GO_BUILD_ID_END: &[u8] = b"\"\n \xff";
/// `buildInfoMagic`.
pub const GO_BUILD_INFO_MAGIC: &[u8] = b"\xff Go buildinf:";
/// `buildInfoSize`.
pub const GO_BUILD_INFO_SIZE: usize = 32;
/// `ptrOffset` inside the build info header.
pub const GO_BUILD_INFO_PTR_OFFSET: usize = 14;
/// `MaxVarintLen64`.
pub const MAX_VARINT_LEN64: usize = 10;
/// `__gopclntab`.
pub const GOPCLNTAB_SECTION: &str = "__gopclntab";
/// `__go_buildinfo`.
pub const GO_BUILDINFO_SECTION: &str = "__go_buildinfo";
/// `__TEXT`.
pub const TEXT_SEGMENT: &str = "__TEXT";
/// `__PAGEZERO`.
pub const PAGEZERO_SEGMENT: &str = "__PAGEZERO";
/// C++ `VAtoFA` failure value (`return -1`).
pub const MACHO_INVALID_ADDRESS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// `LoadCommandType` values the parser switches on.
pub mod lc {
    /// `REQ_DYLD`.
    pub const REQ_DYLD: u32 = 0x8000_0000;
    /// `SEGMENT`.
    pub const SEGMENT: u32 = 0x1;
    /// `SYMTAB`.
    pub const SYMTAB: u32 = 0x2;
    /// `UNIXTHREAD`.
    pub const UNIXTHREAD: u32 = 0x5;
    /// `LOAD_DYLIB`.
    pub const LOAD_DYLIB: u32 = 0xC;
    /// `ID_DYLIB`.
    pub const ID_DYLIB: u32 = 0xD;
    /// `LOAD_WEAK_DYLIB`.
    pub const LOAD_WEAK_DYLIB: u32 = 0x18 | REQ_DYLD;
    /// `SEGMENT_64`.
    pub const SEGMENT_64: u32 = 0x19;
    /// `UUID`.
    pub const UUID: u32 = 0x1B;
    /// `CODE_SIGNATURE`.
    pub const CODE_SIGNATURE: u32 = 0x1D;
    /// `SEGMENT_SPLIT_INFO`.
    pub const SEGMENT_SPLIT_INFO: u32 = 0x1E;
    /// `REEXPORT_DYLIB`.
    pub const REEXPORT_DYLIB: u32 = 0x1F | REQ_DYLD;
    /// `LAZY_LOAD_DYLIB`.
    pub const LAZY_LOAD_DYLIB: u32 = 0x20;
    /// `DYLD_INFO`.
    pub const DYLD_INFO: u32 = 0x22;
    /// `DYLD_INFO_ONLY`.
    pub const DYLD_INFO_ONLY: u32 = 0x22 | REQ_DYLD;
    /// `LOAD_UPWARD_DYLIB`.
    pub const LOAD_UPWARD_DYLIB: u32 = 0x23 | REQ_DYLD;
    /// `VERSION_MIN_MACOSX`.
    pub const VERSION_MIN_MACOSX: u32 = 0x24;
    /// `VERSION_MIN_IPHONEOS`.
    pub const VERSION_MIN_IPHONEOS: u32 = 0x25;
    /// `FUNCTION_STARTS`.
    pub const FUNCTION_STARTS: u32 = 0x26;
    /// `MAIN`.
    pub const MAIN: u32 = 0x28 | REQ_DYLD;
    /// `DATA_IN_CODE`.
    pub const DATA_IN_CODE: u32 = 0x29;
    /// `SOURCE_VERSION`.
    pub const SOURCE_VERSION: u32 = 0x2A;
    /// `DYLIB_CODE_SIGN_DRS`.
    pub const DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
    /// `LINKER_OPTIMIZATION_HINT`.
    pub const LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
    /// `VERSION_MIN_TVOS`.
    pub const VERSION_MIN_TVOS: u32 = 0x2F;
    /// `VERSION_MIN_WATCHOS`.
    pub const VERSION_MIN_WATCHOS: u32 = 0x30;
    /// `DYLD_EXPORTS_TRIE`.
    pub const DYLD_EXPORTS_TRIE: u32 = 0x33 | REQ_DYLD;
    /// `DYLD_CHAINED_FIXUPS`.
    pub const DYLD_CHAINED_FIXUPS: u32 = 0x34 | REQ_DYLD;

    /// The `SetIdDylibs` family.
    #[must_use]
    pub const fn is_dylib(cmd: u32) -> bool {
        matches!(
            cmd,
            ID_DYLIB | LOAD_DYLIB | LOAD_WEAK_DYLIB | REEXPORT_DYLIB | LAZY_LOAD_DYLIB | LOAD_UPWARD_DYLIB
        )
    }

    /// The `SetLinkEditData` family.
    #[must_use]
    pub const fn is_linkedit_data(cmd: u32) -> bool {
        matches!(
            cmd,
            CODE_SIGNATURE
                | SEGMENT_SPLIT_INFO
                | FUNCTION_STARTS
                | DATA_IN_CODE
                | DYLIB_CODE_SIGN_DRS
                | LINKER_OPTIMIZATION_HINT
                | DYLD_EXPORTS_TRIE
                | DYLD_CHAINED_FIXUPS
        )
    }

    /// The `SetVersionMin` family.
    #[must_use]
    pub const fn is_version_min(cmd: u32) -> bool {
        matches!(
            cmd,
            VERSION_MIN_IPHONEOS | VERSION_MIN_MACOSX | VERSION_MIN_TVOS | VERSION_MIN_WATCHOS
        )
    }
}

/// C++ `Panels::IDs` (bit positions of `panelsMask`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PanelId {
    /// `Information`.
    Information = 0,
    /// `LoadCommands`.
    LoadCommands = 1,
    /// `Segments`.
    Segments = 2,
    /// `Sections`.
    Sections = 3,
    /// `DyldInfo`.
    DyldInfo = 4,
    /// `Dylib`.
    Dylib = 5,
    /// `DySymTab`.
    DySymTab = 6,
    /// `GoInformation`.
    GoInformation = 7,
    /// `OpCodes`.
    OpCodes = 8,
}

impl PanelId {
    /// Bit of this panel in the mask.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1_u64 << (self as u8)
    }
}

/// `MAC::ByteOrder`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ByteOrder {
    /// `Unknown`.
    #[default]
    Unknown,
    /// `LittleEndian`.
    LittleEndian,
    /// `BigEndian`.
    BigEndian,
}

/// `MAC::ArchInfo`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchInfo {
    /// `name`.
    pub name: String,
    /// `cputype`.
    pub cputype: i32,
    /// `cpusubtype`.
    pub cpusubtype: i32,
    /// `byteorder`.
    pub byteorder: ByteOrder,
    /// `description`.
    pub description: String,
}

/// `NameMapping.hpp` `ArchInfoTable`: `(name, cputype, cpusubtype,
/// byte order, description)`.
pub const ARCH_INFO_TABLE: [(&str, i32, i32, ByteOrder, &str); 57] = [
    ("hppa", CPU_TYPE_HPPA, 0, ByteOrder::BigEndian, "HP-PA"),
    ("i386", CPU_TYPE_I386, 3, ByteOrder::LittleEndian, "Intel 80x86"),
    ("x86_64", CPU_TYPE_X86_64, 3, ByteOrder::LittleEndian, "Intel x86-64"),
    ("x86_64h", CPU_TYPE_X86_64, 8, ByteOrder::LittleEndian, "Intel x86-64h Haswell"),
    ("i860", CPU_TYPE_I860, 0, ByteOrder::BigEndian, "Intel 860"),
    ("m68k", CPU_TYPE_MC680X0, 1, ByteOrder::BigEndian, "Motorola 68K"),
    ("m88k", CPU_TYPE_MC88000, 0, ByteOrder::BigEndian, "Motorola 88K"),
    ("ppc", CPU_TYPE_POWERPC, 0, ByteOrder::BigEndian, "PowerPC"),
    ("ppc64", CPU_TYPE_POWERPC64, 0, ByteOrder::BigEndian, "PowerPC 64-bit"),
    ("sparc", CPU_TYPE_SPARC, 0, ByteOrder::BigEndian, "SPARC"),
    ("arm", CPU_TYPE_ARM, 0, ByteOrder::LittleEndian, "ARM"),
    ("arm64", CPU_TYPE_ARM64, 0, ByteOrder::LittleEndian, "ARM64"),
    ("any", CPU_TYPE_ANY, CPU_SUBTYPE_MULTIPLE, ByteOrder::Unknown, "Architecture Independent"),
    ("veo", CPU_TYPE_VEO, 2, ByteOrder::BigEndian, "veo"),
    ("hppa7100LC", CPU_TYPE_HPPA, 1, ByteOrder::BigEndian, "HP-PA 7100LC"),
    ("m68030", CPU_TYPE_MC680X0, 3, ByteOrder::BigEndian, "Motorola 68030"),
    ("m68040", CPU_TYPE_MC680X0, 2, ByteOrder::BigEndian, "Motorola 68040"),
    ("i486", CPU_TYPE_I386, 4, ByteOrder::LittleEndian, "Intel 80486"),
    ("i486SX", CPU_TYPE_I386, 4 + 128, ByteOrder::LittleEndian, "Intel 80486SX"),
    ("pentium", CPU_TYPE_I386, 5, ByteOrder::LittleEndian, "Intel Pentium"),
    ("i586", CPU_TYPE_I386, 5, ByteOrder::LittleEndian, "Intel 80586"),
    ("pentpro", CPU_TYPE_I386, 6 + (1 << 4), ByteOrder::LittleEndian, "Intel Pentium Pro"),
    ("i686", CPU_TYPE_I386, 6 + (1 << 4), ByteOrder::LittleEndian, "Intel Pentium Pro"),
    ("pentIIm3", CPU_TYPE_I386, 6 + (3 << 4), ByteOrder::LittleEndian, "Intel Pentium II Model 3"),
    ("pentIIm5", CPU_TYPE_I386, 6 + (5 << 4), ByteOrder::LittleEndian, "Intel Pentium II Model 5"),
    ("pentium4", CPU_TYPE_I386, 10, ByteOrder::LittleEndian, "Intel Pentium 4"),
    ("x86_64h", CPU_TYPE_I386, 8, ByteOrder::LittleEndian, "Intel x86-64h Haswell"),
    ("ppc601", CPU_TYPE_POWERPC, 1, ByteOrder::BigEndian, "PowerPC 601"),
    ("ppc603", CPU_TYPE_POWERPC, 3, ByteOrder::BigEndian, "PowerPC 603"),
    ("ppc603e", CPU_TYPE_POWERPC, 4, ByteOrder::BigEndian, "PowerPC 603e"),
    ("ppc603ev", CPU_TYPE_POWERPC, 5, ByteOrder::BigEndian, "PowerPC 603ev"),
    ("ppc604", CPU_TYPE_POWERPC, 6, ByteOrder::BigEndian, "PowerPC 604"),
    ("ppc604e", CPU_TYPE_POWERPC, 7, ByteOrder::BigEndian, "PowerPC 604e"),
    ("ppc750", CPU_TYPE_POWERPC, 9, ByteOrder::BigEndian, "PowerPC 750"),
    ("ppc7400", CPU_TYPE_POWERPC, 10, ByteOrder::BigEndian, "PowerPC 7400"),
    ("ppc7450", CPU_TYPE_POWERPC, 11, ByteOrder::BigEndian, "PowerPC 7450"),
    ("ppc970", CPU_TYPE_POWERPC, 100, ByteOrder::BigEndian, "PowerPC 970"),
    ("ppc970-64", CPU_TYPE_POWERPC64, 100, ByteOrder::BigEndian, "PowerPC 970 64-bit"),
    ("armv4t", CPU_TYPE_ARM, 5, ByteOrder::LittleEndian, "arm v4t"),
    ("armv5", CPU_TYPE_ARM, 7, ByteOrder::LittleEndian, "arm v5"),
    ("xscale", CPU_TYPE_ARM, 8, ByteOrder::LittleEndian, "arm xscale"),
    ("armv6", CPU_TYPE_ARM, 6, ByteOrder::LittleEndian, "arm v6"),
    ("armv6m", CPU_TYPE_ARM, 14, ByteOrder::LittleEndian, "arm v6m"),
    ("armv7", CPU_TYPE_ARM, 9, ByteOrder::LittleEndian, "arm v7"),
    ("armv7f", CPU_TYPE_ARM, 10, ByteOrder::LittleEndian, "arm v7f"),
    ("armv7s", CPU_TYPE_ARM, 11, ByteOrder::LittleEndian, "arm v7s"),
    ("armv7k", CPU_TYPE_ARM, 12, ByteOrder::LittleEndian, "arm v7k"),
    ("armv7m", CPU_TYPE_ARM, 15, ByteOrder::LittleEndian, "arm v7m"),
    ("armv7em", CPU_TYPE_ARM, 16, ByteOrder::LittleEndian, "arm v7em"),
    ("armv8", CPU_TYPE_ARM, 13, ByteOrder::LittleEndian, "arm v8"),
    ("arm64", CPU_TYPE_ARM64, 1, ByteOrder::LittleEndian, "arm64 v8"),
    ("little", CPU_TYPE_ANY, 0, ByteOrder::LittleEndian, "Little Endian"),
    ("big", CPU_TYPE_ANY, 1, ByteOrder::BigEndian, "Big Endian"),
    ("veo1", CPU_TYPE_VEO, 1, ByteOrder::BigEndian, "veo 1"),
    ("veo2", CPU_TYPE_VEO, 2, ByteOrder::BigEndian, "veo 2"),
    ("veo3", CPU_TYPE_VEO, 3, ByteOrder::BigEndian, "veo 3"),
    ("veo4", CPU_TYPE_VEO, 4, ByteOrder::BigEndian, "veo 4"),
];

fn arch_entry(entry: &(&str, i32, i32, ByteOrder, &str)) -> ArchInfo {
    ArchInfo {
        name: entry.0.to_owned(),
        cputype: entry.1,
        cpusubtype: entry.2,
        byteorder: entry.3,
        description: entry.4.to_owned(),
    }
}

/// C++ `GetArchInfoFromCPUTypeAndSubtype` (`Utils.hpp`).
#[must_use]
pub fn arch_info(cputype: i32, cpusubtype: u32) -> ArchInfo {
    let wanted = cpusubtype & !CPU_SUBTYPE_MASK;
    if let Some(entry) = ARCH_INFO_TABLE.iter().find(|e| {
        e.1 == cputype && (cpusubtype == CPU_SUBTYPE_MULTIPLE.cast_unsigned() || (e.2.cast_unsigned() & !CPU_SUBTYPE_MASK) == wanted)
    }) {
        return arch_entry(entry);
    }
    let mut info = ARCH_INFO_TABLE.iter().find(|e| e.1 == cputype).map(arch_entry).unwrap_or_default();
    info.cpusubtype = cpusubtype.cast_signed();
    if cputype == CPU_TYPE_I386 {
        let family = wanted & 15;
        let model = wanted >> 4;
        info.description = format!("Intel family {family} model {model}");
    } else if cputype == CPU_TYPE_POWERPC {
        info.description = format!("PowerPC cpusubtype {cpusubtype}");
    }
    info
}

// ---------------------------------------------------------------------------
// Structures (`MachOFile` members)
// ---------------------------------------------------------------------------

/// `MAC::mach_header`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MachHeader {
    /// `magic`.
    pub magic: u32,
    /// `cputype`.
    pub cputype: i32,
    /// `cpusubtype`.
    pub cpusubtype: i32,
    /// `filetype`.
    pub filetype: u32,
    /// `ncmds`.
    pub ncmds: u32,
    /// `sizeofcmds`.
    pub sizeofcmds: u32,
    /// `flags`.
    pub flags: u32,
    /// `reserved` (64-bit only; never byte-swapped, as in C++).
    pub reserved: u32,
}

/// `MachOFile::LoadCommand`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadCommand {
    /// `value.cmd`.
    pub cmd: u32,
    /// `value.cmdsize`.
    pub cmdsize: u32,
    /// File offset of the command.
    pub offset: u64,
}

/// `MachOFile::Section`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Section {
    /// `sectname` (NUL-trimmed).
    pub sectname: String,
    /// `segname` (NUL-trimmed).
    pub segname: String,
    /// `addr`.
    pub addr: u64,
    /// `size`.
    pub size: u64,
    /// `offset`.
    pub offset: u32,
    /// `align`.
    pub align: u32,
    /// `reloff`.
    pub reloff: u32,
    /// `nreloc`.
    pub nreloc: u32,
    /// `flags`.
    pub flags: u32,
    /// `reserved1`.
    pub reserved1: u32,
    /// `reserved2`.
    pub reserved2: u32,
    /// `reserved3` (always 0 for 32-bit sections).
    pub reserved3: u32,
}

impl Section {
    /// Zone start used by `CreateBufferView`: `offset`, or `addr` for
    /// `__bss`-style sections with no file offset.
    #[must_use]
    pub const fn zone_start(&self) -> u64 {
        if self.offset != 0 {
            self.offset as u64
        } else {
            self.addr
        }
    }
}

/// `MachOFile::Segment`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    /// `cmd` (`SEGMENT` / `SEGMENT_64`).
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `segname` (NUL-trimmed).
    pub segname: String,
    /// `vmaddr`.
    pub vmaddr: u64,
    /// `vmsize`.
    pub vmsize: u64,
    /// `fileoff`.
    pub fileoff: u64,
    /// `filesize`.
    pub filesize: u64,
    /// `maxprot`.
    pub maxprot: u32,
    /// `initprot`.
    pub initprot: u32,
    /// `nsects`.
    pub nsects: u32,
    /// `flags`.
    pub flags: u32,
    /// `sections`.
    pub sections: Vec<Section>,
}

/// `MAC::dyld_info_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DyldInfoCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `rebase_off`.
    pub rebase_off: u32,
    /// `rebase_size`.
    pub rebase_size: u32,
    /// `bind_off`.
    pub bind_off: u32,
    /// `bind_size`.
    pub bind_size: u32,
    /// `weak_bind_off`.
    pub weak_bind_off: u32,
    /// `weak_bind_size`.
    pub weak_bind_size: u32,
    /// `lazy_bind_off`.
    pub lazy_bind_off: u32,
    /// `lazy_bind_size`.
    pub lazy_bind_size: u32,
    /// `export_off`.
    pub export_off: u32,
    /// `export_size`.
    pub export_size: u32,
}

/// `MachOFile::Dylib`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dylib {
    /// `value.cmd`.
    pub cmd: u32,
    /// `value.cmdsize`.
    pub cmdsize: u32,
    /// `value.dylib.name.offset`.
    pub name_offset: u32,
    /// `value.dylib.timestamp`.
    pub timestamp: u32,
    /// `value.dylib.current_version`.
    pub current_version: u32,
    /// `value.dylib.compatibility_version`.
    pub compatibility_version: u32,
    /// `name` (read at byte 24 of the command).
    pub name: String,
    /// File offset of the command.
    pub offset: u64,
}

/// `MAC::entry_point_command` (also synthesised from `LC_UNIXTHREAD`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryPointCommand {
    /// `cmd` (`MAIN` or `UNIXTHREAD`).
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `entryoff` (a file offset for `LC_MAIN`, a register value for
    /// `LC_UNIXTHREAD`).
    pub entryoff: u64,
    /// `stacksize`.
    pub stacksize: u64,
}

/// `MAC::symtab_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SymtabCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `symoff`.
    pub symoff: u32,
    /// `nsyms`.
    pub nsyms: u32,
    /// `stroff`.
    pub stroff: u32,
    /// `strsize`.
    pub strsize: u32,
}

/// `MachOFile::MyNList`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NList {
    /// `n_strx`.
    pub n_strx: u32,
    /// `n_type`.
    pub n_type: u8,
    /// `n_sect`.
    pub n_sect: u8,
    /// `n_desc`.
    pub n_desc: u16,
    /// `n_value`.
    pub n_value: u64,
    /// `symbolNameDemangled` (raw name; no demangler yet).
    pub name: String,
}

/// `MachOFile::DySymTab`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymTab {
    /// `sc`.
    pub command: SymtabCommand,
    /// `objects`.
    pub symbols: Vec<NList>,
}

/// `MAC::source_version_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceVersionCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `version` (`A.B.C.D.E` packed as `a24.b10.c10.d10.e10`).
    pub version: u64,
}

/// `MAC::uuid_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UuidCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `uuid` (on-disk order).
    pub uuid: [u8; 16],
}

/// `MAC::linkedit_data_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkeditDataCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `dataoff`.
    pub dataoff: u32,
    /// `datasize`.
    pub datasize: u32,
}

/// `MAC::version_min_command`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VersionMinCommand {
    /// `cmd`.
    pub cmd: u32,
    /// `cmdsize`.
    pub cmdsize: u32,
    /// `version` (`X.Y.Z` in nibbles `xxxx.yy.zz`).
    pub version: u32,
    /// `sdk`.
    pub sdk: u32,
}

/// `MAC::Arch` — one fat-archive member.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Arch {
    /// `info`.
    pub info: ArchInfo,
    /// `cputype`.
    pub cputype: i32,
    /// `cpusubtype`.
    pub cpusubtype: i32,
    /// `offset`.
    pub offset: u64,
    /// `size`.
    pub size: u64,
    /// `align` (power of 2).
    pub align: u32,
    /// `reserved` (64-bit fat only).
    pub reserved: u64,
    /// `filetype` from the member's `mach_header`.
    pub filetype: u32,
}

/// What `ParseGoBuild` / `ParseGoBuildInfo` feed into `pcLnTab`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoBuildInfo {
    /// `SetBuildId`.
    pub build_id: Option<String>,
    /// `SetRuntimeBuildVersion`.
    pub runtime_build_version: Option<String>,
    /// `SetRuntimeBuildModInfo`.
    pub runtime_mod_info: Option<String>,
}

/// The C++ `throw`s of `Update()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachoError {
    /// A second `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`.
    DuplicateDyldInfo,
    /// A second `LC_MAIN` / `LC_UNIXTHREAD`.
    DuplicateMain,
    /// A second `LC_SYMTAB`.
    DuplicateSymtab,
    /// A second `LC_SOURCE_VERSION`.
    DuplicateSourceVersion,
    /// A second `LC_UUID`.
    DuplicateUuid,
    /// A second `LC_VERSION_MIN_*`.
    DuplicateVersionMin,
    /// `LC_UNIXTHREAD` on a CPU without an entry-point register rule.
    UnhandledUnixThreadCpu(i32),
    /// Big-endian Go build info (`"Not handled!"`).
    BigEndianGoBuildInfo,
}

impl core::fmt::Display for MachoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateDyldInfo => f.write_str("Multiple LoadCommandType::DYLD_INFO or MAC::LoadCommandType::DYLD_INFO_ONLY found!"),
            Self::DuplicateMain => f.write_str("Multiple LoadCommandType::MAIN found!"),
            Self::DuplicateSymtab => f.write_str("Got a second LoadCommandType::SYMTAB command!"),
            Self::DuplicateSourceVersion => f.write_str("Multiple LoadCommandType::SOURCE_VERSION found!"),
            Self::DuplicateUuid => f.write_str("Multiple LoadCommandType::UUID found!"),
            Self::DuplicateVersionMin => f.write_str("Version min command already set!"),
            Self::UnhandledUnixThreadCpu(cpu) => {
                write!(f, "EP not handled for CPU {cpu} from LoadCommandType::UNIXTHREAD!")
            }
            Self::BigEndianGoBuildInfo => f.write_str("big-endian Go build info not handled"),
        }
    }
}

impl std::error::Error for MachoError {}

/// Where the parser reads from (`obj->GetData().Copy` /
/// `CopyToBuffer`).
pub trait MachoSource {
    /// Reads exactly `size` bytes at `offset` (`CopyToBuffer(..., true)`).
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>>;
    /// Reads up to `size` bytes at `offset`, shorter at the end of the
    /// data (`CopyToBuffer(..., false)`); `None` when nothing is there.
    fn read_up_to(&mut self, offset: u64, size: u32) -> Option<Vec<u8>>;
}

impl MachoSource for [u8] {
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(size as usize)?;
        self.get(start..end).map(<[u8]>::to_vec)
    }

    fn read_up_to(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        let start = usize::try_from(offset).ok()?;
        let end = start.saturating_add(size as usize).min(self.len());
        let slice = self.get(start..end)?;
        (!slice.is_empty()).then(|| slice.to_vec())
    }
}

impl MachoSource for DataCache {
    fn read_exact(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        self.copy_to_vec(offset, size, true).ok()
    }

    fn read_up_to(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        if size == 0 {
            return None;
        }
        self.copy_to_vec(offset, size, false).ok().filter(|v| !v.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Field readers with optional byte swap (`Swap.hpp`)
// ---------------------------------------------------------------------------

/// Reads little-endian fields and swaps them when `swap` is set.
#[derive(Clone, Copy)]
struct Reader<'a> {
    buf: &'a [u8],
    swap: bool,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8], swap: bool) -> Self {
        Self { buf, swap }
    }

    fn u8(&self, at: usize) -> Option<u8> {
        self.buf.get(at).copied()
    }

    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.buf.get(at..at.checked_add(2)?)?;
        let v = u16::from_le_bytes([*b.first()?, *b.get(1)?]);
        Some(if self.swap { v.swap_bytes() } else { v })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.buf.get(at..at.checked_add(4)?)?;
        let v = u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]);
        Some(if self.swap { v.swap_bytes() } else { v })
    }

    fn i32(&self, at: usize) -> Option<i32> {
        self.u32(at).map(u32::cast_signed)
    }

    fn u64(&self, at: usize) -> Option<u64> {
        let b = self.buf.get(at..at.checked_add(8)?)?;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(b);
        let v = u64::from_le_bytes(bytes);
        Some(if self.swap { v.swap_bytes() } else { v })
    }

    /// Raw 16-byte name, NUL-trimmed (never reversed — see the module
    /// notes).
    fn name16(&self, at: usize) -> Option<String> {
        let b = self.buf.get(at..at.checked_add(16)?)?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        Some(String::from_utf8_lossy(b.get(..end).unwrap_or(&[])).into_owned())
    }
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

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .and_then(|p| p.checked_add(from))
}

/// C++ `GetUVariantSizes`: `(value, bytes consumed)`.
#[must_use]
pub fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0_u64;
    let mut s = 0_u32;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VARINT_LEN64 {
            return None;
        }
        if b < 0x80 {
            if i == MAX_VARINT_LEN64.saturating_sub(1) && b > 1 {
                return None;
            }
            x |= u64::from(b).checked_shl(s).unwrap_or(0);
            return Some((x, i.saturating_add(1)));
        }
        x |= u64::from(b & 0x7F).checked_shl(s).unwrap_or(0);
        s = s.saturating_add(7);
    }
    None
}

// ---------------------------------------------------------------------------
// MachoFile
// ---------------------------------------------------------------------------

/// C++ `MachOFile`.
// The four bools mirror the independent C++ members `isMacho`,
// `isFat`, `shouldSwapEndianess`, `is64`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachoFile {
    /// `isMacho`.
    pub is_macho: bool,
    /// `isFat`.
    pub is_fat: bool,
    /// `shouldSwapEndianess`.
    pub should_swap: bool,
    /// `is64`.
    pub is64: bool,
    /// `fatHeader.nfat_arch` (after the swap).
    pub fat_arch_count: u32,
    /// `archs`.
    pub archs: Vec<Arch>,
    /// `header`.
    pub header: MachHeader,
    /// `loadCommands`.
    pub load_commands: Vec<LoadCommand>,
    /// `segments`.
    pub segments: Vec<Segment>,
    /// `dyldInfo`.
    pub dyld_info: Option<DyldInfoCommand>,
    /// `dylibs`.
    pub dylibs: Vec<Dylib>,
    /// `dySymTab`.
    pub symtab: Option<SymTab>,
    /// `main`.
    pub main: Option<EntryPointCommand>,
    /// `sourceVersion`.
    pub source_version: Option<SourceVersionCommand>,
    /// `uuid`.
    pub uuid: Option<UuidCommand>,
    /// `linkEditDatas`.
    pub linkedit_datas: Vec<LinkeditDataCommand>,
    /// `versionMin`.
    pub version_min: Option<VersionMinCommand>,
    /// `executableZonesFAs`.
    pub executable_zones: Vec<(u64, u64)>,
    /// Go build facts (`pcLnTab` inputs).
    pub go_build: GoBuildInfo,
    /// `__gopclntab` `(offset, size)` when present.
    pub go_pclntab: Option<(u64, u64)>,
    /// `panelsMask`.
    pub panels_mask: u64,
}

impl MachoFile {
    /// C++ `Update()` over the object's cache.
    ///
    /// # Errors
    ///
    /// [`MachoError`] for the conditions the C++ throws on.
    pub fn parse_cache(cache: &mut DataCache) -> Result<Self, MachoError> {
        Self::parse_source(cache)
    }

    /// C++ `Update()` over an in-memory image.
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, MachoError> {
        let mut bytes = bytes.to_vec();
        Self::parse_source(bytes.as_mut_slice())
    }

    /// `Update()` over any [`MachoSource`].
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_source<S: MachoSource + ?Sized>(source: &mut S) -> Result<Self, MachoError> {
        let mut file = Self::default();
        file.set_header_info(source);
        file.panels_mask |= PanelId::Information.bit();
        if file.is_macho {
            let mut offset = 0_u64;
            file.set_header(source, &mut offset);
            file.set_load_commands(source, &mut offset);
            file.set_segments_and_sections(source);
            file.set_executable_zones();
            file.set_dyld_info(source)?;
            file.set_dylibs(source);
            file.set_main(source)?;
            file.set_symbols(source)?;
            file.set_source_version(source)?;
            file.set_uuid(source)?;
            file.set_linkedit_data(source);
            file.set_version_min(source)?;

            file.panels_mask |= PanelId::LoadCommands.bit();
            if !file.segments.is_empty() {
                file.panels_mask |= PanelId::Segments.bit() | PanelId::Sections.bit();
            }
            if file.dyld_info.is_some() {
                file.panels_mask |= PanelId::DyldInfo.bit();
            }
            if !file.dylibs.is_empty() {
                file.panels_mask |= PanelId::Dylib.bit();
            }
            if file.symtab.is_some() {
                file.panels_mask |= PanelId::DySymTab.bit();
            }
            if file.parse_go_data(source)? {
                file.panels_mask |= PanelId::GoInformation.bit();
            }
            if is_intel_cpu(file.header.cputype) {
                file.panels_mask |= PanelId::OpCodes.bit();
            }
        } else if file.is_fat {
            file.set_fat_archs(source);
        }
        Ok(file)
    }

    /// C++ `SetHeaderInfo`.
    fn set_header_info<S: MachoSource + ?Sized>(&mut self, source: &mut S) {
        let Some(head) = source.read_exact(0, 4) else {
            return;
        };
        let Some(magic) = Reader::new(&head, false).u32(0) else {
            return;
        };
        self.is_macho = matches!(magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64);
        self.is_fat = matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64);
        self.is64 = matches!(magic, MH_MAGIC_64 | MH_CIGAM_64 | FAT_MAGIC_64 | FAT_CIGAM_64);
        self.should_swap = matches!(magic, MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM | FAT_CIGAM_64);
    }

    /// C++ `SetHeader`: the C++ copies the full 32-byte struct and only
    /// then subtracts `reserved` for 32-bit files, so a 32-bit header
    /// needs 32 readable bytes too.
    fn set_header<S: MachoSource + ?Sized>(&mut self, source: &mut S, offset: &mut u64) -> bool {
        let Some(buf) = source.read_exact(*offset, MACH_HEADER_64_SIZE as u32) else {
            return false;
        };
        let r = Reader::new(&buf, self.should_swap);
        let raw = Reader::new(&buf, false);
        let Some(header) = (|| {
            Some(MachHeader {
                magic: r.u32(0)?,
                cputype: r.i32(4)?,
                cpusubtype: r.i32(8)?,
                filetype: r.u32(12)?,
                ncmds: r.u32(16)?,
                sizeofcmds: r.u32(20)?,
                flags: r.u32(24)?,
                reserved: raw.u32(28)?,
            })
        })() else {
            return false;
        };
        self.header = header;
        *offset = offset.saturating_add(if self.is64 { MACH_HEADER_64_SIZE } else { MACH_HEADER_SIZE } as u64);
        true
    }

    /// C++ `SetLoadCommands`.
    fn set_load_commands<S: MachoSource + ?Sized>(&mut self, source: &mut S, offset: &mut u64) -> bool {
        let count = self.header.ncmds.min(MAX_LOAD_COMMANDS);
        self.load_commands.reserve(count.min(1024) as usize);
        for _ in 0..count {
            let Some(buf) = source.read_exact(*offset, LOAD_COMMAND_SIZE as u32) else {
                return false;
            };
            let r = Reader::new(&buf, self.should_swap);
            let (Some(cmd), Some(cmdsize)) = (r.u32(0), r.u32(4)) else {
                return false;
            };
            self.load_commands.push(LoadCommand {
                cmd,
                cmdsize,
                offset: *offset,
            });
            if (cmdsize as usize) < LOAD_COMMAND_SIZE {
                // Hostile: the C++ would spin on the same offset.
                return false;
            }
            *offset = offset.saturating_add(u64::from(cmdsize));
        }
        true
    }

    /// C++ `SetSegmentsAndTheirSections`.
    fn set_segments_and_sections<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> bool {
        let commands = self.load_commands.clone();
        for lc in &commands {
            let is64 = match lc.cmd {
                lc::SEGMENT => false,
                lc::SEGMENT_64 => true,
                _ => continue,
            };
            let (segment_len, section_len) = if is64 {
                (SEGMENT_COMMAND_64_SIZE, SECTION_64_SIZE)
            } else {
                (SEGMENT_COMMAND_SIZE, SECTION_SIZE)
            };
            let Some(buf) = source.read_exact(lc.offset, segment_len as u32) else {
                return false;
            };
            let r = Reader::new(&buf, self.should_swap);
            let Some(mut segment) = read_segment(&r, is64) else {
                return false;
            };
            let mut offset = lc.offset.saturating_add(segment_len as u64);
            for _ in 0..segment.nsects {
                let Some(sbuf) = source.read_exact(offset, section_len as u32) else {
                    return false;
                };
                let sr = Reader::new(&sbuf, self.should_swap);
                let Some(section) = read_section(&sr, is64) else {
                    return false;
                };
                segment.sections.push(section);
                offset = offset.saturating_add(section_len as u64);
            }
            self.segments.push(segment);
        }
        true
    }

    /// C++ `SetExecutableZones` (`initprot & EXECUTE`).
    fn set_executable_zones(&mut self) {
        for segment in &self.segments {
            if segment.initprot & VM_PROT_EXECUTE == VM_PROT_EXECUTE {
                self.executable_zones
                    .push((segment.fileoff, segment.fileoff.wrapping_add(segment.filesize)));
            }
        }
    }

    /// C++ `SetDyldInfo`.
    fn set_dyld_info<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| c.cmd == lc::DYLD_INFO || c.cmd == lc::DYLD_INFO_ONLY) {
            if self.dyld_info.is_some() {
                return Err(MachoError::DuplicateDyldInfo);
            }
            // emplace() happens before the copy in C++.
            self.dyld_info = Some(DyldInfoCommand::default());
            let Some(buf) = source.read_exact(lc.offset, DYLD_INFO_COMMAND_SIZE as u32) else {
                return Ok(false);
            };
            let r = Reader::new(&buf, self.should_swap);
            let fields: Option<Vec<u32>> = (0_usize..12).map(|i| r.u32(i.saturating_mul(4))).collect();
            let Some(f) = fields else {
                return Ok(false);
            };
            let get = |i: usize| f.get(i).copied().unwrap_or(0);
            self.dyld_info = Some(DyldInfoCommand {
                cmd: get(0),
                cmdsize: get(1),
                rebase_off: get(2),
                rebase_size: get(3),
                bind_off: get(4),
                bind_size: get(5),
                weak_bind_off: get(6),
                weak_bind_size: get(7),
                lazy_bind_off: get(8),
                lazy_bind_size: get(9),
                export_off: get(10),
                export_size: get(11),
            });
        }
        Ok(true)
    }

    /// C++ `SetIdDylibs`.
    fn set_dylibs<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> bool {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| lc::is_dylib(c.cmd)) {
            let Some(buf) = source.read_exact(lc.offset, lc.cmdsize) else {
                continue;
            };
            let r = Reader::new(&buf, self.should_swap);
            let dylib = Dylib {
                cmd: r.u32(0).unwrap_or(0),
                cmdsize: r.u32(4).unwrap_or(0),
                name_offset: r.u32(8).unwrap_or(0),
                timestamp: r.u32(12).unwrap_or(0),
                current_version: r.u32(16).unwrap_or(0),
                compatibility_version: r.u32(20).unwrap_or(0),
                name: cstr_at(&buf, DYLIB_NAME_OFFSET as u64),
                offset: lc.offset,
            };
            self.dylibs.push(dylib);
        }
        true
    }

    /// C++ `SetMain` (`LC_MAIN` and `LC_UNIXTHREAD`).
    fn set_main<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in &commands {
            if lc.cmd == lc::MAIN {
                if self.main.is_some() {
                    return Err(MachoError::DuplicateMain);
                }
                self.main = Some(EntryPointCommand::default());
                let Some(buf) = source.read_exact(lc.offset, ENTRY_POINT_COMMAND_SIZE as u32) else {
                    return Ok(false);
                };
                let r = Reader::new(&buf, self.should_swap);
                if let (Some(cmd), Some(cmdsize), Some(entryoff), Some(stacksize)) =
                    (r.u32(0), r.u32(4), r.u64(8), r.u64(16))
                {
                    self.main = Some(EntryPointCommand {
                        cmd,
                        cmdsize,
                        entryoff,
                        stacksize,
                    });
                }
            } else if lc.cmd == lc::UNIXTHREAD {
                if self.main.is_some() {
                    return Err(MachoError::DuplicateMain);
                }
                let mut main = EntryPointCommand {
                    cmd: lc.cmd,
                    cmdsize: lc.cmdsize,
                    ..EntryPointCommand::default()
                };
                let buf = source.read_exact(lc.offset, lc.cmdsize).unwrap_or_default();
                let r = Reader::new(&buf, self.should_swap);
                let state = THREAD_STATE_OFFSET;
                let entry = match self.header.cputype {
                    CPU_TYPE_I386 => r.u32(state.saturating_add(I386_EIP_OFFSET)).map(u64::from),
                    CPU_TYPE_X86_64 => r.u64(state.saturating_add(X86_64_RIP_OFFSET)),
                    CPU_TYPE_POWERPC => r.u32(state.saturating_add(PPC_SRR0_OFFSET)).map(u64::from),
                    CPU_TYPE_POWERPC64 => r.u64(state.saturating_add(PPC_SRR0_OFFSET)),
                    other => return Err(MachoError::UnhandledUnixThreadCpu(other)),
                };
                main.entryoff = entry.unwrap_or(0);
                self.main = Some(main);
            }
        }
        Ok(true)
    }

    /// C++ `SetSymbols` (`LC_SYMTAB`).
    fn set_symbols<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| c.cmd == lc::SYMTAB) {
            if self.symtab.is_some() {
                return Err(MachoError::DuplicateSymtab);
            }
            self.symtab = Some(SymTab::default());
            let Some(buf) = source.read_exact(lc.offset, SYMTAB_COMMAND_SIZE as u32) else {
                return Ok(false);
            };
            let r = Reader::new(&buf, self.should_swap);
            let Some(command) = (|| {
                Some(SymtabCommand {
                    cmd: r.u32(0)?,
                    cmdsize: r.u32(4)?,
                    symoff: r.u32(8)?,
                    nsyms: r.u32(12)?,
                    stroff: r.u32(16)?,
                    strsize: r.u32(20)?,
                })
            })() else {
                return Ok(false);
            };
            if let Some(table) = self.symtab.as_mut() {
                table.command = command;
            }
            let Some(strings) = source.read_exact(u64::from(command.stroff), command.strsize) else {
                return Ok(false);
            };
            let nlist_size = if self.is64 { NLIST_64_SIZE } else { NLIST_SIZE };
            let table_size = (command.nsyms as usize).saturating_mul(nlist_size);
            let Ok(table_size) = u32::try_from(table_size) else {
                return Ok(false);
            };
            let Some(symbols) = source.read_exact(u64::from(command.symoff), table_size) else {
                return Ok(false);
            };
            let sr = Reader::new(&symbols, self.should_swap);
            let mut list = Vec::with_capacity((command.nsyms as usize).min(4096));
            for i in 0..command.nsyms as usize {
                let at = i.saturating_mul(nlist_size);
                let Some(entry) = read_nlist(&sr, at, self.is64) else {
                    break;
                };
                let name = cstr_at(&strings, u64::from(entry.n_strx));
                list.push(NList { name, ..entry });
            }
            if let Some(table) = self.symtab.as_mut() {
                table.symbols = list;
            }
        }
        Ok(true)
    }

    /// C++ `SetSourceVersion`.
    fn set_source_version<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| c.cmd == lc::SOURCE_VERSION) {
            if self.source_version.is_some() {
                return Err(MachoError::DuplicateSourceVersion);
            }
            self.source_version = Some(SourceVersionCommand::default());
            let Some(buf) = source.read_exact(lc.offset, SOURCE_VERSION_COMMAND_SIZE as u32) else {
                return Ok(false);
            };
            let r = Reader::new(&buf, self.should_swap);
            if let (Some(cmd), Some(cmdsize), Some(version)) = (r.u32(0), r.u32(4), r.u64(8)) {
                self.source_version = Some(SourceVersionCommand { cmd, cmdsize, version });
            }
        }
        Ok(true)
    }

    /// C++ `SetUUID`.
    fn set_uuid<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| c.cmd == lc::UUID) {
            if self.uuid.is_some() {
                return Err(MachoError::DuplicateUuid);
            }
            self.uuid = Some(UuidCommand::default());
            let Some(buf) = source.read_exact(lc.offset, UUID_COMMAND_SIZE as u32) else {
                return Ok(false);
            };
            let r = Reader::new(&buf, self.should_swap);
            let mut uuid = [0_u8; 16];
            if let (Some(cmd), Some(cmdsize), Some(bytes)) = (r.u32(0), r.u32(4), buf.get(8..24)) {
                uuid.copy_from_slice(bytes);
                self.uuid = Some(UuidCommand { cmd, cmdsize, uuid });
            }
        }
        Ok(true)
    }

    /// C++ `SetLinkEditData`.
    fn set_linkedit_data<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> bool {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| lc::is_linkedit_data(c.cmd)) {
            let Some(buf) = source.read_exact(lc.offset, LINKEDIT_DATA_COMMAND_SIZE as u32) else {
                return false;
            };
            let r = Reader::new(&buf, self.should_swap);
            let (Some(cmd), Some(cmdsize), Some(dataoff), Some(datasize)) = (r.u32(0), r.u32(4), r.u32(8), r.u32(12))
            else {
                return false;
            };
            self.linkedit_datas.push(LinkeditDataCommand {
                cmd,
                cmdsize,
                dataoff,
                datasize,
            });
        }
        true
    }

    /// C++ `SetVersionMin`.
    fn set_version_min<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let commands = self.load_commands.clone();
        for lc in commands.iter().filter(|c| lc::is_version_min(c.cmd)) {
            if self.version_min.is_some() {
                return Err(MachoError::DuplicateVersionMin);
            }
            self.version_min = Some(VersionMinCommand::default());
            let Some(buf) = source.read_exact(lc.offset, VERSION_MIN_COMMAND_SIZE as u32) else {
                return Ok(false);
            };
            let r = Reader::new(&buf, self.should_swap);
            if let (Some(cmd), Some(cmdsize), Some(version), Some(sdk)) = (r.u32(0), r.u32(4), r.u32(8), r.u32(12)) {
                self.version_min = Some(VersionMinCommand {
                    cmd,
                    cmdsize,
                    version,
                    sdk,
                });
            }
        }
        Ok(true)
    }

    /// C++ `ParseGoData`: `ParseGoBuild` must succeed; `ParseGoBuildInfo`
    /// is attempted; `__gopclntab` turns the Go panels on.
    fn parse_go_data<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        if !self.parse_go_build(source) {
            return Ok(false);
        }
        self.parse_go_build_info(source)?;
        let pclntab = self
            .segments
            .iter()
            .flat_map(|s| s.sections.iter())
            .find(|s| s.sectname == GOPCLNTAB_SECTION)
            .map(|s| (u64::from(s.offset), s.size));
        if let Some(pclntab) = pclntab {
            self.panels_mask |= PanelId::GoInformation.bit();
            self.go_pclntab = Some(pclntab);
        }
        Ok(true)
    }

    /// C++ `ParseGoBuild`: the build id between `\xff Go build ID: "`
    /// and `"\n \xff` inside `__TEXT`.
    fn parse_go_build<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> bool {
        let Some(text) = self.segments.iter().find(|s| s.segname == TEXT_SEGMENT) else {
            return false;
        };
        let Some(view) = source.read_up_to(text.fileoff, text.filesize as u32) else {
            return false;
        };
        let Some(start) = find(&view, GO_BUILD_ID_PREFIX, 0) else {
            return false;
        };
        let Some(end) = find(&view, GO_BUILD_ID_END, start.saturating_add(1)) else {
            return false;
        };
        let id_start = start.saturating_add(GO_BUILD_ID_PREFIX.len());
        let Some(id) = view.get(id_start..end.max(id_start)) else {
            return false;
        };
        self.go_build.build_id = Some(String::from_utf8_lossy(id).into_owned());
        true
    }

    /// C++ `ParseGoBuildInfo`.
    fn parse_go_build_info<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> Result<bool, MachoError> {
        let mut address = 0_u64;
        let mut size = 0_u64;
        for segment in &self.segments {
            if let Some(section) = segment.sections.iter().find(|s| s.sectname == GO_BUILDINFO_SECTION) {
                address = u64::from(section.offset);
                size = section.size;
            }
        }
        if address == 0 {
            if let Some(segment) = self.segments.iter().find(|s| {
                s.fileoff != 0 && s.filesize != 0 && s.initprot == VM_PROT_RW && s.maxprot == VM_PROT_RW
            }) {
                address = segment.fileoff;
                size = segment.filesize;
            }
        }
        if address == 0 {
            return Ok(false);
        }
        let Some(view) = source.read_up_to(address, size as u32) else {
            return Ok(false);
        };
        let Some(start) = find(&view, GO_BUILD_INFO_MAGIC, 0) else {
            return Ok(false);
        };
        if view.len().saturating_sub(start) < GO_BUILD_INFO_SIZE {
            return Ok(false);
        }
        let Some(info) = view.get(start..start.saturating_add(GO_BUILD_INFO_SIZE)) else {
            return Ok(false);
        };
        let flags = info.get(15).copied().unwrap_or(0);
        if flags & 2 != 0 {
            // Inline varint-prefixed strings after the 32-byte header.
            let rest = view.get(start.saturating_add(GO_BUILD_INFO_SIZE)..).unwrap_or(&[]);
            let Some((len, consumed)) = read_uvarint(rest) else {
                return Ok(false);
            };
            let Some(version) = usize::try_from(len).ok().and_then(|l| rest.get(consumed..consumed.checked_add(l)?)) else {
                return Ok(false);
            };
            self.go_build.runtime_build_version = Some(String::from_utf8_lossy(version).into_owned());
            let after = consumed.saturating_add(version.len());
            let rest = rest.get(after..).unwrap_or(&[]);
            let Some((len, consumed)) = read_uvarint(rest) else {
                return Ok(false);
            };
            let Some(mut modinfo) = usize::try_from(len).ok().and_then(|l| rest.get(consumed..consumed.checked_add(l)?)) else {
                return Ok(false);
            };
            if modinfo.len() >= 33 && modinfo.get(modinfo.len().saturating_sub(17)) == Some(&b'\n') {
                modinfo = modinfo.get(16..modinfo.len().saturating_sub(16)).unwrap_or(&[]);
            }
            self.go_build.runtime_mod_info = Some(String::from_utf8_lossy(modinfo).into_owned());
            return Ok(true);
        }
        let ptr_size = usize::from(info.get(GO_BUILD_INFO_PTR_OFFSET).copied().unwrap_or(0));
        if info.get(GO_BUILD_INFO_PTR_OFFSET.saturating_add(1)).copied().unwrap_or(0) != 0 {
            return Err(MachoError::BigEndianGoBuildInfo);
        }
        let r = Reader::new(info, false);
        let read_ptr = |at: usize| -> Option<u64> {
            if ptr_size == 4 {
                r.u32(at).map(u64::from)
            } else {
                r.u64(at)
            }
        };
        let base = GO_BUILD_INFO_PTR_OFFSET.saturating_add(2);
        let (Some(version_va), Some(modinfo_va)) = (read_ptr(base), read_ptr(base.saturating_add(ptr_size))) else {
            return Ok(false);
        };
        let Some(version) = self.read_go_string(source, version_va, ptr_size) else {
            return Ok(false);
        };
        self.go_build.runtime_build_version = Some(String::from_utf8_lossy(&version).into_owned());
        let Some(modinfo) = self.read_go_string(source, modinfo_va, ptr_size) else {
            return Ok(false);
        };
        let trimmed = if modinfo.len() >= 33 && modinfo.get(modinfo.len().saturating_sub(17)) == Some(&b'\n') {
            modinfo.get(16..modinfo.len().saturating_sub(16)).unwrap_or(&[])
        } else {
            modinfo.as_slice()
        };
        self.go_build.runtime_mod_info = Some(String::from_utf8_lossy(trimmed).into_owned());
        Ok(true)
    }

    /// A Go string header `(data pointer, length)` at virtual address
    /// `va`, then its bytes (`ParseGoBuildInfo` pointer path).
    fn read_go_string<S: MachoSource + ?Sized>(&self, source: &mut S, va: u64, ptr_size: usize) -> Option<Vec<u8>> {
        let header_fa = self.va_to_fa(va);
        let header = source.read_up_to(header_fa, (ptr_size as u32).saturating_mul(2))?;
        let r = Reader::new(&header, false);
        let (data_va, len) = if ptr_size == 4 {
            (u64::from(r.u32(0)?), u64::from(r.u32(4)?))
        } else {
            (r.u64(0)?, r.u64(8)?)
        };
        let data_offset = self.va_to_fa(data_va);
        let len = u32::try_from(len).ok()?;
        let data = source.read_up_to(data_offset, len)?;
        (data.len() as u64 == u64::from(len)).then_some(data)
    }

    /// C++ `Update()` fat branch.
    fn set_fat_archs<S: MachoSource + ?Sized>(&mut self, source: &mut S) -> bool {
        let Some(buf) = source.read_exact(0, FAT_HEADER_SIZE as u32) else {
            return false;
        };
        let r = Reader::new(&buf, self.should_swap);
        let Some(count) = r.u32(4) else {
            return false;
        };
        self.fat_arch_count = count;
        self.archs.clear();
        let mut offset = FAT_HEADER_SIZE as u64;
        let entry_size = if self.is64 { FAT_ARCH64_SIZE } else { FAT_ARCH_SIZE };
        for _ in 0..count {
            let Some(abuf) = source.read_exact(offset, entry_size as u32) else {
                return false;
            };
            let ar = Reader::new(&abuf, self.should_swap);
            let Some(mut arch) = (if self.is64 {
                (|| {
                    Some(Arch {
                        cputype: ar.i32(0)?,
                        cpusubtype: ar.i32(4)?,
                        offset: ar.u64(8)?,
                        size: ar.u64(16)?,
                        align: ar.u32(24)?,
                        reserved: ar.u64(24)?,
                        ..Arch::default()
                    })
                })()
            } else {
                (|| {
                    Some(Arch {
                        cputype: ar.i32(0)?,
                        cpusubtype: ar.i32(4)?,
                        offset: u64::from(ar.u32(8)?),
                        size: u64::from(ar.u32(12)?),
                        align: ar.u32(16)?,
                        ..Arch::default()
                    })
                })()
            }) else {
                return false;
            };
            offset = offset.saturating_add(entry_size as u64);
            // The member's mach_header (full 32 bytes, as `Copy<mach_header>`).
            let Some(mh) = source.read_exact(arch.offset, MACH_HEADER_64_SIZE as u32) else {
                return false;
            };
            let raw = Reader::new(&mh, false);
            let magic = raw.u32(0).unwrap_or(0);
            let hr = Reader::new(&mh, magic == MH_CIGAM || magic == MH_CIGAM_64);
            arch.filetype = hr.u32(12).unwrap_or(0);
            arch.info = arch_info(arch.cputype, arch.cpusubtype.cast_unsigned());
            self.archs.push(arch);
        }
        true
    }

    /// C++ `HasPanel`.
    #[must_use]
    pub const fn has_panel(&self, id: PanelId) -> bool {
        self.panels_mask & id.bit() != 0
    }

    /// C++ `VAtoFA`: first segment (skipping `__PAGEZERO`) whose
    /// `[vmaddr, vmaddr + filesize - 1]` contains the address, with
    /// wrapping arithmetic; `-1` otherwise.
    #[must_use]
    pub fn va_to_fa(&self, addr: u64) -> u64 {
        for seg in &self.segments {
            let end = seg.vmaddr.wrapping_add(seg.filesize).wrapping_sub(1);
            if seg.vmaddr <= addr && addr <= end {
                if seg.segname == PAGEZERO_SEGMENT {
                    continue;
                }
                return addr.wrapping_sub(seg.vmaddr).wrapping_add(seg.fileoff);
            }
        }
        MACHO_INVALID_ADDRESS
    }

    /// Whether `offset` lies in an executable segment.
    #[must_use]
    pub fn is_in_executable_zone(&self, offset: u64) -> bool {
        self.executable_zones
            .iter()
            .any(|&(start, end)| offset >= start && offset < end)
    }

    /// `sizeof(mach_header) + (is64 ? sizeof(reserved) : 0)` — the
    /// `Header` zone size of `CreateBufferView`.
    #[must_use]
    pub const fn header_size(&self) -> u64 {
        if self.is64 {
            MACH_HEADER_64_SIZE as u64
        } else {
            MACH_HEADER_SIZE as u64
        }
    }

    /// `sizeof(nlist_64)` / `sizeof(nlist)` for this file.
    #[must_use]
    pub const fn nlist_size(&self) -> u64 {
        if self.is64 {
            NLIST_64_SIZE as u64
        } else {
            NLIST_SIZE as u64
        }
    }

    /// `sizeof(fat_arch64)` / `sizeof(fat_arch)` for this file.
    #[must_use]
    pub const fn fat_arch_size(&self) -> u64 {
        if self.is64 {
            FAT_ARCH64_SIZE as u64
        } else {
            FAT_ARCH_SIZE as u64
        }
    }
}

/// `CPU_TYPE_I386` / `CPU_TYPE_X86_64` (opcode colouring / panel).
#[must_use]
pub const fn is_intel_cpu(cputype: i32) -> bool {
    matches!(cputype, CPU_TYPE_I386 | CPU_TYPE_X86_64)
}

fn read_segment(r: &Reader<'_>, is64: bool) -> Option<Segment> {
    let mut segment = Segment {
        cmd: r.u32(0)?,
        cmdsize: r.u32(4)?,
        segname: r.name16(8)?,
        ..Segment::default()
    };
    let tail = if is64 {
        segment.vmaddr = r.u64(24)?;
        segment.vmsize = r.u64(32)?;
        segment.fileoff = r.u64(40)?;
        segment.filesize = r.u64(48)?;
        56
    } else {
        segment.vmaddr = u64::from(r.u32(24)?);
        segment.vmsize = u64::from(r.u32(28)?);
        segment.fileoff = u64::from(r.u32(32)?);
        segment.filesize = u64::from(r.u32(36)?);
        40
    };
    segment.maxprot = r.u32(tail)?;
    segment.initprot = r.u32(tail.checked_add(4)?)?;
    segment.nsects = r.u32(tail.checked_add(8)?)?;
    segment.flags = r.u32(tail.checked_add(12)?)?;
    Some(segment)
}

fn read_section(r: &Reader<'_>, is64: bool) -> Option<Section> {
    let mut section = Section {
        sectname: r.name16(0)?,
        segname: r.name16(16)?,
        ..Section::default()
    };
    let tail = if is64 {
        section.addr = r.u64(32)?;
        section.size = r.u64(40)?;
        48
    } else {
        section.addr = u64::from(r.u32(32)?);
        section.size = u64::from(r.u32(36)?);
        40
    };
    section.offset = r.u32(tail)?;
    section.align = r.u32(tail.checked_add(4)?)?;
    section.reloff = r.u32(tail.checked_add(8)?)?;
    section.nreloc = r.u32(tail.checked_add(12)?)?;
    section.flags = r.u32(tail.checked_add(16)?)?;
    section.reserved1 = r.u32(tail.checked_add(20)?)?;
    section.reserved2 = r.u32(tail.checked_add(24)?)?;
    section.reserved3 = if is64 { r.u32(tail.checked_add(28)?)? } else { 0 };
    Some(section)
}

fn read_nlist(r: &Reader<'_>, at: usize, is64: bool) -> Option<NList> {
    Some(NList {
        n_strx: r.u32(at)?,
        n_type: r.u8(at.checked_add(4)?)?,
        n_sect: r.u8(at.checked_add(5)?)?,
        n_desc: r.u16(at.checked_add(6)?)?,
        n_value: if is64 {
            r.u64(at.checked_add(8)?)?
        } else {
            u64::from(r.u32(at.checked_add(8)?)?)
        },
        name: String::new(),
    })
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::unnecessary_to_owned,
    clippy::useless_vec,
    clippy::bool_assert_comparison,
    clippy::redundant_clone
)]
pub mod tests {
    use super::*;
    use gview_core::object::Object;

    /// Byte-order helper for the fixtures.
    fn put(out: &mut Vec<u8>, bytes: &[u8], be: bool) {
        if be {
            out.extend(bytes.iter().rev());
        } else {
            out.extend_from_slice(bytes);
        }
    }

    fn u32v(out: &mut Vec<u8>, v: u32, be: bool) {
        put(out, &v.to_le_bytes(), be);
    }

    fn u64v(out: &mut Vec<u8>, v: u64, be: bool) {
        put(out, &v.to_le_bytes(), be);
    }

    fn name16(out: &mut Vec<u8>, name: &str) {
        let mut n = [0_u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
    }

    /// A section spec: `(sectname, addr, size, file offset)`.
    pub type SectSpec = (&'static str, u64, u64, u32);

    /// Encodes a `segment_command(_64)` with its sections.
    pub fn segment(is64: bool, be: bool, name: &str, vmaddr: u64, fileoff: u64, filesize: u64, initprot: u32, sections: &[SectSpec]) -> Vec<u8> {
        let mut out = Vec::new();
        let (seg_size, sect_size) = if is64 {
            (SEGMENT_COMMAND_64_SIZE, SECTION_64_SIZE)
        } else {
            (SEGMENT_COMMAND_SIZE, SECTION_SIZE)
        };
        let cmdsize = (seg_size + sect_size * sections.len()) as u32;
        u32v(&mut out, if is64 { lc::SEGMENT_64 } else { lc::SEGMENT }, be);
        u32v(&mut out, cmdsize, be);
        name16(&mut out, name);
        if is64 {
            u64v(&mut out, vmaddr, be);
            u64v(&mut out, filesize, be);
            u64v(&mut out, fileoff, be);
            u64v(&mut out, filesize, be);
        } else {
            u32v(&mut out, vmaddr as u32, be);
            u32v(&mut out, filesize as u32, be);
            u32v(&mut out, fileoff as u32, be);
            u32v(&mut out, filesize as u32, be);
        }
        u32v(&mut out, 7, be); // maxprot
        u32v(&mut out, initprot, be);
        u32v(&mut out, sections.len() as u32, be);
        u32v(&mut out, 0, be);
        for (sectname, addr, size, offset) in sections {
            name16(&mut out, sectname);
            name16(&mut out, name);
            if is64 {
                u64v(&mut out, *addr, be);
                u64v(&mut out, *size, be);
            } else {
                u32v(&mut out, *addr as u32, be);
                u32v(&mut out, *size as u32, be);
            }
            u32v(&mut out, *offset, be);
            for v in [4_u32, 0, 0, 0x8000_0400, 0, 0] {
                u32v(&mut out, v, be);
            }
            if is64 {
                u32v(&mut out, 0, be);
            }
        }
        out
    }

    /// Generic command: `cmd`, `cmdsize`, payload `u32`s / `u64`s.
    pub fn command(be: bool, cmd: u32, fields32: &[u32], fields64: &[u64], tail: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let cmdsize = 8 + fields32.len() * 4 + fields64.len() * 8 + tail.len();
        u32v(&mut out, cmd, be);
        u32v(&mut out, cmdsize as u32, be);
        for f in fields32 {
            u32v(&mut out, *f, be);
        }
        for f in fields64 {
            u64v(&mut out, *f, be);
        }
        out.extend_from_slice(tail);
        out
    }

    /// Assembles a thin Mach-O: header, commands, then `body` appended
    /// so that `body_offset()` = header + commands.
    pub fn thin(is64: bool, be: bool, cputype: i32, commands: &[Vec<u8>], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let magic = match (is64, be) {
            (true, false) => MH_MAGIC_64,
            (true, true) => MH_CIGAM_64,
            (false, false) => MH_MAGIC,
            (false, true) => MH_CIGAM,
        };
        // The magic itself is written so that a little-endian read gives `magic`.
        out.extend_from_slice(&magic.to_le_bytes());
        u32v(&mut out, cputype as u32, be);
        u32v(&mut out, 3, be);
        u32v(&mut out, 2, be); // EXECUTE
        u32v(&mut out, commands.len() as u32, be);
        let sizeofcmds: usize = commands.iter().map(Vec::len).sum();
        u32v(&mut out, sizeofcmds as u32, be);
        u32v(&mut out, 0x0020_0085, be);
        if is64 {
            u32v(&mut out, 0, be);
        }
        for c in commands {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(body);
        out
    }

    /// Header + commands size for the fixtures.
    pub fn body_offset(is64: bool, commands: &[Vec<u8>]) -> u64 {
        let header = if is64 { MACH_HEADER_64_SIZE } else { MACH_HEADER_SIZE };
        (header + commands.iter().map(Vec::len).sum::<usize>()) as u64
    }

    /// A typical x86_64 executable with `__PAGEZERO`, `__TEXT` (+
    /// `__text`), `__LINKEDIT`, `LC_SYMTAB`, `LC_MAIN`, `LC_LOAD_DYLIB`,
    /// `LC_UUID`, `LC_SOURCE_VERSION`, `LC_VERSION_MIN_MACOSX`,
    /// `LC_DYLD_INFO_ONLY`, `LC_FUNCTION_STARTS`, `LC_CODE_SIGNATURE`.
    pub fn typical(is64: bool, be: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
        // Layout: commands end, then: text (0x100) at body, strings, symbols.
        let text_size = 0x100_u64;
        let strings = b"\0_main\0_helper\0".to_vec();
        let mut symbols = Vec::new();
        for (strx, value) in [(1_u32, 0x1000_u64), (7, 0x1040)] {
            u32v(&mut symbols, strx, be);
            symbols.push(0x0F); // n_type
            symbols.push(1); // n_sect
            put(&mut symbols, &0x0010_u16.to_le_bytes(), be);
            if is64 {
                u64v(&mut symbols, value, be);
            } else {
                u32v(&mut symbols, value as u32, be);
            }
        }
        // Two-pass: command sizes are fixed so compute body offset first.
        let dylib_name = b"/usr/lib/libSystem.B.dylib\0\0\0\0\0\0";
        let mut cmds_probe = vec![
            segment(is64, be, "__PAGEZERO", 0, 0, 0, 0, &[]),
            segment(is64, be, "__TEXT", 0x1000, 0, 0, 5, &[("__text", 0x1000, text_size, 0)]),
            segment(is64, be, "__LINKEDIT", 0x2000, 0, 0, 1, &[]),
            command(be, lc::SYMTAB, &[0, 2, 0, strings.len() as u32], &[], &[]),
            command(be, lc::MAIN, &[], &[0x40, 0], &[]),
            command(be, lc::LOAD_DYLIB, &[24, 2, 0x0001_0000, 0x0001_0000], &[], dylib_name),
            command(be, lc::UUID, &[], &[], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            command(be, lc::SOURCE_VERSION, &[], &[0x0000_0100_0000_0000], &[]),
            command(be, lc::VERSION_MIN_MACOSX, &[0x000A_0F00, 0x000A_0F00], &[], &[]),
            command(be, lc::DYLD_INFO_ONLY, &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0], &[], &[]),
            command(be, lc::FUNCTION_STARTS, &[0x300, 0x10], &[], &[]),
            command(be, lc::CODE_SIGNATURE, &[0x400, 0x20], &[], &[]),
        ];
        let body = body_offset(is64, &cmds_probe);
        let text_off = body;
        let str_off = text_off + text_size;
        let sym_off = str_off + strings.len() as u64;
        cmds_probe[1] = segment(is64, be, "__TEXT", 0x1000, 0, text_off + text_size, 5, &[("__text", 0x1000, text_size, text_off as u32)]);
        cmds_probe[2] = segment(is64, be, "__LINKEDIT", 0x2000, str_off, (strings.len() + symbols.len()) as u64, 1, &[]);
        cmds_probe[3] = command(be, lc::SYMTAB, &[sym_off as u32, 2, str_off as u32, strings.len() as u32], &[], &[]);
        let mut text = vec![0x90_u8; text_size as usize];
        text[0..4].copy_from_slice(&[0x55, 0x8B, 0xEC, 0xCC]);
        let mut file_body = text;
        file_body.extend_from_slice(&strings);
        file_body.extend_from_slice(&symbols);
        (thin(is64, be, if is64 { CPU_TYPE_X86_64 } else { CPU_TYPE_I386 }, &cmds_probe, &file_body), cmds_probe)
    }

    #[test]
    fn parses_thin_x86_64_with_all_command_families() {
        for (is64, be) in [(true, false), (false, false), (true, true), (false, true)] {
            let (image, cmds) = typical(is64, be);
            let m = MachoFile::parse_bytes(&image).expect("parse");
            assert!(m.is_macho, "is64={is64} be={be}");
            assert!(!m.is_fat);
            assert_eq!(m.is64, is64);
            assert_eq!(m.should_swap, be);
            assert_eq!(m.header.cputype, if is64 { CPU_TYPE_X86_64 } else { CPU_TYPE_I386 });
            assert_eq!(m.header.ncmds, 12);
            assert_eq!(m.header.filetype, 2);
            assert_eq!(m.header.flags, 0x0020_0085);
            assert_eq!(m.load_commands.len(), 12);
            assert_eq!(m.load_commands[0].offset, m.header_size());
            assert_eq!(m.load_commands[1].offset, m.header_size() + cmds[0].len() as u64);
            assert_eq!(m.load_commands[3].cmd, lc::SYMTAB);
            // Segments and sections.
            assert_eq!(m.segments.len(), 3);
            assert_eq!(m.segments[0].segname, "__PAGEZERO");
            assert_eq!(m.segments[1].segname, "__TEXT");
            assert_eq!(m.segments[1].vmaddr, 0x1000);
            assert_eq!(m.segments[1].initprot, 5);
            assert_eq!(m.segments[1].nsects, 1);
            assert_eq!(m.segments[1].sections.len(), 1);
            let text = &m.segments[1].sections[0];
            assert_eq!(text.sectname, "__text");
            assert_eq!(text.segname, "__TEXT");
            assert_eq!(text.addr, 0x1000);
            assert_eq!(text.size, 0x100);
            assert_eq!(u64::from(text.offset), body_offset(is64, &cmds));
            assert_eq!(text.flags, 0x8000_0400);
            assert_eq!(text.zone_start(), u64::from(text.offset));
            // Executable zones: __TEXT only (initprot has EXECUTE).
            assert_eq!(m.executable_zones, [(0, m.segments[1].filesize)]);
            assert!(m.is_in_executable_zone(u64::from(text.offset)));
            // Symbols.
            let symtab = m.symtab.as_ref().expect("symtab");
            assert_eq!(symtab.command.nsyms, 2);
            assert_eq!(symtab.symbols.len(), 2);
            assert_eq!(symtab.symbols[0].name, "_main");
            assert_eq!(symtab.symbols[0].n_value, 0x1000);
            assert_eq!(symtab.symbols[0].n_desc, 0x10);
            assert_eq!(symtab.symbols[0].n_type, 0x0F);
            assert_eq!(symtab.symbols[1].name, "_helper");
            assert_eq!(symtab.symbols[1].n_value, 0x1040);
            // LC_MAIN.
            let main = m.main.expect("main");
            assert_eq!(main.cmd, lc::MAIN);
            assert_eq!(main.entryoff, 0x40);
            assert_eq!(main.cmdsize, 24);
            // Dylib.
            assert_eq!(m.dylibs.len(), 1);
            assert_eq!(m.dylibs[0].name, "/usr/lib/libSystem.B.dylib");
            assert_eq!(m.dylibs[0].name_offset, 24);
            assert_eq!(m.dylibs[0].current_version, 0x0001_0000);
            assert_eq!(m.dylibs[0].offset, m.load_commands[5].offset);
            // UUID (on-disk order, never reversed).
            assert_eq!(m.uuid.expect("uuid").uuid, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
            assert_eq!(m.source_version.expect("sv").version, 0x0000_0100_0000_0000);
            let vm = m.version_min.expect("version min");
            assert_eq!(vm.cmd, lc::VERSION_MIN_MACOSX);
            assert_eq!(vm.version, 0x000A_0F00);
            let di = m.dyld_info.expect("dyld info");
            assert_eq!(di.cmd, lc::DYLD_INFO_ONLY);
            assert_eq!(di.rebase_off, 0x10);
            assert_eq!(di.export_size, 0xA0);
            assert_eq!(m.linkedit_datas.len(), 2);
            assert_eq!(m.linkedit_datas[0].cmd, lc::FUNCTION_STARTS);
            assert_eq!(m.linkedit_datas[1].dataoff, 0x400);
            assert_eq!(m.linkedit_datas[1].datasize, 0x20);
            // Panels.
            for id in [
                PanelId::Information,
                PanelId::LoadCommands,
                PanelId::Segments,
                PanelId::Sections,
                PanelId::DyldInfo,
                PanelId::Dylib,
                PanelId::DySymTab,
                PanelId::OpCodes,
            ] {
                assert!(m.has_panel(id), "{id:?}");
            }
            assert!(!m.has_panel(PanelId::GoInformation));
            assert_eq!(m.go_build, GoBuildInfo::default());
            // VAtoFA: __PAGEZERO skipped, __TEXT maps, beyond invalid.
            assert_eq!(m.va_to_fa(0x1010), 0x10);
            assert_eq!(m.va_to_fa(0x2000), m.segments[2].fileoff);
            assert_eq!(m.va_to_fa(0x9_0000), MACHO_INVALID_ADDRESS);
            assert_eq!(m.va_to_fa(0), MACHO_INVALID_ADDRESS, "__PAGEZERO is skipped");
            assert_eq!(m.nlist_size(), if is64 { 16 } else { 12 });
        }
    }

    #[test]
    fn cache_and_bytes_paths_agree() {
        let (image, _) = typical(true, false);
        let mut object = Object::from_buffer(&image, "a.out", 0);
        let from_cache = MachoFile::parse_cache(object.data_mut()).expect("cache");
        let from_bytes = MachoFile::parse_bytes(&image).expect("bytes");
        assert_eq!(from_cache, from_bytes);
    }

    #[test]
    fn unixthread_entry_point_per_cpu_and_unhandled_cpu_errors() {
        let mut state = vec![0_u8; 16 + 16 * 4];
        state[16 + I386_EIP_OFFSET..16 + I386_EIP_OFFSET + 4].copy_from_slice(&0x1234_u32.to_le_bytes());
        let cmd = command(false, lc::UNIXTHREAD, &[], &[], &state[8..]);
        let image = thin(false, false, CPU_TYPE_I386, std::slice::from_ref(&cmd), &[]);
        let m = MachoFile::parse_bytes(&image).expect("parse");
        let main = m.main.expect("main");
        assert_eq!(main.cmd, lc::UNIXTHREAD);
        assert_eq!(main.entryoff, 0x1234);

        let mut state64 = vec![0_u8; 16 + 21 * 8];
        state64[16 + X86_64_RIP_OFFSET..16 + X86_64_RIP_OFFSET + 8].copy_from_slice(&0x1_0000_ABCD_u64.to_le_bytes());
        let cmd64 = command(false, lc::UNIXTHREAD, &[], &[], &state64[8..]);
        let image = thin(true, false, CPU_TYPE_X86_64, &[cmd64], &[]);
        assert_eq!(MachoFile::parse_bytes(&image).expect("parse").main.expect("main").entryoff, 0x1_0000_ABCD);

        // PowerPC (big-endian on disk): srr0 first.
        let mut ppc = vec![0_u8; 16 + 40 * 4];
        ppc[16..20].copy_from_slice(&0x0000_2000_u32.to_be_bytes());
        let cmdppc = command(true, lc::UNIXTHREAD, &[], &[], &ppc[8..]);
        let image = thin(false, true, CPU_TYPE_POWERPC, &[cmdppc], &[]);
        assert_eq!(MachoFile::parse_bytes(&image).expect("parse").main.expect("main").entryoff, 0x2000);
        let mut ppc64 = vec![0_u8; 16 + 40 * 8];
        ppc64[16..24].copy_from_slice(&0x3000_u64.to_be_bytes());
        let cmdppc64 = command(true, lc::UNIXTHREAD, &[], &[], &ppc64[8..]);
        let image = thin(true, true, CPU_TYPE_POWERPC64, &[cmdppc64], &[]);
        assert_eq!(MachoFile::parse_bytes(&image).expect("parse").main.expect("main").entryoff, 0x3000);

        // ARM64 with LC_UNIXTHREAD: the C++ throws.
        let image = thin(true, false, CPU_TYPE_ARM64, &[cmd], &[]);
        assert_eq!(MachoFile::parse_bytes(&image), Err(MachoError::UnhandledUnixThreadCpu(CPU_TYPE_ARM64)));
    }

    #[test]
    fn duplicate_commands_are_errors_like_the_cpp_throws() {
        let dup = |cmd: Vec<u8>, err: MachoError| {
            let image = thin(true, false, CPU_TYPE_X86_64, &[cmd.clone(), cmd], &[]);
            assert_eq!(MachoFile::parse_bytes(&image), Err(err));
        };
        dup(command(false, lc::MAIN, &[], &[0, 0], &[]), MachoError::DuplicateMain);
        dup(command(false, lc::DYLD_INFO, &[0; 10], &[], &[]), MachoError::DuplicateDyldInfo);
        dup(command(false, lc::SYMTAB, &[0, 0, 0, 0], &[], &[]), MachoError::DuplicateSymtab);
        dup(command(false, lc::UUID, &[], &[], &[0; 16]), MachoError::DuplicateUuid);
        dup(command(false, lc::SOURCE_VERSION, &[], &[0], &[]), MachoError::DuplicateSourceVersion);
        dup(command(false, lc::VERSION_MIN_IPHONEOS, &[0, 0], &[], &[]), MachoError::DuplicateVersionMin);
        assert!(MachoError::DuplicateSymtab.to_string().contains("SYMTAB"));
    }

    #[test]
    fn partial_stages_keep_state_and_never_panic() {
        // Header only, no commands readable: is_macho with empty tables.
        let mut image = thin(true, false, CPU_TYPE_ARM64, &[], &[]);
        image[16..20].copy_from_slice(&5_u32.to_le_bytes()); // ncmds = 5, nothing follows
        let m = MachoFile::parse_bytes(&image).expect("parse");
        assert!(m.is_macho);
        assert_eq!(m.header.ncmds, 5);
        assert!(m.load_commands.is_empty());
        assert!(m.has_panel(PanelId::LoadCommands));
        assert!(!m.has_panel(PanelId::Segments));
        assert!(!m.has_panel(PanelId::OpCodes), "ARM64 has no opcode panel");
        // 32-bit header shorter than 32 bytes: SetHeader fails (C++ copies 32).
        let short = thin(false, false, CPU_TYPE_I386, &[], &[]);
        assert_eq!(short.len(), MACH_HEADER_SIZE);
        let m = MachoFile::parse_bytes(&short).expect("parse");
        assert!(m.is_macho);
        assert_eq!(m.header, MachHeader::default());
        // cmdsize 0: the walk stops instead of spinning.
        let mut zero = thin(true, false, CPU_TYPE_X86_64, &[command(false, lc::UUID, &[], &[], &[0; 16])], &[]);
        zero[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        zero[36..40].copy_from_slice(&0_u32.to_le_bytes());
        let m = MachoFile::parse_bytes(&zero).expect("parse");
        assert_eq!(m.load_commands.len(), 1);
        assert_eq!(m.load_commands[0].cmdsize, 0);
        // LC_MAIN present but truncated: `main` exists with zeros.
        let mut truncated_main = thin(true, false, CPU_TYPE_X86_64, &[command(false, lc::MAIN, &[], &[0x77, 0], &[])], &[]);
        truncated_main.truncate(MACH_HEADER_64_SIZE + 8);
        let m = MachoFile::parse_bytes(&truncated_main).expect("parse");
        assert_eq!(m.main, Some(EntryPointCommand::default()));
        // SYMTAB with an unreadable string table: panel on, no symbols.
        let sym = command(false, lc::SYMTAB, &[0x9_0000, 3, 0x9_0000, 0x10], &[], &[]);
        let m = MachoFile::parse_bytes(&thin(true, false, CPU_TYPE_X86_64, &[sym], &[])).expect("parse");
        assert!(m.has_panel(PanelId::DySymTab));
        assert_eq!(m.symtab.as_ref().map(|s| s.symbols.len()), Some(0));
        assert_eq!(m.symtab.as_ref().map(|s| s.command.nsyms), Some(3));
        // Segment whose sections run past the file: partial segments.
        let seg = segment(true, false, "__DATA", 0x3000, 0, 0, 3, &[("__data", 0x3000, 8, 0)]);
        let mut cut = thin(true, false, CPU_TYPE_X86_64, &[seg], &[]);
        cut.truncate(MACH_HEADER_64_SIZE + SEGMENT_COMMAND_64_SIZE + 10);
        let m = MachoFile::parse_bytes(&cut).expect("parse");
        assert!(m.segments.is_empty());
        // Not a Mach-O at all.
        let m = MachoFile::parse_bytes(b"MZ\x90\x00").expect("parse");
        assert!(!m.is_macho && !m.is_fat);
        assert_eq!(m.panels_mask, PanelId::Information.bit());
        assert_eq!(MachoFile::parse_bytes(b"").expect("parse").panels_mask, PanelId::Information.bit());
    }

    #[test]
    fn go_build_id_buildinfo_and_pclntab() {
        let is64 = true;
        let be = false;
        // __TEXT holds the build id; __DATA holds __go_buildinfo (pointer
        // form) and __gopclntab.
        let mut text = Vec::new();
        text.extend_from_slice(b"\x00\xff Go build ID: \"abc123/def\"\n \xff\x00\x00");
        text.resize(0x80, 0);
        let mut data = vec![0_u8; 0x100];
        // buildinfo at data+0: magic(14) ptrSize=8 flags=0, then two VAs.
        data[..14].copy_from_slice(GO_BUILD_INFO_MAGIC);
        data[14] = 8;
        data[15] = 0;
        let data_va = 0x2000_u64;
        let version_hdr_va = data_va + 0x40;
        let modinfo_hdr_va = data_va + 0x50;
        data[16..24].copy_from_slice(&version_hdr_va.to_le_bytes());
        data[24..32].copy_from_slice(&modinfo_hdr_va.to_le_bytes());
        let version = b"go1.21.0";
        let modinfo = b"path\tcmd\nmod\tx\n";
        let version_va = data_va + 0x60;
        let modinfo_va = data_va + 0x70;
        data[0x40..0x48].copy_from_slice(&version_va.to_le_bytes());
        data[0x48..0x50].copy_from_slice(&(version.len() as u64).to_le_bytes());
        data[0x50..0x58].copy_from_slice(&modinfo_va.to_le_bytes());
        data[0x58..0x60].copy_from_slice(&(modinfo.len() as u64).to_le_bytes());
        data[0x60..0x60 + version.len()].copy_from_slice(version);
        data[0x70..0x70 + modinfo.len()].copy_from_slice(modinfo);
        let pclntab = [0xF1, 0xFF, 0xFF, 0xFF, 0, 0, 1, 8];
        data[0x90..0x98].copy_from_slice(&pclntab);

        let probe = vec![
            segment(is64, be, "__TEXT", 0x1000, 0, 0, 5, &[("__text", 0x1000, 0x80, 0)]),
            segment(is64, be, "__DATA", data_va, 0, 0, 3, &[("__go_buildinfo", data_va, 0x40, 0), ("__gopclntab", data_va + 0x90, 8, 0)]),
        ];
        let body = body_offset(is64, &probe);
        let text_off = body;
        let data_off = body + text.len() as u64;
        let cmds = vec![
            segment(is64, be, "__TEXT", 0x1000, text_off, text.len() as u64, 5, &[("__text", 0x1000, 0x80, text_off as u32)]),
            segment(
                is64,
                be,
                "__DATA",
                data_va,
                data_off,
                data.len() as u64,
                3,
                &[("__go_buildinfo", data_va, 0x40, data_off as u32), ("__gopclntab", data_va + 0x90, 8, data_off as u32 + 0x90)],
            ),
        ];
        let mut file_body = text.clone();
        file_body.extend_from_slice(&data);
        let image = thin(is64, be, CPU_TYPE_ARM64, &cmds, &file_body);
        let m = MachoFile::parse_bytes(&image).expect("parse");
        assert_eq!(m.go_build.build_id.as_deref(), Some("abc123/def"));
        assert_eq!(m.go_build.runtime_build_version.as_deref(), Some("go1.21.0"));
        assert_eq!(m.go_build.runtime_mod_info.as_deref(), Some("path\tcmd\nmod\tx\n"));
        assert!(m.has_panel(PanelId::GoInformation));
        assert_eq!(m.go_pclntab, Some((data_off + 0x90, 8)));

        // Inline (flags & 2) form: varint-prefixed strings after the header.
        let mut inline = vec![0_u8; 0x80];
        inline[..14].copy_from_slice(GO_BUILD_INFO_MAGIC);
        inline[14] = 8;
        inline[15] = 2;
        let mut p = 32;
        inline[p] = 6;
        inline[p + 1..p + 7].copy_from_slice(b"go1.22");
        p += 7;
        // 40-byte modinfo with the 16-byte sentinel wrapper: `\n` at len-17.
        let mut wrapped = vec![b'0'; 16];
        wrapped.extend_from_slice(b"inner-1\n");
        wrapped.extend_from_slice(&[b'1'; 16]);
        let wl = wrapped.len();
        wrapped[wl - 17] = b'\n';
        inline[p] = wl as u8;
        inline[p + 1..p + 1 + wl].copy_from_slice(&wrapped);
        let probe = vec![
            segment(is64, be, "__TEXT", 0x1000, 0, 0, 5, &[("__text", 0x1000, 0x80, 0)]),
            segment(is64, be, "__DATA", data_va, 0, 0, 3, &[("__go_buildinfo", data_va, 0x80, 0)]),
        ];
        let text_off = body_offset(is64, &probe);
        let data_off = text_off + text.len() as u64;
        let cmds = vec![
            segment(is64, be, "__TEXT", 0x1000, text_off, text.len() as u64, 5, &[("__text", 0x1000, 0x80, text_off as u32)]),
            segment(is64, be, "__DATA", data_va, data_off, inline.len() as u64, 3, &[("__go_buildinfo", data_va, 0x80, data_off as u32)]),
        ];
        let mut file_body = text.clone();
        file_body.extend_from_slice(&inline);
        let m = MachoFile::parse_bytes(&thin(is64, be, CPU_TYPE_ARM64, &cmds, &file_body)).expect("parse");
        assert_eq!(m.go_build.runtime_build_version.as_deref(), Some("go1.22"));
        assert_eq!(m.go_build.runtime_mod_info.as_deref(), Some("inner-1\n"));
        // ParseGoData succeeds once the build id is found, so the Go
        // panels are on even without `__gopclntab` (C++ parity).
        assert!(m.has_panel(PanelId::GoInformation));
        assert!(m.go_pclntab.is_none(), "no __gopclntab");

        // Big-endian build info: the C++ throws.
        let mut big = inline.clone();
        big[15] = 1;
        let mut file_body = text.clone();
        file_body.extend_from_slice(&big);
        assert_eq!(
            MachoFile::parse_bytes(&thin(is64, be, CPU_TYPE_ARM64, &cmds, &file_body)),
            Err(MachoError::BigEndianGoBuildInfo)
        );

        // No build id in __TEXT: no Go data at all, even with __gopclntab.
        let mut file_body = vec![0_u8; text.len()];
        file_body.extend_from_slice(&data);
        let probe = vec![
            segment(is64, be, "__TEXT", 0x1000, 0, 0, 5, &[]),
            segment(is64, be, "__DATA", data_va, 0, 0, 3, &[("__gopclntab", data_va + 0x90, 8, 0)]),
        ];
        let text_off = body_offset(is64, &probe);
        let data_off = text_off + text.len() as u64;
        let cmds_pcl = vec![
            segment(is64, be, "__TEXT", 0x1000, text_off, text.len() as u64, 5, &[]),
            segment(is64, be, "__DATA", data_va, data_off, data.len() as u64, 3, &[("__gopclntab", data_va + 0x90, 8, data_off as u32 + 0x90)]),
        ];
        let m = MachoFile::parse_bytes(&thin(is64, be, CPU_TYPE_ARM64, &cmds_pcl, &file_body)).expect("parse");
        assert!(!m.has_panel(PanelId::GoInformation));
        assert!(m.go_pclntab.is_none());
        assert_eq!(read_uvarint(&[0x80]), None);
        assert_eq!(read_uvarint(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
        assert_eq!(read_uvarint(&[0xFF; 11]), None);
    }

    /// Builds a fat archive around `members` (`(cputype, cpusubtype, bytes)`).
    pub fn fat(is64: bool, on_disk_big_endian: bool, members: &[(i32, i32, Vec<u8>)]) -> Vec<u8> {
        let be = on_disk_big_endian;
        let mut out = Vec::new();
        let magic = if is64 { FAT_MAGIC_64 } else { FAT_MAGIC };
        put(&mut out, &magic.to_le_bytes(), be);
        u32v(&mut out, members.len() as u32, be);
        let entry = if is64 { FAT_ARCH64_SIZE } else { FAT_ARCH_SIZE };
        let mut offset = (FAT_HEADER_SIZE + entry * members.len()) as u64;
        offset = (offset + 0xFFF) & !0xFFF;
        let mut offsets = Vec::new();
        for (cputype, cpusubtype, bytes) in members {
            u32v(&mut out, *cputype as u32, be);
            u32v(&mut out, *cpusubtype as u32, be);
            if is64 {
                u64v(&mut out, offset, be);
                u64v(&mut out, bytes.len() as u64, be);
                u32v(&mut out, 12, be);
                u32v(&mut out, 0, be);
            } else {
                u32v(&mut out, offset as u32, be);
                u32v(&mut out, bytes.len() as u32, be);
                u32v(&mut out, 12, be);
            }
            offsets.push(offset);
            offset = (offset + bytes.len() as u64 + 0xFFF) & !0xFFF;
        }
        for (i, (_, _, bytes)) in members.iter().enumerate() {
            out.resize(offsets[i] as usize, 0);
            out.extend_from_slice(bytes);
        }
        out
    }

    #[test]
    fn fat_archives_list_members_with_arch_info() {
        let (x86, _) = typical(true, false);
        let arm = thin(true, false, CPU_TYPE_ARM64, &[], &[]);
        for (is64, be) in [(false, true), (false, false), (true, true), (true, false)] {
            let image = fat(is64, be, &[(CPU_TYPE_X86_64, 3, x86.clone()), (CPU_TYPE_ARM64, 0, arm.clone())]);
            let m = MachoFile::parse_bytes(&image).expect("parse");
            assert!(m.is_fat && !m.is_macho, "is64={is64} be={be}");
            assert_eq!(m.is64, is64);
            assert_eq!(m.should_swap, be);
            assert_eq!(m.fat_arch_count, 2);
            assert_eq!(m.archs.len(), 2);
            assert_eq!(m.archs[0].cputype, CPU_TYPE_X86_64);
            assert_eq!(m.archs[0].info.name, "x86_64");
            assert_eq!(m.archs[0].info.description, "Intel x86-64");
            assert_eq!(m.archs[0].filetype, 2);
            assert_eq!(m.archs[0].align, 12);
            assert_eq!(m.archs[0].size, x86.len() as u64);
            assert_eq!(m.archs[0].offset, 0x1000);
            assert_eq!(m.archs[1].info.name, "arm64");
            assert_eq!(m.archs[1].info.description, "ARM64");
            assert_eq!(m.archs[1].filetype, 2);
            assert_eq!(m.fat_arch_size(), if is64 { 32 } else { 20 });
            assert_eq!(m.panels_mask, PanelId::Information.bit());
            assert!(m.load_commands.is_empty());
        }
        // Member table truncated: partial archs.
        let image = fat(false, true, &[(CPU_TYPE_X86_64, 3, x86.clone()), (CPU_TYPE_ARM64, 0, arm)]);
        let m = MachoFile::parse_bytes(&image[..0x1000 + x86.len()]).expect("parse");
        assert_eq!(m.fat_arch_count, 2);
        assert_eq!(m.archs.len(), 1);
        // Member header unreadable (offset past the end): stops there.
        let mut bad = fat(false, true, &[(CPU_TYPE_X86_64, 3, x86)]);
        bad[16..20].copy_from_slice(&0x00FF_0000_u32.to_be_bytes());
        assert!(MachoFile::parse_bytes(&bad).expect("parse").archs.is_empty());
    }

    #[test]
    fn arch_info_lookup_matches_cpp() {
        let a = arch_info(CPU_TYPE_X86_64, 3);
        assert_eq!((a.name.as_str(), a.description.as_str()), ("x86_64", "Intel x86-64"));
        assert_eq!(a.byteorder, ByteOrder::LittleEndian);
        // Capability bits are masked off.
        let a = arch_info(CPU_TYPE_X86_64, 0x8000_0003);
        assert_eq!(a.name, "x86_64");
        let a = arch_info(CPU_TYPE_X86_64, 8);
        assert_eq!(a.name, "x86_64h");
        // CPU_SUBTYPE_MULTIPLE matches the first entry of the cpu type.
        let a = arch_info(CPU_TYPE_ARM, CPU_SUBTYPE_MULTIPLE as u32);
        assert_eq!(a.name, "arm");
        assert_eq!(a.cpusubtype, 0);
        // Unknown i386 subtype: family / model description.
        let a = arch_info(CPU_TYPE_I386, 0x12);
        assert_eq!(a.name, "i386");
        assert_eq!(a.cpusubtype, 0x12);
        assert_eq!(a.description, "Intel family 2 model 1");
        // Unknown PowerPC subtype.
        let a = arch_info(CPU_TYPE_POWERPC, 77);
        assert_eq!(a.name, "ppc");
        assert_eq!(a.description, "PowerPC cpusubtype 77");
        assert_eq!(a.byteorder, ByteOrder::BigEndian);
        // Unknown cpu type: empty info with the subtype recorded.
        let a = arch_info(1234, 5);
        assert_eq!(a.name, "");
        assert_eq!(a.cputype, 0);
        assert_eq!(a.cpusubtype, 5);
        assert_eq!(a.byteorder, ByteOrder::Unknown);
        assert_eq!(ARCH_INFO_TABLE.len(), 57);
        assert!(is_intel_cpu(CPU_TYPE_I386) && is_intel_cpu(CPU_TYPE_X86_64) && !is_intel_cpu(CPU_TYPE_ARM64));
        assert!(lc::is_dylib(lc::LOAD_WEAK_DYLIB) && !lc::is_dylib(lc::SEGMENT));
        assert!(lc::is_linkedit_data(lc::DYLD_CHAINED_FIXUPS) && !lc::is_linkedit_data(lc::MAIN));
        assert!(lc::is_version_min(lc::VERSION_MIN_WATCHOS) && !lc::is_version_min(lc::UUID));
        assert_eq!(cstr_at(b"ab\0c", 0), "ab");
        assert_eq!(cstr_at(b"ab\0c", 9), "");
        assert_eq!(find(b"xxabcabc", b"abc", 3), Some(5));
        assert_eq!(find(b"xxabc", b"", 0), None);
        assert_eq!(find(b"xx", b"abc", 5), None);
    }

    #[test]
    fn bss_style_sections_use_their_address_as_zone_start() {
        let section = Section {
            offset: 0,
            addr: 0x5000,
            ..Section::default()
        };
        assert_eq!(section.zone_start(), 0x5000);
        assert_eq!(MachoError::UnhandledUnixThreadCpu(12).to_string(), "EP not handled for CPU 12 from LoadCommandType::UNIXTHREAD!");
        assert_eq!(MachoError::BigEndianGoBuildInfo.to_string(), "big-endian Go build info not handled");
    }
}
