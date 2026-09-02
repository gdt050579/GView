//! Mach-O enum name tables (C++ `Types/MachO/include/Mac.hpp` enums
//! and `Types/MachO/include/NameMapping.hpp` maps).
//!
//! Transcribed verbatim from the tables the `Information` panel reads:
//! `ByteOrderNames`, `MachHeaderFlagsNames`,
//! `MachHeaderFlagsDescriptions` and `LoadCommandNames`.
//! `GET_PAIR_FROM_ENUM(X::NAME)` makes the display name the
//! enumerator's own spelling, so these tables map a value to its C++
//! identifier.

use crate::parse::ByteOrder;

/// C++ `ByteOrderNames`.
#[must_use]
pub const fn byte_order_name(order: ByteOrder) -> &'static str {
    match order {
        ByteOrder::Unknown => "Unknown",
        ByteOrder::LittleEndian => "LittleEndian",
        ByteOrder::BigEndian => "BigEndian",
    }
}

/// C++ `MachHeaderFlagsNames` / `MachHeaderFlagsDescriptions`
/// joined: `(flag, name, description)` in ascending flag order,
/// which is the `std::map` iteration order `GetMachHeaderFlagsData`
/// relies on.
pub const MACH_HEADER_FLAGS: [(u32, &str, &str); 28] = [
    (0x1, "NOUNDEFS", "The object file has no undefined references."),
    (0x2, "INCRLINK", "The object file is the output of an incremental link against a base file and can't be link edited again."),
    (0x4, "DYLDLINK", "The object file is input for the dynamic linker and can't be staticly link edited again."),
    (0x8, "BINDATLOAD", "The object file's undefined references are bound by the dynamic linker when loaded."),
    (0x10, "PREBOUND", "The file has its dynamic undefined references prebound."),
    (0x20, "SPLIT_SEGS", "The file has its read-only and read-write segments split."),
    (0x40, "LAZY_INIT", "The shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)."),
    (0x80, "TWOLEVEL", "The image is using two-level name space bindings."),
    (0x100, "FORCE_FLAT", "The executable is forcing all images to use flat name space bindings."),
    (0x200, "NOMULTIDEFS", "This umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used."),
    (0x400, "NOFIXPREBINDING", "Do not have dyld notify the prebinding agent about this executable."),
    (0x800, "PREBINDABLE", "The binary is not prebound but can have its prebinding redone -> only used when FileType::PREBOUND is not set."),
    (0x1000, "ALLMODSBOUND", "Indicates that this binary binds to all two-level namespace modules of its dependent libraries -> only used when MH_PREBINDABLE and MH_TWOLEVEL are both set."),
    (0x2000, "SUBSECTIONS_VIA_SYMBOLS", "Safe to divide up the sections into sub-sections via symbols for dead code stripping."),
    (0x4000, "CANONICAL", "The binary has been canonicalized via the unprebind operation."),
    (0x8000, "WEAK_DEFINES", "The final linked image contains external weak symbols."),
    (0x1_0000, "BINDS_TO_WEAK", "The final linked image uses weak symbols."),
    (0x2_0000, "ALLOW_STACK_EXECUTION", "When this bit is set, all stacks in the task will be given stack execution privilege -> only used in FileType::EXECUTE filetypes."),
    (0x4_0000, "ROOT_SAFE", "When this bit is set, the binary declares it is safe for use in processes with uid zero."),
    (0x8_0000, "SETUID_SAFE", "When this bit is set, the binary declares it is safe for use in processes when issetugid() is true."),
    (0x10_0000, "NO_REEXPORTED_DYLIBS", "When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported."),
    (0x20_0000, "PIE", "When this bit is set, the OS will load the main executable at a random address -> only used in FileType::EXECUTE filetypes."),
    (0x40_0000, "DEAD_STRIPPABLE_DYLIB", "Only for use on dylibs -> when linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib."),
    (0x80_0000, "HAS_TLV_DESCRIPTORS", "Contains a section of type S_THREAD_LOCAL_VARIABLES."),
    (0x100_0000, "NO_HEAP_EXECUTION", "When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g.i386) that don't require it -> only used in MH_EXECUTE filetypes."),
    (0x200_0000, "APP_EXTENSION_SAFE", "The code was linked for use in an application extension."),
    (0x400_0000, "NLIST_OUTOFSYNC_WITH_DYLDINFO", "The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info."),
    (0x800_0000, "SIM_SUPPORT", "Allow LC_MIN_VERSION_MACOS and LoadCommandType::BUILD_VERSION load commands with the platforms macOS, iOSMac, iOSSimulator, tvOSSimulator and watchOSSimulator."),
];

/// C++ `GetMachHeaderFlagsData(flags)` (`Utils.hpp:114-128`): the
/// table entries whose bit is set, in table order.
pub fn set_header_flags(flags: u32) -> impl Iterator<Item = &'static (u32, &'static str, &'static str)> {
    MACH_HEADER_FLAGS.iter().filter(move |(bit, _, _)| bit & flags == *bit)
}

/// C++ `LoadCommandNames.at(cmd)` — the enumerator spelling of a
/// load command, or an empty string where the C++ `std::map::at`
/// would throw.
#[must_use]
pub const fn load_command_name(cmd: u32) -> &'static str {
    match cmd {
        0x1 => "SEGMENT",
        0x2 => "SYMTAB",
        0x3 => "SYMSEG",
        0x4 => "THREAD",
        0x5 => "UNIXTHREAD",
        0x6 => "LOADFVMLIB",
        0x7 => "IDFVMLIB",
        0x8 => "IDENT",
        0x9 => "FVMFILE",
        0xA => "PREPAGE",
        0xB => "DYSYMTAB",
        0xC => "LOAD_DYLIB",
        0xD => "ID_DYLIB",
        0xE => "LOAD_DYLINKER",
        0xF => "ID_DYLINKER",
        0x10 => "PREBOUND_DYLIB",
        0x11 => "ROUTINES",
        0x12 => "SUB_FRAMEWORK",
        0x13 => "SUB_UMBRELLA",
        0x14 => "SUB_CLIENT",
        0x15 => "SUB_LIBRARY",
        0x16 => "TWOLEVEL_HINTS",
        0x17 => "PREBIND_CKSUM",
        0x8000_0018 => "LOAD_WEAK_DYLIB",
        0x19 => "SEGMENT_64",
        0x1A => "ROUTINES_64",
        0x1B => "UUID",
        0x8000_001C => "RPATH",
        0x1D => "CODE_SIGNATURE",
        0x1E => "SEGMENT_SPLIT_INFO",
        0x8000_001F => "REEXPORT_DYLIB",
        0x20 => "LAZY_LOAD_DYLIB",
        0x21 => "ENCRYPTION_INFO",
        0x22 => "DYLD_INFO",
        0x8000_0022 => "DYLD_INFO_ONLY",
        0x8000_0023 => "LOAD_UPWARD_DYLIB",
        0x24 => "VERSION_MIN_MACOSX",
        0x25 => "VERSION_MIN_IPHONEOS",
        0x26 => "FUNCTION_STARTS",
        0x27 => "DYLD_ENVIRONMENT",
        0x8000_0028 => "MAIN",
        0x29 => "DATA_IN_CODE",
        0x2A => "SOURCE_VERSION",
        0x2B => "DYLIB_CODE_SIGN_DRS",
        0x2C => "ENCRYPTION_INFO_64",
        0x2D => "LINKER_OPTION",
        0x2E => "LINKER_OPTIMIZATION_HINT",
        0x2F => "VERSION_MIN_TVOS",
        0x30 => "VERSION_MIN_WATCHOS",
        0x31 => "BUILD_VERSION",
        0x32 => "NOTE",
        0x8000_0033 => "DYLD_EXPORTS_TRIE",
        0x8000_0034 => "DYLD_CHAINED_FIXUPS",
        0x8000_0035 => "FILESET_ENTRY",
        _ => "",
    }
}
