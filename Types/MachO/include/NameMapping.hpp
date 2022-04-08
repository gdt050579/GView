#pragma once

#include "Mac.hpp"

namespace MAC
{
#define GET_PAIR(x)                                                                                                                        \
    {                                                                                                                                      \
        x, (#x)                                                                                                                            \
    }
#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

static const std::map<ByteOrder, std::string_view> ByteOrderNames{
    GET_PAIR_FROM_ENUM(ByteOrder::Unknown),
    GET_PAIR_FROM_ENUM(ByteOrder::LittleEndian),
    GET_PAIR_FROM_ENUM(ByteOrder::BigEndian),
};

static const ArchInfo ArchInfoTable[] = {
    /* architecture families */
    { "hppa", CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_ALL, ByteOrder::BigEndian, "HP-PA" },
    { "i386", CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL, ByteOrder::LittleEndian, "Intel 80x86" },
    { "x86_64", CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, ByteOrder::LittleEndian, "Intel x86-64" },
    { "x86_64h", CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H, ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
    { "i860", CPU_TYPE_I860, CPU_SUBTYPE_I860_ALL, ByteOrder::BigEndian, "Intel 860" },
    { "m68k", CPU_TYPE_MC680x0, CPU_SUBTYPE_MC680x0_ALL, ByteOrder::BigEndian, "Motorola 68K" },
    { "m88k", CPU_TYPE_MC88000, CPU_SUBTYPE_MC88000_ALL, ByteOrder::BigEndian, "Motorola 88K" },
    { "ppc", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_ALL, ByteOrder::BigEndian, "PowerPC" },
    { "ppc64", CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_ALL, ByteOrder::BigEndian, "PowerPC 64-bit" },
    { "sparc", CPU_TYPE_SPARC, CPU_SUBTYPE_SPARC_ALL, ByteOrder::BigEndian, "SPARC" },
    { "arm", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_ALL, ByteOrder::LittleEndian, "ARM" },
    { "arm64", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ByteOrder::LittleEndian, "ARM64" },
    { "any", CPU_TYPE_ANY, CPU_SUBTYPE_MULTIPLE, ByteOrder::Unknown, "Architecture Independent" },
    { "veo", CPU_TYPE_VEO, CPU_SUBTYPE_VEO_ALL, ByteOrder::BigEndian, "veo" },
    /* specific architecture implementations */
    { "hppa7100LC", CPU_TYPE_HPPA, CPU_SUBTYPE_HPPA_7100LC, ByteOrder::BigEndian, "HP-PA 7100LC" },
    { "m68030", CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68030_ONLY, ByteOrder::BigEndian, "Motorola 68030" },
    { "m68040", CPU_TYPE_MC680x0, CPU_SUBTYPE_MC68040, ByteOrder::BigEndian, "Motorola 68040" },
    { "i486", CPU_TYPE_I386, CPU_SUBTYPE_486, ByteOrder::LittleEndian, "Intel 80486" },
    { "i486SX", CPU_TYPE_I386, CPU_SUBTYPE_486SX, ByteOrder::LittleEndian, "Intel 80486SX" },
    { "pentium", CPU_TYPE_I386, CPU_SUBTYPE_PENT, ByteOrder::LittleEndian, "Intel Pentium" }, /* same as 586 */
    { "i586", CPU_TYPE_I386, CPU_SUBTYPE_586, ByteOrder::LittleEndian, "Intel 80586" },
    { "pentpro", CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO, ByteOrder::LittleEndian, "Intel Pentium Pro" }, /* same as 686 */
    { "i686", CPU_TYPE_I386, CPU_SUBTYPE_PENTPRO, ByteOrder::LittleEndian, "Intel Pentium Pro" },
    { "pentIIm3", CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M3, ByteOrder::LittleEndian, "Intel Pentium II Model 3" },
    { "pentIIm5", CPU_TYPE_I386, CPU_SUBTYPE_PENTII_M5, ByteOrder::LittleEndian, "Intel Pentium II Model 5" },
    { "pentium4", CPU_TYPE_I386, CPU_SUBTYPE_PENTIUM_4, ByteOrder::LittleEndian, "Intel Pentium 4" },
    { "x86_64h", CPU_TYPE_I386, CPU_SUBTYPE_X86_64_H, ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
    { "ppc601", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_601, ByteOrder::BigEndian, "PowerPC 601" },
    { "ppc603", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603, ByteOrder::BigEndian, "PowerPC 603" },
    { "ppc603e", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603e, ByteOrder::BigEndian, "PowerPC 603e" },
    { "ppc603ev", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_603ev, ByteOrder::BigEndian, "PowerPC 603ev" },
    { "ppc604", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604, ByteOrder::BigEndian, "PowerPC 604" },
    { "ppc604e", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_604e, ByteOrder::BigEndian, "PowerPC 604e" },
    { "ppc750", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_750, ByteOrder::BigEndian, "PowerPC 750" },
    { "ppc7400", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7400, ByteOrder::BigEndian, "PowerPC 7400" },
    { "ppc7450", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_7450, ByteOrder::BigEndian, "PowerPC 7450" },
    { "ppc970", CPU_TYPE_POWERPC, CPU_SUBTYPE_POWERPC_970, ByteOrder::BigEndian, "PowerPC 970" },
    { "ppc970-64", CPU_TYPE_POWERPC64, CPU_SUBTYPE_POWERPC_970, ByteOrder::BigEndian, "PowerPC 970 64-bit" },
    { "armv4t", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V4T, ByteOrder::LittleEndian, "arm v4t" },
    { "armv5", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V5TEJ, ByteOrder::LittleEndian, "arm v5" },
    { "xscale", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_XSCALE, ByteOrder::LittleEndian, "arm xscale" },
    { "armv6", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6, ByteOrder::LittleEndian, "arm v6" },
    { "armv6m", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6M, ByteOrder::LittleEndian, "arm v6m" },
    { "armv7", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, ByteOrder::LittleEndian, "arm v7" },
    { "armv7f", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7F, ByteOrder::LittleEndian, "arm v7f" },
    { "armv7s", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S, ByteOrder::LittleEndian, "arm v7s" },
    { "armv7k", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K, ByteOrder::LittleEndian, "arm v7k" },
    { "armv7m", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7M, ByteOrder::LittleEndian, "arm v7m" },
    { "armv7em", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7EM, ByteOrder::LittleEndian, "arm v7em" },
    { "armv8", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V8, ByteOrder::LittleEndian, "arm v8" },
    { "arm64", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8, ByteOrder::LittleEndian, "arm64 v8" },
    { "little", CPU_TYPE_ANY, CPU_SUBTYPE_LITTLE_ENDIAN, ByteOrder::LittleEndian, "Little Endian" },
    { "big", CPU_TYPE_ANY, CPU_SUBTYPE_BIG_ENDIAN, ByteOrder::BigEndian, "Big Endian" },
    { "veo1", CPU_TYPE_VEO, CPU_SUBTYPE_VEO_1, ByteOrder::BigEndian, "veo 1" },
    { "veo2", CPU_TYPE_VEO, CPU_SUBTYPE_VEO_2, ByteOrder::BigEndian, "veo 2" }
};

static const std::map<FileType, std::string_view> FileTypeNames{
    GET_PAIR_FROM_ENUM(FileType::OBJECT),     GET_PAIR_FROM_ENUM(FileType::EXECUTE),    GET_PAIR_FROM_ENUM(FileType::FVMLIB),
    GET_PAIR_FROM_ENUM(FileType::CORE),       GET_PAIR_FROM_ENUM(FileType::PRELOAD),    GET_PAIR_FROM_ENUM(FileType::DYLIB),
    GET_PAIR_FROM_ENUM(FileType::BUNDLE),     GET_PAIR_FROM_ENUM(FileType::DYLIB_STUB), GET_PAIR_FROM_ENUM(FileType::DSYM),
    GET_PAIR_FROM_ENUM(FileType::KEXT_BUNDLE)
};

static const std::map<FileType, std::string_view> FileTypeDescriptions{
    { FileType::OBJECT, "Relocatable object file." },
    { FileType::EXECUTE, "Demand paged executable file." },
    { FileType::FVMLIB, "Fixed VM shared library file." },
    { FileType::CORE, "Core file." },
    { FileType::PRELOAD, "Preloaded executable file." },
    { FileType::DYLIB, "Dynamically bound shared library." },
    { FileType::BUNDLE, "Dynamically bound bundle file." },
    { FileType::DYLIB_STUB, "Shared library stub for static | linking only, no section contents." },
    { FileType::DSYM, "Companion file with only debug | sections." },
    { FileType::KEXT_BUNDLE, "X86_64 kexts." }
};

static const std::map<MachHeaderFlags, std::string_view> MachHeaderFlagsDescriptions{
    { MachHeaderFlags::NOUNDEFS, "The object file has no undefined references." },
    { MachHeaderFlags::INCRLINK,
      "The object file is the output of an incremental link against a base file and can't be link edited again." },
    { MachHeaderFlags::DYLDLINK, "The object file is input for the dynamic linker and can't be staticly link edited again." },
    { MachHeaderFlags::BINDATLOAD, "The object file's undefined references are bound by the dynamic linker when loaded." },
    { MachHeaderFlags::PREBOUND, "The file has its dynamic undefined references prebound." },
    { MachHeaderFlags::SPLIT_SEGS, "The file has its read-only and read-write segments split." },
    { MachHeaderFlags::LAZY_INIT,
      "The shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)." },
    { MachHeaderFlags::TWOLEVEL, "The image is using two-level name space bindings." },
    { MachHeaderFlags::FORCE_FLAT, "The executable is forcing all images to use flat name space bindings." },
    { MachHeaderFlags::NOMULTIDEFS,
      "This umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be "
      "used." },
    { MachHeaderFlags::NOFIXPREBINDING, "Do not have dyld notify the prebinding agent about this executable." },
    { MachHeaderFlags::PREBINDABLE,
      "The binary is not prebound but can have its prebinding redone -> only used when FileType::PREBOUND is not set." },
    { MachHeaderFlags::ALLMODSBOUND,
      "Indicates that this binary binds to all two-level namespace modules of its dependent libraries -> only used when "
      "MH_PREBINDABLE and "
      "MH_TWOLEVEL are both set." },
    { MachHeaderFlags::SUBSECTIONS_VIA_SYMBOLS, "Safe to divide up the sections into sub-sections via symbols for dead code stripping." },
    { MachHeaderFlags::CANONICAL, "The binary has been canonicalized via the unprebind operation." },
    { MachHeaderFlags::WEAK_DEFINES, "The final linked image contains external weak symbols." },
    { MachHeaderFlags::BINDS_TO_WEAK, "The final linked image uses weak symbols." },
    { MachHeaderFlags::ALLOW_STACK_EXECUTION,
      "When this bit is set, all stacks in the task will be given stack execution privilege -> only used in FileType::EXECUTE "
      "filetypes." },
    { MachHeaderFlags::ROOT_SAFE, "When this bit is set, the binary declares it is safe for use in processes with uid zero." },
    { MachHeaderFlags::SETUID_SAFE, "When this bit is set, the binary declares it is safe for use in processes when issetugid() is true." },
    { MachHeaderFlags::NO_REEXPORTED_DYLIBS,
      "When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported." },
    { MachHeaderFlags::PIE,
      "When this bit is set, the OS will load the main executable at a random address -> only used in FileType::EXECUTE filetypes." },
    { MachHeaderFlags::DEAD_STRIPPABLE_DYLIB,
      "Only for use on dylibs -> when linking against a dylib that has this bit set, the static linker will automatically not create "
      "a "
      "LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib." },
    { MachHeaderFlags::HAS_TLV_DESCRIPTORS, "Contains a section of type S_THREAD_LOCAL_VARIABLES." },
    { MachHeaderFlags::NO_HEAP_EXECUTION,
      "When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g.i386) that don't "
      "require it -> only used in MH_EXECUTE filetypes." },
    { MachHeaderFlags::APP_EXTENSION_SAFE, "The code was linked for use in an application extension." },
    { MachHeaderFlags::NLIST_OUTOFSYNC_WITH_DYLDINFO,
      "The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info." },
    { MachHeaderFlags::SIM_SUPPORT,
      "Allow LC_MIN_VERSION_MACOS and LoadCommandType::BUILD_VERSION load commands with the platforms macOS, iOSMac, iOSSimulator, "
      "tvOSSimulator and watchOSSimulator." }
};

static const std::map<MachHeaderFlags, std::string_view> MachHeaderFlagsNames{ GET_PAIR_FROM_ENUM(MachHeaderFlags::NOUNDEFS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::INCRLINK),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::DYLDLINK),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::BINDATLOAD),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::PREBOUND),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::SPLIT_SEGS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::LAZY_INIT),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::TWOLEVEL),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::FORCE_FLAT),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::NOMULTIDEFS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::NOFIXPREBINDING),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::PREBINDABLE),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::ALLMODSBOUND),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::SUBSECTIONS_VIA_SYMBOLS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::CANONICAL),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::WEAK_DEFINES),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::BINDS_TO_WEAK),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::ALLOW_STACK_EXECUTION),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::ROOT_SAFE),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::SETUID_SAFE),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::NO_REEXPORTED_DYLIBS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::PIE),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::DEAD_STRIPPABLE_DYLIB),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::HAS_TLV_DESCRIPTORS),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::NO_HEAP_EXECUTION),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::APP_EXTENSION_SAFE),
                                                                               GET_PAIR_FROM_ENUM(
                                                                                     MachHeaderFlags::NLIST_OUTOFSYNC_WITH_DYLDINFO),
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::SIM_SUPPORT) };

static const std::map<LoadCommandType, std::string_view> LoadCommandNames{ GET_PAIR_FROM_ENUM(LoadCommandType::REQ_DYLD),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SEGMENT),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SYMTAB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SYMSEG),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::THREAD),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::UNIXTHREAD),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LOADFVMLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::IDFVMLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::IDENT),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::FVMFILE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::PREPAGE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYSYMTAB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LOAD_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ID_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LOAD_DYLINKER),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ID_DYLINKER),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::PREBOUND_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ROUTINES),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SUB_FRAMEWORK),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SUB_UMBRELLA),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SUB_CLIENT),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SUB_LIBRARY),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::TWOLEVEL_HINTS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::PREBIND_CKSUM),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LOAD_WEAK_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SEGMENT_64),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ROUTINES_64),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::UUID),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::RPATH),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::CODE_SIGNATURE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SEGMENT_SPLIT_INFO),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::REEXPORT_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LAZY_LOAD_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ENCRYPTION_INFO),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_INFO),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_INFO_ONLY),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LOAD_UPWARD_DYLIB),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::VERSION_MIN_MACOSX),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::VERSION_MIN_IPHONEOS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::FUNCTION_STARTS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_ENVIRONMENT),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::MAIN),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DATA_IN_CODE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::SOURCE_VERSION),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLIB_CODE_SIGN_DRS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::ENCRYPTION_INFO_64),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LINKER_OPTION),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::LINKER_OPTIMIZATION_HINT),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::VERSION_MIN_TVOS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::VERSION_MIN_WATCHOS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::BUILD_VERSION),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::NOTE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_EXPORTS_TRIE),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_CHAINED_FIXUPS),
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::FILESET_ENTRY) };

static const std::map<LoadCommandType, std::string_view> LoadCommandDescriptions{
    { LoadCommandType::REQ_DYLD, "Requires dynamic linker." },
    { LoadCommandType::SEGMENT, "Segment of this file to be mapped." },
    { LoadCommandType::SYMTAB, "Link-edit stab symbol table info." },
    { LoadCommandType::SYMSEG, "Link-edit gdb symbol table info (obsolete)." },
    { LoadCommandType::THREAD, "Thread." },
    { LoadCommandType::UNIXTHREAD, "Unix thread (includes a stack)." },
    { LoadCommandType::LOADFVMLIB, "Load a specified fixed VM shared library." },
    { LoadCommandType::IDFVMLIB, "Fixed VM shared library identification." },
    { LoadCommandType::IDENT, "Object identification info (obsolete)." },
    { LoadCommandType::FVMFILE, "Fixed VM file inclusion (internal use)." },
    { LoadCommandType::PREPAGE, "Prepage command (internal use)." },
    { LoadCommandType::DYSYMTAB, "Dynamic link-edit symbol table info." },
    { LoadCommandType::LOAD_DYLIB, "Load a dynamically linked shared library." },
    { LoadCommandType::ID_DYLIB, "Dynamically linked shared lib ident." },
    { LoadCommandType::LOAD_DYLINKER, "Load a dynamic linker." },
    { LoadCommandType::ID_DYLINKER, "Dynamic linker identification." },
    { LoadCommandType::PREBOUND_DYLIB, "Modules prebound for a dynamically linked shared library." },
    { LoadCommandType::ROUTINES, "Image routines." },
    { LoadCommandType::SUB_FRAMEWORK, "Sub framework." },
    { LoadCommandType::SUB_UMBRELLA, "Sub umbrella." },
    { LoadCommandType::SUB_CLIENT, "Sub client." },
    { LoadCommandType::SUB_LIBRARY, "Sub library." },
    { LoadCommandType::TWOLEVEL_HINTS, "Two-level namespace lookup hints." },
    { LoadCommandType::PREBIND_CKSUM, "Prebind checksum." },
    { LoadCommandType::LOAD_WEAK_DYLIB,
      "Load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported)." },
    { LoadCommandType::SEGMENT_64, "64-bit segment of this file to be mapped." },
    { LoadCommandType::ROUTINES_64, "64-bit image routines." },
    { LoadCommandType::UUID, "The uuid." },
    { LoadCommandType::RPATH, "Runpath additions." },
    { LoadCommandType::CODE_SIGNATURE, "Local of code signature." },
    { LoadCommandType::SEGMENT_SPLIT_INFO, "Local of info to split segments." },
    { LoadCommandType::REEXPORT_DYLIB, "Load and re-export dylib." },
    { LoadCommandType::LAZY_LOAD_DYLIB, "Delay load of dylib until first use." },
    { LoadCommandType::ENCRYPTION_INFO, "Encrypted segment information." },
    { LoadCommandType::DYLD_INFO, "Compressed dyld information." },
    { LoadCommandType::DYLD_INFO_ONLY, "Compressed dyld information only." },
    { LoadCommandType::LOAD_UPWARD_DYLIB, "Load upward dylib." },
    { LoadCommandType::VERSION_MIN_MACOSX, "Build for MacOSX min OS version." },
    { LoadCommandType::VERSION_MIN_IPHONEOS, "Build for iPhoneOS min OS version." },
    { LoadCommandType::FUNCTION_STARTS, "Compressed table of function start addresses." },
    { LoadCommandType::DYLD_ENVIRONMENT, "String for dyld to treat like environment variable." },
    { LoadCommandType::MAIN, "Replacement for LoadCommandType::UNIXTHREAD" },
    { LoadCommandType::DATA_IN_CODE, "Table of non-instructions in __text." },
    { LoadCommandType::SOURCE_VERSION, "Source version used to build binary." },
    { LoadCommandType::DYLIB_CODE_SIGN_DRS, "Code signing DRs copied from linked dylibs." },
    { LoadCommandType::ENCRYPTION_INFO_64, "64-bit encrypted segment information." },
    { LoadCommandType::LINKER_OPTION, "Linker options in FileType::OBJECT files." },
    { LoadCommandType::LINKER_OPTIMIZATION_HINT, "Optimization hints in FileType::OBJECT files." },
    { LoadCommandType::VERSION_MIN_TVOS, "Build for AppleTV min OS version." },
    { LoadCommandType::VERSION_MIN_WATCHOS, "Build for Watch min OS version." },
    { LoadCommandType::BUILD_VERSION, "Build for platform min OS version." },
    { LoadCommandType::NOTE, "Arbitrary data included within a Mach-O file." },
    { LoadCommandType::DYLD_EXPORTS_TRIE, "Used with `LinkeditDataCommand`, payload is trie." },
    { LoadCommandType::DYLD_CHAINED_FIXUPS, "Used with `LinkeditDataCommand." },
    { LoadCommandType::FILESET_ENTRY, "Used with fileset_entry_command." },
};

static const std::map<VMProtectionFlags, std::string_view> VMProtectionNames{
    GET_PAIR_FROM_ENUM(VMProtectionFlags::NONE),      GET_PAIR_FROM_ENUM(VMProtectionFlags::READ),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::WRITE),     GET_PAIR_FROM_ENUM(VMProtectionFlags::EXECUTE),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::DEFAULT),   GET_PAIR_FROM_ENUM(VMProtectionFlags::ALL),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::NO_CHANGE), GET_PAIR_FROM_ENUM(VMProtectionFlags::COPY),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::WANTS_COPY)
};

static const std::map<SegmentCommandFlags, std::string_view> SegmentCommandFlagsNames{ GET_PAIR_FROM_ENUM(SegmentCommandFlags::NONE),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::HIGHVM),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::FVMLIB),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::NORELOC),
                                                                                       GET_PAIR_FROM_ENUM(
                                                                                             SegmentCommandFlags::PROTECTED_VERSION_1),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::READONLY) };

static const std::map<SectionType, std::string_view> SectionTypeNames{ GET_PAIR_FROM_ENUM(SectionType::REGULAR),
                                                                       GET_PAIR_FROM_ENUM(SectionType::ZEROFILL),
                                                                       GET_PAIR_FROM_ENUM(SectionType::CSTRING_LITERALS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::_4BYTE_LITERALS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::_8BYTE_LITERALS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::LITERAL_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::NON_LAZY_SYMBOL_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::LAZY_SYMBOL_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::SYMBOL_STUBS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::MOD_INIT_FUNC_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::MOD_TERM_FUNC_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::COALESCED),
                                                                       GET_PAIR_FROM_ENUM(SectionType::GB_ZEROFILL),
                                                                       GET_PAIR_FROM_ENUM(SectionType::INTERPOSING),
                                                                       GET_PAIR_FROM_ENUM(SectionType::_16BYTE_LITERALS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::DTRACE_DOF),
                                                                       GET_PAIR_FROM_ENUM(SectionType::LAZY_DYLIB_SYMBOL_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::THREAD_LOCAL_REGULAR),
                                                                       GET_PAIR_FROM_ENUM(SectionType::THREAD_LOCAL_ZEROFILL),
                                                                       GET_PAIR_FROM_ENUM(SectionType::THREAD_LOCAL_VARIABLES),
                                                                       GET_PAIR_FROM_ENUM(SectionType::THREAD_LOCAL_VARIABLE_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::THREAD_LOCAL_INIT_FUNCTION_POINTERS),
                                                                       GET_PAIR_FROM_ENUM(SectionType::S_INIT_FUNC_OFFSETS) };

static const std::map<SectionAttributtes, std::string_view> SectionAttributtesNames{
    GET_PAIR_FROM_ENUM(SectionAttributtes::USR),
    GET_PAIR_FROM_ENUM(SectionAttributtes::PURE_INSTRUCTIONS),
    GET_PAIR_FROM_ENUM(SectionAttributtes::NO_TOC),
    GET_PAIR_FROM_ENUM(SectionAttributtes::STRIP_STATIC_SYMS),
    GET_PAIR_FROM_ENUM(SectionAttributtes::NO_DEAD_STRIP),
    GET_PAIR_FROM_ENUM(SectionAttributtes::LIVE_SUPPORT),
    GET_PAIR_FROM_ENUM(SectionAttributtes::SELF_MODIFYING_CODE),
    GET_PAIR_FROM_ENUM(SectionAttributtes::DEBUG),
    GET_PAIR_FROM_ENUM(SectionAttributtes::SYS),
    GET_PAIR_FROM_ENUM(SectionAttributtes::SOME_INSTRUCTIONS),
    GET_PAIR_FROM_ENUM(SectionAttributtes::EXT_RELOC),
    GET_PAIR_FROM_ENUM(SectionAttributtes::LOC_RELOC)
};

static const std::map<N_TYPE, std::string_view> NTypeNames{
    GET_PAIR_FROM_ENUM(N_TYPE::STAB), GET_PAIR_FROM_ENUM(N_TYPE::PEXT), GET_PAIR_FROM_ENUM(N_TYPE::TYPE), GET_PAIR_FROM_ENUM(N_TYPE::EXT)
};

static const std::map<N_TYPE_BITS, std::string_view> NTypeBitsNames{
    GET_PAIR_FROM_ENUM(N_TYPE_BITS::UNDF), GET_PAIR_FROM_ENUM(N_TYPE_BITS::ABS),  GET_PAIR_FROM_ENUM(N_TYPE_BITS::TEXT),
    GET_PAIR_FROM_ENUM(N_TYPE_BITS::DATA), GET_PAIR_FROM_ENUM(N_TYPE_BITS::BSS),  GET_PAIR_FROM_ENUM(N_TYPE_BITS::SECT),
    GET_PAIR_FROM_ENUM(N_TYPE_BITS::PBUD), GET_PAIR_FROM_ENUM(N_TYPE_BITS::INDR), GET_PAIR_FROM_ENUM(N_TYPE_BITS::COMM),
    GET_PAIR_FROM_ENUM(N_TYPE_BITS::FN)
};

static const std::map<ReferenceFlag, std::string_view> ReferenceFlagNames{ GET_PAIR_FROM_ENUM(ReferenceFlag::UNDEFINED_NON_LAZY),
                                                                           GET_PAIR_FROM_ENUM(ReferenceFlag::UNDEFINED_LAZY),
                                                                           GET_PAIR_FROM_ENUM(ReferenceFlag::DEFINED),
                                                                           GET_PAIR_FROM_ENUM(ReferenceFlag::PRIVATE_DEFINED),
                                                                           GET_PAIR_FROM_ENUM(ReferenceFlag::PRIVATE_UNDEFINED_NON_LAZY),
                                                                           GET_PAIR_FROM_ENUM(ReferenceFlag::PRIVATE_UNDEFINED_LAZY) };

static const std::map<OrdinalType, std::string_view> OrdinalTypeNames{ GET_PAIR_FROM_ENUM(OrdinalType::SELF_LIBRARY),
                                                                       GET_PAIR_FROM_ENUM(OrdinalType::MAX_LIBRARY),
                                                                       GET_PAIR_FROM_ENUM(OrdinalType::DYNAMIC_LOOKUP),
                                                                       GET_PAIR_FROM_ENUM(OrdinalType::EXECUTABLE) };

static const std::map<N_DESC_BIT_TYPE, std::string_view> NDescBitTypeNames{ GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::REFERENCED_DYNAMICALLY),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::NO_DEAD_STRIP),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::DESC_DISCARDED),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::WEAK_REF),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::WEAK_DEF),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::REF_TO_WEAK),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::ARM_THUMB_DEF),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::SYMBOL_RESOLVER),
                                                                            GET_PAIR_FROM_ENUM(N_DESC_BIT_TYPE::ALT_ENTRY) };

static const std::map<N_STAB_TYPE, std::string_view> NStabTypeNames{
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::GSYM),   GET_PAIR_FROM_ENUM(N_STAB_TYPE::FNAME),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::FUN),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::STSYM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::LCSYM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::MAIN),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::BNSYM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::PC),     GET_PAIR_FROM_ENUM(N_STAB_TYPE::AST),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::OPT),    GET_PAIR_FROM_ENUM(N_STAB_TYPE::RSYM),   GET_PAIR_FROM_ENUM(N_STAB_TYPE::SLINE),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::ENSYM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::DSLINE), GET_PAIR_FROM_ENUM(N_STAB_TYPE::BSLINE),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::SSYM),   GET_PAIR_FROM_ENUM(N_STAB_TYPE::SO),     GET_PAIR_FROM_ENUM(N_STAB_TYPE::OSO),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::LSYM),   GET_PAIR_FROM_ENUM(N_STAB_TYPE::BINCL),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::SOL),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::PARAMS), GET_PAIR_FROM_ENUM(N_STAB_TYPE::SOL),    GET_PAIR_FROM_ENUM(N_STAB_TYPE::VERSION),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::OLEVEL), GET_PAIR_FROM_ENUM(N_STAB_TYPE::EINCL),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::ENTRY),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::LBRAC),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::EXCL),   GET_PAIR_FROM_ENUM(N_STAB_TYPE::RBRAC),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::BCOMM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::ECOMM),  GET_PAIR_FROM_ENUM(N_STAB_TYPE::ECOML),
    GET_PAIR_FROM_ENUM(N_STAB_TYPE::LENG)
};

static const std::map<PlatformType, std::string_view> CodeSignPlatformNames{
    GET_PAIR_FROM_ENUM(PlatformType::UNKNOWN),       GET_PAIR_FROM_ENUM(PlatformType::MACOS),
    GET_PAIR_FROM_ENUM(PlatformType::IOS),           GET_PAIR_FROM_ENUM(PlatformType::TVOS),
    GET_PAIR_FROM_ENUM(PlatformType::WATCHOS),       GET_PAIR_FROM_ENUM(PlatformType::BRIDGEOS),
    GET_PAIR_FROM_ENUM(PlatformType::MACCATALYST),   GET_PAIR_FROM_ENUM(PlatformType::IOSSIMULATOR),
    GET_PAIR_FROM_ENUM(PlatformType::TVOSSIMULATOR), GET_PAIR_FROM_ENUM(PlatformType::WATCHOSSIMULATOR),
    GET_PAIR_FROM_ENUM(PlatformType::DRIVERKIT),     GET_PAIR_FROM_ENUM(PlatformType::_11),
    GET_PAIR_FROM_ENUM(PlatformType::_12),           GET_PAIR_FROM_ENUM(PlatformType::_13),
};

static const std::map<CodeSignFlags, std::string_view> CodeSignFlagNames{ GET_PAIR_FROM_ENUM(CodeSignFlags::VALID),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::ADHOC),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::GET_TASK_ALLOW),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::INSTALLER),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::FORCED_LV),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::INVALID_ALLOWED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::HARD),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::KILL),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::CHECK_EXPIRATION),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::RESTRICT),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::ENFORCEMENT),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::REQUIRE_LV),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::ENTITLEMENTS_VALIDATED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::NVRAM_UNRESTRICTED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::RUNTIME),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::LINKER_SIGNED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::ALLOWED_MACHO),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::EXEC_SET_HARD),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::EXEC_SET_KILL),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::EXEC_SET_ENFORCEMENT),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::EXEC_INHERIT_SIP),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::KILLED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::DYLD_PLATFORM),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::PLATFORM_BINARY),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::PLATFORM_PATH),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::DEBUGGED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::SIGNED),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::DEV_CODE),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::DATAVAULT_CONTROLLER),
                                                                          GET_PAIR_FROM_ENUM(CodeSignFlags::ENTITLEMENT_FLAGS) };

static const std::map<CodeSignExecSegFlags, std::string_view> CodeSignExecSegFlagNames{
    GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::MAIN_BINARY),    GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::ALLOW_UNSIGNED),
    GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::DEBUGGER),       GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::JIT),
    GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::SKIP_LV),        GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::CAN_LOAD_CDHASH),
    GET_PAIR_FROM_ENUM(CodeSignExecSegFlags::CAN_EXEC_CDHASH)
};

static const std::map<CodeSignExecSegFlags, std::string_view> CodeSignExecSegFlagsDescriptions{
    { CodeSignExecSegFlags::MAIN_BINARY, "Executable segment denotes main binary." },
    { CodeSignExecSegFlags::ALLOW_UNSIGNED, "Allow unsigned pages (for debugging)." },
    { CodeSignExecSegFlags::DEBUGGER, "Main binary is debugger." },
    { CodeSignExecSegFlags::JIT, "JIT enabled." },
    { CodeSignExecSegFlags::SKIP_LV, "OBSOLETE: skip library validation." },
    { CodeSignExecSegFlags::CAN_LOAD_CDHASH, "Can bless cdhash for execution." },
    { CodeSignExecSegFlags::CAN_EXEC_CDHASH, "Can execute blessed cdhash." }
};

static const std::map<CodeSignMagic, std::string_view> CodeSignHashTypeNames{
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_NO_HASH), GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_SHA1),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_SHA256),  GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_SHA256_TRUNCATED),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_SHA384),  GET_PAIR_FROM_ENUM(CodeSignMagic::CS_HASHTYPE_SHA512)
};

static const std::map<CodeSignMagic, std::string_view> CodeSignMagicNames{
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_REQUIREMENT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_REQUIREMENTS),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_CODEDIRECTORY),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_EMBEDDED_SIGNATURE),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_EMBEDDED_SIGNATURE_OLD),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_EMBEDDED_ENTITLEMENTS),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_DETACHED_SIGNATURE),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_BLOBWRAPPER),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSMAGIC_BYTE),
};

static const std::map<CodeSignMagic, std::string_view> CodeSignSlotNames{
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_CODEDIRECTORY),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_INFOSLOT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_REQUIREMENTS),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_RESOURCEDIR),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_APPLICATION),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_ENTITLEMENTS),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORIES),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORY_MAX),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_SIGNATURESLOT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_IDENTIFICATIONSLOT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CSSLOT_TICKETSLOT),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SIGNER_TYPE_UNKNOWN),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SIGNER_TYPE_LEGACYVPN),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SIGNER_TYPE_MAC_APP_STORE),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SUPPL_SIGNER_TYPE_UNKNOWN),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SUPPL_SIGNER_TYPE_TRUSTCACHE),
    GET_PAIR_FROM_ENUM(CodeSignMagic::CS_SUPPL_SIGNER_TYPE_LOCAL),
};

static const std::map<CodeSignFlags, std::string_view> CodeSignFlagsDescriptions{
    { CodeSignFlags::VALID, "Dynamically valid." },
    { CodeSignFlags::ADHOC, "Ad hoc signed." },
    { CodeSignFlags::GET_TASK_ALLOW, "Has get-task-allow entitlement." },
    { CodeSignFlags::INSTALLER, "Has installer entitlement." },
    { CodeSignFlags::INVALID_ALLOWED, "(macOS Only) Page invalidation allowed by task port policy." },
    { CodeSignFlags::HARD, "Don't load invalid pages." },
    { CodeSignFlags::KILL, "Kill process if it becomes invalid." },
    { CodeSignFlags::CHECK_EXPIRATION, "Force expiration checking." },
    { CodeSignFlags::RESTRICT, "Tell dyld to treat restricted." },
    { CodeSignFlags::ENFORCEMENT, "Require enforcement." },
    { CodeSignFlags::REQUIRE_LV, "Require library validation." },
    { CodeSignFlags::ENTITLEMENTS_VALIDATED, "Code signature permits restricted entitlements." },
    { CodeSignFlags::NVRAM_UNRESTRICTED, "Has com.apple.rootless.restricted-nvram-variables.heritable entitlement." },
    { CodeSignFlags::RUNTIME, "Apply hardened runtime policies." },
    { CodeSignFlags::LINKER_SIGNED, "Automatically signed by the linker." },
    { CodeSignFlags::ALLOWED_MACHO,
      "(ADHOC | HARD | KILL | CHECK_EXPIRATION | RESTRICT | ENFORCEMENT | REQUIRE_LV | RUNTIME | LINKER_SIGNED)" },
    { CodeSignFlags::EXEC_SET_HARD, "Set CS_HARD on any exec'ed process." },
    { CodeSignFlags::EXEC_SET_KILL, "Set CS_KILL on any exec'ed process." },
    { CodeSignFlags::EXEC_SET_ENFORCEMENT, "Set CS_ENFORCEMENT on any exec'ed process." },
    { CodeSignFlags::EXEC_INHERIT_SIP, "Set CS_INSTALLER on any exec'ed process." },
    { CodeSignFlags::KILLED, "Was killed by kernel for invalidity." },
    { CodeSignFlags::DYLD_PLATFORM, "Dyld used to load this is a platform binary." },
    { CodeSignFlags::PLATFORM_BINARY, "This is a platform binary." },
    { CodeSignFlags::PLATFORM_PATH, "Platform binary by the fact of path (osx only)." },
    { CodeSignFlags::DEBUGGED, "Process is currently or has previously been debugged and allowed to run with invalid pages." },
    { CodeSignFlags::SIGNED, "Process has a signature (may have gone invalid)." },
    { CodeSignFlags::DEV_CODE, "Code is dev signed, cannot be loaded into prod signed code." },
    { CodeSignFlags::DATAVAULT_CONTROLLER, "Has Data Vault controller entitlement." },
    { CodeSignFlags::ENTITLEMENT_FLAGS, "(GET_TASK_ALLOW | INSTALLER | DATAVAULT_CONTROLLER | NVRAM_UNRESTRICTED)" }
};

} // namespace MAC
