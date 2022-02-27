#pragma once

#include "GView.hpp"

namespace GView::Type::MachOFB
{
// https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
// https://github.com/grumbach/nm_otool
constexpr uint32_t MH_MAGIC     = 0xfeedface; /* the mach magic number */
constexpr uint32_t MH_CIGAM     = 0xcefaedfe; /* NXSwapInt(MH_MAGIC) */
constexpr uint32_t MH_MAGIC_64  = 0xfeedfacf; /* the 64-bit mach magic number */
constexpr uint32_t MH_CIGAM_64  = 0xcffaedfe; /* NXSwapInt(MH_MAGIC_64) */
constexpr uint32_t FAT_MAGIC    = 0xcafebabe; /* the fat magic number */
constexpr uint32_t FAT_CIGAM    = 0xbebafeca; /* NXSwapLong(FAT_MAGIC) */
constexpr uint32_t FAT_MAGIC_64 = 0xcafebabf; /* the 64-bit fat magic number */
constexpr uint32_t FAT_CIGAM_64 = 0xbfbafeca; /* NXSwapLong(FAT_MAGIC_64) */

struct fat_header
{
    unsigned long magic;     /* FAT_MAGIC or FAT_MAGIC_64 */
    unsigned long nfat_arch; /* number of structs that follow */
};

// https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/machine.h.auto.html

enum class CPU_STATE : uint32_t
{
    USER   = 0,
    SYSTEM = 1,
    IDLE   = 2,
    NICE   = 3,
    MAX    = 4
};

enum class CPU_ARCH : uint32_t
{
    MASK  = 0xff000000, /* mask for architecture bits */
    ABI64 = 0x01000000  /* 64 bit ABI */
};

enum class CPU_TYPE : uint32_t
{
    ANY = static_cast<uint32_t>(-1),
    VAX = 1,
    /* skip	((cpu_type_t) 2)	*/
    /* skip	((cpu_type_t) 3)	*/
    /* skip	((cpu_type_t) 4)	*/
    /* skip	((cpu_type_t) 5)	*/
    MC680x0 = 6,
    X86     = 7,
    I386    = X86, /* compatibility */
    X86_64  = (X86 | static_cast<uint32_t>(CPU_ARCH::ABI64)),
    /* skip CPU_TYPE_MIPS ((cpu_type_t) 8)	*/
    /* skip 			  ((cpu_type_t) 9)	*/
    MC98000 = 10,
    HPPA    = 11,
    ARM     = 12,
    ARM64   = (ARM | static_cast<uint32_t>(CPU_ARCH::ABI64)),
    MC88000 = 13,
    SPARC   = 14,
    I860    = 15,
    /* skip	CPU_TYPE_ALPHA ((cpu_type_t) 16)	*/
    /* skip				   ((cpu_type_t) 17)	*/
    POWERPC   = 18,
    POWERPC64 = (POWERPC | static_cast<uint32_t>(CPU_ARCH::ABI64))
};

enum class CPU_SUBTYPE_COMPATIBILITY : uint32_t
{
    MASK  = 0xff000000, /* mask for feature flags */
    LIB64 = 0x80000000  /* 64 bit libraries */
};

enum class CPU_SUBTYPE : uint32_t
{
    MULTIPLE      = static_cast<uint32_t>(-1),
    LITTLE_ENDIAN = 0,
    BIG_ENDIAN    = 1,
};

enum class CPU_SUBTYPE_VAX : uint32_t
{
    ALL     = 0,
    VAX780  = 1,
    VAX785  = 2,
    VAX750  = 3,
    VAX730  = 4,
    UVAXI   = 5,
    UVAXII  = 6,
    VAX8200 = 7,
    VAX8500 = 8,
    VAX8600 = 9,
    VAX8650 = 10,
    VAX8800 = 11,
    UVAXIII = 12,
};

enum class CPU_SUBTYPE_MC680 : uint32_t
{
    ALL          = 1,
    MC68030      = 1, /* compat */
    MC68040      = 2,
    MC68030_ONLY = 3,
};

#define CPU_SUBTYPE_INTEL(f, m) ((f) + ((m) << 4))

enum class CPU_SUBTYPE_INTEL : uint32_t
{
    I386_ALL       = CPU_SUBTYPE_INTEL(3, 0),
    _386           = CPU_SUBTYPE_INTEL(3, 0),
    _486           = CPU_SUBTYPE_INTEL(4, 0),
    _486SX         = CPU_SUBTYPE_INTEL(4, 8), // 8 << 4 = 128
    _586           = CPU_SUBTYPE_INTEL(5, 0),
    PENT           = CPU_SUBTYPE_INTEL(5, 0),
    PENTPRO        = CPU_SUBTYPE_INTEL(6, 1),
    PENTII_M3      = CPU_SUBTYPE_INTEL(6, 3),
    PENTII_M5      = CPU_SUBTYPE_INTEL(6, 5),
    CELERON        = CPU_SUBTYPE_INTEL(7, 6),
    CELERON_MOBILE = CPU_SUBTYPE_INTEL(7, 7),
    PENTIUM_3      = CPU_SUBTYPE_INTEL(8, 0),
    PENTIUM_3_M    = CPU_SUBTYPE_INTEL(8, 1),
    PENTIUM_3_XEON = CPU_SUBTYPE_INTEL(8, 2),
    PENTIUM_M      = CPU_SUBTYPE_INTEL(9, 0),
    PENTIUM_4      = CPU_SUBTYPE_INTEL(10, 0),
    PENTIUM_4_M    = CPU_SUBTYPE_INTEL(10, 1),
    ITANIUM        = CPU_SUBTYPE_INTEL(11, 0),
    ITANIUM_2      = CPU_SUBTYPE_INTEL(11, 1),
    XEON           = CPU_SUBTYPE_INTEL(12, 0),
    XEON_MP        = CPU_SUBTYPE_INTEL(12, 1)
};

#define CPU_SUBTYPE_INTEL_FAMILY(x) ((x) &15)
constexpr uint32_t CPU_SUBTYPE_INTEL_FAMILY_MAX = 15;

#define CPU_SUBTYPE_INTEL_MODEL(x) ((x) >> 4)
constexpr uint32_t CPU_SUBTYPE_INTEL_MODEL_ALL = 0;

enum class CPU_SUBTYPE_X86 : uint32_t
{
    ALL     = 3,
    _64_ALL = 3,
    ARCH1   = 4,
    _64_H   = 8, /* Haswell feature subset */
};

enum class CPU_THREADTYPE : uint32_t
{
    NONE      = 0,
    INTEL_HTT = 1
};

enum class CPU_SUBTYPE_MIPS : uint32_t
{
    ALL    = 0,
    R2300  = 1,
    R2600  = 2,
    R2800  = 3,
    R2000a = 4, /* pmax */
    R2000  = 5,
    R3000a = 6, /* 3max */
    R3000  = 7,
};

enum class CPU_SUBTYPE_MC98000 : uint32_t
{
    MC98000_ALL = 0,
    MC98601     = 1
};

enum class CPU_SUBTYPE_HPPA : uint32_t
{
    ALL     = 0,
    _7100   = 0, /* compat */
    _7100LC = 1
};

enum class CPU_SUBTYPE_MC88000 : uint32_t
{
    ALL     = 0,
    MC88100 = 1,
    MC88110 = 2
};

enum class CPU_SUBTYPE_SPARC : uint32_t
{
    ALL = 0
};

enum class CPU_SUBTYPE_I860 : uint32_t
{
    ALL  = 0,
    _860 = 1
};

enum class CPU_SUBTYPE_PowerPC : uint32_t
{
    ALL    = 0,
    _601   = 1,
    _602   = 2,
    _603   = 3,
    _603e  = 4,
    _603ev = 5,
    _604   = 6,
    _604e  = 7,
    _620   = 8,
    _750   = 9,
    _7400  = 10,
    _7450  = 11,
    _970   = 100
};

enum class CPU_SUBTYPE_ARM : uint32_t
{
    ALL    = 0,
    V4T    = 5,
    V6     = 6,
    V5TEJ  = 7,
    XSCALE = 8,
    V7     = 9,
    V7F    = 10, /* Cortex A9 */
    V7S    = 11, /* Swift */
    V7K    = 12,
    V8     = 13,
    V6M    = 14, /* Not meant to be run under xnu */
    V7M    = 15, /* Not meant to be run under xnu */
    V7EM   = 16  /* Not meant to be run under xnu */
};

enum class CPU_SUBTYPE_ARM64 : uint32_t
{
    ALL = 0,
    V8  = 1
};

enum class CPU_Family : uint32_t
{
    UNKNOWN           = 0,
    POWERPC_G3        = 0xcee41549,
    POWERPC_G4        = 0x77c184ae,
    POWERPC_G5        = 0xed76d8aa,
    INTEL_6_13        = 0xaa33392b,
    INTEL_PENRYN      = 0x78ea4fbc,
    INTEL_NEHALEM     = 0x6b5a4cd2,
    INTEL_WESTMERE    = 0x573b5eec,
    INTEL_SANDYBRIDGE = 0x5490b78c,
    INTEL_IVYBRIDGE   = 0x1f65e835,
    INTEL_HASWELL     = 0x10b282dc,
    INTEL_BROADWELL   = 0x582ed09c,
    INTEL_SKYLAKE     = 0x37fc219f,
    INTEL_KABYLAKE    = 0x0f817246,
    ARM_9             = 0xe73283ae,
    ARM_11            = 0x8ff620d8,
    ARM_XSCALE        = 0x53b005f5,
    ARM_12            = 0xbd1b0ae9,
    ARM_13            = 0x0cc90e64,
    ARM_14            = 0x96077ef1,
    ARM_15            = 0xa8511bca,
    ARM_SWIFT         = 0x1e2d6381,
    ARM_CYCLONE       = 0x37a09642,
    ARM_TYPHOON       = 0x2c91a47e,
    ARM_TWISTER       = 0x92fb37c8,
    ARM_HURRICANE     = 0x67ceee93,
    INTEL_6_23        = INTEL_PENRYN,  /* synonim is deprecated */
    INTEL_6_26        = INTEL_NEHALEM, /* synonim is deprecated */
};

// https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
// https://olszanowski.blog/posts/macho-reader-parsing-headers/

struct fat_arch
{
    CPU_TYPE cputype;       /* cpu specifier (int) */
    CPU_SUBTYPE cpusubtype; /* machine specifier (int) */
    uint32_t offset;        /* file offset to this object file */
    uint32_t size;          /* size of this object file */
    uint32_t align;         /* alignment as a power of 2 */
};

// https://opensource.apple.com/source/cctools/cctools-895/include/mach-o/fat.h.auto.html
struct fat_arch64
{
    CPU_TYPE cputype;       /* cpu specifier (int) */
    CPU_SUBTYPE cpusubtype; /* machine specifier (int) */
    uint64_t offset;        /* file offset to this object file */
    uint64_t size;          /* size of this object file */
    uint32_t align;         /* alignment as a power of 2 */
    uint64_t reserved;      /* reserved */
};

// https://opensource.apple.com/source/cctools/cctools-895/include/mach-o/loader.h.auto.html
enum class LoadCommandType : uint32_t
{
    REQ_DYLD       = 0x80000000,
    SEGMENT        = 0x1,  /* segment of this file to be mapped */
    SYMTAB         = 0x2,  /* link-edit stab symbol table info */
    SYMSEG         = 0x3,  /* link-edit gdb symbol table info (obsolete) */
    THREAD         = 0x4,  /* thread */
    UNIXTHREAD     = 0x5,  /* unix thread (includes a stack) */
    LOADFVMLIB     = 0x6,  /* load a specified fixed VM shared library */
    IDFVMLIB       = 0x7,  /* fixed VM shared library identification */
    IDENT          = 0x8,  /* object identification info (obsolete) */
    FVMFILE        = 0x9,  /* fixed VM file inclusion (internal use) */
    PREPAGE        = 0xa,  /* prepage command (internal use) */
    DYSYMTAB       = 0xb,  /* dynamic link-edit symbol table info */
    LOAD_DYLIB     = 0xc,  /* load a dynamically linked shared library */
    ID_DYLIB       = 0xd,  /* dynamically linked shared lib ident */
    LOAD_DYLINKER  = 0xe,  /* load a dynamic linker */
    ID_DYLINKER    = 0xf,  /* dynamic linker identification */
    PREBOUND_DYLIB = 0x10, /* modules prebound for a dynamically linked shared library */
    ROUTINES       = 0x11, /* image routines */
    SUB_FRAMEWORK  = 0x12, /* sub framework */
    SUB_UMBRELLA   = 0x13, /* sub umbrella */
    SUB_CLIENT     = 0x14, /* sub client */
    SUB_LIBRARY    = 0x15, /* sub library */
    TWOLEVEL_HINTS = 0x16, /* two-level namespace lookup hints */
    PREBIND_CKSUM  = 0x17, /* prebind checksum */
    LOAD_WEAK_DYLIB =
          (0x18 | REQ_DYLD), /* load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported). */
    SEGMENT_64               = 0x19,              /* 64-bit segment of this file to be mapped */
    ROUTINES_64              = 0x1a,              /* 64-bit image routines */
    UUID                     = 0x1b,              /* the uuid */
    RPATH                    = (0x1c | REQ_DYLD), /* runpath additions */
    CODE_SIGNATURE           = 0x1d,              /* local of code signature */
    SEGMENT_SPLIT_INFO       = 0x1e,              /* local of info to split segments */
    REEXPORT_DYLIB           = (0x1f | REQ_DYLD), /* load and re-export dylib */
    LAZY_LOAD_DYLIB          = 0x20,              /* delay load of dylib until first use */
    ENCRYPTION_INFO          = 0x21,              /* encrypted segment information */
    DYLD_INFO                = 0x22,              /* compressed dyld information */
    DYLD_INFO_ONLY           = (0x22 | REQ_DYLD), /* compressed dyld information only */
    LOAD_UPWARD_DYLIB        = (0x23 | REQ_DYLD), /* load upward dylib */
    VERSION_MIN_MACOSX       = 0x24,              /* build for MacOSX min OS version */
    VERSION_MIN_IPHONEOS     = 0x25,              /* build for iPhoneOS min OS version */
    FUNCTION_STARTS          = 0x26,              /* compressed table of function start addresses */
    DYLD_ENVIRONMENT         = 0x27,              /* string for dyld to treat like environment variable */
    MAIN                     = (0x28 | REQ_DYLD), /* replacement for LC_UNIXTHREAD */
    DATA_IN_CODE             = 0x29,              /* table of non-instructions in __text */
    SOURCE_VERSION           = 0x2A,              /* source version used to build binary */
    DYLIB_CODE_SIGN_DRS      = 0x2B,              /* Code signing DRs copied from linked dylibs */
    ENCRYPTION_INFO_64       = 0x2C,              /* 64-bit encrypted segment information */
    LINKER_OPTION            = 0x2D,              /* linker options in MH_OBJECT files */
    LINKER_OPTIMIZATION_HINT = 0x2E,              /* optimization hints in MH_OBJECT files */
    VERSION_MIN_TVOS         = 0x2F,              /* build for AppleTV min OS version */
    VERSION_MIN_WATCHOS      = 0x30               /* build for Watch min OS version */

};

struct load_command
{
    LoadCommandType cmd; /* type of load command */
    uint32_t cmdsize;    /* total size of command in bytes */
};

class MachOFBFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    struct Colors
    {
        ColorPair header{ Color::Olive, Color::Transparent };
        ColorPair archs{ Color::Magenta, Color::Transparent };
        ColorPair objectName{ Color::DarkRed, Color::Transparent };
        ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

  public:
    Reference<GView::Utils::FileCache> file;
    fat_header header;
    std::vector<fat_arch> archs;
    std::vector<fat_arch64> archs64;
    bool shouldSwapEndianess;
    bool is64;

  public:
    // OffsetTranslateInterface
    uint64_t TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex) override;
    uint64_t TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Mach-O Fat Binary";
    }

  public:
    MachOFBFile(Reference<GView::Utils::FileCache> file);
    virtual ~MachOFBFile(){};

    bool Update();
};
} // namespace GView::Type::MachOFB
