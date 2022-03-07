#pragma once

#include "GView.hpp"

namespace GView::Type::MachO::Utils
{
template <typename T>
const T SwapEndian(T u)
{
    union
    {
        T object;
        unsigned char bytes[sizeof(T)];
    } source{ u }, dest{};

    for (decltype(sizeof(T)) i = 0; i < sizeof(T); i++)
    {
        dest.bytes[i] = source.bytes[sizeof(T) - i - 1];
    }

    return dest.object;
}

template <typename T>
constexpr std::string BinaryToHexString(const T number, const size_t length)
{
    constexpr const char digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(length * 3);

    const auto input = reinterpret_cast<const uint8_t*>(&number);
    std::for_each(
          input,
          input + length,
          [&output](uint8_t byte)
          {
              output.push_back(digits[byte >> 4]);
              output.push_back(digits[byte & 0x0F]);
              output.push_back(' ');
          });

    if (output.empty() == false)
    {
        output.resize(output.size() - 1);
    }

    return output;
}
} // namespace GView::Type::MachO::Utils

namespace GView::Type::MachO::MAC
{
constexpr uint32_t MH_MAGIC    = 0xfeedface; /* the mach magic number */
constexpr uint32_t MH_CIGAM    = 0xcefaedfe; /* NXSwapInt(MH_MAGIC) */
constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf; /* the 64-bit mach magic number */
constexpr uint32_t MH_CIGAM_64 = 0xcffaedfe; /* NXSwapInt(MH_MAGIC_64) */

typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;
typedef int32_t cpu_threadtype_t;

constexpr uint32_t CPU_STATE_MAX = 3;

constexpr uint32_t CPU_STATE_USER   = 0;
constexpr uint32_t CPU_STATE_SYSTEM = 1;
constexpr uint32_t CPU_STATE_IDLE   = 2;

constexpr uint32_t CPU_ARCH_ABI64    = 0x1000000;
constexpr uint32_t CPU_ARCH_ABI64_32 = 0x2000000;

constexpr cpu_type_t CPU_TYPE_ANY         = -1;
constexpr cpu_type_t CPU_TYPE_VAX         = 1;
constexpr cpu_type_t CPU_TYPE_ROMP        = 2;
constexpr cpu_type_t CPU_TYPE_NS32032     = 4;
constexpr cpu_type_t CPU_TYPE_NS32332     = 5;
constexpr cpu_type_t CPU_TYPE_MC680x0     = 6;
constexpr cpu_type_t CPU_TYPE_I386        = 7;
constexpr cpu_type_t CPU_TYPE_X86_64      = (CPU_TYPE_I386 | CPU_ARCH_ABI64);
constexpr cpu_type_t CPU_TYPE_MIPS        = 8;
constexpr cpu_type_t CPU_TYPE_NS32532     = 9;
constexpr cpu_type_t CPU_TYPE_HPPA        = 11;
constexpr cpu_type_t CPU_TYPE_ARM         = 12;
constexpr cpu_type_t CPU_TYPE_MC88000     = 13;
constexpr cpu_type_t CPU_TYPE_SPARC       = 14;
constexpr cpu_type_t CPU_TYPE_I860        = 15; // big-endian
constexpr cpu_type_t CPU_TYPE_I860_LITTLE = 16; // little-endian
constexpr cpu_type_t CPU_TYPE_RS6000      = 17;
constexpr cpu_type_t CPU_TYPE_MC98000     = 18;
constexpr cpu_type_t CPU_TYPE_POWERPC     = 18;
constexpr cpu_type_t CPU_TYPE_POWERPC64   = (CPU_TYPE_POWERPC | CPU_ARCH_ABI64);
constexpr cpu_type_t CPU_TYPE_VEO         = 255;
constexpr cpu_type_t CPU_TYPE_ARM64       = (CPU_TYPE_ARM | CPU_ARCH_ABI64);
constexpr cpu_type_t CPU_TYPE_ARM64_32    = (CPU_TYPE_ARM | CPU_ARCH_ABI64_32);

/* Capability bits used in the definition of cpu_subtype. */
constexpr uint32_t CPU_SUBTYPE_MASK  = 0xff000000; /* mask for feature flags */
constexpr uint32_t CPU_SUBTYPE_LIB64 = 0x80000000; /* 64 bit libraries */

/* CPU subtype capability flags for ptrauth on arm64e platforms */
constexpr uint32_t CPU_SUBTYPE_ARM64_PTR_AUTH_MASK = 0x0f000000;

/* CPU subtype capability flags for ptrauth on arm64e platforms, take 2 */
constexpr uint32_t CPU_SUBTYPE_ARM64E_VERSIONED_ABI_MASK = 0x80000000;
constexpr uint32_t CPU_SUBTYPE_ARM64E_KERNEL_ABI_MASK    = 0x40000000;
constexpr uint32_t CPU_SUBTYPE_ARM64E_PTR_AUTH_MASK      = 0x3f000000;

constexpr cpu_subtype_t CPU_SUBTYPE_MULTIPLE = -1;

/* VAX subtypes (these do *not* necessary conform to the actual cpu ID assigned by DEC available via the SID register). */
constexpr cpu_subtype_t CPU_SUBTYPE_VAX_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX780  = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX785  = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX750  = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX730  = 4;
constexpr cpu_subtype_t CPU_SUBTYPE_UVAXI   = 5;
constexpr cpu_subtype_t CPU_SUBTYPE_UVAXII  = 6;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX8200 = 7;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX8500 = 8;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX8600 = 9;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX8650 = 10;
constexpr cpu_subtype_t CPU_SUBTYPE_VAX8800 = 11;
constexpr cpu_subtype_t CPU_SUBTYPE_UVAXIII = 12;

/* ROMP subtypes. */
constexpr cpu_subtype_t CPU_SUBTYPE_RT_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_RT_PC  = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_RT_APC = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_RT_135 = 3;

/* 32032/32332/32532 subtypes. */

constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_ALL     = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_DPC     = 1; /* 032 CPU */
constexpr cpu_subtype_t CPU_SUBTYPE_SQT          = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_APC_FPU = 3; /* 32081 FPU */
constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_APC_FPA = 4; /* Weitek FPA */
constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_XPC     = 5; /* 532 CPU */

/* I386 subtypes. */
constexpr cpu_subtype_t CPU_SUBTYPE_I386_ALL   = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_X86_64_ALL = CPU_SUBTYPE_I386_ALL;
constexpr cpu_subtype_t CPU_SUBTYPE_386        = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_486        = 4;
constexpr cpu_subtype_t CPU_SUBTYPE_486SX      = 4 + 128;
constexpr cpu_subtype_t CPU_SUBTYPE_586        = 5;
#define CPU_SUBTYPE_INTEL(f, m) ((cpu_subtype_t) (f) + ((m) << 4))
constexpr cpu_subtype_t CPU_SUBTYPE_PENT      = CPU_SUBTYPE_INTEL(5, 0);
constexpr cpu_subtype_t CPU_SUBTYPE_PENTPRO   = CPU_SUBTYPE_INTEL(6, 1);
constexpr cpu_subtype_t CPU_SUBTYPE_PENTII_M3 = CPU_SUBTYPE_INTEL(6, 3);
constexpr cpu_subtype_t CPU_SUBTYPE_PENTII_M5 = CPU_SUBTYPE_INTEL(6, 5);
constexpr cpu_subtype_t CPU_SUBTYPE_PENTIUM_4 = CPU_SUBTYPE_INTEL(10, 0);

#define CPU_SUBTYPE_INTEL_FAMILY(x) ((x) &15)
constexpr uint32_t CPU_SUBTYPE_INTEL_FAMILY_MAX = 15;

#define CPU_SUBTYPE_INTEL_MODEL(x) ((x) >> 4)
constexpr uint32_t CPU_SUBTYPE_INTEL_MODEL_ALL = 0;

constexpr cpu_subtype_t CPU_SUBTYPE_X86_64_H = 8; /* Haswell and compatible */

/* Mips subtypes. */
constexpr cpu_subtype_t CPU_SUBTYPE_MIPS_ALL    = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_MIPS_R2300  = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_MIPS_R2600  = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_MIPS_R2800  = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_MIPS_R2000a = 4;

/* 680x0 subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_MC680x0_ALL  = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_MC68030      = 1; /* compat */
constexpr cpu_subtype_t CPU_SUBTYPE_MC68040      = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_MC68030_ONLY = 3;

/* HPPA subtypes for Hewlett-Packard HP-PA family of risc processors. Port by NeXT to 700 series. */
constexpr cpu_subtype_t CPU_SUBTYPE_HPPA_ALL    = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_HPPA_7100   = 0; /* compat */
constexpr cpu_subtype_t CPU_SUBTYPE_HPPA_7100LC = 1;

/* Acorn subtypes - Acorn Risc Machine */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_ALL       = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_A500_ARCH = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_A500      = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_A440      = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_M4        = 4;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V4T       = 5;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V6        = 6;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V5TEJ     = 7;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_XSCALE    = 8;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7        = 9;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7F       = 10; /* Cortex A9 */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7S       = 11; /* Swift */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7K       = 12; /* Kirkwood40 */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V6M       = 14; /* Not meant to be run under xnu */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7M       = 15; /* Not meant to be run under xnu */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V7EM      = 16; /* Not meant to be run under xnu */
constexpr cpu_subtype_t CPU_SUBTYPE_ARM_V8        = 13;

constexpr cpu_subtype_t CPU_SUBTYPE_ARM64_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM64_V8  = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_ARM64E    = 2;

constexpr cpu_subtype_t CPU_SUBTYPE_ARM64_32_V8 = 1;

/* MC88000 subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_MC88000_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_MMAX_JPC    = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_MC88100     = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_MC88110     = 2;

/* MC98000 (PowerPC) subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_MC98000_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_MC98601     = 1;

/* I860 subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_I860_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_I860_860 = 1;

/* I860 subtypes for NeXT-internal backwards compatability. */
constexpr cpu_subtype_t CPU_SUBTYPE_LITTLE_ENDIAN = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_BIG_ENDIAN    = 1;

/* I860_LITTLE subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_I860_LITTLE_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_I860_LITTLE     = 1;

/* RS6000 subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_RS6000_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_RS6000     = 1;

/* Sun4 subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_SUN4_ALL = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_SUN4_260 = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_SUN4_110 = 2;

constexpr cpu_subtype_t CPU_SUBTYPE_SPARC_ALL = 0;

/* PowerPC subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_ALL   = 0;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_601   = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_602   = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_603   = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_603e  = 4;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_603ev = 5;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_604   = 6;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_604e  = 7;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_620   = 8;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_750   = 9;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_7400  = 10;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_7450  = 11;
constexpr cpu_subtype_t CPU_SUBTYPE_POWERPC_970   = 100;

/* VEO subtypes */
constexpr cpu_subtype_t CPU_SUBTYPE_VEO_1   = 1;
constexpr cpu_subtype_t CPU_SUBTYPE_VEO_2   = 2;
constexpr cpu_subtype_t CPU_SUBTYPE_VEO_3   = 3;
constexpr cpu_subtype_t CPU_SUBTYPE_VEO_4   = 4;
constexpr cpu_subtype_t CPU_SUBTYPE_VEO_ALL = CPU_SUBTYPE_VEO_2;

#define GET_PAIR(x)                                                                                                                        \
    {                                                                                                                                      \
        x, (#x)                                                                                                                            \
    }

#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

enum class FileType : uint32_t
{
    OBJECT      = 0x1, /* relocatable object file */
    EXECUTE     = 0x2, /* demand paged executable file */
    FVMLIB      = 0x3, /* fixed VM shared library file */
    CORE        = 0x4, /* core file */
    PRELOAD     = 0x5, /* preloaded executable file */
    DYLIB       = 0x6, /* dynamically bound shared library */
    BUNDLE      = 0x8, /* dynamically bound bundle file */
    DYLIB_STUB  = 0x9, /* shared library stub for static | linking only, no section contents */
    DSYM        = 0xA, /* companion file with only debug | sections */
    KEXT_BUNDLE = 0xB, /* x86_64 kexts */
};

// https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/include/mach-o/loader.h
struct mach_header
{
    uint32_t magic;           /* mach magic number identifier */
    cpu_type_t cputype;       /* cpu specifier */
    cpu_subtype_t cpusubtype; /* machine specifier */
    FileType filetype;        /* type of file */
    uint32_t ncmds;           /* number of load commands */
    uint32_t sizeofcmds;      /* the size of all the load commands */
    uint32_t flags;           /* flags */
    uint32_t reserved;        /* reserved (for x64 only!) */
};

/*
 * https://unix.superglobalmegacorp.com/xnu/newsrc/EXTERNAL_HEADERS/architecture/byte_order.h.html
 * Identify the byte order of the current host.
 */

enum class ByteOrder
{
    Unknown,
    LittleEndian,
    BigEndian
};

static const std::map<ByteOrder, std::string_view> ByteOrderNames{
    GET_PAIR_FROM_ENUM(ByteOrder::Unknown),
    GET_PAIR_FROM_ENUM(ByteOrder::LittleEndian),
    GET_PAIR_FROM_ENUM(ByteOrder::BigEndian),
};

struct ArchInfo
{
    std::string name;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    ByteOrder byteorder;
    std::string description;
};

/* The array of all currently know architecture flags (terminated with an entry
 * with all zeros).  Pointer to this returned with NXGetAllArchInfos().
 */
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

static const ArchInfo GetArchInfoFromCPUTypeAndSubtype(cpu_type_t cputype, uint32_t cpusubtype)
{
    for (const auto& arch : ArchInfoTable)
    {
        if (arch.cputype == cputype &&
            (cpusubtype == CPU_SUBTYPE_MULTIPLE || ((arch.cpusubtype & ~CPU_SUBTYPE_MASK) == (cpusubtype & ~CPU_SUBTYPE_MASK))))
        {
            return arch;
        }
    }

    ArchInfo ai;
    for (const auto& arch : ArchInfoTable)
    {
        if (arch.cputype == cputype)
        {
            ai = arch;
            break;
        }
    }

    ai.cpusubtype = cpusubtype;

    if (cputype == CPU_TYPE_I386)
    {
        const auto family = std::to_string(CPU_SUBTYPE_INTEL_FAMILY(cpusubtype & ~CPU_SUBTYPE_MASK));
        const auto model  = std::to_string(CPU_SUBTYPE_INTEL_MODEL(cpusubtype & ~CPU_SUBTYPE_MASK));

        ai.description = "Intel family " + family + " model " + model;
    }
    else if (cputype == CPU_TYPE_POWERPC)
    {
        ai.description = "PowerPC cpusubtype " + std::to_string(cpusubtype);
    }

    return ai;
}

static const std::map<FileType, std::string_view> FileTypeNames{
    GET_PAIR_FROM_ENUM(FileType::OBJECT),     GET_PAIR_FROM_ENUM(FileType::EXECUTE),    GET_PAIR_FROM_ENUM(FileType::FVMLIB),
    GET_PAIR_FROM_ENUM(FileType::CORE),       GET_PAIR_FROM_ENUM(FileType::PRELOAD),    GET_PAIR_FROM_ENUM(FileType::DYLIB),
    GET_PAIR_FROM_ENUM(FileType::BUNDLE),     GET_PAIR_FROM_ENUM(FileType::DYLIB_STUB), GET_PAIR_FROM_ENUM(FileType::DSYM),
    GET_PAIR_FROM_ENUM(FileType::KEXT_BUNDLE)
};

enum class MachHeaderFlags : uint32_t
{
    NOUNDEFS                      = 0x1,
    INCRLINK                      = 0x2,
    DYLDLINK                      = 0x4,
    BINDATLOAD                    = 0x8,
    PREBOUND                      = 0x10,
    SPLIT_SEGS                    = 0x20,
    LAZY_INIT                     = 0x40,
    TWOLEVEL                      = 0x80,
    FORCE_FLAT                    = 0x100,
    NOMULTIDEFS                   = 0x200,
    NOFIXPREBINDING               = 0x400,
    PREBINDABLE                   = 0x800,
    ALLMODSBOUND                  = 0x1000,
    SUBSECTIONS_VIA_SYMBOLS       = 0x2000,
    CANONICAL                     = 0x4000,
    WEAK_DEFINES                  = 0x8000,
    BINDS_TO_WEAK                 = 0x10000,
    ALLOW_STACK_EXECUTION         = 0x20000,
    ROOT_SAFE                     = 0x40000,
    SETUID_SAFE                   = 0x80000,
    NO_REEXPORTED_DYLIBS          = 0x100000,
    PIE                           = 0x200000,
    DEAD_STRIPPABLE_DYLIB         = 0x400000,
    HAS_TLV_DESCRIPTORS           = 0x800000,
    NO_HEAP_EXECUTION             = 0x1000000,
    APP_EXTENSION_SAFE            = 0x02000000,
    NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000,
    SIM_SUPPORT                   = 0x08000000
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

static const std::vector<MachHeaderFlags> GetMachHeaderFlagsData(uint32_t flags)
{
    std::vector<MachHeaderFlags> output;

    for (const auto& data : MachHeaderFlagsNames)
    {
        const auto flag = static_cast<MachHeaderFlags>(static_cast<decltype(flags)>(data.first) & flags);
        if (flag == data.first)
        {
            output.emplace_back(flag);
        }
    }

    return output;
}

// https://opensource.apple.com/source/cctools/cctools-895/include/mach-o/loader.h.auto.html
enum class LoadCommandType : uint32_t
{
    REQ_DYLD                 = 0x80000000,
    SEGMENT                  = 0x1,
    SYMTAB                   = 0x2,
    SYMSEG                   = 0x3,
    THREAD                   = 0x4,
    UNIXTHREAD               = 0x5,
    LOADFVMLIB               = 0x6,
    IDFVMLIB                 = 0x7,
    IDENT                    = 0x8,
    FVMFILE                  = 0x9,
    PREPAGE                  = 0xa,
    DYSYMTAB                 = 0xb,
    LOAD_DYLIB               = 0xc,
    ID_DYLIB                 = 0xd,
    LOAD_DYLINKER            = 0xe,
    ID_DYLINKER              = 0xf,
    PREBOUND_DYLIB           = 0x10,
    ROUTINES                 = 0x11,
    SUB_FRAMEWORK            = 0x12,
    SUB_UMBRELLA             = 0x13,
    SUB_CLIENT               = 0x14,
    SUB_LIBRARY              = 0x15,
    TWOLEVEL_HINTS           = 0x16,
    PREBIND_CKSUM            = 0x17,
    LOAD_WEAK_DYLIB          = (0x18 | REQ_DYLD),
    SEGMENT_64               = 0x19,
    ROUTINES_64              = 0x1a,
    UUID                     = 0x1b,
    RPATH                    = (0x1c | REQ_DYLD),
    CODE_SIGNATURE           = 0x1d,
    SEGMENT_SPLIT_INFO       = 0x1e,
    REEXPORT_DYLIB           = (0x1f | REQ_DYLD),
    LAZY_LOAD_DYLIB          = 0x20,
    ENCRYPTION_INFO          = 0x21,
    DYLD_INFO                = 0x22,
    DYLD_INFO_ONLY           = (0x22 | REQ_DYLD),
    LOAD_UPWARD_DYLIB        = (0x23 | REQ_DYLD),
    VERSION_MIN_MACOSX       = 0x24,
    VERSION_MIN_IPHONEOS     = 0x25,
    FUNCTION_STARTS          = 0x26,
    DYLD_ENVIRONMENT         = 0x27,
    MAIN                     = (0x28 | REQ_DYLD),
    DATA_IN_CODE             = 0x29,
    SOURCE_VERSION           = 0x2A,
    DYLIB_CODE_SIGN_DRS      = 0x2B,
    ENCRYPTION_INFO_64       = 0x2C,
    LINKER_OPTION            = 0x2D,
    LINKER_OPTIMIZATION_HINT = 0x2E,
    VERSION_MIN_TVOS         = 0x2F,
    VERSION_MIN_WATCHOS      = 0x30,
    BUILD_VERSION            = 0x31,
    NOTE                     = 0x32,
    DYLD_EXPORTS_TRIE        = 0x33,
    DYLD_CHAINED_FIXUPS      = 0x34
};

struct load_command
{
    LoadCommandType cmd; /* type of load command */
    uint32_t cmdsize;    /* total size of command in bytes */
};

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
                                                                           GET_PAIR_FROM_ENUM(LoadCommandType::DYLD_CHAINED_FIXUPS) };

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
    { LoadCommandType::DYLD_CHAINED_FIXUPS, "Used with `LinkeditDataCommand." }
};

union lc_str
{
    uint32_t offset; /* offset to the string */
    char* ptr;       /* pointer to the string */
};

// https://opensource.apple.com/source/xnu/xnu-1228/osfmk/mach/vm_prot.h.auto.html
enum class VMProtectionFlags : uint32_t
{
    NONE      = 0x0,
    READ      = 0x1,                      /* read permission */
    WRITE     = 0x2,                      /* write permission */
    EXECUTE   = 0x4,                      /* execute permission */
    DEFAULT   = (READ | WRITE),           /* The default protection for newly-created virtual memory. */
    ALL       = (READ | WRITE | EXECUTE), /* The maximum privileges possible, for parameter checking. */
    NO_CHANGE = 0x8,  /* An invalid protection value. Used only by memory_object_lock_request to indicate no change to page locks.  Using
                       -1 here is a bad idea because it looks like VM_PROT::ALL and then some. */
    COPY = 0x10,      /* When a caller finds that he cannot obtain write permission on a mapped entry, the following flag can be used.  The
                       * entry will be made "needs copy" effectively copying the object (using COW), and write permission will be added to
                       * the maximum protections for the associated entry. */
    WANTS_COPY = 0x10 /* Another invalid protection value. Used only by memory_object_data_request upon an object which has specified a
                       * copy_call copy strategy. It is used when the kernel wants a page belonging to a copy of the object, and is only
                       * asking the object as a result of following a shadow chain. This solves the race between pages being pushed up
                       * by the memory manager and the kernel walking down the shadow chain.
                       */
};

static const std::map<VMProtectionFlags, std::string_view> VMProtectionNames{
    GET_PAIR_FROM_ENUM(VMProtectionFlags::NONE),      GET_PAIR_FROM_ENUM(VMProtectionFlags::READ),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::WRITE),     GET_PAIR_FROM_ENUM(VMProtectionFlags::EXECUTE),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::DEFAULT),   GET_PAIR_FROM_ENUM(VMProtectionFlags::ALL),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::NO_CHANGE), GET_PAIR_FROM_ENUM(VMProtectionFlags::COPY),
    GET_PAIR_FROM_ENUM(VMProtectionFlags::WANTS_COPY)
};

static const std::string GetVMProtectionNamesFromFlags(uint32_t flags)
{
    static const std::initializer_list types{ VMProtectionFlags::NONE,      VMProtectionFlags::READ,    VMProtectionFlags::WRITE,
                                              VMProtectionFlags::EXECUTE,   VMProtectionFlags::DEFAULT, VMProtectionFlags::ALL,
                                              VMProtectionFlags::NO_CHANGE, VMProtectionFlags::COPY,    VMProtectionFlags::WANTS_COPY };

    if (flags == static_cast<uint32_t>(VMProtectionFlags::NONE))
    {
        return "NONE";
    }

    std::string output;
    for (const auto& t : types)
    {
        if (t == VMProtectionFlags::NONE)
        {
            continue;
        }

        if ((flags & static_cast<uint32_t>(t)) == static_cast<uint32_t>(t))
        {
            if ((flags & static_cast<uint32_t>(VMProtectionFlags::DEFAULT)) == static_cast<uint32_t>(VMProtectionFlags::DEFAULT))
            {
                if (t == VMProtectionFlags::READ || t == VMProtectionFlags::WRITE)
                {
                    continue;
                }
            }

            if ((flags & static_cast<uint32_t>(VMProtectionFlags::ALL)) == static_cast<uint32_t>(VMProtectionFlags::ALL))
            {
                if (t == VMProtectionFlags::READ || t == VMProtectionFlags::WRITE || t == VMProtectionFlags::EXECUTE ||
                    t == VMProtectionFlags::DEFAULT)
                {
                    continue;
                }
            }

            if (output.empty())
            {
                output += VMProtectionNames.at(t);
            }
            else
            {
                output += " | ";
                output += VMProtectionNames.at(t);
            }
        }
    }

    return output;
};

struct segment_command
{
    LoadCommandType cmd; /* LC_SEGMENT */
    uint32_t cmdsize;    /* includes sizeof section structs */
    char segname[16];    /* segment name */
    uint32_t vmaddr;     /* memory address of this segment */
    uint32_t vmsize;     /* memory size of this segment */
    uint32_t fileoff;    /* file offset of this segment */
    uint32_t filesize;   /* amount to map from the file */
    uint32_t maxprot;    /* maximum VM protection */
    uint32_t initprot;   /* initial VM protection */
    uint32_t nsects;     /* number of sections in segment */
    uint32_t flags;      /* flags */
};

struct segment_command_64
{
    LoadCommandType cmd; /* LC_SEGMENT_64 */
    uint32_t cmdsize;    /* includes sizeof section_64 structs */
    char segname[16];    /* segment name */
    uint64_t vmaddr;     /* memory address of this segment */
    uint64_t vmsize;     /* memory size of this segment */
    uint64_t fileoff;    /* file offset of this segment */
    uint64_t filesize;   /* amount to map from the file */
    uint32_t maxprot;    /* maximum VM protection */
    uint32_t initprot;   /* initial VM protection */
    uint32_t nsects;     /* number of sections in segment */
    uint32_t flags;      /* flags */
};

enum class SegmentCommandFlags : uint32_t
{
    NONE   = 0x0,
    HIGHVM = 0x01,  /* The file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks
                       in  core files). */
    FVMLIB  = 0x02, /* This segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor */
    NORELOC = 0x04, /* This segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced
                       without relocation. */
    PROTECTED_VERSION_1 = 0x08, /* This segment is protected. If the segment starts at file offset 0, the first page of the segment is
                                   not protected.  All other pages of the segment are protected. */
    READONLY = 0x10             /* This segment is made read-only after fixups */
};

static const std::map<SegmentCommandFlags, std::string_view> SegmentCommandFlagsNames{ GET_PAIR_FROM_ENUM(SegmentCommandFlags::HIGHVM),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::FVMLIB),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::NORELOC),
                                                                                       GET_PAIR_FROM_ENUM(
                                                                                             SegmentCommandFlags::PROTECTED_VERSION_1),
                                                                                       GET_PAIR_FROM_ENUM(SegmentCommandFlags::READONLY) };

static const std::string GetSegmentCommandNamesFromFlags(uint32_t flags)
{
    static const std::initializer_list types{ SegmentCommandFlags::NONE,
                                              SegmentCommandFlags::HIGHVM,
                                              SegmentCommandFlags::FVMLIB,
                                              SegmentCommandFlags::NORELOC,
                                              SegmentCommandFlags::PROTECTED_VERSION_1 };

    if (flags == static_cast<uint32_t>(SegmentCommandFlags::NONE))
    {
        return "NONE";
    }

    std::string output;
    for (const auto& t : types)
    {
        if ((flags & static_cast<uint32_t>(t)) == static_cast<uint32_t>(t))
        {
            if (output.empty())
            {
                output += SegmentCommandFlagsNames.at(t);
            }
            else
            {
                output += " | ";
                output += SegmentCommandFlagsNames.at(t);
            }
        }
    }

    return output;
};

struct section
{                       /* for 32-bit architectures */
    char sectname[16];  /* name of this section */
    char segname[16];   /* segment this section goes in */
    uint32_t addr;      /* memory address of this section */
    uint32_t size;      /* size in bytes of this section */
    uint32_t offset;    /* file offset of this section */
    uint32_t align;     /* section alignment (power of 2) */
    uint32_t reloff;    /* file offset of relocation entries */
    uint32_t nreloc;    /* number of relocation entries */
    uint32_t flags;     /* flags (section type and attributes)*/
    uint32_t reserved1; /* reserved (for offset or index) */
    uint32_t reserved2; /* reserved (for count or sizeof) */
};

struct section_64
{                       /* for 64-bit architectures */
    char sectname[16];  /* name of this section */
    char segname[16];   /* segment this section goes in */
    uint64_t addr;      /* memory address of this section */
    uint64_t size;      /* size in bytes of this section */
    uint32_t offset;    /* file offset of this section */
    uint32_t align;     /* section alignment (power of 2) */
    uint32_t reloff;    /* file offset of relocation entries */
    uint32_t nreloc;    /* number of relocation entries */
    uint32_t flags;     /* flags (section type and attributes)*/
    uint32_t reserved1; /* reserved (for offset or index) */
    uint32_t reserved2; /* reserved (for count or sizeof) */
    uint32_t reserved3; /* reserved */
};

constexpr uint32_t SECTION_TYPE       = 0x000000ff; /* 256 section types */
constexpr uint32_t SECTION_ATTRIBUTES = 0xffffff00; /*  24 section attributes */

/* The flags field of a section structure is separated into two parts a section type and section attributes.  The section types are mutually
 * exclusive (it can only have one type) but the section attributes are not (it may have more than one attribute). */
enum class SectionType : uint32_t
{
    REGULAR                             = 0x00, /* regular section */
    ZEROFILL                            = 0x01, /* zero fill on demand section */
    CSTRING_LITERALS                    = 0x02, /* section with only literal C strings*/
    _4BYTE_LITERALS                     = 0x03, /* section with only 4 byte literals */
    _8BYTE_LITERALS                     = 0x04, /* section with only 8 byte literals */
    LITERAL_POINTERS                    = 0x05, /* section with only pointers to literals */
    NON_LAZY_SYMBOL_POINTERS            = 0x06, /* section with only non-lazy symbol pointers */
    LAZY_SYMBOL_POINTERS                = 0x07, /* section with only lazy symbol pointers */
    SYMBOL_STUBS                        = 0x08, /* section with only symbol stubs, byte size of stub in the reserved2 field */
    MOD_INIT_FUNC_POINTERS              = 0x09, /* section with only function pointers for initialization*/
    MOD_TERM_FUNC_POINTERS              = 0x0a, /* section with only function pointers for termination */
    COALESCED                           = 0x0b, /* section contains symbols that are to be coalesced */
    GB_ZEROFILL                         = 0x0c, /* zero fill on demand section (that can be larger than 4 gigabytes) */
    INTERPOSING                         = 0x0d, /* section with only pairs of function pointers for interposing */
    _16BYTE_LITERALS                    = 0x0e, /* section with only 16 byte literals */
    DTRACE_DOF                          = 0x0f, /* section contains DTrace Object Format */
    LAZY_DYLIB_SYMBOL_POINTERS          = 0x10, /* section with only lazy symbol pointers to lazy loaded dylibs */
    THREAD_LOCAL_REGULAR                = 0x11, /* template of initial values for TLVs */
    THREAD_LOCAL_ZEROFILL               = 0x12, /* template of initial values for TLVs */
    THREAD_LOCAL_VARIABLES              = 0x13, /* TLV descriptors */
    THREAD_LOCAL_VARIABLE_POINTERS      = 0x14, /* pointers to TLV descriptors */
    THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15  /* functions to call to initialize TLV values */
};

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
                                                                       GET_PAIR_FROM_ENUM(
                                                                             SectionType::THREAD_LOCAL_INIT_FUNCTION_POINTERS) };

enum class SectionAttributtes : uint32_t
{
    USR                 = 0xff000000, /* User setable attributes */
    PURE_INSTRUCTIONS   = 0x80000000, /* section contains only true machine instructions */
    NO_TOC              = 0x40000000, /* section contains coalesced symbols that are not to be in a ranlib table of contents */
    STRIP_STATIC_SYMS   = 0x20000000, /* ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
    NO_DEAD_STRIP       = 0x10000000, /* no dead stripping */
    LIVE_SUPPORT        = 0x08000000, /* blocks are live if they reference live blocks */
    SELF_MODIFYING_CODE = 0x04000000, /* Used with i386 code stubs written on by dyld */
    DEBUG               = 0x02000000, /* a debug section */
    SYS                 = 0x00ffff00, /* system setable attributes */
    SOME_INSTRUCTIONS   = 0x00000400, /* section contains some machine instructions */
    EXT_RELOC           = 0x00000200, /* section has external relocation entries */
    LOC_RELOC           = 0x00000100  /* section has local relocation entries */
};

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

static const std::string GetSectionTypeAndAttributesFromFlags(uint32_t flags)
{
    const std::string sectionType{ SectionTypeNames.at(static_cast<SectionType>(flags & SECTION_TYPE)) };

    static const std::initializer_list types{ SectionAttributtes::USR,
                                              SectionAttributtes::PURE_INSTRUCTIONS,
                                              SectionAttributtes::NO_TOC,
                                              SectionAttributtes::STRIP_STATIC_SYMS,
                                              SectionAttributtes::NO_DEAD_STRIP,
                                              SectionAttributtes::NO_DEAD_STRIP,
                                              SectionAttributtes::LIVE_SUPPORT,
                                              SectionAttributtes::SELF_MODIFYING_CODE,
                                              SectionAttributtes::DEBUG,
                                              SectionAttributtes::SYS,
                                              SectionAttributtes::SOME_INSTRUCTIONS,
                                              SectionAttributtes::EXT_RELOC,
                                              SectionAttributtes::LOC_RELOC };

    std::string sectionAttributes;
    for (const auto& t : types)
    {
        if ((flags & static_cast<uint32_t>(t)) == static_cast<uint32_t>(t))
        {
            if (sectionAttributes.empty())
            {
                sectionAttributes += SectionAttributtesNames.at(t);
            }
            else
            {
                sectionAttributes += " | ";
                sectionAttributes += SectionAttributtesNames.at(t);
            }
        }
    }

    if (sectionAttributes.empty())
    {
        sectionAttributes = "NONE";
    }

    const std::string output = sectionType + " [ " + sectionAttributes + " ]";
    return output;
};

struct dyld_info_command
{
    LoadCommandType cmd;     /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
    uint32_t cmdsize;        /* sizeof(struct dyld_info_command) */
    uint32_t rebase_off;     /* file offset to rebase info  */
    uint32_t rebase_size;    /* size of rebase info   */
    uint32_t bind_off;       /* file offset to binding info   */
    uint32_t bind_size;      /* size of binding info  */
    uint32_t weak_bind_off;  /* file offset to weak binding info   */
    uint32_t weak_bind_size; /* size of weak binding info  */
    uint32_t lazy_bind_off;  /* file offset to lazy binding info */
    uint32_t lazy_bind_size; /* size of lazy binding infs */
    uint32_t export_off;     /* file offset to lazy binding info */
    uint32_t export_size;    /* size of lazy binding infs */
};

struct dylib
{
    union lc_str name;              /* library's path name */
    uint32_t timestamp;             /* library's build time stamp */
    uint32_t current_version;       /* library's current version number */
    uint32_t compatibility_version; /* library's compatibility vers number*/
};

struct dylib_command
{
    LoadCommandType cmd; /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB, LC_REEXPORT_DYLIB */
    uint32_t cmdsize;    /* includes pathname string */
    dylib dylib;         /* the library identification */
};

} // namespace GView::Type::MachO::MAC

namespace GView::Type::MachO
{
namespace Panels
{
    enum class IDs : uint8_t
    {
        Information  = 0x0,
        LoadCommands = 0x1,
        Segments     = 0x2,
        Sections     = 0x4,
        DyldInfo     = 0x8,
        IdDylib      = 0x10
    };
};

class MachOFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    struct Colors
    {
        ColorPair header{ Color::Olive, Color::Transparent };
        ColorPair loadCommand{ Color::Magenta, Color::Transparent };
        ColorPair section{ Color::DarkRed, Color::Transparent };
        ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

    struct LoadCommand
    {
        MAC::load_command value;
        uint64_t offset;
    };

    union Segment
    {
        MAC::segment_command x86;
        MAC::segment_command_64 x64;
    };

    union Section
    {
        MAC::section x86;
        MAC::section_64 x64;
    };

    struct DyldInfo
    {
        bool set = false;
        MAC::dyld_info_command value;
    };

    struct IdDylib
    {
        bool set = false;
        MAC::dylib_command value;
        std::string name;
    };

  public:
    Reference<GView::Utils::FileCache> file;
    MAC::mach_header header;
    std::vector<LoadCommand> loadCommands;
    std::vector<Segment> segments;
    std::vector<Section> sections;
    DyldInfo dyldInfo;
    IdDylib idDylib;
    bool shouldSwapEndianess;
    bool is64;

    uint64_t panelsMask;

  public:
    // OffsetTranslateInterface
    uint64_t TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex) override;
    uint64_t TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Mach-O";
    }

  public:
    MachOFile(Reference<GView::Utils::FileCache> file);
    virtual ~MachOFile(){};

    bool Update();

    bool HasPanel(Panels::IDs id);

    bool SetArchitectureAndEndianess(uint64_t& offset);
    bool SetHeader(uint64_t& offset);
    bool SetLoadCommands(uint64_t& offset);
    bool SetSegments(uint64_t& offset);
    bool SetSections(uint64_t& offset);
    bool SetDyldInfo(uint64_t& offset);
    bool SetIdDylib(uint64_t& offset);
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

      public:
        Information(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class LoadCommands : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        LoadCommands(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class Segments : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Segments(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class Sections : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Sections(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class DyldInfo : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

      public:
        DyldInfo(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class IdDylib : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

      public:
        IdDylib(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };
} // namespace Panels
} // namespace GView::Type::MachO
