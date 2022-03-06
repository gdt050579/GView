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
// https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
// https://github.com/grumbach/nm_otool
constexpr uint32_t MH_MAGIC    = 0xfeedface; /* the mach magic number */
constexpr uint32_t MH_CIGAM    = 0xcefaedfe; /* NXSwapInt(MH_MAGIC) */
constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf; /* the 64-bit mach magic number */
constexpr uint32_t MH_CIGAM_64 = 0xcffaedfe; /* NXSwapInt(MH_MAGIC_64) */

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

// https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/machine.h.auto.html
// https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/include/mach/machine.h

enum class CPU_TYPE : uint32_t
{
    ANY  = static_cast<uint32_t>(-1),
    VAX  = 1,
    ROMP = 2,
    /* skip	((cpu_type_t) 3)	*/
    NS32032     = 4,
    NS32332     = 5,
    MC680x0     = 6,
    X86         = 7,
    I386        = X86, /* compatibility */
    X86_64      = (X86 | static_cast<uint32_t>(CPU_ARCH::ABI64)),
    MIPS        = 8,
    NS32532     = 9,
    MC98000     = 10,
    HPPA        = 11,
    ARM         = 12,
    ARM64       = (ARM | static_cast<uint32_t>(CPU_ARCH::ABI64)),
    MC88000     = 13,
    SPARC       = 14,
    I860        = 15, // big-endian
    I860_LITTLE = 16, // little-endian
    RS6000      = 17,
    POWERPC     = 18,
    POWERPC64   = (POWERPC | static_cast<uint32_t>(CPU_ARCH::ABI64)),
    VEO         = 255
};

#define GET_PAIR(x)                                                                                                                        \
    {                                                                                                                                      \
        x, (#x)                                                                                                                            \
    }

#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

static const std::map<CPU_TYPE, std::string_view> CpuTypeNames{ GET_PAIR_FROM_ENUM(CPU_TYPE::ANY),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::VAX),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::ROMP),
                                                                // skipped
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::NS32032),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::NS32332),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::MC680x0),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::X86),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::I386),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::X86_64),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::MIPS),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::NS32532),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::MC98000),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::HPPA),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::ARM),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::ARM64),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::MC88000),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::SPARC),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::I860),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::I860_LITTLE),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::RS6000),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::POWERPC),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::POWERPC64),
                                                                GET_PAIR_FROM_ENUM(CPU_TYPE::VEO) };

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

enum class CPU_SUBTYPE_RT
{
    ALL  = 0,
    PC   = 1,
    APC  = 2,
    _135 = 3
};

enum class CPU_SUBTYPE_MC680 : uint32_t
{
    x0_ALL   = 1,
    _30      = 1, /* compat */
    _40      = 2,
    _30_ONLY = 3,
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
    ALL   = 3,
    ARCH1 = 4
};

enum class CPU_SUBTYPE_X86_64 : uint32_t
{
    ALL   = static_cast<uint32_t>(CPU_SUBTYPE_COMPATIBILITY::LIB64) | 3,
    ALL64 = 3,
    H     = static_cast<uint32_t>(CPU_SUBTYPE_COMPATIBILITY::LIB64) | 8, /* Haswell feature subset */
    H64   = 8                                                            /* Haswell feature subset */
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
    ALL  = 0,
    _601 = 1
};

enum class CPU_SUBTYPE_HPPA : uint32_t
{
    ALL     = 0,
    _7100   = 0, /* compat */
    _7100LC = 1
};

enum class CPU_SUBTYPE_MC88000 : uint32_t
{
    ALL  = 0,
    _100 = 1,
    _110 = 2
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

enum class CPU_SUBTYPE_I860_LITTLE : uint32_t
{
    ALL  = 0,
    _860 = 1
};

enum class CPU_SUBTYPE_RS6000 : uint32_t
{
    ALL = 0,
    _1  = 1
};

enum class CPU_SUBTYPE_SUN4
{
    ALL  = 0,
    _260 = 1,
    _110 = 2
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

/* https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/include/mach/machine.h
 * VEO subtypes
 * Note: the CPU_SUBTYPE_VEO_ALL will likely change over time to be defined as
 * one of the specific subtypes.
 */
enum class CPU_SUBTYPE_VEO : uint32_t
{
    _1  = 1,
    _2  = 2,
    _3  = 3,
    _4  = 4,
    ALL = 1
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

static const std::map<CPU_SUBTYPE, std::string_view> CpuSubtypeNames{
    GET_PAIR(CPU_SUBTYPE::MULTIPLE),
    GET_PAIR(CPU_SUBTYPE::LITTLE_ENDIAN),
    GET_PAIR(CPU_SUBTYPE::BIG_ENDIAN),
};

static const std::map<CPU_SUBTYPE_VAX, std::string_view> CpuSubtypeVaxNames{
    GET_PAIR(CPU_SUBTYPE_VAX::ALL),     GET_PAIR(CPU_SUBTYPE_VAX::VAX780),  GET_PAIR(CPU_SUBTYPE_VAX::VAX785),
    GET_PAIR(CPU_SUBTYPE_VAX::VAX750),  GET_PAIR(CPU_SUBTYPE_VAX::VAX730),  GET_PAIR(CPU_SUBTYPE_VAX::UVAXI),
    GET_PAIR(CPU_SUBTYPE_VAX::UVAXII),  GET_PAIR(CPU_SUBTYPE_VAX::VAX8200), GET_PAIR(CPU_SUBTYPE_VAX::VAX8500),
    GET_PAIR(CPU_SUBTYPE_VAX::VAX8600), GET_PAIR(CPU_SUBTYPE_VAX::VAX8650), GET_PAIR(CPU_SUBTYPE_VAX::VAX8800),
    GET_PAIR(CPU_SUBTYPE_VAX::UVAXIII)
};

static const std::map<CPU_SUBTYPE_RT, std::string_view> CpuSubtypeRompNames{
    GET_PAIR(CPU_SUBTYPE_RT::ALL), GET_PAIR(CPU_SUBTYPE_RT::PC), GET_PAIR(CPU_SUBTYPE_RT::APC), GET_PAIR(CPU_SUBTYPE_RT::_135)
};

static const std::map<CPU_SUBTYPE_MC680, std::string_view> CpuSubtypeMC680Names{ GET_PAIR(CPU_SUBTYPE_MC680::x0_ALL),
                                                                                 GET_PAIR(CPU_SUBTYPE_MC680::_30),
                                                                                 GET_PAIR(CPU_SUBTYPE_MC680::_40),
                                                                                 GET_PAIR(CPU_SUBTYPE_MC680::_30_ONLY) };

static const std::map<CPU_SUBTYPE_X86, std::string_view> CpuSubtypeX86Names{ { CPU_SUBTYPE_X86::ALL, "ALL" },
                                                                             { CPU_SUBTYPE_X86::ARCH1, "ARCH1" } };

static const std::map<CPU_SUBTYPE_X86_64, std::string_view> CpuSubtypeX86_64Names{ { CPU_SUBTYPE_X86_64::ALL, "ALL" },
                                                                                   { CPU_SUBTYPE_X86_64::ALL64, "ALL" },
                                                                                   { CPU_SUBTYPE_X86_64::H, "Haswell" },
                                                                                   { CPU_SUBTYPE_X86_64::H64, "Haswell" } };

static const std::map<CPU_SUBTYPE_MIPS, std::string_view> CpuSubtypeMipsNames{
    GET_PAIR(CPU_SUBTYPE_MIPS::ALL),    GET_PAIR(CPU_SUBTYPE_MIPS::R2300),  GET_PAIR(CPU_SUBTYPE_MIPS::R2600),
    GET_PAIR(CPU_SUBTYPE_MIPS::R2800),  GET_PAIR(CPU_SUBTYPE_MIPS::R2000a), GET_PAIR(CPU_SUBTYPE_MIPS::R2000),
    GET_PAIR(CPU_SUBTYPE_MIPS::R3000a), GET_PAIR(CPU_SUBTYPE_MIPS::R3000),

};

static const std::map<CPU_SUBTYPE_MC98000, std::string_view> CpuSubtypeMC98000Names{ GET_PAIR(CPU_SUBTYPE_MC98000::ALL),
                                                                                     GET_PAIR(CPU_SUBTYPE_MC98000::_601) };

static const std::map<CPU_SUBTYPE_HPPA, std::string_view> CpuSubtypeHppaNames{ GET_PAIR(CPU_SUBTYPE_HPPA::ALL),
                                                                               GET_PAIR(CPU_SUBTYPE_HPPA::_7100),
                                                                               GET_PAIR(CPU_SUBTYPE_HPPA::_7100LC) };

static const std::map<CPU_SUBTYPE_ARM, std::string_view> CpuSubtypeArmNames{
    GET_PAIR(CPU_SUBTYPE_ARM::ALL),    GET_PAIR(CPU_SUBTYPE_ARM::V4T), GET_PAIR(CPU_SUBTYPE_ARM::V6),  GET_PAIR(CPU_SUBTYPE_ARM::V5TEJ),
    GET_PAIR(CPU_SUBTYPE_ARM::XSCALE), GET_PAIR(CPU_SUBTYPE_ARM::V7),  GET_PAIR(CPU_SUBTYPE_ARM::V7F), GET_PAIR(CPU_SUBTYPE_ARM::V7S),
    GET_PAIR(CPU_SUBTYPE_ARM::V7K),    GET_PAIR(CPU_SUBTYPE_ARM::V8),  GET_PAIR(CPU_SUBTYPE_ARM::V6M), GET_PAIR(CPU_SUBTYPE_ARM::V7M),
    GET_PAIR(CPU_SUBTYPE_ARM::V7EM)
};

static const std::map<CPU_SUBTYPE_ARM64, std::string_view> CpuSubtypeArm64Names{ GET_PAIR(CPU_SUBTYPE_ARM64::ALL),
                                                                                 GET_PAIR(CPU_SUBTYPE_ARM64::ALL),
                                                                                 GET_PAIR(CPU_SUBTYPE_ARM64::V8) };

static const std::map<CPU_SUBTYPE_MC88000, std::string_view> CpuSubtypeMC8800Names{ GET_PAIR(CPU_SUBTYPE_MC88000::ALL),
                                                                                    GET_PAIR(CPU_SUBTYPE_MC88000::_100),
                                                                                    GET_PAIR(CPU_SUBTYPE_MC88000::_110) };

static const std::map<CPU_SUBTYPE_SPARC, std::string_view> CpuSubtypeSparcNames{ GET_PAIR(CPU_SUBTYPE_SPARC::ALL) };

static const std::map<CPU_SUBTYPE_I860, std::string_view> CpuSubtypeI860Names{ GET_PAIR(CPU_SUBTYPE_I860::ALL),
                                                                               GET_PAIR(CPU_SUBTYPE_I860::_860) };

static const std::map<CPU_SUBTYPE_I860_LITTLE, std::string_view> CpuSubtypeI860LittleNames{ GET_PAIR(CPU_SUBTYPE_I860_LITTLE::ALL),
                                                                                            GET_PAIR(CPU_SUBTYPE_I860_LITTLE::_860) };

static const std::map<CPU_SUBTYPE_RS6000, std::string_view> CpuSubtypeRS6000Names{ GET_PAIR(CPU_SUBTYPE_RS6000::ALL),
                                                                                   GET_PAIR(CPU_SUBTYPE_RS6000::_1) };

static const std::map<CPU_SUBTYPE_PowerPC, std::string_view> CpuSubtypePowerPcNames{
    GET_PAIR(CPU_SUBTYPE_PowerPC::ALL),  GET_PAIR(CPU_SUBTYPE_PowerPC::_601),  GET_PAIR(CPU_SUBTYPE_PowerPC::_602),
    GET_PAIR(CPU_SUBTYPE_PowerPC::_603), GET_PAIR(CPU_SUBTYPE_PowerPC::_603e), GET_PAIR(CPU_SUBTYPE_PowerPC::_603ev),
    GET_PAIR(CPU_SUBTYPE_PowerPC::_604), GET_PAIR(CPU_SUBTYPE_PowerPC::_604e), GET_PAIR(CPU_SUBTYPE_PowerPC::_620),
    GET_PAIR(CPU_SUBTYPE_PowerPC::_750), GET_PAIR(CPU_SUBTYPE_PowerPC::_7400), GET_PAIR(CPU_SUBTYPE_PowerPC::_7450),
    GET_PAIR(CPU_SUBTYPE_PowerPC::_970)
};

static const std::map<CPU_SUBTYPE_VEO, std::string_view> CpuSubtypeVeoNames{ GET_PAIR(CPU_SUBTYPE_VEO::_1),
                                                                             GET_PAIR(CPU_SUBTYPE_VEO::_2),
                                                                             GET_PAIR(CPU_SUBTYPE_VEO::_3),
                                                                             GET_PAIR(CPU_SUBTYPE_VEO::_4),
                                                                             GET_PAIR(CPU_SUBTYPE_VEO::ALL) };

static const std::string_view GetCPUSubtype(CPU_TYPE type, uint32_t subtype)
{
    switch (type)
    {
    case CPU_TYPE::ANY:
        return CpuSubtypeNames.at(static_cast<CPU_SUBTYPE>(subtype));
    case CPU_TYPE::VAX:
        return CpuSubtypeVaxNames.at(static_cast<CPU_SUBTYPE_VAX>(subtype));
    case CPU_TYPE::ROMP:
        return CpuSubtypeRompNames.at(static_cast<CPU_SUBTYPE_RT>(subtype));
    case CPU_TYPE::NS32032:
        return "(?)";
    case CPU_TYPE::NS32332:
        return "(?)";
    case CPU_TYPE::MC680x0:
        return CpuSubtypeMC680Names.at(static_cast<CPU_SUBTYPE_MC680>(subtype));
    case CPU_TYPE::X86: /* I386 */
        return CpuSubtypeX86Names.at(static_cast<CPU_SUBTYPE_X86>(subtype));
    case CPU_TYPE::X86_64:
        return CpuSubtypeX86_64Names.at(static_cast<CPU_SUBTYPE_X86_64>(subtype));
    case CPU_TYPE::MIPS:
        return CpuSubtypeMipsNames.at(static_cast<CPU_SUBTYPE_MIPS>(subtype));
    case CPU_TYPE::NS32532:
        return "(?)";
    case CPU_TYPE::MC98000:
        return CpuSubtypeMC98000Names.at(static_cast<CPU_SUBTYPE_MC98000>(subtype));
    case CPU_TYPE::HPPA:
        return CpuSubtypeHppaNames.at(static_cast<CPU_SUBTYPE_HPPA>(subtype));
    case CPU_TYPE::ARM:
        return CpuSubtypeArmNames.at(static_cast<CPU_SUBTYPE_ARM>(subtype));
    case CPU_TYPE::ARM64:
        return CpuSubtypeArm64Names.at(static_cast<CPU_SUBTYPE_ARM64>(subtype));
    case CPU_TYPE::MC88000:
        return CpuSubtypeMC8800Names.at(static_cast<CPU_SUBTYPE_MC88000>(subtype));
    case CPU_TYPE::SPARC:
        return CpuSubtypeSparcNames.at(static_cast<CPU_SUBTYPE_SPARC>(subtype));
    case CPU_TYPE::I860:
        return CpuSubtypeI860Names.at(static_cast<CPU_SUBTYPE_I860>(subtype));
    case CPU_TYPE::I860_LITTLE:
        return CpuSubtypeI860LittleNames.at(static_cast<CPU_SUBTYPE_I860_LITTLE>(subtype));
    case CPU_TYPE::RS6000:
        return CpuSubtypeRS6000Names.at(static_cast<CPU_SUBTYPE_RS6000>(subtype));
    case CPU_TYPE::POWERPC:
    case CPU_TYPE::POWERPC64:
        return CpuSubtypePowerPcNames.at(static_cast<CPU_SUBTYPE_PowerPC>(subtype));
    case CPU_TYPE::VEO:
        return CpuSubtypeVeoNames.at(static_cast<CPU_SUBTYPE_VEO>(subtype));
    default:
        return "(?)";
    }
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
    uint32_t magic;      /* mach magic number identifier */
    CPU_TYPE cputype;    /* cpu specifier */
    uint32_t cpusubtype; /* machine specifier */
    FileType filetype;   /* type of file */
    uint32_t ncmds;      /* number of load commands */
    uint32_t sizeofcmds; /* the size of all the load commands */
    uint32_t flags;      /* flags */
    uint32_t reserved;   /* reserved (for x64 only!) */
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
    CPU_TYPE cputype;
    uint32_t cpusubtype;
    ByteOrder byteorder;
    std::string description;
};

static const ArchInfo ArchInfoTable[] = {
    { "hppa", CPU_TYPE::HPPA, static_cast<uint32_t>(CPU_SUBTYPE_HPPA::ALL), ByteOrder::BigEndian, "HP-PA" },
    { "i386", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_X86::ALL), ByteOrder::LittleEndian, "Intel 80x86" },
    { "x86_64", CPU_TYPE::X86_64, static_cast<uint32_t>(CPU_SUBTYPE_X86_64::ALL), ByteOrder::LittleEndian, "Intel x86-64" },
    { "x86_64h", CPU_TYPE::X86_64, static_cast<uint32_t>(CPU_SUBTYPE_X86_64::H), ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
    { "i860", CPU_TYPE::I860, static_cast<uint32_t>(CPU_SUBTYPE_I860::ALL), ByteOrder::BigEndian, "Intel 860" },
    { "m68k", CPU_TYPE::MC680x0, static_cast<uint32_t>(CPU_SUBTYPE_MC680::x0_ALL), ByteOrder::BigEndian, "Motorola 68K" },
    { "m88k", CPU_TYPE::MC88000, static_cast<uint32_t>(CPU_SUBTYPE_MC88000::ALL), ByteOrder::BigEndian, "Motorola 88K" },
    { "ppc", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::ALL), ByteOrder::BigEndian, "PowerPC" },
    { "ppc64", CPU_TYPE::POWERPC64, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::ALL), ByteOrder::BigEndian, "PowerPC 64-bit" },
    { "sparc", CPU_TYPE::SPARC, static_cast<uint32_t>(CPU_SUBTYPE_SPARC::ALL), ByteOrder::BigEndian, "SPARC" },
    { "arm", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::ALL), ByteOrder::LittleEndian, "ARM" },
    { "arm64", CPU_TYPE::ARM64, static_cast<uint32_t>(CPU_SUBTYPE_ARM64::ALL), ByteOrder::LittleEndian, "ARM64" },
    { "any", CPU_TYPE::ANY, static_cast<uint32_t>(CPU_SUBTYPE::MULTIPLE), ByteOrder::Unknown, "Architecture Independent" },
    { "veo", CPU_TYPE::VEO, static_cast<uint32_t>(CPU_SUBTYPE_VEO::ALL), ByteOrder::BigEndian, "veo" },
    /* specific architecture implementations */
    { "hppa7100LC", CPU_TYPE::HPPA, static_cast<uint32_t>(CPU_SUBTYPE_HPPA::_7100LC), ByteOrder::BigEndian, "HP-PA 7100LC" },
    { "m68030", CPU_TYPE::MC680x0, static_cast<uint32_t>(CPU_SUBTYPE_MC680::_30_ONLY), ByteOrder::BigEndian, "Motorola 68030" },
    { "m68040", CPU_TYPE::MC680x0, static_cast<uint32_t>(CPU_SUBTYPE_MC680::_40), ByteOrder::BigEndian, "Motorola 68040" },
    { "i486", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_INTEL::_486), ByteOrder::LittleEndian, "Intel 80486" },
    { "i486SX", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_INTEL::_486SX), ByteOrder::LittleEndian, "Intel 80486SX" },
    { "pentium",
      CPU_TYPE::I386,
      static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENT),
      ByteOrder::LittleEndian,
      "Intel Pentium" }, /* same as 586 */
    { "i586", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_INTEL::_586), ByteOrder::LittleEndian, "Intel 80586" },
    { "pentpro",
      CPU_TYPE::I386,
      static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENTPRO),
      ByteOrder::LittleEndian,
      "Intel Pentium Pro" }, /* same as 686 */
    { "i686", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENTPRO), ByteOrder::LittleEndian, "Intel Pentium Pro" },
    { "pentIIm3",
      CPU_TYPE::I386,
      static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENTII_M3),
      ByteOrder::LittleEndian,
      "Intel Pentium II Model 3" },
    { "pentIIm5",
      CPU_TYPE::I386,
      static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENTII_M5),
      ByteOrder::LittleEndian,
      "Intel Pentium II Model 5" },
    { "pentium4", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_INTEL::PENTIUM_4), ByteOrder::LittleEndian, "Intel Pentium 4" },
    { "x86_64h", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_X86_64::H), ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
    { "ppc601", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_601), ByteOrder::BigEndian, "PowerPC 601" },
    { "ppc603", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_603), ByteOrder::BigEndian, "PowerPC 603" },
    { "ppc603e", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_603e), ByteOrder::BigEndian, "PowerPC 603e" },
    { "ppc603ev", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_603ev), ByteOrder::BigEndian, "PowerPC 603ev" },
    { "ppc604", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_604), ByteOrder::BigEndian, "PowerPC 604" },
    { "ppc604e", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_604e), ByteOrder::BigEndian, "PowerPC 604e" },
    { "ppc750", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_750), ByteOrder::BigEndian, "PowerPC 750" },
    { "ppc7400", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_7400), ByteOrder::BigEndian, "PowerPC 7400" },
    { "ppc7450", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_7450), ByteOrder::BigEndian, "PowerPC 7450" },
    { "ppc970", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_970), ByteOrder::BigEndian, "PowerPC 970" },
    { "ppc970-64", CPU_TYPE::POWERPC64, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::_970), ByteOrder::BigEndian, "PowerPC 970 64-bit" },
    { "armv4t", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V4T), ByteOrder::LittleEndian, "arm v4t" },
    { "armv5", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V5TEJ), ByteOrder::LittleEndian, "arm v5" },
    { "xscale", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::XSCALE), ByteOrder::LittleEndian, "arm xscale" },
    { "armv6", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V6), ByteOrder::LittleEndian, "arm v6" },
    { "armv6m", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V6M), ByteOrder::LittleEndian, "arm v6m" },
    { "armv7", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7), ByteOrder::LittleEndian, "arm v7" },
    { "armv7f", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7F), ByteOrder::LittleEndian, "arm v7f" },
    { "armv7s", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7S), ByteOrder::LittleEndian, "arm v7s" },
    { "armv7k", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7K), ByteOrder::LittleEndian, "arm v7k" },
    { "armv7m", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7M), ByteOrder::LittleEndian, "arm v7m" },
    { "armv7em", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V7EM), ByteOrder::LittleEndian, "arm v7em" },
    { "armv8", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::V8), ByteOrder::LittleEndian, "arm v8" },
    { "arm64", CPU_TYPE::ARM64, static_cast<uint32_t>(CPU_SUBTYPE_ARM64::V8), ByteOrder::LittleEndian, "arm64 v8" },
    { "little", CPU_TYPE::ANY, static_cast<uint32_t>(CPU_SUBTYPE::LITTLE_ENDIAN), ByteOrder::LittleEndian, "Little Endian" },
    { "big", CPU_TYPE::ANY, static_cast<uint32_t>(CPU_SUBTYPE::BIG_ENDIAN), ByteOrder::BigEndian, "Big Endian" },
    { "veo1", CPU_TYPE::VEO, static_cast<uint32_t>(CPU_SUBTYPE_VEO::_1), ByteOrder::BigEndian, "veo 1" },
    { "veo2", CPU_TYPE::VEO, static_cast<uint32_t>(CPU_SUBTYPE_VEO::_2), ByteOrder::BigEndian, "veo 2" }
};

static const ArchInfo GetArchInfoFromCPUTypeAndSubtype(CPU_TYPE cputype, uint32_t cpusubtype)
{
    for (const auto& arch : ArchInfoTable)
    {
        if (arch.cputype == cputype && (cpusubtype == static_cast<uint32_t>(CPU_SUBTYPE::MULTIPLE) ||
                                        ((arch.cpusubtype & ~static_cast<uint32>(CPU_SUBTYPE_COMPATIBILITY::MASK)) ==
                                         (cpusubtype & ~static_cast<uint32>(CPU_SUBTYPE_COMPATIBILITY::MASK)))))
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

    if (cputype == CPU_TYPE::I386)
    {
        const auto family = std::to_string(CPU_SUBTYPE_INTEL_FAMILY(cpusubtype & ~(static_cast<uint32>(CPU_SUBTYPE_COMPATIBILITY::MASK))));
        const auto model  = std::to_string(CPU_SUBTYPE_INTEL_MODEL(cpusubtype & ~(static_cast<uint32>(CPU_SUBTYPE_COMPATIBILITY::MASK))));

        ai.description = "Intel family " + family + " model " + model;
    }
    else if (cputype == CPU_TYPE::POWERPC)
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
                                                                               GET_PAIR_FROM_ENUM(MachHeaderFlags::ROOT_SAFE) };

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
enum class VM_PROT : uint32_t
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

struct segment_command
{
    LoadCommandType cmd; /* LC_SEGMENT */
    uint32_t cmdsize;    /* includes sizeof section structs */
    char segname[16];    /* segment name */
    uint32_t vmaddr;     /* memory address of this segment */
    uint32_t vmsize;     /* memory size of this segment */
    uint32_t fileoff;    /* file offset of this segment */
    uint32_t filesize;   /* amount to map from the file */
    VM_PROT maxprot;     /* maximum VM protection */
    VM_PROT initprot;    /* initial VM protection */
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
    VM_PROT maxprot;     /* maximum VM protection */
    VM_PROT initprot;    /* initial VM protection */
    uint32_t nsects;     /* number of sections in segment */
    uint32_t flags;      /* flags */
};

enum class SegmentCommandFlags : uint32_t
{
    HIGHVM = 0x01,  /* the file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks
                       in  core files) */
    FVMLIB  = 0x02, /* this segment is the VM that is allocated by a fixed VM library, for overlap checking in the link editor */
    NORELOC = 0x04, /* this segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced
                       without relocation */
    PROTECTED_VERSION_1 = 0x08, /* This segment is protected. If the segment starts at file offset 0, the first page of the segment is
                                   not protected.  All other pages of the segment are protected. */
};

} // namespace GView::Type::MachO::MAC

namespace GView::Type::MachO
{
namespace Panels
{
    enum class IDs : uint8_t
    {
        Information  = 0,
        LoadCommands = 1,
        Segments     = 2
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

  public:
    Reference<GView::Utils::FileCache> file;
    MAC::mach_header header;
    std::vector<LoadCommand> loadCommands;
    std::vector<Segment> segments;
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
} // namespace Panels
} // namespace GView::Type::MachO
