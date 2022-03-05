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

#define GET_VARIABLE_NAME(x) (#x)
#define GET_PAIR(x)                                                                                                                        \
    {                                                                                                                                      \
        x, (GET_VARIABLE_NAME(x))                                                                                                          \
    }

static const std::map<CPU_TYPE, std::string_view> CpuTypeNames{ GET_PAIR(CPU_TYPE::ANY),
                                                                GET_PAIR(CPU_TYPE::VAX),
                                                                GET_PAIR(CPU_TYPE::ROMP),
                                                                // skipped
                                                                GET_PAIR(CPU_TYPE::NS32032),
                                                                GET_PAIR(CPU_TYPE::NS32332),
                                                                GET_PAIR(CPU_TYPE::MC680x0),
                                                                GET_PAIR(CPU_TYPE::X86),
                                                                GET_PAIR(CPU_TYPE::I386),
                                                                GET_PAIR(CPU_TYPE::X86_64),
                                                                GET_PAIR(CPU_TYPE::MIPS),
                                                                GET_PAIR(CPU_TYPE::NS32532),
                                                                GET_PAIR(CPU_TYPE::MC98000),
                                                                GET_PAIR(CPU_TYPE::HPPA),
                                                                GET_PAIR(CPU_TYPE::ARM),
                                                                GET_PAIR(CPU_TYPE::ARM64),
                                                                GET_PAIR(CPU_TYPE::MC88000),
                                                                GET_PAIR(CPU_TYPE::SPARC),
                                                                GET_PAIR(CPU_TYPE::I860),
                                                                GET_PAIR(CPU_TYPE::I860_LITTLE),
                                                                GET_PAIR(CPU_TYPE::RS6000),
                                                                GET_PAIR(CPU_TYPE::POWERPC),
                                                                GET_PAIR(CPU_TYPE::POWERPC64),
                                                                GET_PAIR(CPU_TYPE::VEO) };

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

static const std::map<CPU_SUBTYPE_X86, std::string_view> CpuSubtypeX86Names{ GET_PAIR(CPU_SUBTYPE_X86::ALL),
                                                                             GET_PAIR(CPU_SUBTYPE_X86::_64_ALL),
                                                                             GET_PAIR(CPU_SUBTYPE_X86::ARCH1),
                                                                             { CPU_SUBTYPE_X86::_64_H, "CPU_SUBTYPE_X86::_64_Haswell" } };

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
        return CpuSubtypeX86Names.at(static_cast<CPU_SUBTYPE_X86>(subtype));
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

// https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/include/mach-o/loader.h
struct mach_header
{
    uint32_t magic;      /* mach magic number identifier */
    CPU_TYPE cputype;    /* cpu specifier */
    uint32_t cpusubtype; /* machine specifier */
    uint32_t filetype;   /* type of file */
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
    UnknownByteOrder,
    LittleEndian,
    BigEndian
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
    { "x86_64", CPU_TYPE::X86_64, static_cast<uint32_t>(CPU_SUBTYPE_X86::_64_ALL), ByteOrder::LittleEndian, "Intel x86-64" },
    { "x86_64h", CPU_TYPE::X86_64, static_cast<uint32_t>(CPU_SUBTYPE_X86::_64_H), ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
    { "i860", CPU_TYPE::I860, static_cast<uint32_t>(CPU_SUBTYPE_I860::ALL), ByteOrder::BigEndian, "Intel 860" },
    { "m68k", CPU_TYPE::MC680x0, static_cast<uint32_t>(CPU_SUBTYPE_MC680::x0_ALL), ByteOrder::BigEndian, "Motorola 68K" },
    { "m88k", CPU_TYPE::MC88000, static_cast<uint32_t>(CPU_SUBTYPE_MC88000::ALL), ByteOrder::BigEndian, "Motorola 88K" },
    { "ppc", CPU_TYPE::POWERPC, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::ALL), ByteOrder::BigEndian, "PowerPC" },
    { "ppc64", CPU_TYPE::POWERPC64, static_cast<uint32_t>(CPU_SUBTYPE_PowerPC::ALL), ByteOrder::BigEndian, "PowerPC 64-bit" },
    { "sparc", CPU_TYPE::SPARC, static_cast<uint32_t>(CPU_SUBTYPE_SPARC::ALL), ByteOrder::BigEndian, "SPARC" },
    { "arm", CPU_TYPE::ARM, static_cast<uint32_t>(CPU_SUBTYPE_ARM::ALL), ByteOrder::LittleEndian, "ARM" },
    { "arm64", CPU_TYPE::ARM64, static_cast<uint32_t>(CPU_SUBTYPE_ARM64::ALL), ByteOrder::LittleEndian, "ARM64" },
    { "any", CPU_TYPE::ANY, static_cast<uint32_t>(CPU_SUBTYPE::MULTIPLE), ByteOrder::UnknownByteOrder, "Architecture Independent" },
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
    { "x86_64h", CPU_TYPE::I386, static_cast<uint32_t>(CPU_SUBTYPE_X86::_64_H), ByteOrder::LittleEndian, "Intel x86-64h Haswell" },
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

// TODO: mach o arch

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
} // namespace GView::Type::MachO::MAC

namespace GView::Type::MachO
{
namespace Panels
{
    enum class IDs : uint8_t
    {
        Information = 0,
        Objects     = 1
    };
};

class MachOFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    struct Colors
    {
        ColorPair header{ Color::Olive, Color::Transparent };
        ColorPair arch{ Color::Magenta, Color::Transparent };
        ColorPair objectName{ Color::DarkRed, Color::Transparent };
        ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

  public:
    Reference<GView::Utils::FileCache> file;
    MAC::mach_header header;
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

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Panels
} // namespace GView::Type::MachO
