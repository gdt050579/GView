#pragma once

#include "Mac.hpp"
#include "NameMapping.hpp"
#include <array>
#include <cstring>

namespace MAC
{
template <typename T>
const T SwapEndian(T u)
{
    union
    {
        T object;
        unsigned char bytes[sizeof(T)];
    } source{ u }, dest{};

    for (auto i = 0; i < sizeof(T); i++)
    {
        dest.bytes[i] = source.bytes[sizeof(T) - i - 1];
    }

    return dest.object;
}

template <typename T>
void SwapEndianInplace(T* u, uint64_t size)
{
    for (auto i = 0ULL; i < size; i++)
    {
        u[i] = u[size - i - 1];
    }
}

template <typename T>
void SwapEndianInplace(T& var)
{
    static_assert(std::is_pod<T>::value, "Type must be POD type for safety");

    std::array<uint8, sizeof(T)> bytes;
    std::memcpy(bytes.data(), &var, sizeof(T));
    for (uint32 i = 0; i < static_cast<uint32>(sizeof(var) / 2); i++)
    {
        std::swap(bytes[sizeof(var) - 1 - i], bytes[i]);
    }
    std::memcpy(&var, bytes.data(), sizeof(T));
}

template <typename T>
static const std::string BinaryToHexString(const T number, const size_t length)
{

    std::string output;
    output.reserve(length * 3);

    const auto input = reinterpret_cast<const uint8_t*>(&number);
    std::for_each(
          input,
          input + length,
          [&output](uint8_t byte)
          {
              constexpr const char digits[] = "0123456789ABCDEF";
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

static const std::string GetVMProtectionNamesFromFlags(uint32_t flags)
{
    static const std::initializer_list<VMProtectionFlags> types{ VMProtectionFlags::NONE,      VMProtectionFlags::READ,
                                                                 VMProtectionFlags::WRITE,     VMProtectionFlags::EXECUTE,
                                                                 VMProtectionFlags::DEFAULT,   VMProtectionFlags::ALL,
                                                                 VMProtectionFlags::NO_CHANGE, VMProtectionFlags::COPY,
                                                                 VMProtectionFlags::WANTS_COPY };

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

static const std::string GetSegmentCommandNamesFromFlags(uint32_t flags)
{
    static const std::initializer_list<SegmentCommandFlags> types{ SegmentCommandFlags::NONE,
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

static const std::string GetSectionTypeAndAttributesFromFlags(uint32_t flags)
{
    const std::string sectionType{ SectionTypeNames.at(static_cast<SectionType>(flags & SECTION_TYPE)) };

    static const std::initializer_list<SectionAttributtes> types{ SectionAttributtes::USR,
                                                                  SectionAttributtes::PURE_INSTRUCTIONS,
                                                                  SectionAttributtes::NO_TOC,
                                                                  SectionAttributtes::STRIP_STATIC_SYMS,
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

static const std::vector<CodeSignFlags> GetCodeSignFlagsData(uint32_t flags)
{
    std::vector<CodeSignFlags> output;

    const auto hasAllowedMacho =
          static_cast<CodeSignFlags>(static_cast<decltype(flags)>(CodeSignFlags::ALLOWED_MACHO) & flags) == CodeSignFlags::ALLOWED_MACHO;
    const auto hasEntitlement = static_cast<CodeSignFlags>(static_cast<decltype(flags)>(CodeSignFlags::ENTITLEMENT_FLAGS) & flags) ==
                                CodeSignFlags::ENTITLEMENT_FLAGS;

    for (const auto& [k, _] : CodeSignFlagNames)
    {
        if (hasAllowedMacho)
        {
            if (k == CodeSignFlags::ADHOC || k == CodeSignFlags::HARD || k == CodeSignFlags::KILL || k == CodeSignFlags::CHECK_EXPIRATION ||
                k == CodeSignFlags::RESTRICT || k == CodeSignFlags::ENFORCEMENT || k == CodeSignFlags::REQUIRE_LV ||
                k == CodeSignFlags::RUNTIME || k == CodeSignFlags::LINKER_SIGNED)
            {
                continue;
            }
        }

        if (hasEntitlement)
        {
            if (k == CodeSignFlags::GET_TASK_ALLOW || k == CodeSignFlags::INSTALLER || k == CodeSignFlags::DATAVAULT_CONTROLLER ||
                k == CodeSignFlags::NVRAM_UNRESTRICTED)
            {
                continue;
            }
        }

        const auto flag = static_cast<CodeSignFlags>(static_cast<decltype(flags)>(k) & flags);
        if (flag == k)
        {
            output.emplace_back(flag);
        }
    }

    return output;
}

static const std::vector<CodeSignExecSegFlags> GetCodeSignExecSegFlagsData(uint64_t flags)
{
    std::vector<CodeSignExecSegFlags> output;

    for (const auto& [k, _] : CodeSignExecSegFlagNames)
    {
        const auto flag = static_cast<CodeSignExecSegFlags>(static_cast<decltype(flags)>(k) & flags);
        if (flag == k)
        {
            output.emplace_back(flag);
        }
    }

    return output;
}

static inline const CS_CodeDirectory* FindCodeDirectory(const CS_SuperBlob* embedded)
{
    CHECK(embedded != nullptr, nullptr, "");
    CHECK(static_cast<CodeSignMagic>(embedded->magic) /* TODO: endianess? */ == CodeSignMagic::CSMAGIC_EMBEDDED_SIGNATURE, nullptr, "");

    // const CS_BlobIndex* limit = &embedded->index[embedded->count /* TODO: endianess? */];
    // for (const CS_BlobIndex* blob = embedded->index; blob < limit; ++blob)
    //{
    //     if (/* TODO: endianess? */ static_cast<CodeSignMagic>(blob->type) == CodeSignMagic::CSMAGIC_CODEDIRECTORY)
    //     {
    //         auto base = (const unsigned char*) embedded;
    //         auto cd   = (const CS_CodeDirectory*) (base + /* TODO: endianess? */ blob->offset);
    //         if (/* TODO: endianess? */ static_cast<CodeSignMagic>(cd->magic) == CodeSignMagic::CSMAGIC_CODEDIRECTORY)
    //         {
    //             return cd;
    //         }
    //         break;
    //     }
    // }

    // not found
    return nullptr;
}

static bool ValidateSlot(const void* data, size_t length, size_t slot, const CS_CodeDirectory* codeDirectory)
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH + 1] = {
        0,
    };
    // CC_SHA1(data, (CC_LONG) length, digest);
    // return (memcmp(digest, (void*) ((char*) codeDirectory + ntohl(codeDirectory->hashOffset) + 20 * slot), 20) == 0);

    return true;
}
} // namespace MAC
