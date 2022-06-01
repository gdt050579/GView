#pragma once

#include "elf_types.hpp"

namespace GView::Type::ELF
{
static std::string_view GetNameFromElfClass(unsigned char elfClass)
{
    switch (elfClass)
    {
    case ELFCLASSNONE:
        return "INVALID";
    case ELFCLASS32:
        return "32";
    case ELFCLASS64:
        return "64";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfData(unsigned char elfData)
{
    switch (elfData)
    {
    case ELFDATANONE:
        return "INVALID";
    case ELFDATA2LSB:
        return "2LSB";
    case ELFDATA2MSB:
        return "2MSB";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfVersion(unsigned char elfVersion)
{
    switch (elfVersion)
    {
    case EV_NONE:
        return "INVALID";
    case EV_CURRENT:
        return "CURRENT";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfOsAbi(unsigned char elfOsAbi)
{
    switch (elfOsAbi)
    {
    case ELFOSABI_NONE:
        return "NONE";
    case ELFOSABI_HPUX:
        return "Hewlett-Packard HP-UX";
    case ELFOSABI_NETBSD:
        return "NetBSD";
    case ELFOSABI_LINUX:
        return "Linux";
    case ELFOSABI_SOLARIS:
        return "Sun Solaris";
    case ELFOSABI_AIX:
        return "AIX";
    case ELFOSABI_IRIX:
        return "IRIX";
    case ELFOSABI_FREEBSD:
        return "FreeBSD";
    case ELFOSABI_TRU64:
        return "Compaq TRU64 UNIX";
    case ELFOSABI_MODESTO:
        return "Novell Modesto";
    case ELFOSABI_OPENBSD:
        return "Open BSD";
    case ELFOSABI_OPENVMS:
        return "Open VMS";
    case ELFOSABI_NSK:
        return "Hewlett-Packard Non-Stop Kernel";
    case ELFOSABI_AROS:
        return "Amiga Research OS";
    case ELFOSABI_FENIXOS:
        return "The FenixOS highly scalable multi-core OS";
    case ELFOSABI_AMDGPU_HSA:
        return "AMDGPU OS for HSA compatible compute kernels";
    case ELFOSABI_AMDGPU_PAL:
        return "AMDGPU OS for AMD PAL compatible graphics";
    case ELFOSABI_AMDGPU_MESA3D:
        return "AMDGPU OS for Mesa3D compatible graphics";
    default:
        return "UNKNOWN";
    }
}

static std::string_view GetNameFromElfAbiVersion(unsigned char elfOsAbi, unsigned char elfAbiVersion)
{
    switch (elfOsAbi)
    {
    case ELFOSABI_AMDGPU_HSA:
        switch (elfAbiVersion)
        {
        case ELFABIVERSION_AMDGPU_HSA_V2:
            return "AMDGPU OS for HSA v2 compatible compute kernels";
        case ELFABIVERSION_AMDGPU_HSA_V3:
            return "AMDGPU OS for HSA v3 compatible compute kernels";
        case ELFABIVERSION_AMDGPU_HSA_V4:
            return "AMDGPU OS for HSA v5 compatible compute kernels";
        default:
            return "UNKNOWN";
        }
    default:
        return "UNKNOWN";
    }
}
} // namespace GView::Type::ELF
