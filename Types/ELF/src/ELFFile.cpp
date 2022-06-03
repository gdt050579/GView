#include "elf.hpp"

using namespace GView::Type::ELF;

ELFFile::ELFFile()
{
}

bool ELFFile::Update()
{
    uint64 offset = 0;
    CHECK(obj->GetData().Copy<Elf32_Ehdr>(offset, header32), false, "");
    if (header32.e_ident[EI_CLASS] != ELFCLASS32)
    {
        CHECK(header32.e_ident[EI_CLASS] == ELFCLASS64, false, "");
        CHECK(obj->GetData().Copy<Elf64_Ehdr>(offset, header64), false, "");
        is64 = true;
        offset += sizeof(Elf64_Ehdr);
    }
    else
    {
        offset += sizeof(Elf32_Ehdr);
    }

    if (is64)
    {
        offset = header64.e_phoff;
        for (auto i = 0; i < header64.e_phnum; i++)
        {
            Elf64_Phdr entry{};
            CHECK(obj->GetData().Copy<Elf64_Phdr>(offset, entry), false, "");
            segments64.emplace_back(entry);
            offset += sizeof(entry);
        }
    }
    else
    {
        offset = header32.e_phoff;
        for (auto i = 0; i < header32.e_phnum; i++)
        {
            Elf32_Phdr entry{};
            CHECK(obj->GetData().Copy<Elf32_Phdr>(offset, entry), false, "");
            segments32.emplace_back(entry);
            offset += sizeof(entry);
        }
    }

    if (is64)
    {
        offset = header64.e_shoff;
        for (auto i = 0; i < header64.e_shnum; i++)
        {
            auto& entry = sections64.emplace_back(Elf64_Shdr{});
            CHECK(obj->GetData().Copy<Elf64_Shdr>(offset, entry), false, "");
            offset += sizeof(entry);

            auto& segmentIdx = sectionsToSegments.emplace_back(-1);
            for (auto i = 0; i < segments64.size(); i++)
            {
                const auto& segment = segments64.at(i);
                if (segment.p_vaddr != 0 && entry.sh_addr >= segment.p_vaddr &&
                    entry.sh_addr + entry.sh_size <= segment.p_vaddr + segment.p_filesz)
                {
                    segmentIdx = i;
                    break;
                }
            }
        }

        sectionNames.reserve(header64.e_shnum);

        if (header64.e_shstrndx != SHN_UNDEF && header64.e_shstrndx < SHN_LORESERVE)
        {
            const auto& shstrtab = sections64.at(header64.e_shstrndx);
            auto buffer          = obj->GetData().CopyToBuffer(shstrtab.sh_offset, (uint32) shstrtab.sh_size);
            if (buffer.IsValid())
            {
                for (const auto& section : sections64)
                {
                    const auto name = (char*) (buffer.GetData() + section.sh_name);
                    sectionNames.emplace_back(name);
                }
            }
        }
        else if (header64.e_shstrndx >= SHN_LORESERVE)
        {
            // TODO:
        }
    }
    else
    {
        offset = header32.e_shoff;
        for (auto i = 0; i < header32.e_shnum; i++)
        {
            auto& entry = sections32.emplace_back(Elf32_Shdr{});
            CHECK(obj->GetData().Copy<Elf32_Shdr>(offset, entry), false, "");
            offset += sizeof(entry);

            auto& segmentIdx = sectionsToSegments.emplace_back(-1);
            for (auto i = 0; i < segments32.size(); i++)
            {
                const auto& segment = segments32.at(i);
                if (segment.p_vaddr != 0 && entry.sh_addr >= segment.p_vaddr &&
                    entry.sh_addr + entry.sh_size <= segment.p_vaddr + segment.p_filesz)
                {
                    segmentIdx = i;
                    break;
                }
            }
        }

        sectionNames.reserve(header32.e_shnum);

        if (header32.e_shstrndx != SHN_UNDEF && header32.e_shstrndx < SHN_LORESERVE)
        {
            const auto& shstrtab = sections32.at(header32.e_shstrndx);
            auto buffer          = obj->GetData().CopyToBuffer(shstrtab.sh_offset, shstrtab.sh_size);
            if (buffer.IsValid())
            {
                for (const auto& section : sections32)
                {
                    const auto name = (char*) (buffer.GetData() + section.sh_name);
                    sectionNames.emplace_back(name);
                }
            }
        }
        else if (header32.e_shstrndx >= SHN_LORESERVE)
        {
            // TODO:
        }
    }

    return true;
}
