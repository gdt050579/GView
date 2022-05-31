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
        CHECK(obj->GetData().Copy<Elf64_Phdr>(offset, program64), false, "");
        offset += sizeof(Elf64_Phdr);
    }
    else
    {
        CHECK(obj->GetData().Copy<Elf32_Phdr>(offset, program32), false, "");
        offset += sizeof(Elf32_Phdr);
    }

    return true;
}
