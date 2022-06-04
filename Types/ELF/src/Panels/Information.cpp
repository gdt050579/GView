#include "elf.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::ELF::Panels
{
Information::Information(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf)
    : TabPage("Informa&tion"), object(_object), elf(_elf)
{
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);
    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    Update();
}

void Information::UpdateGeneralInformation()
{
    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });
    AddDecAndHexElement("Size", format.data(), elf->obj->GetData().GetSize());

    general->AddItem("Header").SetType(ListViewItem::Type::Category);
    UpdateHeader();
    UpdateGoInformation();
}

void Information::UpdateHeader()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    if (elf->is64)
    {
        const auto& header = elf->header64;

        const auto magic = *(uint32*) header.e_ident;
        AddDecAndHexElement("Magic", format, magic);

        const auto className = ELF::GetNameFromElfClass(header.e_ident[EI_CLASS]);
        const auto classHex  = nf.ToString(header.e_ident[EI_CLASS], hex);
        general->AddItem({ "Class", ls.Format(format.data(), className.data(), classHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto dataName = ELF::GetNameFromElfData(header.e_ident[EI_DATA]);
        const auto dataHex  = nf.ToString(header.e_ident[EI_DATA], hex);
        general->AddItem({ "Data", ls.Format(format.data(), dataName.data(), dataHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

        const auto versionName = ELF::GetNameFromElfVersion(header.e_ident[EI_VERSION]);
        const auto versionHex  = nf.ToString(header.e_ident[EI_VERSION], hex);
        general->AddItem({ "Version", ls.Format(format.data(), versionName.data(), versionHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto osAbiName = ELF::GetNameFromElfOsAbi(header.e_ident[EI_OSABI]);
        const auto osAbiHex  = nf.ToString(header.e_ident[EI_VERSION], hex);
        general->AddItem({ "OS ABI", ls.Format(format.data(), osAbiName.data(), osAbiHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto abiVersionName = ELF::GetNameFromElfAbiVersion(header.e_ident[EI_OSABI], header.e_ident[EI_ABIVERSION]);
        const auto abiVersionHex  = nf.ToString(header.e_ident[EI_ABIVERSION], hex);
        general->AddItem({ "ABI Version", ls.Format(format.data(), abiVersionName.data(), abiVersionHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto pad1 = *(uint32*) (header.e_ident + EI_PAD);
        AddDecAndHexElement("PAD1", format, pad1);
        const auto pad2 = (*(uint32*) (header.e_ident + EI_PAD + sizeof(pad1))) << 8;
        AddDecAndHexElement("PAD2", format, pad2);

        const auto typeName = ELF::GetNameAndDecriptionFromElfType(header.e_type);
        const auto typeHex  = nf.ToString(header.e_type, hex);
        general->AddItem({ "Type", ls.Format(formatDescription.data(), typeName.first.data(), typeHex.data(), typeName.second.data()) })
              .SetType(ListViewItem::Type::Emphasized_2);

        const auto machineName = ELF::GetNameFromElfMachine(header.e_machine);
        const auto machineHex  = nf.ToString(header.e_type, hex);
        general->AddItem({ "Machine", ls.Format(format.data(), machineName.data(), machineHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto versionHName = ELF::GetNameFromElfVersion(header.e_version);
        const auto versionHHex  = nf.ToString(header.e_version, hex);
        general->AddItem({ "Version", ls.Format(format.data(), versionHName.data(), versionHHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        AddDecAndHexElement("Entry Point", format, header.e_entry, ListViewItem::Type::Highlighted);
        AddDecAndHexElement("PHT File Offset", format, header.e_phoff);
        AddDecAndHexElement("SHT File Offset", format, header.e_shoff);
        AddDecAndHexElement("Processor Flags", format, header.e_flags);
        AddDecAndHexElement("ELF Header Size", format, header.e_ehsize);
        AddDecAndHexElement("PHT Entry Size", format, header.e_phentsize);
        AddDecAndHexElement("PHT # Entries", format, header.e_phnum);
        AddDecAndHexElement("SH Size", format, header.e_shentsize);
        AddDecAndHexElement("SHT # Entries", format, header.e_shnum);
        AddDecAndHexElement("SHT String Index", format, header.e_shstrndx);
    }
    else
    {
        const auto& header = elf->header32;

        const auto magic = *(uint32*) header.e_ident;
        AddDecAndHexElement("Magic", format, magic);

        const auto className = ELF::GetNameFromElfClass(header.e_ident[EI_CLASS]);
        const auto classHex  = nf.ToString(header.e_ident[EI_CLASS], hex);
        general->AddItem({ "Class", ls.Format(format.data(), className.data(), classHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto dataName = ELF::GetNameFromElfData(header.e_ident[EI_DATA]);
        const auto dataHex  = nf.ToString(header.e_ident[EI_DATA], hex);
        general->AddItem({ "Data", ls.Format(format.data(), dataName.data(), dataHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

        const auto versionName = ELF::GetNameFromElfVersion(header.e_ident[EI_VERSION]);
        const auto versionHex  = nf.ToString(header.e_ident[EI_VERSION], hex);
        general->AddItem({ "Version", ls.Format(format.data(), versionName.data(), versionHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto osAbiName = ELF::GetNameFromElfOsAbi(header.e_ident[EI_OSABI]);
        const auto osAbiHex  = nf.ToString(header.e_ident[EI_VERSION], hex);
        general->AddItem({ "OS ABI", ls.Format(format.data(), osAbiName.data(), osAbiHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto abiVersionName = ELF::GetNameFromElfAbiVersion(header.e_ident[EI_OSABI], header.e_ident[EI_ABIVERSION]);
        const auto abiVersionHex  = nf.ToString(header.e_ident[EI_ABIVERSION], hex);
        general->AddItem({ "ABI Version", ls.Format(format.data(), abiVersionName.data(), abiVersionHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto pad1 = *(uint32*) (header.e_ident + EI_PAD);
        AddDecAndHexElement("PAD1", format, pad1);
        const auto pad2 = (*(uint32*) (header.e_ident + EI_PAD + sizeof(pad1))) << 8;
        AddDecAndHexElement("PAD2", format, pad2);

        const auto typeName = ELF::GetNameAndDecriptionFromElfType(header.e_type);
        const auto typeHex  = nf.ToString(header.e_type, hex);
        general->AddItem({ "Type", ls.Format(formatDescription.data(), typeName.first.data(), typeHex.data(), typeName.second.data()) })
              .SetType(ListViewItem::Type::Emphasized_2);

        const auto machineName = ELF::GetNameFromElfMachine(header.e_machine);
        const auto machineHex  = nf.ToString(header.e_type, hex);
        general->AddItem({ "Machine", ls.Format(format.data(), machineName.data(), machineHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        const auto versionHName = ELF::GetNameFromElfVersion(header.e_version);
        const auto versionHHex  = nf.ToString(header.e_version, hex);
        general->AddItem({ "Version", ls.Format(format.data(), versionHName.data(), versionHHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);

        AddDecAndHexElement("Entry Point", format, header.e_entry, ListViewItem::Type::Highlighted);
        AddDecAndHexElement("PHT File Offset", format, header.e_phoff);
        AddDecAndHexElement("SHT File Offset", format, header.e_shoff);
        AddDecAndHexElement("Processor Flags", format, header.e_flags);
        AddDecAndHexElement("ELF Header Size", format, header.e_ehsize);
        AddDecAndHexElement("PHT Entry Size", format, header.e_phentsize);
        AddDecAndHexElement("PHT # Entries", format, header.e_phnum);
        AddDecAndHexElement("SH Size", format, header.e_shentsize);
        AddDecAndHexElement("SHT # Entries", format, header.e_shnum);
        AddDecAndHexElement("SHT String Index", format, header.e_shstrndx);
    }
}

void Information::UpdateGoInformation()
{
    CHECKRET(elf->goFunctionHeader != nullptr, "");
    general->AddItem("Go Information").SetType(ListViewItem::Type::Category);

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto magicName = ELF::Go::GetNameForGoMagic(elf->goFunctionHeader->magic);
    const auto magicHex  = nf.ToString((uint32) elf->goFunctionHeader->magic, hex);
    general->AddItem({ "Magic", ls.Format(format.data(), magicName.data(), magicHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Padding", format, elf->goFunctionHeader->padding);
    AddDecAndHexElement("Instruction Size Quantum", format, elf->goFunctionHeader->instructionSizeQuantum);
    AddDecAndHexElement("Size Of UIntPtr", format, elf->goFunctionHeader->sizeOfUintptr);
    AddDecAndHexElement("Size Of Function Symbol Table", format, elf->sizeOfFunctionSymbolTable);

    const auto entriesNo = elf->is64 ? elf->entries64.size() : elf->entries32.size();
    AddDecAndHexElement("# FST Entries", format, (uint32) entriesNo);

    general->AddItem("Go Note").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Name Size", format, elf->nameSize);
    AddDecAndHexElement("Value Size", format, elf->valSize);
    AddDecAndHexElement("Tag", format, elf->tag);
    general->AddItem({ "Note Name", ls.Format("%s", elf->noteName.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    general->AddItem({ "Build ID", ls.Format("%s", elf->buildId.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    general->AddItem({ "GNU String", ls.Format("%s", elf->gnuString.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
        return;

    issues->SetVisible(false);
    this->general->Resize(w, h);
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

void Information::OnAfterResize(int newWidth, int newHeight)
{
    RecomputePanelsPositions();
}
} // namespace GView::Type::ELF::Panels
