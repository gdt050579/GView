#include "elf.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::ELF::Panels
{
GoInformation::GoInformation(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf)
    : TabPage("GoInfo&rmation"), object(_object), elf(_elf)
{
    list = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void GoInformation::UpdateGoInformation()
{
    CHECKRET(elf->pclntab112.header != nullptr, "");
    list->AddItem("Info").SetType(ListViewItem::Type::Category);

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto magicName = ELF::Go::GetNameForGoMagic(elf->pclntab112.header->magic);
    const auto magicHex  = nf.ToString((uint32) elf->pclntab112.header->magic, hex);
    list->AddItem({ "Magic", ls.Format(format.data(), magicName.data(), magicHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Padding", format, elf->pclntab112.header->padding);
    AddDecAndHexElement("Instruction Size Quantum", format, elf->pclntab112.header->instructionSizeQuantum);
    AddDecAndHexElement("Size Of UIntPtr", format, elf->pclntab112.header->sizeOfUintptr);

    const auto entriesNo = elf->is64 ? elf->entries64.size() : elf->entries32.size();
    AddDecAndHexElement("# FST Entries", format, (uint32) entriesNo);

    list->AddItem("Note").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Name Size", format, elf->nameSize);
    AddDecAndHexElement("Value Size", format, elf->valSize);
    AddDecAndHexElement("Tag", format, elf->tag);
    list->AddItem({ "Note Name", ls.Format("%s", elf->noteName.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    list->AddItem({ "Build ID", ls.Format("%s", elf->buildId.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    list->AddItem({ "GNU String", ls.Format("%s", elf->gnuString.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
}

void GoInformation::Update()
{
    list->DeleteAllItems();

    UpdateGoInformation();
}

void GoInformation::OnAfterResize(int newWidth, int newHeight)
{
    auto h1 = std::max(8, ((newHeight - 4) * 6) / 10);
    if (list.IsValid())
    {
        list->Resize(newWidth, h1);
    };
}
} // namespace GView::Type::ELF::Panels
