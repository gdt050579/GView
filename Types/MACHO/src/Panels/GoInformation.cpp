#include "MachO.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::MachO::Panels
{
GoInformation::GoInformation(Reference<Object> _object, Reference<GView::Type::MachO::MachOFile> _macho)
    : TabPage("GoInfo&rmation"), object(_object), macho(_macho)
{
    list = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void GoInformation::UpdateGoInformation()
{
    const auto goHeader = macho->pcLnTab.GetHeader();
    CHECKRET(goHeader != nullptr, "");
    list->AddItem("Info").SetType(ListViewItem::Type::Category);

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto magicName = Golang::GetNameForGoMagic(goHeader->magic);
    const auto magicHex  = nf.ToString((uint32) goHeader->magic, hex);
    list->AddItem({ "Magic", ls.Format(format.data(), magicName, magicHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Padding", format, goHeader->padding);
    AddDecAndHexElement("Instruction Size Quantum", format, goHeader->instructionSizeQuantum);
    AddDecAndHexElement("Size Of UIntPtr", format, goHeader->sizeOfUintptr);

    const auto entriesNo = macho->pcLnTab.GetEntriesCount();
    AddDecAndHexElement("# FST Entries", format, (uint32) entriesNo);

    list->AddItem("Note").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Name Size", format, macho->nameSize);
    AddDecAndHexElement("Value Size", format, macho->valSize);
    AddDecAndHexElement("Tag", format, macho->tag);

    if (macho->pcLnTab.GetBuildId().empty() == false)
        list->AddItem({ "Build ID", ls.Format("%s", macho->pcLnTab.GetBuildId().c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
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
} // namespace GView::Type::MachO::Panels
