#include "pe.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::PE::Panels
{
GoInformation::GoInformation(Reference<Object> _object, Reference<PEFile> _pe) : TabPage("GoInfo&rmation"), object(_object), pe(_pe)
{
    list = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void GoInformation::UpdateGoInformation()
{
    const auto goHeader = pe->pclntab112.GetHeader();
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

    const auto entriesNo = pe->pclntab112.GetEntriesCount();
    AddDecAndHexElement("# FST Entries", format, (uint32) entriesNo);

    list->AddItem("Note").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Name Size", format, pe->nameSize);
    AddDecAndHexElement("Value Size", format, pe->valSize);
    AddDecAndHexElement("Tag", format, pe->tag);

    if (pe->noteName.empty() == false)
        list->AddItem({ "Note Name", ls.Format("%s", pe->noteName.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem({ "Build ID", ls.Format("%s", pe->pclntab112.GetBuildId().c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    list->AddItem({ "Runtime Build Version", ls.Format("%s", pe->pclntab112.GetRuntimeBuildVersion().c_str()) })
          .SetType(ListViewItem::Type::Emphasized_1);
    list->AddItem({ "Runtime Build Mod Info", ls.Format("%s", pe->pclntab112.GetRuntimeBuildModInfo().c_str()) })
          .SetType(ListViewItem::Type::Emphasized_1);
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
} // namespace GView::Type::PE::Panels
