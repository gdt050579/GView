#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

Information::Information(Reference<MachOFile> _machO) : TabPage("Informa&Tion")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void Information::UpdateGeneralInformation()
{
    ItemHandle item;
    LocalString<256> tmp;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("MachO Info");
    general->SetItemType(item, ListViewItemType::Category);
    general->AddItem("File");
    general->AddItem("Size", tmp.Format("%s bytes", n.ToString(machO->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()));
    general->AddItem("Architecture", machO->is64 ? "x64" : "x86");

    const char* fmt = "%u (0x%X)";
    general->AddItem("Magic", tmp.Format(fmt, machO->header.magic, machO->header.magic));
    general->AddItem("CPU Type", tmp.Format(fmt, machO->header.cputype, machO->header.cputype));
    general->AddItem("CPU Subtype", tmp.Format(fmt, machO->header.cpusubtype, machO->header.cpusubtype));
    general->AddItem("File Type", tmp.Format(fmt, machO->header.filetype, machO->header.filetype));
    general->AddItem("Load Commands", tmp.Format(fmt, machO->header.ncmds, machO->header.ncmds));
    general->AddItem(
          "Size of Commands",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->header.sizeofcmds, { NumericFormatFlags::None, 10, 3, ',' }).data(),
                n.ToString(machO->header.sizeofcmds, { NumericFormatFlags::HexPrefix, 10, 3, ',' }).data()));
    general->AddItem("Flags", tmp.Format(fmt, machO->header.flags, machO->header.flags));
    if (machO->is64)
    {
        general->AddItem("Reserved", tmp.Format(fmt, machO->header.reserved, machO->header.reserved));
    }
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    if (general->GetItemsCount() > 15)
    {
        general->Resize(GetWidth(), 18);
    }
    else
    {
        general->Resize(GetWidth(), general->GetItemsCount() + 3);
    }
}

void Information::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
