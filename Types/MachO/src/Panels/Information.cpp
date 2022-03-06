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
    general->AddItem("File", "NOT IMPLEMENTED");
    general->AddItem(
          "Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data(),
                std::string(n.ToString(machO->file->GetSize(), { NumericFormatFlags::HexPrefix, 16 }).data()).c_str()));

    const auto& info = MAC::GetArchInfoFromCPUTypeAndSubtype(machO->header.cputype, machO->header.cpusubtype);

    general->AddItem("Byte Order", MAC::ByteOrderNames.at(info.byteorder));
    general->AddItem("Magic", tmp.Format("%s (0x%X)", machO->is64 ? "MH_MAGIC_64" : "MH_MAGIC", machO->header.magic));
    general->AddItem("CPU Type", tmp.Format("%.*s (0x%X)", info.name.size(), info.name.data(), machO->header.cputype));
    general->AddItem("CPU Subtype", tmp.Format("%.*s (0x%X)", info.description.size(), info.description.data(), machO->header.cpusubtype));
    const auto& fileTypeName = MAC::FileTypeNames.at(machO->header.filetype);
    general->AddItem("File Type", tmp.Format("%.*s (0x%X)", fileTypeName.size(), fileTypeName.data(), machO->header.filetype));
    general->AddItem("Load Commands", tmp.Format("%u (0x%X)", machO->header.ncmds, machO->header.ncmds));
    general->AddItem(
          "Size of Commands",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->header.sizeofcmds, { NumericFormatFlags::HexPrefix, 10, 3, ',' }).data(),
                std::string(n.ToString(machO->header.sizeofcmds, { NumericFormatFlags::HexPrefix, 16 }).data()).c_str()));
    general->AddItem("Flags", tmp.Format("%u (0x%X)", machO->header.flags, machO->header.flags));

    const auto flags = MAC::GetMachHeaderFlagsData(machO->header.flags);
    for (const auto& flag : flags)
    {
        general->AddItem(
              "",
              tmp.Format(
                    "%s (0x%X) %s", MAC::MachHeaderFlagsNames.at(flag).data(), flag, MAC::MachHeaderFlagsDescriptions.at(flag).data()));
    }

    if (machO->is64)
    {
        general->AddItem("Reserved", tmp.Format("%u (0x%X)", machO->header.reserved, machO->header.reserved));
    }
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

void Information::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
