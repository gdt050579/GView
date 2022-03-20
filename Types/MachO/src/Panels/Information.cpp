#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

Information::Information(Reference<MachOFile> _machO) : TabPage("Informa&Tion")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Key", TextAlignament::Left, 16);
    general->AddColumn("Value", TextAlignament::Left, 48);

    Update();
}

void Information::UpdateBasicInfo()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->SetItemType(general->AddItem("Basic Info"), ListViewItemType::Category);

    general->AddItem("File", "NOT IMPLEMENTED");

    const auto fileSize    = nf.ToString(machO->file->GetSize(), dec);
    const auto hexfileSize = nf2.ToString(machO->file->GetSize(), hex);
    general->AddItem("Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()));

    const auto& info = MAC::GetArchInfoFromCPUTypeAndSubtype(machO->header.cputype, machO->header.cpusubtype);

    general->AddItem("Byte Order", MAC::ByteOrderNames.at(info.byteorder));

    general->AddItem("Magic", ls.Format("%-14s (0x%X)", machO->is64 ? "MH_MAGIC_64" : "MH_MAGIC", machO->header.magic));

    general->AddItem("CPU Type", ls.Format("%-14s (0x%X)", info.name.c_str(), machO->header.cputype));

    general->AddItem("CPU Subtype", ls.Format("%-14s (0x%X)", info.description.c_str(), machO->header.cpusubtype));

    const auto& fileTypeName = MAC::FileTypeNames.at(machO->header.filetype);
    auto ftHandle            = general->AddItem("File Type", ls.Format("%-14s (0x%X)", fileTypeName.data(), machO->header.filetype));
    general->SetItemType(ftHandle, ListViewItemType::Emphasized_1);

    general->AddItem("Load Commands", ls.Format("%-14s (0x%X)", nf.ToString(machO->header.ncmds, dec).data(), machO->header.ncmds));

    const auto sizeOfCommands = nf.ToString(machO->header.sizeofcmds, dec);
    const auto sizeOfHex      = nf2.ToString(machO->header.sizeofcmds, hex);
    general->AddItem("Size of Commands", ls.Format("%-14s (%s)", sizeOfCommands.data(), sizeOfHex.data()));

    general->AddItem("Flags", ls.Format("%-14s (0x%X)", nf.ToString(machO->header.flags, dec).data(), machO->header.flags));

    const auto flags = MAC::GetMachHeaderFlagsData(machO->header.flags);
    for (const auto& flag : flags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = MAC::MachHeaderFlagsNames.at(flag).data();
        const auto flagDescription = MAC::MachHeaderFlagsDescriptions.at(flag).data();

        const auto fh = general->AddItem("", ls.Format("%-14s %-12s %s", flagName, hfls.GetText(), flagDescription));
        general->SetItemType(fh, ListViewItemType::Emphasized_2);
    }

    if (machO->is64)
    {
        general->AddItem("Reserved", ls.Format("%-14s (0x%X)", nf.ToString(machO->header.reserved, dec).data(), machO->header.reserved));
    }
}

void Information::UpdateEntryPoint()
{
    CHECKRET(machO->main.isSet, "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->SetItemType(general->AddItem("Entry Point"), ListViewItemType::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->main.ep.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->main.ep.cmd), hex);
    general->AddItem("Command", ls.Format("%-14s (%s)", lcName.data(), hexCommand.data()));

    const auto cmdSize    = nf.ToString(machO->main.ep.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(static_cast<uint32_t>(machO->main.ep.cmdsize), hex);
    general->AddItem("Cmd Size", ls.Format("%-14s (%s)", cmdSize.data(), hexCmdSize.data()));

    const auto epOffset    = nf.ToString(machO->main.ep.entryoff, dec);
    const auto epOffsetHex = nf2.ToString(machO->main.ep.entryoff, hex);
    general->AddItem("EP offset", ls.Format("%-14s (%s)", epOffset.data(), epOffsetHex.data()));

    const auto stackSize    = nf.ToString(machO->main.ep.stacksize, dec);
    const auto stackSizeHex = nf2.ToString(machO->main.ep.stacksize, hex);
    general->AddItem("Stack Size", ls.Format("%-14s (%s)", stackSize.data(), stackSizeHex.data()));
}

void Information::UpdateSourceVersion()
{
    CHECKRET(machO->sourceVersion.isSet, "");

    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->SetItemType(general->AddItem("Source Version"), ListViewItemType::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->sourceVersion.svc.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->sourceVersion.svc.cmd), hex);
    general->AddItem("Command", ls.Format("%-22s (%s)", lcName.data(), hexCommand.data()));

    const auto cmdSize    = nf.ToString(machO->sourceVersion.svc.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(static_cast<uint32_t>(machO->sourceVersion.svc.cmdsize), hex);
    general->AddItem("Cmd Size", ls.Format("%-22s (%s)", cmdSize.data(), hexCmdSize.data()));

    const auto a          = (machO->sourceVersion.svc.version >> 40) & 0xffffff;
    const auto b          = (machO->sourceVersion.svc.version >> 30) & 0x3ff;
    const auto c          = (machO->sourceVersion.svc.version >> 20) & 0x3ff;
    const auto d          = (machO->sourceVersion.svc.version >> 10) & 0x3ff;
    const auto e          = machO->sourceVersion.svc.version & 0x3ff;
    const auto version    = ls.Format("%llu.%llu.%llu.%llu.%llu", a, b, c, d, e);
    const auto versionHex = nf2.ToString(machO->sourceVersion.svc.version, hex);
    general->AddItem("Version", ls.Format("%-22s (%s)", version.data(), versionHex.data()));
}

void Information::UpdateUUID()
{
    CHECKRET(machO->uuid.isSet, "");

    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->SetItemType(general->AddItem("UUID"), ListViewItemType::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->uuid.value.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->uuid.value.cmd), hex);
    general->AddItem("Command", ls.Format("%-35s (%s)", lcName.data(), hexCommand.data()));

    const auto cmdSize    = nf.ToString(machO->uuid.value.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(static_cast<uint32_t>(machO->uuid.value.cmdsize), hex);
    general->AddItem("Cmd Size", ls.Format("%-35s (%s)", cmdSize.data(), hexCmdSize.data()));

    const auto& uuid         = machO->uuid.value.uuid;
    const auto uuidFormmated = ls.Format(
          "%.2x%.2x%.2x%.2x-%.2x%.2x%.2x%.2x-%.2x%.2x%.2x%.2x-%.2x%.2x%.2x%.2x",
          uuid[0],
          uuid[1],
          uuid[2],
          uuid[3],
          uuid[4],
          uuid[5],
          uuid[6],
          uuid[7],
          uuid[8],
          uuid[9],
          uuid[10],
          uuid[11],
          uuid[12],
          uuid[13],
          uuid[14],
          uuid[15]);
    const auto uuidHex = ls2.Format(
          "0x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
          uuid[0],
          uuid[1],
          uuid[2],
          uuid[3],
          uuid[4],
          uuid[5],
          uuid[6],
          uuid[7],
          uuid[8],
          uuid[9],
          uuid[10],
          uuid[11],
          uuid[12],
          uuid[13],
          uuid[14],
          uuid[15]);
    general->AddItem("UUID", ls.Format("%-35s (%s)", uuidFormmated.data(), uuidHex.data()));
}

void Information::UpdateVersionMin()
{
    CHECKRET(machO->versionMinCommand.isSet, "");

    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->SetItemType(general->AddItem("Version Min"), ListViewItemType::Category);

    const auto& lcName    = MAC::LoadCommandNames.at(machO->versionMinCommand.vmc.cmd);
    const auto hexCommand = nf.ToString(static_cast<uint32_t>(machO->versionMinCommand.vmc.cmd), hex);
    general->AddItem("Command", ls.Format("%-22s (%s)", lcName.data(), hexCommand.data()));

    const auto cmdSize    = nf.ToString(machO->versionMinCommand.vmc.cmdsize, dec);
    const auto hexCmdSize = nf2.ToString(static_cast<uint32_t>(machO->versionMinCommand.vmc.cmdsize), hex);
    general->AddItem("Cmd Size", ls.Format("%-22s (%s)", cmdSize.data(), hexCmdSize.data()));

    const auto version = ls.Format(
          "%u.%u.%u",
          machO->versionMinCommand.vmc.version >> 16,
          (machO->versionMinCommand.vmc.version >> 8) & 0xff,
          machO->versionMinCommand.vmc.version & 0xff);
    const auto versionHex = nf2.ToString(machO->versionMinCommand.vmc.version, hex);
    general->AddItem("Version", ls.Format("%-22s (%s)", version.data(), versionHex.data()));

    const auto sdk = ls.Format(
          "%u.%u.%u",
          machO->versionMinCommand.vmc.sdk >> 16,
          (machO->versionMinCommand.vmc.sdk >> 8) & 0xff,
          machO->versionMinCommand.vmc.sdk & 0xff);
    const auto sdkHex = nf2.ToString(machO->versionMinCommand.vmc.sdk, hex);
    general->AddItem("SDK", ls.Format("%-22s (%s)", sdk.data(), sdkHex.data()));
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateBasicInfo();
    UpdateEntryPoint();
    UpdateSourceVersion();
    UpdateUUID();
    UpdateVersionMin();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
