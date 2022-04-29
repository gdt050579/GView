#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Panels::LinkTargetIDList::LinkTargetIDList(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk)
    : TabPage("&LinkTargetIDList")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void Panels::LinkTargetIDList::UpdateGeneralInformation()
{
    general->AddItem("Info").SetType(ListViewItem::Type::Category);
    UpdateLinkTargetIDList();
}

void Panels::LinkTargetIDList::UpdateRootFolderShellItem(RootFolderShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);

    const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at(item.indicator);
    const auto indicatorHex   = nf.ToString((uint8) item.indicator, hex);
    general->AddItem({ "Class Type Indicator", ls.Format("%-20s (%s)", indicatorName.data(), indicatorHex.data()) });

    const auto& sortIndexName = LNK::SortIndexNames.at(item.sortIndex);
    const auto sortIndexHex   = nf.ToString((uint8) item.sortIndex, hex);
    general->AddItem({ "Sort Index", ls.Format("%-20s (%s)", sortIndexName.data(), sortIndexHex.data()) });

    AddGUIDElement("Shell Folder Identifier", item.shellFolderIdentifier);
}

void Panels::LinkTargetIDList::UpdateExtensionBlock0xBEEF0017(ExtensionBlock0xBEEF0017& block)
{
    AddDecAndHexElement("Block Size", "%-20s (%s)", block.size);
    AddDecAndHexElement("Block Version", "%-20s (%s)", block.version);
    AddDecAndHexElement("Block Signature", "%-20s (%s)", block.signature);
    AddDecAndHexElement("Block Unknown0", "%-20s (%s)", block.unknown0);
    AddDecAndHexElement("Block Unknown1", "%-20s (%s)", block.unknown1);
    AddDecAndHexElement("Block Unknown2", "%-20s (%s)", block.unknown2);
    AddDecAndHexElement("Block Unknown3", "%-20s (%s)", block.unknown3);
    AddDecAndHexElement("Block Unknown4", "%-20s (%s)", block.unknown4);
    AddDecAndHexElement("Block Unknown5", "%-20s (%s)", block.unknown5);
    AddDecAndHexElement("Block Unknown6", "%-20s (%s)", block.unknown6);
    AddDecAndHexElement("Block Unknown7", "%-20s (%s)", block.unknown7);
    AddDecAndHexElement("Block Unknown8", "%-20s (%s)", block.unknown8);
    AddDecAndHexElement("Block Unknown9", "%-20s (%s)", block.unknown9);
    AddDecAndHexElement("Block Unknown10", "%-20s (%s)", block.unknown10);

    LocalString<1024> ls;
    NumericFormatter nf;
    DateTime dt;
    dt.CreateFromFATUTC(block.unknown11);
    const auto unknown11Hex = nf.ToString(block.unknown11, hex);
    general->AddItem({ "Date And Time", ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), unknown11Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Block Unknown12", "%-20s (%s)", block.unknown12);
    AddDecAndHexElement("Block Unknown13", "%-20s (%s)", block.unknown13);
    AddDecAndHexElement("Block Unknown14", "%-20s (%s)", block.unknown14);
    AddDecAndHexElement("Block VersionOffset ", "%-20s (%s)", block.blockVersionOffset);
}

void Panels::LinkTargetIDList::UpdateVolumeShellItem(VolumeShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) (item.indicator & 0x70));
    LocalString<16> hfls;

    hfls.Format("(0x%X)", (item.indicator & 0x70));
    general->AddItem({ "", ls.Format("%-20s %-4s", indicatorName.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    const auto vsiFlags = LNK::GetVolumeShellItemFlags(item.indicator & 0x0F);
    for (const auto& flag : vsiFlags)
    {
        hfls.Format("(0x%X)", flag);
        const auto flagName = LNK::VolumeShellItemFlagsNames.at(flag).data();
        general->AddItem({ "", ls.Format("%-20s %-4s", flagName, hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);
    }

    if ((item.indicator & 0x0F) & (uint8) VolumeShellItemFlags::HasName)
    {
        general->AddItem({ "Path", ls.Format("%s", (char8*) &item.unknownFlags, hfls.GetText()) });
    }
    else
    {
        AddDecAndHexElement("Unknown Flags", "%-20s (%s)", item.unknownFlags);
    }
}

void Panels::LinkTargetIDList::UpdateLinkTargetIDList()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    AddDecAndHexElement("ID List Size", "%-20s (%s)", lnk->linkTargetIDList.IDListSize);
    AddDecAndHexElement("ItemIDs #", "%-20s (%s)", lnk->itemIDS.size());

    for (const auto& id : lnk->itemIDS)
    {
        const auto& item     = id->item;
        const auto& type     = item.type;
        const auto indicator = (ClassTypeIndicators) (type > (uint8) ClassTypeIndicators::CLSID_ShellDesktop ? (type & 0x70) : type);

        switch (indicator)
        {
        case ClassTypeIndicators::CLSID_ShellDesktop:
        {
            if (id->ItemIDSize > 20)
            {
                general->AddItem("RootFolderShellItemWithExtensionBlock0xBEEF0017").SetType(ListViewItem::Type::Category);
                const auto rfsi = (RootFolderShellItemWithExtensionBlock0xBEEF0017*) id;
                UpdateRootFolderShellItem(rfsi->item);
                UpdateExtensionBlock0xBEEF0017(rfsi->block);
            }
            else
            {
                general->AddItem("RootFolderShellItem").SetType(ListViewItem::Type::Category);
                const auto rfsi = (RootFolderShellItem*) id;
                UpdateRootFolderShellItem(*rfsi);
            }
        }
        break;
        case ClassTypeIndicators::CLSID_MyComputer:
        {
            general->AddItem("VolumeShellItem").SetType(ListViewItem::Type::Category);
            const auto vsi = (VolumeShellItem*) id;
            UpdateVolumeShellItem(*vsi);
        }
        break;
        case ClassTypeIndicators::CLSID_ShellFSFolder:
        {
            general->AddItem("CLSID_ShellFSFolder").SetType(ListViewItem::Type::Category);
            UpdateFileEntryShellItem_XPAndLater(id);
        }
        break;
        default:
        {
            const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at(indicator);
            const auto indicatorHex   = nf2.ToString((uint8) indicator, hex);
            general->AddItem({ "Class Type Indicator", ls.Format("%-20s (%s)", indicatorName.data(), indicatorHex.data()) })
                  .SetType(ListViewItem::Type::ErrorInformation);
        }
        break;
        }
    }
}

void Panels::LinkTargetIDList::UpdateFileEntryShellItem_XPAndLater(ItemID* id)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    const auto item = *(FileEntryShellItem_XPAndLater*) id;
    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) (item.indicator & 0x70));
    LocalString<16> hfls;
    hfls.Format("(0x%X)", (item.indicator & 0x70));
    general->AddItem({ "", ls.Format("%-20s %-4s", indicatorName.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    const auto fesiFlags = LNK::GetFileEntryShellItemFlags(item.indicator & 0x0F);
    for (const auto& flag : fesiFlags)
    {
        hfls.Format("(0x%X)", flag);
        const auto flagName = LNK::FileEntryShellItemFlagsNames.at(flag).data();
        general->AddItem({ "", ls.Format("%-20s %-4s", flagName, hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("Unknown0", "%-20s %-4s", item.unknown0);
    AddDecAndHexElement("FileSize", "%-20s %-4s", item.fileSize);

    DateTime dt;
    dt.CreateFromFATUTC(item.lastModificationDateAndTime);
    const auto lastModificationDateAndTimeHex = nf.ToString(item.lastModificationDateAndTime, hex);
    general
          ->AddItem({ "Last Modification Date And Time",
                      ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), lastModificationDateAndTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("File Attribute Flags", "%-20s (%s)", item.fileAttributesFlags);

    const auto faFlags = LNK::GetFileAttributeFlags(item.fileAttributesFlags);
    for (const auto& flag : faFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = LNK::FileAttributeFlagsNames.at(flag).data();
        const auto flagDescription = LNK::FileAttributeFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    auto offset            = sizeof(FileEntryShellItem_XPAndLater);
    const auto primaryName = ((uint8*) (id) + offset);

    if ((item.indicator & 0x0F) & (uint8) FileEntryShellItemFlags::HasUnicodeStrings)
    {
        general->AddItem({ "Primary Name", ls.Format("%S", primaryName) });
        offset += (wcslen((wchar_t*) primaryName) * sizeof(wchar_t));
    }
    else
    {
        general->AddItem({ "Primary Name", ls.Format("%s", primaryName) });
        offset += strlen((char*) primaryName);
    }

    offset = (offset % 2 == 0 ? offset + 2 : offset + 1); // 16 bit aligned

    // 04 00 ef be
    auto base = (ExtensionBlock0xBEEF0004Base*) ((uint8*) (id) + offset);
    switch (base->version)
    {
    case VersionBEEF0004::Windows8dot1or10:
        UpdateExtensionBlock0xBEEF0004BaseV9((ExtensionBlock0xBEEF0004_V9*) base);
        break;
    default:
        UpdateExtensionBlock0xBEEF0004Base(*base);
        break;
    }
}

void Panels::LinkTargetIDList::UpdateExtensionBlock0xBEEF0004Base(ExtensionBlock0xBEEF0004Base& block)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("BEEF0004 Size", "%-20s (%s)", block.size);

    const auto& versionName = LNK::VersionBEEF0004Names.at(block.version);
    const auto versionHex   = nf.ToString((uint16) block.version, hex);
    general->AddItem({ "BEEF0004 Version", ls.Format("%-20s (%s)", versionName.data(), versionHex.data()) });

    AddDecAndHexElement("BEEF0004 Signature", "%-20s (%s)", block.signature);

    DateTime dt;
    dt.CreateFromFATUTC(block.creationDateAndTime);
    const auto creationDateAndTimeBEEF0004Hex = nf.ToString(block.creationDateAndTime, hex);
    general
          ->AddItem({ "BEEF0004 Creation Date And Time",
                      ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), creationDateAndTimeBEEF0004Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    dt.CreateFromFATUTC(block.lastDateAndTime);
    const auto lastDateAndTimeBEEF0004Hex = nf.ToString(block.lastDateAndTime, hex);
    general
          ->AddItem({ "BEEF0004 Last Date And Time",
                      ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), lastDateAndTimeBEEF0004Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("BEEF0004 Unknown0", "%-20s (%s)", block.unknown0);
}

void Panels::LinkTargetIDList::UpdateExtensionBlock0xBEEF0004BaseV9(ExtensionBlock0xBEEF0004_V9* block)
{
    UpdateExtensionBlock0xBEEF0004Base(block->base);

    AddDecAndHexElement("BEEF0004 v9 Unknown0", "%-20s (%s)", block->unknown0);
    AddDecAndHexElement("BEEF0004 v9 MFT Entry Index", "%-20s (%s)", (*(uint64*) block->fileReference.mftEntryIndex) & 0xFFFFFFFF);
    AddDecAndHexElement("BEEF0004 v9 Sequence Number", "%-20s (%s)", block->fileReference.sequenceNumber);
    AddDecAndHexElement("BEEF0004 v9 Unknown1", "%-20s (%s)", block->unknown1);
    AddDecAndHexElement("BEEF0004 v9 Long String Size", "%-20s (%s)", block->longStringSize);
    AddDecAndHexElement("BEEF0004 v9 Unknown2", "%-20s (%s)", block->unknown2);
    AddDecAndHexElement("BEEF0004 v9 Unknown3", "%-20s (%s)", block->unknown3);

    if (block->longStringSize > 0)
    {
        LocalString<1024> ls;
        const auto locaLizedName = (uint16*) ((uint8*) block + sizeof(ExtensionBlock0xBEEF0004_V9));
        general->AddItem({ "BEEF0004 v9 Localized Name", ls.Format("%S", locaLizedName) });
    }

    const auto firstExtension = *(uint16*) ((uint8*) block + block->base.size - sizeof(uint16));
    AddDecAndHexElement("BEEF0004 v9 First Extension", "%-20s (%s)", firstExtension);
}

void Panels::LinkTargetIDList::UpdateIssues()
{
}

void Panels::LinkTargetIDList::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<>(this->GetHeight(), (int) general->GetItemsCount() + 3));

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Panels::LinkTargetIDList::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Panels::LinkTargetIDList::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        default:
            break;
        }
    }

    return false;
}

void Panels::LinkTargetIDList::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
