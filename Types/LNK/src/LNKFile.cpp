#include <array>
#include <nlohmann/json.hpp>

#include "LNK.hpp"

using namespace GView::Type::LNK;
using nlohmann::json;

LNKFile::LNKFile()
{
}

bool LNKFile::Update()
{
    auto offset = 0;
    CHECK(obj->GetData().Copy<Header>(offset, header), false, "");
    offset += sizeof(header);

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
    {
        CHECK(obj->GetData().Copy<LinkTargetIDList>(offset, linkTargetIDList), false, "");
        offset += sizeof(LinkTargetIDList);
        linkTargetIDListBuffer = obj->GetData().CopyToBuffer(offset, linkTargetIDList.IDListSize);
        CHECK(linkTargetIDListBuffer.IsValid(), false, "");

        auto offset2 = 0;
        while (offset2 < linkTargetIDList.IDListSize - 2) // - terminal
        {
            const auto itemID = itemIDS.emplace_back((ItemID*) &linkTargetIDListBuffer.GetData()[offset2]);
            offset2 += itemID->ItemIDSize;
        }
        offset += offset2 + 2;
    }

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
    {
        CHECK(obj->GetData().Copy<LocationInformation>(offset, locationInformation), false, "");
        locationInformationBuffer = obj->GetData().CopyToBuffer(offset, locationInformation.size);
        CHECK(locationInformationBuffer.IsValid(), false, "");
        offset += locationInformation.size;

        if (locationInformation.headerSize > 28)
        {
            unicodeLocalPathOffset = *(uint32*) (locationInformationBuffer.GetData() + sizeof(LocationInformation));
            const auto unicodeLocalPathOffsetSize =
                  wcslen(reinterpret_cast<wchar_t*>((void*) (locationInformationBuffer.GetData() + unicodeLocalPathOffset)));
            unicodeLocalPath = { (char16*) (locationInformationBuffer.GetData() + unicodeLocalPathOffset), unicodeLocalPathOffsetSize };

            if (locationInformation.headerSize > 32)
            {
                unicodeCommonPathOffset =
                      *(uint32*) (locationInformationBuffer.GetData() + sizeof(LocationInformation) + sizeof(unicodeLocalPathOffset));
                const auto unicodeCommonPathOffsetSize =
                      wcslen(reinterpret_cast<wchar_t*>((void*) (locationInformationBuffer.GetData() + unicodeCommonPathOffset)));
                unicodeCommonPath = { (char16*) (locationInformationBuffer.GetData() + unicodeCommonPathOffset),
                                      unicodeCommonPathOffsetSize };
            }
        }

        if (locationInformation.volumeInformationOffset > 0)
        {
            volumeInformation = (VolumeInformation*) (locationInformationBuffer.GetData() + locationInformation.volumeInformationOffset);
        }

        if (locationInformation.networkShareOffset > 0)
        {
            networkShareInformation =
                  (NetworkShareInformation*) (locationInformationBuffer.GetData() + locationInformation.networkShareOffset);
        }
    }

    dataStringsBuffer    = obj->GetData().CopyToBuffer(offset, (uint32) (obj->GetData().GetSize() - offset));
    dataStringsOffset    = (uint32) offset;
    const bool isUnicode = (header.linkFlags & (uint32) LNK::LinkFlags::IsUnicode);

    auto dataStringBufferOffset = 0;
    for (const auto& flag : std::array<LNK::LinkFlags, 5>{ LNK::LinkFlags::HasName,
                                                           LNK::LinkFlags::HasRelativePath,
                                                           LNK::LinkFlags::HasWorkingDir,
                                                           LNK::LinkFlags::HasArguments,
                                                           LNK::LinkFlags::HasIconLocation })
    {
        if (header.linkFlags & (uint32) flag)
        {
            DataStringTypes dst = DataStringTypes::Description;

            switch (flag)
            {
            case LNK::LinkFlags::HasName:
                dst = DataStringTypes::Description;
                break;
            case LNK::LinkFlags::HasRelativePath:
                dst = DataStringTypes::RelativePath;
                break;
            case LNK::LinkFlags::HasWorkingDir:
                dst = DataStringTypes::WorkingDirectory;
                break;
            case LNK::LinkFlags::HasArguments:
                dst = DataStringTypes::CommandLineArguments;
                break;
            case LNK::LinkFlags::HasIconLocation:
                dst = DataStringTypes::IconLocation;
                break;
            default:
                break;
            }

            const auto ds  = (DataString*) (dataStringsBuffer.GetData() + dataStringBufferOffset);
            const auto buf = ((uint8*) &ds->charsCount + sizeof(DataString));
            if (isUnicode)
            {
                std::u16string_view sv{ (char16*) buf, ds->charsCount };
                dataStrings.emplace(std::pair<DataStringTypes, ConstString>{ dst, ConstString{ sv } });
                dataStringBufferOffset += (ds->charsCount + 1ULL) * sizeof(char16);
            }
            else
            {
                std::string_view sv{ (char*) buf, ds->charsCount };
                dataStrings.emplace(std::pair<DataStringTypes, ConstString>{ dst, ConstString{ sv } });
                dataStringBufferOffset += (ds->charsCount + 2ULL) * sizeof(char8);
            }
        }
    }

    offset += dataStringBufferOffset;
    extraDataBuffer = obj->GetData().CopyToBuffer(offset, (uint32) (obj->GetData().GetSize() - offset));

    auto extraDataBufferOffset = 0;
    while (extraDataBufferOffset < extraDataBuffer.GetLength())
    {
        const auto extra = (ExtraDataBase*) ((uint8*) extraDataBuffer.GetData() + extraDataBufferOffset);
        CHECKBK(extra->size != 0, "");
        extraDataBases.emplace_back(extra);
        extraDataBufferOffset += extra->size;

        if (extra->signature == ExtraDataSignatures::MetadataPropertyStore)
        {
            auto offset = sizeof(ExtraData_MetadataPropertyStore);
            {
                while (offset < ((ExtraData_MetadataPropertyStore*) extra)->base.size - sizeof(ExtraData_MetadataPropertyStore))
                {
                    auto ps = (PropertyStore*) ((uint8*) extra + offset);
                    propertyStores.emplace(std::pair<PropertyStore*, std::vector<PropertyStore_ShellPropertySheet*>>{ ps, {} });
                    offset += ps->size;
                }
            }

            for (auto& [key, values] : propertyStores)
            {
                offset    = sizeof(PropertyStore);
                auto& sps = values.emplace_back((PropertyStore_ShellPropertySheet*) (((uint8*) key) + offset));
                offset += sizeof(PropertyStore_ShellPropertySheet);
                while (offset < key->size - sizeof(uint32) /* terminal */)
                {
                    auto snpp = (PropertyStore_ShellPropertyNumeric*) ((uint8*) key + offset);
                    offset += snpp->size;
                }
            }
        }
    }

    return true;
}

std::string LNKFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"]        = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();

    context["Header"] = { { "LinkFlags", header.linkFlags },       { "FileAttributes", header.fileAttributeFlags },
                          { "CreationTime", header.creationDate }, { "AccessTime", header.lastAccessDate },
                          { "FileSize", header.fileSize },         { "IconIndex", header.iconIndex },
                          { "ShowCommand", header.showCommand } };

    if (header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo) {
        context["LocationInformation"] = {
            { "Size", locationInformation.size },
            { "HeaderSize", locationInformation.headerSize },
            { "Flags", locationInformation.flags },
            { "VolumeIDOffset", locationInformation.volumeInformationOffset },
            { "LocalBasePathOffset", locationInformation.localPathOffset },
            { "CommonNetworkRelativeLinkOffset", locationInformation.commonPathOffset },
            { "CommonPathSuffixOffset", locationInformation.commonPathOffset },
        };

        if (locationInformation.volumeInformationOffset > 0) {
            context["VolumeInformation"] = {
                { "Size", volumeInformation->size },
                { "DriveType", volumeInformation->driveType },
                { "DriveSerialNumber", volumeInformation->driveSerialNumber },
                { "VolumeLabelOffset", volumeInformation->volumeLabelOffset },
            };
        }

        if (locationInformation.networkShareOffset > 0) {
            context["NetworkShareInformation"] = {
                { "Size", networkShareInformation->size },
                { "Flags", networkShareInformation->flags },
                { "ShareNameOffset", networkShareInformation->networkShareNameOffset },
            };
        }
    }
    return context.dump();
}

namespace GView::Type::LNK::Panels
{
void ShellItems::UpdateRootFolderShellItem(RootFolderShellItem& item)
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

    AddGUIDElement(general, "Shell Folder Identifier", item.shellFolderIdentifier);
}

void ShellItems::UpdateExtensionBlock0xBEEF0017(ExtensionBlock0xBEEF0017& block)
{
    general->AddItem("BEEF0017").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Size", "%-20s (%s)", block.size);
    AddDecAndHexElement("Version", "%-20s (%s)", block.version);
    AddDecAndHexElement("Signature", "%-20s (%s)", block.signature);
    AddDecAndHexElement("Unknown0", "%-20s (%s)", block.unknown0);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", block.unknown1);
    AddDecAndHexElement("Unknown2", "%-20s (%s)", block.unknown2);
    AddDecAndHexElement("Unknown3", "%-20s (%s)", block.unknown3);
    AddDecAndHexElement("Unknown4", "%-20s (%s)", block.unknown4);
    AddDecAndHexElement("Unknown5", "%-20s (%s)", block.unknown5);
    AddDecAndHexElement("Unknown6", "%-20s (%s)", block.unknown6);
    AddDecAndHexElement("Unknown7", "%-20s (%s)", block.unknown7);
    AddDecAndHexElement("Unknown8", "%-20s (%s)", block.unknown8);
    AddDecAndHexElement("Unknown9", "%-20s (%s)", block.unknown9);
    AddDecAndHexElement("Unknown10", "%-20s (%s)", block.unknown10);

    LocalString<1024> ls;
    NumericFormatter nf;
    AppCUI::OS::DateTime dt;
    dt.CreateFromFATUTC(block.unknown11);
    const auto unknown11Hex = nf.ToString(block.unknown11, hex);
    general->AddItem({ "Unknown11 Date And Time", ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), unknown11Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Unknown12", "%-20s (%s)", block.unknown12);
    AddDecAndHexElement("Unknown13", "%-20s (%s)", block.unknown13);
    AddDecAndHexElement("Unknown14", "%-20s (%s)", block.unknown14);
    AddDecAndHexElement("VersionOffset ", "%-20s (%s)", block.blockVersionOffset);
}

void ShellItems::UpdateVolumeShellItem(VolumeShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& indicatorName =
          LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) (item.indicator < 0x50 ? item.indicator & 0x70 : item.indicator));
    LocalString<16> hfls;

    hfls.Format("(0x%X)", (item.indicator < 0x50 ? item.indicator & 0x70 : item.indicator));
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

void ShellItems::UpdateLinkTargetIDList(const std::vector<ItemID*>& itemIDS)
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    for (const auto& id : itemIDS)
    {
        const auto& item = id->item;
        const auto& type = item.type;
        const auto indicator =
              (ClassTypeIndicators) (type > (uint8) ClassTypeIndicators::CLSID_ShellDesktop && type < (uint8) ClassTypeIndicators::CompressedFolderShellItem ? (type & 0x70) : type);

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
            UpdateFileEntryShellItem(id);
        }
        break;
        case ClassTypeIndicators::ControlPanel_:
        {
            general->AddItem("ControlPanel 0x70").SetType(ListViewItem::Type::Category);
            const auto cpsi = (ControlPanelShellItem*) id;
            UpdateControlPanelShellItem(*cpsi);
        }
        break;
        case ClassTypeIndicators::UsersFilesFolder:
        {
            general->AddItem("UsersFilesFolder").SetType(ListViewItem::Type::Category);
            const auto dsi = (DelegateShellItem*) id;
            UpdateDelegateShellItem(*dsi);
        }
        break;
        case ClassTypeIndicators::CLSID_NetworkRoot:
        case ClassTypeIndicators::NetworkLocation:
        {
            general->AddItem("NetworkLocation").SetType(ListViewItem::Type::Category);
            const auto dsi = (NetworkLocationShellItem*) id;
            UpdateNetworkLocationShellItem(*dsi);
        }
        break;
        default:
        {
            general->AddItem("Unknown").SetType(ListViewItem::Type::Category);

            AddDecAndHexElement("Size", "%-20s (%s)", id->ItemIDSize);
            const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at(indicator);
            const auto indicatorHex   = nf2.ToString((uint8) indicator, hex);
            general->AddItem({ "Class Type Indicator", ls.Format("%-20s (%s)", indicatorName.data(), indicatorHex.data()) })
                  .SetType(ListViewItem::Type::ErrorInformation);

            AddDecAndHexElement("Type", "%-20s (%s)", type);
        }
        break;
        }
    }
}

void ShellItems::UpdateFileEntryShellItem(ItemID* id)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    const auto item = *(FileEntryShellItem*) id;
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

    AppCUI::OS::DateTime dt;
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

    auto offset            = sizeof(FileEntryShellItem);
    const auto primaryName = ((uint8*) (id) + offset);

    if ((item.indicator & 0x0F) & (uint8) FileEntryShellItemFlags::HasUnicodeStrings)
    {
        general->AddItem({ "Primary Name", ls.Format("%ls", primaryName) });
        offset += std::min<uint64>((uint64) wcslen(reinterpret_cast<wchar_t*>((void*) (primaryName))) * sizeof(wchar_t), 16ULL);
    }
    else
    {
        general->AddItem({ "Primary Name", ls.Format("%s", primaryName) });
        offset += std::min<uint64>((uint64) strlen((char*) primaryName), 16ULL);
    }

    offset = (offset % 2 == 0 ? offset + 2 : offset + 1); // 16 bit aligned

    auto base = (ExtensionBlock0xBEEF0004Base*) ((uint8*) (id) + offset);
    if (base->signature == 0xBEEF0004)
    {
        switch (base->version)
        {
        case VersionBEEF0004::WindowsXPOr2003:
            UpdateExtensionBlock0xBEEF0004_V3((ExtensionBlock0xBEEF0004_V3*) base);
            break;
        case VersionBEEF0004::WindowsVistaOrSP0:
            UpdateExtensionBlock0xBEEF0004_V7((ExtensionBlock0xBEEF0004_V7*) base);
            break;
        case VersionBEEF0004::Windows2008Or7Or8:
            UpdateExtensionBlock0xBEEF0004_V8((ExtensionBlock0xBEEF0004_V8*) base);
            break;
        case VersionBEEF0004::Windows8dot1or10:
            UpdateExtensionBlock0xBEEF0004_V9((ExtensionBlock0xBEEF0004_V9*) base);
            break;
        default:
            general->AddItem("BEEF0004").SetType(ListViewItem::Type::Category);
            UpdateExtensionBlock0xBEEF0004Base(*base);
            break;
        }
    }

    if (item.indicator & 0x80)
    {
        general->AddItem("BEEF0003").SetType(ListViewItem::Type::Category);
        UpdateExtensionBlock0xBEEF0003(*(ExtensionBlock0xBEEF0003*) ((uint8*) id + offset + base->size));
    }
    else
    {
        const auto current = offset + base->size;
        if (item.size > current)
        {
            general->AddItem("Missing BEEF!").SetType(ListViewItem::Type::Category);
            // Present if shell item contains more data (and flag 0x80 is not set?) (seen in Windows 2003)
            // Extension block -> Seen extension block 0xbeef0005, 0xbeef0006 and 0xbeef001a.
        }
    }
}

void ShellItems::UpdateExtensionBlock0xBEEF0003(ExtensionBlock0xBEEF0003& block)
{
    AddDecAndHexElement("Size", "%-20s (%s)", block.size);
    AddDecAndHexElement("Version", "%-20s (%s)", block.version);
    AddDecAndHexElement("Signature", "%-20s (%s)", block.signature);
    AddGUIDElement(general, "Shell Folder Identifier", block.shellFolderIdentifier);
    AddDecAndHexElement("Version Offset", "%-20s (%s)", block.blockVersionOffset);
}

void ShellItems::UpdateExtensionBlock0xBEEF0004Base(ExtensionBlock0xBEEF0004Base& block)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("Size", "%-20s (%s)", block.size);

    const auto& versionName = LNK::VersionBEEF0004Names.at(block.version);
    const auto versionHex   = nf.ToString((uint16) block.version, hex);
    general->AddItem({ "Version", ls.Format("%-20s (%s)", versionName.data(), versionHex.data()) });

    AddDecAndHexElement("Signature", "%-20s (%s)", block.signature);

    AppCUI::OS::DateTime dt;
    dt.CreateFromFATUTC(block.creationDateAndTime);
    const auto creationDateAndTimeBEEF0004Hex = nf.ToString(block.creationDateAndTime, hex);
    general
          ->AddItem({ "Creation Date And Time",
                      ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), creationDateAndTimeBEEF0004Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    dt.CreateFromFATUTC(block.lastDateAndTime);
    const auto lastDateAndTimeBEEF0004Hex = nf.ToString(block.lastDateAndTime, hex);
    general
          ->AddItem(
                { "Last Date And Time", ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), lastDateAndTimeBEEF0004Hex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", block.unknown0);
}

void ShellItems::UpdateExtensionBlock0xBEEF0004_V3(ExtensionBlock0xBEEF0004_V3* block)
{
    general->AddItem("BEEF0004 v3").SetType(ListViewItem::Type::Category);

    UpdateExtensionBlock0xBEEF0004Base(block->base);

    AddDecAndHexElement("Long String Size", "%-20s (%s)", block->longStringSize);

    if (block->base.unknown0 > 0)
    {
        LocalString<1024> ls;
        const auto locaLizedName = ((uint8*) block + sizeof(ExtensionBlock0xBEEF0004_V3));
        general->AddItem({ "Localized Name", ls.Format("%ls", locaLizedName) });
    }

    const auto firstExtension = *(uint16*) ((uint8*) block + block->base.size - sizeof(uint16));
    AddDecAndHexElement("First Extension", "%-20s (%s)", firstExtension);
}

void ShellItems::UpdateExtensionBlock0xBEEF0004_V7(ExtensionBlock0xBEEF0004_V7* block)
{
    general->AddItem("BEEF0004 v7").SetType(ListViewItem::Type::Category);

    UpdateExtensionBlock0xBEEF0004Base(block->base);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", block->unknown0);
    AddDecAndHexElement("MFT Entry Index", "%-20s (%s)", (*(uint64*) block->fileReference.mftEntryIndex) & 0xFFFFFFFF);
    AddDecAndHexElement("Sequence Number", "%-20s (%s)", block->fileReference.sequenceNumber);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", block->unknown1);
    AddDecAndHexElement("Long String Size", "%-20s (%s)", block->longStringSize);

    LocalString<1024> ls;
    const auto longName = (uint16*) ((uint8*) block + sizeof(ExtensionBlock0xBEEF0004_V7));
    general->AddItem({ "Long Name", ls.Format("%S", longName) });

    if (block->longStringSize > 0)
    {
        const auto locaLizedName = (uint16*) ((uint8*) longName + wcslen((wchar_t*) longName) * sizeof(wchar_t) + 2);
        general->AddItem({ "Localized Name", ls.Format("%S", locaLizedName) });
    }

    const auto firstExtension = *(uint16*) ((uint8*) block + block->base.size - sizeof(uint16));
    AddDecAndHexElement("First Extension", "%-20s (%s)", firstExtension);
}

void ShellItems::UpdateExtensionBlock0xBEEF0004_V8(ExtensionBlock0xBEEF0004_V8* block)
{
    general->AddItem("BEEF0004 v8").SetType(ListViewItem::Type::Category);

    UpdateExtensionBlock0xBEEF0004Base(block->base);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", block->unknown0);
    AddDecAndHexElement("MFT Entry Index", "%-20s (%s)", (*(uint64*) block->fileReference.mftEntryIndex) & 0xFFFFFFFF);
    AddDecAndHexElement("Sequence Number", "%-20s (%s)", block->fileReference.sequenceNumber);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", block->unknown1);
    AddDecAndHexElement("Long String Size", "%-20s (%s)", block->longStringSize);
    AddDecAndHexElement("Unknown3", "%-20s (%s)", block->unknown3);

    LocalString<1024> ls;
    const auto longName = (uint16*) ((uint8*) block + sizeof(ExtensionBlock0xBEEF0004_V8));
    general->AddItem({ "Long Name", ls.Format("%S", longName) });

    if (block->longStringSize > 0)
    {
        const auto locaLizedName = (uint16*) ((uint8*) longName + wcslen((wchar_t*) longName) * sizeof(wchar_t) + 2);
        general->AddItem({ "Localized Name", ls.Format("%S", locaLizedName) });
    }

    const auto firstExtension = *(uint16*) ((uint8*) block + block->base.size - sizeof(uint16));
    AddDecAndHexElement("First Extension", "%-20s (%s)", firstExtension);
}

void ShellItems::UpdateExtensionBlock0xBEEF0004_V9(ExtensionBlock0xBEEF0004_V9* block)
{
    general->AddItem("BEEF0004 v9").SetType(ListViewItem::Type::Category);

    UpdateExtensionBlock0xBEEF0004Base(block->base);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", block->unknown0);
    AddDecAndHexElement("MFT Entry Index", "%-20s (%s)", (*(uint64*) block->fileReference.mftEntryIndex) & 0xFFFFFFFF);
    AddDecAndHexElement("Sequence Number", "%-20s (%s)", block->fileReference.sequenceNumber);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", block->unknown1);
    AddDecAndHexElement("Long String Size", "%-20s (%s)", block->longStringSize);
    AddDecAndHexElement("Unknown2", "%-20s (%s)", block->unknown2);
    AddDecAndHexElement("Unknown3", "%-20s (%s)", block->unknown3);

    LocalString<1024> ls;
    const auto longName = (uint16*) ((uint8*) block + sizeof(ExtensionBlock0xBEEF0004_V9));
    general->AddItem({ "Long Name", ls.Format("%S", longName) });

    if (block->longStringSize > 0)
    {
        const auto locaLizedName = (uint16*) ((uint8*) longName + wcslen((wchar_t*) longName) * sizeof(wchar_t) + 2);
        general->AddItem({ "Localized Name", ls.Format("%S", locaLizedName) });
    }

    const auto firstExtension = *(uint16*) ((uint8*) block + block->base.size - sizeof(uint16));
    AddDecAndHexElement("First Extension", "%-20s (%s)", firstExtension);
}

void ShellItems::UpdateControlPanelShellItem(ControlPanelShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& indicatorName =
          LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) (item.indicator < 0x50 ? item.indicator & 0x70 : item.indicator));
    LocalString<16> hfls;
    hfls.Format("(0x%X)", (item.indicator & 0x70));
    general->AddItem({ "", ls.Format("%-20s %-4s", indicatorName.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", item.unknown0);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", item.unknown1);
    AddGUIDElement(general, "Identifier", item.identifier);
}

void ShellItems::UpdateDelegateShellItem(DelegateShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& indicatorName =
          LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) (item.indicator < 0x50 ? item.indicator & 0x70 : item.indicator));
    LocalString<16> hfls;
    hfls.Format("(0x%X)", (item.indicator & 0x70));
    general->AddItem({ "", ls.Format("%-20s %-4s", indicatorName.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", item.unknown0);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", item.unknown1);
    AddDecAndHexElement("Unknown Signature", "%-20s (%s)", item.unknownSignature);
    AddDecAndHexElement("Sub Shell Item Data Size", "%-20s (%s)", item.subShellItemDataSize);
    AddDecAndHexElement("Subclass Type Indicator", "%-20s (%s)", item.subClassTypeIndicator);
    AddDecAndHexElement("Unknown2", "%-20s (%s)", item.unknown2);
    AddDecAndHexElement("Filesize", "%-20s (%s)", item.filesize);

    AppCUI::OS::DateTime dt;
    dt.CreateFromFATUTC(item.lastModificationDateAndTime);
    const auto lastModificationDateAndTimeHex = nf.ToString(item.lastModificationDateAndTime, hex);
    general
          ->AddItem({ "Last Modification Date And Time",
                      ls.Format("%-20s %-4s", dt.GetStringRepresentation().data(), lastModificationDateAndTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("File Attribute Flags", "%-20s (%s)", item.fileAttributes);

    const auto faFlags = LNK::GetFileAttributeFlags(item.fileAttributes);
    for (const auto& flag : faFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = LNK::FileAttributeFlagsNames.at(flag).data();
        const auto flagDescription = LNK::FileAttributeFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    const auto primaryName = (uint8*) &item + sizeof(DelegateShellItem);
    general->AddItem({ "Primary Name", ls.Format("%s", primaryName) });

    auto offset = sizeof(DelegateShellItem);
    offset += strlen((char*) primaryName);
    offset = (offset % 2 == 0 ? offset + 2 : offset + 1); // 16 bit aligned

    const auto unknown3 = *(uint16*) ((uint8*) &item + offset);
    AddDecAndHexElement("Unknown3", "%-20s (%s)", unknown3);
    offset += sizeof(uint16);

    const auto delegateItemIdentifier = (MyGUID*) ((uint8*) &item + offset);
    AddGUIDElement(general, "Delegate item identifier", *delegateItemIdentifier);
    offset += 16;

    const auto itemClassIdentifier = (MyGUID*) ((uint8*) &item + offset);
    AddGUIDElement(general, "Item (class) identifier", *itemClassIdentifier);
    offset += 16;

    auto base = (ExtensionBlock0xBEEF0004Base*) ((uint8*) &item + offset);
    switch (base->version)
    {
    case VersionBEEF0004::Windows8dot1or10:
        UpdateExtensionBlock0xBEEF0004_V9((ExtensionBlock0xBEEF0004_V9*) base);
        break;
    default:
        general->AddItem("BEEF0004").SetType(ListViewItem::Type::Category);
        UpdateExtensionBlock0xBEEF0004Base(*base);
        break;
    }
}

void ShellItems::UpdateNetworkLocationShellItem(NetworkLocationShellItem& item)
{
    LocalString<1024> ls;
    NumericFormatter nf;

    AddDecAndHexElement("Size", "%-20s (%s)", item.size);
    AddDecAndHexElement("Class Type Indicator", "%-20s (%s)", item.indicator);

    const auto& type = item.indicator;
    const auto indicator =
          (ClassTypeIndicators) (type > (uint8) ClassTypeIndicators::CLSID_ShellDesktop && type < (uint8) ClassTypeIndicators::CompressedFolderShellItem ? (type & 0x70) : type);
    const auto& indicatorName = LNK::ClassTypeIndicatorsNames.at((ClassTypeIndicators) indicator);

    LocalString<16> hfls;
    hfls.Format("(0x%X)", (item.indicator & 0x70));
    general->AddItem({ "", ls.Format("%-20s %-4s", indicatorName.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    AddDecAndHexElement("Unknown0", "%-20s (%s)", item.unknown0);
    AddDecAndHexElement("Flags", "%-20s (%s)", item.flags);

    const auto location = (uint8*) &item + sizeof(NetworkLocationShellItem);
    general->AddItem({ "Location", ls.Format("%s", location) });

    const auto locationSize = strlen((char*) location);

    auto str = (uint8*) &item + sizeof(NetworkLocationShellItem) + locationSize + 1;
    if (item.flags & 0x80)
    {
        general->AddItem({ "Description", ls.Format("%s", str) });
        str += strlen((char*) str) + 1;
    }

    if (item.flags & 0x40)
    {
        general->AddItem({ "Comments", ls.Format("%s", str) });
        str += strlen((char*) str) + 1;
    }

    if (str - ((uint8*) &item) > item.size)
    {
        AddDecAndHexElement("Unknwon", "%-20s (%s)", *(uint32*) ((uint8*) &item + item.size - sizeof(uint32)));
    }

    // Location -> Contains the network name or UNC path ASCII string with end-of-string character.
    // If flag 0x80 is set:
    //      Description -> ASCII string with end-of-string character
    // If flag 0x40 is set:
    //      Comments -> ASCII string with end-of-string character
    // If size > ?
    //      Unknown -> 0x0000 | 0x0002 | 0x000042
}

} // namespace GView::Type::LNK::Panels
