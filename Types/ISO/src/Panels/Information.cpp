#include "iso.hpp"

using namespace GView::Type::ISO;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::ISO::ISOFile> _iso) : TabPage("Informa&tion")
{
    iso     = _iso;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 24);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->SetItemType(general->AddItem("Info"), ListViewItemType::Category);

    general->AddItem("File", "NOT IMPLEMENTED");

    const auto fileSize    = nf.ToString(iso->file->GetSize(), dec);
    const auto hexfileSize = nf2.ToString(iso->file->GetSize(), hex);
    general->AddItem("Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()));
}

void Panels::Information::UpdateVolumeDescriptors()
{
    CHECKRET(iso->headers.empty() == false, "");

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    for (const auto& descriptor : iso->headers)
    {
        switch (descriptor.header.type)
        {
        case SectorType::BootRecord:
        {
            BootRecord br{};
            iso->file->Copy<BootRecord>(descriptor.offsetInFile, br);
            UpdateBootRecord(br);
        }
        break;
        case SectorType::Primary:
        {
            PrimaryVolumeDescriptor pvd{};
            iso->file->Copy<PrimaryVolumeDescriptor>(descriptor.offsetInFile, pvd);
            UpdatePrimaryVolumeDescriptor(pvd);
        }
        break;
        case SectorType::Supplementary:
        {
            SupplementaryVolumeDescriptor pvd{};
            iso->file->Copy<SupplementaryVolumeDescriptor>(descriptor.offsetInFile, pvd);
            UpdateSupplementaryVolumeDescriptor(pvd);
        }
        break;
        case SectorType::Partition:
            break;
        case SectorType::SetTerminator:
        {
            general->SetItemType(general->AddItem("Terminator Volume Descriptor"), ListViewItemType::Category);
            UpdateVolumeHeader(descriptor.header);
        }
        break;
        default:
            throw "Unhandled sector type!";
        }
    }
}

void Panels::Information::UpdateBootRecord(const BootRecord& br)
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->SetItemType(general->AddItem("Boot Record"), ListViewItemType::Category);

    UpdateVolumeHeader(br.vdh);

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(br.bootSystemIdentifier); i++)
    {
        ls2.AddFormat("%.2x", br.bootSystemIdentifier[i]);
    }
    const auto bootSystemIdentifierHex = ls2.GetText();
    general->AddItem(
          "Boot System Identifier",
          ls.Format(
                "%-10s (%s)", std::string{ br.bootSystemIdentifier, sizeof(br.bootSystemIdentifier) }.c_str(), bootSystemIdentifierHex));

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(br.bootIdentifier); i++)
    {
        ls2.AddFormat("%.2x", br.bootIdentifier[i]);
    }
    const auto bootIdentifierHex = ls2.GetText();
    general->AddItem(
          "Boot Identifier",
          ls.Format("%-10s (%s)", std::string{ br.bootIdentifier, sizeof(br.bootIdentifier) }.c_str(), bootIdentifierHex));

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(br.bootSystemUse); i++)
    {
        ls2.AddFormat("%.2x", br.bootSystemUse[i]);
    }
    const auto bootSystemUseHex = ls2.GetText();
    general->AddItem(
          "Boot System Use", ls.Format("%-10s (%s)", std::string{ br.bootSystemUse, sizeof(br.bootSystemUse) }.c_str(), bootSystemUseHex));
}

void Panels::Information::UpdatePrimaryVolumeDescriptor(const PrimaryVolumeDescriptor& pvd)
{
    general->SetItemType(general->AddItem("Primary Volume Descriptor"), ListViewItemType::Category);

    UpdateVolumeHeader(pvd.vdh);
    UpdateVolumeDescriptor(pvd.vdd);
}

void Panels::Information::UpdateVolumeDescriptor(const VolumeDescriptorData& vdd)
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Unused", "");

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(vdd.systemIdentifier); i++)
    {
        ls2.AddFormat("%.2x", vdd.systemIdentifier[i]);
    }
    const auto systemIdentifierHex = ls2.GetText();
    general->AddItem(
          "System Identifier",
          ls.Format("%-14s (%s)", std::string{ vdd.systemIdentifier, sizeof(vdd.systemIdentifier) }.c_str(), systemIdentifierHex));

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(vdd.volumeIdentifier); i++)
    {
        ls2.AddFormat("%.2x", vdd.volumeIdentifier[i]);
    }
    const auto volumeIdentifierHex = ls2.GetText();
    general->AddItem(
          "Volume Identifier",
          ls.Format("%-14s (%s)", std::string{ vdd.volumeIdentifier, sizeof(vdd.volumeIdentifier) }.c_str(), volumeIdentifierHex));

    general->AddItem("Unused Field", "");

    const auto volumeSpaceSize    = nf.ToString(vdd.volumeSpaceSize.LSB, dec);
    const auto hexVolumeSpaceSize = nf2.ToString(vdd.volumeSpaceSize.LSB, hex);
    general->AddItem("Volume Space Size", ls.Format("%-14s (%s)", volumeSpaceSize.data(), hexVolumeSpaceSize.data()));

    general->AddItem("Unused Field 2", "");

    const auto volumeSetSize    = nf.ToString(vdd.volumeSetSize.LSB, dec);
    const auto volumeSetSizeHex = nf2.ToString(vdd.volumeSetSize.LSB, hex);
    general->AddItem("Volume Set Size", ls.Format("%-14s (%s)", volumeSetSize.data(), volumeSetSizeHex.data()));

    const auto volumeSequenceNumber    = nf.ToString(vdd.volumeSequenceNumber.LSB, dec);
    const auto volumeSequenceNumberHex = nf2.ToString(vdd.volumeSequenceNumber.LSB, hex);
    general->AddItem("Volume Sequence Number", ls.Format("%-14s (%s)", volumeSequenceNumber.data(), volumeSequenceNumberHex.data()));

    const auto logicalBlockSize    = nf.ToString(vdd.logicalBlockSize.LSB, dec);
    const auto logicalBlockSizeHex = nf2.ToString(vdd.logicalBlockSize.LSB, hex);
    general->AddItem("Logical Block Size", ls.Format("%-14s (%s)", logicalBlockSize.data(), logicalBlockSizeHex.data()));

    const auto pathTableSize    = nf.ToString(vdd.pathTableSize.LSB, dec);
    const auto pathTableSizeHex = nf2.ToString(vdd.pathTableSize.LSB, hex);
    general->AddItem("Logical Block Size", ls.Format("%-14s (%s)", pathTableSize.data(), pathTableSizeHex.data()));

    const auto locationOfTypeLPathTable    = nf.ToString(vdd.locationOfTypeLPathTable.LSB, dec);
    const auto locationOfTypeLPathTableHex = nf2.ToString(vdd.locationOfTypeLPathTable.LSB, hex);
    general->AddItem(
          "Location Of Type-L Path Table", ls.Format("%-14s (%s)", locationOfTypeLPathTable.data(), locationOfTypeLPathTableHex.data()));

    const auto locationOfTheOptionalTypeLPathTable    = nf.ToString(vdd.locationOfTheOptionalTypeLPathTable.LSB, dec);
    const auto locationOfTheOptionalTypeLPathTableHex = nf2.ToString(vdd.locationOfTheOptionalTypeLPathTable.LSB, hex);
    general->AddItem(
          "Location Of The Optional Type-L Path Table",
          ls.Format("%-14s (%s)", locationOfTheOptionalTypeLPathTable.data(), locationOfTheOptionalTypeLPathTableHex.data()));

    const auto locationOfTypeMPathTable    = nf.ToString(vdd.locationOfTypeMPathTable.LSB, dec);
    const auto locationOfTypeMPathTableHex = nf2.ToString(vdd.locationOfTypeMPathTable.LSB, hex);
    general->AddItem(
          "Location Of Type-M Path Table", ls.Format("%-14s (%s)", locationOfTypeMPathTable.data(), locationOfTypeMPathTableHex.data()));

    const auto locationOfTheOptionalTypeMPathTable    = nf.ToString(vdd.locationOfTheOptionalTypeMPathTable.LSB, dec);
    const auto locationOfTheOptionalTypeMPathTableHex = nf2.ToString(vdd.locationOfTheOptionalTypeMPathTable.LSB, hex);
    general->AddItem(
          "Location Of The Optional Type-M Path Table",
          ls.Format("%-14s (%s)", locationOfTheOptionalTypeMPathTable.data(), locationOfTheOptionalTypeMPathTableHex.data()));

    ls2.Format("0x");
    for (auto i = 0ULL; i < sizeof(vdd.directoryEntryForTheRootDirectory); i++)
    {
        ls2.AddFormat("%.2x", vdd.directoryEntryForTheRootDirectory[i]);
    }
    const auto directoryEntryForTheRootDirectoryHex = ls2.GetText();
    general->AddItem(
          "Directory Entry For The Root Directory",
          ls.Format(
                "%-14s (%s)",
                std::string{ vdd.directoryEntryForTheRootDirectory, sizeof(vdd.directoryEntryForTheRootDirectory) }.c_str(),
                directoryEntryForTheRootDirectoryHex));

    /*
        char volumeSetIdentifier[128];
        char publisherIdentifier[128];
        char dataPreparerIdentifier[128];
        char applicationIdentifier[128];
        char copyrightFileIdentifier[37];
        char abstractFileIdentifier[37];
        char bibliographicFileIdentifier[37];
        dec_datetime volumeCreationDateAndTime;
        dec_datetime volumeModificationDateAndTime;
        dec_datetime volumeExpirationDateAndTime;
        dec_datetime volumeEffectiveDateAndTime;
        int8 fileStructureVersion;
        char unused2;
        char applicationUsed[512];
        char reserved[653];
    */
}

void Panels::Information::UpdateSupplementaryVolumeDescriptor(const SupplementaryVolumeDescriptor& svd)
{
    general->SetItemType(general->AddItem("Supplementary Volume Descriptor"), ListViewItemType::Category);

    UpdateVolumeHeader(svd.vdh);
    UpdateVolumeDescriptor(svd.vdd);
}

void Panels::Information::UpdateVolumeHeader(const VolumeDescriptorHeader& vdh)
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto& typeName = ISO::SectorTypeNames.at(vdh.type);
    const auto hexType   = nf.ToString(static_cast<uint8>(vdh.type), hex);
    general->AddItem("Sector Type", ls.Format("%-14s (%s)", typeName.data(), hexType.data()));

    const auto identifierHex = ls2.Format(
          "0x%.2x%.2x%.2x%.2x%.2x", vdh.identifier[0], vdh.identifier[1], vdh.identifier[2], vdh.identifier[3], vdh.identifier[4]);
    general->AddItem(
          "Identifier", ls.Format("%-14s (%s)", std::string{ vdh.identifier, sizeof(vdh.identifier) }.c_str(), identifierHex.data()));

    const auto version    = nf.ToString(vdh.version, dec);
    const auto hexVersion = nf2.ToString(vdh.version, hex);
    general->AddItem("Version", ls.Format("%-14s (%s)", version.data(), hexVersion.data()));
}

void Panels::Information::UpdateIssues()
{
}

void Panels::Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), general->GetItemsCount() + 3);

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

void Panels::Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateVolumeDescriptors();
    UpdateIssues();
    RecomputePanelsPositions();
}
