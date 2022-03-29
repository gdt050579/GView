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
    general->AddItem("Unused", "");
    AddNameAndHexElement("System Identifier", "%-14s (%s)", vdd.systemIdentifier);
    AddNameAndHexElement("Volume Identifier", "%-14s (%s)", vdd.volumeIdentifier);
    general->AddItem("Unused Field");
    AddDecAndHexElement("Volume Space Size", "%-14s (%s)", vdd.volumeSpaceSize.LSB);
    general->AddItem("Unused Field 2", "");
    AddDecAndHexElement("Volume Set Size", "%-14s (%s)", vdd.volumeSetSize.LSB);
    AddDecAndHexElement("Volume Sequence Number", "%-14s (%s)", vdd.volumeSequenceNumber.LSB);
    AddDecAndHexElement("Logical Block Size", "%-14s (%s)", vdd.logicalBlockSize.LSB);
    AddDecAndHexElement("Path Table Size", "%-14s (%s)", vdd.pathTableSize.LSB);
    AddDecAndHexElement("Location Of Type-L Path Table", "%-14s (%s)", vdd.locationOfTypeLPathTable.LSB);
    AddDecAndHexElement("Location Of The Optional Type-L Path Table", "%-14s (%s)", vdd.locationOfTheOptionalTypeLPathTable.LSB);
    AddDecAndHexElement("Location Of Type-M Path Table", "%-14s (%s)", vdd.locationOfTypeMPathTable.LSB);
    AddDecAndHexElement("Location Of The Optional Type-M Path Table", "%-14s (%s)", vdd.locationOfTheOptionalTypeMPathTable.LSB);
    AddNameAndHexElement("Directory Entry For The Root Directory", "%-14s (%s)", vdd.directoryEntryForTheRootDirectory);
    AddNameAndHexElement("Volume Set Identifier", "%-14s (%s)", vdd.volumeSetIdentifier);
    AddNameAndHexElement("Publisher Set Identifier", "%-14s (%s)", vdd.publisherIdentifier);
    AddNameAndHexElement("Data Preparer Identifier", "%-14s (%s)", vdd.dataPreparerIdentifier);
    AddNameAndHexElement("Application Identifier", "%-14s (%s)", vdd.applicationIdentifier);
    AddNameAndHexElement("Copyright File", "%-14s (%s)", vdd.copyrightFileIdentifier);
    AddNameAndHexElement("Abstract File", "%-14s (%s)", vdd.abstractFileIdentifier);
    AddNameAndHexElement("Bibliographic File", "%-14s (%s)", vdd.bibliographicFileIdentifier);
    AddDateAndHexElement("Volume Creation Date And Time", "%-14s (%s)", vdd.volumeCreationDateAndTime);
    AddDateAndHexElement("Volume Modification Date And Time", "%-14s (%s)", vdd.volumeModificationDateAndTime);
    AddDateAndHexElement("Volume Expiration Date And Time", "%-14s (%s)", vdd.volumeExpirationDateAndTime);
    AddDateAndHexElement("Volume Effective Date And Time", "%-14s (%s)", vdd.volumeEffectiveDateAndTime);
    AddDecAndHexElement("File Structure Version", "%-14s (%s)", vdd.fileStructureVersion);
    general->AddItem("Unused2", "");
    AddNameAndHexElement("Application Used", "%-14s (%s)", vdd.applicationUsed);
    AddNameAndHexElement("Reserved", "%-14s (%s)", vdd.reserved);
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

    general->Resize(GetWidth(), general->GetItemsCount());

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
