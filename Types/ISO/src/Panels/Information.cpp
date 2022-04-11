#include "iso.hpp"

using namespace GView::Type::ISO;
using namespace AppCUI::Controls;

Panels::Information::Information(Reference<GView::Type::ISO::ISOFile> _iso) : TabPage("Informa&tion")
{
    iso     = _iso;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } }, ListViewFlags::None);

    Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", "NOT IMPLEMENTED" });

    const auto fileSize    = nf.ToString(iso->file->GetSize(), dec);
    const auto hexfileSize = nf2.ToString(iso->file->GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()) });
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
            ECMA_119_BootRecord br{};
            iso->file->Copy<ECMA_119_BootRecord>(descriptor.offsetInFile, br);
            UpdateBootRecord(br);
        }
        break;
        case SectorType::Primary:
        {
            ECMA_119_PrimaryVolumeDescriptor pvd{};
            iso->file->Copy<ECMA_119_PrimaryVolumeDescriptor>(descriptor.offsetInFile, pvd);
            UpdatePrimaryVolumeDescriptor(pvd);
        }
        break;
        case SectorType::Supplementary:
        {
            ECMA_119_SupplementaryVolumeDescriptor svd{};
            iso->file->Copy<ECMA_119_SupplementaryVolumeDescriptor>(descriptor.offsetInFile, svd);
            UpdateSupplementaryVolumeDescriptor(svd);
        }
        break;
        case SectorType::Partition:
        {
            ECMA_119_VolumePartitionDescriptor vpd{};
            iso->file->Copy<ECMA_119_VolumePartitionDescriptor>(descriptor.offsetInFile, vpd);
            UpdateVolumePartitionDescriptor(vpd);
        }
        break;
        case SectorType::SetTerminator:
        {
            general->AddItem("Terminator Volume Descriptor").SetType(ListViewItem::Type::Category);
            UpdateVolumeHeader(descriptor.header);
        }
        break;
        default:
            throw "Unhandled sector type!";
        }
    }
}

void Panels::Information::UpdateBootRecord(const ECMA_119_BootRecord& br)
{
    general->AddItem("Boot Record").SetType(ListViewItem::Type::Category);
    UpdateVolumeHeader(br.vdh);
    AddNameAndHexElement("Boot System Identifier", "%-10s (%s)", br.bootSystemIdentifier);
    AddNameAndHexElement("Boot Identifier", "%-10s (%s)", br.bootIdentifier);
    AddNameAndHexElement("Boot System Use", "%-10s (%s)", br.bootSystemUse);
}

void Panels::Information::UpdatePrimaryVolumeDescriptor(const ECMA_119_PrimaryVolumeDescriptor& pvd)
{
    general->AddItem("Primary Volume Descriptor").SetType(ListViewItem::Type::Category);

    UpdateVolumeHeader(pvd.vdh);
    UpdateVolumeDescriptor(pvd.vdd);
}

void Panels::Information::UpdateVolumeDescriptor(const ECMA_119_VolumeDescriptorData& vdd)
{
    general->AddItem({ "Unused", "" });
    AddNameAndHexElement("System Identifier", "%-14s (%s)", vdd.systemIdentifier);
    AddNameAndHexElement("Volume Identifier", "%-14s (%s)", vdd.volumeIdentifier);
    general->AddItem("Unused Field");
    AddDecAndHexElement("Volume Space Size", "%-14s (%s)", vdd.volumeSpaceSize.LSB);
    general->AddItem({ "Unused Field 2", "" });
    AddDecAndHexElement("Volume Set Size", "%-14s (%s)", vdd.volumeSetSize.LSB);
    AddDecAndHexElement("Volume Sequence Number", "%-14s (%s)", vdd.volumeSequenceNumber.LSB);
    AddDecAndHexElement("Logical Block Size", "%-14s (%s)", vdd.logicalBlockSize.LSB);
    AddDecAndHexElement("Path Table Size", "%-14s (%s)", vdd.pathTableSize.LSB);
    AddDecAndHexElement("Location Of Type-L Path Table", "%-14s (%s)", vdd.locationOfTypeLPathTable);
    AddDecAndHexElement("Location Of The Optional Type-L Path Table", "%-14s (%s)", vdd.locationOfTheOptionalTypeLPathTable);
    AddDecAndHexElement("Location Of Type-M Path Table", "%-14s (%s)", vdd.locationOfTypeMPathTable);
    AddDecAndHexElement("Location Of The Optional Type-M Path Table", "%-14s (%s)", vdd.locationOfTheOptionalTypeMPathTable);
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
    general->AddItem({ "Unused2", "" });
    AddNameAndHexElement("Application Used", "%-14s (%s)", vdd.applicationUsed);
    AddNameAndHexElement("Reserved", "%-14s (%s)", vdd.reserved);
}

void GView::Type::ISO::Panels::Information::UpdateVolumePartitionDescriptor(const ECMA_119_VolumePartitionDescriptor& vpd)
{
    general->AddItem("Primary Volume Descriptor").SetType(ListViewItem::Type::Category);

    UpdateVolumeHeader(vpd.vdh);
    general->AddItem({ "Unused", "" });
    AddNameAndHexElement("System Identifier", "%-14s (%s)", vpd.systemIdentifier);
    AddNameAndHexElement("Volume Partition Identifier", "%-14s (%s)", vpd.volumePartitionIdentifier);
    AddDecAndHexElement("Volume Partition Location", "%-14s (%s)", vpd.volumePartitionLocation.LSB);
    AddDecAndHexElement("Volume Partition Size", "%-14s (%s)", vpd.volumePartitionSize.LSB);
    AddNameAndHexElement("System Use", "%-14s (%s)", vpd.systemUse);
}

void Panels::Information::UpdateSupplementaryVolumeDescriptor(const ECMA_119_SupplementaryVolumeDescriptor& svd)
{
    general->AddItem("Supplementary Volume Descriptor").SetType(ListViewItem::Type::Category);

    UpdateVolumeHeader(svd.vdh);
    UpdateVolumeDescriptor(svd.vdd);
}

void Panels::Information::UpdateVolumeHeader(const ECMA_119_VolumeDescriptorHeader& vdh)
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto& typeName = ISO::GetSectorTypeName(vdh.type);
    const auto hexType   = nf.ToString(static_cast<uint8>(vdh.type), hex);
    general->AddItem({ "Sector Type", ls.Format("%-14s (%s)", typeName.data(), hexType.data()) });

    const auto identifierHex = ls2.Format(
          "0x%.2x%.2x%.2x%.2x%.2x", vdh.identifier[0], vdh.identifier[1], vdh.identifier[2], vdh.identifier[3], vdh.identifier[4]);
    general->AddItem(
          { "Identifier", ls.Format("%-14s (%s)", std::string{ vdh.identifier, sizeof(vdh.identifier) }.c_str(), identifierHex.data()) });

    const auto version    = nf.ToString(vdh.version, dec);
    const auto hexVersion = nf2.ToString(vdh.version, hex);
    general->AddItem({ "Version", ls.Format("%-14s (%s)", version.data(), hexVersion.data()) });
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
