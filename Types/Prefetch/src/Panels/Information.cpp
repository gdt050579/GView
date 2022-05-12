#include "Prefetch.hpp"

using namespace AppCUI::OS;
using namespace AppCUI::Controls;

namespace GView::Type::Prefetch::Panels
{
Information::Information(Reference<Object> _object, Reference<GView::Type::Prefetch::PrefetchFile> _prefetch) : TabPage("Informa&tion")
{
    prefetch = _prefetch;
    object   = _object;
    general  = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);
    general->AddItem({ "File", object->GetName() });

    const auto size    = nf.ToString(prefetch->obj->GetData().GetSize(), dec);
    const auto hexSize = nf2.ToString(prefetch->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-20s (%s)", size.data(), hexSize.data()) });
}

void Information::UpdateHeader()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Header").SetType(ListViewItem::Type::Category);
    general->AddItem({ "Version", MagicNames.at(prefetch->header.version) }).SetType(ListViewItem::Type::Highlighted);
    general->AddItem({ "Signature", ls.Format("%.*s", 4, (char*) &prefetch->header.signature) });

    const auto h3    = nf.ToString(prefetch->header.H3, dec);
    const auto hexH3 = nf2.ToString(prefetch->header.H3, hex);
    general->AddItem({ "H3", ls.Format("%-20s (%s)", h3.data(), hexH3.data()) });

    const auto fileSize    = nf.ToString(prefetch->header.fileSize, dec);
    const auto fileSizeHex = nf2.ToString(prefetch->header.fileSize, hex);
    auto filesizeItem      = general->AddItem({ "FileSize", ls.Format("%-20s (%s)", fileSize.data(), fileSizeHex.data()) });

    // filesize validation
    if (prefetch->obj->GetData().GetSize() == prefetch->header.fileSize)
    {
        filesizeItem.SetType(ListViewItem::Type::Emphasized_2);
    }
    else
    {
        issues->AddItem({ "Filesize validation failed!" }).SetType(ListViewItem::Type::ErrorInformation);
        filesizeItem.SetType(ListViewItem::Type::ErrorInformation);
    }

    std::string filename;
    {
        ConstString cs{ u16string_view{ (char16_t*) &prefetch->header.executableName,
                                        sizeof(prefetch->header.executableName) / sizeof(prefetch->header.executableName[0]) } };
        LocalUnicodeStringBuilder<sizeof(prefetch->header.executableName) / sizeof(prefetch->header.executableName[0])> lsub;
        lsub.Set(cs);
        lsub.ToString(filename);
    }
    general->AddItem({ "Executable", ls.Format("%s", filename.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);
    general->AddItem({ "Executable Path", ls.Format("%s", prefetch->exePath.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);

    ListViewItem hashItem{};
    {
        const auto hash    = nf.ToString(prefetch->header.hash, dec);
        const auto hashHex = nf2.ToString(prefetch->header.hash, hex);
        hashItem           = general->AddItem({ "Hash", ls.Format("%-20s (%s)", hash.data(), hashHex.data()) });
    }

    // hash validation
    if (prefetch->exePath != "")
    {
        const auto pos  = object->GetName().find_last_of('-');
        const auto pos2 = object->GetName().find_last_of('.');
        if (pos != std::string::npos && pos2 != std::string::npos)
        {
            uint32 hashValue = 0;
            {
                std::string hashFromName;
                ConstString cs{ std::u16string_view(object->GetName().data() + pos + 1, pos2 - (pos + 1)) };
                LocalUnicodeStringBuilder<sizeof(prefetch->header.executableName) / sizeof(prefetch->header.executableName[0])> lsub;
                lsub.Set(cs);
                lsub.ToString(hashFromName);
                hashValue = std::stoul(hashFromName, 0, 16);
            }

            if (hashValue == prefetch->header.hash)
            {
                if (prefetch->header.version != Prefetch::Magic::WIN_10 || prefetch->xpHash != 0)
                {
                    if (hashValue == prefetch->xpHash || hashValue == prefetch->vistaHash || hashValue == prefetch->hash2008)
                    {
                        hashItem.SetType(ListViewItem::Type::Emphasized_2);
                    }
                    else if (hashValue - prefetch->xpHash >= 0 && hashValue - prefetch->xpHash <= 8)
                    {
                        hashItem.SetType(ListViewItem::Type::Emphasized_2);
                        general->AddItem({ "/Prefetch:", ls.Format("%u", hashValue - prefetch->xpHash) })
                              .SetColor(ColorPair{ Color::Pink, Color::Transparent });
                    }
                    else if (hashValue - prefetch->vistaHash >= 0 && hashValue - prefetch->vistaHash <= 8)
                    {
                        hashItem.SetType(ListViewItem::Type::Emphasized_2);
                        general->AddItem({ "/Prefetch:", ls.Format("%u", hashValue - prefetch->vistaHash) })
                              .SetColor(ColorPair{ Color::Pink, Color::Transparent });
                    }
                    else if (hashValue - prefetch->hash2008 >= 0 && hashValue - prefetch->hash2008 <= 8)
                    {
                        hashItem.SetType(ListViewItem::Type::Emphasized_2);
                        general->AddItem({ "/Prefetch:", ls.Format("%u", hashValue - prefetch->hash2008) })
                              .SetColor(ColorPair{ Color::Pink, Color::Transparent });
                    }
                    else
                    {
                        LocalString<64> ls2;
                        issues->AddItem(
                                    { ls2.Format("Hash validation failed when compared to computed XP hash (0x%X)!", prefetch->xpHash) })
                              .SetType(ListViewItem::Type::ErrorInformation);
                        issues->AddItem({ ls2.Format(
                                              "Hash validation failed when compared to computed VISTA hash (0x%X)!", prefetch->vistaHash) })
                              .SetType(ListViewItem::Type::ErrorInformation);
                        issues->AddItem({ ls2.Format(
                                              "Hash validation failed when compared to computed 2008 hash (0x%X)!", prefetch->hash2008) })
                              .SetType(ListViewItem::Type::ErrorInformation);
                        hashItem.SetType(ListViewItem::Type::ErrorInformation);
                    }
                }
                else
                {
                    issues->AddItem("Unable to validate path hash for Windows 10 prefetch files!")
                          .SetType(ListViewItem::Type::ErrorInformation);
                    hashItem.SetType(ListViewItem::Type::ErrorInformation);
                }
            }
            else
            {
                issues->AddItem("Hash validation failed when comparing to filename.").SetType(ListViewItem::Type::ErrorInformation);
                hashItem.SetType(ListViewItem::Type::ErrorInformation);
            }
        }
        else
        {
            issues->AddItem({ "Hash validation failed when comparing to filename." }).SetType(ListViewItem::Type::ErrorInformation);
            hashItem.SetType(ListViewItem::Type::ErrorInformation);
        }
    }
    else
    {
        issues->AddItem({ "Hash validation failed - computed hash not found!" }).SetType(ListViewItem::Type::ErrorInformation);
        hashItem.SetType(ListViewItem::Type::ErrorInformation);
    }

    const auto h7    = nf.ToString(prefetch->header.H7, dec);
    const auto h7Hex = nf2.ToString(prefetch->header.H7, hex);
    general->AddItem({ "H7", ls.Format("%-20s (%s)", h7.data(), h7Hex.data()) });

    const auto fileInformationSize    = nf.ToString(prefetch->area.sectionA.offset - sizeof(prefetch->header), dec);
    const auto fileInformationSizeHex = nf2.ToString(prefetch->area.sectionA.offset - sizeof(prefetch->header), hex);
    general->AddItem({ "File Information Size", ls.Format("%-20s (%s)", fileInformationSize.data(), fileInformationSizeHex.data()) })
          .SetType(ListViewItem::Type::Highlighted);
}

void Information::UpdateSectionArea()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& area = prefetch->area;

    general->AddItem("File Information").SetType(ListViewItem::Type::Category);
    const auto sectionAOffset    = nf.ToString(area.sectionA.offset, dec);
    const auto sectionAOffsetHex = nf2.ToString(area.sectionA.offset, hex);
    general->AddItem({ "Section A Offset", ls.Format("%-20s (%s)", sectionAOffset.data(), sectionAOffsetHex.data()) });

    const auto sectionAEntries    = nf.ToString(area.sectionA.entries, dec);
    const auto sectionAEntriesHex = nf2.ToString(area.sectionA.entries, hex);
    general->AddItem({ "Section A Entries", ls.Format("%-20s (%s)", sectionAEntries.data(), sectionAEntriesHex.data()) });

    const auto sectionBOffset    = nf.ToString(area.sectionB.offset, dec);
    const auto sectionBOffsetHex = nf2.ToString(area.sectionB.offset, hex);
    general->AddItem({ "Section B Offset", ls.Format("%-20s (%s)", sectionBOffset.data(), sectionBOffsetHex.data()) });

    const auto sectionBEntries    = nf.ToString(area.sectionB.entries, dec);
    const auto sectionBEntriesHex = nf2.ToString(area.sectionB.entries, hex);
    general->AddItem({ "Section B Entries", ls.Format("%-20s (%s)", sectionBEntries.data(), sectionBEntriesHex.data()) });

    const auto sectionCOffset    = nf.ToString(area.sectionC.offset, dec);
    const auto sectionCOffsetHex = nf2.ToString(area.sectionC.offset, hex);
    general->AddItem({ "Section C Offset", ls.Format("%-20s (%s)", sectionCOffset.data(), sectionCOffsetHex.data()) });

    const auto sectionCLength    = nf.ToString(area.sectionC.length, dec);
    const auto sectionCLengthHex = nf2.ToString(area.sectionC.length, hex);
    general->AddItem({ "Section C Length", ls.Format("%-20s (%s)", sectionCLength.data(), sectionCLengthHex.data()) });

    const auto sectionDOffset    = nf.ToString(area.sectionD.offset, dec);
    const auto sectionDOffsetHex = nf2.ToString(area.sectionD.offset, hex);
    general->AddItem({ "Section D Offset", ls.Format("%-20s (%s)", sectionDOffset.data(), sectionDOffsetHex.data()) });

    const auto sectionDEntries    = nf.ToString(area.sectionD.entries, dec);
    const auto sectionDEntriesHex = nf2.ToString(area.sectionD.entries, hex);
    general->AddItem({ "Section D Entries", ls.Format("%-20s (%s)", sectionDEntries.data(), sectionDEntriesHex.data()) });

    const auto sectionDSize    = nf.ToString(area.sectionD.size, dec);
    const auto sectionDSizeHex = nf2.ToString(area.sectionD.size, hex);
    general->AddItem({ "Section D Size", ls.Format("%-20s (%s)", sectionDSize.data(), sectionDSizeHex.data()) });
}

void Information::UpdateFileInformation_17()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    DateTime dt;
    dt.CreateFromFileTime(fileInformation.latestExecutionTime);
    const auto latestExecutionTimeHex = nf2.ToString(*(uint64*) &fileInformation.latestExecutionTime, hex);
    general
          ->AddItem(
                { "Latest Execution Time", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), latestExecutionTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    const auto unknownPart1    = nf.ToString(fileInformation.unknown[0], dec);
    const auto unknownPart1Hex = nf2.ToString(fileInformation.unknown[0], hex);
    general->AddItem({ "Unknown Part 1", ls.Format("%-20s (%s)", unknownPart1.data(), unknownPart1Hex.data()) });

    const auto unknownPart2    = nf.ToString(fileInformation.unknown[1], dec);
    const auto unknownPart2Hex = nf2.ToString(fileInformation.unknown[1], hex);
    general->AddItem({ "Unknown Part 2", ls.Format("%-20s (%s)", unknownPart2.data(), unknownPart2Hex.data()) });

    const auto executionCount    = nf.ToString(fileInformation.executionCount, dec);
    const auto executionCountHex = nf2.ToString(fileInformation.executionCount, hex);
    general->AddItem({ "Execution Count", ls.Format("%-20s (%s)", executionCount.data(), executionCountHex.data()) });

    const auto unknown2    = nf.ToString(fileInformation.unknown2, dec);
    const auto unknown2Hex = nf2.ToString(fileInformation.unknown2, hex);
    general->AddItem({ "Unknown 2", ls.Format("%-20s (%s)", unknown2.data(), unknown2Hex.data()) });
}

void Information::UpdateFileInformation_23()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_23>(prefetch->fileInformation);

    const auto unknown0    = nf.ToString(fileInformation.unknown0, dec);
    const auto unknown0Hex = nf2.ToString(fileInformation.unknown0, hex);
    general->AddItem({ "Unknown 0", ls.Format("%-20s (%s)", unknown0.data(), unknown0Hex.data()) });

    DateTime dt;
    dt.CreateFromFileTime(fileInformation.latestExecutionTime);
    const auto latestExecutionTimeHex = nf2.ToString(*(uint64*) &fileInformation.latestExecutionTime, hex);
    general
          ->AddItem(
                { "Latest Execution Time", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), latestExecutionTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    const auto unknown10    = nf.ToString(fileInformation.unknown1[0], dec);
    const auto unknown10Hex = nf2.ToString(fileInformation.unknown1[0], hex);
    general->AddItem({ "Unknown 10", ls.Format("%-20s (%s)", unknown10.data(), unknown10Hex.data()) });

    const auto unknown11    = nf.ToString(fileInformation.unknown1[1], dec);
    const auto unknown11Hex = nf2.ToString(fileInformation.unknown1[1], hex);
    general->AddItem({ "Unknown 11", ls.Format("%-20s (%s)", unknown11.data(), unknown11Hex.data()) });

    const auto executionCount    = nf.ToString(fileInformation.executionCount, dec);
    const auto executionCountHex = nf2.ToString(fileInformation.executionCount, hex);
    general->AddItem({ "Execution Count", ls.Format("%-20s (%s)", executionCount.data(), executionCountHex.data()) });

    const auto unknown2    = nf.ToString(fileInformation.unknown2, dec);
    const auto unknown2Hex = nf2.ToString(fileInformation.unknown2, hex);
    general->AddItem({ "Unknown 2", ls.Format("%-20s (%s)", unknown2.data(), unknown2Hex.data()) });

    ls.Format("");
    for (uint32 i = 0; i < sizeof(fileInformation.unknown3) / sizeof(fileInformation.unknown3[0]); i++)
    {
        ls.AddFormat("%02X", fileInformation.unknown3[i]);
    }
    general->AddItem({ "Unknown 3 (80 bytes)", ls.GetText() });
}

void Information::UpdateFileInformation_26()
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_26>(prefetch->fileInformation);

    const auto unknown    = nf.ToString(fileInformation.unknown0, dec);
    const auto unknownHex = nf2.ToString(fileInformation.unknown0, hex);
    general->AddItem({ "Unknown", ls.Format("%-20s (%s)", unknown.data(), unknownHex.data()) });

    DateTime dt;
    dt.CreateFromFileTime(fileInformation.latestExecutionTime);
    const auto latestExecutionTimeHex = nf2.ToString(fileInformation.latestExecutionTime, hex);
    general
          ->AddItem(
                { "Latest Execution Time", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), latestExecutionTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    for (uint32 i = 0; i < sizeof(fileInformation.olderExecutionTime) / sizeof(fileInformation.olderExecutionTime[0]); i++)
    {
        const auto olderExecutionTimeHex = nf2.ToString(fileInformation.olderExecutionTime[i], hex);
        if (dt.CreateFromFileTime(fileInformation.olderExecutionTime[i]))
        {
            general
                  ->AddItem({ ls.Format("#%u Older Execution Time", i),
                              ls2.Format("%-20s (%s)", dt.GetStringRepresentation().data(), olderExecutionTimeHex.data()) })
                  .SetType(ListViewItem::Type::Emphasized_1);
        }
        else
        {
            general
                  ->AddItem({ ls.Format("#%u Older Execution Time", i), ls2.Format("%-20s (%s)", "Invalid", olderExecutionTimeHex.data()) })
                  .SetType(ListViewItem::Type::WarningInformation);
        }
    }

    const auto unknown1    = nf.ToString(fileInformation.unknown1, dec);
    const auto unknown1Hex = nf2.ToString(fileInformation.unknown1, hex);
    general->AddItem({ "Unknown 1", ls.Format("%-20s (%s)", unknown1.data(), unknown1Hex.data()) });

    const auto unknown2    = nf.ToString(fileInformation.unknown2, dec);
    const auto unknown2Hex = nf2.ToString(fileInformation.unknown2, hex);
    general->AddItem({ "Unknown 2", ls.Format("%-20s (%s)", unknown2.data(), unknown2Hex.data()) });

    const auto executionCount    = nf.ToString(fileInformation.executionCount, dec);
    const auto executionCountHex = nf2.ToString(fileInformation.executionCount, hex);
    general->AddItem({ "Execution Count", ls.Format("%-20s (%s)", executionCount.data(), executionCountHex.data()) });

    const auto unknown3    = nf.ToString(fileInformation.unknown3, dec);
    const auto unknown3Hex = nf2.ToString(fileInformation.unknown3, hex);
    general->AddItem({ "Unknown 3", ls.Format("%-20s (%s)", unknown3.data(), unknown3Hex.data()) });

    const auto unknown4    = nf.ToString(fileInformation.unknown4, dec);
    const auto unknown4Hex = nf2.ToString(fileInformation.unknown4, hex);
    general->AddItem({ "Unknown 4", ls.Format("%-20s (%s)", unknown4.data(), unknown4Hex.data()) });

    ls.Format("");
    for (uint32 i = 0; i < sizeof(fileInformation.unknown5) / sizeof(fileInformation.unknown5[0]); i++)
    {
        ls.AddFormat("%02X", fileInformation.unknown5[i]);
    }
    general->AddItem({ "Unknown 5 (80 bytes)", ls.GetText() });
}

void Information::UpdateFileInformation_30v1()
{
    UpdateFileInformation_26();
}

void Information::UpdateFileInformation_30v2()
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_30v2>(prefetch->fileInformation);

    const auto unknown    = nf.ToString(fileInformation.unknown0, dec);
    const auto unknownHex = nf2.ToString(fileInformation.unknown0, hex);
    general->AddItem({ "Unknown", ls.Format("%-20s (%s)", unknown.data(), unknownHex.data()) });

    DateTime dt;
    dt.CreateFromFileTime(fileInformation.latestExecutionTime);
    const auto latestExecutionTimeHex = nf2.ToString(fileInformation.latestExecutionTime, hex);
    general
          ->AddItem(
                { "Latest Execution Time", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), latestExecutionTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    for (uint32 i = 0; i < sizeof(fileInformation.olderExecutionTime) / sizeof(fileInformation.olderExecutionTime[0]); i++)
    {
        const auto olderExecutionTimeHex = nf2.ToString(fileInformation.olderExecutionTime[i], hex);
        if (dt.CreateFromFileTime(fileInformation.olderExecutionTime[i]))
        {
            general
                  ->AddItem({ ls.Format("#%u Older Execution Time", i),
                              ls2.Format("%-20s (%s)", dt.GetStringRepresentation().data(), olderExecutionTimeHex.data()) })
                  .SetType(ListViewItem::Type::Emphasized_1);
        }
        else
        {
            general
                  ->AddItem({ ls.Format("#%u Older Execution Time", i), ls2.Format("%-20s (%s)", "Invalid", olderExecutionTimeHex.data()) })
                  .SetType(ListViewItem::Type::WarningInformation);
        }
    }

    const auto unknown1    = nf.ToString(fileInformation.unknown1, dec);
    const auto unknown1Hex = nf2.ToString(fileInformation.unknown1, hex);
    general->AddItem({ "Unknown 1", ls.Format("%-20s (%s)", unknown1.data(), unknown1Hex.data()) });

    const auto executionCount    = nf.ToString(fileInformation.executionCount, dec);
    const auto executionCountHex = nf2.ToString(fileInformation.executionCount, hex);
    general->AddItem({ "Execution Count", ls.Format("%-20s (%s)", executionCount.data(), executionCountHex.data()) });

    const auto unknown2    = nf.ToString(fileInformation.unknown2, dec);
    const auto unknown2Hex = nf2.ToString(fileInformation.unknown2, hex);
    general->AddItem({ "Unknown 2", ls.Format("%-20s (%s)", unknown2.data(), unknown2Hex.data()) });

    const auto unknown3    = nf.ToString(fileInformation.unknown3, dec);
    const auto unknown3Hex = nf2.ToString(fileInformation.unknown3, hex);
    general->AddItem({ "Unknown 3", ls.Format("%-20s (%s)", unknown3.data(), unknown3Hex.data()) });

    const auto executablePathOffset    = nf.ToString(fileInformation.executablePathOffset, dec);
    const auto executablePathOffsetHex = nf2.ToString(fileInformation.executablePathOffset, hex);
    general->AddItem({ "Executable Path Offset", ls.Format("%-20s (%s)", executablePathOffset.data(), executablePathOffsetHex.data()) });

    const auto executablePathSize    = nf.ToString(fileInformation.executablePathSize, dec);
    const auto executablePathSizeHex = nf2.ToString(fileInformation.executablePathSize, hex);
    general->AddItem({ "Executable Path Size", ls.Format("%-20s (%s)", executablePathSize.data(), executablePathSizeHex.data()) });

    ls.Format("");
    for (uint32 i = 0; i < sizeof(fileInformation.unknown4) / sizeof(fileInformation.unknown4[0]); i++)
    {
        ls.AddFormat("%02X", fileInformation.unknown4[i]);
    }
    general->AddItem({ "Unknown 4 (76 bytes)", ls.GetText() });
}

void Information::UpdateFileInformation()
{
    UpdateSectionArea();

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        UpdateFileInformation_17();
        break;
    case Magic::WIN_VISTA_7:
        UpdateFileInformation_23();
        break;
    case Magic::WIN_8:
        UpdateFileInformation_26();
        break;
    case Magic::WIN_10:
        if (prefetch->win10Version == Prefetch::Win10Version::V1)
        {
            UpdateFileInformation_30v1();
        }
        else if (prefetch->win10Version == Prefetch::Win10Version::V2)
        {
            UpdateFileInformation_30v2();
        }
        break;
    default:
        break;
    }
}

void Information::RecomputePanelsPositions()
{
    int py = 0;
    int w  = this->GetWidth();
    int h  = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
        return;

    py += (this->general->GetItemsCount() + 3);
    this->general->Resize(w, py);

    if (this->issues->IsVisible())
    {
        this->issues->MoveTo(0, py);
        this->issues->Resize(w, h - py);
    }
}

void Information::UpdateIssues()
{
    issues->SetVisible(issues->GetItemsCount());
}

void Information::Update()
{
    general->DeleteAllItems();
    issues->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateHeader();
    UpdateFileInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
} // namespace GView::Type::Prefetch::Panels
