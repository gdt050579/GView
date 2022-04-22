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
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { { "Info", TextAlignament::Left, 200 } }, ListViewFlags::HideColumns);

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
        issues->AddItem({ "Filesize validation failed!" });
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

    const auto hash    = nf.ToString(prefetch->header.H6, dec);
    const auto hashHex = nf2.ToString(prefetch->header.H6, hex);
    auto hashItem      = general->AddItem({ "Hash", ls.Format("%-20s (%s)", hash.data(), hashHex.data()) });

    // hash validation
    if (prefetch->hashComputed != 0)
    {
        const auto pos  = object->GetName().find_last_of('-');
        const auto pos2 = object->GetName().find_last_of('.');
        if (pos != std::string::npos && pos2 != std::string::npos)
        {
            std::string hashFromName;
            {
                ConstString cs{ std::u16string_view(object->GetName().data() + pos + 1, pos2 - (pos + 1)) };
                LocalUnicodeStringBuilder<sizeof(prefetch->header.executableName) / sizeof(prefetch->header.executableName[0])> lsub;
                lsub.Set(cs);
                lsub.ToString(hashFromName);
            }

            const auto hashHex = ls.Format("%08X", prefetch->header.H6);

            if (hashFromName.compare(hashHex) == 0)
            {
                const auto computedHashHex = ls.Format("%08X", prefetch->hashComputed);
                if (hashFromName.compare(computedHashHex) == 0)
                {
                    hashItem.SetType(ListViewItem::Type::Emphasized_2);
                }
                else
                {
                    LocalString<64> ls2;
                    issues->AddItem(
                          { ls2.Format("Hash validation failed when compared to computed hash (0x%s)!", computedHashHex.data()) });
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
            issues->AddItem({ "Hash validation failed when comparing to filename." });
            hashItem.SetType(ListViewItem::Type::ErrorInformation);
        }
    }
    else
    {
        issues->AddItem({ "Hash validation failed - computed hash not found!" });
        hashItem.SetType(ListViewItem::Type::ErrorInformation);
    }

    const auto h7    = nf.ToString(prefetch->header.H7, dec);
    const auto h7Hex = nf2.ToString(prefetch->header.H7, hex);
    general->AddItem({ "H7", ls.Format("%-20s (%s)", h7.data(), h7Hex.data()) });
}

void Information::UpdateFileInformation_17()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    general->AddItem("File Information").SetType(ListViewItem::Type::Category);
    const auto sectionAOffset    = nf.ToString(fileInformation.sectionA.offset, dec);
    const auto sectionAOffsetHex = nf2.ToString(fileInformation.sectionA.offset, hex);
    general->AddItem({ "Section A Offset", ls.Format("%-20s (%s)", sectionAOffset.data(), sectionAOffsetHex.data()) });

    const auto sectionAEntries    = nf.ToString(fileInformation.sectionA.entries, dec);
    const auto sectionAEntriesHex = nf2.ToString(fileInformation.sectionA.entries, hex);
    general->AddItem({ "Section A Entries", ls.Format("%-20s (%s)", sectionAEntries.data(), sectionAEntriesHex.data()) });

    const auto sectionBOffset    = nf.ToString(fileInformation.sectionB.offset, dec);
    const auto sectionBOffsetHex = nf2.ToString(fileInformation.sectionB.offset, hex);
    general->AddItem({ "Section B Offset", ls.Format("%-20s (%s)", sectionBOffset.data(), sectionBOffsetHex.data()) });

    const auto sectionBEntries    = nf.ToString(fileInformation.sectionB.entries, dec);
    const auto sectionBEntriesHex = nf2.ToString(fileInformation.sectionB.entries, hex);
    general->AddItem({ "Section B Entries", ls.Format("%-20s (%s)", sectionBEntries.data(), sectionBEntriesHex.data()) });

    const auto sectionCOffset    = nf.ToString(fileInformation.sectionC.offset, dec);
    const auto sectionCOffsetHex = nf2.ToString(fileInformation.sectionC.offset, hex);
    general->AddItem({ "Section C Offset", ls.Format("%-20s (%s)", sectionCOffset.data(), sectionCOffsetHex.data()) });

    const auto sectionCLength    = nf.ToString(fileInformation.sectionC.length, dec);
    const auto sectionCLengthHex = nf2.ToString(fileInformation.sectionC.length, hex);
    general->AddItem({ "Section C Length", ls.Format("%-20s (%s)", sectionCLength.data(), sectionCLengthHex.data()) });

    const auto sectionDOffset    = nf.ToString(fileInformation.sectionD.offset, dec);
    const auto sectionDOffsetHex = nf2.ToString(fileInformation.sectionD.offset, hex);
    general->AddItem({ "Section D Offset", ls.Format("%-20s (%s)", sectionDOffset.data(), sectionDOffsetHex.data()) });

    const auto sectionDEntries    = nf.ToString(fileInformation.sectionD.entries, dec);
    const auto sectionDEntriesHex = nf2.ToString(fileInformation.sectionD.entries, hex);
    general->AddItem({ "Section D Entries", ls.Format("%-20s (%s)", sectionDEntries.data(), sectionDEntriesHex.data()) });

    const auto sectionDSize    = nf.ToString(fileInformation.sectionD.size, dec);
    const auto sectionDSizeHex = nf2.ToString(fileInformation.sectionD.size, hex);
    general->AddItem({ "Section D Size", ls.Format("%-20s (%s)", sectionDSize.data(), sectionDSizeHex.data()) });

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

    general->AddItem("File Information").SetType(ListViewItem::Type::Category);
    const auto sectionAOffset    = nf.ToString(fileInformation.sectionA.offset, dec);
    const auto sectionAOffsetHex = nf2.ToString(fileInformation.sectionA.offset, hex);
    general->AddItem({ "Section A Offset", ls.Format("%-20s (%s)", sectionAOffset.data(), sectionAOffsetHex.data()) });

    const auto sectionAEntries    = nf.ToString(fileInformation.sectionA.entries, dec);
    const auto sectionAEntriesHex = nf2.ToString(fileInformation.sectionA.entries, hex);
    general->AddItem({ "Section A Entries", ls.Format("%-20s (%s)", sectionAEntries.data(), sectionAEntriesHex.data()) });

    const auto sectionBOffset    = nf.ToString(fileInformation.sectionB.offset, dec);
    const auto sectionBOffsetHex = nf2.ToString(fileInformation.sectionB.offset, hex);
    general->AddItem({ "Section B Offset", ls.Format("%-20s (%s)", sectionBOffset.data(), sectionBOffsetHex.data()) });

    const auto sectionBEntries    = nf.ToString(fileInformation.sectionB.entries, dec);
    const auto sectionBEntriesHex = nf2.ToString(fileInformation.sectionB.entries, hex);
    general->AddItem({ "Section B Entries", ls.Format("%-20s (%s)", sectionBEntries.data(), sectionBEntriesHex.data()) });

    const auto sectionCOffset    = nf.ToString(fileInformation.sectionC.offset, dec);
    const auto sectionCOffsetHex = nf2.ToString(fileInformation.sectionC.offset, hex);
    general->AddItem({ "Section C Offset", ls.Format("%-20s (%s)", sectionCOffset.data(), sectionCOffsetHex.data()) });

    const auto sectionCLength    = nf.ToString(fileInformation.sectionC.length, dec);
    const auto sectionCLengthHex = nf2.ToString(fileInformation.sectionC.length, hex);
    general->AddItem({ "Section C Length", ls.Format("%-20s (%s)", sectionCLength.data(), sectionCLengthHex.data()) });

    const auto sectionDOffset    = nf.ToString(fileInformation.sectionD.offset, dec);
    const auto sectionDOffsetHex = nf2.ToString(fileInformation.sectionD.offset, hex);
    general->AddItem({ "Section D Offset", ls.Format("%-20s (%s)", sectionDOffset.data(), sectionDOffsetHex.data()) });

    const auto sectionDEntries    = nf.ToString(fileInformation.sectionD.entries, dec);
    const auto sectionDEntriesHex = nf2.ToString(fileInformation.sectionD.entries, hex);
    general->AddItem({ "Section D Entries", ls.Format("%-20s (%s)", sectionDEntries.data(), sectionDEntriesHex.data()) });

    const auto sectionDSize    = nf.ToString(fileInformation.sectionD.size, dec);
    const auto sectionDSizeHex = nf2.ToString(fileInformation.sectionD.size, hex);
    general->AddItem({ "Section D Size", ls.Format("%-20s (%s)", sectionDSize.data(), sectionDSizeHex.data()) });

    const auto unknown0    = nf.ToString(fileInformation.unknown[0], dec);
    const auto unknown0Hex = nf2.ToString(fileInformation.unknown[0], hex);
    general->AddItem({ "Unknown Part 1", ls.Format("%-20s (%s)", unknown0.data(), unknown0Hex.data()) });

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

    general->AddItem({ "Unknown array (80 bytes)" });
}

void Information::UpdateFileInformation_26()
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    auto& fileInformation = std::get<FileInformation_26>(prefetch->fileInformation);

    general->AddItem("File Information").SetType(ListViewItem::Type::Category);
    const auto sectionAOffset    = nf.ToString(fileInformation.sectionA.offset, dec);
    const auto sectionAOffsetHex = nf2.ToString(fileInformation.sectionA.offset, hex);
    general->AddItem({ "Section A Offset", ls.Format("%-20s (%s)", sectionAOffset.data(), sectionAOffsetHex.data()) });

    const auto sectionAEntries    = nf.ToString(fileInformation.sectionA.entries, dec);
    const auto sectionAEntriesHex = nf2.ToString(fileInformation.sectionA.entries, hex);
    general->AddItem({ "Section A Entries", ls.Format("%-20s (%s)", sectionAEntries.data(), sectionAEntriesHex.data()) });

    const auto sectionBOffset    = nf.ToString(fileInformation.sectionB.offset, dec);
    const auto sectionBOffsetHex = nf2.ToString(fileInformation.sectionB.offset, hex);
    general->AddItem({ "Section B Offset", ls.Format("%-20s (%s)", sectionBOffset.data(), sectionBOffsetHex.data()) });

    const auto sectionBEntries    = nf.ToString(fileInformation.sectionB.entries, dec);
    const auto sectionBEntriesHex = nf2.ToString(fileInformation.sectionB.entries, hex);
    general->AddItem({ "Section B Entries", ls.Format("%-20s (%s)", sectionBEntries.data(), sectionBEntriesHex.data()) });

    const auto sectionCOffset    = nf.ToString(fileInformation.sectionC.offset, dec);
    const auto sectionCOffsetHex = nf2.ToString(fileInformation.sectionC.offset, hex);
    general->AddItem({ "Section C Offset", ls.Format("%-20s (%s)", sectionCOffset.data(), sectionCOffsetHex.data()) });

    const auto sectionCLength    = nf.ToString(fileInformation.sectionC.length, dec);
    const auto sectionCLengthHex = nf2.ToString(fileInformation.sectionC.length, hex);
    general->AddItem({ "Section C Length", ls.Format("%-20s (%s)", sectionCLength.data(), sectionCLengthHex.data()) });

    const auto sectionDOffset    = nf.ToString(fileInformation.sectionD.offset, dec);
    const auto sectionDOffsetHex = nf2.ToString(fileInformation.sectionD.offset, hex);
    general->AddItem({ "Section D Offset", ls.Format("%-20s (%s)", sectionDOffset.data(), sectionDOffsetHex.data()) });

    const auto sectionDEntries    = nf.ToString(fileInformation.sectionD.entries, dec);
    const auto sectionDEntriesHex = nf2.ToString(fileInformation.sectionD.entries, hex);
    general->AddItem({ "Section D Entries", ls.Format("%-20s (%s)", sectionDEntries.data(), sectionDEntriesHex.data()) });

    const auto sectionDSize    = nf.ToString(fileInformation.sectionD.size, dec);
    const auto sectionDSizeHex = nf2.ToString(fileInformation.sectionD.size, hex);
    general->AddItem({ "Section D Size", ls.Format("%-20s (%s)", sectionDSize.data(), sectionDSizeHex.data()) });

    const auto unknown0    = nf.ToString(fileInformation.unknown[0], dec);
    const auto unknown0Hex = nf2.ToString(fileInformation.unknown[0], hex);
    general->AddItem({ "Unknown Part 1", ls.Format("%-20s (%s)", unknown0.data(), unknown0Hex.data()) });

    DateTime dt;
    dt.CreateFromFileTime(fileInformation.latestExecutionTime);
    const auto latestExecutionTimeHex = nf2.ToString(fileInformation.latestExecutionTime, hex);
    general
          ->AddItem(
                { "Latest Execution Time", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), latestExecutionTimeHex.data()) })
          .SetType(ListViewItem::Type::Emphasized_1);

    for (uint32 i = 0; i < sizeof(fileInformation.olderExecutionTime) / sizeof(fileInformation.olderExecutionTime[0]); i++)
    {
        dt.CreateFromFileTime(fileInformation.olderExecutionTime[i]);
        const auto olderExecutionTimeHex = nf2.ToString(fileInformation.olderExecutionTime[i], hex);
        general
              ->AddItem({ ls.Format("#%u Older Execution Time", i),
                          ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), olderExecutionTimeHex.data()) })
              .SetType(ListViewItem::Type::Emphasized_1);
    }

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

    const auto unknown3    = nf.ToString(fileInformation.unknown3, dec);
    const auto unknown3Hex = nf2.ToString(fileInformation.unknown3, hex);
    general->AddItem({ "Unknown 2", ls.Format("%-20s (%s)", unknown3.data(), unknown3Hex.data()) });

    general->AddItem({ "Unknown array (80 bytes)" });
}

void Information::UpdateFileInformation()
{
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
    default:
        break;
    }
}

void Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
        return;
    if (this->issues->IsVisible())
        last = 1;
    // if (InfoPanelCtx.pnlIcon->IsVisible()) last = 3;

    // resize
    if (last == 0)
    {
        this->general->Resize(w, h - py);
    }
    else
    {
        if (this->general->GetItemsCount() > 15)
        {
            this->general->Resize(w, 18);
            py += 18;
        }
        else
        {
            this->general->Resize(w, this->general->GetItemsCount() + 3);
            py += (this->general->GetItemsCount() + 3);
        }
    }

    if (this->issues->IsVisible())
    {
        this->issues->MoveTo(0, py);
        if (last == 1)
        {
            this->issues->Resize(w, h - py);
        }
        else
        {
            if (this->issues->GetItemsCount() > 6)
            {
                this->issues->Resize(w, 8);
                py += 8;
            }
            else
            {
                this->issues->Resize(w, this->issues->GetItemsCount() + 2);
                py += (this->issues->GetItemsCount() + 2);
            }
        }
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
