#include "prefetch.hpp"

namespace GView::Type::Prefetch::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class Action : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

FileInformationEntry::FileInformationEntry(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win)
    : TabPage("&ASection")
{
    prefetch = _prefetch;
    win      = _win;
    base     = 16;

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        list = Factory::ListView::Create(
              this,
              "d:c",
              { { "Start Time", TextAlignament::Right, 12 },
                { "Duration", TextAlignament::Right, 10 },
                { "Filename Offset", TextAlignament::Right, 18 },
                { "Filename Size", TextAlignament::Right, 16 },
                { "Unknown", TextAlignament::Right, 10 },
                { "Path", TextAlignament::Right, 140 } },
              ListViewFlags::None);

        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
        list = Factory::ListView::Create(
              this,
              "d:c",
              { { "Start Time", TextAlignament::Right, 12 },
                { "Duration", TextAlignament::Right, 10 },
                { "Average Duration", TextAlignament::Right, 20 },
                { "Filename Offset", TextAlignament::Right, 18 },
                { "Filename Size", TextAlignament::Right, 16 },
                { "Unknown", TextAlignament::Right, 10 },
                { "NTFS File Reference", TextAlignament::Right, 24 },
                { "Path", TextAlignament::Right, 100 } },
              ListViewFlags::None);
        break;
    case Magic::WIN_10:
    default:
        break;
    }

    Update();
}

std::string_view FileInformationEntry::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void FileInformationEntry::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void FileInformationEntry::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void FileInformationEntry::Update_17()
{
    LocalString<128> tmp;
    NumericFormatter n;

    auto& fileInformation = std::get<FileInformation_17>(prefetch->fileInformation);

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = prefetch->bufferSectionAEntries.GetObject<FileMetricsEntryRecord_17>(sizeof(FileMetricsEntryRecord_17) * i);

        auto item = list->AddItem({ tmp.Format("%s", GetValue(n, entry->startTime).data()) });
        item.SetText(1, tmp.Format("%s", GetValue(n, entry->duration).data()));
        item.SetText(2, tmp.Format("%s", GetValue(n, entry->filenameOffset).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, entry->filenameSize).data()));
        item.SetText(4, tmp.Format("%s", GetValue(n, entry->unknown).data()));

        ConstString cs(
              std::u16string_view{ (char16_t*) (prefetch->bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize });
        LocalUnicodeStringBuilder<512> lusb;
        lusb.Set(cs);
        std::string filename;
        lusb.ToString(filename);

        item.SetText(5, filename.c_str());

        item.SetData<FileMetricsEntryRecord_17>(
              (FileMetricsEntryRecord_17*) (prefetch->bufferSectionAEntries.GetData() + sizeof(FileMetricsEntryRecord_17) * i));

        if (prefetch->exePath.compare(filename) == 0)
        {
            item.SetType(ListViewItem::Type::Emphasized_2);
        }
    }
}

void FileInformationEntry::Update_23()
{
    auto& fileInformation = std::get<FileInformation_23>(prefetch->fileInformation);
    Update_23_26(fileInformation.sectionA.entries);
}

void FileInformationEntry::Update_26()
{
    auto& fileInformation = std::get<FileInformation_26>(prefetch->fileInformation);
    Update_23_26(fileInformation.sectionA.entries);
}

void FileInformationEntry::Update_23_26(uint32 sectionAEntries)
{
    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0U; i < sectionAEntries; i++)
    {
        const auto offset = sizeof(FileMetricsEntryRecord_23_26) * i;
        auto entry        = prefetch->bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23_26>(offset);

        auto item = list->AddItem({ tmp.Format("%s", GetValue(n, entry->startTime).data()) });
        item.SetText(1, tmp.Format("%s", GetValue(n, entry->duration).data()));
        item.SetText(2, tmp.Format("%s", GetValue(n, entry->averageDuration).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, entry->filenameOffset).data()));
        item.SetText(4, tmp.Format("%s", GetValue(n, entry->filenameSize).data()));
        item.SetText(5, tmp.Format("%s", GetValue(n, entry->unknown).data()));
        item.SetText(6, tmp.Format("%s", GetValue(n, entry->ntfsFileReference).data()));

        ConstString cs(
              std::u16string_view{ (char16_t*) (prefetch->bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize });
        LocalUnicodeStringBuilder<512> lusb;
        lusb.Set(cs);
        std::string filename;
        lusb.ToString(filename);

        item.SetText(7, filename.c_str());

        item.SetData<FileMetricsEntryRecord_23_26>(
              (FileMetricsEntryRecord_23_26*) (prefetch->bufferSectionAEntries.GetData() + sizeof(FileMetricsEntryRecord_23_26) * i));

        if (prefetch->exePath.compare(filename) == 0)
        {
            item.SetType(ListViewItem::Type::Emphasized_2);
        }
    }
}

void FileInformationEntry::Update()
{
    list->DeleteAllItems();

    CHECKRET(prefetch->bufferSectionAEntries.IsValid(), "");

    // TODO: global issues in prefetch!

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        Update_17();
        break;
    case Magic::WIN_VISTA_7:
        Update_23();
        break;
    case Magic::WIN_8:
        Update_26();
        break;
    case Magic::WIN_10:
    default:
        break;
    }
}

bool FileInformationEntry::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool FileInformationEntry::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<Action>(controlID))
        {
        case Action::GoTo:
            GoToSelectedSection();
            return true;
        case Action::ChangeBase:
            base = 26 - base;
            Update();
            return true;
        case Action::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::Prefetch::Panels
