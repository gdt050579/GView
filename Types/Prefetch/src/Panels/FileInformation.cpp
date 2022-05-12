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
              { "n:Start Time,a:r,w:12",
                "n:Duration,a:r,w:10",
                "n:Filename Offset,a:r,w:18",
                "n:Filename Size,a:r,w:16",
                "n:Unknown,a:r,w:10",
                "n:Path,a:r,w:140" },
              ListViewFlags::None);

        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
    case Magic::WIN_10:
        list = Factory::ListView::Create(
              this,
              "d:c",
              { "n:Start Time,a:r,w:12",
                "n:Duration,a:r,w:10",
                "n:Average Duration,a:r,w:20",
                "n:Filename Offset,a:r,w:18",
                "n:Filename Size,a:r,w:16",
                "n:Unknown,a:r,w:10",
                "n:NTFS File Reference,a:r,w:24",
                "n:Path,a:r,w:100" },
              ListViewFlags::None);
        break;
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

    for (auto i = 0U; i < prefetch->area.sectionA.entries; i++)
    {
        auto entry = prefetch->bufferSectionA.GetObject<FileMetricsEntryRecord_17>(sizeof(FileMetricsEntryRecord_17) * i);

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
              (FileMetricsEntryRecord_17*) (prefetch->bufferSectionA.GetData() + sizeof(FileMetricsEntryRecord_17) * i));

        if (prefetch->exePath.compare(filename) == 0)
        {
            item.SetType(ListViewItem::Type::Emphasized_2);
        }
    }
}

void FileInformationEntry::Update_23_26_30()
{
    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0U; i < prefetch->area.sectionA.entries; i++)
    {
        const auto offset = (uint32) sizeof(FileMetricsEntryRecord_23_26_30) * i;
        auto entry        = prefetch->bufferSectionA.GetObject<FileMetricsEntryRecord_23_26_30>(offset);

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

        item.SetData<FileMetricsEntryRecord_23_26_30>(
              (FileMetricsEntryRecord_23_26_30*) (prefetch->bufferSectionA.GetData() + sizeof(FileMetricsEntryRecord_23_26_30) * i));

        if (prefetch->exePath.compare(filename) == 0)
        {
            item.SetType(ListViewItem::Type::Emphasized_2);
        }
    }
}

void FileInformationEntry::Update()
{
    list->DeleteAllItems();

    CHECKRET(prefetch->bufferSectionA.IsValid(), "");

    // TODO: global issues in prefetch!

    switch (prefetch->header.version)
    {
    case Magic::WIN_XP_2003:
        Update_17();
        break;
    case Magic::WIN_VISTA_7:
    case Magic::WIN_8:
    case Magic::WIN_10:
        Update_23_26_30();
        break;
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
