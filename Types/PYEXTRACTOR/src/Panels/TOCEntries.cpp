#include <pyextractor.hpp>

using namespace GView::Type::PYEXTRACTOR;
using namespace GView::Type::PYEXTRACTOR::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int ENTRY_GOTO       = 1;
constexpr int ENTRY_SELECT     = 2;
constexpr int ENTRY_CHANGEBASE = 3;
constexpr int ENTRY_OPEN       = 4;

TOCEntries::TOCEntries(Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> _py, Reference<GView::View::WindowInterface> _win) : TabPage("T&OCEntries")
{
    py   = _py;
    win  = _win;
    base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:6",
            "n:Name,w:50",
            "n:Size,a:r,w:8",
            "n:Position,a:r,w:14",
            "n:Compressed Data Size,a:r,w:26",
            "n:Uncompressed Data Size,a:r,w:26",
            "n:Commpression Flag,a:r,w:20",
            "n:Type Compression Data,a:r,w:26" },
          ListViewFlags::None);

    Update();
}

std::string_view TOCEntries::GetValue(NumericFormatter& n, uint32 value)
{
    if (base == 10)
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    else
        return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void TOCEntries::GoToSelectedEntry()
{
    auto entry = list->GetCurrentItem().GetData<PYEXTRACTOR::TOCEntry>();
    if (entry.IsValid()) {
        win->GetCurrentView()->GoTo(entry->entryPos);
    }
}

void TOCEntries::SelectCurrentEntry()
{
    auto entry = list->GetCurrentItem().GetData<PYEXTRACTOR::TOCEntry>();
    if (entry.IsValid()) {
        win->GetCurrentView()->Select(entry->entryPos, entry->entrySize);
    }
}

void TOCEntries::OpenCurrentEntry()
{
    auto entry       = list->GetCurrentItem().GetData<PYEXTRACTOR::TOCEntry>();
    const auto& pos  = entry->entryPos;
    const auto& size = entry->cmprsdDataSize;

    const auto bufferCompressed = py->obj->GetData().CopyToBuffer(pos, size);
    CHECKRET(bufferCompressed.IsValid(), "");

    Buffer bufferDecompressed{};
    CHECKRET(Decoding::ZLIB::Decompress(bufferCompressed, bufferCompressed.GetLength(), bufferDecompressed, entry->uncmprsdDataSize), "");

    LocalUnicodeStringBuilder<2048> fullPath;
    fullPath.Add(py->obj->GetPath());
    fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
    fullPath.Add(entry->name);

    GView::App::OpenBuffer(BufferView{ bufferDecompressed }, entry->name, fullPath, GView::App::OpenMethod::BestMatch);
}

void TOCEntries::Update()
{
    NumericFormatter n;
    LocalString<128> tmp;
    list->DeleteAllItems();

    for (auto i = 0U; i < py->tocEntries.size(); i++) {
        auto& entry = py->tocEntries.at(i);
        auto item   = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });
        item.SetData<PYEXTRACTOR::TOCEntry>(&py->tocEntries.at(i));

        item.SetText(1, std::string_view{ reinterpret_cast<char*>(entry.name.GetData()), entry.name.GetLength() });
        item.SetText(2, GetValue(n, entry.entrySize));
        item.SetText(3, GetValue(n, entry.entryPos));
        item.SetText(4, GetValue(n, entry.cmprsdDataSize));
        item.SetText(5, GetValue(n, entry.uncmprsdDataSize));
        item.SetText(6, GetValue(n, entry.cmprsFlag));
        item.SetText(7, GetValue(n, entry.typeCmprsData));
    }
}

bool TOCEntries::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", ENTRY_GOTO);
    commandBar.SetCommand(Key::F9, "Select", ENTRY_SELECT);
    if (base == 10) {
        commandBar.SetCommand(Key::F2, "Dec", ENTRY_CHANGEBASE);
    } else {
        commandBar.SetCommand(Key::F2, "Hex", ENTRY_CHANGEBASE);
    }
    commandBar.SetCommand(Key::Ctrl | Key::O, "Open", ENTRY_OPEN);

    return true;
}

bool TOCEntries::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemPressed) {
        GoToSelectedEntry();
        return true;
    }
    if (evnt == Event::Command) {
        switch (controlID) {
        case ENTRY_GOTO:
            GoToSelectedEntry();
            return true;
        case ENTRY_CHANGEBASE:
            base = 26 - base;
            Update();
            return true;
        case ENTRY_SELECT:
            SelectCurrentEntry();
        case ENTRY_OPEN:
            OpenCurrentEntry();
            return true;
        }
    }
    return false;
}
