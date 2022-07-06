#include "JT.hpp"

namespace GView::Type::JT::Panels
{
using namespace AppCUI::Application;
using namespace AppCUI::Endian;
using namespace AppCUI::Input;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Segments::Segments(Reference<JTFile> _jt, Reference<GView::View::WindowInterface> _win) : TabPage("&Segments")
{
    jt   = _jt;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:#,a:r,w:6",
            "n:Segment ID,a:l,w:38",
            "n:Segment Offset,a:l,w:16",
            "n:Segment Length,a:l,w:16",
            "n:Segment Attributes,a:l,w:60" },
          ListViewFlags::None);

    Update();
}

std::string_view Segments::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Segments::GoToSelectedSection()
{
    auto record = list->GetCurrentItem().GetData<TOCEntry>();
    win->GetCurrentView()->GoTo(record->segmentOffset);
}

void Segments::SelectCurrentSection()
{
    auto record = list->GetCurrentItem().GetData<TOCEntry>();
    win->GetCurrentView()->Select(record->segmentOffset, record->segmentLength);
}

void Segments::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0ULL; i < jt->tc.entries.size(); i++)
    {
        auto& record = jt->tc.entries.at(i);

        auto item = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });

        item.SetText(
              1,
              tmp.Format(
                    "%s",
                    tmp.Format(
                             "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                             record.segmentID.a,
                             record.segmentID.b,
                             record.segmentID.c,
                             record.segmentID.d[0],
                             record.segmentID.d[1],
                             record.segmentID.d[2],
                             record.segmentID.d[3],
                             record.segmentID.d[4],
                             record.segmentID.d[5],
                             record.segmentID.d[6],
                             record.segmentID.d[7])
                          .data()));

        item.SetText(2, tmp.Format("%s", GetValue(n, record.segmentOffset).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, record.segmentLength).data()));

        const auto attrs = GetSegmentAttributes(record.segmentAttributes);
        item.SetText(4, tmp.Format("%-10s %s", GetValue(n, record.segmentAttributes).data(), attrs.data()));

        item.SetData<TOCEntry>(&record);
    }
}

bool Segments::OnUpdateCommandBar(CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Segments::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemPressed)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<ObjectAction>(controlID))
        {
        case ObjectAction::GoTo:
            GoToSelectedSection();
            return true;
        case ObjectAction::ChangeBase:
            Base = 26 - Base;
            Update();
            return true;
        case ObjectAction::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::JT::Panels
