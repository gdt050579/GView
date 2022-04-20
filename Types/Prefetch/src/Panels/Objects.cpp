#include "prefetch.hpp"

namespace GView::Type::Prefetch::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Objects::Objects(Reference<PrefetchFile> _prefetch, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    prefetch = _prefetch;
    win      = _win;
    Base     = 16;

    list = Factory::ListView::Create(this, "d:c", { { "Placeholder", TextAlignament::Right, 10 } }, ListViewFlags::None);

    Update();
}

std::string_view Objects::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Objects::GoToSelectedSection()
{
    win->GetCurrentView()->GoTo(0);
}

void Panels::Objects::SelectCurrentSection()
{
    win->GetCurrentView()->Select(0, 0);
}

void Panels::Objects::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    // for (auto i = 0ULL; i < iso->records.size(); i++)
    // {
    //     const auto& record = iso->records[i];
    //     auto item          = list->AddItem({ tmp.Format("%s", GetValue(n, record.lengthOfDirectoryRecord).data()) });
    //     item.SetText(1, tmp.Format("%s", GetValue(n, record.extendedAttributeRecordLength).data()));
    //
    //     item.SetData<ECMA_119_DirectoryRecord>(&iso->records[i]);
    // }
}

bool Panels::Objects::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Panels::Objects::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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
} // namespace GView::Type::Prefetch::Panels
