#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class Action : int32_t
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Dylib::Dylib(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("D&ylibs")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { { "Command", TextAlignament::Left, 16 },
            { "Size", TextAlignament::Right, 8 },
            { "Name", TextAlignament::Left, 100 },
            { "Name Offset", TextAlignament::Right, 13 },
            { "Timestamp", TextAlignament::Left, 24 },
            { "Current Version", TextAlignament::Right, 25 },
            { "Compatibility Version", TextAlignament::Right, 25 } },
          ListViewFlags::None);

    if (machO->is64)
        list->GetColumn(3).SetText("Name Ptr");

    Update();
}

std::string_view Dylib::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Dylib::GoToSelectedSection()
{
    auto di = list->GetCurrentItem().GetData<MachOFile::Dylib>();

    win->GetCurrentView()->GoTo(di->offset);
}

void Dylib::SelectCurrentSection()
{
    auto di = list->GetCurrentItem().GetData<MachOFile::Dylib>();
    //auto di = list->GetItemData<const MachOFile::Dylib>(list->GetCurrentItem());
    win->GetCurrentView()->Select(di->offset, di->value.cmdsize);
}

void Dylib::Update()
{
    LocalString<128> tmp;
    NumericFormatter n;
    list->DeleteAllItems();

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    for (const auto& d : machO->dylibs)
    {
        tmp.Format(
              "%s (%s)",
              std::string(MAC::LoadCommandNames.at(d.value.cmd)).c_str(),
              GetValue(n, static_cast<uint32_t>(d.value.cmd)).data());
        auto item = list->AddItem(tmp);

        item.SetData<MachOFile::Dylib>(const_cast<MachOFile::Dylib*>(&d));

        item.SetText(1, GetValue(n, d.value.cmdsize).data());
        item.SetText(2, d.name.c_str());

        item.SetText(3, GetValue(n, d.value.dylib.name.offset).data());

        const auto timestamp = (time_t) d.value.dylib.timestamp;
        item.SetText(4, tmp.Format("%s (%s)", ctime(&timestamp), GetValue(n, d.value.dylib.timestamp).data()));
        item.SetText(
              5,
              tmp.Format(
                    "%u.%u.%u (%s)",
                    d.value.dylib.current_version >> 16,
                    (d.value.dylib.current_version >> 8) & 0xff,
                    d.value.dylib.current_version & 0xff,
                    GetValue(n, d.value.dylib.current_version).data()));
        item.SetText(
              6,
              tmp.Format(
                    "%u.%u.%u (%s)",
                    d.value.dylib.compatibility_version >> 16,
                    (d.value.dylib.compatibility_version >> 8) & 0xff,
                    d.value.dylib.compatibility_version & 0xff,
                    GetValue(n, d.value.dylib.compatibility_version).data()));
    }
}

bool Dylib::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(Action::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(Action::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(Action::ChangeBase));

    return true;
}

bool Dylib::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemClicked)
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
            Base = 26 - Base;
            Update();
            return true;
        case Action::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}
} // namespace GView::Type::MachO::Panels
