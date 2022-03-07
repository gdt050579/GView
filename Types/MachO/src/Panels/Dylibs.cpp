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

Dylib::Dylib(Reference<MachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("D&ylib")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Command", TextAlignament::Left, 16);
    list->AddColumn("Size", TextAlignament::Right, 8);
    list->AddColumn("Name", TextAlignament::Left, 100);
    if (machO->is64)
    {
        list->AddColumn("Name Ptr", TextAlignament::Right, 13);
    }
    else
    {
        list->AddColumn("Name Offset", TextAlignament::Right, 13);
    }
    list->AddColumn("Timestamp", TextAlignament::Left, 24);
    list->AddColumn("Current Version", TextAlignament::Right, 25);
    list->AddColumn("Compatibility Version", TextAlignament::Right, 25);

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
    auto di = list->GetItemData<const MachOFile::Dylib>(list->GetCurrentItem());
    win->GetCurrentView()->GoTo(di->offset);
}

void Dylib::SelectCurrentSection()
{
    auto di = list->GetItemData<const MachOFile::Dylib>(list->GetCurrentItem());
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

        list->SetItemData<MachOFile::Dylib>(item, const_cast<MachOFile::Dylib*>(&d));

        list->SetItemText(item, 1, GetValue(n, d.value.cmdsize).data());
        list->SetItemText(item, 2, d.name.c_str());

        if (machO->is64)
        {
            list->SetItemText(item, 3, GetValue(n, (uintptr_t) d.value.dylib.name.ptr).data());
        }
        else
        {
            list->SetItemText(item, 3, GetValue(n, d.value.dylib.name.offset).data());
        }

        const auto timestamp = (time_t) d.value.dylib.timestamp;

        list->SetItemText(item, 4, tmp.Format("%s (%s)", ctime(&timestamp), GetValue(n, d.value.dylib.timestamp).data()));
        list->SetItemText(
              item,
              5,
              tmp.Format(
                    "%u.%u.%u (%s)",
                    d.value.dylib.current_version >> 16,
                    (d.value.dylib.current_version >> 8) & 0xff,
                    d.value.dylib.current_version & 0xff,
                    GetValue(n, d.value.dylib.current_version).data()));
        list->SetItemText(
              item,
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
