#include "MachOFB.hpp"

namespace GView::Type::MachOFB::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

template <typename T>
struct Identity
{
    typedef T type;
};

enum class ObjectAction : int32_t
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Objects::Objects(Reference<MachOFBFile> _fat, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    fat  = _fat;
    win  = _win;
    Base = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Name", TextAlignament::Right, 10);
    list->AddColumn("Description", TextAlignament::Right, 25);
    list->AddColumn("CPU type", TextAlignament::Right, 20);
    list->AddColumn("CPU subtype", TextAlignament::Right, 30);
    list->AddColumn("Offset", TextAlignament::Right, 12);
    list->AddColumn("Size", TextAlignament::Right, 12);
    list->AddColumn("Align", TextAlignament::Right, 12);

    Update();
}

std::string_view Objects::GetValue(NumericFormatter& n, uint64_t value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Objects::GoToSelectedSection()
{
    const auto& vArch = list->GetItemData<Identity<decltype(fat->archs)>::type::value_type>(list->GetCurrentItem())
                              .
                              operator Identity<decltype(fat->archs)>::type::value_type&();

    uint64_t offset = 0;

    switch (vArch.index())
    {
    case 0:
    {
        const auto& arch = std::get<0>(vArch);
        offset           = arch.offset;
    }
    break;
    case 1:
    {
        const auto& arch = std::get<1>(vArch);
        offset           = arch.offset;
    }
    break;
    default:
        break;
    }

    win->GetCurrentView()->GoTo(offset);
}

void Panels::Objects::SelectCurrentSection()
{
    const auto& vArch = list->GetItemData<Identity<decltype(fat->archs)>::type::value_type>(list->GetCurrentItem())
                              .
                              operator Identity<decltype(fat->archs)>::type::value_type&();

    uint64_t offset = 0;
    uint64_t size   = 0;

    switch (vArch.index())
    {
    case 0:
    {
        const auto& arch = std::get<0>(vArch);
        offset           = arch.offset;
        size             = arch.size;
    }
    break;
    case 1:
    {
        const auto& arch = std::get<1>(vArch);
        offset           = arch.offset;
        size             = arch.size;
    }
    break;
    default:
        break;
    }

    win->GetCurrentView()->Select(offset, size);
}

void Panels::Objects::Update()
{
    LocalString<128> temp;
    NumericFormatter n;
    list->DeleteAllItems();

    for (decltype(fat->header.nfat_arch) i = 0U; i < fat->header.nfat_arch; i++)
    {
        const auto& ai = fat->archsInfo[i];

        temp.Format("#%lu %s", i, ai.name.c_str());
        auto item = list->AddItem(temp); // name
        list->SetItemText(item, 1, ai.description.c_str());

        list->SetItemData<Identity<decltype(fat->archs)>::type::value_type>(item, &fat->archs[i]);

        MAC::CPU_TYPE cputype{};
        uint32_t cpusubtype{};
        uint64_t offset{};
        uint64_t size{};
        uint64_t align{};

        switch (fat->archs[i].index())
        {
        case 0:
        {
            const auto& arch = std::get<0>(fat->archs[i]);
            cputype          = arch.cputype;
            cpusubtype       = arch.cpusubtype;
            offset           = arch.offset;
            size             = arch.size;
            align            = arch.align;
        }
        break;
        case 1:
        {
            const auto& arch = std::get<1>(fat->archs[i]);
            cputype          = arch.cputype;
            cpusubtype       = arch.cpusubtype;
            offset           = arch.offset;
            size             = arch.size;
            align            = arch.align;
        }
        break;
        default:
            break;
        }

        list->SetItemText(item, 2, MAC::CpuTypeNames.at(cputype));
        list->SetItemText(
              item,
              3,
              std::string(MAC::GetCPUSubtype(cputype, static_cast<uint32_t>(cpusubtype))) + " (" + std::to_string(cpusubtype) + ")");
        list->SetItemText(item, 4, GetValue(n, offset));
        list->SetItemText(item, 5, GetValue(n, size));
        list->SetItemText(item, 6, GetValue(n, align));
    }
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

    if (evnt == Event::ListViewItemClicked)
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

} // namespace GView::Type::MachOFB::Panels
