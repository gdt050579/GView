#include "UniversalMachO.hpp"

namespace GView::Type::UniversalMachO::Panels
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

Objects::Objects(Reference<UniversalMachOFile> _machO, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    machO = _machO;
    win   = _win;
    Base  = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("CPU type", TextAlignament::Right, 25);
    list->AddColumn("CPU subtype", TextAlignament::Right, 25);
    list->AddColumn("File type", TextAlignament::Left, 80);
    list->AddColumn("Offset", TextAlignament::Right, 12);
    list->AddColumn("Size", TextAlignament::Right, 12);
    list->AddColumn("Align", TextAlignament::Right, 12);
    list->AddColumn("Real Align", TextAlignament::Right, 12);

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
    const auto& arch = list->GetItemData<Identity<decltype(machO->archs)>::type::value_type>(list->GetCurrentItem())
                             .
                             operator Identity<decltype(machO->archs)>::type::value_type&();
    win->GetCurrentView()->GoTo(arch.offset);
}

void Panels::Objects::SelectCurrentSection()
{
    const auto& arch = list->GetItemData<Identity<decltype(machO->archs)>::type::value_type>(list->GetCurrentItem())
                             .
                             operator Identity<decltype(machO->archs)>::type::value_type&();
    win->GetCurrentView()->Select(arch.offset, arch.size);
}

void Panels::Objects::Update()
{
    LocalString<128> tmp;
    NumericFormatter n;

    list->DeleteAllItems();

    for (decltype(machO->header.nfat_arch) i = 0U; i < machO->header.nfat_arch; i++)
    {
        const auto& info = machO->archs[i].info;

        auto item = list->AddItem(tmp.Format("%s (%s)", info.name.c_str(), GetValue(n, machO->archs[i].cputype).data()));
        list->SetItemText(item, 1, tmp.Format("%s (%s)", info.description.c_str(), GetValue(n, machO->archs[i].cpusubtype).data()));

        const auto fileType             = machO->archs[i].filetype;
        const auto& fileTypeName        = MAC::FileTypeNames.at(fileType);
        const auto& fileTypeDescription = MAC::FileTypeDescriptions.at(fileType);
        list->SetItemText(item, 2, tmp.Format("%s (0x%X) %s", fileTypeName.data(), fileType, fileTypeDescription.data()));

        list->SetItemText(item, 3, GetValue(n, machO->archs[i].offset));
        list->SetItemText(item, 4, GetValue(n, machO->archs[i].size));
        list->SetItemText(item, 5, GetValue(n, machO->archs[i].align));
        list->SetItemText(item, 6, GetValue(n, 1ULL << machO->archs[i].align));

        list->SetItemData<Identity<decltype(machO->archs)>::type::value_type>(item, &machO->archs[i]);
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

} // namespace GView::Type::UniversalMachO::Panels
