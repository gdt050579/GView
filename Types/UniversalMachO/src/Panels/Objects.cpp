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

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:CPU type,a:r,w:25",
            "n:CPU subtype,a:r,w:25",
            "n:File type,e:80",
            "n:Offset,a:r,w:12",
            "n:Size,a:r,w:12",
            "n:Align,a:r,w:12",
            "n:Real Align,a:r,w:12" },
          ListViewFlags::None);

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
    const auto& arch = list->GetCurrentItem().GetData<Identity<decltype(machO->archs)>::type::value_type>().
                       operator Identity<decltype(machO->archs)>::type::value_type&();
    win->GetCurrentView()->GoTo(arch.offset);
}

void Panels::Objects::SelectCurrentSection()
{
    const auto& arch = list->GetCurrentItem().GetData<Identity<decltype(machO->archs)>::type::value_type>().
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
        item.SetText(1, tmp.Format("%s (%s)", info.description.c_str(), GetValue(n, machO->archs[i].cpusubtype).data()));

        const auto fileType             = machO->archs[i].filetype;
        const auto& fileTypeName        = MAC::FileTypeNames.at(fileType);
        const auto& fileTypeDescription = MAC::FileTypeDescriptions.at(fileType);
        item.SetText(2, tmp.Format("%s (0x%X) %s", fileTypeName.data(), fileType, fileTypeDescription.data()));
        item.SetText(3, GetValue(n, machO->archs[i].offset));
        item.SetText(4, GetValue(n, machO->archs[i].size));
        item.SetText(5, GetValue(n, machO->archs[i].align));
        item.SetText(6, GetValue(n, 1ULL << machO->archs[i].align));

        item.SetData<Identity<decltype(machO->archs)>::type::value_type>(&machO->archs[i]);
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

} // namespace GView::Type::UniversalMachO::Panels
