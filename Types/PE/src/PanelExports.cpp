#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 PE_EXP_GOTO = 1;

Panels::Exports::Exports(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Exports")
{
    pe  = _pe;
    win = _win;

    list = Factory::ListView::Create(this, "d:c", { "n:Name,w:60", "n:Ord,w:5", "n:RVA,w:12" }, ListViewFlags::None);

    Update();
}
void Panels::Exports::Update()
{
    LocalString<128> temp;
    NumericFormatter n;

    list->DeleteAllItems();
    for (auto& exp : pe->exp)
    {
        list->AddItem({ exp.Name, n.ToDec(exp.Ordinal), temp.Format("%u (0x%08X)", exp.RVA, exp.RVA) })
              .SetData((uint64) pe->ConvertAddress(exp.RVA, AddressType::RVA, AddressType::FileOffset));
    }
}
bool Panels::Exports::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_EXP_GOTO);
    return true;
}
bool Panels::Exports::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if ((evnt == Event::ListViewItemPressed) || ((evnt == Event::Command) && (controlID == PE_EXP_GOTO)))
    {
        auto addr = list->GetCurrentItem().GetData(GView::Utils::INVALID_OFFSET);
        if (addr != GView::Utils::INVALID_OFFSET)
            win->GetCurrentView()->GoTo(addr);
        return true;
    }
    return false;
}