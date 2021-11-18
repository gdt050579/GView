#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr unsigned int PE_RES_GOTO = 1;

Panels::Resources::Resources(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Resources")
{
    pe  = _pe;
    win = _win;

    list = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("&Type", TextAlignament::Left, 12);
    list->AddColumn("&Name", TextAlignament::Left, 16);
    list->AddColumn("&ID", TextAlignament::Left, 4);
    list->AddColumn("File &Ofs", TextAlignament::Right, 10);
    list->AddColumn("&Size", TextAlignament::Right, 10);
    list->AddColumn("&CodePage", TextAlignament::Left, 10);
    list->AddColumn("&Language", TextAlignament::Left, 18);

    Update();
}
void Panels::Resources::Update()
{
    LocalString<128> temp;
    NumericFormatter n;

    list->DeleteAllItems();
    for (auto& r : pe->res)
    {
        auto nm = PEFile::ResourceIDToName(r.Type).data();
        if (!nm)
            nm = "Unknown";
        auto handle = list->AddItem(temp.Format("%s (%d)", nm, r.Type), r.Name, n.ToDec(r.ID));
        list->SetItemText(handle, 3, n.ToDec(r.Start));
        list->SetItemText(handle, 4, n.ToDec(r.Size));
        list->SetItemText(handle, 5, n.ToDec(r.CodePage));
        list->SetItemText(handle, 6, temp.Format("%s (%d)", PEFile::LanguageIDToName(r.Language).data(), r.Language));
    }
}
bool Panels::Resources::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_RES_GOTO);
    return true;
}
bool Panels::Resources::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    // if ((evnt == Event::ListViewItemClicked) || ((evnt == Event::Command) && (controlID == PE_EXP_GOTO)))
    //{
    //    auto addr = list->GetItemData(list->GetCurrentItem(), GView::Utils::INVALID_OFFSET);
    //    if (addr != GView::Utils::INVALID_OFFSET)
    //        win->GetCurrentView()->GoTo(addr);
    //    return true;
    //}
    return false;
}