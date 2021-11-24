#include "decompiler.hpp"

using namespace GView::Type::DECOMPILER;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

Panels::Sections::Sections(Reference<GView::Type::DECOMPILER::DecompilerFile> _decompiler, Reference<GView::View::WindowInterface> _win)
    : TabPage("&Sections")
{
    decompiler = _decompiler;
    win        = _win;
    Base       = 16;

    list = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("Name", TextAlignament::Left, 8);
    Update();
}

void Panels::Sections::Update()
{
    list->DeleteAllItems();
    auto item = list->AddItem("Decompile");
    list->SetItemText(item, 0, "Run");
}

bool Panels::Sections::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemClicked)
    {
        decompiler->StartDecompiling();
        return true;
    }
}