#include "ico.hpp"

using namespace GView::Type::ICO;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 ICO_DIRS_GOTO            = 1;
constexpr uint32 ICO_DIRS_SELECT          = 2;

Panels::Directories::Directories(Reference<GView::Type::ICO::ICOFile> _ico, Reference<GView::View::WindowInterface> _win)
    : TabPage("&Directories")
{
    ico = _ico;
    win = _win;

    list = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
    // columns
    list->AddColumn("Image", TextAlignament::Left);
    list->AddColumn("Pallette", TextAlignament::Right, 10);
    if (ico->isIcoFormat)
    {
        list->AddColumn("ColPln", TextAlignament::Right, 10);
        list->AddColumn("Bit/Pxl", TextAlignament::Right, 10);
    }
    else
    {
        list->AddColumn("Hotspot", TextAlignament::Left, 10);
    }
    list->AddColumn("Size", TextAlignament::Left, 10);
    list->AddColumn("Offset", TextAlignament::Left, 10);

    Update();
}
void Panels::Directories::GoToSelectedDirectory()
{
    auto d = list->GetItemData<ICO::DirectoryEntry>(list->GetCurrentItem());
    if (d.IsValid())
        win->GetCurrentView()->GoTo(d->ico.offset);
}
void Panels::Directories::SelectCurrentDirectory()
{
    auto d = list->GetItemData<ICO::DirectoryEntry>(list->GetCurrentItem());
    if (d.IsValid())
        win->GetCurrentView()->Select(d->ico.offset, d->ico.size);
}
void Panels::Directories::Update()
{
    LocalString<128> temp;

    list->DeleteAllItems();

    for (auto& d : ico->dirs)
    {
        int w = d.ico.width;
        int h = d.ico.height;
        if (w == 0)
            w = 256;
        if (h == 0)
            h = 256;
        auto item = list->AddItem(temp.Format("%d x %d", w, h));
        if (d.ico.colorPallette == 0)
            list->SetItemText(item, 1, "None");
        else
            list->SetItemText(item, 1, temp.Format("%d", d.ico.colorPallette));
        if (ico->isIcoFormat)
        {
            list->SetItemText(item, 2, temp.Format("%d", d.ico.colorPlanes));
            list->SetItemText(item, 3, temp.Format("%d", d.ico.bitsPerPixels));
            list->SetItemText(item, 4, temp.Format("0x%X (%u)", d.ico.size, d.ico.size));
            list->SetItemText(item, 5, temp.Format("0x%X (%u)", d.ico.offset, d.ico.offset));
        }
        else
        {
            list->SetItemText(item, 2, temp.Format("%d,%d", d.cursor.hotstopX, d.cursor.hotstopY));
            list->SetItemText(item, 3, temp.Format("0x%X (%u)", d.ico.size, d.ico.size));
            list->SetItemText(item, 4, temp.Format("0x%X (%u)", d.ico.offset, d.ico.offset));
        }
        list->SetItemData<ICO::DirectoryEntry>(item, &d);
    }
}

bool Panels::Directories::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", ICO_DIRS_GOTO);
    commandBar.SetCommand(Key::F9, "Select", ICO_DIRS_SELECT);
    return true;
}

bool Panels::Directories::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::ListViewItemClicked)
    {
        GoToSelectedDirectory();
        return true;
    }
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case ICO_DIRS_GOTO:
            GoToSelectedDirectory();
            return true;
        case ICO_DIRS_SELECT:
            SelectCurrentDirectory();
            return true;
        }
    }
    return false;
}