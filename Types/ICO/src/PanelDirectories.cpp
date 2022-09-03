#include "ico.hpp"

using namespace GView::Type::ICO;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 ICO_DIRS_GOTO   = 1;
constexpr uint32 ICO_DIRS_SELECT = 2;

Panels::Directories::Directories(Reference<GView::Type::ICO::ICOFile> _ico, Reference<GView::View::WindowInterface> _win)
    : TabPage("&Directories")
{
    ico = _ico;
    win = _win;

    list = Factory::ListView::Create(this, "d:c", { "n:Image,w:10", "n:Pallette,w:10" }, ListViewFlags::None);
    // columns
    if (ico->isIcoFormat)
    {
        list->AddColumns({ "n:ColPln,a:r,w:10", "n:Bit/Pxl,a:r,w:10" });
    }
    else
    {
        list->AddColumn("n:Hotspot,w:10");
    }
    list->AddColumns({ "n:Size,w:10", "n:Offset,w:10" });

    Update();
}
void Panels::Directories::GoToSelectedDirectory()
{
    auto d = list->GetCurrentItem().GetData<ICO::DirectoryEntry>();
    if (d.IsValid())
        win->GetCurrentView()->GoTo(d->ico.offset);
}
void Panels::Directories::SelectCurrentDirectory()
{
    auto d = list->GetCurrentItem().GetData<ICO::DirectoryEntry>();
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
            item.SetText(1, "None");
        else
            item.SetText(1, temp.Format("%d", d.ico.colorPallette));
        if (ico->isIcoFormat)
        {
            item.SetText(2, temp.Format("%d", d.ico.colorPlanes));
            item.SetText(3, temp.Format("%d", d.ico.bitsPerPixels));
            item.SetText(4, temp.Format("0x%X (%u)", d.ico.size, d.ico.size));
            item.SetText(5, temp.Format("0x%X (%u)", d.ico.offset, d.ico.offset));
        }
        else
        {
            item.SetText(2, temp.Format("%d,%d", d.cursor.hotstopX, d.cursor.hotstopY));
            item.SetText(3, temp.Format("0x%X (%u)", d.ico.size, d.ico.size));
            item.SetText(4, temp.Format("0x%X (%u)", d.ico.offset, d.ico.offset));
        }
        item.SetData<ICO::DirectoryEntry>(&d);
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
    if (evnt == Event::ListViewItemPressed)
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