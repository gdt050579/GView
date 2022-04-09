#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 PE_RES_GOTO   = 1;
constexpr uint32 PE_RES_SAVE   = 2;
constexpr uint32 PE_RES_SELECT = 3;

Panels::Resources::Resources(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Resources")
{
    pe  = _pe;
    win = _win;

    list = this->CreateChildControl<ListView>(
          "d:c",
          {
                { "&Type", TextAlignament::Left, 16 },
                { "&Name", TextAlignament::Left, 16 },
                { "&ID", TextAlignament::Left, 4 },
                { "&Extra infos", TextAlignament::Left, 20 },
                { "File &Ofs", TextAlignament::Right, 10 },
                { "&Size", TextAlignament::Right, 10 },
                { "&CodePage", TextAlignament::Left, 10 },
                { "&Language", TextAlignament::Left, 18 },
          },
          ListViewFlags::None);

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
        auto item = list->AddItem({ temp.Format("%s (%d)", nm, r.Type), r.Name, n.ToDec(r.ID) });
        switch (r.Type)
        {
        case ResourceType::Icon:
            if (pe->GetResourceImageInformation(r, temp))
                item.SetText(3, temp);
            else
                item.SetText(3, "?");
            break;
        default:
            // no specific extra informations to add
            break;
        }
        item.SetText(4, n.ToDec(r.Start));
        item.SetText(5, n.ToDec(r.Size));
        item.SetText(6, n.ToDec(r.CodePage));
        item.SetText(7, temp.Format("%s (%d)", PEFile::LanguageIDToName(r.Language).data(), r.Language));
        item.SetData<PEFile::ResourceInformation>(&r);
    }
}
bool Panels::Resources::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_RES_GOTO);
    commandBar.SetCommand(Key::F2, "Save", PE_RES_SAVE);
    commandBar.SetCommand(Key::F9, "Select", PE_RES_SELECT);
    return true;
}
void Panels::Resources::SaveCurrentResource()
{
    auto r = list->GetItemData<PEFile::ResourceInformation>(list->GetCurrentItem());
    LocalString<128> tmp;
    tmp.Format("resource_%08X_%X_%d.res", r->Start, r->Size, r->ID);
    auto res = AppCUI::Dialogs::FileDialog::ShowSaveFileWindow(tmp, "", "");
    if (res.has_value())
    {
        auto buf = this->win->GetObject()->cache.CopyToBuffer(r->Start, r->Size);
        if (AppCUI::OS::File::WriteContent(res.value(), BufferView{ buf }) == false)
        {
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Fail to create file !");
        }
    }
}
void Panels::Resources::GoToSelectedResource()
{
    auto sect = list->GetItemData<PEFile::ResourceInformation>(list->GetCurrentItem());
    if (sect.IsValid())
        win->GetCurrentView()->GoTo(sect->Start);
}
void Panels::Resources::SelectCurrentResource()
{
    auto sect = list->GetItemData<PEFile::ResourceInformation>(list->GetCurrentItem());
    if (sect.IsValid())
        win->GetCurrentView()->Select(sect->Start, sect->Size);
}
bool Panels::Resources::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        case PE_RES_SAVE:
            SaveCurrentResource();
            return true;
        case PE_RES_GOTO:
            GoToSelectedResource();
            return true;
        case PE_RES_SELECT:
            SelectCurrentResource();
            return true;
        }
    }
    if (evnt == Event::ListViewItemClicked)
    {
        GoToSelectedResource();
        return true;
    }
    return false;
};