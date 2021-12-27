#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CLEAR  = 2;
constexpr int32 BTN_ID_RELOAD = 3;
constexpr int32 BTN_ID_CANCEL = 4;

SelectionEditor::SelectionEditor(Reference<Utils::Selection> _selection, uint32 index)
    : Window("Selection Editor", "d:c,w:61,h:10", WindowFlags::None), selection(_selection), zoneIndex(index)
{
    Factory::Label::Create(this, "&Offset", "x:1,y:1,w:10");
    Factory::Label::Create(this, "&Type", "x:35,y:1,w:10");
    Factory::Label::Create(this, "&Size", "x:1,y:3,w:10");
    Factory::Label::Create(this, "&Base", "x:35,y:3,w:10");
    txOffset  = Factory::TextField::Create(this, "", "x:11,y:1,w:20");
    cbOfsType = Factory::ComboBox::Create(this, "x:40,y:1,w:17");
    txSize    = Factory::TextField::Create(this, "", "x:11,y:3,w:20");
    cbBase    = Factory::ComboBox::Create(this, "x:40,y:3,w:17", "Auto,Dec,Hex");
    Factory::Button::Create(this, "OK", "l:2,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "ClearSel", "l:16,b:0,w:13", BTN_ID_CLEAR);
    Factory::Button::Create(this, "Reload", "l:30,b:0,w:13", BTN_ID_RELOAD);
    Factory::Button::Create(this, "Cancel", "l:44,b:0,w:13", BTN_ID_CANCEL);

    RefreshSizeAndOffset();
}
void SelectionEditor::RefreshSizeAndOffset()
{
    LocalString<128> tmp;
    NumericFormatter n;
    uint64 start, end;
    if (selection->GetSelection(zoneIndex, start, end))
    {
        tmp.Set("0x");
        tmp.Add(n.ToHex(start));
        txOffset->SetText(tmp);
        tmp.Set("0x");
        tmp.Add(n.ToHex(end - start));
        txSize->SetText(tmp);
    }
    else
    {
        txOffset->SetText("");
        txSize->SetText("");
    }
    txOffset->SetFocus();
}
void SelectionEditor::Validate()
{
}
bool SelectionEditor::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (Window::OnEvent(control, eventType, ID))
        return true;
    if (eventType == Event::ButtonClicked)
    {
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(0);
            return true;
        case BTN_ID_CLEAR:
            txOffset->SetText("");
            txSize->SetText("");
            return true;
        case BTN_ID_RELOAD:
            RefreshSizeAndOffset();
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
    }
    return false;
}