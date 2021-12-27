#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CLEAR  = 2;
constexpr int32 BTN_ID_RELOAD = 3;
constexpr int32 BTN_ID_CANCEL = 4;

SelectionEditor::SelectionEditor(Reference<Utils::Selection> _selection, uint32 index, Reference<SettingsData> _settings)
    : Window("Selection Editor", "d:c,w:61,h:10", WindowFlags::None), selection(_selection), zoneIndex(index), settings(_settings)
{
    LocalString<128> tmp;
    for (uint32 tr = 0; tr < settings->translationMethodsCount; tr++)
    {
        if (tr > 0)
            tmp.AddChar(',');
        tmp.Add(settings->translationMethods[tr].name);
    }
    Factory::Label::Create(this, "&Offset", "x:1,y:1,w:6");
    Factory::Label::Create(this, "&Type", "x:30,y:1,w:5");
    Factory::Label::Create(this, "&Size", "x:1,y:3,w:5");
    Factory::Label::Create(this, "&Base", "x:30,y:3,w:5");
    txOffset  = Factory::TextField::Create(this, "", "x:8,y:1,w:18");
    cbOfsType = Factory::ComboBox::Create(this, "x:35,y:1,w:22", tmp.ToStringView());
    txSize    = Factory::TextField::Create(this, "", "x:8,y:3,w:18");
    cbBase    = Factory::ComboBox::Create(this, "x:35,y:3,w:22", "Auto,Dec,Hex");
    txOffset->SetHotKey('O');
    txSize->SetHotKey('S');
    cbOfsType->SetHotKey('T');
    cbBase->SetHotKey('B');

    cbBase->SetCurentItemIndex(0);
    cbOfsType->SetCurentItemIndex(0);

    Factory::Button::Create(this, "OK", "l:2,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "C&learSel", "l:16,b:0,w:13", BTN_ID_CLEAR);
    Factory::Button::Create(this, "&Reload", "l:30,b:0,w:13", BTN_ID_RELOAD);
    Factory::Button::Create(this, "&Cancel", "l:44,b:0,w:13", BTN_ID_CANCEL);

    RefreshSizeAndOffset();
}
bool SelectionEditor::GetValues(uint64& start, uint64& size)
{
    LocalString<128> tmp;
    LocalString<256> error;
    NumberParseFlags flags = NumberParseFlags::BaseAuto;

    if (cbBase->GetCurrentItemIndex() == 1)
        flags = NumberParseFlags::Base10;
    if (cbBase->GetCurrentItemIndex() == 2)
        flags = NumberParseFlags::Base16;

    if (tmp.Set(txOffset->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Invalid number (expecting ascii characters) for offset !");
        txOffset->SetFocus();
        return false;
    }
    auto ofs = Number::ToUInt64(tmp, flags);
    if (!ofs.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", "Offset `%s` is not a valid UInt64 number !");
        txOffset->SetFocus();
        return false;
    }
    if (tmp.Set(txSize->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Invalid number (expecting ascii characters) for size !");
        txSize->SetFocus();
        return false;
    }
    auto sz = Number::ToUInt64(tmp, flags);
    if (!sz.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", "Size `%s` is not a valid UInt64 number !");
        txSize->SetFocus();
        return false;
    }
    // all good
    start = ofs.value();
    size  = sz.value();
    return true;
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
    if ((txOffset->GetText().Len() == 0) && (txSize->GetText().Len() == 0))
    {
        // no selection (clear selection);
        selection->Clear(zoneIndex);
        Exit(0);
        return;
    }
    // we have some values
    uint64 start, size;
    if (GetValues(start,size))
    {
        selection->SetSelection(zoneIndex, start, start+size-1);
        Exit(0);
        return;
    }
}
bool SelectionEditor::OnEvent(Reference<Control> control, Event eventType, int ID)
{
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
 
    switch (eventType)
    {
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(0);
        return true;
    }

    return false;
}