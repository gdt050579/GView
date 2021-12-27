#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CLEAR  = 2;
constexpr int32 BTN_ID_RELOAD = 3;
constexpr int32 BTN_ID_CANCEL = 4;

SelectionEditor::SelectionEditor(Reference<Utils::Selection> _selection, uint32 index, Reference<SettingsData> _settings, uint64 sz)
    : Window("Selection Editor", "d:c,w:61,h:10", WindowFlags::None), selection(_selection), zoneIndex(index), settings(_settings),
      maxSize(sz)
{
    LocalString<128> tmp;
    if (this->settings->translationMethodsCount == 0)
    {
        tmp.Set("FileOffset");
    }
    else
    {
        for (uint32 tr = 0; tr < settings->translationMethodsCount; tr++)
        {
            if (tr > 0)
                tmp.AddChar(',');
            tmp.Add(settings->translationMethods[tr].name);
        }
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
        Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%s` is not a valid UInt64 number !", tmp.GetText()));
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
        Dialogs::MessageBox::ShowError("Error", error.Format("Size `%s` is not a valid UInt64 number !", tmp.GetText()));
        txSize->SetFocus();
        return false;
    }
    // all good
    start = ofs.value();
    // convert to FileOffset
    if (settings->offsetTranslateCallback.IsValid())
    {
        auto result = settings->offsetTranslateCallback->TranslateToFileOffset(start, cbOfsType->GetCurrentItemIndex());
        if (result == GView::Utils::INVALID_OFFSET)
        {
            Dialogs::MessageBox::ShowError(
                  "Error",
                  error.Format(
                        "Offset `%llu` is not a valid '%s' value !",
                        start,
                        settings->translationMethods[cbOfsType->GetCurrentItemIndex()].name.GetText()));
            txOffset->SetFocus();
            return false;
        }
        start = result;
    }
    size = sz.value();
    if (start >= maxSize)
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%llu` is bigger than the offset size: `%llu`", start, maxSize));
        txOffset->SetFocus();
        return false;
    }
    if (size >= maxSize)
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Size `%llu` is bigger than the offset size: `%llu`", size, maxSize));
        txSize->SetFocus();
        return false;
    }
    auto end = start + size;
    if ((end < start) || (end < size))
    {
        Dialogs::MessageBox::ShowError(
              "Error", error.Format("Integer overflow while summing up start:`%llu` to size: `%llu`", start, size));
        txOffset->SetFocus();
        return false;
    }
    if (start + size > maxSize)
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Selection is outside maximum size (%llu)", maxSize));
        txOffset->SetFocus();
        return false;
    }
    if (size == 0)
    {
        Dialogs::MessageBox::ShowError("Error", "Selection size can not be 0 !");
        txSize->SetFocus();
        return false;
    }
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
    if (GetValues(start, size))
    {
        selection->SetSelection(zoneIndex, start, start + size - 1);
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