#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

GoToDialog::GoToDialog(Reference<SettingsData> _settings, uint64 currentPos, uint64 sz)
    : Window("GoTo", "d:c,w:60,h:10", WindowFlags::ProcessReturn), settings(_settings), maxSize(sz)
{
    resultedPos = GView::Utils::INVALID_OFFSET;
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
    Factory::Label::Create(this, "&Address", "x:1,y:1,w:8");
    Factory::Label::Create(this, "&Type", "x:1,y:3,w:8");
    txOffset  = Factory::TextField::Create(this, "", "x:10,y:1,w:46");
    cbOfsType = Factory::ComboBox::Create(this, "x:10,y:3,w:46", tmp.ToStringView());
    txOffset->SetHotKey('A');
    txOffset->SetText(tmp.Format("0x%llX", currentPos));
    cbOfsType->SetHotKey('T');
    cbOfsType->SetCurentItemIndex(0);

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);
    
    txOffset->SetFocus();
}
void GoToDialog::Validate()
{
    LocalString<128> tmp;
    LocalString<256> error;
    NumberParseFlags flags = NumberParseFlags::BaseAuto;

    if (tmp.Set(txOffset->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Invalid number (expecting ascii characters) for offset !");
        txOffset->SetFocus();
        return;
    }
    auto ofs = Number::ToUInt64(tmp, flags);
    if (!ofs.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%s` is not a valid UInt64 number !", tmp.GetText()));
        txOffset->SetFocus();
        return;
    }

    // all good
    auto newPos = ofs.value();
    // convert to FileOffset
    if (settings->offsetTranslateCallback.IsValid())
    {
        auto result = settings->offsetTranslateCallback->TranslateToFileOffset(newPos, cbOfsType->GetCurrentItemIndex());
        if (result == GView::Utils::INVALID_OFFSET)
        {
            Dialogs::MessageBox::ShowError(
                  "Error",
                  error.Format(
                        "Offset `%llu` is not a valid '%s' value !",
                        newPos,
                        settings->translationMethods[cbOfsType->GetCurrentItemIndex()].name.GetText()));
            txOffset->SetFocus();
            return;
        }
        newPos = result;
    }
    if (newPos >= maxSize)
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%llu` is bigger than the offset size: `%llu`", newPos, maxSize));
        txOffset->SetFocus();
        return;
    }
    resultedPos = newPos;
    Exit(Dialogs::Result::Ok);
}

bool GoToDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked)
    {
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
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
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}