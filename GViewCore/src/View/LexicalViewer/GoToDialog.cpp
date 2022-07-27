#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK        = 1;
constexpr int32 BTN_ID_CANCEL    = 2;
constexpr int32 RB_GROUP_ID      = 123;

GoToDialog::GoToDialog(uint64 currentPos, uint64 sz, uint32 currentLine, uint32 _maxLines)
    : Window("GoTo", "d:c,w:60,h:10", WindowFlags::ProcessReturn), maxSize(sz), maxLines(_maxLines)
{
    LocalString<128> tmp;
    resultedPos = GView::Utils::INVALID_OFFSET;
    gotoLine    = true;

    rbLineNumber = Factory::RadioBox::Create(this, tmp.Format("&Line (1..%u)", _maxLines), "x:1,y:1,w:38", RB_GROUP_ID);
    txLineNumber = Factory::TextField::Create(this, tmp.Format("%u", currentLine), "x:40,y:1,w:16");

    rbFileOffset = Factory::RadioBox::Create(this, tmp.Format("&File offset (0..%llu)", sz), "x:1,y:3,w:38", RB_GROUP_ID);
    txFileOffset = Factory::TextField::Create(this, tmp.Format("%llu", currentPos), "x:40,y:3,w:16");

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

    rbLineNumber->SetChecked(true);    
    UpdateEnableStatus();
}
void GoToDialog::UpdateEnableStatus()
{
    txLineNumber->SetEnabled(rbLineNumber->IsChecked());
    txFileOffset->SetEnabled(rbFileOffset->IsChecked());
    if (txLineNumber->IsEnabled())
        txLineNumber->SetFocus();
    if (txFileOffset->IsEnabled())
        txFileOffset->SetFocus();
}
void GoToDialog::Validate()
{
    LocalString<128> tmp;
    LocalString<256> error;
    Reference<TextField> input = rbLineNumber->IsChecked() ? txLineNumber : txFileOffset;
    NumberParseFlags flags     = NumberParseFlags::BaseAuto;

    if (tmp.Set(input->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Fail to get the value of the numerical field !");
        input->SetFocus();
        return;
    }
    auto ofs = Number::ToUInt64(tmp, flags);
    if (!ofs.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Value `%s` is not a valid number !", tmp.GetText()));
        input->SetFocus();
        return;
    }

    // all good
    auto newPos = ofs.value();
    gotoLine    = rbLineNumber->IsChecked();
    // checks in boundery
    if (rbLineNumber->IsChecked())
    {
        if ((newPos > maxLines) || (newPos < 1))
        {
            Dialogs::MessageBox::ShowError("Error", error.Format("Valid line number are between 1 and %u", maxLines));
            input->SetFocus();
            return;
        }
    }
    else
    {
        if (newPos >= maxSize)
        {
            Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%llu` is bigger than the offset size: `%llu`", newPos, maxSize));
            input->SetFocus();
            return;
        }
    }
    // convert to FileOffset
    resultedPos = newPos;
    Exit(Dialogs::Result::Ok);
}

bool GoToDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    switch (eventType)
    {
    case Event::ButtonClicked:
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
        break;
    case Event::CheckedStatusChanged:
        UpdateEnableStatus();
        return true;
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}