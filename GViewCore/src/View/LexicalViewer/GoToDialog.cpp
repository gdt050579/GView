#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

GoToDialog::GoToDialog(uint32 currentLine, uint32 _maxLines)
    : Window("GoTo", "d:c,w:40,h:8", WindowFlags::ProcessReturn), maxLines(_maxLines)
{
    LocalString<128> tmp;
    this->selectedLineNo = 0;

    Factory::Label::Create(this, tmp.Format("&Line (1..%u)", _maxLines), "x:1,y:1,w:16");
    txLineNumber = Factory::TextField::Create(this, tmp.Format("%u", currentLine), "x:17,y:1,w:19");
    txLineNumber->SetHotKey('L');

    Factory::Button::Create(this, "&OK", "l:5,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:20,b:0,w:13", BTN_ID_CANCEL);
    txLineNumber->SetFocus();
}

void GoToDialog::Validate()
{
    LocalString<128> tmp;
    LocalString<256> error;


    if (tmp.Set(txLineNumber->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Fail to get the line number of the numerical field !");
        txLineNumber->SetFocus();
        return;
    }
    auto lineNo = Number::ToUInt32(tmp, NumberParseFlags::BaseAuto);
    if (!lineNo.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Value `%s` is not a valid number !", tmp.GetText()));
        txLineNumber->SetFocus();
        return;
    }
    if ((lineNo.value() > maxLines) || (lineNo.value() < 1))
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Valid line number are between 1 and %u", maxLines));
        txLineNumber->SetFocus();
        return;
    }
    selectedLineNo = lineNo.value();
    Exit(Dialogs::Result::Ok);
}

bool GoToDialog::OnEvent(Reference<Control>, Event eventType, int ID)
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
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer
