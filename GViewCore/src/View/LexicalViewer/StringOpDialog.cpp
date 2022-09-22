#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 APPLY_GROUP_ID = 1;

StringOpDialog::StringOpDialog(TokenObject& _tok, const char16* text)
    : Window("String Operations", "d:c,w:70,h:21", WindowFlags::ProcessReturn), tok(_tok)
{
    Factory::Label::Create(this, "Value", "x:1,y:1,w:30");
    Factory::TextArea::Create(
          this, tok.GetOriginalText(text), "x:1,y:2,w:65,h:4", TextAreaFlags::Readonly | TextAreaFlags::ShowLineNumbers);
    Factory::Label::Create(this, "&New value (an empty field means using the original text)", "x:1,y:7,w:60");
    this->txNewValue = Factory::TextField::Create(this, tok.value.ToStringView(), "x:1,y:8,w:65,h:1");
    this->txNewValue->SetHotKey('N');

    // buttons
    Factory::Button::Create(this, "&OK", "l:21,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);

    this->txNewValue->SetFocus();
}
bool StringOpDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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
            Exit(Dialogs::Result::Ok);
            return true;
        }
        break;

    case Event::WindowAccept:
        Exit(Dialogs::Result::Ok);
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}