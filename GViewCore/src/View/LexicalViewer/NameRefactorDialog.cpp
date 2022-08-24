#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 APPLY_GROUP_ID = 1;

NameRefactorDialog::NameRefactorDialog(TokenObject& _tok, const char16* text, bool hasSelection)
    : Window("Rename", "d:c,w:70,h:20", WindowFlags::ProcessReturn), tok(_tok)
{
    Factory::Label::Create(this, "Original\nText", "x:1,y:1,w:12,h:2");
    Factory::TextArea::Create(this, tok.GetOriginalText(text), "x:15,y:1,w:50,h:5", TextAreaFlags::Readonly);
    Factory::Label::Create(this, "New value", "x:1,y:7,w:12");
    this->txNewValue = Factory::TextArea::Create(this, tok.value.ToStringView(), "x:15,y:7,w:50,h:3", TextAreaFlags::ShowLineNumbers);

    // apply methods
    this->rbApplyOnCurrent = Factory::RadioBox::Create(this, "Apply on &current token alone", "x:1,y:11,w:60", APPLY_GROUP_ID);
    this->rbApplyOnBlock =
          Factory::RadioBox::Create(this, "Apply on all similar tokens from current &block", "x:1,y:12,w:60", APPLY_GROUP_ID);
    this->rbApplyOnSelection =
          Factory::RadioBox::Create(this, "Apply on all similar tokens from &selection", "x:1,y:13,w:60", APPLY_GROUP_ID);
    this->rbApplyOnAll = Factory::RadioBox::Create(this, "Apply on &all similar tokens from the program", "x:1,y:14,w:60", APPLY_GROUP_ID);

    if (!hasSelection)
    {
        this->rbApplyOnSelection->SetVisible(false);
        this->rbApplyOnBlock->SetChecked(true);
    }
    else
    {
        this->rbApplyOnSelection->SetChecked(true);
    }



    this->txNewValue->SetFocus();
}
bool NameRefactorDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    // switch (eventType)
    //{
    // case Event::ButtonClicked:
    //     switch (ID)
    //     {
    //     case BTN_ID_CANCEL:
    //         Exit(Dialogs::Result::Cancel);
    //         return true;
    //     case BTN_ID_OK:
    //         Validate();
    //         return true;
    //     }
    //     break;
    // case Event::CheckedStatusChanged:
    //     UpdateEnableStatus();
    //     return true;
    // case Event::WindowAccept:
    //     //Validate();
    //     return true;
    // case Event::WindowClose:
    //     Exit(Dialogs::Result::Cancel);
    //     return true;
    // }

    return false;
}