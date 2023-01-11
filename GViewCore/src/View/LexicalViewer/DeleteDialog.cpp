#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 APPLY_GROUP_ID = 1;

DeleteDialog::DeleteDialog(TokenObject& tok, const char16* text, bool hasSelection, bool belongsToABlock)
    : Window("Delete", "d:c,w:70,h:12", WindowFlags::ProcessReturn)
{
    Factory::Label::Create(this, "Delete the following token (or block/selection) ?", "x:1,y:1,w:60");
    Factory::TextField::Create(this, tok.GetText(text), "x:1,y:2,w:65", TextFieldFlags::Readonly);

    // apply methods
    this->rbApplyOnCurrent = Factory::RadioBox::Create(this, "Delete &current token alone", "x:1,y:4,w:60", APPLY_GROUP_ID);
    this->rbApplyOnBlock =
          Factory::RadioBox::Create(this, "Delete the &block where current token resides", "x:1,y:5,w:60", APPLY_GROUP_ID);
    this->rbApplyOnSelection =
          Factory::RadioBox::Create(this, "Delete &selection", "x:1,y:6,w:60", APPLY_GROUP_ID);

    this->rbApplyOnSelection->SetEnabled(hasSelection);
    this->rbApplyOnBlock->SetEnabled(belongsToABlock);

    if (hasSelection)
        this->rbApplyOnSelection->SetChecked(true);
    else if (belongsToABlock)
        this->rbApplyOnBlock->SetChecked(true);
    else
        this->rbApplyOnCurrent->SetChecked(true);

    // buttons
    Factory::Button::Create(this, "&Delete", "l:21,b:0,w:13", BTN_ID_OK)->SetFocus();
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
}
bool DeleteDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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