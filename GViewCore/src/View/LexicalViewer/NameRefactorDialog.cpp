#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 APPLY_GROUP_ID = 1;

NameRefactorDialog::NameRefactorDialog(TokenObject& _tok, const char16* text, bool hasSelection)
    : Window("Rename", "d:c,w:70,h:21", WindowFlags::ProcessReturn), tok(_tok)
{
    Factory::Label::Create(this, "Original text", "x:1,y:1,w:30");
    Factory::TextArea::Create(this, tok.GetOriginalText(text), "x:1,y:2,w:65,h:4", TextAreaFlags::Readonly | TextAreaFlags::ShowLineNumbers);
    Factory::Label::Create(this, "&New value (an empty field means using the original text)", "x:1,y:7,w:60");
    this->txNewValue = Factory::TextField::Create(this, tok.value.ToStringView(), "x:1,y:8,w:65,h:1");
    this->txNewValue->SetHotKey('N');

    // apply methods
    this->rbApplyOnCurrent = Factory::RadioBox::Create(this, "Apply on &current token alone", "x:1,y:10,w:60", APPLY_GROUP_ID);
    this->rbApplyOnBlock =
          Factory::RadioBox::Create(this, "Apply on all similar tokens from current &block", "x:1,y:11,w:60", APPLY_GROUP_ID);
    this->rbApplyOnSelection =
          Factory::RadioBox::Create(this, "Apply on all similar tokens from &selection", "x:1,y:12,w:60", APPLY_GROUP_ID);
    this->rbApplyOnAll = Factory::RadioBox::Create(this, "Apply on &all similar tokens from the program", "x:1,y:13,w:60", APPLY_GROUP_ID);

    if (!hasSelection)
    {
        this->rbApplyOnSelection->SetEnabled(false);
        this->rbApplyOnBlock->SetChecked(true);
    }
    else
    {
        this->rbApplyOnSelection->SetChecked(true);
    }

    this->cbReparse = Factory::CheckBox::Create(this, "&Reparse the entire content after rename is done", "x:1,y:15,w:60");

    // buttons
    Factory::Button::Create(this, "&OK", "l:21,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);



    this->txNewValue->SetFocus();
}
bool NameRefactorDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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
             //Validate();
             return true;
         }
         break;

     case Event::WindowAccept:
         //Validate();
         return true;
     case Event::WindowClose:
         Exit(Dialogs::Result::Cancel);
         return true;
     }

    return false;
}