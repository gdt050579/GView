#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

void SingleLineEditWindow::Validate()
{
    LocalString<128> tmp;
    if (textField->GetText().IsEmpty())
    {
        Dialogs::MessageBox::ShowError("Error", "Please write something in the comment section !");
        textField->SetFocus();
    }
    data = textField->GetText();
    Exit(Dialogs::Result::Ok);
}

SingleLineEditWindow::SingleLineEditWindow(std::string initialText, const char* title) : Window(title, "d:c,w:60,h:7", WindowFlags::ProcessReturn)
{
    data = initialText;
    Factory::Label::Create(this, "&Text", "x:1,y:1,w:8");
    textField = Factory::TextField::Create(this, initialText, "x:10,y:1,w:46");
    textField->SetHotKey('T');

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

    textField->SetFocus();
}

bool SingleLineEditWindow::OnEvent(Reference<Control>, Event eventType, int ID)
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
