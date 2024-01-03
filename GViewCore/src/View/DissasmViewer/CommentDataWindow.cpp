#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

void CommentDataWindow::Validate()
{
    LocalString<128> tmp;
    if (commentTextField->GetText().IsEmpty())
    {
        Dialogs::MessageBox::ShowError("Error", "Please write something in the comment section !");
        commentTextField->SetFocus();
    }
    data = commentTextField->GetText();
    Exit(Dialogs::Result::Ok);
}

CommentDataWindow::CommentDataWindow(std::string initialComment) : Window("Add comment", "d:c,w:60,h:7", WindowFlags::ProcessReturn)
{
    data = initialComment;
    Factory::Label::Create(this, "&Comment", "x:1,y:1,w:8");
    commentTextField = Factory::TextField::Create(this, initialComment, "x:10,y:1,w:46");
    commentTextField->SetHotKey('C');

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

    commentTextField->SetFocus();
}

bool CommentDataWindow::OnEvent(Reference<Control>, Event eventType, int ID)
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
