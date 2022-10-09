#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

FindAllDialog::FindAllDialog(uint32 currentLine, uint32 _maxLines)
    : Window("All apearences", "d:c,w:80,h:20", WindowFlags::ProcessReturn), maxLines(_maxLines)
{
    LocalString<128> tmp;
    this->selectedLineNo = 0;

    auto lst = Factory::ListView::Create(this, "l:1,t:0,r:1,b:3", { "n:Line,a:l,w:6", "n:Content,a:l,w:200" }); 

    Factory::Button::Create(this, "&OK", "l:25,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:40,b:0,w:13", BTN_ID_CANCEL);
}

void FindAllDialog::Validate()
{
    selectedLineNo = 0;
    Exit(Dialogs::Result::Ok);
}

bool FindAllDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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