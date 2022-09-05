#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

SaveAsDialog::SaveAsDialog()
    : Window("Save As", "d:c,w:40,h:8", WindowFlags::ProcessReturn)
{
    Factory::Button::Create(this, "&OK", "l:5,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:20,b:0,w:13", BTN_ID_CANCEL);
}

bool SaveAsDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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
} // namespace GView::View::LexicalViewer