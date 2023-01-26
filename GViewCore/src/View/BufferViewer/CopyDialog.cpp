#include "BufferViewer.hpp"

namespace GView::View::BufferViewer
{
constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

CopyDialog::CopyDialog(Reference<GView::Object> object, uint64 currentPos)
    : Window("Copy", "d:c,w:30%,h:18", WindowFlags::ProcessReturn | WindowFlags::Sizeable), object(object), currentPos(currentPos)
{
}

bool CopyDialog::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked)
    {
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Exit(Dialogs::Result::Ok);
            return true;
        }
    }

    switch (eventType)
    {
    case Event::WindowAccept:
        Exit(Dialogs::Result::Ok);
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::BufferViewer
