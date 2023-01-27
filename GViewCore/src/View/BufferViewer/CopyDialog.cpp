#include "BufferViewer.hpp"

namespace GView::View::BufferViewer
{
constexpr int32 BTN_ID_OK                        = 1;
constexpr int32 BTN_ID_CANCEL                    = 2;
constexpr int32 CHECKBOX_ID_COPY_ASCII           = 3;
constexpr int32 CHECKBOX_ID_COPY_UNICODE         = 4;
constexpr int32 CHECKBOX_ID_COPY_UNICODE_AS_SEEN = 5;
constexpr int32 CHECKBOX_ID_COPY_DUMP_BUFFER     = 6;
constexpr int32 CHECKBOX_ID_COPY_HEX             = 7;
constexpr int32 CHECKBOX_ID_COPY_ARRAY           = 8;
constexpr int32 CHECKBOX_ID_COPY_FILE            = 9;
constexpr int32 CHECKBOX_ID_COPY_SELECTION       = 10;

CopyDialog::CopyDialog(Reference<GView::Object> object, uint64 currentPos)
    : Window("Copy to Clipboard", "d:c,w:20%,h:12", WindowFlags::ProcessReturn), object(object), currentPos(currentPos)
{
    copyAscii = Factory::RadioBox::Create(this, "Copy as &ascii text", "x:5%,y:1,w:60%,h:1", CHECKBOX_ID_COPY_ASCII);
    copyAscii->SetChecked(true);
    copyAscii->Handlers()->OnCheck = this;

    copyUnicode = Factory::RadioBox::Create(this, "Copy as &unicode text(UCS-2)", "x:5%,y:2,w:60%,h:1", CHECKBOX_ID_COPY_UNICODE);
    copyUnicode->Handlers()->OnCheck = this;

    copyUnicodeAsSeen = Factory::CheckBox::Create(this, "As seen", "x:70%,y:2,w:40%,h:1", CHECKBOX_ID_COPY_UNICODE_AS_SEEN);
    copyUnicodeAsSeen->SetChecked(true);
    copyUnicodeAsSeen->Handlers()->OnCheck = this;

    copyDump = Factory::RadioBox::Create(this, "Copy as dump &buffer", "x:5%,y:3,w:60%,h:1", CHECKBOX_ID_COPY_DUMP_BUFFER);
    copyDump->Handlers()->OnCheck = this;

    copyHex                      = Factory::RadioBox::Create(this, "Copy as &hex dump", "x:5%,y:4,w:60%,h:1", CHECKBOX_ID_COPY_HEX);
    copyHex->Handlers()->OnCheck = this;

    copyArray                      = Factory::RadioBox::Create(this, "Copy as C/C++ a&rray", "x:5%,y:5,w:60%,h:1", CHECKBOX_ID_COPY_ARRAY);
    copyArray->Handlers()->OnCheck = this;

    copyFile                      = Factory::RadioBox::Create(this, "Copy entire &file", "x:5%,y:7,w:60%,h:1", CHECKBOX_ID_COPY_FILE);
    copyFile->Handlers()->OnCheck = this;

    copySelection = Factory::RadioBox::Create(this, "Copy &selection", "x:5%,y:8,w:60%,h:1", CHECKBOX_ID_COPY_SELECTION);
    copySelection->SetChecked(true);
    copySelection->Handlers()->OnCheck = this;
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

void CopyDialog::OnCheck(Reference<Controls::Control> control, bool value)
{
}
} // namespace GView::View::BufferViewer
