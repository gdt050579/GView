#include "BufferViewer.hpp"

namespace GView::View::BufferViewer
{
constexpr int32 BTN_ID_OK                    = 1;
constexpr int32 BTN_ID_CANCEL                = 2;
constexpr int32 CHECKBOX_ID_TEXT             = 3;
constexpr int32 CHECKBOX_ID_BINARY           = 4;
constexpr int32 CHECKBOX_ID_TEXT_ASCII       = 5;
constexpr int32 CHECKBOX_ID_TEXT_UNICODE     = 6;
constexpr int32 CHECKBOX_ID_SEARCH_FILE      = 7;
constexpr int32 CHECKBOX_ID_SEARCH_SELECTION = 8;

FindDialog::FindDialog(Reference<SettingsData> settings, uint64 currentPos, Reference<GView::Object> object)
    : Window("Find", "d:c,w:30%,h:30%", WindowFlags::ProcessReturn), settings(settings), currentPos(currentPos), object(object),
      resultedPos(GView::Utils::INVALID_OFFSET)
{
    CHECKRET(SetDescription(), "");

    input = Factory::TextField::Create(this, "", "x:0,y:3,w:100%,h:1");
    input->SetFocus();

    textOption = Factory::CheckBox::Create(this, "&Text Search", "x:0,y:5,w:40%,h:1", CHECKBOX_ID_TEXT);
    textOption->SetChecked(true);
    textOption->Handlers()->OnCheck = this;

    binaryOption                      = Factory::CheckBox::Create(this, "&Binary Search", "x:0,y:6,w:40%,h:1", CHECKBOX_ID_BINARY);
    binaryOption->Handlers()->OnCheck = this;

    textAscii = Factory::CheckBox::Create(this, "&Ascii Text", "x:60%,y:5,w:40%,h:1", CHECKBOX_ID_TEXT_ASCII);
    textAscii->SetChecked(true);
    textAscii->Handlers()->OnCheck = this;

    textUnicode                      = Factory::CheckBox::Create(this, "&Unicode Text", "x:60%,y:6,w:40%,h:1", CHECKBOX_ID_TEXT_UNICODE);
    textUnicode->Handlers()->OnCheck = this;

    fileSearch = Factory::CheckBox::Create(this, "&File Search", "x:0,y:8,w:40%,h:1", CHECKBOX_ID_SEARCH_FILE);
    fileSearch->SetChecked(true);
    fileSearch->Handlers()->OnCheck = this;

    selectionSearch = Factory::CheckBox::Create(this, "&Selection Search", "x:0,y:9,w:40%,h:1", CHECKBOX_ID_SEARCH_SELECTION);
    selectionSearch->Handlers()->OnCheck = this;

    if (object->GetContentType()->GetSelectionZonesCount() == 0)
    {
        fileSearch->SetEnabled(false);
        selectionSearch->SetEnabled(false);
    }

    Factory::Button::Create(this, "&OK", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL);
}

bool FindDialog::OnEvent(Reference<Control>, Event eventType, int ID)
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

bool FindDialog::OnKeyEvent(Input::Key keyCode, char16 UnicodeChar)
{
    if (keyCode == (Input::Key::Alt | Input::Key::I))
    {
        input->SetFocus();
        return true;
    }
    return Window::OnKeyEvent(keyCode, UnicodeChar);
}

void FindDialog::OnCheck(Reference<Controls::Control> control, bool value)
{
    const auto id = control->GetControlID();
    switch (id)
    {
    case CHECKBOX_ID_TEXT:
        binaryOption->SetChecked(!value);
        if (!value)
            binaryOption->SetFocus();
        break;
    case CHECKBOX_ID_BINARY:
        textOption->SetChecked(!value);
        if (!value)
            textOption->SetFocus();
        break;

    case CHECKBOX_ID_TEXT_ASCII:
        textUnicode->SetChecked(!value);
        if (!value)
            textUnicode->SetFocus();
        break;
    case CHECKBOX_ID_TEXT_UNICODE:
        textAscii->SetChecked(!value);
        if (!value)
            textAscii->SetFocus();
        break;

    case CHECKBOX_ID_SEARCH_FILE:
        selectionSearch->SetChecked(!value);
        if (!value)
            selectionSearch->SetFocus();
        break;
    case CHECKBOX_ID_SEARCH_SELECTION:
        fileSearch->SetChecked(!value);
        if (!value)
            fileSearch->SetFocus();
        break;
    }
}

bool FindDialog::SetDescription()
{
    description = Factory::CanvasViewer::Create(
          this, "d:t,h:3", this->GetWidth(), 3, Controls::ViewerFlags::Border | Controls::ViewerFlags::HideScrollBar);

    CHECK(description.IsValid(), false, "");

    CHECK(description->SetText("Text Format"), false, "");

    CHECK(description->GetCanvas()->FillRect(
                0,
                0,
                this->GetWidth(),
                3,
                ' ',
                ColorPair{ this->GetConfig()->Window.Background.Normal, this->GetConfig()->Window.Background.Normal }),
          false,
          "");

    WriteTextParams wtp{ WriteTextFlags::SingleLine | WriteTextFlags::ClipToWidth | WriteTextFlags::FitTextToWidth |
                               WriteTextFlags::OverwriteColors,
                         TextAlignament::Left };
    wtp.X     = 0;
    wtp.Y     = 0;
    wtp.Color = ColorPair{ Color::Yellow, Color::Transparent };
    CHECK(description->GetCanvas()->WriteText("Enter the plain text to find. Alt+I to focus on input text field.", wtp), false, "");
    description->SetEnabled(false);

    return true;
}
} // namespace GView::View::BufferViewer
