#include "BufferViewer.hpp"

#include <array>

namespace GView::View::BufferViewer
{
constexpr int32 BTN_ID_OK                         = 1;
constexpr int32 BTN_ID_CANCEL                     = 2;
constexpr int32 CHECKBOX_ID_TEXT                  = 3;
constexpr int32 CHECKBOX_ID_BINARY                = 4;
constexpr int32 CHECKBOX_ID_TEXT_ASCII            = 5;
constexpr int32 CHECKBOX_ID_TEXT_UNICODE          = 6;
constexpr int32 CHECKBOX_ID_SEARCH_FILE           = 7;
constexpr int32 CHECKBOX_ID_SEARCH_SELECTION      = 8;
constexpr int32 CHECKBOX_ID_BUFFER_SELECT         = 9;
constexpr int32 CHECKBOX_ID_BUFFER_MOVE           = 10;
constexpr int32 CHECKBOX_ID_IGNORE_CASE           = 11;
constexpr int32 CHECKBOX_ID_ALIGN_TEXT_UPPER_LEFT = 12;
constexpr int32 CHECKBOX_ID_TEXT_HEX              = 13;
constexpr int32 CHECKBOX_ID_TEXT_DEC              = 14;

constexpr uint32 DIALOG_HEIGHT_TEXT_FORMAT      = 18;
constexpr uint32 DESCRIPTION_HEIGHT_TEXT_FORMAT = 3;
constexpr std::string_view TEXT_FORMAT_TITLE    = "Text Format";
constexpr std::string_view TEXT_FORMAT_BODY     = "Enter the plain text to find. Alt+I to focus on input text field.";

constexpr std::string_view BINARY_FORMAT_TITLE = "Binary Format";
constexpr std::array<std::string_view, 8> BINARY_FORMAT_BODY{ "Enter the pattern to find. Alt+I to focus on input text field.",
                                                              "- \'string\' or \"string\"",
                                                              "- ? for anything and numbers",
                                                              "- can have specifier:",
                                                              " * (b) - byte",
                                                              " * (w) - word",
                                                              " * (d) - double",
                                                              " * (q) - qword" };

constexpr uint32 DIALOG_HEIGHT_BINARY_FORMAT = DIALOG_HEIGHT_TEXT_FORMAT + (uint32) BINARY_FORMAT_BODY.size() - 1U;
constexpr uint32 DESCRIPTION_HEIGHT_BINARY_FORMAT =
      DESCRIPTION_HEIGHT_TEXT_FORMAT + (DIALOG_HEIGHT_BINARY_FORMAT - DIALOG_HEIGHT_TEXT_FORMAT);

FindDialog::FindDialog(Reference<SettingsData> settings, uint64 currentPos, Reference<GView::Object> object)
    : Window("Find", "d:c,w:30%,h:18", WindowFlags::ProcessReturn | WindowFlags::Sizeable), settings(settings), currentPos(currentPos),
      object(object), resultedPos(GView::Utils::INVALID_OFFSET)
{
    description = Factory::CanvasViewer::Create(
          this,
          "d:t,h:3",
          this->GetWidth(),
          DESCRIPTION_HEIGHT_TEXT_FORMAT,
          Controls::ViewerFlags::Border | Controls::ViewerFlags::HideScrollBar);

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

    textHex = Factory::CheckBox::Create(this, "&Hex - default base", "x:60%,y:5,w:40%,h:1", CHECKBOX_ID_TEXT_HEX);
    textHex->SetChecked(true);
    textHex->Handlers()->OnCheck = this;

    textDec                      = Factory::CheckBox::Create(this, "&Dec - default base", "x:60%,y:6,w:40%,h:1", CHECKBOX_ID_TEXT_DEC);
    textDec->Handlers()->OnCheck = this;

    searchFile = Factory::CheckBox::Create(this, "&File Search", "x:0,y:8,w:40%,h:1", CHECKBOX_ID_SEARCH_FILE);
    searchFile->SetChecked(true);
    searchFile->Handlers()->OnCheck = this;

    searchSelection = Factory::CheckBox::Create(this, "&Selection Search", "x:0,y:9,w:40%,h:1", CHECKBOX_ID_SEARCH_SELECTION);
    searchSelection->Handlers()->OnCheck = this;

    if (object->GetContentType()->GetSelectionZonesCount() == 0)
    {
        searchFile->SetEnabled(false);
        searchSelection->SetEnabled(false);
    }

    bufferSelect = Factory::CheckBox::Create(this, "&Select buffer", "x:60%,y:8,w:40%,h:1", CHECKBOX_ID_BUFFER_SELECT);
    bufferSelect->SetChecked(true);
    bufferSelect->Handlers()->OnCheck = this;

    bufferMoveCursorTo = Factory::CheckBox::Create(this, "&Move cursor to buffer", "x:60%,y:9,w:40%,h:1", CHECKBOX_ID_BUFFER_MOVE);
    bufferMoveCursorTo->Handlers()->OnCheck = this;

    ignoreCase = Factory::CheckBox::Create(this, "&Ignore Case", "x:0,y:11,w:40%,h:1", CHECKBOX_ID_IGNORE_CASE);
    ignoreCase->SetChecked(true);
    ignoreCase->Handlers()->OnCheck = this;

    alingTextToUpperLeftCorner =
          Factory::CheckBox::Create(this, "&Align text to upper left corner", "x:0,y:12,w:45%,h:1", CHECKBOX_ID_ALIGN_TEXT_UPPER_LEFT);
    alingTextToUpperLeftCorner->SetChecked(true);
    alingTextToUpperLeftCorner->Handlers()->OnCheck = this;

    Factory::Button::Create(this, "&OK", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL);

    SetDescription();
    Update();
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
        CHECKRET(Update(), "");
        break;
    case CHECKBOX_ID_BINARY:
        textOption->SetChecked(!value);
        if (!value)
            textOption->SetFocus();
        CHECKRET(Update(), "");
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
        searchSelection->SetChecked(!value);
        if (!value)
            searchSelection->SetFocus();
        break;
    case CHECKBOX_ID_SEARCH_SELECTION:
        searchFile->SetChecked(!value);
        if (!value)
            searchFile->SetFocus();
        break;

    case CHECKBOX_ID_BUFFER_SELECT:
        bufferMoveCursorTo->SetChecked(!value);
        if (!value)
            bufferMoveCursorTo->SetFocus();
        break;
    case CHECKBOX_ID_BUFFER_MOVE:
        bufferSelect->SetChecked(!value);
        if (!value)
            bufferSelect->SetFocus();
        break;

    case CHECKBOX_ID_TEXT_HEX:
        textDec->SetChecked(!value);
        if (!value)
            textDec->SetFocus();
        break;
    case CHECKBOX_ID_TEXT_DEC:
        textHex->SetChecked(!value);
        if (!value)
            textHex->SetFocus();
        break;
    }
}

bool FindDialog::SetDescription()
{
    const auto height = textOption->IsChecked() ? DESCRIPTION_HEIGHT_TEXT_FORMAT : DESCRIPTION_HEIGHT_BINARY_FORMAT;
    description->Resize(description->GetWidth(), height);

    CHECK(description.IsValid(), false, "");

    const auto title = textOption->IsChecked() ? TEXT_FORMAT_TITLE.data() : BINARY_FORMAT_TITLE.data();
    CHECK(description->SetText(title), false, "");

    const uint32 canvasHeight = textOption->IsChecked() ? DESCRIPTION_HEIGHT_TEXT_FORMAT : DESCRIPTION_HEIGHT_BINARY_FORMAT;
    CHECK(description->GetCanvas()->Resize(description->GetCanvas()->GetWidth(), canvasHeight), false, "");

    const auto color     = this->GetConfig()->Window.Background.Normal;
    const auto colorPair = ColorPair{ color, color };
    CHECK(description->GetCanvas()->FillRect(0, 0, this->GetWidth(), canvasHeight, ' ', colorPair), false, "");

    const auto flags =
          WriteTextFlags::SingleLine | WriteTextFlags::ClipToWidth | WriteTextFlags::FitTextToWidth | WriteTextFlags::OverwriteColors;
    WriteTextParams wtp{ flags, TextAlignament::Left };
    wtp.X     = 0;
    wtp.Y     = 0;
    wtp.Color = ColorPair{ Color::Yellow, Color::Transparent };

    if (textOption->IsChecked())
    {
        CHECK(description->GetCanvas()->WriteText(TEXT_FORMAT_BODY.data(), wtp), false, "");
    }
    else
    {
        for (const auto& line : BINARY_FORMAT_BODY)
        {
            CHECK(description->GetCanvas()->WriteText(line.data(), wtp), false, "");
            wtp.Y++;
        }
    }

    description->SetEnabled(false);

    return true;
}

bool FindDialog::Update()
{
    if (textOption->IsChecked() && this->GetHeight() == DIALOG_HEIGHT_TEXT_FORMAT ||
        binaryOption->IsChecked() && this->GetHeight() == DIALOG_HEIGHT_BINARY_FORMAT)
    {
        return true;
    }

    const auto height = textOption->IsChecked() ? DIALOG_HEIGHT_TEXT_FORMAT : DIALOG_HEIGHT_BINARY_FORMAT;

    this->Resize(this->GetWidth(), height);
    SetDescription();

    const uint32 deltaHeight = DIALOG_HEIGHT_BINARY_FORMAT - DIALOG_HEIGHT_TEXT_FORMAT;
    const int32 sign         = textOption->IsChecked() ? -1 : 1;
    const int32 deltaSigned  = sign * deltaHeight;

    if (textOption->IsChecked())
    {
        textAscii->SetVisible(true);
        textUnicode->SetVisible(true);

        textHex->SetVisible(false);
        textDec->SetVisible(false);

        return true;
    }

    input->MoveTo(input->GetX(), input->GetY() + deltaSigned);
    textOption->MoveTo(textOption->GetX(), textOption->GetY() + deltaSigned);
    binaryOption->MoveTo(binaryOption->GetX(), binaryOption->GetY() + deltaSigned);

    textAscii->SetVisible(false);
    textUnicode->SetVisible(false);

    textHex->SetVisible(true);
    textDec->SetVisible(true);

    textHex->MoveTo(textAscii->GetX(), textAscii->GetY() + deltaSigned);
    textDec->MoveTo(textUnicode->GetX(), textUnicode->GetY() + deltaSigned);

    searchFile->MoveTo(searchFile->GetX(), searchFile->GetY() + deltaSigned);
    searchSelection->MoveTo(searchSelection->GetX(), searchSelection->GetY() + deltaSigned);
    bufferSelect->MoveTo(bufferSelect->GetX(), bufferSelect->GetY() + deltaSigned);
    bufferMoveCursorTo->MoveTo(bufferMoveCursorTo->GetX(), bufferMoveCursorTo->GetY() + deltaSigned);
    ignoreCase->MoveTo(ignoreCase->GetX(), ignoreCase->GetY() + deltaSigned);
    alingTextToUpperLeftCorner->MoveTo(alingTextToUpperLeftCorner->GetX(), alingTextToUpperLeftCorner->GetY() + deltaSigned);

    return true;
}
} // namespace GView::View::BufferViewer
