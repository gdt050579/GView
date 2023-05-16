#include "GridViewer.hpp"

#include <array>
#include <regex>
#include <charconv>

namespace GView::View::GridViewer
{
constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

constexpr int32 RADIOBOX_ID_TEXT                  = 3;
constexpr int32 RADIOBOX_ID_BINARY                = 4;
constexpr int32 RADIOBOX_ID_TEXT_ASCII            = 5;
constexpr int32 RADIOBOX_ID_TEXT_UNICODE          = 6;
constexpr int32 RADIOBOX_ID_SEARCH_FILE           = 7;
constexpr int32 RADIOBOX_ID_SEARCH_SELECTION      = 8;
constexpr int32 RADIOBOX_ID_BUFFER_SELECT         = 9;
constexpr int32 RADIOBOX_ID_BUFFER_MOVE           = 10;
constexpr int32 CHECKBOX_ID_IGNORE_CASE           = 11;
constexpr int32 CHECKBOX_ID_ALIGN_TEXT_UPPER_LEFT = 12;
constexpr int32 RADIOBOX_ID_TEXT_HEX              = 13;
constexpr int32 RADIOBOX_ID_TEXT_DEC              = 14;
constexpr int32 CHECKBOX_ID_TEXT_REGEX            = 15;

constexpr int32 GROUPD_ID_SEARCH_TYPE    = 1;
constexpr int32 GROUPD_ID_TEXT_TYPE      = 2;
constexpr int32 GROUPD_ID_BUFFER_TYPE    = 3;
constexpr int32 GROUPD_ID_SELECTION_TYPE = 4;
constexpr int32 GROUPD_ID_BUFFER_ACTION  = 5;

constexpr uint32 DIALOG_HEIGHT_TEXT_FORMAT      = 18;
constexpr uint32 DESCRIPTION_HEIGHT_TEXT_FORMAT = 3;
constexpr std::string_view TEXT_FORMAT_TITLE    = "Text Pattern";
constexpr std::string_view TEXT_FORMAT_BODY     = "Plain text or regex (ECMAScript) to find. Alt+I to focus on input text field.";

constexpr std::string_view BINARY_FORMAT_TITLE = "Binary Pattern";
constexpr std::array<std::string_view, 4> BINARY_FORMAT_BODY{ "Binary pattern to find. Alt+I to focus on input text field.",
                                                              "- bytes separated through spaces",
                                                              "- input can be decimal or hexadecimal (lowercase or uppercase)",
                                                              "- ? - meaning any character (eg. 0d 0a ? ? 0d 0a)" };

constexpr uint32 DIALOG_HEIGHT_BINARY_FORMAT      = DIALOG_HEIGHT_TEXT_FORMAT + (uint32) BINARY_FORMAT_BODY.size() - 1U;
constexpr uint32 DESCRIPTION_HEIGHT_BINARY_FORMAT = DESCRIPTION_HEIGHT_TEXT_FORMAT + (DIALOG_HEIGHT_BINARY_FORMAT - DIALOG_HEIGHT_TEXT_FORMAT);

constexpr std::string_view ANYTHING_PATTERN{ "???" };

FindDialog::FindDialog()
    : Window("Find", "d:c,w:30%,h:18", WindowFlags::ProcessReturn | WindowFlags::Sizeable), currentPos(GView::Utils::INVALID_OFFSET),
      position(GView::Utils::INVALID_OFFSET), match({ GView::Utils::INVALID_OFFSET, 0 })
{
    description = Factory::CanvasViewer::Create(
          this, "d:t,h:3", this->GetWidth(), DESCRIPTION_HEIGHT_TEXT_FORMAT, Controls::ViewerFlags::Border | Controls::ViewerFlags::HideScrollBar);

    input = Factory::TextField::Create(this, "", "x:0,y:3,w:100%,h:1");
    input->SetFocus();

    textOption                      = Factory::RadioBox::Create(this, "&Text Search", "x:0,y:5,w:40%,h:1", GROUPD_ID_SEARCH_TYPE, RADIOBOX_ID_TEXT, true);
    textOption->Handlers()->OnCheck = this;

    binaryOption                      = Factory::RadioBox::Create(this, "&Binary Search", "x:0,y:6,w:40%,h:1", GROUPD_ID_SEARCH_TYPE, RADIOBOX_ID_TEXT);
    binaryOption->Handlers()->OnCheck = this;

    textAscii                      = Factory::RadioBox::Create(this, "&Ascii Text", "x:60%,y:5,w:40%,h:1", GROUPD_ID_TEXT_TYPE, RADIOBOX_ID_TEXT_ASCII, true);
    textAscii->Handlers()->OnCheck = this;

    textUnicode                      = Factory::RadioBox::Create(this, "&Unicode Text", "x:60%,y:6,w:40%,h:1", GROUPD_ID_TEXT_TYPE, RADIOBOX_ID_TEXT_UNICODE);
    textUnicode->Handlers()->OnCheck = this;

    textHex = Factory::RadioBox::Create(this, "&Hex - default base", "x:60%,y:5,w:40%,h:1", GROUPD_ID_BUFFER_TYPE, RADIOBOX_ID_TEXT_HEX, true);
    textHex->Handlers()->OnCheck = this;
    textHex->SetVisible(false);

    textDec                      = Factory::RadioBox::Create(this, "&Dec - default base", "x:60%,y:6,w:40%,h:1", GROUPD_ID_BUFFER_TYPE, RADIOBOX_ID_TEXT_DEC);
    textDec->Handlers()->OnCheck = this;
    textDec->SetVisible(false);

    textRegex                      = Factory::CheckBox::Create(this, "Use &Regex", "x:60%,y:7,w:40%,h:1", CHECKBOX_ID_TEXT_REGEX);
    textRegex->Handlers()->OnCheck = this;

    searchFile = Factory::RadioBox::Create(this, "&File Search", "x:0,y:8,w:40%,h:1", GROUPD_ID_SELECTION_TYPE, RADIOBOX_ID_SEARCH_FILE, true);
    searchFile->Handlers()->OnCheck = this;

    searchSelection = Factory::RadioBox::Create(this, "&Selection Search", "x:0,y:9,w:40%,h:1", GROUPD_ID_SELECTION_TYPE, RADIOBOX_ID_SEARCH_SELECTION);
    searchSelection->Handlers()->OnCheck = this;

    bufferSelect = Factory::RadioBox::Create(this, "&Select buffer", "x:60%,y:8,w:40%,h:1", GROUPD_ID_BUFFER_ACTION, RADIOBOX_ID_BUFFER_SELECT, true);
    bufferSelect->Handlers()->OnCheck = this;

    bufferMoveCursorTo = Factory::RadioBox::Create(this, "&Move cursor to buffer", "x:60%,y:9,w:40%,h:1", GROUPD_ID_BUFFER_ACTION, RADIOBOX_ID_BUFFER_MOVE);
    bufferMoveCursorTo->Handlers()->OnCheck = this;

    ignoreCase = Factory::CheckBox::Create(this, "I&gnore Case", "x:0,y:11,w:40%,h:1", CHECKBOX_ID_IGNORE_CASE);
    ignoreCase->SetChecked(true);
    ignoreCase->Handlers()->OnCheck = this;

    alingTextToUpperLeftCorner = Factory::CheckBox::Create(this, "A&lign text to upper left corner", "x:0,y:12,w:45%,h:1", CHECKBOX_ID_ALIGN_TEXT_UPPER_LEFT);
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
            newRequest = true;
            CHECK(ProcessInput(), false, "");
            return true;
        }
    }

    switch (eventType)
    { 
    case Event::WindowAccept:
        Exit(Dialogs::Result::Ok);
        newRequest = true;
        CHECK(ProcessInput(), false, "");
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

void FindDialog::OnCheck(Reference<Controls::Control> control, bool /* value */)
{
    const auto id = control->GetControlID();
    switch (id)
    {
    case RADIOBOX_ID_TEXT:
    case RADIOBOX_ID_BINARY:
        CHECKRET(Update(), "");
        break;

    case RADIOBOX_ID_TEXT_ASCII:
    case RADIOBOX_ID_TEXT_UNICODE:
        break;

    case RADIOBOX_ID_SEARCH_FILE:
    case RADIOBOX_ID_SEARCH_SELECTION:
        break;

    case RADIOBOX_ID_BUFFER_SELECT:
    case RADIOBOX_ID_BUFFER_MOVE:
        break;

    case RADIOBOX_ID_TEXT_HEX:
    case RADIOBOX_ID_TEXT_DEC:
        break;
    }
}

void FindDialog::OnFocus()
{
    if (this->input.IsValid())
    {
        this->input->SetFocus();
    }
    return Window::OnFocus();
}

bool FindDialog::SetDescription()
{
    const auto height = textOption->IsChecked() ? DESCRIPTION_HEIGHT_TEXT_FORMAT : DESCRIPTION_HEIGHT_BINARY_FORMAT;
    description->Resize(description->GetWidth(), height);

    CHECK(description.IsValid(), false, "");

    const auto title = textOption->IsChecked() ? TEXT_FORMAT_TITLE.data() : BINARY_FORMAT_TITLE.data();
    CHECK(description->SetText(title), false, "");

    const uint32 canvasHeight = textOption->IsChecked() ? DESCRIPTION_HEIGHT_TEXT_FORMAT : DESCRIPTION_HEIGHT_BINARY_FORMAT;
    CHECK(description->GetCanvas()->Resize(description->GetWidth(), canvasHeight), false, "");

    const auto color     = this->GetConfig()->Window.Background.Normal;
    const auto colorPair = ColorPair{ color, color };
    CHECK(description->GetCanvas()->FillRect(0, 0, this->GetWidth(), canvasHeight, ' ', colorPair), false, "");

    const auto flags = WriteTextFlags::SingleLine | WriteTextFlags::ClipToWidth | WriteTextFlags::FitTextToWidth | WriteTextFlags::OverwriteColors;
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
    if ((textOption->IsChecked() && this->GetHeight() == DIALOG_HEIGHT_TEXT_FORMAT) ||
        (binaryOption->IsChecked() && this->GetHeight() == DIALOG_HEIGHT_BINARY_FORMAT))
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
        textRegex->SetVisible(true);

        textHex->SetVisible(false);
        textDec->SetVisible(false);

        return true;
    }

    input->MoveTo(input->GetX(), input->GetY() + deltaSigned);
    textOption->MoveTo(textOption->GetX(), textOption->GetY() + deltaSigned);
    binaryOption->MoveTo(binaryOption->GetX(), binaryOption->GetY() + deltaSigned);

    textAscii->SetVisible(false);
    textUnicode->SetVisible(false);
    textRegex->SetVisible(false);

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

std::u16string FindDialog::GetFilterValue()
{
    return (std::u16string) this->input->GetText();
}

bool FindDialog::ProcessInput()
{
    CHECK(currentPos != GView::Utils::INVALID_OFFSET, false, "");
    CHECK(object.IsValid(), false, "");
    CHECK(input.IsValid(), false, "");

    if (input->GetText().Len() == 0)
    {
        Dialogs::MessageBox::ShowError("Error!", "Missing input!");
        return false;
    }
    return true;
}
} // namespace GView::View::GridViewer
