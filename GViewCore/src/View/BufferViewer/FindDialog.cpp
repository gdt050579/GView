#include "BufferViewer.hpp"

#include <array>
#include <regex>

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
constexpr int32 CHECKBOX_ID_TEXT_REGEX            = 15;

constexpr uint32 DIALOG_HEIGHT_TEXT_FORMAT      = 18;
constexpr uint32 DESCRIPTION_HEIGHT_TEXT_FORMAT = 3;
constexpr std::string_view TEXT_FORMAT_TITLE    = "Text Pattern";
constexpr std::string_view TEXT_FORMAT_BODY     = "Plain text or regex (ECMAScript) to find. Alt+I to focus on input text field.";

constexpr std::string_view BINARY_FORMAT_TITLE = "Binary Pattern";
constexpr std::array<std::string_view, 8> BINARY_FORMAT_BODY{ "Binary pattern to find. Alt+I to focus on input text field.",
                                                              "- bytes separated through spaces",
                                                              "- input can be decimal or hexadecimal" };

constexpr uint32 DIALOG_HEIGHT_BINARY_FORMAT = DIALOG_HEIGHT_TEXT_FORMAT + (uint32) BINARY_FORMAT_BODY.size() - 1U;
constexpr uint32 DESCRIPTION_HEIGHT_BINARY_FORMAT =
      DESCRIPTION_HEIGHT_TEXT_FORMAT + (DIALOG_HEIGHT_BINARY_FORMAT - DIALOG_HEIGHT_TEXT_FORMAT);

FindDialog::FindDialog(Reference<SettingsData> settings, uint64 currentPos, Reference<GView::Object> object)
    : Window("Find", "d:c,w:30%,h:18", WindowFlags::ProcessReturn | WindowFlags::Sizeable), settings(settings), currentPos(currentPos),
      object(object), position(GView::Utils::INVALID_OFFSET)
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
    textHex->SetVisible(false);

    textDec                      = Factory::CheckBox::Create(this, "&Dec - default base", "x:60%,y:6,w:40%,h:1", CHECKBOX_ID_TEXT_DEC);
    textDec->Handlers()->OnCheck = this;
    textDec->SetVisible(false);

    textRegex                      = Factory::CheckBox::Create(this, "Use &Regex", "x:60%,y:7,w:40%,h:1", CHECKBOX_ID_TEXT_REGEX);
    textRegex->Handlers()->OnCheck = this;

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
            CHECK(ProcessInput(), false, "");
            return true;
        }
    }

    switch (eventType)
    {
    case Event::WindowAccept:
        Exit(Dialogs::Result::Ok);
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

bool FindDialog::ProcessInput()
{
    UnicodeStringBuilder usb{};
    CHECK(usb.Set(input->GetText()), false, "");
    CHECK(usb.Len() > 0, false, "");

    std::vector<TypeInterface::SelectionZone> selectedZones;
    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++)
    {
        selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    const auto computeForFile = !searchSelection->IsChecked();

    auto objectSize = 0ULL;
    if (computeForFile)
    {
        objectSize = object->GetData().GetSize();
    }
    else
    {
        for (auto& sz : selectedZones)
        {
            objectSize += sz.end - sz.start + 1;
        }
    }
    ProgressStatus::Init("Searching...", objectSize);

    LocalString<512> ls;

    const char* format = "Reading [0x%.8llX/0x%.8llX] bytes...";
    if (objectSize > 0xFFFFFFFF)
    {
        format = "[0x%.16llX/0x%.16llX] bytes...";
    }

    const auto block = object->GetData().GetCacheSize();

    if (textOption->IsChecked())
    {
        if (textAscii->IsChecked())
        {
            std::string ascii;
            usb.ToString(ascii);

            if (textRegex->IsChecked() == false)
            {
                const static std::regex specialChars{ R"([-[\]{}()*+?.,\^$|#\s])" };
                ascii = std::regex_replace(ascii, specialChars, R"(\$&)");
            }

            const std::regex pattern(
                  ascii,
                  (ignoreCase->IsChecked() ? std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize
                                           : std::regex_constants::ECMAScript | std::regex_constants::optimize));

            if (computeForFile)
            {
                auto offset = currentPos;
                auto left   = object->GetData().GetSize() - currentPos;

                do
                {
                    CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

                    const auto sizeToRead = (left >= block ? block : left);
                    left -= (left >= block ? block : left);

                    const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
                    CHECK(buffer.IsValid(), false, "");

                    auto start = (char const* const) buffer.GetData();
                    auto end   = (char const* const) (start + buffer.GetLength());
                    std::cmatch m{};
                    found = std::regex_search(start, end, m, pattern);
                    if (found)
                    {
                        this->position = offset + m.position();
                        this->length   = m.length();

                        return true;
                    }

                    offset += sizeToRead;
                } while (left > 0);
            }
            else
            {
                for (const auto& zone : selectedZones)
                {
                    auto offset = zone.start;
                    auto left   = zone.end - zone.start + 1;

                    do
                    {
                        CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

                        const auto sizeToRead = (left >= block ? block : left);
                        left -= (left >= block ? block : left);

                        const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
                        CHECK(buffer.IsValid(), false, "");

                        auto start = (char const* const) buffer.GetData();
                        auto end   = (char const* const) (start + buffer.GetLength());
                        std::cmatch m{};
                        found = std::regex_search(start, end, m, pattern);
                        if (found)
                        {
                            this->position = offset + m.position();
                            this->length   = m.length();

                            return true;
                        }

                        offset += sizeToRead;
                    } while (left > 0);
                }
            }
        }
        else
        {
            std::wstring unicode{ (wchar_t*) usb.ToStringView().data(), usb.ToStringView().size() };

            if (textRegex->IsChecked() == false)
            {
                const static std::wregex specialChars{ LR"([-[\]{}()*+?.,\^$|#\s])" };
                unicode = std::regex_replace(unicode, specialChars, LR"(\$&)");
            }

            const std::wregex pattern(
                  (wchar_t*) usb.ToStringView().data(),
                  (ignoreCase->IsChecked() ? std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize
                                           : std::regex_constants::ECMAScript | std::regex_constants::optimize));

            if (computeForFile)
            {
                auto offset = currentPos;
                auto left   = object->GetData().GetSize() - currentPos;

                do
                {
                    CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

                    const auto sizeToRead = (left >= block ? block : left);
                    left -= (left >= block ? block : left);

                    const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
                    CHECK(buffer.IsValid(), false, "");

                    auto start = (wchar_t const* const) buffer.GetData();
                    auto end   = (wchar_t const* const) (start + buffer.GetLength());
                    std::wcmatch m{};
                    found = std::regex_search(start, end, m, pattern);
                    if (found)
                    {
                        this->position = offset + m.position();
                        this->length   = m.length();

                        return true;
                    }

                    offset += sizeToRead;
                } while (left > 0);
            }
            else
            {
                for (const auto& zone : selectedZones)
                {
                    auto offset = zone.start;
                    auto left   = zone.end - zone.start + 1;

                    do
                    {
                        CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

                        const auto sizeToRead = (left >= block ? block : left);
                        left -= (left >= block ? block : left);

                        const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
                        CHECK(buffer.IsValid(), false, "");

                        auto start = (wchar_t const* const) buffer.GetData();
                        auto end   = (wchar_t const* const) (start + buffer.GetLength());
                        std::wcmatch m{};
                        found = std::regex_search(start, end, m, pattern);
                        if (found)
                        {
                            this->position = offset + m.position();
                            this->length   = m.length();

                            return true;
                        }

                        offset += sizeToRead;
                    } while (left > 0);
                }
            }
        }
    }
    else
    {
    }

    return false;
}

} // namespace GView::View::BufferViewer
