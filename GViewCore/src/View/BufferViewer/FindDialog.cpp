#include "BufferViewer.hpp"

#include <array>
#include <regex>
#include <charconv>

namespace GView::View::BufferViewer
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

void FindDialog::UpdateData(uint64 currentPos, Reference<GView::Object> object)
{
    this->currentPos = currentPos;
    this->object     = object;

    const bool isAtLeastOneZoneSelected = object->GetContentType()->GetSelectionZonesCount() > 0;
    if (searchFile.IsValid())
    {
        searchFile->SetEnabled(isAtLeastOneZoneSelected);
    }
    if (searchSelection.IsValid())
    {
        searchSelection->SetEnabled(isAtLeastOneZoneSelected);
    }
}

std::pair<uint64, uint64> FindDialog::GetNextMatch(uint64 currentPos)
{
    this->currentPos = currentPos;
    ProcessInput();
    return match;
}

std::pair<uint64, uint64> FindDialog::GetPreviousMatch(uint64 currentPos)
{
    const auto initialCurrentPos = this->currentPos;
    while (true)
    {
        const auto end   = currentPos - 1;
        this->currentPos = this->object->GetData().GetCacheSize() > currentPos ? 0 : currentPos - this->object->GetData().GetCacheSize();
        ProcessInput(end, true);
        if (HasResults())
        {
            this->currentPos = match.first;
            break;
        }
        CHECKBK(this->currentPos, "");
    };
    if (HasResults() == false)
    {
        this->currentPos = initialCurrentPos;
    }
    return match;
}

bool ValidateDecimal(std::string_view number)
{
    CHECK(number.size() <= 3, false, "");

    if (number.find('?') == std::string::npos)
    {
        if (number.size() == 3)
        {
            CHECK(number[0] >= '0' && number[0] <= '2', false, "");
            CHECK(number[1] >= '0' && number[1] <= '5', false, "");
            if (number[1] == '5')
            {
                CHECK(number[2] >= '0' && number[2] <= '5', false, "");
            }
            else
            {
                CHECK(number[2] >= '0' && number[2] <= '9', false, "");
            }
        }
        else if (number.size() == 2)
        {
            CHECK(number[0] >= '0' && number[0] <= '9', false, "");
            CHECK(number[1] >= '0' && number[1] <= '9', false, "");
        }
        else if (number.size() == 1)
        {
            CHECK(number[0] >= '0' && number[0] <= '9', false, "");
        }
    }
    else
    {
        CHECK(ANYTHING_PATTERN.starts_with(number), false, "");
    }

    return true;
}

bool ValidateHex(std::string_view number)
{
    CHECK(number.size() <= 2, false, "");

    if (number.find('?') == std::string::npos)
    {
        CHECK((number[0] >= '0' && number[0] <= '9') || (number[0] >= 'a' && number[0] <= 'f') || (number[0] >= 'A' && number[0] <= 'F'), false, "");
        if (number.size() == 2)
        {
            CHECK((number[0] >= '1' && number[1] <= '9') || (number[1] >= 'a' && number[1] <= 'f') || (number[1] >= 'A' && number[1] <= 'F'), false, "");
        }
    }
    else
    {
        CHECK(ANYTHING_PATTERN.starts_with(number), false, "");
    }

    return true;
}

bool FindDialog::ProcessInput(uint64 end, bool last)
{
    CHECK(currentPos != GView::Utils::INVALID_OFFSET, false, "");
    CHECK(object.IsValid(), false, "");
    CHECK(input.IsValid(), false, "");

    if (input->GetText().Len() == 0)
    {
        Dialogs::MessageBox::ShowError("Error!", "Missing input!");
        return false;
    }

    CHECK(usb.Set(input->GetText()), false, "");
    CHECK(usb.Len() > 0, false, "");

    if (newRequest)
    {
        match      = { GView::Utils::INVALID_OFFSET, 0 };
        newRequest = false;
    }

    std::vector<TypeInterface::SelectionZone> selectedZones;
    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++)
    {
        selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    const auto computeForFile = !searchSelection->IsChecked();

    auto objectSize = 0ULL;
    if (computeForFile)
    {
        if (last && end != GView::Utils::INVALID_OFFSET)
        {
            objectSize = end - currentPos;
        }
        else
        {
            objectSize = object->GetData().GetSize();
        }
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

    const auto block = (last && end != GView::Utils::INVALID_OFFSET) ? (end - currentPos) : object->GetData().GetCacheSize();

    const auto SearchInAsciiChunk = [&](uint64 offset, uint64 left, const std::regex& pattern)
    {
        do
        {
            CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

            const auto sizeToRead = (left >= block ? block : left);
            left -= (left >= block ? block : left);

            const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
            CHECK(buffer.IsValid(), false, "");

            const auto initialStart = reinterpret_cast<char const*>(buffer.GetData());
            auto start              = reinterpret_cast<char const*>(buffer.GetData());
            const auto end          = reinterpret_cast<char const*>(start + buffer.GetLength());
            std::cmatch matches{};
            while (std::regex_search(start, end, matches, pattern))
            {
                match = std::pair<uint64, uint64>{ offset + (start - initialStart) + matches.position(), matches.length() };
                start += matches.position() + matches.length();
                CHECKBK(last, "");
            }

            offset += sizeToRead;
        } while (left > 0);

        return true;
    };

    const auto SearchInUnicodeChunk = [&](uint64 offset, uint64 left, const std::wregex& pattern)
    {
        do
        {
            CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

            const auto sizeToRead = (left >= block ? block : left);
            left -= (left >= block ? block : left);

            const auto buffer = object->GetData().Get(offset, static_cast<uint32>(sizeToRead), true);
            CHECK(buffer.IsValid(), false, "");

            auto initialStart = reinterpret_cast<wchar_t const*>(buffer.GetData());
            auto start        = reinterpret_cast<wchar_t const*>(buffer.GetData());
            const auto end    = reinterpret_cast<wchar_t const*>(start + buffer.GetLength());
            std::wcmatch matches{};
            while (std::regex_search(start, end, matches, pattern))
            {
                match = std::pair<uint64, uint64>{ offset + (start - initialStart) * sizeof(wchar_t) + matches.position(), matches.length() };
                start += matches.position() + matches.length();
                CHECKBK(last, "");
            }

            offset += sizeToRead;
        } while (left > 0);

        return true;
    };

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
                auto left   = (last && end != GView::Utils::INVALID_OFFSET) ? (end - currentPos) : (object->GetData().GetSize() - currentPos);

                CHECK(SearchInAsciiChunk(offset, left, pattern), false, "");
                CHECK(HasResults() == false, true, "");
            }
            else
            {
                for (const auto& zone : selectedZones)
                {
                    auto offset = zone.start;
                    auto left   = zone.end - zone.start + 1;

                    CHECK(SearchInAsciiChunk(offset, left, pattern), false, "");
                    CHECK(HasResults() == false, true, "");
                }
            }
        }
        else
        {
            std::wstring unicode{ reinterpret_cast<const wchar_t*>(usb.ToStringView().data()), usb.ToStringView().size() };

            if (textRegex->IsChecked() == false)
            {
                const static std::wregex specialChars{ LR"([-[\]{}()*+?.,\^$|#\s])" };
                unicode = std::regex_replace(unicode, specialChars, LR"(\$&)");
            }

            const std::wregex pattern(
                  reinterpret_cast<wchar_t const* const>(usb.ToStringView().data()),
                  (ignoreCase->IsChecked() ? std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize
                                           : std::regex_constants::ECMAScript | std::regex_constants::optimize));

            if (computeForFile)
            {
                auto offset = currentPos;
                auto left   = (last && end != GView::Utils::INVALID_OFFSET) ? (end - currentPos) : (object->GetData().GetSize() - currentPos);

                CHECK(SearchInUnicodeChunk(offset, left, pattern), false, "");
                CHECK(HasResults() == false, true, "");
            }
            else
            {
                for (const auto& zone : selectedZones)
                {
                    auto offset = zone.start;
                    auto left   = zone.end - zone.start + 1;

                    CHECK(SearchInUnicodeChunk(offset, left, pattern), false, "");
                    CHECK(HasResults() == false, true, "");
                }
            }
        }
    }
    else
    {
        std::string input;
        usb.ToString(input);

        std::string regexPayload;
        regexPayload.reserve(input.size() * 2);

        uint64 last    = 0;
        uint64 current = input.find_first_of(' ', last);
        do
        {
            if (current == std::string::npos)
            {
                current = input.size();
            }

            std::string_view number{ input.data() + last, current - last };

            if (textDec->IsChecked())
            {
                if (ValidateDecimal(number) == false)
                {
                    Dialogs::MessageBox::ShowError("Error!", "Invalid input!");
                    return false;
                }

                if (number[0] == '?')
                {
                    regexPayload.append("[\\x00-\\xFF]");
                }
                else
                {
                    uint8 n;
                    const std::from_chars_result resultFrom = std::from_chars(number.data(), number.data() + number.size(), n);
                    if (resultFrom.ec == std::errc::invalid_argument || resultFrom.ec == std::errc::result_out_of_range)
                    {
                        Dialogs::MessageBox::ShowError("Error!", "Invalid input - conversion failed!");
                        return false;
                    }

                    char hex[10]                        = { 0 };
                    const std::to_chars_result resultTo = std::to_chars(std::begin(hex), std::end(hex), n, 16);
                    if (resultTo.ec == std::errc::invalid_argument || resultTo.ec == std::errc::result_out_of_range)
                    {
                        Dialogs::MessageBox::ShowError("Error!", "Invalid input - conversion failed!");
                        return false;
                    }
                    regexPayload.append("\\x");
                    if (hex[1] == 0)
                    {
                        regexPayload.append("0");
                    }
                    regexPayload.append(hex);
                }
            }
            else
            {
                if (number.size() > 2)
                {
                    Dialogs::MessageBox::ShowError("Error!", "Invalid input!");
                    return false;
                }

                if (ValidateHex(number) == false)
                {
                    Dialogs::MessageBox::ShowError("Error!", "Invalid input!");
                    return false;
                }

                if (number[0] == '?')
                {
                    regexPayload.append("[\\x00-\\xFF]");
                }
                else
                {
                    regexPayload.append("\\x");
                    if (number.size() == 1)
                    {
                        regexPayload.append("0");
                    }
                    regexPayload.append(number);
                }
            }
            last = current + 1;
        } while ((current = input.find_first_of(' ', last)) && last < input.size());

        const std::regex pattern(
              regexPayload,
              (ignoreCase->IsChecked() ? std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize
                                       : std::regex_constants::ECMAScript | std::regex_constants::optimize));

        if (computeForFile)
        {
            auto offset = currentPos;
            auto left   = (last && end != GView::Utils::INVALID_OFFSET) ? (end - currentPos) : (object->GetData().GetSize() - currentPos);

            CHECK(SearchInAsciiChunk(offset, left, pattern), false, "");
            CHECK(HasResults() == false, true, "");
        }
        else
        {
            for (const auto& zone : selectedZones)
            {
                auto offset = zone.start;
                auto left   = zone.end - zone.start + 1;

                CHECK(SearchInAsciiChunk(offset, left, pattern), false, "");
                CHECK(HasResults() == false, true, "");
            }
        }
    }

    return false;
}
} // namespace GView::View::BufferViewer
