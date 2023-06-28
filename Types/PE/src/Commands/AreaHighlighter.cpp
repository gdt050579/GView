#include "pe.hpp"

#include <fstream>
#include <regex>

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;
using namespace AppCUI::Dialogs;

constexpr int BUTTON_ID_CHOOSE_FILE = 1;
constexpr int BUTTON_ID_OK          = 2;
constexpr int BUTTON_ID_CANCEL      = 3;

constexpr ColorPair HIGHLIGHTED_AREA{ Color::DarkBlue, Color::Green };

AreaHighlighter::AreaHighlighter(Reference<PEFile> pe) : Window("Executed Code Highlighter", "x:30%,y:40%,w:110,h:17", WindowFlags::ProcessReturn), pe(pe)
{
    ld = Factory::Label::Create(this, "Choose a file that will be parsed in order to highlight the executed code", "x:1,y:1,w:98%,h:1");

    lfn  = Factory::Label::Create(this, "File &Name", "x:1,y:3,w:10%");
    tfcp = Factory::TextField::Create(this, "", "x:11%,y:3,w:75%");
    tfcp->SetHotKey('N');
    bcp = Factory::Button::Create(this, "Choose &file", "x:87%,y:3,w:13%", BUTTON_ID_CHOOSE_FILE);
    bcp->SetFocus();

    lre  = Factory::Label::Create(this, "The regular expression that will find executed instructions:", "x:1,y:5,w:98%,h:1");
    tfre = Factory::TextField::Create(this, "", "x:1,y:7,w:98%,h:1");

    lff  = Factory::Label::Create(this, "Line filter:", "x:1,y:9,w:98%,h:1");
    tfff = Factory::TextField::Create(this, "", "x:1,y:11,w:98%,h:1");

    bok     = Factory::Button::Create(this, "&Ok", "x:22%,y:13,w:15%", BUTTON_ID_OK);
    bcancel = Factory::Button::Create(this, "&Cancel", "x:63%,y:13,w:15%", BUTTON_ID_CANCEL);
};

void AreaHighlighter::ChooseFile()
{
    auto path = std::filesystem::path(pe->obj->GetPath());
    if (std::filesystem::is_regular_file(path))
    {
        path = path.parent_path();
    }

    while (true)
    {
        auto res = FileDialog::ShowOpenFileWindow("", "", path.generic_u16string());
        if (res.has_value())
        {
            const auto p = res->u8string();
            if (std::filesystem::is_regular_file(std::filesystem::path(p)))
            {
                tfcp->SetText(p);
                bok->SetFocus();
                break;
            }
            else
            {
                MessageBox::ShowError("Error", u8"The chosen path is not a file: " + p);
            }
        }
        else
        {
            tfcp->SetText("Command canceled!");
            break;
        }
    }
}

bool AreaHighlighter::FindExecutedCode()
{
    const auto path = std::filesystem::path(tfcp->GetText());
    if (!std::filesystem::is_regular_file(path))
    {
        MessageBox::ShowError("Error", u8"The chosen path is not a file: " + path.u8string());
        return false;
    }

    if (tfre->GetText().IsEmpty())
    {
        MessageBox::ShowError("Error", u8"The regex is empty!");
        return false;
    }

    addresses.clear();

    std::ifstream infile(path);

    UnicodeStringBuilder usb{ tfre->GetText() };
    std::string ascii;
    usb.ToString(ascii);

    const static std::regex specialChars{ R"([-[\]{}()*+?.,\^$|#\s])" };
    // ascii = std::regex_replace(ascii, specialChars, R"(\$&)");
    const std::regex pattern(ascii, std::regex_constants::ECMAScript | std::regex_constants::optimize);

    std::string filter;
    if (!tfff->GetText().IsEmpty())
    {
        usb.Set(tfff->GetText());
        usb.ToString(filter);
    }

    std::string line;
    auto offset = 0u;
    while (std::getline(infile, line))
    {
        if (!filter.empty())
        {
            if (line.find(filter) == std::string::npos)
            {
                continue;
            }
        }

        const auto initialStart = reinterpret_cast<char const*>(line.c_str());
        auto start              = reinterpret_cast<char const*>(line.c_str());
        const auto end          = reinterpret_cast<char const*>(start + line.size());
        std::cmatch matches{};
        while (std::regex_search(start, end, matches, pattern))
        {
            if (matches.size() > 2)
            {
                const auto startAddress = pe->ConvertAddress(
                      std::stoull(matches[1].str(), nullptr, 16), GView::Type::PE::AddressType::VA, GView::Type::PE::AddressType::FileOffset);

                if (startAddress != PE_INVALID_ADDRESS)
                {
                    const auto bytes      = matches[0].str();
                    const auto bytesCount = std::count_if(bytes.begin(), bytes.end(), [](unsigned char c) { return c == ' '; }) - 1;
                    const auto endAddress = startAddress + bytesCount;

                    bool found = false;
                    for (auto& [s, e] : addresses)
                    {
                        if (startAddress >= s && startAddress <= e)
                        {
                            e     = std::max<uint64>(e, endAddress);
                            found = true;
                            break;
                        }

                        if (endAddress >= s && endAddress <= e)
                        {
                            s     = std::min<uint64>(s, startAddress);
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                    {
                        addresses.push_back({ startAddress, endAddress });
                    }
                }
            }
            start += matches.position() + matches.length();
        }
    }

    infile.close();

    if (addresses.empty())
    {
        MessageBox::ShowError("Error", u8"No executed code found!");
        return false;
    }

    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto view      = interface->GetCurrentView();
        view->SetBufferColorProcessorCallback(this);
        view->OnEvent(nullptr, AppCUI::Controls::Event::Command, View::VIEW_COMMAND_ACTIVATE_CODE_EXECUTION);
    }

    return true;
}

bool AreaHighlighter::GetColorForByteAt(uint64 offset, const GView::View::ViewData& vd, ColorPair& cp)
{
    for (const auto& [k, v] : addresses)
    {
        if (k <= offset && offset < v)
        {
            cp = HIGHLIGHTED_AREA;
            return true;
        }
    }

    return false;
}

bool AreaHighlighter::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    switch (evnt)
    {
    case Event::WindowClose:
        return Exit(Dialogs::Result::Cancel);
    case Event::ButtonClicked:
        switch (controlID)
        {
        case BUTTON_ID_CHOOSE_FILE:
            ChooseFile();
            return true;
        case BUTTON_ID_OK:
            if (FindExecutedCode())
            {
                return Exit(Dialogs::Result::Ok);
            }
            return true;
        case BUTTON_ID_CANCEL:
            return Exit(Dialogs::Result::Cancel);
        default:
            break;
        }
    default:
        return false;
    }
}
} // namespace GView::Type::PE::Commands
