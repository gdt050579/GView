#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;
using namespace AppCUI::Dialogs;

constexpr int BUTTON_ID_CHOOSE_FILE = 1;
constexpr int BUTTON_ID_OK          = 2;
constexpr int BUTTON_ID_CANCEL      = 3;

AreaHighlighter::AreaHighlighter(Reference<PEFile> pe) : Window("Executed Code Highlighter", "x:30%,y:40%,w:110,h:13", WindowFlags::ProcessReturn), pe(pe)
{
    ld = Factory::Label::Create(this, "Choose a file that will be parsed in order to highlight the executed code", "x:1,y:1,w:98%,h:1");

    lfn  = Factory::Label::Create(this, "File &Name", "x:1,y:3,w:10%");
    tfcp = Factory::TextField::Create(this, "", "x:11%,y:3,w:75%");
    tfcp->SetHotKey('N');
    bcp = Factory::Button::Create(this, "Choose &file", "x:87%,y:3,w:13%", BUTTON_ID_CHOOSE_FILE);

    lre  = Factory::Label::Create(this, "The regular expression that will process each line parsed", "x:1,y:5,w:98%,h:1");
    tfre = Factory::TextField::Create(this, "", "x:1,y:7,w:98%,h:1");

    bok     = Factory::Button::Create(this, "&Ok", "x:22%,y:9,w:15%", BUTTON_ID_OK);
    bcancel = Factory::Button::Create(this, "&Cancel", "x:63%,y:9,w:15%", BUTTON_ID_CANCEL);
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
            // TODO:
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
