#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;
using namespace AppCUI::Dialogs;

AreaHighlighter::AreaHighlighter(Reference<PEFile> pe)
    : Window("Area Highlighter", "x:25%,y:5%,w:50%,h:90%", WindowFlags::Sizeable | WindowFlags::ProcessReturn), pe(pe)
{
    auto path = std::filesystem::path(pe->obj->GetPath());
    if (std::filesystem::is_regular_file(path))
    {
        path = path.parent_path();
    }

    chosenPath = Factory::TextField::Create(this, "", "x:2,y:1,w:98%,h:1");

    auto res   = FileDialog::ShowOpenFileWindow("", "", path.generic_u16string());
    if (res.has_value())
    {
        chosenPath->SetText(res->u8string());
    }
    else
    {
        chosenPath->SetText("Command canceled!");
    }
};
} // namespace GView::Type::PE::Commands
