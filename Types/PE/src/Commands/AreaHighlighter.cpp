#include "pe.hpp"

namespace GView::Type::PE::Commands
{
using namespace AppCUI::Controls;

AreaHighlighter::AreaHighlighter(Reference<PEFile> pe)
    : Window("Area Highlighter", "x:25%,y:5%,w:50%,h:90%", WindowFlags::Sizeable | WindowFlags::ProcessReturn), pe(pe)
{
	// TODO:
};
} // namespace GView::Type::PE::Commands
