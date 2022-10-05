#include "Internal.hpp"

namespace GView::App
{
    using namespace AppCUI::Controls;
SelectTypeDialog::SelectTypeDialog(const std::vector<GView::Type::Plugin>& typePlugins) : Window("Select type", "d:c,w:80,h:20", WindowFlags::ProcessReturn)
{
    auto lstView = Factory::ListView::Create(this, "x:1,y:1,w:30,h:18", { "n:Name,w:10,a:l", "n:Description,w:100,a:l" });
}
bool SelectTypeDialog::OnEvent(Reference<Control>, Event eventType, int)
{
    return false;
}
} // namespace GView::App