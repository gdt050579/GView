#include "GViewApp.hpp"

using namespace GView::View;

Builder::Builder()
{
    verticalPanels.reserve(32);
    horizontalPanels.reserve(16);
    views.reserve(8);
}
bool Builder::AddPanel(std::unique_ptr<AppCUI::Controls::Control> ctrl, bool vertical)
{
    CHECK(ctrl, false, "Expecting a valid control !");
    if (vertical)
        verticalPanels.push_back(std::move(ctrl));
    else
        horizontalPanels.push_back(std::move(ctrl));
    return true;
}
IBufferViewBuilder& Builder::AddBufferView(const std::string_view& name)
{
    views.push_back(std::make_unique<BufferViewBuilder>(name));
    return (*(reinterpret_cast<IBufferViewBuilder*>(views.back().get())));
}

