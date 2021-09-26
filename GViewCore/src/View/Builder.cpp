#include "GViewInternal.hpp"

using namespace GView::View;

Builder::Builder()
{
    infoPanels.reserve(32);
    views.reserve(8);
}
bool Builder::AddPanel(std::unique_ptr<AppCUI::Controls::Control> ctrl, bool vertical)
{
    NOT_IMPLEMENTED(false);
}
IBufferViewBuilder& Builder::AddBufferView(const std::string_view& name)
{
    views.push_back(std::make_unique<BufferViewBuilder>(name));
    return (*(reinterpret_cast<IBufferViewBuilder*>(views.back().get())));
}

