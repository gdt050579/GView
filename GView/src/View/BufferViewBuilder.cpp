#include "GViewApp.hpp"

using namespace GView::View;

BufferViewBuilder::BufferViewBuilder(const std::string_view& name)
{
    // not implemented
}
void BufferViewBuilder::AddZone(unsigned long long start, unsigned long long size, AppCUI::Graphics::ColorPair col, std::string_view name)
{
    // not implemented
}
Pointer<Control> BufferViewBuilder::Build(GView::Object& obj)
{
    return Pointer<Control>(new BufferView(obj));
}