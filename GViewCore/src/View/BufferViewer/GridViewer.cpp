#include "GViewApp.hpp"

namespace GView::View
{
GridViewer::GridViewer(std::string_view name, Reference<GView::Object> obj) : name(name), obj(obj)
{
}

bool GridViewer::GoTo(unsigned long long offset)
{
    return true;
}

bool GridViewer::Select(unsigned long long offset, unsigned long long size)
{
    return true;
}

std::string_view GridViewer::GetName()
{
    return name;
}

void GridViewer::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height)
{
}

void GridViewer::InitGrid()
{
    grid = AppCUI::Controls::Factory::Grid::Create(
          this, "d:c,w:100%,h:100%", 25, 25, AppCUI::Controls::GridFlags::TransparentBackground | AppCUI::Controls::GridFlags::HideHeader);
}

void GridViewer::UpdateGrid()
{
}
}; // namespace GView::View
