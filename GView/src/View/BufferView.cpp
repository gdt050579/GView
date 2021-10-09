#include "GViewApp.hpp"

using namespace GView::View;

BufferView::BufferView(GView::Object& obj, BufferViewBuilder* setting) : UserControl("d:c"), fileObj(obj)
{

}
void BufferView::Paint(Renderer& renderer)
{
    renderer.Clear(':', ColorPair{ Color::DarkGreen,Color::Black });
}