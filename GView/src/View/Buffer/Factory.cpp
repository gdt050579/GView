#include "GViewApp.hpp"

using namespace GView::View;

Buffer::Factory::Factory(const std::string_view& name)
{
    // not implemented
}
void Buffer::Factory::AddZone(unsigned long long start, unsigned long long size, AppCUI::Graphics::ColorPair col, std::string_view name)
{
    // not implemented
}
void Buffer::Factory::AddBookmark(unsigned char index, unsigned long long fileOffset)
{

}
Pointer<Control> Buffer::Factory::Build(GView::Object& obj)
{
    return Pointer<Control>(new Buffer::ViewerControl(obj, this));
}