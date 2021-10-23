#include <GViewApp.hpp>

using namespace GView::Utils;
using namespace AppCUI::Graphics;

Zone::Zone() : start(INVALID_OFFSET), end(INVALID_OFFSET), color(NoColorPair), name()
{
}

void Zone::Set(unsigned long long s, unsigned long long e, ColorPair c, std::string_view txt)
{
    this->start = s;
    this->end   = e;
    this->color = c;
    this->name  = txt;
}