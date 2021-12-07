#include "Internal.hpp"

using namespace GView::Utils;
using namespace AppCUI::Graphics;

Zone::Zone() : start(INVALID_OFFSET), end(INVALID_OFFSET), color(NoColorPair), name()
{
}

void Zone::Set(uint64 s, uint64 e, ColorPair c, std::string_view txt)
{
    this->start = s;
    this->end   = e;
    this->color = c;
    this->name  = txt;
}