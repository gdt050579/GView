#include <GViewApp.hpp>

using namespace GView::Utils;

Zone::Zone(): start(INVALID_OFFSET), end(INVALID_OFFSET), color(NoColorPair), textSize(0) { }
Zone::Zone(unsigned long long s, unsigned long long e, ColorPair c, std::u16string_view txt)
{
    this->start = s;
    this->end = e;
    this->color = c;
    this->textSize = (unsigned int)(std::min(txt.length(), sizeof(this->text) / sizeof(char16_t)));
    auto ptr = txt.data();
    auto ptr_end = ptr + this->textSize;
    auto ptr_t = this->text;
    for (; ptr < ptr_end; ptr++, ptr_t)
        *ptr_t = *ptr;                
}
Zone::Zone(unsigned long long s, unsigned long long e, ColorPair c, std::string_view txt)
{
    this->start = s;
    this->end = e;
    this->color = c;
    this->textSize = (unsigned int)(std::min(txt.length(), sizeof(this->text) / sizeof(char16_t)));
    auto ptr = txt.data();
    auto ptr_end = ptr + this->textSize;
    auto ptr_t = this->text;
    for (; ptr < ptr_end; ptr++, ptr_t)
        *ptr_t = *ptr;
}