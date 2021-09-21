#include <GViewApp.hpp>

using namespace GView::Type;

SimplePattern::SimplePattern()
{
    this->Count = 0;
    this->Offset = 0;
}
bool SimplePattern::Init(std::string_view text)
{
    NOT_IMPLEMENTED(false);
}
bool SimplePattern::Match(const unsigned char* buffer, unsigned int bufferSize) const
{
    if (this->Count == 0)
        return true; // no pattern means it matches everything
    if (!buffer)
        return false; // null buffer
    if (((unsigned int)this->Offset) + ((unsigned int)this->Count) > bufferSize)
        return false; // outside the testing buffer
    auto s = buffer + this->Offset;
    auto e = s + this->Count;
    const unsigned char* p = this->CharactersToMatch;
    for (; s < e; s++, p++)
    {
        if ((*p) == '?')
            continue;
        if ((*s) != (*p))
            return false;
    }
    return true;
}