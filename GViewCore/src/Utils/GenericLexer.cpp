#include <GView.hpp>

namespace GView::Utils::Tokenizer
{
GenericLexer::GenericLexer(const char16* _text, uint32 _size)
{
    this->text = _text;
    this->size = _size;
    if (this->text == nullptr)
        this->size = 0; // sanity check
}
GenericLexer::GenericLexer(u16string_view _text)
{
    if (_text.empty())
    {
        this->text = nullptr;
        this->size = 0;
    }
    else
    {
        if (_text.size() > 0x7FFFFFFF)
        {
            this->text = nullptr;
            this->size = 0;
        }
        else
        {
            this->text = _text.data();
            this->size = static_cast<uint32>(_text.size() & 0xFFFFFFFF);
        }
    }
    if (this->text == nullptr)
        this->size = 0; // sanity check
}
uint32 GenericLexer::ParseTillNextLine(uint32 index)
{
    if (index >= size)
        return size;
    auto* p = text + index;
    while ((index < size) && ((*p) != '\n') && ((*p) != '\r'))
    {
        index++;
        p++;
    }
    return index;
}
uint32 GenericLexer::Parse(uint32 index, bool (*validate)(char16 character))
{
    if (index >= size)
        return size;
    if (validate == nullptr)
        return index;
    auto* p = text + index;
    while ((index < size) && (validate(*p)))
    {
        index++;
        p++;
    }
    return index;
}
uint32 GenericLexer::ParseSameGroupID(uint32 index, uint32 (*charToGroupID)(char16 character))
{
    if (index >= size)
        return size;
    if (charToGroupID == nullptr)
        return index;
    auto* p = text + index;
    auto id = charToGroupID(*p);
    while ((index < size) && (charToGroupID(*p) == id))
    {
        index++;
        p++;
    }
    return index;
}

} // namespace GView::Utils