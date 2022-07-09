#include <GView.hpp>

namespace GView::Utils
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


} // namespace GView::Utils