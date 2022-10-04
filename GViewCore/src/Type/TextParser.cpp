#include "Internal.hpp"

namespace GView::Type::Matcher
{
TextParser::TextParser(const char16* text, uint32 size)
{
    if ((text == nullptr) || (size == 0))
    {
        this->Raw.text  = nullptr;
        this->Text.text = nullptr;
        this->Raw.size  = 0;
        this->Text.size = 0;
    }
    else
    {
        this->Raw.text = text;
        this->Raw.size = size;
        
        auto p = text;
        auto e = text + size;
        while ((p < e) && (((*p) == ' ') || ((*p) == '\t') || ((*p) == '\n') || ((*p) == '\r')))
            p++;
        if (p==e)
        {
            this->Raw.text  = nullptr;
            this->Text.text = nullptr;
            this->Raw.size  = 0;
            this->Text.size = 0;
        }
        else
        {
            this->Text.text = p;
            this->Text.size = static_cast<uint32>(e - p);
        }
    }
}
} // namespace GView::Type::Matcher