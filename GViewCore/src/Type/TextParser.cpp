#include "Internal.hpp"

namespace GView::Type::Matcher
{
TextParser::TextParser(const char16* text, uint32 size)
{
    this->Lines.computed = false;

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
        if (p == e)
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
void TextParser::ComputeLineOffsets()
{
    auto p            = this->Raw.text;
    auto e            = this->Raw.text + this->Raw.size;
    auto maxLines     = ARRAY_LEN(this->Lines.offsets);
    this->Lines.count = 0;

    while ((p < e) && (this->Lines.count < maxLines))
    {
        // skip any new line until a valid character
        while ((p < e) && (((*p) == '\n') || ((*p) == '\r')))
            p++;
        // skip any space or tab
        while ((p < e) && (((*p) == ' ') || ((*p) == '\t')))
            p++;
        this->Lines.offsets[this->Lines.count++] = static_cast<uint32>(p - this->Raw.text);
        // skip until a new line
        while ((p < e) && ((*p) != '\n') && ((*p) != '\r'))
            p++;
    }
    this->Lines.computed = true;
}
} // namespace GView::Type::Matcher