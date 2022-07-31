#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{
#define INSTANCE reinterpret_cast<Instance*>(this->data)
uint32 TokensList::Len() const
{
    return (uint32) (INSTANCE->tokens.size());
}
Token TokensList::operator[](uint32 index) const
{
    if ((size_t) index >= INSTANCE->tokens.size())
        return Token();
    return Token(this->data, index);
}
Token TokensList::Add(TokenType type, uint32 start, uint32 end)
{
    uint32 len = INSTANCE->tokens.size();
    if ((start >= end) || (start > len) || (end > (len + 1)))
    {
        LOG_ERROR("Invalid token offset: start=%du, end=%u, length=%u", start, end, len);
        return Token();
    }
    if (len > 0)
    {
        auto& lastToken = INSTANCE->tokens[len - 1];
        if (start < lastToken.end)
        {
            LOG_ERROR("All tokens must be provided in order (current token starts at %u, but last token ends at %u)", start, lastToken.end);
            return Token();
        }
    }
    auto cToken  = INSTANCE->tokens.emplace_back();
    cToken.type  = type;
    cToken.start = start;
    cToken.end   = end;
    return Token(this->data, len);
}
}; // namespace GView::View::LexicalViewer