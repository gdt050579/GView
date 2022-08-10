#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{
#define INSTANCE reinterpret_cast<Instance*>(this->data)
#define CREATE_TOKENREF(err)                                                                                                               \
    if (this->data == nullptr)                                                                                                             \
        return (err);                                                                                                                      \
    if ((size_t) this->index >= INSTANCE->tokens.size())                                                                                   \
        return (err);                                                                                                                      \
    auto& tok = INSTANCE->tokens[this->index];

// TOKEN methods
uint32 Token::GetTypeID() const
{
    CREATE_TOKENREF(0);
    return tok.type;
}
u16string_view Token::GetText() const
{
    CREATE_TOKENREF(u16string_view{});
    return { INSTANCE->GetUnicodeText() + tok.start, (size_t) (tok.end - tok.start) };
}

// TOKENLIST methods

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
Token TokensList::Add(uint32 typeID, uint32 start, uint32 end, TokenColor color)
{
    uint32 itemsCount = INSTANCE->tokens.size();
    uint32 len        = INSTANCE->GetUnicodeTextLen();
    if ((start >= end) || (start >= len) || (end > (len + 1)))
    {
        LOG_ERROR("Invalid token offset: start=%du, end=%u, length=%u", start, end, len);
        return Token();
    }
    if (itemsCount > 0)
    {
        auto& lastToken = INSTANCE->tokens[itemsCount - 1];
        if (start < lastToken.end)
        {
            LOG_ERROR("All tokens must be provided in order (current token starts at %u, but last token ends at %u)", start, lastToken.end);
            return Token();
        }
    }
    auto& cToken     = INSTANCE->tokens.emplace_back();
    cToken.type      = typeID;
    cToken.start     = start;
    cToken.end       = end;
    cToken.height    = 1;
    cToken.maxWidth  = 0;
    cToken.maxHeight = 0;
    cToken.color     = color;
    cToken.width     = (uint8) (std::min(end - start, (uint32) 0xFE));
    cToken.blockLink = Token::INVALID_INDEX;

    return Token(this->data, itemsCount);
}
Token TokensList::AddErrorToken(uint32 start, uint32 end, ConstString error)
{
    auto tok = Add(0, start, end, TokenColor::Error);
    if (tok.IsValid())
    {
        // add error
    }
    return tok;
}
bool TokensList::CreateBlock(uint32 start, uint32 end, bool hasBlockEndMarker)
{
    uint32 itemsCount = INSTANCE->tokens.size();
    CHECK(start < itemsCount, false, "Invalid token index (start=%u), should be less than %u", start, itemsCount);
    CHECK(end < itemsCount, false, "Invalid token index (end=%u), should be less than %u", end, itemsCount);
    CHECK(start < end, false, "Start token index(%u) should be smaller than end token index(%u)", start, end);

    // link the two tokens
    INSTANCE->tokens[start].blockLink = end;
    INSTANCE->tokens[end].blockLink   = start;
    
    // set token flags

    return true;
}
}; // namespace GView::View::LexicalViewer