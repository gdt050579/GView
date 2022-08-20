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
Token TokensList::GetLastToken() const
{
    uint32 count = (uint32) INSTANCE->tokens.size();
    if (count > 0)
        return Token(this->data, count - 1);
    else
        return Token();
}
Token TokensList::Add(uint32 typeID, uint32 start, uint32 end, TokenColor color)
{
    return Add(typeID, start, end, color, TokenDataType::None, TokenAlignament::None);
}
Token TokensList::Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenDataType dataType)
{
    return Add(typeID, start, end, color, dataType, TokenAlignament::None);
}
Token TokensList::Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenAlignament align)
{
    return Add(typeID, start, end, color, TokenDataType::None, align);
}
Token TokensList::Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenDataType dataType, TokenAlignament align)
{
    uint32 itemsCount = static_cast<uint32>(INSTANCE->tokens.size());
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
    cToken.blockID   = BlockObject::INVALID_ID;
    cToken.status    = TokenStatus::Visible;
    cToken.align     = align;
    cToken.dataType  = dataType;

    this->lastTokenID = typeID;

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
bool TokensList::CreateBlock(uint32 start, uint32 end, BlockAlignament align, bool hasBlockEndMarker)
{
    uint32 itemsCount = static_cast<uint32>(INSTANCE->tokens.size());
    CHECK(start < itemsCount, false, "Invalid token index (start=%u), should be less than %u", start, itemsCount);
    CHECK(end < itemsCount, false, "Invalid token index (end=%u), should be less than %u", end, itemsCount);
    CHECK(start < end, false, "Start token index(%u) should be smaller than end token index(%u)", start, end);

    // create a block
    auto& block        = INSTANCE->blocks.emplace_back();
    uint32 blockID     = (uint32) (INSTANCE->blocks.size() - 1);
    block.tokenStart   = start;
    block.tokenEnd     = end;
    block.align        = align;
    block.hasEndMarker = hasBlockEndMarker;

    // set token flags
    INSTANCE->tokens[start].SetBlockStartFlag();
    INSTANCE->tokens[start].blockID = blockID;

    return true;
}
}; // namespace GView::View::LexicalViewer