#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
// bitcoin + ethereum + stellar

static const std::string_view WALLET_REGEX_ASCII{ R"(^(((bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})|(0x[a-fA-F0-9]{40})|(G[a-zA-Z0-9]{55})))" };
static const std::string_view WALLET_REGEX_UNICODE{
    R"(^(((b\x00c\x001\x00|([13]\x00))([a-zA-HJ-NP-Z0-9]\x00){25,39})|(0x\x00([a-fA-F0-9]\x00){40})|(G\x00([a-zA-Z0-9]\x00){55})))"
};

Wallet::Wallet(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(WALLET_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(WALLET_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view Wallet::GetName() const
{
    return "Wallet";
}

const std::string_view Wallet::GetOutputExtension() const
{
    return "wallet";
}

uint32 Wallet::GetSubGroup() const
{
    return static_cast<uint32>(Types::Wallet);
}

Result Wallet::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 16, Result::NotFound, "");

    if (this->matcherAscii.Match(buffer, start, end)) {
        start += offset;
        end += offset;
        return Result::Ascii;
    }

    CHECK(unicode, Result::NotFound, "");
    CHECK(precachedBuffer.GetData()[1] == 0, Result::NotFound, ""); // we already checked ascii printable

    if (this->matcherUnicode.Match(buffer, start, end)) {
        start += offset;
        end += offset;
        return Result::Unicode;
    }

    return Result::NotFound;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
