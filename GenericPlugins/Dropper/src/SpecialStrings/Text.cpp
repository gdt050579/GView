#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static const std::string_view TEXT_REGEX_ASCII{ R"(^([a-zA-Z .0-9\_\<\>\(\)@]{10,}))" };
static const std::string_view TEXT_REGEX_UNICODE{ R"(^(([a-zA-Z .0-9\_\<\>\(\)@]\x00){10,}))" };

Text::Text(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(TEXT_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(TEXT_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view Text::GetName() const
{
    return "Text";
}

const std::string_view Text::GetOutputExtension() const
{
    return "text";
}

Result Text::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 10, Result::NotFound, "");

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
