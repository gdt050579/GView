#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static const std::string_view URL_REGEX_ASCII{ R"(^(((https*:\/\/)|((https*:\/\/www)|(www)\.))[a-zA-Z0-9_]+\.[a-zA-Z0-9_\.]+(\/[a-zA-Z0-9_\.]*)*))" };
static const std::string_view URL_REGEX_UNICODE{
    R"(^(((h\x00t\x00t\x00p\x00(s\x00)*:\x00\/\x00\/\x00)|((h\x00t\x00t\x00p\x00(s\x00)*:\x00\/\x00\/\x00w\x00w\x00w\x00)|(w\x00w\x00w\x00)\.\x00))([a-zA-Z0-9_]\x00)+\.\x00([a-zA-Z0-9_\.]\x00)+(\/\x00([a-zA-Z0-9_\.]\x00)*)*))"
};

URL::URL(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(URL_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(URL_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view URL::GetName() const
{
    return "URL";
}

const std::string_view URL::GetOutputExtension() const
{
    return "url";
}

Subcategory URL::GetSubGroup() const
{
    return Subcategory::URL;
}

Result URL::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() > 0, Result::NotFound, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), Result::NotFound, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 4, Result::NotFound, "");

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
