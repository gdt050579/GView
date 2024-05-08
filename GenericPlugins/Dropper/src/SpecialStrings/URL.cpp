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

Subcategory URL::GetSubcategory() const
{
    return Subcategory::URL;
}

bool URL::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() > 0, false, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), false, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= 4, false, "");

    if (this->matcherAscii.Match(buffer, finding.start, finding.end)) {
        finding.start += offset;
        finding.end += offset;
        finding.result = Result::Ascii;
        return true;
    }

    CHECK(unicode, false, "");
    CHECK(precachedBuffer.GetData()[1] == 0, false, ""); // we already checked ascii printable

    if (this->matcherUnicode.Match(buffer, finding.start, finding.end)) {
        finding.start += offset;
        finding.end += offset;
        finding.result = Result::Unicode;
        return true;
    }

    return true;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
