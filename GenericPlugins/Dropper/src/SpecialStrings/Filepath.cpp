#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static constexpr std::string_view PATH_REGEX_ASCII{ R"(^(([a-zA-Z]{1}\:\\[a-zA-Z0-9\\_\. ]+)|(((\/|\.\.)[a-zA-Z\/\.0-9]+\/[a-zA-Z\/\.0-9]+))))" };
static constexpr std::string_view PATH_REGEX_UNICODE{
    R"(^((([a-zA-Z]\x00){1}\\x00:\x00\\x00\\x00([a-zA-Z0-9\\_\. ]\x00)+)|((((\/\x00)|\.\x00\.\x00)([a-zA-Z\/\.0-9]\x00)+\/\x00([a-zA-Z\/\.0-9]\x00)+))))"
};

Filepath::Filepath(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(PATH_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(PATH_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view Filepath::GetName() const
{
    return "Filepath";
}

const std::string_view Filepath::GetOutputExtension() const
{
    return "filepath";
}

Subcategory Filepath::GetSubcategory() const
{
    return Subcategory::Filepath;
}

bool Filepath::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
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
