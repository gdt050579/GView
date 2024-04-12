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

const char* Filepath::GetName()
{
    return "Filepath";
}

const char* Filepath::GetOutputExtension()
{
    return "filepath";
}

Result Filepath::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
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
