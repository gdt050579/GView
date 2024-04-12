#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
static const std::string_view REGISTRY_REGEX_ASCII{
    R"(^((HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG|HKCC)\\[a-zA-Z .0-9\_\\]+))"
};
static const std::string_view REGISTRY_REGEX_UNICODE{
    R"(^((H\x00K\x00E\x00Y\x00_\x00L\x00O\x00C\x00A\x00L\x00_\x00M\x00A\x00C\x00H\x00I\x00N\x00E\x00|H\x00K\x00L\x00M\x00|H\x00K\x00E\x00Y\x00_\x00C\x00U\x00R\x00R\x00E\x00N\x00T\x00_\x00U\x00S\x00E\x00R\x00|H\x00K\x00C\x00U\x00|H\x00K\x00E\x00Y\x00_\x00U\x00S\x00E\x00R\x00S\x00|H\x00K\x00U\x00|H\x00K\x00E\x00Y\x00_\x00C\x00L\x00A\x00S\x00S\x00E\x00S\x00_\x00R\x00O\x00O\x00T\x00|H\x00K\x00C\x00R\x00|H\x00K\x00E\x00Y\x00_\x00C\x00U\x00R\x00R\x00E\x00N\x00T\x00_\x00C\x00O\x00N\x00F\x00I\x00G\x00|H\x00K\x00C\x00C\x00)\\x00\\x00([a-zA-Z .0-9\_\\]\x00)+))"
};

Registry::Registry(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
    this->matcherAscii.Init(REGISTRY_REGEX_ASCII, unicode, caseSensitive);
    this->matcherUnicode.Init(REGISTRY_REGEX_UNICODE, unicode, caseSensitive);
}

const std::string_view Registry::GetName() const
{
    return "Registry";
}

const std::string_view Registry::GetOutputExtension() const
{
    return "reg";
}

Result Registry::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
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
