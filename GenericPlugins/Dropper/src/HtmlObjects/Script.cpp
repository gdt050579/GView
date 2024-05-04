#include "HtmlObjects.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
constexpr std::string_view START{ "<script>" };
constexpr std::string_view END{ "</script>" };

const std::string_view Script::GetName() const
{
    return "Script";
}

Category Script::GetCategory() const
{
    return Category::HtmlObjects;
}

Subcategory Script::GetSubcategory() const
{
    return Subcategory::Script;
}

const std::string_view Script::GetOutputExtension() const
{
    return "script";
}

Priority Script::GetPriority() const
{
    return Priority::Text;
}

bool Script::ShouldGroupInOneFile() const
{
    return false;
}

bool Script::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() >= START.size(), false, "");
    CHECK(memcmp(precachedBuffer.GetData(), START.data(), START.size()) == 0, false, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= START.size() + END.size(), false, "");

    finding.start = offset;
    finding.end   = offset;

    uint64 i = 0;
    while (buffer.GetLength() >= END.size()) {
        CHECK(IsAsciiPrintable(buffer.GetData()[i]), false, "");

        if (memcmp(buffer.GetData() + i, END.data(), END.size()) == 0) {
            finding.end += END.size();
            finding.result = Result::Ascii;
            return true;
        }

        finding.end += 1;
        i++;

        if (i + END.size() == buffer.GetLength()) {
            offset += i + END.size();
            buffer = file.Get(offset, file.GetCacheSize() / 12, false);
            i      = 0;
        }
    }

    return true;
}
} // namespace GView::GenericPlugins::Droppper::HtmlObjects
