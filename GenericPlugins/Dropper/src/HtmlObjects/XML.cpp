#include "HtmlObjects.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
constexpr std::string_view START{ "<?xml" };
constexpr std::string_view END{ ">" };

const std::string_view XML::GetName() const
{
    return "XML";
}

Category XML::GetCategory() const
{
    return Category::HtmlObjects;
}

const std::string_view XML::GetOutputExtension() const
{
    return "xml";
}

Subcategory XML::GetSubcategory() const
{
    return Subcategory::XML;
}

Priority XML::GetPriority() const
{
    return Priority::Text;
}

bool XML::ShouldGroupInOneFile() const
{
    return false;
}

bool XML::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() >= START.size(), false, "");
    CHECK(memcmp(precachedBuffer.GetData(), START.data(), START.size()) == 0, false, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= START.size() + END.size(), false, "");

    finding.start = offset;
    finding.end   = offset;

    bool foundHeader = false;
    uint64 i         = 0;
    while (buffer.GetLength() >= END.size()) {
        CHECK(IsAsciiPrintable(buffer.GetData()[i]), false, "");

        if (memcmp(buffer.GetData() + i, END.data(), END.size()) == 0) {
            finding.end += END.size();
            foundHeader = true;
            break;
        }

        finding.end += 1;
        i++;

        if (i + END.size() == buffer.GetLength()) {
            offset += i + END.size();
            buffer = file.Get(offset, file.GetCacheSize() / 12, false);
            i      = 0;
        }
    }

    CHECK(foundHeader, false, "");
    offset += i + 1;

    buffer          = file.Get(offset, file.GetCacheSize() / 12, false);
    i               = 0;
    uint32 tagStart = 0;
    bool inside     = false;
    while (buffer.GetLength()) {
        const auto c = buffer.GetData()[i];
        i++;

        if (inside) {
            if (c == '>') {
                inside      = false;
                finding.end = offset + i;
            } else if (IsAsciiPrintable(c) || c == '\n' || c == '\r') {
                // nothing
            } else {
                break;
            }
        } else {
            if (c == ' ' || c == '\n' || c == '\r') {
                // nothing
            } else if (c == '<') {
                inside = true;
            } else {
                break;
            }
        }

        if (i + 1 == buffer.GetLength()) {
            offset += i + 1;
            buffer = file.Get(offset, file.GetCacheSize() / 12, false);
            i      = 0;
        }
    }

    finding.result = Result::Ascii;

    return true;
}
} // namespace GView::GenericPlugins::Droppper::HtmlObjects
