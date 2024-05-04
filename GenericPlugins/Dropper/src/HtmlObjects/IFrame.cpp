#include "HtmlObjects.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
constexpr std::string_view START{ "<iframe>" };
constexpr std::string_view END{ "</iframe>" };

const std::string_view IFrame::GetName() const
{
    return "IFrame";
}

Category IFrame::GetCategory() const
{
    return Category::HtmlObjects;
}

Subcategory IFrame::GetSubcategory() const
{
    return Subcategory::IFrame;
}

const std::string_view IFrame::GetOutputExtension() const
{
    return "iframe";
}

Priority IFrame::GetPriority() const
{
    return Priority::Text;
}

bool IFrame::ShouldGroupInOneFile() const
{
    return false;
}

bool IFrame::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
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
