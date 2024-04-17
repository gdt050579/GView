#include "HtmlObjects.hpp"

namespace GView::GenericPlugins::Droppper::HtmlObjects
{
constexpr std::string_view START{ "<iframe>" };
constexpr std::string_view END{ "</iframe>" };

const std::string_view IFrame::GetName() const
{
    return "IFrame";
}

ObjectCategory IFrame::GetGroup() const
{
    return ObjectCategory::HtmlObjects;
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

Result IFrame::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(precachedBuffer.GetLength() >= START.size(), Result::NotFound, "");
    CHECK(memcmp(precachedBuffer.GetData(), START.data(), START.size()) == 0, Result::NotFound, "");

    auto buffer = file.Get(offset, file.GetCacheSize() / 12, false);
    CHECK(buffer.GetLength() >= START.size() + END.size(), Result::NotFound, "");

    start = offset;
    end   = offset;

    uint64 i = 0;
    while (buffer.GetLength() >= END.size()) {
        CHECK(IsAsciiPrintable(buffer.GetData()[i]), Result::NotFound, "");

        if (memcmp(buffer.GetData() + i, END.data(), END.size()) == 0) {
            end += END.size();
            return Result::Ascii;
        }

        end += 1;
        i++;

        if (i + END.size() == buffer.GetLength()) {
            offset += i + END.size();
            buffer = file.Get(offset, file.GetCacheSize() / 12, false);
            i      = 0;
        }
    }

    return Result::NotFound;
}
} // namespace GView::GenericPlugins::Droppper::HtmlObjects
