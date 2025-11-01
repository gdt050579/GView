#include "DissasmDataTypes.hpp"
#include "DissasmIOHelpers.hpp"
#include <array>

using namespace GView::View::DissasmViewer;

void DissasmComments::AddOrUpdateComment(uint32 line, std::string comment)
{
    comments[line - 1] = std::move(comment);
}

bool DissasmComments::GetComment(uint32 line, std::string& comment) const
{
    const auto it = comments.find(line - 1);
    if (it != comments.end()) {
        comment = it->second;
        return true;
    }
    return false;
}

bool DissasmComments::HasComment(uint32 line) const
{
    return comments.contains(line - 1);
}

void DissasmComments::RemoveComment(uint32 line)
{
    const auto it = comments.find(line - 1);
    if (it != comments.end()) {
        comments.erase(it);
        return;
    }
    Dialogs::MessageBox::ShowError("Error", "No comments found on the selected line !");
}

void DissasmComments::AdjustCommentsOffsets(uint32 changedLine, bool isAddedLine)
{
    decltype(comments) commentsAjusted = {};
    for (auto& comment : comments) {
        if (comment.first >= changedLine) {
            if (isAddedLine)
                commentsAjusted.insert({ comment.first + 1, std::move(comment.second) });
            else
                commentsAjusted.insert({ comment.first - 1, std::move(comment.second) });
        }
    }

    comments = std::move(commentsAjusted);
}

uint32 DissasmComments::GetRequiredSizeForSerialization() const
{
    uint32 result = 0;
    for (const auto& comment : comments) {
        result += sizeof(comment.first) + sizeof(uint32) + (uint32) comment.second.size();
    }
    return result;
}

void DissasmComments::ToBuffer(std::vector<std::byte>& buffer) const
{
    append_bytes(buffer, (uint32) comments.size());
    for (const auto& comment : comments) {
        append_bytes(buffer, comment.first);
        append_string(buffer, comment.second);
    }
}

bool DissasmComments::LoadFromBuffer(const std::byte*& start, const std::byte* end)
{
    if (start + sizeof(uint32) > end)
        return false;

    uint32 commentsCount = 0;
    if (!read_primitive(start, end, commentsCount))
        return false;
    while (commentsCount > 0) {
        uint32 offset = 0;
        if (!read_primitive(start, end, offset))
            return false;
        uint32 comment_size = 0;
        if (!read_primitive(start, end, comment_size))
            return false;
        const std::byte* out = nullptr;
        if (!read_bytes(start, end, comment_size, out))
            return false;
        comments[offset] = std::string((const char*) out, comment_size);
        --commentsCount;
    }

    return true;
}

uint32 AnnotationContainer::GetRequiredSizeForSerialization() const
{
    uint32 result = 3 * sizeof(uint32);
    for (const auto& annotation : mappings) {
        result += sizeof(annotation.first) + sizeof(uint32) + (uint32) annotation.second.first.size() + sizeof(annotation.second.second);
    }
    for (const auto& name : initial_name_to_current_name) {
        result += sizeof(uint32) + (uint32) name.first.size() + sizeof(uint32) + (uint32) name.second.size();
    }
    for (const auto& name : current_name_to_initial_name) {
        result += sizeof(uint32) + (uint32) name.first.size() + sizeof(uint32) + (uint32) name.second.size();
    }
    return result;
}

void AnnotationContainer::ToBuffer(std::vector<std::byte>& buffer) const
{
    append_bytes(buffer, (uint32) mappings.size());
    for (const auto& [line, details] : mappings) {
        const auto& [call_name, call_value] = details;
        append_bytes(buffer, line);
        append_string(buffer, call_name);
        append_bytes(buffer, call_value);
    }
    std::array<const MapNameLinkType*, 2> availableMaps  = { &initial_name_to_current_name, &current_name_to_initial_name };
    for (const auto& map : availableMaps) {
        append_bytes(buffer, (uint32) map->size());
        for (const auto& [name1, name2] : *map) {
            append_string(buffer, name1);
            append_string(buffer, name2);
        }
    }
}

bool AnnotationContainer::LoadFromBuffer(const std::byte*& start, const std::byte* end)
{
    if (start + sizeof(uint32) > end)
        return false;
    uint32 annotationsCount = 0;
    if (!read_primitive(start, end, annotationsCount))
        return false;
    while (annotationsCount > 0) {
        uint32 offset = 0;
        if (!read_primitive(start, end, offset))
            return false;
        uint32 annotationSize       = 0;
        const std::byte* annotation = nullptr;
        if (!read_string_with_size(start, end, annotationSize, annotation))
            return false;
        AnnoationCallValueType callValue = 0;
        if (!read_primitive(start, end, callValue))
            return false;
        std::string annName((const char*) annotation, annotationSize);
        mappings[offset] = { std::move(annName), callValue };
        --annotationsCount;
    }

    std::array<MapNameLinkType*, 2> availableMaps = { &initial_name_to_current_name, &current_name_to_initial_name };

    for (const auto& map : availableMaps) {
        uint32 count = 0;
        if (!read_primitive(start, end, count))
            return false;
        while (count > 0) {
            uint32 name1Size            = 0;
            const std::byte* name1Value = nullptr;
            if (!read_string_with_size(start, end, name1Size, name1Value))
                return false;
            uint32 name2Size            = 0;
            const std::byte* name2Value = nullptr;
            if (!read_string_with_size(start, end, name2Size, name2Value))
                return false;

            auto name1 = std::string((const char*) name1Value, name1Size);
            auto name2 = std::string((const char*) name2Value, name2Size);

            (*map)[std::move(name1)] = std::move(name2);
            --count;
        }
    }

    return false;
}
