#include "DissasmDataTypes.hpp"
#include "DissasmIOHelpers.hpp"
#include <array>
#include <algorithm>

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
        } else {
            commentsAjusted.insert({ comment.first, std::move(comment.second) }); // comments before the changed line stay in place
        }
    }

    comments = std::move(commentsAjusted);
}

void DissasmComments::RemoveLine(uint32 line)
{
    // comments are keyed by line - 1, so the comment of line 0 lives at UINT32_MAX and is never after the removed line
    decltype(comments) commentsAjusted = {};
    for (auto& [key, text] : comments) {
        const uint32 commentLine = key + 1u;
        if (commentLine == line)
            continue;
        commentsAjusted.insert({ commentLine > line ? key - 1u : key, std::move(text) });
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

    return true;
}

DissasmLocalVariable* DissasmFunctionFrame::FindVariable(int32 frameOffset)
{
    auto it = std::lower_bound(
          variables.begin(), variables.end(), frameOffset, [](const DissasmLocalVariable& var, int32 offset) { return var.frameOffset < offset; });
    if (it == variables.end() || it->frameOffset != frameOffset)
        return nullptr;
    return &(*it);
}

const DissasmLocalVariable* DissasmFunctionFrame::FindVariable(int32 frameOffset) const
{
    return const_cast<DissasmFunctionFrame*>(this)->FindVariable(frameOffset);
}

bool DissasmFunctionFrame::HasVariableNamed(std::string_view name) const
{
    for (const auto& var : variables)
        if (var.name == name)
            return true;
    return false;
}

const DissasmFunctionFrame* DissasmLocalVariables::FindFunctionByAddress(uint64 address) const
{
    // first function starting after address, the candidate is the one before it
    auto it = std::upper_bound(
          functions.begin(), functions.end(), address, [](uint64 value, const DissasmFunctionFrame& fn) { return value < fn.startAddress; });
    if (it == functions.begin())
        return nullptr;
    --it;
    if (address >= it->endAddress)
        return nullptr;
    return &(*it);
}

DissasmFunctionFrame* DissasmLocalVariables::FindFunctionByStart(uint64 startAddress)
{
    auto it = std::lower_bound(
          functions.begin(), functions.end(), startAddress, [](const DissasmFunctionFrame& fn, uint64 value) { return fn.startAddress < value; });
    if (it == functions.end() || it->startAddress != startAddress)
        return nullptr;
    return &(*it);
}

const DissasmFunctionFrame* DissasmLocalVariables::FindFunctionByStart(uint64 startAddress) const
{
    return const_cast<DissasmLocalVariables*>(this)->FindFunctionByStart(startAddress);
}

void DissasmLocalVariables::ToBuffer(std::vector<std::byte>& buffer) const
{
    append_bytes(buffer, (uint32) functions.size());
    for (const auto& fn : functions) {
        append_bytes(buffer, fn.startAddress);
        append_bytes(buffer, fn.endAddress);
        append_bytes(buffer, (uint32) fn.variables.size());
        for (const auto& var : fn.variables) {
            append_bytes(buffer, var.frameOffset);
            append_bytes(buffer, var.size);
            append_string(buffer, var.name);
        }
    }
}

bool DissasmLocalVariables::LoadFromBuffer(const std::byte*& start, const std::byte* end)
{
    // the cache file is untrusted input: everything is parsed into a temporary and committed only if it is fully consistent
    constexpr size_t MIN_FUNCTION_RECORD_SIZE = sizeof(uint64) * 2 + sizeof(uint32);
    constexpr size_t MIN_VARIABLE_RECORD_SIZE = sizeof(int32) + sizeof(uint16) + sizeof(uint32);

    uint32 functionsCount = 0;
    if (!read_primitive(start, end, functionsCount))
        return false;
    if (functionsCount > static_cast<size_t>(end - start) / MIN_FUNCTION_RECORD_SIZE)
        return false;

    std::vector<DissasmFunctionFrame> loaded;
    loaded.reserve(functionsCount);
    for (uint32 i = 0; i < functionsCount; i++) {
        DissasmFunctionFrame fn{};
        uint32 variablesCount = 0;
        if (!read_primitive(start, end, fn.startAddress) || !read_primitive(start, end, fn.endAddress) || !read_primitive(start, end, variablesCount))
            return false;
        if (fn.startAddress > 0xFFFFFFFFull || fn.startAddress >= fn.endAddress)
            return false;
        if (!loaded.empty() && fn.startAddress < loaded.back().endAddress)
            return false;
        if (variablesCount > DISSASM_MAX_LOCAL_VARIABLES_PER_FUNCTION || variablesCount > static_cast<size_t>(end - start) / MIN_VARIABLE_RECORD_SIZE)
            return false;

        fn.variables.reserve(variablesCount);
        for (uint32 j = 0; j < variablesCount; j++) {
            DissasmLocalVariable var{};
            if (!read_primitive(start, end, var.frameOffset) || !read_primitive(start, end, var.size) ||
                !read_u32_len_prefixed_string(start, end, var.name))
                return false;
            if (var.name.empty() || var.name.size() > DISSASM_MAX_LOCAL_VARIABLE_NAME_SIZE)
                return false;
            if (!fn.variables.empty() && var.frameOffset <= fn.variables.back().frameOffset)
                return false;
            if (fn.HasVariableNamed(var.name))
                return false;
            fn.variables.push_back(std::move(var));
        }
        loaded.push_back(std::move(fn));
    }

    functions = std::move(loaded);
    return true;
}
