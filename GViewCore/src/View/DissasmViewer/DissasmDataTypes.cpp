#include "DissasmDataTypes.hpp"
#include "DissasmIOHelpers.hpp"

using namespace GView::View::DissasmViewer;

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

    append_bytes(buffer, (uint32) initial_name_to_current_name.size());
    for (const auto& [name1, name2] : initial_name_to_current_name) {
        append_string(buffer, name1);
        append_string(buffer, name2);
    }

    append_bytes(buffer, (uint32) current_name_to_initial_name.size());
    for (const auto& [name1, name2] : current_name_to_initial_name) {
        append_string(buffer, name1);
        append_string(buffer, name2);
    }
}

void AnnotationContainer::LoadFromBuffer(const std::byte*& start, const std::byte* end)
{

}
