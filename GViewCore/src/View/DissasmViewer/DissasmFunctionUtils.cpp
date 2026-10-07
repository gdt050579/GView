
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include <algorithm>
using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

// TODO: maybe add also minimum number?
bool CheckExtractInsnHexValue(const char* op_str, uint64& value, uint64 maxSize)
{
    const char* ptr     = op_str;
    const char* start   = nullptr;
    uint32 size         = 0;
    bool insideBrackets = false;

    auto checkValidSequence = [&ptr, &insideBrackets]() -> bool {
        while (ptr && *ptr != '\0') {
            if (*ptr == ' ' || *ptr == '[' || *ptr >= 'a' && *ptr <= 'z' || *ptr >= 'A' && *ptr <= 'Z') {
                if (*ptr == '[') {
                    if (insideBrackets)
                        return false;
                    insideBrackets = true;
                }
                ptr++;
                continue;
            }
            if (*ptr >= '0' && *ptr <= '9') {
                break;
            }
            return false;
        }
        return true;
    };

    if (!checkValidSequence())
        return false;

    // while (ptr && *ptr != '\0') {
    //     if (*ptr == ' ' || *ptr == '[' || *ptr >= 'a' && *ptr <= 'z' || *ptr >= 'A' && *ptr <= 'Z') {
    //         if (*ptr == '[') {
    //             if (insideBrackets)
    //                 return false;
    //             insideBrackets = true;
    //         }
    //         ptr++;
    //         continue;
    //     }
    //     if (*ptr >= '0' && *ptr <= '9') {
    //         break;
    //     }
    //     return false;
    // }

    bool is_hex = false;
    while (ptr && *ptr != '\0') {
        if (!start) {
            if (*ptr == '0') // not hex
            {
                ptr++;
                if (!ptr || *ptr != 'x') {
                    start = ptr - 1;
                    size  = 1;
                    continue;
                }
                ptr++;
                start  = ptr;
                is_hex = true;
                continue;
            } else {
                is_hex = false;
                start  = ptr;
                continue;
            }
        } else {
            if (*ptr >= '0' && *ptr <= '9' || *ptr >= 'a' && *ptr <= 'f') {
                size++;
            } else {
                if (size < maxSize - 2)
                    return false;
                break;
            }
        }
        ptr++;
    }

    if (insideBrackets) {
        if (!ptr)
            return false;
        if (*ptr != ']')
            return false;
        ptr++;
    }

    if (maxSize < size) {
        const uint32 diff = size - static_cast<uint32>(maxSize);
        size -= diff;
        start += diff;
    }

    if (!size || !start)
        return false;

    if (size < 2) {
        ptr = !is_hex ? op_str : op_str + 2;
        while (ptr && *ptr != '\0') {
            if (!(*ptr >= '0' && *ptr <= '9' || *ptr >= 'a' && *ptr <= 'f'))
                return false;
            ptr++;
        }
    }

    if (!checkValidSequence())
        return false;

    const NumberParseFlags numberFlags = is_hex ? NumberParseFlags::Base16 : NumberParseFlags::Base10;
    const auto sv                      = std::string_view(start, size);
    const auto converted               = Number::ToUInt64(sv, numberFlags);
    if (!converted.has_value())
        return false;

    value = converted.value();

    return true;
}

LocalString<64> FormatFunctionName(uint64 functionAddress, const char* prefix)
{
    NumericFormatter formatter;
    const auto sv = formatter.ToHex(functionAddress);
    LocalString<64> callName;
    callName.Add(prefix);
    // Pad to 9 hex digits by hand. "%09s" relied on the '0' flag with a string conversion, which is undefined
    // behaviour: MSVC pads with zeros, glibc and Apple libc with spaces, so the names differed per platform.
    if (sv.size() < 9) {
        callName.AddChars('0', static_cast<uint32>(9 - sv.size()));
    }
    callName.Add(sv);
    return callName;
}

AsmOffsetLine SearchForClosestAsmOffsetLineByOffset(const std::vector<AsmOffsetLine>& values, uint64 searchedOffset, uint32* index)
{
    assert(!values.empty());
    // the last cached offset placed before (or at) the searched one, the first one when the searched offset is before the code
    auto it = std::upper_bound(values.begin(), values.end(), searchedOffset, [](uint64 offset, const AsmOffsetLine& entry) { return offset < entry.offset; });
    if (it != values.begin())
        --it;
    if (index)
        *index = static_cast<uint32>(it - values.begin());
    return *it;
}

uint64 GetCachedOffsetWindowEnd(const DissasmCodeZone* zone, uint32 cachedOffsetIndex)
{
    const auto& offsets = zone->cachedCodeOffsets;
    if (static_cast<size_t>(cachedOffsetIndex) + 1u < offsets.size())
        return offsets[cachedOffsetIndex + 1u].offset - offsets[0].offset + DISSASM_MAX_INSTRUCTION_SIZE;
    // after the last cached offset there are less than DISSASM_INSTRUCTION_OFFSET_MARGIN bytes of decoded instructions
    return offsets[cachedOffsetIndex].offset - offsets[0].offset + DISSASM_INSTRUCTION_OFFSET_MARGIN + 2 * DISSASM_MAX_INSTRUCTION_SIZE;
}

cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli)
{
    diffLines = 0;
    // the decoding position is moved below: the next drawn line has to search its cached offset again
    zone->offsetCacheMaxLine = 0;

    const uint64 codeStart = zone->cachedCodeOffsets[0].offset;
    if (offsetToReach < codeStart) {
        diffLines = UINT32_MAX;
        return nullptr;
    }

    uint32 cachedOffsetIndex = 0;
    const auto closestData   = SearchForClosestAsmOffsetLineByOffset(zone->cachedCodeOffsets, offsetToReach, &cachedOffsetIndex);
    zone->lastClosestLine    = closestData.line;
    zone->asmWindowEnd       = GetCachedOffsetWindowEnd(zone, cachedOffsetIndex);
    if (!zone->FetchCodeWindow(obj, closestData.offset - codeStart, zone->asmWindowEnd)) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        diffLines = UINT32_MAX;
        return nullptr;
    }

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);
    offsetToReach -= codeStart;
    while (zone->asmAddress <= offsetToReach) {
        if (!cs_disasm_iter(handle, &zone->asmData, (size_t*) &zone->asmSize, &zone->asmAddress, insn)) {
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            cs_close(&handle);
            return nullptr;
        }
        diffLines++;
    }
    diffLines += closestData.line - 1;
    cs_close(&handle);
    return insn;
}

AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<AsmOffsetLine>& values, uint64 searchedLine, uint32* index)
{
    assert(!values.empty());
    uint32 left  = 0;
    uint32 right = static_cast<uint32>(values.size()) - 1u;
    while (left < right) {
        const uint32 mid = (left + right) / 2;
        if (searchedLine == values[mid].line) {
            if (index)
                *index = mid;
            return values[mid];
        }
        if (searchedLine < values[mid].line)
            right = mid - 1;
        else
            left = mid + 1;
    }
    if (left > 0 && values[left].line > searchedLine) {
        if (index)
            *index = left - 1;
        return values[left - 1];
    }
    if (index)
        *index = left;
    return values[left];
}