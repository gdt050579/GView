
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
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
    auto sv = formatter.ToHex(functionAddress);
    LocalString<64> callName;
    callName.AddFormat("%s%09s", prefix, sv.data());
    return callName;
}

AsmOffsetLine SearchForClosestAsmOffsetLineByOffset(const std::vector<AsmOffsetLine>& values, uint64 searchedOffset)
{
    assert(!values.empty());
    uint32 left  = 0;
    uint32 right = static_cast<uint32>(values.size()) - 1u;
    while (left < right) {
        const uint32 mid = (left + right) / 2;
        if (searchedOffset == values[mid].offset)
            return values[mid];
        if (searchedOffset < values[mid].offset)
            right = mid - 1;
        else
            left = mid + 1;
    }
    if (left > 0 && values[left].offset > searchedOffset)
        return values[left - 1];

    return values[left];
}

cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli)
{
    const auto closestData = SearchForClosestAsmOffsetLineByOffset(zone->cachedCodeOffsets, offsetToReach);
    zone->lastClosestLine  = closestData.line;
    zone->asmAddress       = closestData.offset - zone->cachedCodeOffsets[0].offset;
    zone->asmSize          = zone->zoneDetails.size - zone->asmAddress;

    // TODO: maybe get less data ?
    const auto instructionData = obj->GetData().Get(zone->cachedCodeOffsets[0].offset + zone->asmAddress, static_cast<uint32>(zone->asmSize), false);
    zone->lastData             = instructionData;
    if (!instructionData.IsValid()) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        diffLines = UINT32_MAX;
        return nullptr;
    }

    zone->asmData = const_cast<uint8*>(zone->lastData.GetData());

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        cs_close(&handle);
        return nullptr;
    }

    diffLines     = 0;
    cs_insn* insn = cs_malloc(handle);
    if (offsetToReach >= zone->cachedCodeOffsets[0].offset)
        offsetToReach -= zone->cachedCodeOffsets[0].offset;
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