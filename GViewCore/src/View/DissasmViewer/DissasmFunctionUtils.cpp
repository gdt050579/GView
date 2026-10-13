
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
            if (*ptr == ' ' || *ptr == '[' || (*ptr >= 'a' && *ptr <= 'z') || (*ptr >= 'A' && *ptr <= 'Z')) {
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
            if ((*ptr >= '0' && *ptr <= '9') || (*ptr >= 'a' && *ptr <= 'f')) {
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
            if (!((*ptr >= '0' && *ptr <= '9') || (*ptr >= 'a' && *ptr <= 'f')))
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

std::optional<uint64> GetDirectBranchTarget(std::string_view operands)
{
    const bool isHex          = operands.size() > 2 && operands[0] == '0' && operands[1] == 'x';
    const std::string_view sv = isHex ? operands.substr(2) : operands;
    const uint64 base         = isHex ? 16u : 10u;
    if (sv.empty())
        return {};
    uint64 value = 0;
    for (const char c : sv) {
        uint64 digit;
        if (c >= '0' && c <= '9')
            digit = static_cast<uint64>(c - '0');
        else if (isHex && c >= 'a' && c <= 'f')
            digit = static_cast<uint64>(c - 'a' + 10);
        else
            return {};
        if (value > (UINT64_MAX - digit) / base)
            return {};
        value = value * base + digit;
    }
    return value;
}

namespace
{
int32 HexDigitValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
bool IsNameCharacter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
bool CanPrecedeNumber(char c)
{
    return c == ' ' || c == '[' || c == ',' || c == '+' || c == '-' || c == '*' || c == ':';
}
} // namespace

std::vector<OperandNumber> FindOperandNumbers(std::string_view operands)
{
    std::vector<OperandNumber> numbers;
    const auto size = static_cast<uint32>(operands.size());
    uint32 pos      = 0;
    while (pos < size) {
        const char c = operands[pos];
        if (c < '0' || c > '9' || (pos > 0 && !CanPrecedeNumber(operands[pos - 1]))) {
            pos++;
            continue;
        }

        const uint32 start = pos;
        const bool isHex   = c == '0' && pos + 2 < size && operands[pos + 1] == 'x' && HexDigitValue(operands[pos + 2]) >= 0;
        uint64 value       = 0;
        bool fits          = true;
        if (isHex) {
            pos += 2;
            for (; pos < size && HexDigitValue(operands[pos]) >= 0; pos++) {
                fits  = fits && (value >> 60) == 0;
                value = (value << 4) | static_cast<uint64>(HexDigitValue(operands[pos]));
            }
        } else {
            for (; pos < size && operands[pos] >= '0' && operands[pos] <= '9'; pos++) {
                const auto digit = static_cast<uint64>(operands[pos] - '0');
                fits             = fits && value <= (UINT64_MAX - digit) / 10u;
                value            = value * 10u + digit;
            }
        }
        // a number glued to a name (e.g. "1st") or one that does not fit in 64 bits is not a value
        if (pos < size && IsNameCharacter(operands[pos])) {
            while (pos < size && IsNameCharacter(operands[pos]))
                pos++;
            continue;
        }
        if (fits)
            numbers.push_back({ start, pos - start, value, isHex });
    }
    return numbers;
}

std::string FormatOperandNumbers(std::string_view operands, uint32 decimalMask, uint32* trackedPosition)
{
    std::string result;
    result.reserve(operands.size() + 16u);

    const auto numbers   = FindOperandNumbers(operands);
    const uint32 tracked = trackedPosition ? *trackedPosition : 0;
    uint32 copied        = 0;
    for (uint32 index = 0; index < static_cast<uint32>(numbers.size()) && index < 32u; index++) {
        const auto& number = numbers[index];
        if (!number.isHex || (decimalMask & (1u << index)) == 0)
            continue;
        result.append(operands.substr(copied, number.start - copied));
        const auto decimal = std::to_string(number.value);
        if (trackedPosition && number.start < tracked)
            *trackedPosition = *trackedPosition + static_cast<uint32>(decimal.size()) - number.length;
        result.append(decimal);
        copied = number.start + number.length;
    }
    result.append(operands.substr(copied));
    return result;
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