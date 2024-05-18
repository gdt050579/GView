#include "DissasmViewer.hpp"
#include "DissasmX86.hpp"
#include <capstone/capstone.h>
#include <cassert>
#include <ranges>
#include <utility>
#include <list>
#include <algorithm>

#pragma warning(disable : 4996) // The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

// TODO: performance improvements
//  consider using the same cs_insn and cs handle for all instructions that are on the same thread instead of creating new ones

constexpr size_t DISSASM_INSTRUCTION_OFFSET_MARGIN = 500;
constexpr uint32 callOP                            = 1819042147u; //*(uint32*) "call";
constexpr uint32 addOP                             = 6579297u;    //*((uint32*) "add");
constexpr uint32 pushOP                            = 1752397168u; //*((uint32*) "push");
constexpr uint32 movOP                             = 7761773u;    //*((uint32*) "mov");

const uint8 HEX_MAPPER[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };

// Dissasm menu configuration
constexpr uint32 addressTotalLength                 = 16;
constexpr uint32 opCodesGroupsShown                 = 8;
constexpr uint32 opCodesTotalLength                 = opCodesGroupsShown * 3 + 1;
constexpr uint32 textColumnTextLength               = opCodesGroupsShown;
constexpr uint32 textColumnSpacesLength             = 4;
constexpr uint32 textColumnTotalLength              = textColumnTextLength + textColumnSpacesLength;
constexpr uint32 textColumnIndicatorArrowLinesSpace = 3;
constexpr uint32 textAndOpCodesTotalLength          = opCodesTotalLength + textColumnTotalLength;
constexpr uint32 textTotalColumnLength =
      addressTotalLength + textColumnTextLength + opCodesTotalLength + textColumnTotalLength + textColumnIndicatorArrowLinesSpace;
constexpr uint32 commentPaddingLength   = 10;
constexpr uint32 textPaddingLabelsSpace = 3;

// TODO consider inline?
AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<AsmOffsetLine>& values, uint64 searchedLine, uint32* index = nullptr)
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

// TODO: to be moved inside plugin for some sort of API for token<->color
inline ColorPair GetASMColorPairByKeyword(std::string_view keyword, DissasmColors& colors, const AsmData& data)
{
    if (keyword.empty())
        return colors.AsmDefaultColor;
    if (keyword[0] == 'j')
        return colors.AsmJumpInstruction;

    LocalString<4> holder;
    holder.Set(keyword);
    const uint32 val = *reinterpret_cast<const uint32*>(holder.GetText());

    const auto it = data.instructionToColor.find(val);
    if (it != data.instructionToColor.end()) {
        return it->second;
    }

    if (keyword.size() < 4) {
        // General registers: EAX EBX ECX EDX -> AsmWorkRegisterColor
        // 16 bits: AX BX CX DX -> AsmWorkRegisterColor
        // 8 bits: AH AL BH BL CH CL DH DL -> AsmWorkRegisterColor
        // Segment registers: CS DS ES FS GS SS -> AsmWorkRegisterColor
        // Index and pointers: ESI EDI EBP EIP ESP along with variations (ESI, SI) AsmStackRegisterColor
        switch (keyword[keyword.size() - 1]) {
        case 'x':
        case 's':
        case 'l':
        case 'h':
            return colors.AsmWorkRegisterColor;
        case 'p':
        case 'i':
            return colors.AsmStackRegisterColor;
        default:
            break;
        }
    }

    return colors.AsmDefaultColor;
}

// TODO: to be moved inside plugin for some sort of API for token<->color
inline void DissasmAddColorsToInstruction(
      DissasmAsmPreCacheLine& insn, CharacterBuffer& cb, Config& cfg, DissasmColors& colors, AsmData& data, const CodePage& codePage, uint64 addressPadding = 0)
{
    // TODO: replace CharacterBuffer with Canvas;

    const MemoryMappingEntry* mappingPtr = (const MemoryMappingEntry*) insn.mapping;
    // cb.Clear();

    // TODO: Unicode --> alt caracter
    // AppCUI::Graphics:: GetCharacterCode
    // TODO: in loc de label jmp_address:
    LocalString<128> string;
    string.SetFormat("0x%08" PRIx64 "     ", insn.address + addressPadding);
    cb.Add(string, colors.AsmOffsetColor);

    if (!cfg.ShowOnlyDissasm) {
        cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

        for (uint32 i = 0; i < opCodesGroupsShown; i++) {
            if (i >= insn.size) {
                string.Clear();
                const uint32 remaining = opCodesGroupsShown - i;
                // const uint32 spaces    = remaining >= 2 ? remaining - 2 : 0;
                string.SetChars(' ', remaining * 3);
                cb.Add(string, colors.AsmDefaultColor);
                break;
            }
            const uint8 byte = insn.bytes[i];
            string.SetFormat("%02x ", byte);
            cb.Add(string, colors.AsmDefaultColor);
        }

        cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

        for (uint32 i = 0; i < textColumnTextLength; i++) {
            if (i >= insn.size) {
                string.Clear();
                const uint32 remaining = textColumnTextLength - i - 1;
                string.SetChars(' ', remaining);
                cb.Add(string, colors.AsmDefaultColor);
                break;
            }
            if (i != textColumnTextLength - 1) {
                const uint8 byte = insn.bytes[i];
                cb.InsertChar(codePage[byte], cb.Len(), colors.AsmDefaultColor);
            }
        }

        string.Clear();
        string.SetChars(' ', textColumnSpacesLength);
        cb.Add(string, colors.AsmDefaultColor);
    }

    cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

    string.Clear();
    string.SetChars(' ', textColumnIndicatorArrowLinesSpace);

    if (insn.lineArrowToDraw && cfg.EnableDeepScanDissasmOnStart) {
        // string.SetChars(' ', textColumnIndicatorArrowLinesSpace);
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine1)
            string[0] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine2)
            string[1] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine3)
            string[2] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine ||
            insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawEndingLine) {
            for (int32 i = 0; i < static_cast<int32>(textColumnIndicatorArrowLinesSpace); i++)
                if (string[i] == ' ')
                    string[i] = '-';
            const bool is_start = (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine) > 0;
            string[2]           = is_start ? '<' : '>';
        }
    }

    cb.Add(string, colors.AsmDefaultColor);

    if (insn.size > 0) {
        string.Clear();
        string.SetChars(' ', textPaddingLabelsSpace);

        cb.Add(string, colors.AsmDefaultColor);
    }

    string.SetFormat("%-6s", insn.mnemonic);
    const ColorPair color = GetASMColorPairByKeyword(insn.mnemonic, colors, data);
    cb.Add(string, color);

    if (insn.op_str) {
        const std::string_view op_str = insn.op_str;
        // TODO: add checks to verify  lambdaBuffer.Set, for x86 it's possible to be fine but not for other languages
        LocalString<32> lambdaBuffer;
        auto checkValidAndAdd = [&cb, &colors, &lambdaBuffer, &data](std::string_view token) {
            lambdaBuffer.Clear();
            if (token.length() > 2 && token[0] == '0' && token[1] == 'x') {
                cb.Add(token.data(), colors.AsmOffsetColor);
                return;
            }
            lambdaBuffer.Set(token.data());
            const ColorPair color = GetASMColorPairByKeyword(token, colors, data);
            cb.Add(token, color);
        };

        if (op_str.length() > 2 && op_str[0] == '0' && op_str[1] == 'x') {
            cb.Add(" ");
            checkValidAndAdd(op_str);
            return;
        }

        char lastOp = ' ';
        LocalString<32> buffer;
        for (const char c : op_str) {
            if (c == ' ' || c == ',' || c == '[' || c == ']') {
                if (buffer.Len() > 0) {
                    if (lastOp != '[')
                        cb.Add(" ");
                    checkValidAndAdd(buffer.GetText());
                    buffer.Clear();
                }
                if (c != ' ') {
                    const char tmp[3] = { ' ', c, '\0' };
                    const char* start = (c == '[') ? tmp : tmp + 1;
                    cb.Add(start, colors.AsmCompareInstructionColor);
                }
                lastOp = c;
                continue;
            }
            buffer.AddChar(c);
        }
        if (buffer.Len() > 0) {
            cb.Add(" ");
            checkValidAndAdd(buffer.GetText());
        }
    } else {
        if (mappingPtr) {
            string.SetFormat("%s", mappingPtr->name.data());
            const ColorPair mapColor = mappingPtr->type == MemoryMappingType::TextMapping ? colors.AsmLocationInstruction : colors.AsmFunctionColor;
            cb.Add(string, mapColor);
        }
        assert(mappingPtr);
    }

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
}

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

inline bool populateOffsetsVector(
      vector<AsmOffsetLine>& offsets, DisassemblyZone& zoneDetails, GView::Object& obj, int internalArchitecture, uint32& totalLines)
{
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj.GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);

    if (offsets.empty()) {
        offsets.reserve(256);
        offsets.push_back({ zoneDetails.entryPoint, 0 });
    }

    size_t minimalValue = offsets[0].offset;

    cs_insn* insn     = cs_malloc(handle);
    size_t lastOffset = offsets[0].offset;

    constexpr uint32 addInstructionsStop = 30; // TODO: update this -> for now it stops, later will fold

    std::list<uint64> finalOffsets;

    size_t size       = zoneDetails.startingZonePoint + zoneDetails.size;
    uint64 address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    uint64 endAddress = zoneDetails.size;

    if (address >= endAddress) {
        cs_close(&handle);
        return false;
    }

    auto data = instructionData.GetData() + address;

    // std::string saved1 = "s1", saved2 = "s2";
    uint64 startingOffset = offsets[0].offset;

    size_t lastSize = size;
    // std::vector<uint64> tempStorage;
    // tempStorage.push_back(lastOffset);

    do {
        if (size > lastSize) {
            lastSize = size;
            // tempStorage.reserve(size / DISSASM_INSTRUCTION_OFFSET_MARGIN + 1);
        }

        while (address < endAddress) {
            if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                break;

            if ((insn->mnemonic[0] == 'j' || *(uint32*) insn->mnemonic == callOP)) // && insn->op_str[0] == '0' /* && insn->op_str[1] == 'x'*/)
            {
                uint64 computedValue = 0;
                if (insn->op_str[1] == 'x') {
                    // uint64 computedValue = 0;
                    char* ptr = &insn->op_str[2];
                    // TODO: also check not to overflow access!
                    while (*ptr && *ptr != ' ' && *ptr != ',') {
                        if (!(*ptr >= 'a' && *ptr <= 'f' || *ptr >= '0' && *ptr <= '9')) {
                            computedValue = 0;
                            break;
                        }
                        computedValue = computedValue * 16 + HEX_MAPPER[static_cast<uint8>(*ptr)];
                        ptr++;
                    }
                } else {
                    char* ptr = &insn->op_str[0];
                    while (*ptr && *ptr != ' ' && *ptr != ',') {
                        if (*ptr < '0' || *ptr > '9') {
                            computedValue = 0;
                            break;
                        }
                        computedValue = computedValue * 10 + (static_cast<uint8>(*ptr) - '0');
                        ptr++;
                    }
                    if (computedValue < zoneDetails.startingZonePoint)
                        computedValue += zoneDetails.startingZonePoint;
                    // if (insn->op_str[1] == '\0') {
                    //     computedValue = zoneDetails.startingZonePoint;
                    // }
                }

                if (computedValue < minimalValue && computedValue >= zoneDetails.startingZonePoint) {
                    minimalValue = computedValue;
                    // saved1       = insn->mnemonic;
                    // saved2       = insn->op_str;
                }
            }
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            if (adjustedSize - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
                lastOffset = adjustedSize;
            }
        }
        if (minimalValue >= startingOffset)
            break;

        // pushBack                       = false;
        const size_t zoneSizeToAnalyze = startingOffset - minimalValue;
        // finalOffsets.push_front(minimalValue);

        address        = minimalValue - zoneDetails.startingZonePoint;
        endAddress     = zoneSizeToAnalyze + address;
        size           = address + zoneSizeToAnalyze;
        data           = instructionData.GetData() + address;
        lastOffset     = minimalValue;
        startingOffset = minimalValue;
    } while (true);

    size       = zoneDetails.size;
    address    = minimalValue - zoneDetails.startingZonePoint;
    data       = instructionData.GetData() + address;
    lastOffset = address;

    uint32 lineIndex = 0;
    offsets.clear();
    offsets.push_back({ minimalValue, 0 });

    constexpr uint32 alOpStr         = 7102752u; //* (uint32*) " al";
    uint32 continuousAddInstructions = 0;

    while (cs_disasm_iter(handle, &data, &size, &address, insn)) {
        lineIndex++;
        if (address - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
            lastOffset                = address;
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            offsets.push_back({ adjustedSize, lineIndex });
        }

        if (*(uint32*) insn->mnemonic == addOP && insn->op_str[0] == 'b' && *(uint32*) &insn->op_str[15] == alOpStr) {
            if (++continuousAddInstructions == addInstructionsStop) {
                lineIndex -= continuousAddInstructions;
                break;
            }
        } else
            continuousAddInstructions = 0;
    }

    totalLines = lineIndex;
    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}

inline cs_insn* GetCurrentInstructionByLine(
      uint32 lineToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli = nullptr)
{
    uint32 lineDifferences = 1;
    // TODO: first or be transformed into an abs ?
    const bool lineIsAtMargin = lineToReach >= zone->offsetCacheMaxLine;
    if (lineToReach < zone->lastDrawnLine || lineToReach - zone->lastDrawnLine > 1 || lineIsAtMargin) {
        // TODO: can be inlined as function
        uint32 codeOffsetIndex      = 0;
        const auto closestData      = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, lineToReach, &codeOffsetIndex);
        const bool samePreviousZone = closestData.line == zone->lastClosestLine;
        zone->lastClosestLine       = closestData.line;
        zone->asmAddress            = closestData.offset - zone->cachedCodeOffsets[0].offset;
        zone->asmSize               = zone->zoneDetails.size - zone->asmAddress;
        if (static_cast<size_t>(codeOffsetIndex) + 1u < zone->cachedCodeOffsets.size())
            zone->offsetCacheMaxLine = zone->cachedCodeOffsets[static_cast<size_t>(codeOffsetIndex) + 1u].line;
        else
            zone->offsetCacheMaxLine = UINT32_MAX;

        if (!samePreviousZone) {
            // TODO: maybe get less data ?
            const auto instructionData = obj->GetData().Get(zone->cachedCodeOffsets[0].offset + zone->asmAddress, static_cast<uint32>(zone->asmSize), false);
            zone->lastData             = instructionData;
            if (!instructionData.IsValid()) {
                if (dli)
                    dli->WriteErrorToScreen("ERROR: extract valid data from file!");
                diffLines = UINT32_MAX;
                return nullptr;
            }
        }
        zone->asmData = const_cast<uint8*>(zone->lastData.GetData());
        // if (lineInView > zone->lastDrawnLine)
        //     lineDifferences = lineInView - zone->lastDrawnLine + 1;
        lineDifferences = lineToReach - closestData.line + 1;
    }

    if (diffLines == 1) {
        diffLines = lineDifferences;
        return nullptr;
    }

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        cs_close(&handle);
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);

    while (lineDifferences > 0) {
        if (!cs_disasm_iter(handle, &zone->asmData, (size_t*) &zone->asmSize, &zone->asmAddress, insn)) {
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            cs_close(&handle);
            return nullptr;
        }
        lineDifferences--;
    }

    cs_close(&handle);
    return insn;
}

inline cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli = nullptr)
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

inline LocalString<64> FormatFunctionName(uint64 functionAddress, const char* prefix)
{
    NumericFormatter formatter;
    auto sv = formatter.ToHex(functionAddress);
    LocalString<64> callName;
    callName.AddFormat("%s%09s", prefix, sv.data());
    return callName;
}

inline bool ExtractCallsToInsertFunctionNames(
      vector<AsmOffsetLine>& offsets,
      DissasmCodeZone* zone,
      Reference<GView::Object> obj,
      int internalArchitecture,
      uint32& totalLines,
      uint64 maxLocationMemoryMappingSize)
{
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    cs_insn* insn = cs_malloc(handle);

    DisassemblyZone& zoneDetails = zone->zoneDetails;
    const auto instructionData   = obj->GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);

    uint32 linesToDecode = totalLines;
    size_t size          = zoneDetails.size;
    uint64 address       = offsets[0].offset - zoneDetails.startingZonePoint;
    auto data            = instructionData.GetData() + address;

    std::vector<std::pair<uint64, std::string>> callsFound;
    std::unordered_map<uint64, bool> callsMap; // true for offset, false for sub
    callsFound.reserve(16);
    bool foundCall     = false;
    uint64 callAddress = 0;
    while (cs_disasm_iter(handle, &data, &size, &address, insn) && linesToDecode > 0) {
        linesToDecode--;
        const bool isJump = insn->mnemonic[0] == 'j';
        if (*(uint32*) insn->mnemonic == callOP || isJump) {
            uint64 value;
            const bool foundValue = CheckExtractInsnHexValue(insn->op_str, value, maxLocationMemoryMappingSize);
            if (foundValue && value < zoneDetails.startingZonePoint + zoneDetails.size) {
                if (value < offsets[0].offset)
                    value += offsets[0].offset;
                const char* prefix = isJump ? "offset_0x" : "sub_0x";
                const auto it      = callsMap.find(value);
                if (it != callsMap.end()) {
                    if (isJump == it->second)
                        continue;
                }
                auto callName = FormatFunctionName(value, prefix);
                callsFound.emplace_back(value, callName.GetText());
                callsMap.insert({ value, isJump });
            }
        } else {
            const auto mnemonicVal = *(uint32*) insn->mnemonic;
            if (foundCall) {
                if (mnemonicVal == movOP && strcmp(insn->op_str, "ebp, esp") == 0) {
                    if (callAddress < offsets[0].offset)
                        callAddress += offsets[0].offset;
                    const auto it = callsMap.find(callAddress);
                    if (it != callsMap.end()) {
                        if (!it->second)
                            continue;
                    }
                    const char* prefix = "sub_0x";
                    auto callName      = FormatFunctionName(callAddress, prefix);
                    callsFound.emplace_back(callAddress, callName.GetText());
                    callsMap.insert({ callAddress, true });
                }
                foundCall = false;
            } else {
                if (mnemonicVal == pushOP) {
                    if (strcmp(insn->op_str, "ebp") == 0) {
                        callAddress = insn->address;
                        foundCall   = true;
                    }
                }
            }
        }
    }

    auto val = callsFound[0].first;

    enum labelType { SUB, OFFSET, OTHER };
    auto getLabelType = [](const std::string& s) -> labelType {
        assert(!s.empty());
        if (s.size() < 4)
            return OTHER;
        if (memcmp(s.c_str(), "sub_", 4) == 0)
            return SUB;
        if (s.size() < 7)
            return OTHER;
        if (memcmp(s.c_str(), "offset_", 7) == 0)
            return OFFSET;
        return OTHER;
    };

    std::vector<uint32> indexesToErase;
    for (int32 i = static_cast<int32>(callsFound.size()) - 1; i >= 0; i--) {
        const auto& call = callsFound[i];
        if (call.first == zone->zoneDetails.entryPoint) {
            indexesToErase.push_back(i);
            break;
        }
    }
    for (const auto indexToErase : indexesToErase)
        callsFound.erase(callsFound.begin() + indexToErase);

    callsFound.emplace_back(zone->zoneDetails.entryPoint, "EntryPoint");
    // TODO: this can be extracted for the user to add / delete its own operations
    std::sort(callsFound.begin(), callsFound.end(), [getLabelType](const auto& a, const auto& b) {
        if (a.first < b.first)
            return true;
        if (a.first > b.first)
            return false;
        return getLabelType(a.second) < getLabelType(b.second);

        // return a.second.compare(b.second) > 0; // move sub instructions first
    });

    // TODO: if there are missing called improve predicate to delele only sub and offset
    callsFound.erase(
          std::unique(callsFound.begin(), callsFound.end(), [](const auto& left, const auto& right) { return left.first == right.first; }), callsFound.end());

    // callsFound.push_back({ 1030, "call2" });
    // callsFound.push_back({ 1130, "call 3" });
    // callsFound.push_back({ 1140, "call 5" });
    uint32 extraLines = 0;
    for (const auto& call : callsFound) {
        const uint64 callValue = call.first;
        uint32 diffLines       = 0;
        auto callInsn          = GetCurrentInstructionByOffset(callValue, zone, obj, diffLines);
        if (callInsn) {
            zone->dissasmType.annotations.insert({ diffLines + extraLines, { call.second, callValue - offsets[0].offset } });
            cs_free(callInsn, 1);
            extraLines++;
        }
    }
    totalLines += static_cast<uint32>(callsFound.size());
    cs_free(insn, 1);
    cs_close(&handle);

    return true;
}

inline const MemoryMappingEntry* TryExtractMemoryMapping(const Pointer<SettingsData>& settings, uint64 initialLocation, const uint64 possibleLocationAdjustment)
{
    const auto& mapping = settings->memoryMappings.find(initialLocation);
    if (mapping != settings->memoryMappings.end())
        return &mapping->second;
    const auto& mapping2 = settings->memoryMappings.find(initialLocation + possibleLocationAdjustment);
    if (mapping2 != settings->memoryMappings.end())
        return &mapping2->second;
    return nullptr;
}

inline optional<vector<uint8>> TryExtractPushText(Reference<GView::Object> obj, const uint64_t offset)
{
    const auto stringBuffer = obj->GetData().Get(offset, DISSAM_MAXIMUM_STRING_PREVIEW * 2, false);
    if (!stringBuffer.IsValid())
        return {};

    auto dataStart = stringBuffer.GetData();
    auto dataEnd   = dataStart + stringBuffer.GetLength();

    std::vector<uint8> textFound;
    textFound.reserve(DISSAM_MAXIMUM_STRING_PREVIEW * 2);
    textFound.push_back('"');
    bool wasZero = true;

    while (dataStart < dataEnd) {
        if (*dataStart >= 32 && *dataStart <= 126) {
            textFound.push_back(*dataStart);
            wasZero = false;
        } else if (*dataStart == '\0') {
            if (wasZero)
                break;
            wasZero = true;
        } else {
            break;
        }
        dataStart++;
    }

    if (textFound.size() >= DISSAM_MAXIMUM_STRING_PREVIEW) {
        while (textFound.size() > DISSAM_MAXIMUM_STRING_PREVIEW)
            textFound.erase(textFound.begin() + textFound.size() - 1);
        textFound.push_back('.');
        textFound.push_back('.');
        textFound.push_back('.');
    }
    textFound.push_back('"');
    textFound.push_back('\0');
    return textFound;
}

std::optional<uint32> DissasmGetCurrentAsmLineAndPrepareCodeZone(DissasmCodeZone* zone, uint32 currentLine)
{
    const uint32 levelToReach = currentLine;
    uint32& levelNow          = zone->structureIndex;
    bool reAdapt              = false;
    while (true) {
        const DissasmCodeInternalType& currentType = zone->types.back();
        if (currentType.indexZoneStart <= levelToReach && currentType.indexZoneEnd >= levelToReach)
            break;
        zone->types.pop_back();
        zone->levels.pop_back();
        reAdapt = true;
    }

    while (reAdapt && !zone->types.back().get().internalTypes.empty()) {
        DissasmCodeInternalType& currentType = zone->types.back();
        for (uint32 i = 0; i < currentType.internalTypes.size(); i++) {
            auto& internalType = currentType.internalTypes[i];
            if (internalType.indexZoneStart <= levelToReach && internalType.indexZoneEnd >= levelToReach) {
                zone->types.push_back(internalType);
                zone->levels.push_back(i);
                break;
            }
        }
    }

    DissasmCodeInternalType& currentType = zone->types.back();
    // TODO: do a faster search using a binary search using the annotations and start from there
    // TODO: maybe use some caching here?
    if (reAdapt || levelNow < levelToReach && levelNow + 1 != levelToReach || levelNow > levelToReach && levelNow - 1 != levelToReach) {
        currentType.textLinesPassed = 0;
        currentType.asmLinesPassed  = 0;
        for (uint32 i = currentType.indexZoneStart; i <= levelToReach; i++) {
            if (currentType.annotations.contains(i)) {
                currentType.textLinesPassed++;
                continue;
            }
            currentType.asmLinesPassed++;
        }
    } else {
        if (currentType.annotations.contains(levelToReach))
            currentType.textLinesPassed++;
        else
            currentType.asmLinesPassed++;
    }

    levelNow = levelToReach;

    if (currentType.annotations.contains(levelToReach))
        return {};

    const uint32 value = currentType.GetCurrentAsmLine();
    if (value == 0)
        return {};

    return value - 1u;
}

bool DissasmAsmPreCacheLine::TryGetDataFromAnnotations(const DissasmCodeInternalType& currentType, uint32 lineToSearch, DrawLineInfo* dli)
{
    const auto foundAnnotation = currentType.annotations.find(lineToSearch);
    if (foundAnnotation == currentType.annotations.end()) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: failed to find annotation for line!");
        return false;
    }

    size        = 0;
    currentLine = lineToSearch;
    address     = foundAnnotation->second.second;

    if (currentType.isCollapsed) {
        op_str      = strdup(currentType.name.c_str());
        op_str_size = static_cast<uint32>(currentType.name.size());
        strncpy(mnemonic, "collapsed", std::min<uint32>(sizeof(mnemonic), 9));
        return true;
    }

    strncpy(mnemonic, foundAnnotation->second.first.data(), sizeof(mnemonic));
    // strncpy((char*) bytes, "------", sizeof(bytes));
    // size        = static_cast<uint32>(strlen((char*) bytes));

    op_str      = strdup("<--");
    op_str_size = static_cast<uint32>(strlen(op_str));
    return true;
}

bool DissasmAsmPreCacheLine::TryGetDataFromInsn(DissasmInsnExtractLineParams& params)
{
    uint32 diffLines = 0;
    cs_insn* insn    = GetCurrentInstructionByLine(params.asmLine, params.zone, params.obj, diffLines, params.dli);
    if (!insn)
        return false;

    address = insn->address;
    memcpy(bytes, insn->bytes, std::min<uint32>(sizeof(bytes), sizeof(insn->bytes)));
    size        = insn->size;
    currentLine = params.actualLine;

    if (params.isCollapsed && params.zoneName) {
        op_str      = strdup(params.zoneName->c_str());
        op_str_size = static_cast<uint32>(params.zoneName->size());
        strncpy(mnemonic, "collapsed", std::min<uint32>(sizeof(mnemonic), 9));
        cs_free(insn, 1);
        return true;
    }

    memcpy(mnemonic, insn->mnemonic, CS_MNEMONIC_SIZE);

    if (!params.settings || !params.asmData)
        return true;

    switch (*((uint32*) insn->mnemonic)) {
    case pushOP:
        flags = DissasmAsmPreCacheLine::InstructionFlag::PushFlag;
        break;
    case callOP:
        flags = DissasmAsmPreCacheLine::InstructionFlag::CallFlag;
        break;
    default:
        if (insn->mnemonic[0] == 'j') {
            flags = DissasmAsmPreCacheLine::InstructionFlag::JmpFlag;
        } else {
            op_str      = strdup(insn->op_str);
            op_str_size = static_cast<uint32>(strlen(op_str));
            // params.zone->asmPreCacheData.cachedAsmLines.push_back(std::move(asmCacheLine));
            cs_free(insn, 1);
            return true;
        }
    }

    // TODO: improve efficiency by filtering instructions
    uint64 hexVal = 0;
    if (CheckExtractInsnHexValue(insn->op_str, hexVal, params.settings->maxLocationMemoryMappingSize)) {
        hexValue = hexVal;
        if (hexVal == 0 && flags != DissasmAsmPreCacheLine::InstructionFlag::PushFlag)
            hexValue = params.zone->cachedCodeOffsets[0].offset;
    }
    bool alreadyInitComment = false;
    if (params.zone->asmPreCacheData.HasAnyFlag(params.asmLine))
        alreadyInitComment = true;

    const uint64 finalIndex = params.zone->asmAddress + params.settings->offsetTranslateCallback->TranslateFromFileOffset(
                                                              params.zone->zoneDetails.entryPoint, (uint32) DissasmPEConversionType::RVA);
    auto& lastZone          = params.zone->types.back().get();
    bool shouldConsiderCall = false;
    if (flags == DissasmAsmPreCacheLine::InstructionFlag::CallFlag) {
        const MemoryMappingEntry* mappingPtr = nullptr; // TryExtractMemoryMapping(params.settings, hexVal, finalIndex);

        const auto& mapping_ptr = params.settings->memoryMappings.find(hexVal);
        if (mapping_ptr != params.settings->memoryMappings.end())
            mappingPtr = &mapping_ptr->second;
        else {
            const auto& mapping2 = params.settings->memoryMappings.find(hexVal + finalIndex);
            if (mapping2 != params.settings->memoryMappings.end())
                mappingPtr = &mapping2->second;
        }

        if (mappingPtr) {
            mapping     = mappingPtr;
            op_str_size = (uint32) mappingPtr->name.size();
            if (mappingPtr->type == MemoryMappingType::FunctionMapping && !alreadyInitComment) {
                // TODO: add functions to the obj AsmData to search for name instead of manually doing CRC
                GView::Hashes::CRC32 crc32{};
                uint32 hash    = 0;
                const bool res = crc32.Init(GView::Hashes::CRC32Type::JAMCRC) &&
                                 crc32.Update(reinterpret_cast<const uint8*>(mappingPtr->name.data()), static_cast<uint32>(mappingPtr->name.size())) &&
                                 crc32.Final(hash);
                if (res) {
                    const auto it = params.asmData->functions.find(hash);
                    if (it != params.asmData->functions.end()) {
                        params.zone->asmPreCacheData.AnnounceCallInstruction(params.zone, it->second, lastZone.commentsData);
                        params.zone->asmPreCacheData.AddInstructionFlag(params.asmLine, DissasmAsmPreCacheLine::CallFlag);
                    }
                }
            }
        } else {
            shouldConsiderCall = true;
        }
    } else if (flags == DissasmAsmPreCacheLine::InstructionFlag::PushFlag) {
        if (!alreadyInitComment && !lastZone.commentsData.comments.contains(params.actualLine)) {
            const auto offset = params.settings->offsetTranslateCallback->TranslateToFileOffset(hexVal, (uint32) DissasmPEConversionType::RVA);
            if (offset != static_cast<uint64>(-1) && offset + DISSAM_MAXIMUM_STRING_PREVIEW < params.obj->GetData().GetSize()) {
                const auto textFoundOption = TryExtractPushText(params.obj, offset);
                if (textFoundOption.has_value()) {
                    const auto& textFound = textFoundOption.value();
                    if (textFound.size() > 3) {
                        lastZone.commentsData.AddOrUpdateComment(params.actualLine, (const char*) textFound.data());
                        params.zone->asmPreCacheData.AddInstructionFlag(params.asmLine, DissasmAsmPreCacheLine::PushFlag);
                    }
                }
            }
        }
    }

    if (flags == DissasmAsmPreCacheLine::InstructionFlag::JmpFlag || shouldConsiderCall) {
        if (!hexValue.has_value()) {
            flags       = 0;
            op_str      = strdup(insn->op_str);
            op_str_size = static_cast<uint32>(strlen(op_str));
            // params.zone->asmPreCacheData.cachedAsmLines.push_back(std::move(asmCacheLine));
            cs_free(insn, 1);
            return true;
        }

        const char* prefix = !shouldConsiderCall ? "jmp_0x" : "sub_0x";

        NumericFormatter n;
        const auto res = n.ToString(hexValue.value(), { NumericFormatFlags::HexPrefix, 16 });

        auto fnName = FormatFunctionName(hexValue.value(), prefix);
        fnName.AddFormat(" (%s)", res.data());

        op_str      = strdup(fnName.GetText());
        op_str_size = static_cast<uint32>(fnName.Len());
    }

    if (!op_str && !mapping) {
        op_str      = strdup(insn->op_str);
        op_str_size = (uint32) strlen(op_str);
    }
    // params.zone->asmPreCacheData.cachedAsmLines.push_back(std::move(asmCacheLine));
    cs_free(insn, 1);
    return true;
}

// bool DissasmAsmPreCacheLine::TryGetDataFromInsn(cs_insn* insn, uint32 currentLine)
//{
//     if (!insn)
//         return false;
//     this->address     = insn->address;
//     memcpy(bytes, insn->bytes, std::min<uint32>(sizeof(bytes), sizeof(insn->bytes)));
//     this->size        = insn->size;
//     memcpy(mnemonic, insn->mnemonic, CS_MNEMONIC_SIZE);
//     this->currentLine = currentLine;
//
//     this->op_str      = strdup(insn->op_str);
//     this->op_str_size = (uint32) strlen(this->op_str);
//     strcpy(this->mnemonic, insn->mnemonic);
//
//     this->hexValue = currentLine; //??
//     return true;
// }

void DissasmAsmPreCacheData::PrepareLabelArrows()
{
    if (cachedAsmLines.empty())
        return;

    const uint64 minimalAddress = cachedAsmLines.front().address;
    const uint64 maximalAddress = cachedAsmLines.back().address;

    std::vector<DissasmAsmPreCacheLine*> startInstructions;
    startInstructions.reserve(textColumnIndicatorArrowLinesSpace);

    for (auto& line : cachedAsmLines) {
        line.lineArrowToDraw = 0;
        if (line.flags != DissasmAsmPreCacheLine::InstructionFlag::CallFlag && line.flags != DissasmAsmPreCacheLine::InstructionFlag::JmpFlag)
            continue;
        if (!line.hexValue.has_value())
            continue;
        if (line.hexValue.value() < minimalAddress || line.hexValue.value() > maximalAddress)
            continue;
        startInstructions.push_back(&line);
        if (startInstructions.size() >= textColumnIndicatorArrowLinesSpace)
            break;
    }

    if (startInstructions.empty())
        return;

    std::sort(startInstructions.begin(), startInstructions.end(), [](const DissasmAsmPreCacheLine* a, const DissasmAsmPreCacheLine* b) {
        return a->hexValue.value() < b->hexValue.value();
    });

    std::vector<DissasmAsmPreCacheLine*> actualLabelsLines;
    actualLabelsLines.reserve(startInstructions.size());

    {
        auto cacheLineIt = cachedAsmLines.begin();
        auto labelIt     = startInstructions.begin();
        while (labelIt != startInstructions.end() && cacheLineIt != cachedAsmLines.end()) {
            if (cacheLineIt->address == (*labelIt)->hexValue.value()) {
                actualLabelsLines.push_back(&(*cacheLineIt));
                ++labelIt;
            } else
                ++cacheLineIt;
            //++cacheLineIt;
        }
    }

    assert(startInstructions.size() == actualLabelsLines.size());

    auto startOpIt   = startInstructions.begin();
    auto endOpIt     = actualLabelsLines.begin();
    uint32 lineIndex = 0;
    uint8 lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine1;

    while (startOpIt != startInstructions.end()) {
        const bool startOpIsSmaller       = (*startOpIt)->currentLine < (*endOpIt)->currentLine;
        DissasmAsmPreCacheLine* startLine = startOpIsSmaller ? *startOpIt : *endOpIt;
        DissasmAsmPreCacheLine* endLine   = startOpIsSmaller ? *endOpIt : *startOpIt;

        startLine->lineArrowToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine;
        endLine->lineArrowToDraw   = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawEndingLine;

        while (startLine <= endLine) {
            startLine->lineArrowToDraw |= lineToDraw;
            ++startLine;
        }

        ++startOpIt;
        ++endOpIt;
        switch (++lineIndex) {
        case 0:
            lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine1;
            break;
        case 1:
            lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine2;
            break;
        case 2:
            lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine3;
            break;
        case 3:
            lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine4;
            break;
        case 4:
            lineToDraw = DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine5;
            break;
        default:
            assert(false); // invalid lineToDraw value
        }
    }
}

bool Instance::DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0) {
        dli.WriteErrorToScreen("No data available!");
        return true;
    }

    chars.Clear();

    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    LocalString<256> spaces;
    spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
    chars.Set(spaces);

    if (dli.textLineToDraw == 0) {
        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), ColorMan.Colors.StructureColor);

        HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(zoneName.size()), static_cast<uint32>(zoneName.size()) + Layout.startingTextLineOffset);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);

        if (!zone->isInit) {
            {
                DissasmCodeZoneInitData initData{};
                initData.enableDeepScanDissasmOnStart = config.EnableDeepScanDissasmOnStart;
                initData.obj                          = obj;
                initData.dli                          = &dli;
                initData.maxLocationMemoryMappingSize = settings->maxLocationMemoryMappingSize;
                initData.visibleRows                  = Layout.visibleRows;

                if (!zone->InitZone(initData))
                    return false;
                if (initData.hasAdjustedSize)
                    AdjustZoneExtendedSize(zone, initData.adjustedZoneSize);
            }
        }

        return true;
    }

    const bool firstLineToDraw = dli.screenLineToDraw == 0;
    if (dli.textLineToDraw == 1 || firstLineToDraw) {
        const ColorPair titleColumnColor = { ColorMan.Colors.AsmTitleColumnColor.Foreground, ColorMan.Colors.AsmTitleColor.Background };

        constexpr std::string_view address = "File address";
        chars.Add(address.data(), ColorMan.Colors.AsmTitleColor);

        spaces.Clear();
        spaces.SetChars(' ', addressTotalLength - static_cast<uint32>(address.size()) - 1u);
        chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

        chars.InsertChar('|', chars.Len(), titleColumnColor);

        if (!config.ShowOnlyDissasm) {
            constexpr std::string_view opCodes = "Op Codes";
            chars.Add(opCodes.data(), ColorMan.Colors.AsmTitleColor);
            spaces.Clear();
            spaces.SetChars(' ', opCodesTotalLength - static_cast<uint32>(opCodes.size()) - 1u);
            chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

            chars.InsertChar('|', chars.Len(), titleColumnColor);

            constexpr std::string_view textTitle = "Text";
            chars.Add(textTitle.data(), ColorMan.Colors.AsmTitleColor);
            spaces.Clear();
            spaces.SetChars(' ', textColumnTotalLength - static_cast<uint32>(textTitle.size()) - 1u);
            chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

            chars.InsertChar('|', chars.Len(), titleColumnColor);
        }

        constexpr std::string_view dissasmTitle = "Dissasm";
        chars.Add(dissasmTitle.data(), ColorMan.Colors.AsmTitleColor);
        uint32 titleColorRemaining = Layout.totalCharactersPerLine - chars.Len();
        if (chars.Len() > Layout.totalCharactersPerLine)
            titleColorRemaining = 0;
        spaces.Clear();
        spaces.SetChars(' ', titleColorRemaining);
        chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

        HighlightSelectionAndDrawCursorText(dli, chars.Len() - Layout.startingTextLineOffset, chars.Len());

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);
        return true;
    }

    uint32 currentLine = dli.textLineToDraw - 2u;
    if (firstLineToDraw)
        --currentLine;

    if (!zone->isInit) {
        {
            DissasmCodeZoneInitData initData{};
            initData.enableDeepScanDissasmOnStart = config.EnableDeepScanDissasmOnStart;
            initData.obj                          = obj;
            initData.dli                          = &dli;
            initData.maxLocationMemoryMappingSize = settings->maxLocationMemoryMappingSize;
            initData.visibleRows                  = Layout.visibleRows;

            if (!zone->InitZone(initData))
                return false;
            if (initData.hasAdjustedSize)
                AdjustZoneExtendedSize(zone, initData.adjustedZoneSize);
        }
    }

    auto& asmPreCacheData = zone->asmPreCacheData;
    if (asmPreCacheData.cachedAsmLines.empty()) {
        uint32 linesToPrepare       = std::min<uint32>(Layout.visibleRows, zone->extendedSize);
        const uint32 remainingLines = zone->extendedSize - currentLine + 1;
        linesToPrepare              = std::min<uint32>(linesToPrepare, remainingLines);
        const uint32 endingLine     = currentLine + linesToPrepare;

        DissasmInsnExtractLineParams params{};
        params.obj      = obj;
        params.settings = settings.get();
        params.asmData  = &asmData;
        params.dli      = &dli;
        params.zone     = zone;

        uint32 currentLineAux = currentLine;
        while (currentLineAux < endingLine) {
            auto asmCacheLine = zone->GetCurrentAsmLine(currentLineAux, obj, &params);
            asmPreCacheData.cachedAsmLines.push_back(std::move(asmCacheLine));
            currentLineAux++;
        }

        asmPreCacheData.ComputeMaxLine();
        if (config.EnableDeepScanDissasmOnStart)
            asmPreCacheData.PrepareLabelArrows();
    }

    const auto asmCacheLine = zone->asmPreCacheData.GetLine();
    if (!asmCacheLine)
        return false;
    if (asmCacheLine->shouldAddButton) {
        RegisterStructureCollapseButton(
              dli.screenLineToDraw + 1, asmCacheLine->isZoneCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone, true);
    }
    DissasmAddColorsToInstruction(*asmCacheLine, chars, config, ColorMan.Colors, asmData, codePage, zone->cachedCodeOffsets[0].offset);
    std::string comment;
    assert(asmCacheLine->parent);
    if (asmCacheLine->parent && !asmCacheLine->parent->isCollapsed && asmCacheLine->parent->commentsData.GetComment(currentLine, comment)) {
        uint32 diffLine = zone->asmPreCacheData.maxLineSize + textTotalColumnLength + commentPaddingLength;
        if (config.ShowOnlyDissasm)
            diffLine -= textAndOpCodesTotalLength;
        if (chars.Len() > diffLine)
            diffLine = commentPaddingLength;
        else
            diffLine -= chars.Len();
        LocalString<DISSAM_MINIMUM_COMMENTS_X> spaces;
        spaces.AddChars(' ', diffLine);
        spaces.AddChars(';', 1);
        chars.Add(spaces, ColorMan.Colors.AsmComment);
        chars.Add(comment, ColorMan.Colors.AsmComment);
    }

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };

    /*if (isCursorLine)
        chars.SetColor(Layout.startingTextLineOffset, chars.Len(), config.Colors.HighlightCursorLine);*/

    HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(bufferToDraw.length()), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    // poolBuffer.lineToDrawOnScreen = dli.screenLineToDraw + 1;
    bool foundZone = false;
    for (const auto& z : asmData.zonesToClear)
        if (z == zone) {
            foundZone = true;
            break;
        }
    if (!foundZone)
        asmData.zonesToClear.push_back(zone);
    return true;
}

void Instance::CommandExportAsmFile()
{
    int zoneIndex = 0;
    LocalString<128> string;
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone) {
            AppCUI::Utils::UnicodeStringBuilder sb;
            sb.Add(obj->GetPath());
            LocalString<32> fileName;
            fileName.SetFormat(".x86.z%d.asm", zoneIndex);
            sb.Add(fileName);

            AppCUI::OS::File f;
            if (!f.Create(sb.ToStringView(), true)) {
                continue;
            }
            if (!f.OpenWrite(sb.ToStringView())) {
                f.Close();
                continue;
            }

            f.Write("ASMZoneZone\n", sizeof("ASMZoneZone\n") - 1);

            csh handle;
            const auto resCode = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
            if (resCode != CS_ERR_OK) {
                f.Write(cs_strerror(resCode));
                f.Close();
            }

            cs_insn* insn = cs_malloc(handle);

            const auto dissamZone      = static_cast<DissasmCodeZone*>(zone.get());
            const uint64 staringOffset = dissamZone->cachedCodeOffsets[0].offset;
            size_t size                = dissamZone->zoneDetails.size - (staringOffset - dissamZone->zoneDetails.startingZonePoint);

            uint64 address          = 0;
            const uint64 endAddress = size;

            const auto dataBuffer = obj->GetData().Get(staringOffset, static_cast<uint32>(size), false);
            if (!dataBuffer.IsValid()) {
                f.Write("Failed to get data from file!");
                f.Close();
                continue;
            }
            auto data = dataBuffer.GetData();

            while (address < endAddress) {
                if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                    break;

                string.SetFormat("0x%" PRIx64 ":     %-10s %s\n", insn->address + staringOffset, insn->mnemonic, insn->op_str);
                f.Write(string.GetText(), string.Len());
            }

            cs_free(insn, 1);
            cs_close(&handle);
            f.Close();
            zoneIndex++;

            GView::App::OpenFile(sb.ToStringView(), App::OpenMethod::BestMatch);
        }
    }
}

void Instance::DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line, uint64* offsetToReach)
{
    uint32 diffLines     = 0;
    uint64 computedValue = 0;
    cs_insn* insn;
    if (!offsetToReach) {
        if (line <= 1)
            return;

        const decltype(DissasmCodeZone::structureIndex) index = zone->structureIndex;
        decltype(DissasmCodeZone::types) types                = zone->types;
        decltype(DissasmCodeZone::levels) levels              = zone->levels;

        const auto adjustedLine = DissasmGetCurrentAsmLineAndPrepareCodeZone(zone, line - 2);

        zone->structureIndex = index;
        zone->types          = std::move(types);
        zone->levels         = std::move(levels);

        if (!adjustedLine.has_value())
            return;

        insn = GetCurrentInstructionByLine(adjustedLine.value(), zone, obj, diffLines);
        if (!insn) {
            Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
            return;
        }
        if (insn->mnemonic[0] == 'j' || insn->mnemonic[0] == 'c' && *(uint32*) insn->mnemonic == callOP) {
            if (insn->op_str[0] == '0' && insn->op_str[1] == 'x') {
                char* val = &insn->op_str[2];

                while (*val && *val != ',' && *val != ' ') {
                    if (*val >= '0' && *val <= '9')
                        computedValue = computedValue * 16 + (*val - '0');
                    else if (*val >= 'a' && *val <= 'f')
                        computedValue = computedValue * 16 + (*val - 'a' + 10);
                    else {
                        Dialogs::MessageBox::ShowNotification("Warning", "Invalid jump value!");
                        computedValue = 0;
                        break;
                    }
                    val++;
                }
            } else if (insn->op_str[0] >= '0' && insn->op_str[0] <= '9' && insn->op_str[1] == '\0') {
                computedValue = zone->cachedCodeOffsets[0].offset + (insn->op_str[0] - '0');
            } else {
                cs_free(insn, 1);
                return;
            }
            cs_free(insn, 1);
        } else {
            cs_free(insn, 1);
            return;
        }
    } else
        computedValue = *offsetToReach;

    if (computedValue == 0 || computedValue > zone->zoneDetails.startingZonePoint + zone->zoneDetails.size)
        return;

    if (computedValue < zone->zoneDetails.startingZonePoint)
        computedValue += zone->zoneDetails.startingZonePoint;

    // computedValue = 1064;

    diffLines = 0;
    insn      = GetCurrentInstructionByOffset(computedValue, zone, obj, diffLines);
    if (!insn) {
        Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
        return;
    }
    cs_free(insn, 1);

    // diffLines++; // increased because of the menu bar

    const decltype(DissasmCodeZone::structureIndex) index = zone->structureIndex;
    decltype(DissasmCodeZone::types) types                = zone->types;
    decltype(DissasmCodeZone::levels) levels              = zone->levels;

    // TODO: can be improved by extracting the common part of the calculation of the actual line and to search for the closest zone directly
    const auto adjustedLine = DissasmGetCurrentAsmLineAndPrepareCodeZone(zone, diffLines);
    uint32 actualLine       = zone->types.back().get().beforeTextLines + 2; //+1 for menu, +1 for title

    const auto annotations = zone->types.back().get().annotations;
    for (const auto& entry : annotations) // no std::views::keys on mac
    {
        if (entry.first >= diffLines)
            break;
        actualLine++;
    }

    // if (adjustedLine.has_value())
    //     actualLine += adjustedLine.value() + 1;

    zone->structureIndex = index;
    zone->types          = std::move(types);
    zone->levels         = std::move(levels);

    diffLines += actualLine;

    jumps_holder.insert(Cursor.saveState());
    Cursor.lineInView    = std::min<uint32>(5, diffLines);
    Cursor.startViewLine = diffLines + zone->startLineIndex - Cursor.lineInView;
    Cursor.hasMovedView  = true;
}

void Instance::CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation operation)
{
    if (operation == CollapsibleZoneOperation::Add && !selection.HasSelection(0)) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a single selection on a dissasm zone to add a zone!");
        return;
    }

    uint32 lineStart;
    uint32 lineEnd;
    if (selection.HasSelection(0)) {
        lineStart = selection.GetSelectionStart(0).line;
        lineEnd   = selection.GetSelectionEnd(0).line;
    } else {
        lineStart = Cursor.lineInView + Cursor.startViewLine;
        lineEnd   = lineStart + 1;
    }

    const auto zonesFound = GetZonesIndexesFromLinePosition(lineStart, lineEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    if (zonesFound[0].startingLine <= 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please do not select the title in the collapsible zones!");
        return;
    }

    auto zone = static_cast<DissasmCodeZone*>(parseZone.get());

    const uint32 zoneLineStart  = zonesFound[0].startingLine - 2; // 2 for title and menu -- need to be adjusted
    const uint32 zoneLinesCount = lineEnd - lineStart + 1u;
    const uint32 zoneLineEnd    = zoneLineStart + zoneLinesCount;

    int32 difference          = 0;
    const char* operationName = nullptr;
    switch (operation) {
    case CollapsibleZoneOperation::Add:
        if (!zone->AddCollapsibleZone(zoneLineStart, zoneLineEnd))
            operationName = "Add";
        break;
    case CollapsibleZoneOperation::Expand:
        if (!zone->CollapseOrExtendZone(zoneLineStart, DissasmCodeZone::CollapseExpandType::Expand, difference))
            operationName = "Expand";
        break;
    case CollapsibleZoneOperation::Collapse:
        if (!zone->CollapseOrExtendZone(zoneLineStart, DissasmCodeZone::CollapseExpandType::Collapse, difference))
            operationName = "Collapse";
        break;
    case CollapsibleZoneOperation::Remove:
        if (!zone->RemoveCollapsibleZone(zoneLineStart))
            operationName = "Collapse";
        break;
    default:
        Dialogs::MessageBox::ShowNotification("Warning", "Unimplemented!");
        break;
    }

    if (operationName) {
        LocalString<64> message;
        message.SetFormat("Failed to %s to zone!", operationName);
        Dialogs::MessageBox::ShowNotification("Error", message);
    } else {
        zone->ResetZoneCaching();
        if (difference) {
            AdjustZoneExtendedSize(zone, difference);
        }
    }
}

bool DissasmCodeZone::InitZone(DissasmCodeZoneInitData& initData)
{
    // TODO: move this on init
    if (!cs_support(CS_ARCH_X86)) {
        initData.dli->WriteErrorToScreen("Capstone does not support X86");
        initData.adjustedZoneSize = 1;
        initData.hasAdjustedSize  = true;
        return false;
    }

    switch (zoneDetails.language) {
    case DisassemblyLanguage::x86:
        internalArchitecture = CS_MODE_32;
        break;
    case DisassemblyLanguage::x64:
        internalArchitecture = CS_MODE_64;
        break;
    default: {
        initData.dli->WriteErrorToScreen("ERROR: unsupported language!");
        return false;
    }
    }

    uint32 totalLines = 0;
    if (!populateOffsetsVector(cachedCodeOffsets, zoneDetails, initData.obj, internalArchitecture, totalLines)) {
        initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    if (initData.enableDeepScanDissasmOnStart &&
        !ExtractCallsToInsertFunctionNames(cachedCodeOffsets, this, initData.obj, internalArchitecture, totalLines, initData.maxLocationMemoryMappingSize)) {
        initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    totalLines++; //+1 for title
    initData.adjustedZoneSize = totalLines;
    initData.hasAdjustedSize  = true;
    // AdjustZoneExtendedSize(zone, totalLines);
    lastDrawnLine          = 0;
    const auto closestData = SearchForClosestAsmOffsetLineByLine(cachedCodeOffsets, lastDrawnLine);
    lastClosestLine        = closestData.line;
    isInit                 = true;

    asmAddress = 0;
    asmSize    = zoneDetails.size - asmAddress;

    const auto instructionData = initData.obj->GetData().Get(cachedCodeOffsets[0].offset + asmAddress, static_cast<uint32>(asmSize), false);
    lastData                   = instructionData;
    if (!instructionData.IsValid()) {
        initData.dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        return false;
    }
    asmData = const_cast<uint8*>(instructionData.GetData());

    const uint32 preReverseSize = std::min<uint32>(initData.visibleRows, extendedSize);
    asmPreCacheData.cachedAsmLines.reserve(preReverseSize);

    structureIndex = 0;
    types.push_back(dissasmType);
    levels.push_back(0);

    dissasmType.indexZoneStart = 0; //+1 for the title
    dissasmType.indexZoneEnd   = totalLines + 1;
    // dissasmType.annotations.insert({ 2, "loc fn" });

    return true;
}

void DissasmCodeZone::ReachZoneLine(uint32 line)
{
    changedLevel = false;
    if (lastReachedLine == line)
        return;

    const uint32 levelToReach = line;
    uint32& levelNow          = this->structureIndex;
    bool reAdapt              = false;
    while (true) {
        const DissasmCodeInternalType& currentType = types.back();
        if (currentType.indexZoneStart <= levelToReach && levelToReach < currentType.indexZoneEnd) {
            if (!currentType.internalTypes.empty())
                reAdapt = true;
            break;
        }
        types.pop_back();
        levels.pop_back();
        reAdapt = true;
    }

    while (reAdapt && !types.back().get().internalTypes.empty()) {
        DissasmCodeInternalType& currentType = types.back();
        for (uint32 i = 0; i < currentType.internalTypes.size(); i++) {
            auto& internalType = currentType.internalTypes[i];
            if (internalType.indexZoneStart <= levelToReach && levelToReach < internalType.indexZoneEnd) {
                types.emplace_back(internalType);
                levels.push_back(i);
                changedLevel                   = true;
                newLevelChangeData.hasName     = !internalType.name.empty();
                newLevelChangeData.isCollapsed = internalType.isCollapsed;
                break;
            }
        }
    }

    DissasmCodeInternalType& currentType = types.back();
    // TODO: do a faster search using a binary search using the annotations and start from there
    // TODO: maybe use some caching here?
    if (reAdapt || levelNow < levelToReach && levelNow + 1 != levelToReach || levelNow > levelToReach && levelNow - 1 != levelToReach) {
        currentType.textLinesPassed = 0;
        currentType.asmLinesPassed  = 0;
        for (uint32 i = currentType.indexZoneStart; i <= levelToReach; i++) {
            if (currentType.annotations.contains(i)) {
                currentType.textLinesPassed++;
                continue;
            }
            currentType.asmLinesPassed++;
        }
    } else {
        if (currentType.annotations.contains(levelToReach))
            currentType.textLinesPassed++;
        else
            currentType.asmLinesPassed++;
    }

    levelNow        = levelToReach;
    lastReachedLine = levelToReach;

    // if (currentType.annotations.contains(levelToReach))
    //     return {};

    // const uint32 value = currentType.GetCurrentAsmLine();
    // if (value == 0)
    //     return {};

    // return value - 1u;
}

bool DissasmCodeZone::ResetTypesReferenceList()
{
    types.clear();
    levels.clear();
    structureIndex  = 0;
    lastReachedLine = static_cast<uint32>(-1);
    types.emplace_back(dissasmType);
    levels.push_back(0);
    ResetZoneCaching();
    return true;
}

using ValidChildCallback = bool(DissasmCodeInternalType*, void*);

DissasmCodeInternalType* SearchBottomWithFnUpCollapsibleZoneRecursive(
      DissasmCodeInternalType& parent, uint32 line, ValidChildCallback isValidChild, void* context = nullptr)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            auto child = SearchBottomWithFnUpCollapsibleZoneRecursive(zone, line, isValidChild, context);
            if (child && isValidChild(child, context))
                return child;
            if (isValidChild(&zone, context))
                return &zone;
            return nullptr;
        }
    }

    return nullptr;
}

DissasmCodeInternalType* SearchBottomWithFnUpCollapsibleZone(
      DissasmCodeInternalType& parent, uint32 line, ValidChildCallback isValidChild, void* context = nullptr)
{
    if (parent.internalTypes.empty()) {
        if (isValidChild(&parent, context))
            return &parent;
        return nullptr;
    }
    return SearchBottomWithFnUpCollapsibleZoneRecursive(parent, line, isValidChild, context);
}

DissasmCodeInternalType* GetRecursiveCollpasedZoneByLineRecursive(DissasmCodeInternalType& parent, uint32 line)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            auto child = GetRecursiveCollpasedZoneByLineRecursive(zone, line);
            if (child)
                return child;
            return &zone;
        }
    }

    return nullptr;
}

DissasmCodeInternalType* GView::View::DissasmViewer::GetRecursiveCollpasedZoneByLine(DissasmCodeInternalType& parent, uint32 line)
{
    if (parent.internalTypes.empty())
        return &parent;
    return GetRecursiveCollpasedZoneByLineRecursive(parent, line);
}

bool GView::View::DissasmViewer::DissasmCodeZone::TryRenameLine(uint32 line)
{
    // TODO: improve, add searching function to search inside types for the current annotation
    auto& annotations = dissasmType.annotations;
    auto it           = annotations.find(line);
    if (it != annotations.end()) {
        SingleLineEditWindow dlg(it->second.first, "Edit label");
        if (dlg.Show() == Dialogs::Result::Ok) {
            const auto res = dlg.GetResult();
            if (!res.empty())
                it->second.first = res;
        }
        return true;
    }

    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->isCollapsed; };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (collapsedZone) {
        SingleLineEditWindow dlg(collapsedZone->name, "Edit collapsed zone label");
        if (dlg.Show() == Dialogs::Result::Ok) {
            const auto res = dlg.GetResult();
            if (!res.empty())
                collapsedZone->name = res;
        }
        return true;
    }

    return false;
}

bool DissasmCodeZone::GetComment(uint32 line, std::string& comment)
{
    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->commentsData.HasComment(*((uint32*) ctx)); };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (collapsedZone) {
        if (!collapsedZone->commentsData.GetComment(line, comment)) {
            Dialogs::MessageBox::ShowError("Error processing comments", "Invalid behaviour");
            return false;
        }
        return true;
    }

    return false;
}

bool DissasmCodeZone::AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr)
{
    const auto collapsedZone = GetRecursiveCollpasedZoneByLine(dissasmType, line);

    if (!collapsedZone) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Failed to find the required line!");
        return false;
    }

    collapsedZone->commentsData.AddOrUpdateComment(line, comment);
    return true;
}

bool DissasmCodeZone::RemoveComment(uint32 line, bool showErr)
{
    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->commentsData.HasComment(*((uint32*) ctx)); };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (!collapsedZone) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Could not find the comment!");
        return false;
    }

    collapsedZone->commentsData.RemoveComment(line);
    return true;
}

DissasmAsmPreCacheLine DissasmCodeZone::GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params)
{
    ReachZoneLine(currentLine);

    const DissasmCodeInternalType& currentType = types.back();

    DissasmAsmPreCacheLine asmCacheLine{};
    asmCacheLine.parent = &currentType;
    if (changedLevel && newLevelChangeData.hasName) {
        asmCacheLine.shouldAddButton = true;
        asmCacheLine.isZoneCollapsed = newLevelChangeData.isCollapsed;
    }

    if (currentType.isCollapsed) {
        assert(!currentType.name.empty());
    }

    if (asmCacheLine.TryGetDataFromAnnotations(currentType, currentLine)) {
        return asmCacheLine;
    }

    const uint32 value = currentType.GetCurrentAsmLine();
    assert(value != 0);

    uint32 asmLine = value - 1u;

    DissasmInsnExtractLineParams* paramsPtr = params;
    DissasmInsnExtractLineParams newParams{};
    if (paramsPtr == nullptr) {
        paramsPtr = &newParams;
    }
    paramsPtr->asmLine     = asmLine;
    paramsPtr->obj         = obj;
    paramsPtr->actualLine  = currentLine;
    paramsPtr->zone        = this;
    paramsPtr->isCollapsed = currentType.isCollapsed;
    paramsPtr->zoneName    = &currentType.name;

    const auto isValidData = asmCacheLine.TryGetDataFromInsn(*paramsPtr);
    assert(isValidData);
    lastDrawnLine = asmLine;

    // uint32 difflines = 0;
    // auto insn        = GetCurrentInstructionByLine(value - 1, this, obj, difflines);

    // assert(asmCacheLine.TryGetDataFromInsn(insn, currentLine));
    // cs_free(insn, 1);
    return asmCacheLine;
}

#pragma region CollapsibleZoneOperations

bool GetRecursiveZoneByLine(DissasmCodeInternalType& parent, uint32 line, DissasmCodeZone::CollapseExpandType collapse, int32& difference)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            if (GetRecursiveZoneByLine(zone, line, collapse, difference)) {
                zone.indexZoneEnd += difference;
                continue;
            }

            if (!zone.internalTypes.empty() || zone.name.empty())
                return false;

            if (collapse == DissasmCodeZone::CollapseExpandType::Collapse && zone.isCollapsed ||
                collapse == DissasmCodeZone::CollapseExpandType::Expand && !zone.isCollapsed)
                return false;

            if (collapse == DissasmCodeZone::CollapseExpandType::NegateCurrentState)
                collapse = zone.isCollapsed ? DissasmCodeZone::CollapseExpandType::Expand : DissasmCodeZone::CollapseExpandType::Collapse;

            difference = static_cast<int32>(zone.workingIndexZoneEnd - zone.workingIndexZoneStart - 1);
            if (collapse == DissasmCodeZone::CollapseExpandType::Collapse)
                difference = -difference;
            zone.isCollapsed = collapse == DissasmCodeZone::CollapseExpandType::Collapse;
            zone.indexZoneEnd += difference;
            continue;
        }
        if (difference && line < zone.indexZoneStart) {
            zone.indexZoneStart += difference;
            zone.indexZoneEnd += difference;

            AnnotationContainer zoneAnnotations = std::move(zone.annotations);
            zone.annotations                    = {};
            for (auto& annotation : zoneAnnotations) {
                zone.annotations.insert({ annotation.first + difference, std::move(annotation.second) });
            }

            DissasmComments odlComments = std::move(zone.commentsData);
            zone.commentsData           = {};
            for (auto& comment : odlComments.comments) {
                zone.commentsData.comments.insert({ comment.first + difference, std::move(comment.second) });
            }
        }
    }
    return difference != 0;
}

bool DissasmCodeZone::CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference)
{
    difference = 0;
    if (!GetRecursiveZoneByLine(dissasmType, zoneLine, collapse, difference))
        return false;

    if (difference) {
        difference += (int32) this->dissasmType.indexZoneEnd - 1;
    }

    return true;
}

bool DissasmCodeZone::RemoveCollapsibleZone(uint32 zoneLine)
{
    const auto zoneDetailsData = dissasmType.GetRemoveZoneCollapsibleDetails(zoneLine);
    if (!zoneDetailsData.zone)
        return false;
    if (!dissasmType.RemoveCollapsibleZone(zoneLine, zoneDetailsData))
        return false;
    ResetTypesReferenceList();
    return true;
}

void DissasmCodeZone::ResetZoneCaching()
{
    asmPreCacheData.Clear();
    for (auto& type : types) {
        type.get().asmLinesPassed  = 0;
        type.get().textLinesPassed = 0;
    }
}

bool DissasmCodeZone::AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd)
{
    if (!this->CanAddNewZone(zoneLineStart, zoneLineEnd)) {
        return false;
    }

    if (!dissasmType.AddNewZone(zoneLineStart, zoneLineEnd))
        return false;
    ResetTypesReferenceList();
    return true;
}

bool DissasmCodeInternalType::CanAddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd) const
{
    // TODO: add similar optimization like GetRemoveZoneCollapsibleDetails to end when too big interval is given
    for (const auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLineStart && zoneLineStart < zone.indexZoneEnd) {
            if (zone.indexZoneStart <= zoneLineStart && zoneLineEnd <= zone.indexZoneEnd) {
                if (!zone.name.empty() && zone.indexZoneStart == zoneLineStart && zone.indexZoneEnd == zoneLineEnd)
                    return false;
                return zone.CanAddNewZone(zoneLineStart, zoneLineEnd);
            }
            return false;
        }
    }
    return true;
}

bool DissasmCodeInternalType::AddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd)
{
    Reference<DissasmCodeInternalType> parentZone     = this;
    uint32 indexFound                                 = 0;
    bool doNotDeleteOldZone                           = internalTypes.empty();
    bool hasParent                                    = false;
    std::vector<DissasmCodeInternalType>* zonesHolder = &internalTypes;
    for (auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLineStart && zoneLineEnd <= zone.indexZoneEnd) {
            if (zone.name.empty() && zone.indexZoneStart == zoneLineStart && zone.indexZoneEnd == zoneLineEnd) {
                LocalString<128> zoneName;
                zoneName.SetFormat("Zone-IndexStart %u -IndexEnd %u", zoneLineStart, zoneLineEnd);
                zone.name = zoneName.GetText();
                return true;
            }
            parentZone = &zone;
            if (!zone.name.empty()) {
                zonesHolder        = &zone.internalTypes;
                indexFound         = 0;
                doNotDeleteOldZone = true;
                hasParent          = true;
            }
            break;
        }
        indexFound++;
    }

    LocalString<128> zoneName;
    zoneName.SetFormat("Zone-IndexStart %u -IndexEnd %u", zoneLineStart, zoneLineEnd);

    DissasmCodeInternalType newZone = {};
    newZone.name                    = zoneName.GetText();
    newZone.indexZoneStart          = zoneLineStart;
    newZone.workingIndexZoneStart   = newZone.indexZoneStart;
    newZone.indexZoneEnd            = zoneLineEnd;
    newZone.workingIndexZoneEnd     = newZone.indexZoneEnd;

    // TODO: improve annotations moving
    decltype(annotations) annotationsBefore, annotationCurrent, annotationAfter;
    for (const auto& zoneVal : parentZone->annotations) {
        if (zoneVal.first < zoneLineStart)
            annotationsBefore.insert(zoneVal);
        else if (zoneVal.first >= zoneLineStart && zoneVal.first < zoneLineEnd)
            annotationCurrent.insert(zoneVal);
        else if (zoneVal.first >= zoneLineEnd)
            annotationAfter.insert(zoneVal);
    }

    // TODO: improve annotations moving
    uint32 commentsZoneLineStart = zoneLineStart - 1;
    if (zoneLineStart == 0)
        commentsZoneLineStart = 0;
    uint32 commentsZoneLineEnd = zoneLineEnd - 1;
    decltype(commentsData.comments) commentsBefore, commentsCurrent, commentsAfter;
    for (const auto& commentsVal : parentZone->commentsData.comments) {
        if (commentsVal.first < commentsZoneLineStart)
            commentsBefore.insert(commentsVal);
        else if (commentsVal.first >= commentsZoneLineStart && commentsVal.first < commentsZoneLineEnd)
            commentsCurrent.insert(commentsVal);
        else if (commentsVal.first >= commentsZoneLineEnd)
            commentsAfter.insert(commentsVal);
    }

    newZone.annotations           = std::move(annotationCurrent);
    newZone.commentsData.comments = std::move(commentsCurrent);

    DissasmCodeInternalType firstZone = {};
    firstZone.indexZoneStart          = std::min(parentZone->indexZoneStart, zoneLineStart);
    firstZone.workingIndexZoneStart   = firstZone.indexZoneStart;
    firstZone.annotations             = std::move(annotationsBefore);
    firstZone.commentsData.comments   = std::move(commentsBefore);

    DissasmCodeInternalType lastZone = {};

    if (indexFound > 0) {
        const auto& prevZone = internalTypes[indexFound - 1];
        firstZone.UpdateDataLineFromPrevious(prevZone);
    }
    if (hasParent) {
        firstZone.beforeAsmLines  = parentZone->beforeAsmLines;
        firstZone.beforeTextLines = parentZone->beforeTextLines;
    }

    if (zoneLineStart == parentZone->indexZoneStart) { // first line
        firstZone.name                = newZone.name;
        firstZone.indexZoneEnd        = zoneLineEnd;
        firstZone.workingIndexZoneEnd = firstZone.indexZoneEnd;
        firstZone.annotations.insert(newZone.annotations.begin(), newZone.annotations.end());
        firstZone.commentsData.comments.insert(newZone.commentsData.comments.begin(), newZone.commentsData.comments.end());
        // newZone.UpdateDataLineFromPrevious(firstZone);
        lastZone.UpdateDataLineFromPrevious(firstZone);
        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(firstZone));
    } else {
        firstZone.indexZoneEnd        = zoneLineStart;
        firstZone.workingIndexZoneEnd = firstZone.indexZoneEnd;

        newZone.UpdateDataLineFromPrevious(firstZone);
        lastZone.UpdateDataLineFromPrevious(newZone);

        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(firstZone));
        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(newZone));
    }

    lastZone.annotations           = std::move(annotationAfter);
    lastZone.commentsData.comments = std::move(commentsAfter);
    lastZone.indexZoneEnd          = indexZoneEnd;
    lastZone.workingIndexZoneEnd   = lastZone.indexZoneEnd;
    if (zoneLineEnd == indexZoneEnd) {
        lastZone.indexZoneStart        = zoneLineStart;
        lastZone.workingIndexZoneStart = lastZone.indexZoneStart;
    } else {
        lastZone.indexZoneStart        = zoneLineEnd;
        lastZone.workingIndexZoneStart = lastZone.indexZoneStart;
        lastZone.indexZoneEnd          = indexZoneEnd;
        lastZone.workingIndexZoneEnd   = lastZone.indexZoneEnd;

        if (indexFound + 1 < internalTypes.size()) {
            auto& nextZone               = internalTypes[indexFound + 1];
            lastZone.indexZoneEnd        = nextZone.indexZoneStart;
            lastZone.workingIndexZoneEnd = lastZone.indexZoneEnd;
        }
    }

    zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(lastZone));

    if (indexFound < internalTypes.size() && !doNotDeleteOldZone) {
        internalTypes.erase(internalTypes.begin() + indexFound);
    }
    return true;
}

DissasmCodeRemovableZoneDetails DissasmCodeInternalType::GetRemoveZoneCollapsibleDetails(uint32 zoneLine, uint32 depthLevel)
{
    if (internalTypes.empty())
        return {};
    if (zoneLine > internalTypes.back().indexZoneEnd)
        return {};
    uint32 zoneIndex = 0;
    for (auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLine && zoneLine < zone.indexZoneEnd) {
            if (!zone.name.empty() && !zone.isCollapsed) {
                return { &zone, depthLevel == 0 ? this : nullptr, zoneIndex };
            }
            const auto result = zone.GetRemoveZoneCollapsibleDetails(zoneLine, depthLevel + 1);
            if (!result.zone)
                return {};
            if (result.parent)
                return result;
            return { result.zone, &zone, result.zoneIndex };
        }
        zoneIndex++;
    }
    return {};
}

bool DissasmCodeInternalType::RemoveCollapsibleZone(uint32 zoneLine, const DissasmCodeRemovableZoneDetails& removableDetails)
{
    auto& parentInternalTypes = removableDetails.parent->internalTypes;
    if (parentInternalTypes.size() == 2) { // last two zone, we clear them
        for (const auto& zone : parentInternalTypes) {
            if (zone.isCollapsed)
                return false; // TODO: remove special case for the last two zones when one of them is collapsed
        }
        parentInternalTypes.clear();
        return true;
    }

    // special case: when we have 3 zones and only the middle one is collpasible
    // after we remove it, we need to merge the first and the last one since they are not collapsible
    // so having only 3 zones => we can remove all since we never have only one zone
    if (parentInternalTypes.size() == 3 && removableDetails.zoneIndex == 1) {
        for (const auto& zone : parentInternalTypes) {
            if (zone.isCollapsed)
                return false; // TODO: remove special case when we have 3 zones and only the middle one is collapsible and some of them are collapsed
        }
        if (parentInternalTypes[0].name.empty() && parentInternalTypes[2].name.empty()) {
            parentInternalTypes.clear();
            return true;
        }
    }

    // TODO: optimize this
    std::vector<uint32> indexesToRemove;
    indexesToRemove.reserve(2);

    DissasmCodeInternalType* zoneToUpdate = removableDetails.zone;
    if (removableDetails.zoneIndex > 0)
        zoneToUpdate = &parentInternalTypes[removableDetails.zoneIndex - 1];

    if (removableDetails.zoneIndex < static_cast<uint32>(parentInternalTypes.size()) - 1) {
        const auto& nextZone = parentInternalTypes[removableDetails.zoneIndex + 1];
        if (nextZone.name.empty()) {
            {
                indexesToRemove.push_back(removableDetails.zoneIndex + 1);
                zoneToUpdate->indexZoneEnd        = nextZone.indexZoneEnd;
                zoneToUpdate->workingIndexZoneEnd = nextZone.workingIndexZoneEnd;
                zoneToUpdate->annotations.insert(nextZone.annotations.begin(), nextZone.annotations.end());
            }
        }
    }
    if (removableDetails.zoneIndex > 0) {
        const auto& prevZone = parentInternalTypes[removableDetails.zoneIndex - 1];
        if (prevZone.name.empty()) {
            {
                indexesToRemove.push_back(removableDetails.zoneIndex);
                zoneToUpdate->indexZoneStart        = prevZone.indexZoneStart;
                zoneToUpdate->workingIndexZoneStart = prevZone.workingIndexZoneStart;
                zoneToUpdate->annotations.insert(prevZone.annotations.begin(), prevZone.annotations.end());
            }
        }
    }
    for (const auto index : indexesToRemove) {
        parentInternalTypes.erase(parentInternalTypes.begin() + index);
    }

    zoneToUpdate->name.clear();

    return true;
}

#pragma endregion