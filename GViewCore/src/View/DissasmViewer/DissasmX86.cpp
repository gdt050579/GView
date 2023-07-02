#include "DissasmViewer.hpp"
#include <capstone/capstone.h>
#include <cassert>
#include <ranges>
#include <utility>
#include <list>
#include <array>
#include <cmath>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

constexpr size_t DISSASM_INSTRUCTION_OFFSET_MARGIN = 500;
constexpr uint32 callOP                            = 1819042147u; //*(uint32*) "call";
constexpr uint32 addOP                             = 6579297u;    //*((uint32*) "add");
constexpr uint32 pushOP                            = 1752397168u; //*((uint32*) "push");

const uint8 HEX_MAPPER[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };

// Dissasm menu configuration
constexpr uint32 addressTotalLength     = 16;
constexpr uint32 opCodesGroupsShown     = 8;
constexpr uint32 opCodesTotalLength     = opCodesGroupsShown * 3 + 1;
constexpr uint32 textColumnTextLength   = opCodesGroupsShown;
constexpr uint32 textColumnSpacesLength = 4;
constexpr uint32 textColumnTotalLength  = textColumnTextLength + textColumnSpacesLength;
constexpr uint32 textTotalColumnLength  = addressTotalLength + textColumnTextLength + opCodesTotalLength + textColumnTotalLength;
constexpr uint32 commentPaddingLength   = 10;

// TODO consider inline?
AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<AsmOffsetLine>& values, uint64 searchedLine, uint32* index = nullptr)
{
    assert(!values.empty());
    uint32 left  = 0;
    uint32 right = static_cast<uint32>(values.size()) - 1u;
    while (left < right)
    {
        const uint32 mid = (left + right) / 2;
        if (searchedLine == values[mid].line)
        {
            if (index)
                *index = mid;
            return values[mid];
        }
        if (searchedLine < values[mid].line)
            right = mid - 1;
        else
            left = mid + 1;
    }
    if (left > 0 && values[left].line > searchedLine)
    {
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
    while (left < right)
    {
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
inline ColorPair GetASMColorPairByKeyword(std::string_view keyword, Config& cfg, const AsmData& data)
{
    if (keyword.empty())
        return cfg.Colors.AsmDefaultColor;
    if (keyword[0] == 'j')
        return cfg.Colors.AsmJumpInstruction;

    LocalString<4> holder;
    holder.Set(keyword);
    const uint32 val = *reinterpret_cast<const uint32*>(holder.GetText());

    const auto it = data.instructionToColor.find(val);
    if (it != data.instructionToColor.end())
    {
        return it->second;
    }

    if (keyword.size() < 4)
    {
        // General registers: EAX EBX ECX EDX -> AsmWorkRegisterColor
        // 16 bits: AX BX CX DX -> AsmWorkRegisterColor
        // 8 bits: AH AL BH BL CH CL DH DL -> AsmWorkRegisterColor
        // Segment registers: CS DS ES FS GS SS -> AsmWorkRegisterColor
        // Index and pointers: ESI EDI EBP EIP ESP along with variations (ESI, SI) AsmStackRegisterColor
        switch (keyword[keyword.size() - 1])
        {
        case 'x':
        case 's':
        case 'l':
        case 'h':
            return cfg.Colors.AsmWorkRegisterColor;
        case 'p':
        case 'i':
            return cfg.Colors.AsmStackRegisterColor;
        default:
            break;
        }
    }

    return cfg.Colors.AsmDefaultColor;
}

// TODO: to be moved inside plugin for some sort of API for token<->color
inline void DissasmAddColorsToInstruction(
      DissasmAsmPreCacheLine& insn,
      CharacterBuffer& cb,
      Config& cfg,
      const LayoutDissasm& layout,
      AsmData& data,
      const CodePage& codePage,
      uint64 addressPadding = 0)
{
    const MemoryMappingEntry* mappingPtr = (const MemoryMappingEntry*) insn.mapping;
    // cb.Clear();

    LocalString<128> string;
    string.SetFormat("0x%08" PRIx64 "     ", insn.address + addressPadding);
    cb.Add(string, cfg.Colors.AsmOffsetColor);
    cb.InsertChar('|', cb.Len(), cfg.Colors.AsmTitleColumnColor);

    for (uint32 i = 0; i < opCodesGroupsShown; i++)
    {
        if (i >= insn.size)
        {
            string.Clear();
            const uint32 remaining = opCodesGroupsShown - i;
            // const uint32 spaces    = remaining >= 2 ? remaining - 2 : 0;
            string.SetChars(' ', remaining * 3);
            cb.Add(string, cfg.Colors.AsmDefaultColor);
            break;
        }
        const uint8 byte = insn.bytes[i];
        string.SetFormat("%02x ", byte);
        cb.Add(string, cfg.Colors.AsmDefaultColor);
    }

    cb.InsertChar('|', cb.Len(), cfg.Colors.AsmTitleColumnColor);

    for (uint32 i = 0; i < textColumnTextLength; i++)
    {
        if (i >= insn.size)
        {
            string.Clear();
            const uint32 remaining = textColumnTextLength - i - 1;
            string.SetChars(' ', remaining);
            cb.Add(string, cfg.Colors.AsmDefaultColor);
            break;
        }
        const uint8 byte = insn.bytes[i];
        cb.InsertChar(codePage[byte], cb.Len(), cfg.Colors.AsmDefaultColor);
    }

    string.Clear();
    string.SetChars(' ', textColumnSpacesLength);
    cb.Add(string, cfg.Colors.AsmDefaultColor);

    cb.InsertChar('|', cb.Len(), cfg.Colors.AsmTitleColumnColor);

    string.SetFormat("%-6s", insn.mnemonic);
    const ColorPair color = GetASMColorPairByKeyword(insn.mnemonic, cfg, data);
    cb.Add(string, color);

    if (insn.op_str)
    {
        const std::string_view op_str = insn.op_str;
        // TODO: add checks to verify  lambdaBuffer.Set, for x86 it's possible to be fine but not for other languages
        LocalString<32> lambdaBuffer;
        auto checkValidAndAdd = [&cb, &cfg, &lambdaBuffer, &data](std::string_view token)
        {
            lambdaBuffer.Clear();
            if (token.length() > 2 && token[0] == '0' && token[1] == 'x')
            {
                cb.Add(token.data(), cfg.Colors.AsmOffsetColor);
                return;
            }
            lambdaBuffer.Set(token.data());
            const ColorPair color = GetASMColorPairByKeyword(token, cfg, data);
            cb.Add(token, color);
        };

        if (op_str.length() > 2 && op_str[0] == '0' && op_str[1] == 'x')
        {
            cb.Add(" ");
            checkValidAndAdd(op_str);
            return;
        }

        char lastOp = ' ';
        LocalString<32> buffer;
        for (const char c : op_str)
        {
            if (c == ' ' || c == ',' || c == '[' || c == ']')
            {
                if (buffer.Len() > 0)
                {
                    if (lastOp != '[')
                        cb.Add(" ");
                    checkValidAndAdd(buffer.GetText());
                    buffer.Clear();
                }
                if (c != ' ')
                {
                    const char tmp[3] = { ' ', c, '\0' };
                    const char* start = (c == '[') ? tmp : tmp + 1;
                    cb.Add(start, cfg.Colors.AsmCompareInstructionColor);
                }
                lastOp = c;
                continue;
            }
            buffer.AddChar(c);
        }
        if (buffer.Len() > 0)
        {
            cb.Add(" ");
            checkValidAndAdd(buffer.GetText());
        }
    }
    else
    {
        if (mappingPtr)
        {
            string.SetFormat("%s", mappingPtr->name.data());
            const ColorPair mapColor = mappingPtr->type == MemoryMappingType::TextMapping ? cfg.Colors.AsmLocationInstruction : cfg.Colors.AsmFunctionColor;
            cb.Add(string, mapColor);
        }
        assert(mappingPtr);
    }

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
}

// TODO: maybe add also minimum number?
bool CheckExtractInsnHexValue(cs_insn& insn, uint64& value, uint64 maxSize)
{
    char* ptr   = insn.op_str;
    char* start = nullptr;
    uint32 size = 0;

    if (ptr[0] == '0' && ptr[1] == '\0')
    {
        value = 0;
        return true;
    }

    while (ptr && *ptr != '\0')
    {
        if (!start)
        {
            if (ptr && *ptr == '0')
            {
                ptr++;
                if (!ptr || *ptr != 'x')
                    return false;
                ptr++;
                start = ptr;
                continue;
            }
        }
        else
        {
            if (*ptr >= '0' && *ptr <= '9' || *ptr >= 'a' && *ptr <= 'f')
            {
                size++;
            }
            else
            {
                if (size < maxSize - 2)
                    return false;
                break;
            }
        }
        ptr++;
    }

    if (maxSize < size)
    {
        const uint32 diff = size - static_cast<uint32>(maxSize);
        size -= diff;
        start += diff;
    }

    if (!start || !ptr || size < 2)
        return false;

    const auto sv        = std::string_view(start, size);
    const auto converted = Number::ToUInt64(sv, NumberParseFlags::Base16);
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
    if (resCode != CS_ERR_OK)
    {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj.GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);

    size_t minimalValue = offsets[0].offset;

    cs_insn* insn     = cs_malloc(handle);
    size_t lastOffset = offsets[0].offset;

    constexpr uint32 addInstructionsStop = 30; // TODO: update this -> for now it stops, later will fold

    std::list<uint64> finalOffsets;

    size_t size       = zoneDetails.startingZonePoint + zoneDetails.size;
    uint64 address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    uint64 endAddress = zoneDetails.size;

    if (address >= endAddress)
    {
        cs_close(&handle);
        return false;
    }

    auto data = instructionData.GetData() + address;

    // std::string saved1 = "s1", saved2 = "s2";
    uint64 startingOffset = offsets[0].offset;

    size_t lastSize = size;
    // std::vector<uint64> tempStorage;
    // tempStorage.push_back(lastOffset);

    do
    {
        if (size > lastSize)
        {
            lastSize = size;
            // tempStorage.reserve(size / DISSASM_INSTRUCTION_OFFSET_MARGIN + 1);
        }

        while (address < endAddress)
        {
            if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                break;

            if ((insn->mnemonic[0] == 'j' || *(uint32*) insn->mnemonic == callOP) && insn->op_str[0] == '0' /* && insn->op_str[1] == 'x'*/)
            {
                uint64 computedValue = 0;
                if (insn->op_str[1] == 'x')
                {
                    // uint64 computedValue = 0;
                    char* ptr = &insn->op_str[2];
                    // TODO: also check not to overflow access!
                    while (*ptr && *ptr != ' ' && *ptr != ',')
                    {
                        computedValue = computedValue * 16 + HEX_MAPPER[*ptr];
                        ptr++;
                    }
                }
                else if (insn->op_str[1] == '\0')
                {
                    computedValue = zoneDetails.startingZonePoint;
                }

                if (computedValue < minimalValue && computedValue >= zoneDetails.startingZonePoint)
                {
                    minimalValue = computedValue;
                    // saved1       = insn->mnemonic;
                    // saved2       = insn->op_str;
                }
            }
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            if (adjustedSize - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN)
            {
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

    while (cs_disasm_iter(handle, &data, &size, &address, insn))
    {
        lineIndex++;
        if (address - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN)
        {
            lastOffset                = address;
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            offsets.push_back({ adjustedSize, lineIndex });
        }

        if (*(uint32*) insn->mnemonic == addOP && insn->op_str[0] == 'b' && *(uint32*) &insn->op_str[15] == alOpStr)
        {
            if (++continuousAddInstructions == addInstructionsStop)
            {
                lineIndex -= continuousAddInstructions;
                break;
            }
        }
        else
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
    if (lineToReach < zone->lastDrawnLine || lineToReach - zone->lastDrawnLine > 1 || lineToReach >= zone->offsetCacheMaxLine)
    {
        // TODO: can be inlined as function
        uint32 codeOffsetIndex = 0;
        const auto closestData = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, lineToReach, &codeOffsetIndex);
        zone->lastClosestLine  = closestData.line;
        zone->asmAddress       = closestData.offset - zone->cachedCodeOffsets[0].offset;
        zone->asmSize          = zone->zoneDetails.size - zone->asmAddress;
        if (static_cast<size_t>(codeOffsetIndex) + 1u < zone->cachedCodeOffsets.size())
            zone->offsetCacheMaxLine = zone->cachedCodeOffsets[static_cast<size_t>(codeOffsetIndex) + 1u].line;
        else
            zone->offsetCacheMaxLine = UINT32_MAX;

        if (closestData.line != zone->lastClosestLine)
        {
            // TODO: maybe get less data ?
            const auto instructionData = obj->GetData().Get(zone->cachedCodeOffsets[0].offset + zone->asmAddress, static_cast<uint32>(zone->asmSize), false);
            zone->lastData             = instructionData;
            if (!instructionData.IsValid())
            {
                if (dli)
                    dli->WriteErrorToScreen("ERROR: extract valid data from file!");
                diffLines = UINT32_MAX;
                return nullptr;
            }
        }
        zone->asmData = const_cast<uint8*>(zone->lastData.GetData());
        // if (lineInView > zone->lastDrawnLine)
        //     lineDifferences = lineInView - zone->lastDrawnLine + 1;
        lineDifferences = lineToReach - closestData.line;
    }

    if (diffLines == 1)
    {
        diffLines = lineDifferences;
        return nullptr;
    }

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK)
    {
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        cs_close(&handle);
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);

    while (lineDifferences > 0)
    {
        if (!cs_disasm_iter(handle, &zone->asmData, (size_t*) &zone->asmSize, &zone->asmAddress, insn))
        {
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
    if (!instructionData.IsValid())
    {
        if (dli)
            dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        diffLines = UINT32_MAX;
        return nullptr;
    }

    zone->asmData = const_cast<uint8*>(zone->lastData.GetData());

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK)
    {
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        cs_close(&handle);
        return nullptr;
    }

    diffLines     = 0;
    cs_insn* insn = cs_malloc(handle);
    if (offsetToReach >= zone->cachedCodeOffsets[0].offset)
        offsetToReach -= zone->cachedCodeOffsets[0].offset;
    while (zone->asmAddress <= offsetToReach)
    {
        if (!cs_disasm_iter(handle, &zone->asmData, (size_t*) &zone->asmSize, &zone->asmAddress, insn))
        {
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            cs_close(&handle);
            return nullptr;
        }
        diffLines++;
    }
    diffLines += closestData.line;
    cs_close(&handle);
    return insn;
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
    if (resCode != CS_ERR_OK)
    {
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
    callsFound.reserve(16);
    while (cs_disasm_iter(handle, &data, &size, &address, insn) && linesToDecode > 0)
    {
        linesToDecode--;
        if (*(uint32*) insn->mnemonic == callOP)
        {
            uint64 value;
            const bool foundValue = CheckExtractInsnHexValue(*insn, value, maxLocationMemoryMappingSize);
            if (foundValue && value < zoneDetails.startingZonePoint + zoneDetails.size)
            {
                if (value == 0)
                    value = zoneDetails.startingZonePoint;
                NumericFormatter formatter;
                auto sv = formatter.ToString(value, NumericFormatFlags::HexPrefix);
                LocalString<64> callName;
                callName.SetFormat("sub_%s", sv.data());
                callsFound.push_back({ value, callName.GetText() });
            }
        }
    }
    //callsFound.push_back({ 1030, "call2" });
    //callsFound.push_back({ 1130, "call 3" });
    //callsFound.push_back({ 1140, "call 5" });
    for (const auto& call : callsFound)
    {
        uint64 callValue = call.first;
        if (callValue == 0)
            callValue = offsets[0].offset;

        uint32 diffLines = 0;
        auto callInsn    = GetCurrentInstructionByOffset(callValue, zone, obj, diffLines);
        if (callInsn)
        {
            zone->dissasmType.annotations.insert({ diffLines, { call.second, callValue - offsets[0].offset } });
            cs_free(callInsn, 1);
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

    while (dataStart < dataEnd)
    {
        if (*dataStart >= 32 && *dataStart <= 126)
        {
            textFound.push_back(*dataStart);
            wasZero = false;
        }
        else if (*dataStart == '\0')
        {
            if (wasZero)
                break;
            wasZero = true;
        }
        else
        {
            break;
        }
        dataStart++;
    }

    if (textFound.size() >= DISSAM_MAXIMUM_STRING_PREVIEW)
    {
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

std::optional<uint32> DissasmPrepareCodeZone(DissasmCodeZone* zone, uint32 currentLine)
{
    const uint32 levelToReach = currentLine;
    uint32& levelNow          = zone->structureIndex;
    bool reAdapt              = false;
    while (true)
    {
        const DissasmCodeInternalType& currentType = zone->types.back();
        if (currentType.indexZoneStart <= levelToReach && currentType.indexZoneEnd >= levelToReach)
            break;
        zone->types.pop_back();
        zone->levels.pop_back();
        reAdapt = true;
    }

    while (reAdapt && !zone->types.back().get().internalTypes.empty())
    {
        DissasmCodeInternalType& currentType = zone->types.back();
        for (uint32 i = 0; i < currentType.internalTypes.size(); i++)
        {
            auto& internalType = currentType.internalTypes[i];
            if (internalType.indexZoneStart <= levelToReach && internalType.indexZoneEnd >= levelToReach)
            {
                zone->types.push_back(internalType);
                zone->levels.push_back(i);
                break;
            }
        }
    }

    DissasmCodeInternalType& currentType = zone->types.back();
    // TODO: do a faster search using a binary search using the annotations and start from there
    // TODO: maybe use some caching here?
    if (reAdapt || levelNow < levelToReach && levelNow + 1 != levelToReach || levelNow > levelToReach && levelNow - 1 != levelToReach)
    {
        currentType.textLinesPassed = 0;
        currentType.asmLinesPassed  = 0;
        for (uint32 i = currentType.indexZoneStart; i <= levelToReach; i++)
        {
            if (currentType.annotations.contains(i))
            {
                currentType.textLinesPassed++;
                continue;
            }
            currentType.asmLinesPassed++;
        }
    }
    else
    {
        if (currentType.annotations.contains(levelToReach))
            currentType.textLinesPassed++;
        else
            currentType.asmLinesPassed++;
    }

    const auto foundAnnotation = currentType.annotations.find(levelToReach);
    if (foundAnnotation != currentType.annotations.end())
    {
        DissasmAsmPreCacheLine asmCacheLine{};
        asmCacheLine.address = foundAnnotation->second.second;
        strncpy(asmCacheLine.mnemonic, foundAnnotation->second.first.data(), sizeof(asmCacheLine.mnemonic));
        strncpy((char*) asmCacheLine.bytes, "------", sizeof(asmCacheLine.bytes));
        asmCacheLine.size        = static_cast<uint32>(strlen((char*) asmCacheLine.bytes));
        asmCacheLine.currentLine = currentLine;
        asmCacheLine.op_str      = strdup("<--");
        asmCacheLine.op_str_size = static_cast<uint32>(strlen(asmCacheLine.op_str));
        zone->asmPreCacheData.cachedAsmLines.push_back(asmCacheLine);
        return {};
    }

    levelNow = levelToReach;

    return currentType.asmLinesPassed + currentType.beforeAsmLines;
}

bool ExtractDissasmAsmPreCacheLineFromCsInsn(
      Reference<GView::Object> obj, const Pointer<SettingsData>& settings, AsmData& asmData, DrawLineInfo& dli, DissasmCodeZone* zone, uint32 currentLine)
{
    uint32 diffLines = 0;
    cs_insn* insn    = GetCurrentInstructionByLine(currentLine, zone, obj, diffLines, &dli);
    if (!insn)
        return false;

    DissasmAsmPreCacheLine asmCacheLine{};
    asmCacheLine.address = insn->address;
    memcpy(asmCacheLine.bytes, insn->bytes, std::min<uint32>(sizeof(asmCacheLine.bytes), sizeof(insn->bytes)));
    asmCacheLine.size = insn->size;
    memcpy(asmCacheLine.mnemonic, insn->mnemonic, CS_MNEMONIC_SIZE);
    asmCacheLine.currentLine = currentLine;

    switch (*((uint32*) insn->mnemonic))
    {
    case pushOP:
        asmCacheLine.flags = DissasmAsmPreCacheData::InstructionFlag::PushFlag;
        break;
    case callOP:
        asmCacheLine.flags = DissasmAsmPreCacheData::InstructionFlag::CallFlag;
        break;
    default:
        if (insn->mnemonic[0] == 'j')
        {
            asmCacheLine.flags = DissasmAsmPreCacheData::InstructionFlag::JmpFlag;
        }
        else
        {
            asmCacheLine.op_str      = strdup(insn->op_str);
            asmCacheLine.op_str_size = static_cast<uint32>(strlen(asmCacheLine.op_str));
            zone->asmPreCacheData.cachedAsmLines.push_back(asmCacheLine);
            cs_free(insn, 1);
            return true;
        }
    }

    // TODO: be more generic not only x86
    if (asmCacheLine.flags == DissasmAsmPreCacheData::InstructionFlag::CallFlag && insn->op_str[0] == '0' && insn->op_str[1] == '\0')
    {
        NumericFormatter n;
        const auto res           = n.ToString(zone->cachedCodeOffsets[0].offset, { NumericFormatFlags::HexPrefix, 16 });
        asmCacheLine.op_str      = strdup(res.data());
        asmCacheLine.op_str_size = static_cast<uint32>(strlen(asmCacheLine.op_str));
        zone->asmPreCacheData.cachedAsmLines.push_back(asmCacheLine);
        cs_free(insn, 1);
        return true;
    }

    // TODO: improve efficiency by filtering instructions
    uint64 hexVal = 0;
    if (CheckExtractInsnHexValue(*insn, hexVal, settings->maxLocationMemoryMappingSize))
        asmCacheLine.hexValue = hexVal;
    bool alreadyInitComment = false;
    if (zone->asmPreCacheData.HasAnyFlag(currentLine))
        alreadyInitComment = true;

    const uint64 finalIndex =
          zone->asmAddress + settings->offsetTranslateCallback->TranslateFromFileOffset(zone->zoneDetails.entryPoint, (uint32) DissasmPEConversionType::RVA);
    if (asmCacheLine.flags == DissasmAsmPreCacheData::InstructionFlag::CallFlag)
    {
        auto mappingPtr = TryExtractMemoryMapping(settings, hexVal, finalIndex);
        if (mappingPtr)
        {
            asmCacheLine.mapping     = mappingPtr;
            asmCacheLine.op_str_size = (uint32) mappingPtr->name.size();
            if (mappingPtr->type == MemoryMappingType::FunctionMapping && !alreadyInitComment)
            {
                // TODO: add functions to the obj AsmData to search for name instead of manually doing CRC
                GView::Hashes::CRC32 crc32{};
                uint32 hash    = 0;
                const bool res = crc32.Init(GView::Hashes::CRC32Type::JAMCRC) &&
                                 crc32.Update((const uint8*) mappingPtr->name.data(), mappingPtr->name.size()) && crc32.Final(hash);
                if (res)
                {
                    const auto it = asmData.functions.find(hash);
                    if (it != asmData.functions.end())
                    {
                        zone->asmPreCacheData.AnnounceCallInstruction(zone, it->second);
                        zone->asmPreCacheData.AddInstructionFlag(currentLine, DissasmAsmPreCacheData::CallFlag);
                    }
                }
            }
        }
    }
    else if (asmCacheLine.flags == DissasmAsmPreCacheData::InstructionFlag::PushFlag)
    {
        if (!alreadyInitComment && !zone->comments.contains(currentLine))
        {
            const auto offset = settings->offsetTranslateCallback->TranslateToFileOffset(hexVal, (uint32) DissasmPEConversionType::RVA);
            if (offset != static_cast<uint64>(-1) && offset + DISSAM_MAXIMUM_STRING_PREVIEW < obj->GetData().GetSize())
            {
                const auto textFoundOption = TryExtractPushText(obj, offset);
                if (textFoundOption.has_value())
                {
                    const auto& textFound = textFoundOption.value();
                    if (textFound.size() > 3)
                    {
                        // TODO: add functions zone->comments to adjust comments instead of manually doing it
                        zone->comments.insert({ currentLine, (const char*) textFound.data() });
                        zone->asmPreCacheData.AddInstructionFlag(currentLine, DissasmAsmPreCacheData::PushFlag);
                    }
                }
            }
        }
    }

    if (!asmCacheLine.op_str && !asmCacheLine.mapping)
    {
        asmCacheLine.op_str      = strdup(insn->op_str);
        asmCacheLine.op_str_size = (uint32) strlen(asmCacheLine.op_str);
    }
    zone->asmPreCacheData.cachedAsmLines.push_back(asmCacheLine);
    cs_free(insn, 1);
    return true;
}

bool populateAsmPreCacheData(
      Config& config,
      Reference<GView::Object> obj,
      const Pointer<SettingsData>& settings,
      AsmData& asmData,
      DrawLineInfo& dli,
      DissasmCodeZone* zone,
      uint32 startingLine,
      uint32 linesToPrepare)
{
    uint32 currentLine      = startingLine;
    const uint32 endingLine = currentLine + linesToPrepare;
    while (currentLine < endingLine)
    {
        auto adjustedLine = DissasmPrepareCodeZone(zone, currentLine);
        if (adjustedLine.has_value())
        {
            if (!ExtractDissasmAsmPreCacheLineFromCsInsn(obj, settings, asmData, dli, zone, adjustedLine.value()))
            {
                dli.WriteErrorToScreen("ERROR: failed to extract asm ExtractDissasmAsmPreCacheLineFromCsInsn line!");
                return false;
            }
        }
        currentLine++;
    }
    zone->asmPreCacheData.ComputeMaxLine();
    return true;
}

bool Instance::InitDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    // TODO: move this on init
    if (!cs_support(CS_ARCH_X86))
    {
        dli.WriteErrorToScreen("Capstone does not support X86");
        AdjustZoneExtendedSize(zone, 1);
        return false;
    }

    switch (zone->zoneDetails.language)
    {
    case DisassemblyLanguage::x86:
        zone->internalArchitecture = CS_MODE_32;
        break;
    case DisassemblyLanguage::x64:
        zone->internalArchitecture = CS_MODE_64;
        break;
    default:
    {
        dli.WriteErrorToScreen("ERROR: unsupported language!");
        return false;
    }
    }

    uint32 totalLines = 0;
    if (!populateOffsetsVector(zone->cachedCodeOffsets, zone->zoneDetails, obj, zone->internalArchitecture, totalLines))
    {
        dli.WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    //if (!ExtractCallsToInsertFunctionNames(zone->cachedCodeOffsets, zone, obj, zone->internalArchitecture, totalLines, settings->maxLocationMemoryMappingSize))
    //{
    //    dli.WriteErrorToScreen("ERROR: failed to populate offsets vector!");
    //    return false;
    //}
    totalLines++; //+1 for title
    AdjustZoneExtendedSize(zone, totalLines);
    zone->lastDrawnLine    = 0;
    const auto closestData = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, zone->lastDrawnLine);
    zone->lastClosestLine  = closestData.line;
    zone->isInit           = true;

    zone->asmAddress = 0;
    zone->asmSize    = zone->zoneDetails.size - zone->asmAddress;

    const auto instructionData = obj->GetData().Get(zone->cachedCodeOffsets[0].offset + zone->asmAddress, static_cast<uint32>(zone->asmSize), false);
    zone->lastData             = instructionData;
    if (!instructionData.IsValid())
    {
        dli.WriteErrorToScreen("ERROR: extract valid data from file!");
        return false;
    }
    zone->asmData = const_cast<uint8*>(instructionData.GetData());

    const uint32 preReverseSize = std::min<uint32>(Layout.visibleRows, zone->extendedSize);
    zone->asmPreCacheData.cachedAsmLines.reserve(preReverseSize);

    zone->structureIndex = 1;
    zone->types.push_back(zone->dissasmType);
    zone->levels.push_back(0);

    zone->dissasmType.indexZoneStart = 1; //+1 for the title
    zone->dissasmType.indexZoneEnd   = totalLines + 1;
    // zone->dissasmType.annotations.insert({ 2, "loc fn" });

    return true;
}

bool Instance::DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0)
    {
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

    if (dli.textLineToDraw == 0)
    {
        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), config.Colors.StructureColor);

        // TODO: maybe extract this as methods?
        HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(zoneName.size()), static_cast<uint32>(zoneName.size()) + Layout.startingTextLineOffset);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);

        if (!zone->isInit)
        {
            if (!InitDissasmZone(dli, zone))
                return false;
        }

        return true;
    }

    const bool firstLineToDraw = dli.screenLineToDraw == 0;
    if (dli.textLineToDraw == 1 || firstLineToDraw)
    {
        const ColorPair titleColumnColor = { config.Colors.AsmTitleColumnColor.Foreground, config.Colors.AsmTitleColor.Background };

        constexpr std::string_view address = "File address";
        chars.Add(address.data(), config.Colors.AsmTitleColor);

        spaces.Clear();
        spaces.SetChars(' ', addressTotalLength - static_cast<uint32>(address.size()) - 1u);
        chars.Add(spaces, config.Colors.AsmTitleColor);

        chars.InsertChar('|', chars.Len(), titleColumnColor);

        constexpr std::string_view opCodes = "Op Codes";
        chars.Add(opCodes.data(), config.Colors.AsmTitleColor);
        spaces.Clear();
        spaces.SetChars(' ', opCodesTotalLength - static_cast<uint32>(opCodes.size()) - 1u);
        chars.Add(spaces, config.Colors.AsmTitleColor);

        chars.InsertChar('|', chars.Len(), titleColumnColor);

        constexpr std::string_view textTitle = "Text";
        chars.Add(textTitle.data(), config.Colors.AsmTitleColor);
        spaces.Clear();
        spaces.SetChars(' ', textColumnTotalLength - static_cast<uint32>(textTitle.size()) - 1u);
        chars.Add(spaces, config.Colors.AsmTitleColor);

        chars.InsertChar('|', chars.Len(), titleColumnColor);

        constexpr std::string_view dissasmTitle = "Dissasm";
        chars.Add(dissasmTitle.data(), config.Colors.AsmTitleColor);
        const uint32 titleColorRemaining = Layout.totalCharactersPerLine - chars.Len();
        spaces.Clear();
        spaces.SetChars(' ', titleColorRemaining);
        chars.Add(spaces, config.Colors.AsmTitleColor);

        HighlightSelectionAndDrawCursorText(dli, chars.Len() - Layout.startingTextLineOffset, chars.Len());

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);
        return true;
    }

    uint32 currentLine = dli.textLineToDraw - 1u;
    if (firstLineToDraw)
        --currentLine;

    if (!zone->isInit)
    {
        if (!InitDissasmZone(dli, zone))
            return false;
    }

    // move the function DissasmPrepareCodeZone as a function inside DissasmCodeZone
    // DissasmPrepareCodeZone(zone, currentLine);

    uint32 linesToPrepare       = std::min<uint32>(Layout.visibleRows, zone->extendedSize);
    const uint32 remainingLines = zone->extendedSize - currentLine + 1;
    linesToPrepare              = std::min<uint32>(linesToPrepare, remainingLines);
    if (zone->asmPreCacheData.cachedAsmLines.empty())
        populateAsmPreCacheData(config, obj, settings, asmData, dli, zone, currentLine, linesToPrepare);

    auto asmCacheLine = zone->asmPreCacheData.GetLine();
    if (!asmCacheLine)
        return false;
    DissasmAddColorsToInstruction(*asmCacheLine, chars, config, Layout, asmData, codePage, zone->cachedCodeOffsets[0].offset);

    zone->lastDrawnLine = currentLine;

    const auto it = zone->comments.find(currentLine);
    if (it != zone->comments.end())
    {
        uint32 diffLine = zone->asmPreCacheData.maxLineSize + textTotalColumnLength + commentPaddingLength;
        if (chars.Len() > diffLine)
            diffLine = commentPaddingLength;
        else
            diffLine -= chars.Len();
        LocalString<DISSAM_MINIMUM_COMMENTS_X> spaces;
        spaces.AddChars(' ', diffLine);
        spaces.AddChars(';', 1);
        chars.Add(spaces, config.Colors.AsmComment);
        chars.Add(it->second, config.Colors.AsmComment);
    }

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };

    /*if (isCursorLine)
        chars.SetColor(Layout.startingTextLineOffset, chars.Len(), config.Colors.HighlightCursorLine);*/

    HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(bufferToDraw.length()), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    // poolBuffer.lineToDrawOnScreen = dli.screenLineToDraw + 1;
    bool foundZone = false;
    for (const auto& z : asmData.zonesToClear)
        if (z == zone)
        {
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
    for (const auto& zone : settings->parseZones)
    {
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
        {
            AppCUI::Utils::UnicodeStringBuilder sb;
            sb.Add(obj->GetPath());
            LocalString<32> fileName;
            fileName.SetFormat(".x86.z%d.asm", zoneIndex);
            sb.Add(fileName);

            AppCUI::OS::File f;
            if (!f.Create(sb.ToStringView(), true))
            {
                continue;
            }
            if (!f.OpenWrite(sb.ToStringView()))
            {
                f.Close();
                continue;
            }

            f.Write("ASMZoneZone\n", sizeof("ASMZoneZone\n") - 1);

            csh handle;
            const auto resCode = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
            if (resCode != CS_ERR_OK)
            {
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
            if (!dataBuffer.IsValid())
            {
                f.Write("Failed to get data from file!");
                f.Close();
                continue;
            }
            auto data = dataBuffer.GetData();

            while (address < endAddress)
            {
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
    if (!offsetToReach)
    {
        insn = GetCurrentInstructionByLine(line - 1, zone, obj, diffLines);
        if (!insn)
        {
            Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
            return;
        }
        if (insn->mnemonic[0] == 'j' || insn->mnemonic[0] == 'c' && *(uint32*) insn->mnemonic == callOP)
        {
            if (insn->op_str[0] == '0' && insn->op_str[1] == 'x')
            {
                char* val = &insn->op_str[2];

                while (*val && *val != ',' && *val != ' ')
                {
                    if (*val >= '0' && *val <= '9')
                        computedValue = computedValue * 16 + (*val - '0');
                    else if (*val >= 'a' && *val <= 'f')
                        computedValue = computedValue * 16 + (*val - 'a' + 10);
                    else
                    {
                        Dialogs::MessageBox::ShowNotification("Warning", "Invalid jump value!");
                        computedValue = 0;
                        break;
                    }
                    val++;
                }
            }
            else if (insn->op_str[0] == '0' && insn->op_str[1] == '\0')
            {
                computedValue = zone->cachedCodeOffsets[0].offset;
            }
            else
            {
                cs_free(insn, 1);
                return;
            }
            cs_free(insn, 1);
        }
        else
        {
            cs_free(insn, 1);
            return;
        }
    }
    else
        computedValue = *offsetToReach;

    if (computedValue == 0 || computedValue > zone->zoneDetails.startingZonePoint + zone->zoneDetails.size)
        return;

    // computedValue = 1064;

    diffLines = 0;
    insn      = GetCurrentInstructionByOffset(computedValue, zone, obj, diffLines);
    if (!insn)
    {
        Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
        return;
    }
    cs_free(insn, 1);

    diffLines++; // increased because of the menu bar
    jumps_holder.insert(Cursor.saveState());
    Cursor.lineInView    = std::min<uint32>(5, diffLines);
    Cursor.startViewLine = diffLines + zone->startLineIndex - Cursor.lineInView;
    Cursor.hasMovedView  = true;
}

void Instance::CommandDissasmAddZone()
{
    uint64 offsetStart = 0;
    uint64 offsetEnd   = 0;
    if (!selection.HasAnySelection() || !selection.GetSelection(0, offsetStart, offsetEnd))
    {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
    if (zonesFound.empty() || zonesFound.size() != 1)
    {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
    {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    if (zonesFound[0].startingLine == 0)
    {
        Dialogs::MessageBox::ShowNotification("Warning", "Please add comment inside the region, not on the title!");
        return;
    }

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
}

void Instance::CommandDissasmRemoveZone()
{
}
