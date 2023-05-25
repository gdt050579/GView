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

const uint8 HEX_MAPPER[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };

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
      const cs_insn& insn,
      CharacterBuffer& cb,
      Config& cfg,
      const LayoutDissasm& layout,
      AsmData& data,
      uint64 addressPadding                = 0,
      const MemoryMappingEntry* mappingPtr = nullptr)
{
    cb.Clear();

    LocalString<128> string;
    string.SetChars(' ', std::min<uint8>(128, static_cast<uint8>(layout.startingTextLineOffset)));
    cb.Add(string);

    string.SetFormat("0x%" PRIx64 ":     ", insn.address + addressPadding);
    cb.Add(string, cfg.Colors.AsmOffsetColor);

    string.SetFormat("%-6s", insn.mnemonic);
    const ColorPair color = GetASMColorPairByKeyword(insn.mnemonic, cfg, data);
    cb.Add(string, color);

    const std::string_view op_str = insn.op_str;
    if (!op_str.empty() && !mappingPtr)
    {
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
    else if (mappingPtr)
    {
        string.SetFormat("%s", mappingPtr->name.data());
        const ColorPair mapColor = mappingPtr->type == MemoryMappingType::TextMapping ? cfg.Colors.AsmLocationInstruction : cfg.Colors.AsmFunctionColor;
        cb.Add(string, mapColor);
    }

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
}

inline bool populate_offsets_vector(
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

// TODO: maybe add also minimum number?
bool CheckExtractInsnHexValue(cs_insn& insn, uint64& value, uint64 maxSize)
{
    char* ptr   = insn.op_str;
    char* start = nullptr;
    uint32 size = 0;

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
        lineDifferences = lineToReach - closestData.line + 1;
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
    if (offsetToReach > zone->cachedCodeOffsets[0].offset)
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

bool Instance::InitDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    uint32 totalLines = 0;
    if (!populate_offsets_vector(zone->cachedCodeOffsets, zone->zoneDetails, obj, zone->internalArchitecture, totalLines))
    {
        // dli.WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        // return false;
    }
    AdjustZoneExtendedSize(zone, totalLines);
    zone->lastDrawnLine    = 0;
    const auto closestData = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, zone->lastDrawnLine);
    zone->lastClosestLine  = closestData.line;
    switch (zone->zoneDetails.architecture)
    {
    case DissasmArchitecture::x86:
        zone->internalArchitecture = CS_MODE_32;
        break;
    case DissasmArchitecture::x64:
        zone->internalArchitecture = CS_MODE_64;
        break;
    case DissasmArchitecture::Other:
    {
        return false;
    }
    }
    zone->isInit = true;

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

    return true;
}

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0)
    {
        dli.WriteErrorToScreen("No data available!");
        return true;
    }

    if (zone->zoneDetails.architecture == DissasmArchitecture::Other)
    {
        dli.WriteErrorToScreen("Unsupported architecture!");
        return true;
    }

    chars.Clear();

    dli.chNameAndSize = this->chars.GetBuffer() + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    if (dli.textLineToDraw == 0)
    {
        LocalString<256> spaces;
        spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
        chars.Set(spaces);
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

    const uint32 currentLine = dli.textLineToDraw - 1u;
    auto& poolBuffer         = asmData.bufferPool.GetPoolBuffer(currentLine);
    poolBuffer.comments      = &zone->comments;
    poolBuffer.currentLine   = currentLine;
    auto& chars              = poolBuffer.chars;

    chars.Clear();

    dli.chNameAndSize = chars.GetBuffer() + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    // TODO: reenable caching
    /*
    //if (zone->isInit && lineInView >= zone->startingCacheLineIndex &&
    //    lineInView - zone->startingCacheLineIndex < DISSASM_MAX_CACHED_LINES)
    //{
    //    const uint32 lineAsmToDraw = lineInView - zone->startingCacheLineIndex;

    //    chars.Set(zone->cachedLines[lineAsmToDraw]);

    //    // TODO: maybe update line inside lineToDraw instead of drawing the comment every time
    //    const auto it = zone->comments.find(lineAsmToDraw);
    //    if (it != zone->comments.end())
    //    {
    //        constexpr char tmp[] = "    //";
    //        chars.Add(tmp, config.Colors.AsmComment);
    //        chars.Add(it->second, config.Colors.AsmComment);
    //    }

    //    HighlightSelectionAndDrawCursorText(dli, chars.Len());

    //    const uint32 cursorLine = static_cast<uint32>((this->Cursor.currentPos - this->Cursor.startView) / Layout.textSize);
    //    if (cursorLine == dli.screenLineToDraw)
    //    {
    //        const uint32 index = this->Cursor.currentPos % Layout.textSize + Layout.startingTextLineOffset;

    //        if (index < chars.Len())
    //            chars.GetBuffer()[index].Color = config.Colors.Selection;
    //        else
    //            dli.renderer.WriteCharacter(index, cursorLine + 1, codePage[' '], config.Colors.Selection);
    //    }

    //    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };
    //    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    //    return true;
    //}*/

    // TODO: move this in onCreate and use a boolean value if enabled
    if (!cs_support(CS_ARCH_X86))
    {
        dli.WriteErrorToScreen("Capstone does not support X86");
        AdjustZoneExtendedSize(zone, 1);
        return false;
    }

    if (!zone->isInit)
    {
        if (!InitDissasmZone(dli, zone))
            return false;
    }

    // currentLine = lineToReach;

    uint32 diffLines = 0;
    cs_insn* insn    = GetCurrentInstructionByLine(currentLine, zone, obj, diffLines, &dli);
    if (!insn)
        return false;

    bool isCall = false, shouldSearchHex = false;
    const std::string_view sv = insn->mnemonic;
    if (sv.size() == 4)
    {
        if (sv == "push")
        {
            poolBuffer.isPush = true;
            shouldSearchHex   = true;
        }
        else if (sv == "call")
        {
            isCall          = true;
            shouldSearchHex = true;
        }
    }

    // TODO: be more generic
    if (isCall && insn->op_str[0] == '0' && insn->op_str[1] == '\0')
    {
        NumericFormatter n;
        const auto res = n.ToString(zone->cachedCodeOffsets[0].offset, { NumericFormatFlags::HexPrefix, 16 });
        if (res.size() < 16)
            memcpy(insn->op_str, res.data(), res.size() + 1);
    }

    // TODO: improve efficiency by filtering instructions
    const MemoryMappingEntry* mappingPtr = nullptr;
    const uint64 finalIndex =
          zone->asmAddress + settings->offsetTranslateCallback->TranslateFromFileOffset(zone->zoneDetails.entryPoint, (uint32) DissasmPEConversionType::RVA);
    uint64 hexVal = 0;

    // TODO: once found an offset store it to not redo the same computation again
    if (shouldSearchHex && CheckExtractInsnHexValue(*insn, hexVal, settings->maxLocationMemoryMappingSize))
    {
        // poolBuffer.isPush
        if (isCall)
        {
            const auto& mapping = settings->memoryMappings.find(hexVal);
            if (mapping != settings->memoryMappings.end())
                mappingPtr = &mapping->second;
            else
            {
                const auto& mapping2 = settings->memoryMappings.find(hexVal + finalIndex);
                if (mapping2 != settings->memoryMappings.end())
                    mappingPtr = &mapping2->second;
            }

            if (mappingPtr)
            {
                if (mappingPtr->type == MemoryMappingType::FunctionMapping)
                {
                    GView::Hashes::CRC16 crc16{};
                    uint16 hash    = 0;
                    const bool res = crc16.Init() && crc16.Update((const uint8*) mappingPtr->name.data(), mappingPtr->name.size()) && crc16.Final(hash);
                    if (res)
                    {
                        const auto it = asmData.functions.find(hash);
                        if (it != asmData.functions.end())
                        {
                            if (!asmData.CheckInstructionHasFlag(currentLine, AsmData::CallFlag))
                            {
                                asmData.bufferPool.AnnounceCallInstruction(it->second);
                                asmData.AddInstructionFlag(currentLine, AsmData::CallFlag);
                            }
                        }
                    }
                }
            }
        }
        else if (poolBuffer.isPush)
        {
            auto offset = settings->offsetTranslateCallback->TranslateToFileOffset(hexVal, (uint32) DissasmPEConversionType::RVA);
            if (offset != static_cast<uint64>(-1) && offset + DISSAM_MAXIMUM_STRING_PREVIEW < obj->GetData().GetSize())
            {
                const auto stringBuffer = obj->GetData().Get(offset, DISSAM_MAXIMUM_STRING_PREVIEW * 2, false);
                if (stringBuffer.IsValid())
                {
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

                    if (textFound.size() > 3)
                    {
                        const auto it = zone->comments.find(currentLine);
                        if (it != zone->comments.end())
                        {
                            auto len = 10;
                            if (chars.Len() < DISSAM_MINIMUM_COMMENTS_X)
                                len = DISSAM_MINIMUM_COMMENTS_X - chars.Len();
                            LocalString<DISSAM_MINIMUM_COMMENTS_X> spaces;
                            spaces.AddChars(' ', len);
                            spaces.AddChars(';', 1);
                            chars.Add(spaces, config.Colors.AsmComment);
                            chars.Add(it->second, config.Colors.AsmComment);
                        }
                        else
                            zone->comments.insert({ currentLine, (char*) textFound.data() });
                    }
                }
            }
        }
    }

    // cursorLine == zone->startLineIndex - currentLine
    //  TODO: refactor this in the future
    /*const uint32 cursorLine = Cursor.lineInView + Cursor.startViewLine;
    const bool isCursorLine = cursorLine == dli.screenLineToDraw;*/
    DissasmAddColorsToInstruction(*insn, chars, config, Layout, asmData, zone->cachedCodeOffsets[0].offset, mappingPtr);

    cs_free(insn, 1);
    // cs_close(&handle);

    zone->lastDrawnLine = currentLine;

    const auto it = zone->comments.find(currentLine);
    if (it != zone->comments.end())
    {
        auto len = 10;
        if (chars.Len() < DISSAM_MINIMUM_COMMENTS_X)
            len = DISSAM_MINIMUM_COMMENTS_X - chars.Len();
        LocalString<DISSAM_MINIMUM_COMMENTS_X> spaces;
        spaces.AddChars(' ', len);
        spaces.AddChars(';', 1);
        chars.Add(spaces, config.Colors.AsmComment);
        chars.Add(it->second, config.Colors.AsmComment);
    }

    // const uint32 lineAsmToDraw = zone->startingCacheLineIndex - lineInView;

    // assert(zone->zoneDetails.size > zone->zoneDetails.entryPoint);

    // const uint64 latestOffset      = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, zone->lastInstrOffsetInCachedLines);
    // const uint64 remainingZoneSize = zone->zoneDetails.size - latestOffset;

    //// TODO: move this in onCreate and use a boolean value if enabled
    // if (!cs_support(CS_ARCH_X86))
    //{
    //     WriteErrorToScreen(dli, "Capstone does not support X86");
    //     AdjustZoneExtendedSize(zone, 1);
    //     return false;
    // }

    // csh handle;
    // const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    // if (resCode != CS_ERR_OK)
    //{
    //     WriteErrorToScreen(dli, cs_strerror(resCode));
    //     return false;
    // }

    // const auto instructionData = obj->GetData().Get(latestOffset, remainingZoneSize, false);
    //// TODO: write err instead of returning true
    // if (!instructionData.IsValid())
    //{
    //     WriteErrorToScreen(dli, "ERROR: extract valid data from file!");
    //     cs_close(&handle);
    //     return false;
    // }

    // cs_insn* insn = cs_malloc(handle);

    //// size_t size       = zoneDetails.startingZonePoint + zoneDetails.size;
    //// size_t address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    //// size_t endAddress = zoneDetails.size;

    //// if (!cs_disasm_iter(handle, &data, &size, &address, insn))
    ////     break;

    // cs_free(insn, 1);

    //// cs_insn* insn;
    //// const size_t count = cs_disasm(
    ////       handle, instructionData.GetData(), instructionData.GetLength(), zone->zoneDetails.entryPoint, DISSASM_MAX_CACHED_LINES,
    ///&insn); / if (count > 0)
    ////{
    ////     for (size_t j = 0; j < count; j++)
    ////     {
    ////         DissasmAddColorsToInstruction(insn[j], zone->cachedLines[j], codePage, config, Layout, asmData);

    ////        if (lineAsmToDraw == j)
    ////        {
    ////            chars.Set(zone->cachedLines[lineAsmToDraw]);
    ////        }
    ////    }

    ////    cs_free(insn, count);
    ////}
    //// else
    ////{
    ////    WriteErrorToScreen(dli, "ERROR: Failed to disassemble given code!");
    ////}

    // cs_close(&handle);

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };

    /*if (isCursorLine)
        chars.SetColor(Layout.startingTextLineOffset, chars.Len(), config.Colors.HighlightCursorLine);*/

    HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(bufferToDraw.length()), static_cast<uint32>(bufferToDraw.length()));

    // dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    poolBuffer.lineToDrawOnScreen = dli.screenLineToDraw + 1;
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

void Instance::DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line)
{
    uint32 diffLines = 0;
    cs_insn* insn    = GetCurrentInstructionByLine(line - 1, zone, obj, diffLines);
    if (!insn)
    {
        Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
        return;
    }
    uint32 computedValue = 0;
    if (insn->mnemonic[0] == 'j')
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
    cs_free(insn, 1);

    if (computedValue == 0)
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

    jumps_holder.insert(Cursor.saveState());
    Cursor.lineInView    = std::min<uint32>(5, diffLines);
    Cursor.startViewLine = diffLines + zone->startLineIndex - Cursor.lineInView;
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
