#include "DissasmViewer.hpp"
#include <capstone/capstone.h>
#include <cassert>
#include <ranges>
#include <utility>
#include <list>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define DISSASM_INSTRUCTION_OFFSET_MARGIN 500

uint64 SearchForClosestOffset(std::vector<uint64>& values, uint64 searchedOffset)
{
    assert(!values.empty());
    uint32 left  = 0;
    uint32 right = values.size() - 1u;
    while (left != right)
    {
        const uint32 mid = (left + right) / 2;
        if (searchedOffset == values[mid])
            return searchedOffset;
        if (searchedOffset < values[mid])
            right = mid - 1;
        else
            left = mid + 1;
    }
    if (right < values.size() - 1 && searchedOffset - values[left] < values[right + 1] - searchedOffset)
        return values[right + 1];

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
      const cs_insn& insn, CharacterBuffer& cb, CodePage& cp, Config& cfg, const LayoutDissasm& layout, AsmData& data)
{
    cb.Clear();

    LocalString<128> string;
    string.SetChars(' ', std::min<uint8>(128, static_cast<uint8>(layout.startingTextLineOffset)));
    cb.Add(string);

    string.SetFormat("0x%" PRIx64 ":     ", insn.address);
    cb.Add(string, cfg.Colors.AsmOffsetColor);

    string.SetFormat("%-6s", insn.mnemonic);
    const ColorPair color = GetASMColorPairByKeyword(insn.mnemonic, cfg, data);
    cb.Add(string, color);

    const std::string_view op_str = insn.op_str;
    if (!op_str.empty())
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

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
}

inline bool populate_offsets_vector(vector<uint64>& offsets, DisassemblyZone& zoneDetails, GView::Object& obj)
{
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (resCode != CS_ERR_OK)
    {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj.GetData().Get(zoneDetails.startingZonePoint, zoneDetails.size, false);

    size_t minimalValue = offsets[0];

    cs_insn* insn     = cs_malloc(handle);
    size_t lastOffset = offsets[0];

    constexpr uint32 callOP = 1819042147u; //*(uint32*) "call";

    // TODO: change method!
    uint8 mapper[(int) 'g'] = { 0 };
    for (int i = '0'; i <= '9'; i++)
        mapper[i] = i - '0';
    uint8 value = 10;
    for (int i = 'a'; i <= 'f'; i++)
        mapper[i] = value++;

    std::list<uint64> finalOffsets;

    size_t size       = zoneDetails.startingZonePoint + zoneDetails.size;
    size_t address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    size_t endAddress = zoneDetails.size;
    auto data         = instructionData.GetData() + address;

    //std::string saved1 = "s1", saved2 = "s2";
    uint64 startingOffset = offsets[0];

    size_t lastSize = size;
    std::vector<uint64> tempStorage;
    tempStorage.push_back(lastOffset);

    do
    {
        if (size > lastSize)
        {
            lastSize = size;
            tempStorage.reserve(size / DISSASM_INSTRUCTION_OFFSET_MARGIN + 1);
        }

        while (address < endAddress)
        {
            if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                break;

            if ((insn->mnemonic[0] == 'j' || *(uint32*) insn->mnemonic == callOP) && insn->op_str[0] == '0' && insn->op_str[1] == 'x')
            {
                uint64 computedValue = 0;
                char* ptr            = &insn->op_str[2];
                while (*ptr && *ptr != ' ' && *ptr != ',')
                {
                    computedValue = computedValue * 16 + mapper[*ptr];
                    ptr++;
                }
                if (computedValue < minimalValue && computedValue >= zoneDetails.startingZonePoint)
                {
                    minimalValue = computedValue;
                    //saved1       = insn->mnemonic;
                    //saved2       = insn->op_str;
                }
            }
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            if (adjustedSize - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN)
            {
                lastOffset = adjustedSize;
                tempStorage.push_back(lastOffset);
                // if (pushBack)
                //     finalOffsets.push_back(lastOffset);
                // else
                //     finalOffsets.push_front(lastOffset);
            }
        }
        if (minimalValue >= startingOffset)
            break;

        for (auto& it : std::ranges::reverse_view(tempStorage))
            finalOffsets.push_front(it);
        tempStorage.clear();

        // pushBack                       = false;
        const size_t zoneSizeToAnalyze = startingOffset - minimalValue;
        tempStorage.push_back(minimalValue);
        // finalOffsets.push_front(minimalValue);

        address        = minimalValue - zoneDetails.startingZonePoint;
        endAddress     = zoneSizeToAnalyze + address;
        size           = address + zoneSizeToAnalyze;
        data           = instructionData.GetData() + address;
        lastOffset     = minimalValue;
        startingOffset = minimalValue;
    } while (true);

    for (auto& it : std::ranges::reverse_view(tempStorage))
        finalOffsets.push_front(it);

    offsets.clear();
    offsets.reserve(finalOffsets.size());
    for (auto& it : finalOffsets)
        offsets.push_back(it);

    cs_close(&handle);
    return true;
}

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0)
    {
        WriteErrorToScreen(dli, "No data available!");
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

        HighlightSelectionText(dli, zoneName.size());

        const uint32 cursorLine = static_cast<uint32>((this->Cursor.currentPos - this->Cursor.startView) / Layout.textSize);
        if (cursorLine == dli.screenLineToDraw)
        {
            const uint32 index = this->Cursor.currentPos % Layout.textSize + Layout.startingTextLineOffset;

            if (index < chars.Len())
                chars.GetBuffer()[index].Color = config.Colors.Selection;
            else
                dli.renderer.WriteCharacter(index, cursorLine + 1, codePage[' '], config.Colors.Selection);
        }

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);
        AdjustZoneExtendedSize(zone, 100);
        return true;
    }

    const uint32 currentLine = dli.textLineToDraw - 1u;
    if (zone->isInit && currentLine >= zone->startingCacheLineIndex)
    {
        const uint32 lineAsmToDraw = currentLine - zone->startingCacheLineIndex;

        chars.Set(zone->cachedLines[lineAsmToDraw]);

        // TODO: maybe update line inside lineToDraw instead of drawing the comment every time
        auto it = zone->comments.find(lineAsmToDraw);
        if (it != zone->comments.end())
        {
            char tmp[] = "    //";
            chars.Add(tmp, config.Colors.AsmComment);
            chars.Add(it->second, config.Colors.AsmComment);
        }

        HighlightSelectionText(dli, chars.Len());

        const uint32 cursorLine = static_cast<uint32>((this->Cursor.currentPos - this->Cursor.startView) / Layout.textSize);
        if (cursorLine == dli.screenLineToDraw)
        {
            const uint32 index = this->Cursor.currentPos % Layout.textSize + Layout.startingTextLineOffset;

            if (index < chars.Len())
                chars.GetBuffer()[index].Color = config.Colors.Selection;
            else
                dli.renderer.WriteCharacter(index, cursorLine + 1, codePage[' '], config.Colors.Selection);
        }

        const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };
        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
        return true;
    }

    if (!zone->isInit)
    {
        populate_offsets_vector(zone->cachedCodeOffsets, zone->zoneDetails, obj);
        zone->isInit = true;
    }
    const uint32 lineAsmToDraw = zone->startingCacheLineIndex - currentLine;

    // assert(zone->zoneDetails.size > zone->zoneDetails.entryPoint);

    const uint64 latestOffset      = SearchForClosestOffset(zone->cachedCodeOffsets, zone->lastInstrOffsetInCachedLines);
    const uint64 remainingZoneSize = zone->zoneDetails.size - latestOffset;

    // TODO: move this in onCreate and use a boolean value if enabled
    if (!cs_support(CS_ARCH_X86))
    {
        WriteErrorToScreen(dli, "Capstone does not support X86");
        AdjustZoneExtendedSize(zone, 1);
        return false;
    }

    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    if (resCode != CS_ERR_OK)
    {
        WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj->GetData().Get(latestOffset, remainingZoneSize, false);
    if (!instructionData.IsValid())
        return true;

    cs_insn* insn;
    size_t count = cs_disasm(
          handle, instructionData.GetData(), instructionData.GetLength(), zone->zoneDetails.entryPoint, DISSASM_MAX_CACHED_LINES, &insn);
    if (count > 0)
    {
        for (size_t j = 0; j < count; j++)
        {
            DissasmAddColorsToInstruction(insn[j], zone->cachedLines[j], codePage, config, Layout, asmData);

            if (lineAsmToDraw == j)
            {
                chars.Set(zone->cachedLines[lineAsmToDraw]);
            }
        }

        cs_free(insn, count);
    }
    else
    {
        WriteErrorToScreen(dli, "ERROR: Failed to disassemble given code!");
    }

    cs_close(&handle);

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    return true;
}