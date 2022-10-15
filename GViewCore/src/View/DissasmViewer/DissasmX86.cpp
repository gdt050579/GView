#include "DissasmViewer.hpp"
#include <capstone/capstone.h>
#include <cassert>
#include <utility>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

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

inline void DissasmAddColorsToInstruction(const cs_insn& insn, CharacterBuffer& cb, CodePage& cp, Config& cfg, const LayoutDissasm& layout)
{
    cb.Clear();

    LocalString<128> string;
    string.SetChars(' ', std::min<uint16>(128, layout.startingTextLineOffset));
    cb.Add(string);

    string.SetFormat("0x%" PRIx64 ":           ", insn.address);
    cb.Add(string, cfg.Colors.AsmOffsetColor);

    string.SetFormat("%s ", insn.mnemonic);
    cb.Add(string, cfg.Colors.AsmWorkRegisterColor);

    string.SetFormat("%s", insn.op_str);
    if (string.Len() > 0)
        cb.Add(string, cfg.Colors.AsmDefaultColor);

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);

    // auto c = zone->cachedLines[j].GetBuffer();
    // for (uint32 i = 0; i < string.Len(); i++)
    //{
    //     c->Code  = codePage[string[i]];
    //     c->Color = config.Colors.Normal;
    //     c++;
    // }
}

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0)
    {
        WriteErrorToScreen(dli, "No data available!");
        return true;
    }

    chars.Clear();
    // auto clearChar = this->chars.GetBuffer();
    // for (uint32 i = 0; i < Layout.startingTextLineOffset; i++)
    //{
    //     clearChar->Code  = codePage[' '];
    //     clearChar->Color = config.Colors.Normal;
    //     clearChar++;
    // }

    dli.chNameAndSize = this->chars.GetBuffer() + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    if (dli.textLineToDraw == 0)
    {
        LocalString<256> spaces;
        spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
        chars.Set(spaces);
        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), config.Colors.StructureColor);
        // dli.renderer.WriteSingleLineText(
        //       Layout.startingTextLineOffset, dli.screenLineToDraw + 1, "Dissasm zone", config.Colors.StructureColor);

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

        // const auto bufferToDraw = CharacterView{ chars.GetBuffer(), (uint32) (dli.chText - this->chars.GetBuffer()) };
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

        const auto bufferToDraw = CharacterView{ chars.GetBuffer(), zone->cachedLines[lineAsmToDraw].Len() };
        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
        return true;
    }
    zone->isInit               = true;
    const uint32 lineAsmToDraw = zone->startingCacheLineIndex - currentLine;

    assert(zone->zoneDetails.size > zone->zoneDetails.entryPoint);

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
            DissasmAddColorsToInstruction(insn[j], zone->cachedLines[j], codePage, config, Layout);

            if (lineAsmToDraw == j)
            {
                chars.Set(zone->cachedLines[lineAsmToDraw]);
                // auto start = zone->cachedLines[lineAsmToDraw].GetBuffer();
                // auto end   = zone->cachedLines[lineAsmToDraw].GetBuffer() + zone->cachedLines[lineAsmToDraw].Len();
                //// TODO: check not to overflow
                // while (start != end)
                //{
                //     *dli.chText = *start;
                //     dli.chText++;
                //     start++;
                // }
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