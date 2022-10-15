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

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0)
    {
        WriteErrorToScreen(dli, "No data available!");
        return true;
    }

    auto clearChar = this->chars.GetBuffer();
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++)
    {
        clearChar->Code  = codePage[' '];
        clearChar->Color = config.Colors.Normal;
        clearChar++;
    }

    dli.chNameAndSize = this->chars.GetBuffer() + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    if (dli.textLineToDraw == 0)
    {
        AddStringToChars(dli, config.Colors.StructureColor, "Dissasm zone");
        //dli.renderer.WriteSingleLineText(
        //      Layout.startingTextLineOffset, dli.screenLineToDraw + 1, "Dissasm zone", config.Colors.StructureColor);

        HighlightSelectionText(dli, sizeof("Dissasm zone"));

        const uint32 cursorLine = static_cast<uint32>((this->Cursor.currentPos - this->Cursor.startView) / Layout.textSize);
        if (cursorLine == dli.screenLineToDraw)
        {
            const uint32 index             = this->Cursor.currentPos % Layout.textSize;
            dli.chNameAndSize[index].Color = config.Colors.Selection;
        }

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, chars, false);

        RegisterStructureCollapseButton(dli, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);
        AdjustZoneExtendedSize(zone, 100);
        return true;
    }

    const uint32 currentLine = dli.textLineToDraw - 1u;
    if (zone->isInit && currentLine >= zone->startingCacheLineIndex)
    {
        const uint32 lineAsmToDraw = currentLine - zone->startingCacheLineIndex;
        auto start                 = zone->cachedLines[lineAsmToDraw].GetBuffer();
        auto end                   = zone->cachedLines[lineAsmToDraw].GetBuffer() + zone->cachedLines[lineAsmToDraw].Len();
        // TODO: check not to overflow
        while (start != end)
        {
            *dli.chText = *start;
            dli.chText++;
            start++;
        }

        HighlightSelectionText(dli, dli.chText - dli.chNameAndSize);

        const uint32 cursorLine = static_cast<uint32>((this->Cursor.currentPos - this->Cursor.startView) / Layout.textSize);
        if (cursorLine == dli.screenLineToDraw)
        {
            const uint32 index             = this->Cursor.currentPos % Layout.textSize;
            dli.chNameAndSize[index].Color = config.Colors.Selection;
        }

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, chars, false);
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
        LocalString<192> string;
        for (size_t j = 0; j < count; j++)
        {
            zone->cachedLines[j].Fill(' ', Layout.textSize);
            string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);

            auto c = zone->cachedLines[j].GetBuffer();
            for (uint32 i = 0; i < string.Len(); i++)
            {
                c->Code  = codePage[string[i]];
                c->Color = config.Colors.Normal;
                c++;
            }

            if (lineAsmToDraw == j)
            {
                auto start = zone->cachedLines[lineAsmToDraw].GetBuffer();
                auto end   = zone->cachedLines[lineAsmToDraw].GetBuffer() + zone->cachedLines[lineAsmToDraw].Len();
                // TODO: check not to overflow
                while (start != end)
                {
                    *dli.chText = *start;
                    dli.chText++;
                    start++;
                }
            }
        }

        cs_free(insn, count);
    }
    else
    {
        WriteErrorToScreen(dli, "ERROR: Failed to disassemble given code!");
    }

    cs_close(&handle);

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, chars, false);
    return true;
}