#include "DissasmViewer.hpp"
#include <capstone/capstone.h>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* structureZone)
{
    if (obj->GetData().GetSize() == 0)
        return true;
    DisassemblyZone& zone         = structureZone->zoneDetails;
    uint64 entryPointSizeUntilEnd = zone.size - zone.entryPoint;

    if (dli.textLineToDraw == 0)
    {
        dli.renderer.WriteSingleLineText(
              Layout.startingTextLineOffset, dli.screenLineToDraw + 1, "Dissasm zone", config.Colors.StructureColor);
        return true;
    }

    csh handle;

    // TODO: move this in onCreate and use a boolean value if enabled
    if (!cs_support(CS_ARCH_X86))
    {
        WriteErrorToScreen(dli, "Capstone does not support X86");
        return false;
    }

    const auto resCode = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    if (resCode != CS_ERR_OK)
    {
        WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj->GetData().Get(zone.entryPoint, entryPointSizeUntilEnd, false);
    if (!instructionData.IsValid())
        return true;

    cs_insn* insn;
    size_t count = cs_disasm(handle, instructionData.GetData(), instructionData.GetLength(), zone.entryPoint, 0, &insn);
    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
        printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);

    return true;
}