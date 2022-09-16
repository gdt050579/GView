#include "DissasmViewer.hpp"
#include <capstone/capstone.h>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* structureZone)
{
    if (obj->GetData().GetSize() == 0)
        return true;
    DissasemblyZone& zone         = structureZone->zoneDetails;
    uint64 entryPointSizeUntilEnd = zone.size - zone.entryPoint;

    csh handle;

    if (!cs_support(CS_ARCH_X86))
    {
        return false;
    }

    auto resCode = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
    if (resCode != CS_ERR_OK)
    {
        auto res = cs_strerror(resCode);
        return false;
    }

    auto instructionData = obj->GetData().Get(zone.startingZonePoint, zone.size,false);
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


    dli.renderer.WriteSingleLineText(
          Layout.startingTextLineOffset, structureZone->startLineIndex + 1, "Dissasm zone", config.Colors.Normal);

    return true;
}