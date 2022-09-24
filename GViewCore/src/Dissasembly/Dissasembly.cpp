#include "Internal.hpp"
#include <capstone/capstone.h>

namespace GView::Dissasembly
{
bool DissasembleInstruction(BufferView buf, Architecture arch, uint64 va, Mode mode, Instruction& instruction)
{
    cs_insn insn{};

    struct HandleWrapper
    {
        csh value{ 0 };
        ~HandleWrapper()
        {
            CHECKRET(cs_close(&value), "");
        }
    } wHandle{};

    const auto actualArch = (cs_arch) arch;
    cs_mode actualMode{ CS_MODE_LITTLE_ENDIAN };
    if (actualArch == CS_ARCH_ARM)
    {
        actualMode = (cs_mode) (CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS);
    }
    else if (actualArch == CS_ARCH_ARM64)
    {
        actualMode = CS_MODE_ARM; // (cs_mode)(CS_MODE_ARM | CS_MODE_V8);
    }
    else if (actualArch == CS_ARCH_X86)
    {
        if (mode == Mode::X32)
        {
            actualMode = CS_MODE_32;
        }
        else if (mode == Mode::X64)
        {
            actualMode = CS_MODE_64;
        }
    }

    const auto result = cs_open(actualArch, actualMode, &wHandle.value);
    CHECK(result == CS_ERR_OK, false, "Error: %u!", result);

    auto data   = buf.GetData();
    auto length = buf.GetLength();

    uint64 address = va;
    CHECK(cs_disasm_iter(wHandle.value, &data, &length, &address, &insn), false, "");

    memcpy(&instruction, &insn, sizeof(instruction));

    return true;
}

bool DissasembleInstructionIntelx86(BufferView buf, uint64 va, Instruction& instruction)
{
    CHECK(DissasembleInstruction(buf, Architecture::X86, va, Mode::X32, instruction), false, "");
    return true;
}

bool DissasembleInstructionIntelx64(BufferView buf, uint64 va, Instruction& instruction)
{
    CHECK(DissasembleInstruction(buf, Architecture::X86, va, Mode::X64, instruction), false, "");
    return true;
}
} // namespace GView::Dissasembly
