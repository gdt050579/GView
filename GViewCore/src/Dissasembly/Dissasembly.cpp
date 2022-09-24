#include "Internal.hpp"
#include <capstone/capstone.h>

namespace GView::Dissasembly
{
bool DissasemblerIntel::Init(bool isx64, bool isLittleEndian)
{
    if (handle == 0)
    {
        cs_arch arch = CS_ARCH_X86;
        cs_mode mode = isx64 ? CS_MODE_64 : CS_MODE_32;
        mode         = (cs_mode) ((uint32) mode | (isLittleEndian ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN));

        const auto result = cs_open(arch, mode, &handle);
        CHECK(result == CS_ERR_OK, false, "Error: %u!", result);
    }
    return true;
}

bool DissasemblerIntel::DissasembleInstruction(BufferView buf, uint64 va, Instruction& instruction)
{
    CHECK(handle != 0, false, "");

    cs_insn insn{};

    auto data   = buf.GetData();
    auto length = buf.GetLength();

    uint64 address = va;
    CHECK(cs_disasm_iter(handle, &data, &length, &address, &insn), false, "");

    memcpy(&instruction, &insn, sizeof(instruction));

    return true;
}

DissasemblerIntel::~DissasemblerIntel()
{
    CHECKRET(cs_close(&handle), "");
    handle = 0;
}
} // namespace GView::Dissasembly
