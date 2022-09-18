#include "Internal.hpp"

#include <capstone/capstone.h>

#include <fstream>

namespace GView::Dissasembly
{
bool DissasembleInstruction(BufferView buf, Architecture arch, uint64 va, Mode mode)
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
        // CS_MODE_ARM          = 0,      ///< 32-bit ARM
        // CS_MODE_THUMB  = 1 << 4, ///< ARM's Thumb mode, including Thumb-2
        // CS_MODE_MCLASS = 1 << 5, ///< ARM's Cortex-M series
        // CS_MODE_V8     = 1 << 6, ///< ARMv8 A32 encodings for ARM
    }
    else if (actualArch == CS_ARCH_ARM64)
    {
        actualMode = CS_MODE_V8;
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

    auto aa = buf.GetData();
    auto bb = buf.GetLength();

    uint64 address = va;
    CHECK(cs_disasm_iter(wHandle.value, &aa, &bb, &address, &insn), false, "");

    auto id = (arm_insn) insn.id;

    if (id == ARM_INS_PUSH)
    {
        std::ofstream outfile;
        outfile.open(R"(Z:\Repositories\github\GView\arm_windows.txt)", std::ios_base::app); // append instead of overwrite
        outfile << insn.mnemonic << " " << insn.op_str << " |=> " << std::hex << insn.id << " " << insn.address << " " << insn.size
                << " |=> ";
        for (auto i = 0; i < insn.size; i++)
        {
            outfile << (uint16) buf.GetData()[i] << " ";
        }

        outfile << std::endl;
    }

    return true;
}
} // namespace GView::Dissasembly
