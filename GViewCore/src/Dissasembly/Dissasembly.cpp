#include "Internal.hpp"
#include <capstone/capstone.h>

namespace GView::Dissasembly
{
bool DissasemblerIntel::Init(bool isx64, bool isLittleEndian)
{
    if (handle == 0)
    {
        this->isX64 = isx64;

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

bool DissasemblerIntel::IsCallInstruction(const Instruction& instruction) const
{
    CHECK(instruction.id == X86_INS_CALL, false, "");
    return true;
}

bool DissasemblerIntel::IsLCallInstruction(const Instruction& instruction) const
{
    CHECK(instruction.id == X86_INS_LCALL, false, "");
    return true;
}

bool DissasemblerIntel::IsJmpInstruction(const Instruction& instruction) const
{
    CHECK(instruction.id == X86_INS_JMP, false, "");
    return true;
}

bool DissasemblerIntel::IsLJmpInstruction(const Instruction& instruction) const
{
    CHECK(instruction.id == X86_INS_LJMP, false, "");
    return true;
}

bool DissasemblerIntel::IsBreakpointInstruction(const Instruction& instruction) const
{
    switch (instruction.id)
    {
    case X86_INS_INT:
    case X86_INS_INT1:
    case X86_INS_INT3:
    case X86_INS_INTO:
        return true;
    default:
        RETURNERROR(false, "");
    }
}

bool DissasemblerIntel::AreFunctionStartInstructions(const Instruction& instruction1, const Instruction& instruction2) const
{
    switch (instruction1.id)
    {
    case X86_INS_PUSH:
    case X86_INS_PUSHAW:
    case X86_INS_PUSHAL:
    case X86_INS_PUSHF:
    case X86_INS_PUSHFD:
    case X86_INS_PUSHFQ:
    {
        const std::string_view opStr{ instruction1.opStr, GView::Dissasembly::OP_STR_SIZE };
        if (this->isX64)
        {
            CHECK(opStr.starts_with("rsp"), false, "");
        }
        else
        {
            CHECK(opStr.starts_with("esp"), false, "");
        }

        switch (instruction2.id)
        {
        case X86_INS_MOV:
        case X86_INS_MOVABS:
        case X86_INS_MOVAPD:
        case X86_INS_MOVAPS:
        case X86_INS_MOVBE:
        case X86_INS_MOVDDUP:
        case X86_INS_MOVDIR64B:
        case X86_INS_MOVDIRI:
        case X86_INS_MOVDQA:
        case X86_INS_MOVDQU:
        case X86_INS_MOVHLPS:
        case X86_INS_MOVHPD:
        case X86_INS_MOVHPS:
        case X86_INS_MOVLHPS:
        case X86_INS_MOVLPD:
        case X86_INS_MOVLPS:
        case X86_INS_MOVMSKPD:
        case X86_INS_MOVMSKPS:
        case X86_INS_MOVNTDQA:
        case X86_INS_MOVNTDQ:
        case X86_INS_MOVNTI:
        case X86_INS_MOVNTPD:
        case X86_INS_MOVNTPS:
        case X86_INS_MOVNTSD:
        case X86_INS_MOVNTSS:
        case X86_INS_MOVSB:
        case X86_INS_MOVSD:
        case X86_INS_MOVSHDUP:
        case X86_INS_MOVSLDUP:
        case X86_INS_MOVSQ:
        case X86_INS_MOVSS:
        case X86_INS_MOVSW:
        case X86_INS_MOVSX:
        case X86_INS_MOVSXD:
        case X86_INS_MOVUPD:
        case X86_INS_MOVUPS:
        case X86_INS_MOVZX:
            return true;
        default:
            RETURNERROR(false, "Instruction not mov!");
        }
    }

    // sub rsp, 40; mov edx, 2
    case X86_INS_SUB:
    case X86_INS_SUBPD:
    case X86_INS_SUBPS:
    case X86_INS_FSUBR:
    case X86_INS_FISUBR:
    case X86_INS_FSUBRP:
    case X86_INS_SUBSD:
    case X86_INS_SUBSS:
    case X86_INS_FSUB:
    case X86_INS_FISUB:
    case X86_INS_FSUBP:
    {
        const std::string_view opStr{ instruction1.opStr, GView::Dissasembly::OP_STR_SIZE };
        if (this->isX64)
        {
            CHECK(opStr.starts_with("rsp"), false, "");
        }
        else
        {
            CHECK(opStr.starts_with("esp"), false, "");
        }

        return true;
    }

    case X86_INS_ENDBR64:
    case X86_INS_ENDBR32:
    {
        CHECK(instruction2.id != X86_INS_RET, false, ""); // function end
        return true;
    }
    default:
        RETURNERROR(false, "Instruction not push!");
    }
}

bool DissasemblerIntel::IsFunctionEndInstruction(const Instruction& instruction) const
{
    switch (instruction.id)
    {
        // case X86_INS_IRET:  // Interrupt return (16-bit operand size).
        // case X86_INS_IRETD: // Interrupt return (32-bit operand size).
        // case X86_INS_IRETQ: // Interrupt return (64-bit operand size).

    case X86_INS_RET:   // Near return to calling procedure.
    case X86_INS_RETF:  // Far return to calling procedure.
    case X86_INS_RETFQ: // Far return to calling procedure (pops address and code segment).
        return true;
    case X86_INS_SYSRET:  // Return to compatibility mode from fast system call.
    case X86_INS_SYSRETQ: // Return to 64-bit mode from fast system call.
        return true;
    default:
        RETURNERROR(false, "");
    }
}

DissasemblerIntel::~DissasemblerIntel()
{
    CHECKRET(cs_close(&handle), "");
    handle = 0;
}
} // namespace GView::Dissasembly
