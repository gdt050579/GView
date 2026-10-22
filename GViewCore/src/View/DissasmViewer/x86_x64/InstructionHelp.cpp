#include "X86InstructionInfo.hpp"

#include <unordered_map>

using namespace AppCUI;
using namespace GView::View::DissasmViewer;

namespace
{
using HelpTable = std::unordered_map<std::string_view, std::string_view>;

// the conditions of jcc / setcc / cmovcc
const HelpTable& X86Conditions()
{
    static const HelpTable conditions = {
        { "o", "overflow (OF = 1)" },
        { "no", "no overflow (OF = 0)" },
        { "b", "below, unsigned < (CF = 1)" },
        { "c", "below, unsigned < (CF = 1)" },
        { "nae", "below, unsigned < (CF = 1)" },
        { "ae", "above or equal, unsigned >= (CF = 0)" },
        { "nb", "above or equal, unsigned >= (CF = 0)" },
        { "nc", "above or equal, unsigned >= (CF = 0)" },
        { "e", "equal / zero (ZF = 1)" },
        { "z", "equal / zero (ZF = 1)" },
        { "ne", "not equal / not zero (ZF = 0)" },
        { "nz", "not equal / not zero (ZF = 0)" },
        { "be", "below or equal, unsigned <= (CF = 1 or ZF = 1)" },
        { "na", "below or equal, unsigned <= (CF = 1 or ZF = 1)" },
        { "a", "above, unsigned > (CF = 0 and ZF = 0)" },
        { "nbe", "above, unsigned > (CF = 0 and ZF = 0)" },
        { "s", "sign: negative (SF = 1)" },
        { "ns", "no sign: positive or zero (SF = 0)" },
        { "p", "parity even (PF = 1)" },
        { "pe", "parity even (PF = 1)" },
        { "np", "parity odd (PF = 0)" },
        { "po", "parity odd (PF = 0)" },
        { "l", "less, signed < (SF != OF)" },
        { "nge", "less, signed < (SF != OF)" },
        { "ge", "greater or equal, signed >= (SF = OF)" },
        { "nl", "greater or equal, signed >= (SF = OF)" },
        { "le", "less or equal, signed <= (ZF = 1 or SF != OF)" },
        { "ng", "less or equal, signed <= (ZF = 1 or SF != OF)" },
        { "g", "greater, signed > (ZF = 0 and SF = OF)" },
        { "nle", "greater, signed > (ZF = 0 and SF = OF)" },
    };
    return conditions;
}

const HelpTable& ArmConditions()
{
    static const HelpTable conditions = {
        { "eq", "equal (Z = 1)" },
        { "ne", "not equal (Z = 0)" },
        { "hs", "unsigned >= (C = 1)" },
        { "cs", "unsigned >= (C = 1)" },
        { "lo", "unsigned < (C = 0)" },
        { "cc", "unsigned < (C = 0)" },
        { "mi", "negative (N = 1)" },
        { "pl", "positive or zero (N = 0)" },
        { "vs", "overflow (V = 1)" },
        { "vc", "no overflow (V = 0)" },
        { "hi", "unsigned > (C = 1 and Z = 0)" },
        { "ls", "unsigned <= (C = 0 or Z = 1)" },
        { "ge", "signed >= (N = V)" },
        { "lt", "signed < (N != V)" },
        { "gt", "signed > (Z = 0 and N = V)" },
        { "le", "signed <= (Z = 1 or N != V)" },
        { "al", "always" },
    };
    return conditions;
}

const HelpTable& X86Help()
{
    static const HelpTable help = {
        { "mov", "copy the source to the destination" },
        { "movabs", "copy a 64 bit immediate / absolute address" },
        { "movzx", "copy with zero extension" },
        { "movsx", "copy with sign extension" },
        { "movsxd", "copy with sign extension (32 -> 64 bits)" },
        { "lea", "load the address: destination = the computed address (no memory read)" },
        { "push", "push on the stack (rsp -= size)" },
        { "pop", "pop from the stack (rsp += size)" },
        { "pushfq", "push the flags" },
        { "pushfd", "push the flags" },
        { "popfq", "pop the flags" },
        { "popfd", "pop the flags" },
        { "add", "add: destination += source (sets the flags)" },
        { "adc", "add with carry: destination += source + CF" },
        { "sub", "subtract: destination -= source (sets the flags)" },
        { "sbb", "subtract with borrow: destination -= source + CF" },
        { "inc", "add 1 (CF unchanged)" },
        { "dec", "subtract 1 (CF unchanged)" },
        { "neg", "two's complement negation: destination = -destination" },
        { "not", "bitwise not" },
        { "and", "bitwise and (sets the flags)" },
        { "or", "bitwise or (sets the flags)" },
        { "xor", "bitwise xor (xor reg, reg: zero)" },
        { "test", "bitwise and that only sets the flags" },
        { "cmp", "compare: a subtraction that only sets the flags" },
        { "mul", "unsigned multiply by rax / eax (the result in rdx:rax)" },
        { "imul", "signed multiply" },
        { "div", "unsigned divide rdx:rax (quotient in rax, remainder in rdx)" },
        { "idiv", "signed divide rdx:rax (quotient in rax, remainder in rdx)" },
        { "shl", "shift left (multiply by 2^n)" },
        { "sal", "shift left (multiply by 2^n)" },
        { "shr", "logical shift right (unsigned divide by 2^n)" },
        { "sar", "arithmetic shift right (signed divide by 2^n, rounded down)" },
        { "rol", "rotate left" },
        { "ror", "rotate right" },
        { "rcl", "rotate left through CF" },
        { "rcr", "rotate right through CF" },
        { "shld", "double precision shift left (bits from the source)" },
        { "shrd", "double precision shift right (bits from the source)" },
        { "bt", "copy a bit to CF" },
        { "bts", "copy a bit to CF, then set it" },
        { "btr", "copy a bit to CF, then clear it" },
        { "btc", "copy a bit to CF, then complement it" },
        { "bsf", "the index of the lowest set bit" },
        { "bsr", "the index of the highest set bit" },
        { "tzcnt", "count the trailing zero bits" },
        { "lzcnt", "count the leading zero bits" },
        { "popcnt", "count the set bits" },
        { "bswap", "reverse the byte order" },
        { "xchg", "exchange (with memory: atomic)" },
        { "xadd", "exchange and add" },
        { "cmpxchg", "compare with rax / eax: equal -> store the source, else load rax / eax" },
        { "cmpxchg8b", "compare and exchange 8 bytes (edx:eax with ecx:ebx)" },
        { "cmpxchg16b", "compare and exchange 16 bytes (rdx:rax with rcx:rbx)" },
        { "cbw", "sign extend al into ax" },
        { "cwde", "sign extend ax into eax" },
        { "cdqe", "sign extend eax into rax" },
        { "cwd", "sign extend ax into dx:ax (before idiv)" },
        { "cdq", "sign extend eax into edx:eax (before idiv)" },
        { "cqo", "sign extend rax into rdx:rax (before idiv)" },
        { "call", "call: push the return address, then jump" },
        { "ret", "return: pop the return address (ret n: then remove n bytes of arguments)" },
        { "retf", "far return" },
        { "jmp", "jump" },
        { "jcxz", "jump if cx is 0" },
        { "jecxz", "jump if ecx is 0" },
        { "jrcxz", "jump if rcx is 0" },
        { "loop", "decrement rcx / ecx, jump if it is not 0" },
        { "loope", "decrement rcx / ecx, jump if it is not 0 and ZF = 1" },
        { "loopne", "decrement rcx / ecx, jump if it is not 0 and ZF = 0" },
        { "leave", "mov rsp, rbp; pop rbp (the epilogue of a frame)" },
        { "enter", "push rbp; mov rbp, rsp; sub rsp, n (build a frame)" },
        { "nop", "no operation (padding)" },
        { "int3", "breakpoint trap (the debuggers; padding of MSVC)" },
        { "int", "software interrupt (int 0x29: __fastfail; int 0x2e / 0x80: a system call)" },
        { "into", "interrupt 4 if OF = 1" },
        { "syscall", "system call (its number in rax)" },
        { "sysenter", "system call (its number in eax)" },
        { "hlt", "halt the processor until an interrupt (privileged)" },
        { "ud2", "undefined instruction: raises #UD (unreachable code, __builtin_trap)" },
        { "cpuid", "processor identification (the anti-VM checks use it)" },
        { "rdtsc", "read the time-stamp counter into edx:eax (timing, anti-debug)" },
        { "rdtscp", "read the time-stamp counter and the processor id (timing, anti-debug)" },
        { "rdrand", "a hardware random number" },
        { "rdseed", "a hardware random seed" },
        { "pause", "spin-wait loop hint" },
        { "cld", "clear the direction flag (the string instructions go up)" },
        { "std", "set the direction flag (the string instructions go down)" },
        { "clc", "clear CF" },
        { "stc", "set CF" },
        { "cmc", "complement CF" },
        { "cli", "disable the interrupts (privileged)" },
        { "sti", "enable the interrupts (privileged)" },
        { "movsb", "copy a byte from [rsi] to [rdi] (rep: rcx times)" },
        { "movsw", "copy a word from [rsi] to [rdi] (rep: rcx times)" },
        { "movsq", "copy a qword from [rsi] to [rdi] (rep: rcx times)" },
        { "stosb", "store al to [rdi] (rep: rcx times, memset)" },
        { "stosw", "store ax to [rdi] (rep: rcx times)" },
        { "stosd", "store eax to [rdi] (rep: rcx times)" },
        { "stosq", "store rax to [rdi] (rep: rcx times)" },
        { "lodsb", "load a byte from [rsi] into al" },
        { "lodsw", "load a word from [rsi] into ax" },
        { "lodsd", "load a dword from [rsi] into eax" },
        { "lodsq", "load a qword from [rsi] into rax" },
        { "scasb", "compare al with [rdi] (repne: strlen / memchr)" },
        { "scasw", "compare ax with [rdi]" },
        { "scasd", "compare eax with [rdi]" },
        { "scasq", "compare rax with [rdi]" },
        { "cmpsb", "compare [rsi] with [rdi] (repe: memcmp)" },
        { "cmpsw", "compare the words at [rsi] and [rdi]" },
        { "cmpsq", "compare the qwords at [rsi] and [rdi]" },
        { "xlatb", "al = [rbx + al] (a table lookup)" },
        { "lahf", "load the flags into ah" },
        { "sahf", "store ah into the flags" },
        { "endbr64", "indirect branch target (CET): no operation" },
        { "endbr32", "indirect branch target (CET): no operation" },
        { "mfence", "memory barrier (loads and stores)" },
        { "lfence", "load barrier (speculation barrier)" },
        { "sfence", "store barrier" },
        { "clflush", "flush a cache line" },
        { "movaps", "move 128 bits (aligned)" },
        { "movups", "move 128 bits (unaligned)" },
        { "movapd", "move 128 bits (aligned)" },
        { "movupd", "move 128 bits (unaligned)" },
        { "movdqa", "move 128 bits (aligned)" },
        { "movdqu", "move 128 bits (unaligned)" },
        { "movd", "move 32 bits between a general and a vector register" },
        { "movq", "move 64 bits between a general and a vector register" },
        { "movss", "move a scalar float (32 bits)" },
        { "pxor", "bitwise xor of vectors (with itself: zero)" },
        { "pand", "bitwise and of vectors" },
        { "por", "bitwise or of vectors" },
        { "pshufb", "shuffle the bytes of a vector" },
        { "pshufd", "shuffle the dwords of a vector" },
        { "pcmpeqb", "compare the bytes of two vectors for equality (strlen / memchr)" },
        { "pmovmskb", "a mask of the top bits of the bytes of a vector" },
        { "crc32", "accumulate a CRC32C" },
        { "vzeroupper", "clear the upper halves of the ymm registers" },
        { "xgetbv", "read an extended control register (the AVX state)" },
        { "sgdt", "store the GDT register (anti-VM checks)" },
        { "sidt", "store the IDT register (anti-VM checks: the red pill)" },
        { "sldt", "store the LDT register (anti-VM checks)" },
        { "smsw", "store the machine status word (anti-VM checks)" },
        { "str", "store the task register (anti-VM checks)" },
        { "in", "read an I/O port (privileged; the VMware backdoor)" },
        { "out", "write an I/O port (privileged)" },
        { "aesenc", "one round of AES encryption" },
        { "aesenclast", "the last round of AES encryption" },
        { "aesdec", "one round of AES decryption" },
        { "aesdeclast", "the last round of AES decryption" },
        { "aeskeygenassist", "AES key expansion" },
        { "pclmulqdq", "carry-less multiply (GCM, CRC)" },
    };
    return help;
}

const HelpTable& Arm64Help()
{
    static const HelpTable help = {
        { "mov", "copy a register / an immediate" },
        { "movz", "move a 16 bit immediate, zero the other bits" },
        { "movk", "insert a 16 bit immediate, keep the other bits" },
        { "movn", "move the inverted immediate" },
        { "adr", "the address of a label (pc relative)" },
        { "adrp", "the address of the 4 KB page of a label (then add / ldr with its offset in the page)" },
        { "add", "add" },
        { "adds", "add, sets the flags" },
        { "sub", "subtract" },
        { "subs", "subtract, sets the flags" },
        { "cmp", "compare: a subtraction that only sets the flags" },
        { "cmn", "compare negative: an addition that only sets the flags" },
        { "tst", "bitwise and that only sets the flags" },
        { "and", "bitwise and" },
        { "ands", "bitwise and, sets the flags" },
        { "orr", "bitwise or" },
        { "eor", "bitwise xor" },
        { "bic", "bit clear: and with the inverted operand" },
        { "orn", "or with the inverted operand" },
        { "eon", "xor with the inverted operand" },
        { "mvn", "bitwise not" },
        { "neg", "negate" },
        { "mul", "multiply" },
        { "madd", "multiply-add: d = a + n * m" },
        { "msub", "multiply-subtract: d = a - n * m (with sdiv / udiv: the remainder)" },
        { "mneg", "multiply-negate: d = -(n * m)" },
        { "smull", "signed 32 x 32 -> 64 bit multiply" },
        { "umull", "unsigned 32 x 32 -> 64 bit multiply" },
        { "smulh", "the high 64 bits of the signed 128 bit product" },
        { "umulh", "the high 64 bits of the unsigned 128 bit product (divisions by a constant)" },
        { "sdiv", "signed divide (no remainder: msub gives it)" },
        { "udiv", "unsigned divide (no remainder: msub gives it)" },
        { "lsl", "logical shift left" },
        { "lsr", "logical shift right" },
        { "asr", "arithmetic shift right" },
        { "ror", "rotate right" },
        { "ubfx", "extract a bit field (zero extended)" },
        { "sbfx", "extract a bit field (sign extended)" },
        { "ubfiz", "insert a bit field into zeros" },
        { "sbfiz", "insert a sign extended bit field into zeros" },
        { "bfi", "insert a bit field" },
        { "bfxil", "extract a bit field into the low bits" },
        { "sxtw", "sign extend a word" },
        { "sxtb", "sign extend a byte" },
        { "sxth", "sign extend a halfword" },
        { "uxtb", "zero extend a byte" },
        { "uxth", "zero extend a halfword" },
        { "extr", "extract bits from a pair of registers" },
        { "clz", "count the leading zero bits" },
        { "rbit", "reverse the bits" },
        { "rev", "reverse the byte order" },
        { "rev16", "reverse the bytes of every halfword" },
        { "rev32", "reverse the bytes of every word" },
        { "ldr", "load a register from memory" },
        { "ldrb", "load a byte (zero extended)" },
        { "ldrh", "load a halfword (zero extended)" },
        { "ldrsb", "load a byte (sign extended)" },
        { "ldrsh", "load a halfword (sign extended)" },
        { "ldrsw", "load a word (sign extended to 64 bits)" },
        { "ldur", "load a register (unscaled offset)" },
        { "ldurb", "load a byte (unscaled offset)" },
        { "ldurh", "load a halfword (unscaled offset)" },
        { "str", "store a register to memory" },
        { "strb", "store a byte" },
        { "strh", "store a halfword" },
        { "stur", "store a register (unscaled offset)" },
        { "sturb", "store a byte (unscaled offset)" },
        { "sturh", "store a halfword (unscaled offset)" },
        { "ldp", "load a pair of registers" },
        { "stp", "store a pair of registers (stp x29, x30, [sp, #-n]!: a prologue)" },
        { "ldpsw", "load a pair of words (sign extended)" },
        { "ldxr", "load exclusive (an atomic loop with stxr)" },
        { "stxr", "store exclusive (status 0: done)" },
        { "ldaxr", "load-acquire exclusive" },
        { "stlxr", "store-release exclusive" },
        { "ldar", "load-acquire" },
        { "stlr", "store-release" },
        { "cas", "compare and swap (atomic)" },
        { "casa", "compare and swap, acquire (atomic)" },
        { "casal", "compare and swap, acquire and release (atomic)" },
        { "swp", "swap (atomic)" },
        { "ldadd", "atomic add (returns the old value)" },
        { "b", "branch" },
        { "bl", "branch with link: call (the return address in x30)" },
        { "br", "branch to a register" },
        { "blr", "call a register" },
        { "ret", "return (to x30)" },
        { "retaa", "authenticate the return address, then return" },
        { "retab", "authenticate the return address, then return" },
        { "cbz", "branch if the register is zero" },
        { "cbnz", "branch if the register is not zero" },
        { "tbz", "branch if the bit is zero" },
        { "tbnz", "branch if the bit is not zero" },
        { "csel", "select the first register if the condition holds, else the second" },
        { "csinc", "select the first register if the condition holds, else the second + 1" },
        { "csinv", "select the first register if the condition holds, else not the second" },
        { "csneg", "select the first register if the condition holds, else -the second" },
        { "cset", "1 if the condition holds, else 0" },
        { "csetm", "all ones if the condition holds, else 0" },
        { "cinc", "+1 if the condition holds" },
        { "cinv", "invert if the condition holds" },
        { "cneg", "negate if the condition holds" },
        { "ccmp", "compare if the condition holds, else set the flags to the immediate" },
        { "ccmn", "compare negative if the condition holds, else set the flags to the immediate" },
        { "nop", "no operation (padding)" },
        { "brk", "breakpoint trap (__builtin_trap)" },
        { "svc", "system call (supervisor call)" },
        { "hvc", "hypervisor call" },
        { "smc", "secure monitor call" },
        { "hlt", "halt (external debug)" },
        { "udf", "undefined instruction: a trap" },
        { "dmb", "data memory barrier" },
        { "dsb", "data synchronization barrier" },
        { "isb", "instruction synchronization barrier" },
        { "mrs", "read a system register (mrs x0, tpidr_el0: the thread pointer)" },
        { "msr", "write a system register" },
        { "paciasp", "sign the return address (pointer authentication)" },
        { "pacibsp", "sign the return address (pointer authentication)" },
        { "autiasp", "authenticate the return address (pointer authentication)" },
        { "autibsp", "authenticate the return address (pointer authentication)" },
        { "bti", "branch target (BTI): no operation" },
        { "fmov", "move to / from a floating point register" },
        { "fadd", "floating point add" },
        { "fsub", "floating point subtract" },
        { "fmul", "floating point multiply" },
        { "fdiv", "floating point divide" },
        { "fsqrt", "floating point square root" },
        { "fcmp", "floating point compare" },
        { "scvtf", "convert a signed integer to floating point" },
        { "ucvtf", "convert an unsigned integer to floating point" },
        { "fcvtzs", "convert floating point to a signed integer (toward zero)" },
        { "fcvtzu", "convert floating point to an unsigned integer (toward zero)" },
        { "prfm", "prefetch (a hint)" },
        { "yield", "spin-wait loop hint" },
        { "wfe", "wait for an event" },
        { "wfi", "wait for an interrupt" },
        { "sev", "send an event" },
    };
    return help;
}

const HelpTable& Arm32Help()
{
    static const HelpTable help = {
        { "push", "store registers on the stack" },
        { "pop", "load registers from the stack (with pc: return)" },
        { "bx", "branch to a register (bit 0: Thumb; bx lr: return)" },
        { "blx", "call (switches between ARM and Thumb)" },
        { "ldm", "load multiple registers" },
        { "stm", "store multiple registers" },
        { "ldmia", "load multiple registers, increment after" },
        { "stmdb", "store multiple registers, decrement before" },
        { "movw", "move a 16 bit immediate into the low half (zero the top)" },
        { "movt", "move a 16 bit immediate into the top half" },
        { "mla", "multiply-accumulate: d = a + n * m" },
        { "mls", "multiply-subtract: d = a - n * m" },
        { "rsb", "reverse subtract: d = operand - n" },
        { "ldrd", "load two registers" },
        { "strd", "store two registers" },
        { "ldrex", "load exclusive (an atomic loop with strex)" },
        { "strex", "store exclusive (status 0: done)" },
        { "tbb", "table branch with byte offsets (a switch)" },
        { "tbh", "table branch with halfword offsets (a switch)" },
        { "bkpt", "breakpoint" },
        { "cpsid", "disable the interrupts (privileged)" },
        { "cpsie", "enable the interrupts (privileged)" },
        { "mrc", "read a coprocessor register (mrc p15: the thread pointer)" },
        { "mcr", "write a coprocessor register" },
        { "vpush", "store floating point registers on the stack" },
        { "vpop", "load floating point registers from the stack" },
        { "vldr", "load a floating point register" },
        { "vstr", "store a floating point register" },
        { "vmov", "move between floating point / general registers" },
        { "adr", "the address of a label (pc relative)" },
    };
    return help;
}

std::string_view Find(const HelpTable& table, std::string_view name)
{
    const auto found = table.find(name);
    return found != table.end() ? found->second : std::string_view();
}

std::string DescribeX86(std::string_view mnemonic, std::string_view operands)
{
    if (const auto help = Find(X86Help(), mnemonic); !help.empty())
        return std::string(help);
    // movsd / cmpsd: the strings without operands, the SSE scalar doubles with xmm operands
    const bool vector = operands.find("xmm") != std::string_view::npos || operands.find("ymm") != std::string_view::npos;
    if (mnemonic == "movsd")
        return vector ? "move a scalar double (64 bits)" : "copy a dword from [rsi] to [rdi] (rep: rcx times)";
    if (mnemonic == "cmpsd")
        return vector ? "compare scalar doubles" : "compare the dwords at [rsi] and [rdi]";
    const auto& conditions = X86Conditions();
    for (const auto& [prefix, text] : { std::pair<std::string_view, std::string_view>{ "cmov", "move if " }, { "set", "set the byte to 1 if " }, { "j", "jump if " } })
        if (mnemonic.size() > prefix.size() && mnemonic.starts_with(prefix))
            if (const auto condition = Find(conditions, mnemonic.substr(prefix.size())); !condition.empty())
                return std::string(text) + std::string(condition) + (prefix == "set" ? ", else 0" : "");
    // SSE / AVX arithmetic: addss, mulpd, sqrtsd, ucomiss, ...
    static const HelpTable SSE_OPERATIONS = {
        { "add", "add" },       { "sub", "subtract" },          { "mul", "multiply" },        { "div", "divide" },
        { "sqrt", "square root" }, { "min", "minimum" },        { "max", "maximum" },         { "comi", "compare (sets the flags)" },
        { "ucomi", "compare, unordered (sets the flags)" },     { "and", "bitwise and" },     { "andn", "bitwise and not" },
        { "or", "bitwise or" }, { "xor", "bitwise xor (with itself: zero)" }, { "rcp", "approximate reciprocal" },
        { "rsqrt", "approximate reciprocal square root" },      { "unpckl", "interleave the low halves" },
        { "unpckh", "interleave the high halves" },             { "shuf", "shuffle" },        { "cmp", "compare (a mask)" },
    };
    if (mnemonic.size() > 2) {
        const auto suffix = mnemonic.substr(mnemonic.size() - 2);
        const std::string_view kind = suffix == "ss" ? "a scalar float" : suffix == "sd" ? "a scalar double" : suffix == "ps" ? "packed floats"
                                                                         : suffix == "pd" ? "packed doubles" : std::string_view();
        if (!kind.empty())
            if (const auto operation = Find(SSE_OPERATIONS, mnemonic.substr(0, mnemonic.size() - 2)); !operation.empty())
                return std::string(operation) + " (" + std::string(kind) + ")";
    }
    if (mnemonic.starts_with("cvt"))
        return "convert between integer / floating point formats";
    if (mnemonic.starts_with("prefetch"))
        return "prefetch a cache line (a hint)";
    if (mnemonic.starts_with("sha1") || mnemonic.starts_with("sha256"))
        return "a step of SHA hashing";
    // AVX: the v form of an SSE instruction
    if (mnemonic.size() > 1 && mnemonic.front() == 'v')
        if (auto help = DescribeX86(mnemonic.substr(1), operands); !help.empty())
            return help + " (AVX)";
    return {};
}

std::string DescribeArm(std::string_view mnemonic, bool arm64)
{
    // 32 bit ARM: its own names first, then the names it shares with ARM64 (add, ldr, b, bl, cmp, ...)
    if (!arm64)
        if (const auto help = Find(Arm32Help(), mnemonic); !help.empty())
            return std::string(help);
    if (const auto help = Find(Arm64Help(), mnemonic); !help.empty())
        return std::string(help);
    const auto& conditions = ArmConditions();
    // ARM64: b.eq / b.ne ...
    if (mnemonic.starts_with("b.") && mnemonic.size() > 2)
        if (const auto condition = Find(conditions, mnemonic.substr(2)); !condition.empty())
            return "branch if " + std::string(condition);
    if (arm64)
        return {};
    // Thumb: the width qualifiers (add.w, b.n)
    if (mnemonic.ends_with(".w") || mnemonic.ends_with(".n"))
        return DescribeArm(mnemonic.substr(0, mnemonic.size() - 2), false);
    // 32 bit ARM: the condition suffix (bne, moveq, ldrne, bxlt) and the flags suffix (adds, movs)
    if (mnemonic.size() > 2)
        if (const auto condition = Find(conditions, mnemonic.substr(mnemonic.size() - 2)); !condition.empty())
            if (auto help = DescribeArm(mnemonic.substr(0, mnemonic.size() - 2), false); !help.empty())
                return help + ", if " + std::string(condition);
    if (mnemonic.size() > 1 && mnemonic.back() == 's')
        if (auto help = DescribeArm(mnemonic.substr(0, mnemonic.size() - 1), false); !help.empty())
            return help + ", sets the flags";
    // it / itt / ite / itete ...: an if-then block
    if (mnemonic.size() >= 2 && mnemonic.size() <= 5 && mnemonic.starts_with("it") &&
        mnemonic.find_first_not_of("te", 2) == std::string_view::npos)
        return "if-then block: the next 1 to 4 instructions are conditional";
    return {};
}
} // namespace

std::string GView::View::DissasmViewer::DescribeInstruction(std::string_view mnemonic, std::string_view operands, DissasmArch arch)
{
    if (mnemonic.empty())
        return {};
    if (IsArmArch(arch))
        return DescribeArm(mnemonic, arch == DissasmArch::Arm64);
    // the prefixes: rep movsb, lock cmpxchg, bnd jmp, notrack jmp
    std::string prefixes;
    for (;;) {
        const auto space = mnemonic.find(' ');
        if (space == std::string_view::npos)
            break;
        const auto prefix = mnemonic.substr(0, space);
        if (prefix == "lock")
            prefixes += "atomic: ";
        else if (prefix == "rep" || prefix == "repe" || prefix == "repz" || prefix == "repne" || prefix == "repnz")
            prefixes += prefix == "rep" ? "repeated rcx times: " : (prefix == "repe" || prefix == "repz" ? "repeated while equal: " : "repeated while not equal: ");
        mnemonic = mnemonic.substr(space + 1); // bnd / notrack / xacquire / xrelease: nothing to say
    }
    auto help = DescribeX86(mnemonic, operands);
    return help.empty() ? help : prefixes + help;
}
