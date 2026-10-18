
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include <algorithm>
#include <cstdio>
using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

LocalString<64> FormatFunctionName(uint64 functionAddress, const char* prefix)
{
    NumericFormatter formatter;
    const auto sv = formatter.ToHex(functionAddress);
    LocalString<64> callName;
    callName.Add(prefix);
    // Pad to 9 hex digits by hand. "%09s" relied on the '0' flag with a string conversion, which is undefined
    // behaviour: MSVC pads with zeros, glibc and Apple libc with spaces, so the names differed per platform.
    if (sv.size() < 9) {
        callName.AddChars('0', static_cast<uint32>(9 - sv.size()));
    }
    callName.Add(sv);
    return callName;
}

namespace
{
int32 HexDigitValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
bool IsNameCharacter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
bool CanPrecedeNumber(char c)
{
    return c == ' ' || c == '[' || c == ',' || c == '+' || c == '-' || c == '*' || c == ':' || c == '#'; // ARM64: #0x10
}
} // namespace

std::vector<OperandNumber> FindOperandNumbers(std::string_view operands)
{
    std::vector<OperandNumber> numbers;
    const auto size = static_cast<uint32>(operands.size());
    uint32 pos      = 0;
    while (pos < size) {
        const char c = operands[pos];
        if (c < '0' || c > '9' || (pos > 0 && !CanPrecedeNumber(operands[pos - 1]))) {
            pos++;
            continue;
        }

        const uint32 start = pos;
        const bool isHex   = c == '0' && pos + 2 < size && operands[pos + 1] == 'x' && HexDigitValue(operands[pos + 2]) >= 0;
        uint64 value       = 0;
        bool fits          = true;
        if (isHex) {
            pos += 2;
            for (; pos < size && HexDigitValue(operands[pos]) >= 0; pos++) {
                fits  = fits && (value >> 60) == 0;
                value = (value << 4) | static_cast<uint64>(HexDigitValue(operands[pos]));
            }
        } else {
            for (; pos < size && operands[pos] >= '0' && operands[pos] <= '9'; pos++) {
                const auto digit = static_cast<uint64>(operands[pos] - '0');
                fits             = fits && value <= (UINT64_MAX - digit) / 10u;
                value            = value * 10u + digit;
            }
        }
        // a number glued to a name (e.g. "1st") or one that does not fit in 64 bits is not a value
        if (pos < size && IsNameCharacter(operands[pos])) {
            while (pos < size && IsNameCharacter(operands[pos]))
                pos++;
            continue;
        }
        if (fits)
            numbers.push_back({ start, pos - start, value, isHex });
    }
    return numbers;
}

std::string FormatOperandNumbers(std::string_view operands, uint32 decimalMask, uint32* trackedPosition)
{
    std::string result;
    result.reserve(operands.size() + 16u);

    const auto numbers   = FindOperandNumbers(operands);
    const uint32 tracked = trackedPosition ? *trackedPosition : 0;
    uint32 copied        = 0;
    for (uint32 index = 0; index < static_cast<uint32>(numbers.size()) && index < 32u; index++) {
        const auto& number = numbers[index];
        if (!number.isHex || (decimalMask & (1u << index)) == 0)
            continue;
        result.append(operands.substr(copied, number.start - copied));
        const auto decimal = std::to_string(number.value);
        if (trackedPosition && number.start < tracked)
            *trackedPosition = *trackedPosition + static_cast<uint32>(decimal.size()) - number.length;
        result.append(decimal);
        copied = number.start + number.length;
    }
    result.append(operands.substr(copied));
    return result;
}

AsmOffsetLine SearchForClosestAsmOffsetLineByOffset(const std::vector<AsmOffsetLine>& values, uint64 searchedOffset, uint32* index)
{
    assert(!values.empty());
    // the last cached offset placed before (or at) the searched one, the first one when the searched offset is before the code
    auto it = std::upper_bound(values.begin(), values.end(), searchedOffset, [](uint64 offset, const AsmOffsetLine& entry) { return offset < entry.offset; });
    if (it != values.begin())
        --it;
    if (index)
        *index = static_cast<uint32>(it - values.begin());
    return *it;
}

uint64 GetCachedOffsetWindowEnd(const DissasmCodeZone* zone, uint32 cachedOffsetIndex)
{
    const auto& offsets = zone->cachedCodeOffsets;
    if (static_cast<size_t>(cachedOffsetIndex) + 1u < offsets.size())
        return offsets[cachedOffsetIndex + 1u].offset - offsets[0].offset + DISSASM_MAX_LINE_SIZE;
    // after the last cached offset there are less than DISSASM_INSTRUCTION_OFFSET_MARGIN bytes of decoded instructions
    return offsets[cachedOffsetIndex].offset - offsets[0].offset + DISSASM_INSTRUCTION_OFFSET_MARGIN + 2 * DISSASM_MAX_LINE_SIZE;
}

namespace
{
// int3, nop (90, 66 90) or a long nop (0f 1f .., 66 0f 1f .., 66 2e 0f 1f .., 66 66 2e ..)
bool IsPaddingStart(const uint8_t* code, size_t size)
{
    if (code[0] == 0xCC || code[0] == 0x90)
        return true;
    if (size < 2)
        return false;
    if (code[0] == 0x0F)
        return code[1] == 0x1F;
    return code[0] == 0x66 && (code[1] == 0x90 || code[1] == 0x0F || code[1] == 0x2E || code[1] == 0x66);
}

// The padding from the address up to the next 16 bytes aligned address (or up to the first byte that is not padding): one line,
// "align N" (N: the alignment of its end, at most 0x10). Only a run of at least 2 bytes that is not longer than N: a lone nop or int3
// stays an instruction. The run never needs more than DISSASM_MAX_LINE_SIZE bytes: the same line from any decoding window.
bool DecodeX86Padding(csh handle, const uint8_t** code, size_t* size, uint64_t* address, cs_insn* insn, size_t available, AppCUI::uint64 alignmentBase)
{
    const AppCUI::uint64 start    = *address + alignmentBase;
    const AppCUI::uint64 chunkEnd = (start | 0xF) + 1;
    const size_t limit            = static_cast<size_t>(std::min<AppCUI::uint64>(chunkEnd - start, available));
    size_t length                 = 0;
    while (length < limit) {
        if ((*code)[length] == 0xCC) {
            length++;
            continue;
        }
        const uint8_t* data = *code + length;
        size_t left         = limit - length;
        uint64_t at         = *address + length;
        if (!IsPaddingStart(data, left) || !cs_disasm_iter(handle, &data, &left, &at, insn) || insn->id != X86_INS_NOP)
            break;
        length += insn->size;
    }
    const AppCUI::uint64 end       = start + length;
    const AppCUI::uint64 alignment = std::min<AppCUI::uint64>(end & (~end + 1), 0x10); // the lowest set bit
    if (length < 2 || alignment < 2 || length > alignment)
        return false;

    insn->id = 0; // X86_INS_INVALID: a data line, no flow
    if (insn->detail)
        memset(insn->detail, 0, sizeof(cs_detail));
    insn->address = *address;
    insn->size    = static_cast<uint16_t>(length);
    memset(insn->bytes, 0, sizeof(insn->bytes));
    memcpy(insn->bytes, *code, std::min(length, sizeof(insn->bytes)));
    snprintf(insn->mnemonic, sizeof(insn->mnemonic), "align");
    snprintf(insn->op_str, sizeof(insn->op_str), "0x%x", static_cast<unsigned int>(alignment));
    *code += length;
    *size -= length;
    *address += length;
    return true;
}
// a line that is not an instruction (X86_INS_INVALID / ARM64_INS_INVALID: no flow): db / .word / align
void SetDataLine(cs_insn* insn, uint64_t address, const uint8_t* bytes, size_t length, const char* mnemonic, const char* operands)
{
    insn->id = 0;
    if (insn->detail)
        memset(insn->detail, 0, sizeof(cs_detail)); // no groups / operands (the previous instruction left its own)
    insn->address = address;
    insn->size    = static_cast<uint16_t>(length);
    memset(insn->bytes, 0, sizeof(insn->bytes));
    memcpy(insn->bytes, bytes, std::min(length, sizeof(insn->bytes)));
    snprintf(insn->mnemonic, sizeof(insn->mnemonic), "%s", mnemonic);
    snprintf(insn->op_str, sizeof(insn->op_str), "%s", operands);
}

// An entry of a jump table: a data line of `unit` bytes (db / dw / dd / dq, ARM: db / .short / .word / .quad); a last entry shorter than the
// unit (the end of the table, of the code) is a db line
bool DecodeTableLine(const uint8_t** code, size_t* size, uint64_t* address, cs_insn* insn, size_t available, uint8_t unit, bool isArm)
{
    if (available == 0)
        return false;
    const bool isUtf16 = unit == DissasmInstructionSet::UTF16_STRING && available >= 2;
    if (unit == DissasmInstructionSet::ASCII_STRING || isUtf16) {
        // a string defined by the user: up to DISSASM_MAX_LINE_SIZE bytes per line, db "text", 0 / du "text", 0 (UTF-16: 2 bytes per
        // character); what is not printable as numbers
        const size_t charSize = isUtf16 ? 2 : 1;
        const size_t width    = std::min<size_t>(available, DISSASM_MAX_LINE_SIZE) / charSize * charSize;
        std::string text;
        bool inQuotes = false;
        for (size_t index = 0; index < width; index += charSize) {
            const uint32_t value = isUtf16 ? static_cast<uint32_t>((*code)[index] | ((*code)[index + 1] << 8)) : (*code)[index];
            if (value >= 0x20 && value < 0x7F && value != '"') {
                if (!inQuotes)
                    text += text.empty() ? "\"" : ", \"";
                inQuotes = true;
                text.push_back(static_cast<char>(value));
                continue;
            }
            if (inQuotes)
                text.push_back('"');
            inQuotes = false;
            char number[8];
            snprintf(number, sizeof(number), value == 0 ? "0" : (isUtf16 ? "0x%04x" : "0x%02x"), static_cast<unsigned int>(value));
            text += text.empty() ? "" : ", ";
            text += number;
        }
        if (inQuotes)
            text.push_back('"');
        SetDataLine(insn, *address, *code, width, isUtf16 ? "du" : (isArm ? ".ascii" : "db"), text.c_str());
        *code += width;
        *size -= width;
        *address += width;
        return true;
    }
    const size_t width = available >= unit && unit <= 8 ? unit : 1; // the last byte of a UTF-16 string of an odd size: db
    uint64_t value     = 0;
    for (size_t index = 0; index < width; index++)
        value |= static_cast<uint64_t>((*code)[index]) << (8 * index);
    char text[24];
    const char* mnemonic = "db";
    switch (width) {
    case 2:
        mnemonic = isArm ? ".short" : "dw";
        snprintf(text, sizeof(text), "0x%04llx", static_cast<unsigned long long>(value));
        break;
    case 4:
        mnemonic = isArm ? ".word" : "dd";
        snprintf(text, sizeof(text), "0x%08llx", static_cast<unsigned long long>(value));
        break;
    case 8:
        mnemonic = isArm ? ".quad" : "dq";
        snprintf(text, sizeof(text), "0x%016llx", static_cast<unsigned long long>(value));
        break;
    default:
        snprintf(text, sizeof(text), "0x%02llx", static_cast<unsigned long long>(value));
        break;
    }
    SetDataLine(insn, *address, *code, width, mnemonic, text);
    *code += width;
    *size -= width;
    *address += width;
    return true;
}

// ARM64: 4 bytes instructions. A run of nops up to the next 16 bytes aligned address is one align line (as on x86, at least 2 of them,
// not longer than the alignment of its end); an undecodable word is a data line (.word 0x..), the bytes before a boundary or the end of
// the code (less than 4) are db lines
bool DecodeArm64Line(csh handle, const uint8_t** code, size_t* size, uint64_t* address, cs_insn* insn, size_t available, AppCUI::uint64 alignmentBase)
{
    constexpr uint32_t NOP = 0xD503201F;
    const auto wordAt      = [](const uint8_t* bytes) {
        return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) | (static_cast<uint32_t>(bytes[2]) << 16) |
               (static_cast<uint32_t>(bytes[3]) << 24);
    };
    const auto advance = [code, size, address](size_t length) {
        *code += length;
        *size -= length;
        *address += length;
    };
    char text[24];
    if (alignmentBase != GView::View::DissasmViewer::DISSASM_NO_PADDING_ALIGNMENT && available >= 8 && wordAt(*code) == NOP) {
        const AppCUI::uint64 start    = *address + alignmentBase;
        const AppCUI::uint64 chunkEnd = (start | 0xF) + 1;
        const size_t limit            = static_cast<size_t>(std::min<AppCUI::uint64>(chunkEnd - start, available));
        size_t length                 = 0;
        while (length + 4 <= limit && wordAt(*code + length) == NOP)
            length += 4;
        const AppCUI::uint64 end       = start + length;
        const AppCUI::uint64 alignment = std::min<AppCUI::uint64>(end & (~end + 1), 0x10);
        if (length >= 8 && length <= alignment) {
            snprintf(text, sizeof(text), "0x%x", static_cast<unsigned int>(alignment));
            SetDataLine(insn, *address, *code, length, "align", text);
            advance(length);
            return true;
        }
    }
    if (available >= 4) {
        const uint8_t* data = *code;
        size_t left         = 4;
        uint64_t at         = *address;
        if (cs_disasm_iter(handle, &data, &left, &at, insn)) {
            advance(4);
            return true;
        }
        snprintf(text, sizeof(text), "0x%08x", static_cast<unsigned int>(wordAt(*code)));
        SetDataLine(insn, *address, *code, 4, ".word", text);
        advance(4);
        return true;
    }
    snprintf(text, sizeof(text), "0x%02x", static_cast<unsigned int>(**code));
    SetDataLine(insn, *address, *code, 1, "db", text);
    advance(1);
    return true;
}

// 32 bit ARM: the mode of the address (ARM: 4 bytes, Thumb: 2 or 4 bytes; the handle is switched to it). An undecodable instruction is a
// data line (.word 0x.. / .short 0x..); a data region (a literal pool, ELF $d) is made of .word lines; less than a unit before a boundary:
// db lines
bool DecodeArm32Line(csh handle, const uint8_t** code, size_t* size, uint64_t* address, cs_insn* insn, size_t available, ArmCodeMode mode)
{
    const auto advance = [code, size, address](size_t length) {
        *code += length;
        *size -= length;
        *address += length;
    };
    char text[24];
    const uint8_t* bytes = *code;
    const auto dataLine  = [&](size_t width) {
        if (width == 4)
            snprintf(text, sizeof(text), "0x%08x", static_cast<unsigned int>(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (static_cast<uint32_t>(bytes[3]) << 24)));
        else if (width == 2)
            snprintf(text, sizeof(text), "0x%04x", static_cast<unsigned int>(bytes[0] | (bytes[1] << 8)));
        else
            snprintf(text, sizeof(text), "0x%02x", static_cast<unsigned int>(bytes[0]));
        SetDataLine(insn, *address, bytes, width, width == 4 ? ".word" : (width == 2 ? ".short" : "db"), text);
        advance(width);
        return true;
    };
    if (mode == ArmCodeMode::Data)
        return dataLine(available >= 4 ? 4 : 1);
    const bool thumb      = mode == ArmCodeMode::Thumb;
    const size_t unitSize = thumb ? 2 : 4;
    if (available < unitSize)
        return dataLine(1);
    cs_option(handle, CS_OPT_MODE, thumb ? CS_MODE_THUMB : CS_MODE_ARM);
    const uint8_t* data = *code;
    size_t left         = std::min<size_t>(available, 4);
    uint64_t at         = *address;
    if (cs_disasm_iter(handle, &data, &left, &at, insn)) {
        advance(insn->size);
        return true;
    }
    return dataLine(unitSize);
}
} // namespace

bool DecodeX86Line(
      csh handle,
      const uint8_t** code,
      size_t* size,
      uint64_t* address,
      cs_insn* insn,
      const std::vector<AppCUI::uint64>* boundaries,
      AppCUI::uint64 alignmentBase,
      const DissasmInstructionSet* instructionSet)
{
    if (*size == 0)
        return false;
    // an instruction never ends after the next boundary
    size_t available = *size;
    if (boundaries && !boundaries->empty()) {
        const auto next = std::upper_bound(boundaries->begin(), boundaries->end(), static_cast<AppCUI::uint64>(*address));
        if (next != boundaries->end() && *next - *address < available)
            available = static_cast<size_t>(*next - *address);
    }
    // the jump tables found by the analysis: data lines of their entries; no instruction runs into a table
    if (instructionSet && !instructionSet->dataRanges.empty()) {
        if (const auto* range = instructionSet->DataRangeAt(*address)) {
            const size_t left = static_cast<size_t>(std::min<AppCUI::uint64>(range->end - *address, available));
            return DecodeTableLine(code, size, address, insn, left, range->unit, instructionSet->kind != DissasmInstructionSet::Kind::X86);
        }
        const auto nextRange = instructionSet->NextDataRangeStart(*address);
        if (nextRange.has_value() && nextRange.value() - *address < available)
            available = static_cast<size_t>(nextRange.value() - *address);
    }
    if (instructionSet && instructionSet->kind == DissasmInstructionSet::Kind::Arm64)
        return DecodeArm64Line(handle, code, size, address, insn, available, alignmentBase);
    if (instructionSet && instructionSet->kind == DissasmInstructionSet::Kind::Arm32)
        return DecodeArm32Line(handle, code, size, address, insn, available, instructionSet->ModeAt(*address));
    if (alignmentBase != DISSASM_NO_PADDING_ALIGNMENT && IsPaddingStart(*code, available) &&
        DecodeX86Padding(handle, code, size, address, insn, available, alignmentBase))
        return true;
    size_t left = available;
    if (cs_disasm_iter(handle, code, &left, address, insn)) {
        *size -= available - left;
        return true;
    }

    // cs_disasm_iter leaves the position as it is on failure: the byte becomes a data line of its own
    const uint8_t value = **code;
    insn->id            = 0; // X86_INS_INVALID: a data line, not an instruction
    if (insn->detail)
        memset(insn->detail, 0, sizeof(cs_detail)); // no groups / operands (the previous instruction left its own)
    insn->address       = *address;
    insn->size          = 1;
    memset(insn->bytes, 0, sizeof(insn->bytes));
    insn->bytes[0] = value;
    snprintf(insn->mnemonic, sizeof(insn->mnemonic), "db");
    snprintf(insn->op_str, sizeof(insn->op_str), "0x%02x", static_cast<unsigned int>(value));
    (*code)++;
    (*size)--;
    (*address)++;
    return true;
}

namespace
{
// ret, padding or undecodable bytes: the next line can start a function
bool IsFlowEndOrPadding(const cs_insn& insn)
{
    switch (insn.id) {
    case X86_INS_INVALID: // db 0x..
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
    case X86_INS_INT3:
    case X86_INS_HLT:
    case X86_INS_UD2:
    case X86_INS_NOP:
        return true;
    case X86_INS_ADD: // 00 00: zero padding
        return strcmp(insn.op_str, "byte ptr [rax], al") == 0 || strcmp(insn.op_str, "byte ptr [eax], al") == 0;
    default:
        return false;
    }
}

bool IsCalleeSavedRegister(std::string_view reg, bool is64)
{
    if (is64)
        return reg == "rbx" || reg == "rsi" || reg == "rdi" || reg == "rbp" || reg == "r12" || reg == "r13" || reg == "r14" || reg == "r15";
    return reg == "ebx" || reg == "esi" || reg == "edi" || reg == "ebp";
}

// mov qword ptr [rsp + 8], rbx: an argument / non volatile register saved in the home space (MSVC x64)
bool IsHomeSpaceSave(std::string_view operands)
{
    constexpr std::string_view prefix = "qword ptr [rsp + ";
    if (!operands.starts_with(prefix))
        return false;
    operands.remove_prefix(prefix.size());
    for (const std::string_view slot : { "8], ", "0x10], ", "0x18], ", "0x20], " }) {
        if (!operands.starts_with(slot))
            continue;
        const auto reg = operands.substr(slot.size());
        return reg == "rcx" || reg == "rdx" || reg == "r8" || reg == "r9" || reg == "rbx" || reg == "rsi" || reg == "rdi" || reg == "rbp";
    }
    return false;
}
} // namespace

std::optional<uint64> X86PrologueDetector::Next(const cs_insn& insn, uint64 fileOffset)
{
    const std::string_view operands     = insn.op_str;
    const std::string_view framePointer = is64 ? "rbp" : "ebp";
    const std::string_view frameSetup   = is64 ? "rbp, rsp" : "ebp, esp";
    const std::string_view stackSub     = is64 ? "rsp, " : "esp, ";

    const bool wasAfterPadding = afterPadding;
    const bool wasAfterJump    = afterJump;
    afterPadding               = IsFlowEndOrPadding(insn);
    afterJump                  = insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP;

    // the second line of a prologue
    const Pending previous = pending;
    pending                = Pending::None;
    const bool isPush      = insn.id == X86_INS_PUSH;
    const bool isStackSub  = insn.id == X86_INS_SUB && operands.starts_with(stackSub);
    const bool isFrameMov  = insn.id == X86_INS_MOV && operands == frameSetup;
    switch (previous) {
    case Pending::FramePush:
        if (isFrameMov || (pendingAfterPadding && (isPush || isStackSub)))
            return pendingOffset;
        break;
    case Pending::SavedRegisterPush:
        if (isPush || isStackSub || isFrameMov)
            return pendingOffset;
        break;
    case Pending::HotPatch:
        if (isPush && operands == framePointer) {
            pending = Pending::FramePush; // mov edi, edi; push ebp: the function starts at the mov
            return {};
        }
        break;
    case Pending::None:
        break;
    }

    // the first line of a prologue
    if (isPush && operands == framePointer) {
        pending             = Pending::FramePush;
        pendingOffset       = fileOffset;
        pendingAfterPadding = wasAfterPadding;
        return {};
    }
    if (insn.id == X86_INS_ENDBR32 || insn.id == X86_INS_ENDBR64)
        return (wasAfterPadding || wasAfterJump) ? std::optional<uint64>(fileOffset) : std::nullopt;
    if (!wasAfterPadding || afterPadding)
        return {}; // inside the code, or more padding

    switch (insn.id) {
    case X86_INS_MOV:
        if (!is64 && operands == "edi, edi") {
            pending             = Pending::HotPatch;
            pendingOffset       = fileOffset;
            pendingAfterPadding = true;
            return {};
        }
        if (is64 && (IsHomeSpaceSave(operands) || operands == "rax, rsp" || operands == "r11, rsp"))
            return fileOffset;
        break;
    case X86_INS_SUB:
        if (is64 && isStackSub)
            return fileOffset;
        break;
    case X86_INS_PUSH:
        if (IsCalleeSavedRegister(operands, is64)) {
            pending             = Pending::SavedRegisterPush;
            pendingOffset       = fileOffset;
            pendingAfterPadding = true;
        }
        break;
    default:
        break;
    }
    return {};
}

bool DissasmCodeLinesWalker::Next(cs_insn* insn)
{
    if (address >= codeSize)
        return false;
    // a whole instruction (or the end of the code): the same bytes as the code windows of the drawn lines, so the same lines are decoded.
    // The view is taken again for every line, nothing else can refill the data cache under it.
    const uint32 requested = static_cast<uint32>(std::min<uint64>(codeSize - address, DISSASM_MAX_LINE_SIZE));
    const auto view        = obj->GetData().Get(codeStart + address, requested, false);
    if (!view.IsValid() || view.GetLength() == 0)
        return false;
    const uint8_t* data = view.GetData();
    size_t size         = static_cast<size_t>(std::min<uint64>(view.GetLength(), requested));
    uint64_t current    = address;
    if (!DecodeX86Line(handle, &data, &size, &current, insn, boundaries, alignmentBase, instructionSet))
        return false;
    address = current;
    return true;
}

cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli)
{
    diffLines = 0;
    // the decoding position is moved below: the next drawn line has to search its cached offset again
    zone->offsetCacheMaxLine = 0;

    const uint64 codeStart = zone->cachedCodeOffsets[0].offset;
    if (offsetToReach < codeStart) {
        diffLines = UINT32_MAX;
        return nullptr;
    }

    uint32 cachedOffsetIndex = 0;
    const auto closestData   = SearchForClosestAsmOffsetLineByOffset(zone->cachedCodeOffsets, offsetToReach, &cachedOffsetIndex);
    zone->lastClosestLine    = closestData.line;
    zone->asmWindowEnd       = GetCachedOffsetWindowEnd(zone, cachedOffsetIndex);
    if (!zone->FetchCodeWindow(obj, closestData.offset - codeStart, zone->asmWindowEnd)) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        diffLines = UINT32_MAX;
        return nullptr;
    }

    const csh handle = zone->GetDecodeHandle();
    if (handle == 0) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: capstone could not be initialized!");
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);
    offsetToReach -= codeStart;
    // cs_disasm_iter takes a size_t (32 bits on 32 bit targets), asmSize is 64 bits: never alias it through a size_t pointer
    size_t remainingSize = static_cast<size_t>(zone->asmSize);
    while (zone->asmAddress <= offsetToReach) {
        // undecodable bytes are data lines (db): the same lines as the ones counted by the zone initialization
        const bool decoded =
              DecodeX86Line(handle, &zone->asmData, &remainingSize, &zone->asmAddress, insn, &zone->instructionBoundaries, zone->paddingAlignmentBase,
                            &zone->instructionSet);
        zone->asmSize      = remainingSize;
        if (!decoded) { // no bytes left: the offset is after the decoded code
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            return nullptr;
        }
        diffLines++;
    }
    diffLines += closestData.line - 1;
    return insn;
}

AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<AsmOffsetLine>& values, uint64 searchedLine, uint32* index)
{
    assert(!values.empty());
    uint32 left  = 0;
    uint32 right = static_cast<uint32>(values.size()) - 1u;
    while (left < right) {
        const uint32 mid = (left + right) / 2;
        if (searchedLine == values[mid].line) {
            if (index)
                *index = mid;
            return values[mid];
        }
        if (searchedLine < values[mid].line)
            right = mid - 1;
        else
            left = mid + 1;
    }
    if (left > 0 && values[left].line > searchedLine) {
        if (index)
            *index = left - 1;
        return values[left - 1];
    }
    if (index)
        *index = left;
    return values[left];
}

// the characters of a name, a register or a number (mangled names: ?Name@@YAXXZ, $LN5)
bool IsTokenCharacter(char16_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '@' || c == '?' || c == '$' || c == '.';
}

// the occurrences of `token` (a whole name: the characters around it are not name characters) get `color`
void HighlightTokenOccurrences(AppCUI::Graphics::CharacterBuffer& chars, AppCUI::uint32 fromColumn, std::string_view token, AppCUI::Graphics::ColorPair color)
{
    Character* buffer   = chars.GetBuffer();
    const uint32 length = chars.Len();
    const auto size     = static_cast<uint32>(token.size());
    for (uint32 column = fromColumn; column + size <= length; column++) {
        if (column > 0 && IsTokenCharacter(buffer[column - 1].Code))
            continue;
        if (column + size < length && IsTokenCharacter(buffer[column + size].Code))
            continue;
        bool matches = true;
        for (uint32 index = 0; index < size && matches; index++)
            matches = buffer[column + index].Code == static_cast<char16>(static_cast<unsigned char>(token[index]));
        if (!matches)
            continue;
        for (uint32 index = 0; index < size; index++)
            buffer[column + index].Color = color;
        column += size - 1;
    }
}
