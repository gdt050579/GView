#pragma once

#include "DissasmViewer.hpp"

namespace GView::View::DissasmViewer
{
// Recognizes a frame based function (push ebp; mov ebp, esp / push rbp; mov rbp, rsp / enter) starting at `codeAddress` and collects the stack
// slots addressed only through the frame register ([ebp - 8] -> var_8, [ebp + 8] -> arg_0) until the end of the function: the first
// ret / jmp / int3 that is not followed by code reached through a branch of the function, a write to the frame register or `limitAddress`.
// `detailHandle` must be a capstone handle opened with CS_OPT_DETAIL; `code` holds the bytes found at the relative address `codeAddress`.
// Returns false when the function does not use a frame pointer. The variables of the returned frame are sorted by their frame offset.
bool AnalyzeX86FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, bool is64, DissasmFunctionFrame& frame);

// IDA like names: [ebp - 0x4C] -> var_4C, [ebp + 8] -> arg_0 (x86) / [rbp + 0x10] -> arg_0 (x64)
void FormatDefaultLocalVariableName(int32 frameOffset, bool is64, std::string& name);
// "var_8 = dword ptr -8", `nameSize` receives the length of the name placed at the start of the text
void FormatLocalVariableDefinition(const DissasmLocalVariable& variable, std::string& text, uint32& nameSize);
bool IsValidLocalVariableName(std::string_view name);

struct X86FrameOperand {
    uint32 replaceStart; // first character after "[ebp"
    uint32 replaceEnd;   // position of the closing ']'
    int32 frameOffset;
};
// Finds a memory operand that uses only the frame register and a displacement ("[ebp - 8]", "[rbp + 0x10]") inside the capstone Intel syntax
// operands string. Operands with an index register or without displacement are ignored.
bool FindX86FrameOperand(std::string_view operands, bool is64, X86FrameOperand& result);
} // namespace GView::View::DissasmViewer
