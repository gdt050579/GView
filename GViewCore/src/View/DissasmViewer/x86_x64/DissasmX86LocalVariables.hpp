#pragma once

#include "DissasmViewer.hpp"
#include <functional>

namespace GView::View::DissasmViewer
{
// Recognizes a frame based function (push ebp; mov ebp, esp / push rbp; mov rbp, rsp / enter) starting at `codeAddress` and collects the stack
// slots addressed only through the frame register ([ebp - 8] -> var_8, [ebp + 8] -> arg_0) until the end of the function: the first
// ret / jmp / int3 that is not followed by code reached through a branch of the function, a write to the frame register or `limitAddress`.
// `detailHandle` must be a capstone handle opened with CS_OPT_DETAIL; `code` holds the bytes found at the relative address `codeAddress`.
// Returns false when the function does not use a frame pointer. The variables of the returned frame are sorted by their frame offset.
bool AnalyzeX86FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, bool is64, DissasmFunctionFrame& frame);

// 32 bit code: the bytes a callee pops from the stack of its caller (stdcall / thiscall: ret 8; cdecl: 0), none when it is not known
using X86CalleeStackPurge = std::function<std::optional<uint32>(const cs_insn& call)>;

// Without a frame register (MSVC x64: push rbx; sub rsp, 0x30, then [rsp + 0x20]; x86 FPO / GCC -O2: [esp + 0x1c]): the stack pointer is
// followed from the entry (push / pop / sub / add / lea rsp, [rsp + n]; mov eax, 0x2000 before __chkstk), the slots are kept in offsets
// from the stack pointer of the entry: [rsp + 0x20] with rsp = entry - 0x38 is var_18; the arguments above the return address are arg_0
// ([entry + 8] / [entry + 4]) ... (frame.usesFrameRegister = false, frame.stackDeltas). The code after a ret / jmp goes on with the depth
// of a branch to it (or the depth of the body). 32 bit: a call moves esp by what its callee pops (`calleePurge`; when it is not known: the
// arguments pushed since the previous call, unless the caller cleans up: add esp, 8 / pop ecx), a ret reached with an unbalanced stack
// rejects the function (the ambiguous pushes are read again: push ecx at the entry, a local or an argument; push esi after a call, a saved
// register or an argument), and so does a function without a ret or a jmp with the stack of the entry (a chunk of another function).
// False when the stack pointer is written otherwise (mov esp, ebp: a frame of AnalyzeX86FunctionFrame) or no slot is used
bool AnalyzeX86StackFrame(
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      bool is64,
      DissasmFunctionFrame& frame,
      const X86CalleeStackPurge& calleePurge = {});

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
// [rsp + 0x20] / [esp] (or a copy of the stack pointer: [r11 - 0x28]): a slot of the stack pointer; frameOffset receives the displacement
bool FindX86StackOperand(std::string_view operands, X86FrameOperand& result, std::string_view stackRegister = "rsp");

// ARM64: a function with a frame register (stp x29, x30, [sp, #-N]!; mov x29, sp / add x29, sp, #M) and its slots: the ones addressed
// through x29 ([x29, #-0x8] -> var_8) and the ones addressed through sp, kept in x29 offsets (frame.stackOffset: sp - x29 in the body of
// the function). The saved registers (the frame record, stp x20, x19, ...) are not variables. A function without x29 that reserves stack
// (sub sp, sp, #N) has its slots relative to the sp of its entry (frame.usesFrameRegister = false). False when it has neither.
bool AnalyzeArm64FunctionFrame(csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, DissasmFunctionFrame& frame);

struct Arm64FrameOperand {
    uint32 replaceStart; // first character after "#"
    uint32 replaceEnd;   // position of the closing ']'
    int32 displacement;
    bool isStackPointerBased; // [sp, #n]: the frame offset is n + frame.stackOffset
    bool needsSeparator;      // [sp]: no displacement, ", #" goes before the name
};
// Finds a slot operand of the capstone operands string: [x29, #-0x10], [sp, #0x18], [sp] (not the writeback forms [sp, #-0x10]! /
// [sp], #0x10); `frameRegister`: x29, fp (r11) or r7
bool FindArm64FrameOperand(std::string_view operands, Arm64FrameOperand& result);
bool FindArmFrameOperand(std::string_view operands, std::string_view frameRegister, Arm64FrameOperand& result);

// 32 bit ARM (the mode of the function: `thumb`): push {..., r11, lr}; mov r11, sp / add r11, sp, #M (ARM) or push {r7, lr}; mov r7, sp
// (Thumb), then the slots of the frame register and of sp (in frame register offsets), as AnalyzeArm64FunctionFrame; a function without
// a frame register that reserves stack: the slots from the sp of its entry. frame.frameRegister: 11 or 7 (0 without one)
bool AnalyzeArm32FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, bool thumb, DissasmFunctionFrame& frame);
} // namespace GView::View::DissasmViewer
