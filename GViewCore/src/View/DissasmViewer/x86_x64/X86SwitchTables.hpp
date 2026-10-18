#pragma once

#include <AppCUI/include/AppCUI.hpp>
#include <capstone/capstone.h>

#include <array>
#include <functional>
#include <optional>
#include <vector>

namespace GView::View::DissasmViewer
{
// The jump table of a switch, found at its indirect jmp. The addresses are in the address space of the labels (VA).
struct X86JumpTable {
    enum class EntryKind : AppCUI::uint8 {
        Absolute,          // the entries are addresses: jmp dword ptr [eax * 4 + table] (MSVC x86)
        ImageBaseRelative, // the entries are RVAs: mov ecx, [rdx + rax * 4 + table_rva]; add rcx, rdx (MSVC x64, rdx = __ImageBase)
        TableRelative,     // the entries are signed offsets from the table: movsxd rax, [rdx + rax * 4]; add rax, rdx (GCC / MinGW)
    };
    AppCUI::uint64 tableAddress = 0;
    AppCUI::uint8 entrySize     = 4;
    EntryKind kind              = EntryKind::Absolute;
    AppCUI::uint64 base         = 0; // ImageBaseRelative: the image base; TableRelative: the table address
    std::optional<AppCUI::uint32> casesCount;     // from the bounds check before the jmp (cmp reg, N; ja default)
    std::optional<AppCUI::uint64> indexTableAddress; // MSVC: a byte table gives the entry of every case (movzx eax, byte ptr [rdx + rax + ...])
};

// Recognizes the jump tables of the switches while the instructions are decoded in order (capstone details enabled).
class X86SwitchDetector
{
  public:
    X86SwitchDetector(bool is64, AppCUI::uint64 labelBase, std::optional<AppCUI::uint64> imageBase);
    // called for every decoded instruction: the jump table when the instruction is the indirect jmp of a switch
    std::optional<X86JumpTable> Next(const cs_insn& insn);

  private:
    struct Recent {
        cs_insn insn;
        cs_detail detail;
    };
    static constexpr size_t HISTORY = 24;

    // the previously decoded instructions: 0 is the one before the current instruction
    const cs_insn* Previous(size_t index) const;
    std::optional<X86JumpTable> FindRegisterJumpTable(x86_reg target) const;
    std::optional<AppCUI::uint32> FindCasesCount() const;

    bool is64;
    AppCUI::uint64 labelBase;
    AppCUI::uint64 addressMask;
    std::optional<AppCUI::uint64> imageBase;
    std::array<Recent, HISTORY> recent{};
    size_t recentCount = 0;
    size_t recentHead  = 0; // the next written slot
};

// The targets of the cases of a jump table, in the order of the cases (the same target can appear several times). readValue reads a value of
// 1, 4 or 8 bytes at an address; isTarget tells if an address can be a case (an address of the code). A table without a known bounds check
// ends at its first entry that is not a target.
std::vector<AppCUI::uint64> ReadX86JumpTableTargets(
      const X86JumpTable& table,
      const std::function<std::optional<AppCUI::uint64>(AppCUI::uint64 address, AppCUI::uint8 size)>& readValue,
      const std::function<bool(AppCUI::uint64 address)>& isTarget);
} // namespace GView::View::DissasmViewer
