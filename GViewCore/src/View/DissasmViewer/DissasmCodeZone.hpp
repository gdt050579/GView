#pragma once

#include "DissasmViewer.hpp"
#include "x86_x64/X86InstructionInfo.hpp"

#include <unordered_set>

namespace GView::View::DissasmViewer
{
struct DissasmDeepScan;
struct DissasmLineCounter;

// a block of a function placed apart from it (IDA: a function chunk / tail): only jumps of the function reach it and it jumps back into it
struct DissasmFunctionChunk {
    uint64 start = 0, end = 0; // relative, end exclusive
    uint64 function = 0;       // the relative start of its function
    bool operator==(const DissasmFunctionChunk&) const = default;
};

// a function found by the analysis (DissasmCodeZone::GetFunctions)
struct DissasmFunctionInfo {
    uint64 start = 0; // relative address
    uint64 size  = 0; // the size given by the plugin (exception data), or up to the next function
    std::string name;
    uint32 xrefs      = 0; // the references to the function (calls, jumps, addresses taken)
    bool isThunk      = false;
    bool isExport     = false;
    bool isEntryPoint = false;
    bool isNoReturn   = false; // never returns to its caller (DissasmCodeZone::noReturnFunctions)
    std::vector<std::pair<uint64, uint64>> chunks; // its chunks apart from it: relative start, end
    uint32 apiCategories = 0;                      // what the APIs it calls do (DissasmApiCategory): the triage of the functions
};

// What the GoTo dialog accepts. A prefix chooses the kind (va:, rva:, off: / offset:, line:); otherwise the text is a label name, or else an
// address in the shown address mode. The addresses are hexadecimal, as in IDA (140001000, 0x140001000, 140001000h); a line is decimal.
struct DissasmGoToRequest {
    std::string name; // a label name, looked for before the address (empty with a prefix)
    std::optional<uint64> address;
    DissasmPEConversionType addressType = DissasmPEConversionType::FileOffset;
    std::optional<uint32> line;
};
std::optional<DissasmGoToRequest> ParseDissasmGoToText(std::string_view text, DissasmPEConversionType shownAddressType);
// the first name of an answer of the assistant (names separated by commas / new lines, numbered or quoted); empty when there is none
std::string ParseAssistantSuggestedName(std::string_view answer);

// a function edited by the user (IDA: P creates a function, Delete function, the noreturn attribute): the flags of
// DissasmCodeZone::userFunctions. NORETURN / RETURNS replace what the analysis finds
enum DissasmUserFunctionFlags : uint8 {
    USER_FUNCTION_CREATE   = 1,
    USER_FUNCTION_DELETE   = 2,
    USER_FUNCTION_NORETURN = 4,
    USER_FUNCTION_RETURNS  = 8,
    USER_FUNCTION_ALL      = 15,
};

// An edit of the user with what it replaced: it can be undone and redone (Ctrl+Z / Ctrl+Y)
struct DissasmEdit {
    enum class Kind : uint8 { Comment, LabelName, VariableName, DecimalOperand, AddZone, RemoveZone, DataRanges, UserFunctions, VariableStructures, OperandStructure };
    Kind kind = Kind::Comment;
    DissasmCommentAnchor anchor;              // Comment
    uint64 address     = 0;                   // LabelName: the label; VariableName: the function; DecimalOperand: the instruction
    int32 frameOffset  = 0;                   // VariableName
    uint32 numberIndex = 0;                   // DecimalOperand
    std::optional<std::string> before, after; // Comment (none: no comment), LabelName, VariableName, OperandStructure (none: no structure)
    DissasmCollapsibleZone zone;              // AddZone / RemoveZone
    std::vector<DissasmInstructionSet::DataRange> rangesBefore, rangesAfter; // DataRanges (address: the edited line)
    std::map<uint64, uint8> functionsBefore, functionsAfter;                 // UserFunctions (address: the function)
    std::map<std::pair<uint64, int32>, std::string> structuresBefore, structuresAfter; // VariableStructures (address: the function)
};
// the edits that can be undone / redone
struct DissasmEditHistory {
    std::vector<DissasmEdit> undo, redo;
};
struct DissasmReanalysis; // DissasmAnnotations.hpp
// where an undone / redone edit is (relative address of a line, or a line of the expanded layout): the cursor goes there
struct DissasmEditPlace {
    std::optional<uint64> address;
    std::optional<uint32> expandedLine;
    bool onLabel    = false; // the edit is on the label (or a local variable) of the address, not on its instruction
    bool reanalyze  = false; // the data / the functions defined by the user changed: the zone needs a new analysis (ReanalyzeCodeZone)
};

// a call between two functions (DissasmCodeZone::GetCallers / GetCallees)
struct DissasmCodeZone;
struct DissasmCallReference {
    uint64 site = 0;                     // relative address of the call / jmp instruction
    std::string function;                // the caller / the callee (an import: its name, an indirect call: its operands)
    std::optional<uint64> functionStart; // relative address of the function when it is in the code
    bool isTailJump = false;             // a jmp to another function
    // another code zone of the file (another executable section): the zone of `site` (a caller) / of `functionStart` (a callee), whose
    // relative addresses they are; none: the zone that was asked
    DissasmCodeZone* zone = nullptr;
};

// a cross reference and the code zone of its source (the xrefs of a zone are kept by the zone of their source)
struct DissasmZoneXref {
    const DissasmXref* xref;
    DissasmCodeZone* zone;
};

// The basic blocks of a function (the graph view, DissasmCodeZone::BuildFunctionGraph): blocks[0] is the entry, only the blocks reached
// from it are kept, the blocks are sorted by address
struct DissasmGraphBlock {
    enum class EdgeKind : uint8 { Jump, True, False, Switch }; // Jump: a jmp or the next block (no branch)
    struct Edge {
        size_t target; // index of the block
        EdgeKind kind;
    };
    uint64 start = 0, end = 0;          // relative addresses [start, end)
    std::vector<uint32> instructions;   // the ordinals of the instructions (decode order from the function start)
    std::vector<uint64> addresses;      // their relative addresses
    std::vector<Edge> successors;
    bool exits = false; // ret, a jmp out of the function (a tail call)
};
struct DissasmFunctionGraph {
    uint64 functionStart = 0;
    std::vector<DissasmGraphBlock> blocks;
    bool truncated = false; // too many blocks / instructions: the graph stops there
};

// The places of the blocks of a graph (the graph window): layers by the longest path from the entry over the forward edges (a forward edge
// goes to a block of a bigger index); an edge that crosses several layers passes through a dummy node in each of them (a column between
// the boxes, never behind one); the order of every layer reduces the crossings (barycenter sweeps, the best order kept); every node is
// placed under the middle of the nodes above it, the order kept, the nodes of a layer never overlap.
struct DissasmGraphLayout {
    struct Node {
        int x = 0, y = 0, width = 0, height = 0;
        int layer   = 0;
        bool isDummy = false;
    };
    std::vector<Node> nodes; // the blocks (the same index), then the dummies
    // a forward edge (its source block, the index of the edge in its successors): the dummy nodes it passes through, from the top
    std::map<std::pair<size_t, size_t>, std::vector<size_t>> edgeDummies;
    std::vector<int> layerTop, layerHeight;
    int width = 0, height = 0; // the space the nodes use (from 0, the margins included)
};
// blockSizes: the width and the height of every block
DissasmGraphLayout LayoutFunctionGraph(const DissasmFunctionGraph& graph, const std::vector<std::pair<int, int>>& blockSizes);
// the crossings of the segments of the forward edges between the consecutive layers of a layout (the order of the nodes: their x)
size_t CountGraphCrossings(const DissasmGraphLayout& layout, const DissasmFunctionGraph& graph);

// a string used by the code (DissasmCodeZone::GetReferencedStrings)
struct DissasmStringReference {
    uint64 address = 0; // in the address space of the labels (VA)
    std::string text;   // quoted: "ascii" or L"utf-16"
    uint32 xrefs = 0;
};

// Search (Ctrl+F): text of the listing, a byte pattern (48 8B ?? 05, ?? is any byte) or an immediate / displacement value
// the bytes of a pattern, -1 for ?? (any byte); none when the text is not a pattern
std::optional<std::vector<int16>> ParseDissasmBytePattern(std::string_view text);
// a decimal number, or hexadecimal with 0x / h (0x1000, 1000h); a minus sign for a negative value
std::optional<uint64> ParseDissasmSearchNumber(std::string_view text);

struct DissasmCodeZone : public ParseZone {
    enum class CollapseExpandType : uint8 { Collapse, Expand, NegateCurrentState };
    uint32 lastDrawnLine      = 0; // optimization not to recompute buffer every time
    uint32 lastClosestLine    = 0;
    uint32 offsetCacheMaxLine = 0; // 0 forces the next decoded line to search its closest cached offset
    BufferView lastData;

    // fields only for dissasmx86/x64
    const uint8* asmData = nullptr;
    uint64 asmSize = 0, asmAddress = 0;
    uint64 asmWindowEnd = 0; // end (exclusive, relative address) of the bytes that can be decoded from the current cached offset

    // the labels and the local variable lines, keyed by their line in the expanded layout (DissasmCodeInternalType)
    DissasmCodeInternalType dissasmType{};
    // the collapsible zones, sorted by start (and the outer zone first for the same start), in the expanded layout
    std::vector<DissasmCollapsibleZone> collapsibleZones;

    DissasmAsmPreCacheData asmPreCacheData;

    std::vector<AsmOffsetLine> cachedCodeOffsets;
    DisassemblyZone zoneDetails{};
    int internalArchitecture = 0;           // the capstone mode (CS_MODE_32 / CS_MODE_64 / CS_MODE_ARM)
    cs_arch capstoneArch     = CS_ARCH_X86; // CS_ARCH_X86 / CS_ARCH_ARM64
    bool hasDecoder          = false;       // the language is known: capstoneArch and internalArchitecture are set
    bool isInit              = false;
    bool systemVCalls        = false; // x64 code of an ELF / Mach-O file: the System V calling convention (GetX64ArgumentSlot)
    bool initTried           = false; // InitZone ran (it may have failed): the zones prepared in the background are not tried again

    // x86/x64: decoded instructions count (the zone lines are the instructions plus the annotations of the root type)
    uint32 asmLinesCount = 0;
    // x86/x64: local variables of the frame based functions, filled only by the deep scan
    DissasmLocalVariables localVariables;
    // x86/x64: instruction address (relative, as DissasmAsmPreCacheLine::address) -> bit mask of the operand numbers
    // (FindOperandNumbers order) that are shown as decimal numbers instead of hexadecimal
    std::map<uint64, uint32> decimalOperands;
    // the suggestions of the assistant, kept apart from the data of the user until they are accepted (A) or dismissed (Shift+A)
    DissasmUserComments aiComments;              // by anchor
    std::map<uint64, std::string> suggestedNames; // relative address of a label -> the name suggested for it
    // the cache had a record for this zone that could not be applied to the analysis: it is kept aside on save (not overwritten)
    bool cacheRecordRejected = false;
    // x86/x64: the address of the first decoded instruction in the address space of the labels, the VA (offset translation of the plugin)
    // or the file offset when the plugin has no translation. The label of the relative address r is named after labelAddressBase + r.
    uint64 labelAddressBase = 0;
    // DecodeX86Line: labelAddressBase when the padding between the functions is shown as align lines (Config.AlignPadding)
    uint64 paddingAlignmentBase = DISSASM_NO_PADDING_ALIGNMENT;
    // x86/x64: the comments of the user, by anchor (they follow their instruction / label / variable whatever the lines become)
    DissasmUserComments userComments;
    // the names the user gave to labels that the analysis does not find (a cache of another version): saved again, applied when the
    // label comes back. Keyed by the relative address of the label.
    std::map<uint64, std::string> orphanLabelNames;
    // the record that an older version could not apply (kept aside in the cache) was merged into this zone: it is not kept any more
    bool mergedUnappliedRecord = false;
    // the object of the zone (set by InitZone): the line based calls decode their line from it
    Reference<GView::Object> zoneObject;
    // x86/x64 (deep scan): the cross references of the code (address space of the labels) and the function starts (relative, sorted)
    DissasmXrefs xrefs;
    std::vector<uint64> functionStarts;
    std::unordered_map<uint64, std::string> thunkImports; // relative address of an import thunk (jmp [slot]) -> the import
    // the functions that never return (IDA: noreturn): by their name (exit, abort, ExitProcess, a thunk of one) or because no path of
    // theirs returns; relative starts, sorted. The calls to them (and to the imports that do not return): relative addresses
    std::vector<uint64> noReturnFunctions;
    std::unordered_set<uint64> noReturnCalls;
    // the end (relative, exclusive) of every function of functionStarts (the same index): the end of its last instruction that a path from
    // its start reaches (IDA: the function end), the padding and the dead code after it excluded; at most the next function start
    std::vector<uint64> functionEnds;
    // the end of a function (relative start): functionEnds, else the next function start
    uint64 GetFunctionEnd(uint64 functionStart) const;
    // the chunks of the functions (DissasmFunctionChunk), sorted by start; the chunk that contains an address
    std::vector<DissasmFunctionChunk> functionChunks;
    // the categories of the APIs every function of functionStarts calls / jumps to directly (DissasmApiCategory, the same index)
    std::vector<uint32> functionApiCategories;
    const DissasmFunctionChunk* FindChunkContaining(uint64 relativeAddress) const;
    // the code of a function: [start, end) (`end`: its next function, or functionEnds with `reachableEnd`) and its chunks, by address
    std::vector<std::pair<uint64, uint64>> GetFunctionRanges(uint64 functionStart, uint64 end) const;
    // the frame of the function of an instruction: the one whose range contains it, or the frame register frame of the function of its
    // chunk ([ebp - 8] means the same there; the stack pointer frames need the depth at the chunk)
    const DissasmFunctionFrame* FindFrameOfAddress(uint64 relativeAddress) const;
    // IDA's attributes of a function, for its label line: "noreturn", "thunk", "bp-based frame" (empty when it has none / is not a function)
    std::string FormatFunctionAttributes(uint64 relativeAddress) const;
    // the relative addresses where an instruction starts (function entries, section starts): no decoded instruction crosses them
    std::vector<uint64> instructionBoundaries;
    std::unordered_map<uint64, uint32> switchJumps;        // relative address of the indirect jmp of a switch -> its cases count
    // the jump tables inside the code shown as data lines (instructionSet.dataRanges): relative address of an entry -> its case (relative)
    std::map<uint64, uint64> tableEntries;
    // a data zone: the slots named by the plugin (the import slots, the Objective-C references and classes), relative addresses, sorted: a
    // label each, even when no code refers to them (CollectDataZoneTargets)
    std::vector<uint64> namedSlots;
    // a data zone: the names of the fields of its structures (relative address -> SecurityCookie), the comments of their lines
    std::unordered_map<uint64, std::string> fieldNames;
    // the pointers the loader writes (the relocations of a PIE / shared object), by file offset; can be null
    const std::map<uint64, uint64>* relocatedPointers = nullptr;
    // the value of the pointer at a relative address that the loader writes (its bytes in the file are 0 or the addend)
    std::optional<uint64> GetRelocatedPointer(uint64 relativeAddress) const
    {
        if (!relocatedPointers || relocatedPointers->empty())
            return {};
        const auto it = relocatedPointers->find(zoneDetails.startingZonePoint + relativeAddress);
        return it != relocatedPointers->end() ? std::optional<uint64>(it->second) : std::nullopt;
    }
    // ARM64 (deep scan): relative address of an instruction of an adrp pair (add / ldr / str [page + offset], br / blr through the slot read
    // before) -> the relative address it uses; the lines are decoded alone, the pair is known only by the sweep
    std::unordered_map<uint64, uint64> resolvedAddresses;
    std::unordered_map<uint64, uint64> adrpPages; // ARM64: the address of the first pair of an adrp, by its address (adrp x8, name@PAGE)
    // x64 (MSVC): relative address of an instruction that reads a table through a register holding the image base ([rdx + rcx + 0x2d9f0],
    // rdx = __ImageBase: the displacement is an RVA) -> the VA of the table
    std::unordered_map<uint64, uint64> imageBaseTables;
    static uint8 MemoryOperandAccess(const cs_insn& insn)
    {
        if (insn.detail)
            for (uint8 index = 0; index < insn.detail->x86.op_count; index++)
                if (insn.detail->x86.operands[index].type == X86_OP_MEM)
                    return insn.detail->x86.operands[index].access;
        return CS_AC_READ;
    }
    // the operands of an instruction (GetInstructionOperands) with the address of its adrp pair (ARM64)
    X86OperandsInfo GetOperandsInfo(const cs_insn& insn) const
    {
        auto operands = GetInstructionOperands(insn, GetArchAt(insn.address), labelAddressBase);
        if (!resolvedAddresses.empty()) {
            const auto resolved = resolvedAddresses.find(insn.address);
            if (resolved != resolvedAddresses.end()) {
                operands.ripTarget = resolved->second;
                if (IsArm32Code()) { // ldr / bx / blx: read; str: written; movt / add r0, pc, r0 / adr: the address is taken
                    const bool isRead     = insn.id == ARM_INS_LDR || insn.id == ARM_INS_LDRB || insn.id == ARM_INS_LDRH || insn.id == ARM_INS_BX || insn.id == ARM_INS_BLX;
                    const bool isWritten  = insn.id == ARM_INS_STR || insn.id == ARM_INS_STRB || insn.id == ARM_INS_STRH;
                    operands.memoryAccess = static_cast<uint8>(isRead ? CS_AC_READ : (isWritten ? CS_AC_WRITE : 0));
                } else if (IsArm64Code())
                    operands.memoryAccess = insn.id == ARM64_INS_ADD ? 0 : static_cast<uint8>(insn.id == ARM64_INS_STR || insn.id == ARM64_INS_STRB || insn.id == ARM64_INS_STRH ? CS_AC_WRITE : CS_AC_READ);
                else // 32 bit x86 PIC: [ebx + disp] with ebx known; lea takes the address
                    operands.memoryAccess = insn.id == X86_INS_LEA ? 0 : MemoryOperandAccess(insn);
            }
        }
        return operands;
    }

    // the name shown for the label at the relative address (renamed or not); empty when there is no label there
    std::string GetLabelNameAt(uint64 relativeAddress) const;
    // the relative address of the label with this name (the exact name first, then ignoring the case)
    std::optional<uint64> FindLabelByName(std::string_view name) const;
    // the functions of the analysis, by address; functionEntries (the plugin) gives the exports and the sizes it knows
    std::vector<DissasmFunctionInfo> GetFunctions(const std::map<uint64, DissasmFunctionEntry>* functionEntries) const;
    // the start of the function that contains a relative address (the last function start before it)
    std::optional<uint64> GetFunctionContaining(uint64 relativeAddress) const;
    // the basic blocks of the function, up to the next function start
    DissasmFunctionGraph BuildFunctionGraph(uint64 functionStart) const;
    // the calls (and tail jumps) to the function, by the place of the call
    std::vector<DissasmCallReference> GetCallers(uint64 functionStart) const;
    // the calls (and tail jumps) of the function, in its order; findImport names the calls through the import slots
    std::vector<DissasmCallReference> GetCallees(uint64 functionStart, const std::function<const MemoryMappingEntry*(const X86OperandsInfo&)>& findImport) const;
    // the strings at the data addresses used by the instructions (lea rcx, [rip + ...] / push offset), by address
    std::vector<DissasmStringReference> GetReferencedStrings(const std::function<std::optional<uint64>(uint64)>& addressToFileOffset) const;
    // the strings used by this zone and by the other code zones of the file: a string used by several zones once, with all its references
    std::vector<DissasmStringReference> GetReferencedStringsOfFile(const std::function<std::optional<uint64>(uint64)>& addressToFileOffset) const;
    // the relative address of the first match in [from, to) of the code
    std::optional<uint64> FindBytes(const std::vector<int16>& pattern, uint64 from, uint64 to) const;
    // the first instruction in [from, to) (relative addresses, from is an instruction of the listing) with this immediate / displacement
    std::optional<uint64> FindImmediate(uint64 value, uint64 from, uint64 to) const;
    // the first shown line in [fromLine, toLine) whose text contains `text` (labels, instructions, comments)
    std::optional<uint32> FindText(std::string_view text, bool matchCase, uint32 fromLine, uint32 toLine, DissasmInsnExtractLineParams* params);
    // "sub_140001010+0x1A": the function that contains the relative address (its name as shown)
    std::string FormatCodeAddress(uint64 relativeAddress) const;
    // the references to the label at the relative address, shown after the label: "xrefs: sub_140001010+0x84 (call), ... +3"
    std::string FormatXrefsSummary(uint64 relativeAddress) const;
    // the other code zones of the file (the other executable sections, LinkCodeZones): their xrefs to this zone, their functions called
    // from it. A zone that is not analyzed yet (never shown) has none.
    std::vector<DissasmCodeZone*> siblingZones;
    // the data defined by the user in the code (IDA D / A / U), relative addresses, sorted: InitZone counts the lines with them (a change
    // needs a new analysis of the zone, ReanalyzeCodeZone); saved in the cache (read before the zone is analyzed) and in the annotations
    std::vector<DissasmInstructionSet::DataRange> userDataRanges;
    // D: the data line at the address gets the next size (db, dw, dd, dq, then db again); an instruction becomes a db line. A: the ASCII text
    // that starts at the address (up to its zero) becomes a string; false when there is no text. U: the data / string of the address is
    // removed (decoded as code again); false when the address has none.
    bool DefineUserData(uint64 address);
    bool DefineUserString(uint64 address);
    bool UndefineUserData(uint64 address);
    void SetUserDataRange(const DissasmInstructionSet::DataRange& range); // the ranges it overlaps are removed
    // the functions edited by the user (IDA P / Delete function / the noreturn attribute): relative address -> DissasmUserFunctionFlags.
    // Like userDataRanges: a change needs a new analysis of the zone, saved in the cache and in the annotations
    std::map<uint64, uint8> userFunctions;
    // P: a function starts at the address (false when one starts there already). Delete: the function that starts at the address is not a
    // function any more (its label stays, loc_); false for the entry point and for an address where no function starts. The noreturn
    // attribute: the function does not return when the analysis found that it returns, and the other way around
    bool CreateUserFunction(uint64 address);
    bool DeleteUserFunction(uint64 functionStart);
    bool ToggleUserNoReturn(uint64 functionStart);
    // the structures the user gives to the variables (IDA Alt+Q): (function start, frame offset) -> the name of the structure
    // (FindApiStructure); empty: no structure (the one the analysis finds is not applied). Like userFunctions: a change needs a new analysis
    // (the variables inside the structure are its fields), saved in the cache and in the annotations
    std::map<std::pair<uint64, int32>, std::string> userVariableStructures;
    // the structure offsets the user gave to the memory operands (IDA T): the relative address of an instruction -> the structure whose field
    // its displacement is ([rbx + 0x3c] -> [rbx + STARTUPINFOW.dwFlags]). Only the drawing changes (as decimalOperands); saved in the cache
    // and in the annotations
    std::map<uint64, std::string> operandStructures;
    // the bookmarks of the user (IDA Alt+M / Ctrl+M): the relative address of a line (an instruction; a label / a variable line: its
    // instruction) -> its description (DISSASM_MAX_BOOKMARK_SIZE at most). Saved in the cache and in the annotations, shown in the
    // navigation band
    std::map<uint64, std::string> bookmarks;
    // T: the structure of the operand of the instruction (empty: none), an edit of the user (it can be undone); false when nothing changes
    bool SetOperandStructure(uint64 address, const std::string& structure);
    // a data zone: the places the code of the other zones refers to (relative, sorted) and the largest access there (0: an address taken)
    void CollectDataZoneTargets(std::vector<uint64>& targets, std::vector<uint8>& sizes) const;
    // the references to an address (VA) from this zone, then from the other code zones of the file
    std::vector<DissasmZoneXref> GetXrefsTo(uint64 address) const;
    // this zone or another analyzed code zone of the file that has the address (VA) in its code; none outside of them
    DissasmCodeZone* FindCodeZoneOfAddress(uint64 address) const;

    // the name of the label placed at the relative address `address` (as IDA: sub_140001000, loc_140001020)
    std::string GetLabelName(std::string_view prefix, uint64 address) const;
    // the labels loaded from a cache saved before the labels were named after the VA (sub_0x<file offset> / offset_0x<file offset>) get
    // the names of the analysis; the labels renamed by the user keep their names
    void MigrateLegacyLabelNames();

    DissasmCodeZone(); // out of line: the deep scan is only declared here
    // owns the capstone handle
    DissasmCodeZone(const DissasmCodeZone&)            = delete;
    DissasmCodeZone& operator=(const DissasmCodeZone&) = delete;
    ~DissasmCodeZone() override;

    // x86/x64: the capstone handle that decodes the lines, opened once (in the mode of the zone) and closed with the zone; 0 when capstone
    // can not open it
    csh GetDecodeHandle() const;

    void ResetZoneCaching();
    // the zone of the shown lines [zoneLineStart, zoneLineEnd) (a collapsed line counts as its whole zone); false when it would
    // overlap a zone without being nested in it, or the same zone exists
    bool AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd);
    // the innermost zone of the shown line `zoneLine` (the zone of a collapsed line); `difference` is the new size of the code zone (its
    // lines and the title); false when there is no zone or it already has the requested state
    bool CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference);
    // removes the innermost expanded zone of the shown line `zoneLine`
    bool RemoveCollapsibleZone(uint32 zoneLine);

    // the edits of the user (comments, renames, numbers base, collapsible zones) can be undone / redone; none when there is no edit
    // or it can not be applied any more (its place has changed)
    std::optional<DissasmEditPlace> UndoEdit();
    std::optional<DissasmEditPlace> RedoEdit();
    bool CanUndoEdit() const
    {
        return !undoEdits.empty();
    }
    bool CanRedoEdit() const
    {
        return !redoEdits.empty();
    }
    void ClearEditHistory();
    // the history taken before a new analysis and given back after it: the edits of the collapsible zones are dropped (they are kept by
    // their lines, which the new analysis changes), the others are kept by address
    DissasmEditHistory TakeEditHistory();
    void RestoreEditHistory(DissasmEditHistory history);
    // D / A / U: the data ranges before the change (userDataRanges has the new ones); `address` is the edited line
    void RecordUserDataEdit(std::vector<DissasmInstructionSet::DataRange> before, uint64 address);
    // P / Delete function / the noreturn attribute: the functions of the user before the change; `address` is the function
    void RecordUserFunctionsEdit(std::map<uint64, uint8> before, uint64 address);
    // Alt+Q: the structures of the variables before the change; `address` is the function
    void RecordUserVariableStructuresEdit(std::map<std::pair<uint64, int32>, std::string> before, uint64 address);
    // a new analysis that continues in the background (BeginCodeZoneReanalysis): the annotations come back when its deep scan ends
    std::unique_ptr<DissasmReanalysis> pendingReanalysis;
    std::optional<uint64> pendingReanalysisAddress; // the line to show again then

    // the suggestions of the assistant on a shown line: the comment of the line, the name suggested for its label
    bool GetAIComment(const DissasmAsmPreCacheLine& line, std::string& comment) const;
    bool SetAIComment(uint32 line, std::string comment);
    std::optional<std::string> GetSuggestedName(const DissasmAsmPreCacheLine& line) const;
    // the suggestion of the line becomes data of the user (a rename / a comment, they can be undone); Dismiss removes it
    Utils::GStatus AcceptAISuggestion(uint32 line);
    bool DismissAISuggestion(uint32 line);
    // the display line of the label of a relative address (none when it has no label or it is hidden by a collapsed zone)
    std::optional<uint32> GetLabelDisplayLine(uint64 relativeAddress) const;
    // the code of a function as it is sent to the assistant: its lines (labels, variables, instructions with the names of their targets and
    // their generated comments) until its ret, the next function or the limits; the calls after the limits are listed
    std::string BuildAssistantFunctionText(uint64 functionStart, DissasmInsnExtractLineParams* params);
    // renames the label of a line of the expanded layout (an edit of the user: it can be undone)
    bool RenameLabel(uint32 expandedLine, const std::string& currentName, const std::string& newName);

    bool InitZone(DissasmCodeZoneInitData& initData);
    // the deep scan that did not end in InitZone (its budget): the zone shows the instructions without labels until it ends. The line
    // count that did not end in InitZone comes first: the zone shows the lines counted so far
    bool IsDeepScanPending() const
    {
        return deepScan != nullptr || lineCounter != nullptr;
    }
    bool IsCountingLines() const
    {
        return lineCounter != nullptr;
    }
    // continues the deep scan until the deadline; true when it has ended (CommitDeepScan gives its results to the zone)
    bool ContinueDeepScan(std::chrono::steady_clock::time_point deadline);
    // the results of the ended deep scan become the labels, cross references and local variables of the zone: the lines change
    void CommitDeepScan();
    void CancelDeepScan(); // the zone keeps the instructions without labels
    float GetDeepScanProgress() const; // 0..1
    // x86/x64 zone initialized successfully: only then the lines can be reached / decoded
    bool CanReachAsmLines() const
    {
        return isInit && linesReady && IsNativeCodeLanguage(zoneDetails.language);
    }

    // the line index (the sorted lines of the annotations) after the annotations changed; the decoding starts again from a cached offset
    void RebuildLineIndex();
    // the lines of the expanded layout: the instructions and the annotations
    uint32 GetExpandedLinesCount() const
    {
        return asmLinesCount + static_cast<uint32>(dissasmType.annotations.size());
    }
    // the shown lines: the collapsed zones are one line each
    uint32 GetDisplayLinesCount() const;
    struct LinePlace {
        uint32 expandedLine;
        const DissasmCollapsibleZone* collapsedZone; // the collapsed zone shown on the line (expandedLine is its start)
    };
    // the expanded line of a shown line; none after the last line
    std::optional<LinePlace> DisplayToExpanded(uint32 displayLine) const;
    // the shown line of an expanded line (the line of the collapsed zone that hides it)
    uint32 ExpandedToDisplay(uint32 expandedLine) const;
    // the instruction index of an expanded line that is not an annotation
    uint32 ExpandedToInstructionIndex(uint32 expandedLine) const;
    // the expanded line of the instruction `instructionIndex`
    uint32 InstructionIndexToExpanded(uint32 instructionIndex) const;
    bool IsAnnotationLine(uint32 expandedLine) const;
    // the innermost zone that contains the expanded line / that starts on it
    DissasmCollapsibleZone* FindInnermostZone(uint32 expandedLine);
    const DissasmCollapsibleZone* FindInnermostZoneStartingAt(uint32 expandedLine) const;

    Utils::GStatus TryRenameLine(
          uint32 line, Reference<GView::Object> obj, std::string_view* newName = nullptr, DissasmInsnExtractLineParams* params = nullptr);

    // the comments of the user are attached to the anchor of a line (DissasmCommentAnchor), the line versions find the anchor of the line
    bool GetComment(uint32 line, std::string& comment);
    bool GetComment(const DissasmAsmPreCacheLine& line, std::string& comment) const;
    bool AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr = true);
    bool RemoveComment(uint32 line, bool showErr = true);
    // the instruction, the label or the variable of a line (a collapsed zone: the anchor of its first line)
    static DissasmCommentAnchor GetLineAnchor(const DissasmAsmPreCacheLine& line);
    std::optional<DissasmCommentAnchor> GetAnchorOfLine(uint32 line);
    DissasmAsmPreCacheLine GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);

    // x86/x64 code window: bytes from cachedCodeOffsets[0].offset until the end of the zone
    uint64 GetCodeSize() const;
    // file offset of an address decoded by this zone (the decoded addresses start at 0 on cachedCodeOffsets[0].offset), none when the
    // address is not inside the decoded code (another section, a backward branch that wrapped around, ...)
    std::optional<uint64> GetFileOffsetOfAddress(uint64 address) const;
    // points asmData/asmSize/asmAddress to [relativeStart, relativeEnd), clamped to the zone and to what the data cache returns
    bool FetchCodeWindow(Reference<GView::Object> obj, uint64 relativeStart, uint64 relativeEnd);

    // local variables
    // 64 bit addresses (x64, ARM64)
    bool Is64BitCode() const
    {
        return zoneDetails.language == DisassemblyLanguage::x64 || zoneDetails.language == DisassemblyLanguage::ARM64;
    }
    bool IsArm64Code() const
    {
        return zoneDetails.language == DisassemblyLanguage::ARM64;
    }
    // 32 bit ARM (ARM / Thumb modes)
    bool IsArm32Code() const
    {
        return zoneDetails.language == DisassemblyLanguage::ARM || zoneDetails.language == DisassemblyLanguage::Thumb;
    }
    bool IsArmCode() const
    {
        return IsArm64Code() || IsArm32Code();
    }
    DissasmArch GetArch() const
    {
        switch (zoneDetails.language) {
        case DisassemblyLanguage::ARM64:
            return DissasmArch::Arm64;
        case DisassemblyLanguage::ARM:
            return DissasmArch::Arm;
        case DisassemblyLanguage::Thumb:
            return DissasmArch::Thumb;
        case DisassemblyLanguage::x64:
            return DissasmArch::X64;
        default:
            return DissasmArch::X86;
        }
    }
    // the instruction set at an address: 32 bit ARM changes its mode (ARM / Thumb) inside a zone
    DissasmArch GetArchAt(uint64 relativeAddress) const
    {
        if (!IsArm32Code())
            return GetArch();
        return instructionSet.ModeAt(relativeAddress) == ArmCodeMode::Thumb ? DissasmArch::Thumb : DissasmArch::Arm;
    }
    const char* GetArchitectureName() const
    {
        switch (zoneDetails.language) {
        case DisassemblyLanguage::ARM64:
            return "ARM64";
        case DisassemblyLanguage::ARM:
            return "ARM";
        case DisassemblyLanguage::Thumb:
            return "Thumb";
        case DisassemblyLanguage::x64:
            return "x64";
        default:
            return "x86";
        }
    }
    // the code decoded by capstone (x86, x64, ARM64, ARM / Thumb), not the Java bytecode
    static bool IsNativeCodeLanguage(DisassemblyLanguage language)
    {
        return language == DisassemblyLanguage::x86 || language == DisassemblyLanguage::x64 || language == DisassemblyLanguage::ARM64 ||
               language == DisassemblyLanguage::ARM || language == DisassemblyLanguage::Thumb;
    }
    // DecodeX86Line: the instruction set, the modes of 32 bit ARM code
    DissasmInstructionSet instructionSet;
    // the variable defined by `line` (variable line) or used by the instruction on `line`
    bool GetLocalVariableFromLine(uint32 line, Reference<GView::Object> obj, uint64& functionStart, int32& frameOffset);
    Utils::GStatus RenameLocalVariable(uint64 functionStart, int32 frameOffset, std::string_view newName);
    // removes the variable and its definition line; the zone loses one line when `lineRemoved` is set
    Utils::GStatus RemoveLocalVariable(uint64 functionStart, int32 frameOffset, bool& lineRemoved);
    // removes annotation lines (expanded layout) shifting the annotations and the collapsible zones that follow them
    void RemoveRootAnnotationLines(const std::vector<uint32>& sortedLines);
    uint32 GetRootZoneLinesCount() const
    {
        return GetExpandedLinesCount();
    }

    // switches the operand number `numberIndex` of the instruction at `address` between hexadecimal and decimal
    void ToggleDecimalOperand(uint64 address, uint32 numberIndex);
    uint32 GetDecimalOperandsMask(uint64 address) const
    {
        const auto it = decimalOperands.find(address);
        return it != decimalOperands.end() ? it->second : 0u;
    }

    // the record of the zone (cache version 4); not const: the anchors of the collapsible zones are read from their lines
    bool ToBuffer(std::vector<std::byte>& buffer);
    // `zoneLinesChanged` is set when the cache removed lines (deleted local variables), the zone size must be adjusted
    bool TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged);
    // the comments of the line keyed records (cache versions 1 and 2, kept in the root type by line) are moved to their anchors
    void MoveLineCommentsToAnchors();
    // the label names of the user, by the relative address of the label (the renamed labels and orphanLabelNames)
    std::vector<std::pair<uint64, std::string>> GetUserLabelNames() const;
    // gives the name to the label placed at `address`; false when there is no such label (the name is kept in orphanLabelNames) or the
    // name is used by another label
    bool ApplyUserLabelName(uint64 address, const std::string& name);

    // the collapsible zones by the anchors of their first and last lines (saved in the cache): the lines move, the anchors stay
    struct CollapsibleZoneAnchors {
        DissasmCommentAnchor first;
        DissasmCommentAnchor last;
        std::string name;
        bool isCollapsed;
    };
    std::vector<CollapsibleZoneAnchors> GetCollapsibleZoneAnchors();
    // the zones placed on the lines of their anchors (the ones that can not be placed are ignored); true when the shown lines changed
    bool ApplyCollapsibleZoneAnchors(const std::vector<CollapsibleZoneAnchors>& zones);
    // the expanded line of an anchor; none when this analysis has no such line
    std::optional<uint32> GetExpandedLineOfAnchor(const DissasmCommentAnchor& anchor);

  private:
    bool TryLoadCodeZoneRecord(DissasmCache& cache, bool& zoneLinesChanged);
    // true when the merged zones changed the shown lines
    bool MergeUnappliedRecord(DissasmCache& cache);
    // the line of the expanded layout as it is drawn (no collapsed zone)
    DissasmAsmPreCacheLine BuildExpandedLine(uint32 expandedLine, uint32 displayLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);
    bool CanPlaceZone(const DissasmCollapsibleZone& zone) const;
    void InsertZone(DissasmCollapsibleZone zone);

    mutable csh decodeHandle = 0; // GetDecodeHandle: opened at the first use
    std::vector<DissasmEdit> undoEdits, redoEdits;
    void RecordEdit(DissasmEdit edit);
    bool ApplyEdit(const DissasmEdit& edit, bool forward);
    std::unique_ptr<DissasmDeepScan> deepScan;
    std::unique_ptr<DissasmLineCounter> lineCounter;
    std::optional<DissasmCodeZoneInitData> deepScanInitData; // the deep scan starts once the lines are counted
    bool FinishLineCount(); // the lines are counted: the deep scan starts; false when it could not start
    bool linesReady  = false;
    std::vector<uint32> annotationLines;                // the sorted lines of dissasmType.annotations
    std::unordered_map<uint64, uint32> labelLineOfAddress; // relative address of a label -> its line (expanded layout)
    std::vector<uint64> sortedLabelAddresses;               // the same addresses, sorted (a data zone names an address after its label)
};

// the lines of the zone as they are shown (without the title), the collapsed zones count as one line
uint32 GetCodeZoneLinesCount(const DissasmCodeZone& zone);
// the listing of an initialized x86/x64 code zone (an .asm file): the lines as they are shown (labels, local variables, jump / call targets
// with their labels, import names) with the comments of the user and the generated comments
bool BuildX86AsmListing(DissasmCodeZone& zone, Reference<GView::Object> obj, SettingsData* settings, AsmData* asmData, std::string& listing);
// the import (memory mapping, keyed by the RVA of its slot) used by the operands: [rip + 0x...] on x64, the VA of the slot ([0x402010]) on x86
const MemoryMappingEntry* FindX86OperandsImport(SettingsData* settings, const DissasmCodeZone* zone, const X86OperandsInfo& operands);
// the init data of a code zone of the viewer settings (the addresses of the labels, the file translation, the imports, the function entries)
void PrepareCodeZoneInitData(SettingsData* settings, Reference<GView::Object> obj, DissasmCodeZone* zone, DissasmCodeZoneInitData& initData);

// A search (Ctrl+F / F6) in the code zones of the file (the executable sections), in their order: zones[startZone] after `from`, the next
// zones, the zones before it, then zones[startZone] up to `from`. `from` and the position found are a line of the zone for a text, a
// relative address for bytes / an immediate. makeParams gives the line parameters of a zone (the text search draws the lines), may be empty.
// The lines of a data zone: strings (ASCII of at least 4 characters with their zero, UTF-16), runs of pointers (aligned values that
// isPointer accepts, `pointerSize` bytes) and rows of the other bytes. An item never crosses a target (a place the code refers to: a label
// starts its line) or a fixed range (the data defined by the user, kept as they are). Relative addresses, sorted.
// targetSizes (empty, or one per target): the bytes the code reads / writes there (mov eax, dword ptr [X]: a dd line at X), 0 unknown
// the pointers the loader writes (relocations: file offset -> value) into `bytes`, the copy of the file from `fileOffset`
void ApplyRelocatedPointers(const std::map<uint64, uint64>* relocations, uint64 fileOffset, uint8* bytes, uint64 size, uint8 pointerSize);
std::vector<DissasmInstructionSet::DataRange> BuildDataZoneRanges(
      const uint8* bytes,
      uint64 size,
      const std::vector<uint64>& targets,
      const std::vector<uint8>& targetSizes,
      const std::vector<DissasmInstructionSet::DataRange>& fixedRanges,
      uint8 pointerSize,
      const std::function<bool(uint64)>& isPointer);
// the name of the label of a string (IDA): "a" and the words of the text (aHelloWorld), asc_<address> when it has no letter or digit
std::string MakeStringLabelName(std::string_view text, uint64 address);

struct DissasmSearchHit {
    DissasmCodeZone* zone;
    uint64 position;
};
std::optional<DissasmSearchHit> SearchCodeZones(
      const std::vector<DissasmCodeZone*>& zones,
      size_t startZone,
      uint64 from,
      const DissasmSearch& search,
      const std::function<DissasmInsnExtractLineParams*(DissasmCodeZone*)>& makeParams);

// A row of the navigation band (Instance::PaintNavigationBand; IDA's navigation band, and beyond it the functions colored by the most
// telling category of the APIs they call, GetMainApiCategory): what the lines of the row hold, the most telling last (a row with several
// lines gets the largest)
enum DissasmBandCell : uint8 {
    BAND_EMPTY,
    BAND_DATA,     // a data zone, a structure, a text zone
    BAND_CODE,     // the code of a code zone outside of the functions (before the first one)
    BAND_FUNCTION, // a function that calls none of the categorized APIs
    BAND_FILE,
    BAND_LOADING,
    BAND_REGISTRY,
    BAND_SERVICE,
    BAND_CRYPTO,
    BAND_NETWORK,
    BAND_PROCESS,
    BAND_ANTIDEBUG,
    BAND_INJECTION,
};
constexpr uint8 BAND_BOOKMARK              = 0x80; // a flag on the cell: a bookmark of the user is in the row
constexpr size_t DISSASM_MAX_BOOKMARK_SIZE = 256;
DissasmBandCell GetDissasmBandCellOfCategory(uint32 category);
// the band of `rows` rows for the lines [0, totalLines) of the view: the zones, the functions of the code zones (from their label line to
// the label of the next one) with their categories; a collapsed zone / function is its line. The rows of the bookmarks (the row of their
// label, else of the label of their function) get BAND_BOOKMARK
std::vector<uint8> BuildDissasmNavigationBand(const std::vector<const ParseZone*>& zones, uint64 totalLines, uint32 rows);

} // namespace GView::View::DissasmViewer
