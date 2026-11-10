#include "DissasmCodeZone.hpp"
#include "DissasmAnnotations.hpp"
#include "DissasmFunctionUtils.hpp"
#include "DissasmRtti.hpp"
#include "x86_x64/DissasmX86LocalVariables.hpp"
#include "x86_x64/X86InstructionInfo.hpp"
#include "x86_x64/X86SwitchTables.hpp"

#include <algorithm>
#include <cctype>
#include <numeric>
#include <unordered_set>
#include <set>
#include <map>
#include <span>

using namespace GView::View::DissasmViewer;
using GView::Utils::GStatus;

constexpr uint64 DISSASM_MAX_ANALYZED_FUNCTION_SIZE = 0x1000000; // 16 MB, larger functions are analyzed only partially

// a method of GCC told by its code (AddGccMethodPrototypes) by the name of its function or of one of its thunks (j_std::istream::ignore(long))
static const AsmFunctionDetails* FindMethodPrototypeByName(
      const std::map<std::string, std::shared_ptr<const DissasmUserPrototype>, std::less<>>& prototypes, std::string_view name)
{
    if (prototypes.empty())
        return nullptr;
    while (name.size() > 2 && name.starts_with("j_"))
        name.remove_prefix(2);
    const auto found = prototypes.find(name);
    return found != prototypes.end() ? &found->second->details : nullptr;
}

// the pointers of the Control Flow Guard in the load config (the plugin names them: __guard_dispatch_icall_fptr, __guard_xfg_dispatch_icall_fptr,
// the _x64 ones of the x64 view of an ARM64X image): a jmp through one is a thunk of the run-time
static bool IsGuardPointerName(std::string_view name)
{
    return name.starts_with("__guard_") && (name.ends_with("_fptr") || name.find("_fptr_") != std::string_view::npos);
}

// the pointers to the functions of the emulator in the CHPE metadata of an ARM64X image (the plugin names them, AddDissasmArm64ECMetadata):
// __os_arm64x_check_icall_cfg (the check of an indirect call of ARM64EC code), __os_arm64x_dispatch_call_no_redirect (an exit thunk), ...
static bool IsArm64ECPointerName(std::string_view name)
{
    return name.starts_with("__os_arm64x_");
}

// The lines of the zone, counted by a linear sweep (DecodeX86Line) that stops at a deadline and continues later: a big zone shows its first
// lines before the end of its code is read. A cached offset (file offset, line) is kept every DISSASM_INSTRUCTION_OFFSET_MARGIN bytes.
// The code is decoded from the start of the zone: every decoded address (and every branch target) is relative to it. An undecodable byte
// is a data line (db) and the decoding continues after it (inline data, jump tables); a zone bigger than the data cache window is decoded
// window after window.
struct GView::View::DissasmViewer::DissasmLineCounter {
    // the zero bytes at the end of the section (file alignment padding) decode as "add byte ptr [rax], al": a trailing run of them is not
    // shown. A run inside the code (between functions, data) is decoded as it is. Not in a data zone: its zeros are the variables
    // initialized to 0 (the plugins give the size of the data, not of its padding)
    static constexpr uint32 TRAILING_ZEROS_MINIMUM_LINES = 4;
    static constexpr uint32 LINES_BETWEEN_DEADLINE_CHECKS = 4096;

    vector<AsmOffsetLine>& offsets;
    Reference<GView::Object> obj;
    uint64 zoneStart;
    uint64 zoneSize;
    const std::vector<uint64>* boundaries;
    uint64 alignmentBase;
    csh handle    = 0;
    cs_insn* insn = nullptr;
    DissasmCodeLinesWalker walker;
    uint32 lines        = 0;
    uint32 zeroRunLines = 0;
    uint64 lastOffset   = 0;
    bool ended          = false;
    bool trimTrailingZeros;

    DissasmLineCounter(
          vector<AsmOffsetLine>& offsets,
          const DisassemblyZone& zoneDetails,
          Reference<GView::Object> obj,
          const std::vector<uint64>* boundaries,
          uint64 alignmentBase)
        : offsets(offsets), obj(obj), zoneStart(zoneDetails.startingZonePoint), zoneSize(zoneDetails.size), boundaries(boundaries),
          alignmentBase(alignmentBase), walker(obj, zoneDetails.startingZonePoint, zoneDetails.size, 0, 0, boundaries, alignmentBase),
          trimTrailingZeros(!zoneDetails.isData)
    {
    }

    ~DissasmLineCounter()
    {
        if (insn)
            cs_free(insn, 1);
        if (handle != 0)
            cs_close(&handle);
    }

    bool Start(cs_arch arch, int internalArchitecture, const DissasmInstructionSet* instructionSet)
    {
        if (cs_open(arch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK) {
            handle = 0;
            return false;
        }
        insn   = cs_malloc(handle);
        walker = DissasmCodeLinesWalker(obj, zoneStart, zoneSize, handle, 0, boundaries, alignmentBase, instructionSet);
        offsets.clear();
        offsets.push_back({ zoneStart, 0 });
        return insn != nullptr;
    }

    // true when the whole code is counted
    bool Run(std::chrono::steady_clock::time_point deadline)
    {
        if (ended)
            return true;
        uint32 linesUntilCheck = LINES_BETWEEN_DEADLINE_CHECKS;
        while (walker.Next(insn)) {
            lines++;
            const uint64 address = walker.GetAddress(); // the next line
            if (address - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
                lastOffset = address;
                offsets.push_back({ address + zoneStart, lines });
            }
            // only zero bytes: 00 00 (x86: add byte ptr [rax], al), 00 00 00 00 (ARM64: udf #0), a last 00 byte (a data line: db 0x00)
            const bool isZeroPadding = std::all_of(insn->bytes, insn->bytes + std::min<size_t>(insn->size, sizeof(insn->bytes)), [](uint8 value) {
                return value == 0;
            });
            zeroRunLines = isZeroPadding ? zeroRunLines + 1u : 0u;
            if (--linesUntilCheck == 0) {
                linesUntilCheck = LINES_BETWEEN_DEADLINE_CHECKS;
                if (std::chrono::steady_clock::now() >= deadline)
                    return false;
            }
        }
        if (trimTrailingZeros && zeroRunLines >= TRAILING_ZEROS_MINIMUM_LINES && zeroRunLines < lines) {
            lines -= zeroRunLines;
            // the cached offsets placed inside the removed lines point to lines that do not exist
            while (offsets.size() > 1 && offsets.back().line >= lines)
                offsets.pop_back();
        }
        ended = true;
        return true;
    }

    // the part of the code already counted: 0..1
    float GetProgress() const
    {
        return zoneSize == 0 ? 1.0f : static_cast<float>(static_cast<double>(walker.GetAddress()) / static_cast<double>(zoneSize));
    }
};

// The deep scan of a code zone: the labels (calls, jumps, functions, import thunks, switch cases), the cross references and the local
// variables. It runs in steps, each one until a deadline: a big zone is analyzed while its linear listing is already shown. The results
// stay here until the scan ends and are given to the zone at once (Commit): the drawn lines never see a partial analysis.
// The jump tables found inside the code (MSVC x64, Thumb tbb / tbh) become data lines: the lines are counted again with them (Recount) and
// the sweep starts again on the new lines (the bytes of a table decoded as instructions gave false labels and could hide the instructions
// after it), until no new table is found (at most DISSASM_MAX_TABLE_PASSES sweeps).
// the variable becomes the structure: the variables inside it are removed (its fields); not when it would cover the saved registers / the
// return address (a local below 0 that ends above it), nor another structure (unless `overStructures`: the choice of the user)
static bool ApplyFrameStructure(DissasmFunctionFrame& frame, DissasmLocalVariable& variable, const DissasmApiStructure* structure, bool overStructures)
{
    if (!structure)
        return false;
    const int64 start = variable.frameOffset, end = start + structure->size;
    if (start < 0 && end > 0)
        return false;
    const auto first = std::upper_bound(
          frame.variables.begin(), frame.variables.end(), variable.frameOffset, [](int32 offset, const DissasmLocalVariable& var) { return offset < var.frameOffset; });
    auto last = first;
    while (last != frame.variables.end() && last->frameOffset < end) {
        if (last->structure && !overStructures)
            return false;
        ++last;
    }
    variable.structure = structure;
    frame.variables.erase(first, last); // after the variable: its address stays valid
    return true;
}

struct GView::View::DissasmViewer::DissasmDeepScan {
    static constexpr uint32 DISSASM_MAX_TABLE_PASSES = 3;
    enum class Phase : uint8 { Sweep, Recount, Labels, Done };
    enum LabelType { SUB, OFFSET, OTHER };

    DissasmCodeZone* zone;
    Reference<GView::Object> obj;
    int internalArchitecture;
    bool detectLocalVariables;
    std::function<bool(uint64)> isFileAddress;
    const std::map<uint64, DissasmFunctionEntry>* functionEntries;
    const std::set<uint64>* codeLocations; // Settings::AddCodeLocation (file offsets): never function starts
    const std::vector<LandingPad>* landingPads; // Settings::AddLandingPads (file offsets): the exception handling of GCC / clang
    const std::map<uint64, uint64>* codeRanges; // Settings::AddCodeRange (file offset -> size): the FDEs of ELF, the ARM64 fragments of PE
    std::function<const MemoryMappingEntry*(const X86OperandsInfo&)> findImport;
    std::function<std::optional<uint64>(uint64)> addressToFileOffset;

    Phase phase = Phase::Sweep;
    // the code is [codeStart, codeStart + codeSize): the same lines as the ones counted by DissasmLineCounter
    const uint64 codeStart;
    const uint64 codeSize;
    uint32 lines; // the lines of the zone (counted again when tables became data lines)
    uint32 linesToDecode;
    const bool is64;
    const uint64 addressMask; // the addresses of 32 bit code wrap around at 4 GB
    const uint64 labelBase;
    const DissasmArch arch;
    const std::optional<uint64> imageBase;

    // the instruction set of the zone and the tables found by the previous sweeps; the lines counted with them
    DissasmInstructionSet instructionSet;
    std::vector<DissasmInstructionSet::DataRange> pendingRanges; // found by this sweep, not yet data lines
    // 32 bit: the immediates of the code that are addresses of the code zone (push offset X / mov eax, offset X) and their instruction:
    // the exception tables of MSVC among them (AddExceptionData), the __ehhandler stubs (MarkX86ExceptionScopes); relative
    std::vector<std::pair<uint64, uint64>> exceptionTableCandidates;
    // 32 bit: the exception tables AddExceptionData read (the last sweep), by relative address: the records of the SEH4 scope tables, the
    // FuncInfo of the C++ exception handling (the parent state of every state and its unwind action, the try blocks and their catch blocks)
    struct X86ScopeRecord {
        int32 enclosing;
        uint32 filter;  // 0: __finally, 1: EXCEPTION_EXECUTE_HANDLER, else the VA of the filter
        uint64 handler; // the __except / __finally block
    };
    struct X86TryBlock {
        int32 low, high;
        std::vector<std::pair<uint64, std::string>> catches; // the catch block (NO_TARGET: not in the zone), the type it takes
    };
    struct X86FuncInfo {
        std::vector<int32> parentStates;
        std::vector<uint64> actions; // NO_TARGET: none
        std::vector<X86TryBlock> tryBlocks;
    };
    std::map<uint64, std::vector<X86ScopeRecord>> x86ScopeTables;
    std::map<uint64, X86FuncInfo> x86FuncInfos;
    std::unordered_map<uint64, std::string> exceptionFieldNames; // the fields of the exception tables: DissasmCodeZone::fieldNames
    std::unique_ptr<DissasmLineCounter> recounter;
    std::vector<AsmOffsetLine> recountedOffsets;
    bool recounted = false;
    bool recountOnly = false; // the reached padding: the lines are counted again, the sweep is not done again (no instruction moves)
    // the align lines of the sweep and how the code reaches them: the line before falls through (after a call or not)
    struct PaddingRun {
        uint64 start, end;
        bool fallsThrough, afterCall;
        uint64 previousAddress; // the line before (relative): a call that does not return does not go on into the padding
    };
    std::vector<PaddingRun> paddingRuns;
    bool previousFallsThrough = false, previousIsCall = false;
    uint64 previousAddress    = 0;
    // the instructions that change the flow (the functions that do not return, InferNoReturnFunctions): relative addresses, in the order
    // of the sweep
    enum class FlowKind : uint8 { Call, Jump, ConditionalJump, Return, Trap, Unknown, MaybeReturn }; // MaybeReturn: a conditional return
    static constexpr uint64 NO_TARGET = UINT64_MAX;
    struct FlowRecord {
        uint64 address;
        uint64 target; // a direct branch (relative); NO_TARGET: an indirect one
        uint8 size;
        FlowKind kind;
        bool noReturnImport; // through the slot of an import that does not return
        bool localImport;    // through the slot of an import named as a function of the zone (localImports)
    };
    std::vector<FlowRecord> flowRecords;
    std::unordered_map<uint64, std::string> localImports;       // relative address of the instruction -> the import
    std::unordered_map<uint64, uint32> importCallCategories;   // a call / jmp through an import slot -> what the import does (DissasmApiCategory)
    std::unordered_set<uint64> comProducerCalls;               // the calls of an API that gives a COM interface (FindComProducer)
    std::unordered_map<uint64, std::string> interfaceCalls;    // TrackComInterfaces: DissasmCodeZone::interfaceCalls
    std::unordered_map<uint64, std::pair<size_t, std::string_view>> comOutputs; // a call: its parameter that receives an interface, which one
    std::unordered_set<uint64> cfgCheckCalls;                  // x86: the CFG checks of the calls of the methods (they take no argument)
    std::unordered_set<uint64> knownPrototypeCalls;            // the calls through an import slot of an API with a prototype (FindApiPrototype)
    std::unordered_set<uint64> demangledPrototypeCalls;        // the same of a demangled C++ name (its types only: no seed of the inference)
    std::unordered_map<uint64, bool> knownPrototypeTargets;    // a direct target (relative) -> its name has a prototype (NameVariablesFromCalls)
    std::map<uint64, std::shared_ptr<const DissasmUserPrototype>> inferredPrototypes; // InferPrototypes, by function start
    // x86 / x64: the incoming argument whose address a call of the function passes as its va_list (NameVariablesFromCalls; the format wrappers:
    // _vsnwprintf(buffer, count, format, &first)): the index of that argument, the type of the format passed before it, two that differ
    struct VariadicArgumentSlot {
        uint32 first = 0;
        std::string_view formatType;
        bool conflict = false;
    };
    std::optional<VariadicArgumentSlot> variadicArgumentSlot;
    std::map<std::string, std::shared_ptr<const DissasmUserPrototype>, std::less<>> methodPrototypes; // AddGccMethodPrototypes, by name
    std::vector<std::pair<uint64, std::string>> functionComparisons; // the walk of a function: its cmp of a returned value with a constant
    std::unordered_map<uint64, std::vector<std::pair<uint64, std::string>>> comparisonsByFunction; // the last walk of each function
    std::unordered_map<uint64, std::string> returnValueConstants;                                 // DissasmCodeZone::returnValueConstants
    std::unordered_map<uint64, std::pair<std::string, std::string>> argumentDefinitions;          // DissasmCodeZone::argumentDefinitions
    // x64 structured exception handling (CollectExceptionScopes): the funclets with the frame of their function (relative starts; the
    // unwind data of the function: its prologue size, its frame register and offset / 16), the marks of the scopes
    struct FuncletLink {
        uint64 funclet, parent;
        uint64 size; // of the funclet (its .pdata entry), 0: unknown
        uint8 prologSize, frameRegister, frameOffset;
    };
    std::vector<FuncletLink> funcletLinks;
    std::unordered_multimap<uint64, size_t> funcletsOfParent; // the funclets of a function (their top function), by its start
    // ARM64: the funclets of a function (SEH / C++ EH: their x29 is its frame, the unwinder gives it: mov x29, x1 / used as it is), relative
    // starts: the top function of each funclet, the funclets of a function
    std::unordered_map<uint64, uint64> arm64FuncletParents;
    std::unordered_multimap<uint64, uint64> arm64FuncletsOfParent;
    std::vector<DissasmFunctionFrame> pendingChunkFrames;      // AddChunkFrames / AddX86FuncletSlots: the frames of the chunks / funclets, until Commit
    // 32 bit MSVC: the code the exception handling runs on the frame of a function (its ebp: the catch blocks, the unwind funclets, the
    // filters / __finally / __except blocks of SEH4), by the start of the function (MarkX86ExceptionScopes)
    std::unordered_multimap<uint64, uint64> x86FuncletsOfParent;
    std::unordered_map<uint64, std::vector<DissasmCodeZone::ExceptionMark>> exceptionMarks; // DissasmCodeZone::exceptionMarks
    std::unordered_map<std::string, uint64> localFunctionNames; // the names of the plugin of the functions of the zone -> relative start
    std::unordered_set<uint64> noReturnStarts; // relative starts of the functions that do not return: their names, then InferNoReturnFunctions
    std::unordered_set<uint64> userReturns;    // the functions the user says return (USER_FUNCTION_RETURNS): never noreturn
    std::unordered_set<uint64> noReturnCalls;  // relative addresses of the calls to them
    // ARM64: the calls of a helper that keeps the registers but x16 / x17 and may move sp (Arm64HelperStackChange: MSVC's
    // __security_push_cookie, -0x10; __chkstk, 0), by relative address: the change of sp (FindArm64StackHelpers)
    std::unordered_map<uint64, int32> stackHelperCalls;
    uint32 passes  = 1;
    std::map<uint64, uint64> tableEntries; // relative address of an entry of a table -> the relative address of its case

    csh handle           = 0;
    cs_insn* insn        = nullptr;
    csh detailHandle     = 0;
    bool hasDetailHandle = false;
    // the same addresses as the drawn lines: 0 is the first decoded instruction; the undecodable bytes are data lines
    DissasmCodeLinesWalker walker;
    X86PrologueDetector prologueDetector;
    X86SwitchDetector switchDetector;
    bool atBlockStart = true; // the previous instruction does not continue into the current one (ret, jmp, int3, nop padding)
    std::optional<uint64> blockEndbr;  // the endbr64 / endbr32 that starts the current block (CET: the stubs start with it)

    std::vector<std::pair<uint64, std::string>> callsFound; // file offset of a label, its name
    std::unordered_map<uint64, bool> callsMap;              // true for loc, false for sub
    std::vector<std::pair<uint64, std::string>> thunks;     // file offset of an import thunk, the import
    // ARM64EC: the calls through __os_arm64x_dispatch_call_no_redirect (an exit thunk: true) and the jumps through __os_arm64x_dispatch_ret
    // (the end of an entry thunk: false), relative addresses (NameArm64ECThunks)
    std::vector<std::pair<uint64, bool>> arm64ECThunkCalls;

    // the results, given to the zone by Commit
    DissasmXrefs xrefs;
    std::unordered_map<uint64, std::string> thunkImports;
    std::unordered_map<uint64, uint64> otherZoneJumps; // a jmp / b to the code of another zone that starts a block (relative) -> its VA
    std::unordered_map<uint64, uint32> switchJumps;
    std::unordered_map<uint64, uint64> resolvedAddresses; // ARM64: the addresses of the adrp pairs
    std::unordered_map<uint64, uint64> adrpPages;         // ARM64: the address of the first pair of each adrp
    std::unordered_map<uint64, uint64> imageBaseTables;   // x64: the tables read through a register holding the image base
    std::array<bool, 16> imageBaseRegisters{};            // x64: the registers that hold the image base (lea reg, __ImageBase), per function
    Arm64AdrpTracker adrpTracker;
    Arm32Tracker arm32Tracker;
    std::vector<uint64> prologueCandidates;         // ARM64: file offsets of the prologues at a block start
    // the code whose address is taken (lea rcx, [rip + func], push offset func; the pointer tables of the data zones): a function when it
    // starts a block (after a ret / jmp / padding), relative addresses
    std::vector<uint64> addressTakenTargets;
    std::vector<uint64> dataPointerTargets; // every pointer of the data zones into the code (relative): the code they reach is reached
    // ARM64: the anchors of the jump tables (adr x9, anchor; ldrsw x8, [x10, w0, uxtw #2]; add x8, x9, x8, lsl #2; br x8), relative: code of
    // the function of the switch (MSVC puts it after a case, the cases on both sides of it), not a function whose address is taken
    std::unordered_set<uint64> switchAnchors;
    // ARM64: the targets of the br through an address built by adrp + add (the veneers to the far cold code), relative: jumps, not the
    // address of a function taken by the add
    std::unordered_set<uint64> farJumpTargets;
    std::vector<bool> blockStarts; // the instructions that start a block, by relative address
    std::optional<uint64> returnedAddress; // mov eax, offset X: an address taken only when the next instruction is not a ret
    // 32 bit x86 PIC: the value of ebx (the global offset table, VA) set by call $+5; pop ebx / call __x86.get_pc_thunk.bx, then add ebx, imm;
    // functionEbx: the value of the function (ebx comes back after an epilogue path), until the next function
    std::optional<uint64> ebxValue, functionEbx, pendingPopEbx;
    std::optional<uint64> globalOffsetTable; // set by the constructor
    std::unordered_set<uint64> conditionalTargets;  // ARM64: relative targets of the conditional branches
    std::vector<uint64> functionStarts;
    std::unordered_map<uint64, std::optional<uint32>> calleePurges; // 32 bit: what the functions of the zone pop (ret 8), by start
    std::unordered_map<uint64, bool> frameHelpers;                  // 32 bit: the functions that build the frame of their caller, by start
    std::unordered_set<uint64> helperFrameStarts;                   // 32 bit: the jump targets that start with a frame helper (FinishSweep)
    AnnotationContainer annotations;
    std::vector<DissasmFunctionFrame> frames;
    std::vector<uint64> functionEnds; // ComputeFunctionEnds
    std::unordered_map<uint64, std::vector<uint64>> switchCaseTargets; // SwitchCases() once the sweeps end: the frames go on with the cases
    std::vector<uint64> computedGotoTargets; // DemoteComputedGotoTargets: the endbr64 starts that are locations of their function (sorted)
    // the landing pads of the unwinding (Settings::AddLandingPads) and their call sites, relative, sorted: a pad is code of the function or
    // of the chunk of its call site (the unwinder goes there from it, as a jump)
    std::vector<std::pair<uint64, uint64>> landingPadSources;
    std::vector<DissasmFunctionChunk> chunks; // DetectFunctionChunks
    std::vector<DissasmFunctionChunk> coldChunks;         // the chunks the jumps tell, the code locations: their slots on the frame of their function
    std::unordered_multimap<uint64, size_t> coldChunksOf; // the cold chunks of a function (indexes in coldChunks), by its start
    std::vector<uint32> functionApiCategories; // ComputeApiCategories
    size_t labelIndex = 0; // the next label placed on its line
    uint32 extraLines = 0;

    DissasmDeepScan(DissasmCodeZone* zone, const DissasmCodeZoneInitData& initData, int internalArchitecture, uint32 asmLines)
        : zone(zone), obj(initData.obj), internalArchitecture(internalArchitecture), detectLocalVariables(initData.enableLocalVariablesDetection),
          isFileAddress(initData.isFileAddress), functionEntries(initData.functionEntries), codeLocations(initData.codeLocations),
          landingPads(initData.landingPads), codeRanges(initData.codeRanges), findImport(initData.findImport),
          addressToFileOffset(initData.addressToFileOffset), codeStart(zone->cachedCodeOffsets[0].offset), codeSize(zone->GetCodeSize()), lines(asmLines),
          linesToDecode(asmLines), is64(zone->Is64BitCode()), addressMask(is64 ? UINT64_MAX : 0xFFFFFFFFull), labelBase(zone->labelAddressBase),
          arch(zone->GetArch()), imageBase(initData.imageBase), instructionSet(zone->instructionSet), walker(initData.obj, codeStart, codeSize, 0),
          prologueDetector(is64), switchDetector(is64, zone->labelAddressBase, initData.imageBase), adrpTracker(zone->labelAddressBase),
          arm32Tracker(zone->labelAddressBase, LiteralReader())
    {
        globalOffsetTable = initData.globalOffsetTable;
    }

    // a word of a literal pool (32 bit ARM)
    Arm32Tracker::ReadWord LiteralReader()
    {
        return [this](uint64 relativeAddress) -> std::optional<uint32> {
            if (!addressToFileOffset)
                return {};
            const auto value = ReadTableValue(labelBase + relativeAddress, 4);
            return value.has_value() ? std::optional<uint32>(static_cast<uint32>(value.value())) : std::nullopt;
        };
    }

    ~DissasmDeepScan()
    {
        if (insn)
            cs_free(insn, 1);
        if (handle != 0)
            cs_close(&handle);
        if (hasDetailHandle)
            cs_close(&detailHandle);
    }

    static LabelType GetLabelType(const std::string& name)
    {
        if (name.size() < 4)
            return OTHER;
        if (memcmp(name.c_str(), "sub_", 4) == 0)
            return SUB;
        if (memcmp(name.c_str(), "loc_", 4) == 0)
            return OFFSET;
        return OTHER;
    }

    void AddFunctionStart(uint64 functionOffset)
    {
        const auto it = callsMap.find(functionOffset);
        if (it != callsMap.end() && !it->second)
            return; // already a sub
        callsFound.emplace_back(functionOffset, zone->GetLabelName("sub_", functionOffset - codeStart));
        callsMap.insert({ functionOffset, false });
    }

    bool Start()
    {
        if (codeSize == 0)
            return false;
        // the instruction details give the branches and their targets (GetX86Flow / GetX86OperandsInfo)
        if (cs_open(zone->capstoneArch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK) {
            handle = 0;
            return false;
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
            return false;
        insn   = cs_malloc(handle);
        walker = DissasmCodeLinesWalker(obj, codeStart, codeSize, handle, 0, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
        callsFound.reserve(16);
        constexpr uint64 MAX_BLOCK_STARTS_MAP = 256ull * 1024 * 1024; // a bit per byte of code
        if (!zone->zoneDetails.isData && codeSize <= MAX_BLOCK_STARTS_MAP)
            blockStarts.assign(static_cast<size_t>(codeSize), false);
        if (zone->zoneDetails.isData) {
            StartDataZone();
            return true;
        }
        AddPluginFunctions();
        return true;
    }

    // a data zone: no instructions to sweep; its labels are the places the code of the other zones refers to (named after what is there:
    // aText for a string, off_ for pointers, unk_ for the other bytes), its pointers are references to what they point to
    void StartDataZone()
    {
        for (const auto& range : instructionSet.dataRanges) {
            if (!range.isOffset || range.unit == 0)
                continue;
            for (uint64 entry = range.start; entry + range.unit <= range.end; entry += range.unit) {
                auto value = ReadTableValue(labelBase + entry, range.unit);
                if (value.has_value() && range.reference == DissasmInstructionSet::REFERENCE_RVA)
                    value = imageBase.has_value() ? std::optional<uint64>(imageBase.value() + value.value()) : std::nullopt;
                else if (value.has_value() && range.reference == DissasmInstructionSet::REFERENCE_RELATIVE)
                    value = labelBase + entry + static_cast<uint64>(range.unit == 4 ? static_cast<int64>(static_cast<int32>(value.value())) : static_cast<int64>(value.value()));
                if (value.has_value() && isFileAddress && isFileAddress(value.value()))
                    xrefs.Add(labelBase + entry, value.value(), DissasmXrefKind::Offset);
            }
        }
        xrefs.Finish();
        std::unordered_set<std::string> usedNames;
        std::vector<uint64> targets;
        std::vector<uint8> targetSizes;
        zone->CollectDataZoneTargets(targets, targetSizes);
        LocalString<64> text;
        for (size_t targetIndex = 0; targetIndex < targets.size(); targetIndex++) {
            const uint64 target = targets[targetIndex];
            std::string name;
            const auto* range = instructionSet.DataRangeAt(target);
            if (range && range->start == target && (range->unit == DissasmInstructionSet::ASCII_STRING || range->unit == DissasmInstructionSet::UTF16_STRING)) {
                // the text of the string (UTF-16: the low bytes)
                const bool wide    = range->unit == DissasmInstructionSet::UTF16_STRING;
                const auto view    = GetZoneBytes(obj, codeStart + target, static_cast<uint32>(std::min<uint64>(range->end - target, 64)));
                std::string value;
                for (size_t index = 0; view.IsValid() && index < view.GetLength(); index += wide ? 2 : 1)
                    value.push_back(static_cast<char>(view.GetData()[index]));
                name = MakeStringLabelName(value, labelBase + target);
            } else {
                X86OperandsInfo operands;
                operands.absoluteMemory = labelBase + target;
                const auto* import      = findImport ? findImport(operands) : nullptr;
                if (import && !import->name.empty()) {
                    // an import slot: __imp_ and the name of the import (a demangled C++ name keeps its letters and digits); a slot named by
                    // the metadata (TextMapping: selRef_alloc, classRef_NSString, _OBJC_CLASS_$_Animal) keeps its name
                    name = import->type == MemoryMappingType::FunctionMapping ? "__imp_" : "";
                    // the names of the metadata keep the characters of the C++ names (Animal::vftable, std::pair<int,int>::typeinfo)
                    const bool isMetadata = import->type == MemoryMappingType::TextMapping;
                    for (const char c : import->name)
                        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' ||
                            (isMetadata && (c == ':' || c == '<' || c == '>' || c == '~' || c == ',' || c == '{' || c == '}' || c == '(' ||
                                            c == ')' || c == '-')))
                            name.push_back(c);
                        else if (name.back() != '_')
                            name.push_back('_');
                } else if (const auto guid = GetZoneBytes(obj, codeStart + target, 16); guid.IsValid() && guid.GetLength() == 16 && target + 16 <= codeSize &&
                                                                                                  !FindGuidName(guid.GetData()).empty()) {
                    name = FindGuidName(guid.GetData()); // IID_IWbemLocator, CLSID_ShellLink, FOLDERID_Startup (IDA names the known GUIDs)
                } else {
                    // IDA: the type of what the code reads / writes there (byte_, word_, dword_, qword_, xmmword_), off_ for pointers
                    const uint8 size   = targetSizes[targetIndex];
                    const char* prefix = range && range->isOffset ? "off_"
                                         : size == 1          ? "byte_"
                                         : size == 2          ? "word_"
                                         : size == 4          ? "dword_"
                                         : size == 8          ? "qword_"
                                         : size == 16         ? "xmmword_"
                                                              : "unk_";
                    text.SetFormat("%s%llX", prefix, static_cast<unsigned long long>(labelBase + target));
                    name = text.GetText();
                }
            }
            // a name used twice: aText_1, aText_2, ...
            std::string unique = name;
            for (uint32 index = 1; usedNames.contains(unique) && index < 1000; index++)
                unique = name + "_" + std::to_string(index);
            usedNames.insert(unique);
            callsFound.emplace_back(codeStart + target, std::move(unique));
            callsMap.insert({ codeStart + target, true });
        }
        phase = Phase::Labels; // sorted: the targets are
    }

    // the functions known by the plugin (exports, exception data, TLS callbacks): functions even when nothing calls them directly
    void AddPluginFunctions()
    {
        localFunctionNames.clear();
        if (functionEntries) {
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it) {
                AddFunctionStart(it->first);
                if (it->second.name.empty())
                    continue;
                localFunctionNames.emplace(it->second.name, it->first - codeStart);
                if (IsNoReturnFunctionName(it->second.name))
                    noReturnStarts.insert(it->first - codeStart); // exit, abort, __stack_chk_fail of the symbols / exports
            }
        }
        // the functions of the user (P) and their attributes
        userReturns.clear();
        for (const auto& [address, flags] : zone->userFunctions) {
            if (address >= codeSize)
                continue;
            if (flags & USER_FUNCTION_CREATE)
                AddFunctionStart(codeStart + address);
            if (flags & USER_FUNCTION_NORETURN)
                noReturnStarts.insert(address);
            if (flags & USER_FUNCTION_RETURNS)
                userReturns.insert(address);
        }
    }

    // a new sweep on the lines counted again: everything found by the previous one is dropped
    void ResetSweep()
    {
        prologueDetector = X86PrologueDetector(is64);
        switchDetector   = X86SwitchDetector(is64, labelBase, imageBase);
        atBlockStart     = true;
        blockEndbr.reset();
        callsFound.clear();
        callsMap.clear();
        thunks.clear();
        arm64ECThunkCalls.clear();
        xrefs = DissasmXrefs{};
        thunkImports.clear();
        otherZoneJumps.clear();
        switchJumps.clear();
        resolvedAddresses.clear();
        adrpPages.clear();
        imageBaseTables.clear();
        imageBaseRegisters.fill(false);
        adrpTracker  = Arm64AdrpTracker(labelBase);
        arm32Tracker = Arm32Tracker(labelBase, LiteralReader());
        prologueCandidates.clear();
        conditionalTargets.clear();
        addressTakenTargets.clear();
        dataPointerTargets.clear();
        switchAnchors.clear();
        farJumpTargets.clear();
        computedGotoTargets.clear();
        x86FuncletsOfParent.clear();
        helperFrameStarts.clear();
        coldChunks.clear();
        coldChunksOf.clear();
        returnedAddress.reset();
        ebxValue.reset();
        functionEbx.reset();
        pendingPopEbx.reset();
        blockStarts.assign(blockStarts.size(), false);
        tableEntries.clear();
        pendingRanges.clear();
        exceptionTableCandidates.clear();
        paddingRuns.clear();
        previousFallsThrough = previousIsCall = false;
        previousAddress = 0;
        flowRecords.clear();
        localImports.clear();
        importCallCategories.clear();
        knownPrototypeCalls.clear();
        demangledPrototypeCalls.clear();
        comProducerCalls.clear();
        noReturnStarts.clear();
        noReturnCalls.clear();
        linesToDecode = lines;
        walker        = DissasmCodeLinesWalker(obj, codeStart, codeSize, handle, 0, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
        AddPluginFunctions();
    }

    // the bytes [start, end) (relative) of a table inside the code: data lines of `unit` bytes after the next sweep. A range that covers
    // a function entry / a section start, or overlaps another table, is not a table
    void AddDataCandidate(uint64 start, uint64 end, uint8 unit, bool isOffset = false)
    {
        end = std::min(end, codeSize);
        if (start >= end)
            return;
        const auto boundary = std::upper_bound(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), start);
        if (boundary != zone->instructionBoundaries.end() && *boundary < end)
            return;
        const DissasmInstructionSet::DataRange range{ start, end, unit, isOffset };
        if (const auto* known = instructionSet.DataRangeAt(start); known && known->start == start && known->end == end)
            return; // a data line already
        for (const auto& pending : pendingRanges)
            if (pending.start < end && start < pending.end)
                return;
        DissasmInstructionSet check = instructionSet;
        if (check.AddDataRange(range))
            pendingRanges.push_back(range);
    }

    // a jump table (VA) inside the code: its entries (the VA of the case of every entry) become data lines with the names of their cases,
    // its first entry gets a label (IDA: jpt_ + the address of the jump) read by the jump
    void AddTable(uint64 jumpAddress, uint64 from, uint64 table, uint8 unit, const std::vector<uint64>& entryTargets, bool alignEnd)
    {
        if (table < labelBase || table - labelBase >= codeSize || entryTargets.empty() || unit == 0)
            return;
        const uint64 start = table - labelBase;
        uint64 end         = start + entryTargets.size() * unit;
        if (alignEnd) // Thumb: the instruction after a tbb table of an odd size is 2 bytes aligned
            end = (end + 1) & ~static_cast<uint64>(1);
        AddDataCandidate(start, end, unit);
        for (size_t index = 0; index < entryTargets.size(); index++)
            if (entryTargets[index] >= labelBase)
                tableEntries[start + index * unit] = entryTargets[index] - labelBase;
        xrefs.Add(from, table, DissasmXrefKind::Read);
        const uint64 tableOffset = codeStart + start;
        if (!callsMap.contains(tableOffset)) {
            callsFound.emplace_back(tableOffset, zone->GetLabelName("jpt_", jumpAddress));
            callsMap.insert({ tableOffset, true });
        }
    }

    // the line of the instruction at a file offset (the lines of the scan: counted again when tables became data lines); none after the
    // last decoded line. The labels come by address: the walk goes on from the line of the previous one when it is not behind the target
    // and not before the closest cached offset (one decoding of the lines for all the labels, not one per label from its cached offset)
    std::optional<DissasmCodeLinesWalker> labelWalker;
    uint32 labelWalkerLine = 0; // the line of the instruction at labelWalker->GetAddress()
    std::optional<uint32> LineOfOffset(uint64 fileOffset)
    {
        const auto& offsets = recounted ? recountedOffsets : zone->cachedCodeOffsets;
        if (offsets.empty() || fileOffset < codeStart)
            return {};
        auto closest = std::upper_bound(offsets.begin(), offsets.end(), fileOffset, [](uint64 value, const AsmOffsetLine& item) { return value < item.offset; });
        --closest; // the first cached offset is the code start
        const uint64 target = fileOffset - codeStart;
        if (!labelWalker.has_value() || labelWalker->GetAddress() > target || labelWalker->GetAddress() < closest->offset - codeStart) {
            labelWalker.emplace(
                  obj, codeStart, codeSize, handle, closest->offset - codeStart, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
            labelWalkerLine = closest->line;
        }
        while (labelWalker->Next(insn)) {
            const uint32 line = labelWalkerLine++;
            if (labelWalker->GetAddress() > target)
                return line;
        }
        labelWalker.reset(); // the end of the code
        return {};
    }

    // a field of an exception table: relative address, size, a pointer (shown with the name of what it points to), its name
    struct ExceptionField {
        uint64 address;
        uint8 size;
        bool pointer;
        std::string name;
    };

    // a dword of the code zone (relative address)
    std::optional<uint32> ReadCodeDword(uint64 address)
    {
        uint32 value = 0;
        if (address + 4 > codeSize || !obj->GetData().Copy<uint32>(codeStart + address, value))
            return std::nullopt;
        return value;
    }

    // a VA of the code zone: relative, none otherwise
    std::optional<uint64> CodeAddressOf(uint32 value) const
    {
        return value >= labelBase && value - labelBase < codeSize ? std::optional<uint64>(value - labelBase) : std::nullopt;
    }

    // the scope table of SEH4 (_EH4_SCOPETABLE, the operand of push before __SEH_prolog4): the GS and EH cookie offsets (-2: none, else a
    // negative offset from ebp), then the records { EnclosingLevel (-2 for the first), FilterFunc (0: __finally), HandlerFunc } of the code
    bool ReadScopeTable(uint64 table, std::vector<ExceptionField>& fields, std::vector<X86ScopeRecord>& parsed)
    {
        constexpr uint32 MAX_RECORDS = 64;
        const auto isCookieOffset = [](std::optional<uint32> value) {
            return value.has_value() && (value.value() == 0xFFFFFFFE || value.value() == 0 || (value.value() >= 0xFFFF0000u));
        };
        std::array<std::optional<uint32>, 4> header{ ReadCodeDword(table), ReadCodeDword(table + 4), ReadCodeDword(table + 8), ReadCodeDword(table + 12) };
        if (!isCookieOffset(header[0]) || !isCookieOffset(header[2]) || !header[1].has_value() || !header[3].has_value() || header[1].value() > 0x10000 ||
            header[3].value() > 0x10000)
            return false;
        std::vector<ExceptionField> found = { { table, 4, false, "GSCookieOffset" },
                                              { table + 4, 4, false, "GSCookieXOROffset" },
                                              { table + 8, 4, false, "EHCookieOffset" },
                                              { table + 12, 4, false, "EHCookieXOROffset" } };
        uint32 records = 0;
        for (; records < MAX_RECORDS; records++) {
            const uint64 record = table + 16 + 12ull * records;
            const auto level = ReadCodeDword(record), filter = ReadCodeDword(record + 4), handler = ReadCodeDword(record + 8);
            const auto handlerAddress = handler.has_value() ? CodeAddressOf(handler.value()) : std::nullopt;
            const auto filterAddress  = filter.has_value() && filter.value() > 1 ? CodeAddressOf(filter.value()) : std::nullopt;
            if (!level.has_value() || !handlerAddress.has_value() || (level.value() != 0xFFFFFFFE && level.value() >= records) ||
                (filter.value_or(2) > 1 && !filterAddress.has_value()) || (records == 0 && level.value() != 0xFFFFFFFE))
                break;
            const std::string prefix = "ScopeRecord[" + std::to_string(records) + "].";
            found.push_back({ record, 4, false, prefix + "EnclosingLevel" });
            found.push_back({ record + 4, 4, filter.value() > 1, prefix + "FilterFunc" });
            found.push_back({ record + 8, 4, true, prefix + "HandlerFunc" });
            parsed.push_back({ static_cast<int32>(level.value()), filter.value(), handlerAddress.value() });
        }
        if (records == 0)
            return false;
        fields.insert(fields.end(), found.begin(), found.end());
        return true;
    }

    // the type a catch takes: its TypeDescriptor (x86: pVFTable, spare, then the name: .?AVbad_alloc@std@@) with the adjectives (const, a
    // reference); "..." for all
    std::string CatchTypeName(uint32 adjectives, uint32 type)
    {
        constexpr uint32 HT_IS_CONST = 1, HT_IS_REFERENCE = 8, HT_IS_STD_DOT_DOT = 0x40, MAX_NAME = 256;
        if (type == 0 || (adjectives & HT_IS_STD_DOT_DOT))
            return "...";
        const auto offset = addressToFileOffset ? addressToFileOffset(static_cast<uint64>(type) + 8) : std::nullopt;
        std::string name;
        for (uint32 index = 0; offset.has_value() && index < MAX_NAME; index++) {
            uint8 c = 0;
            if (!obj->GetData().Copy<uint8>(offset.value() + index, c) || c == 0)
                break;
            if (c < 0x20 || c > 0x7E)
                return "?";
            name.push_back(static_cast<char>(c));
        }
        if (name.empty())
            return "?";
        std::string text = (adjectives & HT_IS_CONST) ? "const " : "";
        text += DemangleMsvcTypeName(name);
        if (adjectives & HT_IS_REFERENCE)
            text += " &";
        return text;
    }

    // the FuncInfo of the C++ exception handling (mov eax, offset FuncInfo; jmp __CxxFrameHandler3): its magic, then the maps it points to
    // in the code zone: the unwind map { toState, action }, the try blocks { tryLow, tryHigh, catchHigh, nCatches, pHandlerArray } and
    // their handlers { adjectives, pType, dispCatchObj, addressOfHandler }. The unwind actions are funclets (functions of .text$x after
    // the code: lea ecx, [ebp - 0x18]; jmp dtor); the catch blocks are code of their function (they return the address where it goes on)
    bool ReadFuncInfo(uint64 table, std::vector<ExceptionField>& fields, std::vector<uint64>& funclets, std::vector<uint64>& tables, X86FuncInfo& parsed)
    {
        constexpr uint32 MAX_STATES = 0x1000, MAX_TRY_BLOCKS = 0x100, MAX_CATCHES = 64;
        const auto magic = ReadCodeDword(table);
        if (!magic.has_value() || (magic.value() & 0x1FFFFFFF) < 0x19930520 || (magic.value() & 0x1FFFFFFF) > 0x19930522)
            return false;
        const auto maxState = ReadCodeDword(table + 4), unwindMap = ReadCodeDword(table + 8), tryCount = ReadCodeDword(table + 12),
                   tryMap = ReadCodeDword(table + 16), ipCount = ReadCodeDword(table + 20), ipMap = ReadCodeDword(table + 24);
        if (!maxState.has_value() || maxState.value() > MAX_STATES || !tryCount.has_value() || tryCount.value() > MAX_TRY_BLOCKS || !unwindMap.has_value() ||
            !tryMap.has_value() || !ipCount.has_value() || !ipMap.has_value())
            return false;
        std::vector<ExceptionField> found = { { table, 4, false, "magicNumber" },      { table + 4, 4, false, "maxState" },
                                              { table + 8, 4, true, "pUnwindMap" },    { table + 12, 4, false, "nTryBlocks" },
                                              { table + 16, 4, true, "pTryBlockMap" }, { table + 20, 4, false, "nIPMapEntries" },
                                              { table + 24, 4, true, "pIPToStateMap" } };
        const uint32 version = magic.value() & 0x1FFFFFFF;
        if (version >= 0x19930521)
            found.push_back({ table + 28, 4, true, "pESTypeList" });
        if (version >= 0x19930522)
            found.push_back({ table + 32, 4, false, "EHFlags" });
        // the unwind map
        if (const auto map = maxState.value() > 0 ? CodeAddressOf(unwindMap.value()) : std::nullopt; map.has_value()) {
            tables.push_back(map.value());
            for (uint32 state = 0; state < maxState.value(); state++) {
                const uint64 entry = map.value() + 8ull * state;
                const auto action  = ReadCodeDword(entry + 4);
                const auto parent  = ReadCodeDword(entry);
                if (!action.has_value() || !parent.has_value())
                    return false;
                parsed.parentStates.push_back(static_cast<int32>(parent.value()));
                parsed.actions.push_back(action.value() != 0 ? CodeAddressOf(action.value()).value_or(NO_TARGET) : NO_TARGET);
                const std::string prefix = "UnwindMap[" + std::to_string(state) + "].";
                found.push_back({ entry, 4, false, prefix + "toState" });
                found.push_back({ entry + 4, 4, action.value() != 0, prefix + "action" });
                if (const auto funclet = action.value() != 0 ? CodeAddressOf(action.value()) : std::nullopt; funclet.has_value())
                    funclets.push_back(funclet.value());
            }
        }
        // the try blocks and their handlers
        if (const auto map = tryCount.value() > 0 ? CodeAddressOf(tryMap.value()) : std::nullopt; map.has_value()) {
            tables.push_back(map.value());
            for (uint32 index = 0; index < tryCount.value(); index++) {
                const uint64 entry   = map.value() + 20ull * index;
                const auto catches   = ReadCodeDword(entry + 12);
                const auto handlers  = ReadCodeDword(entry + 16);
                if (!catches.has_value() || catches.value() > MAX_CATCHES || !handlers.has_value())
                    return false;
                const auto low = ReadCodeDword(entry), high = ReadCodeDword(entry + 4);
                if (!low.has_value() || !high.has_value())
                    return false;
                X86TryBlock block{ static_cast<int32>(low.value()), static_cast<int32>(high.value()), {} };
                const std::string prefix = "TryBlockMap[" + std::to_string(index) + "].";
                found.push_back({ entry, 4, false, prefix + "tryLow" });
                found.push_back({ entry + 4, 4, false, prefix + "tryHigh" });
                found.push_back({ entry + 8, 4, false, prefix + "catchHigh" });
                found.push_back({ entry + 12, 4, false, prefix + "nCatches" });
                found.push_back({ entry + 16, 4, true, prefix + "pHandlerArray" });
                const auto array = catches.value() > 0 ? CodeAddressOf(handlers.value()) : std::nullopt;
                if (!array.has_value()) {
                    parsed.tryBlocks.push_back(std::move(block));
                    continue;
                }
                tables.push_back(array.value());
                for (uint32 handler = 0; handler < catches.value(); handler++) {
                    const uint64 type    = array.value() + 16ull * handler;
                    const auto address   = ReadCodeDword(type + 12);
                    if (!address.has_value())
                        return false;
                    block.catches.emplace_back(CodeAddressOf(address.value()).value_or(NO_TARGET),
                                               CatchTypeName(ReadCodeDword(type).value_or(0), ReadCodeDword(type + 4).value_or(0)));
                    const std::string name = "HandlerType[" + std::to_string(handler) + "].";
                    found.push_back({ type, 4, false, name + "adjectives" });
                    found.push_back({ type + 4, 4, true, name + "pType" });
                    found.push_back({ type + 8, 4, false, name + "dispCatchObj" });
                    found.push_back({ type + 12, 4, true, name + "addressOfHandler" });
                }
                parsed.tryBlocks.push_back(std::move(block));
            }
        }
        fields.insert(fields.end(), found.begin(), found.end());
        return true;
    }

    // 32 bit MSVC: the exception data after the code (.xdata$x: the scope tables of SEH4, the FuncInfo of the C++ exception handling and
    // their maps), referred to by the immediates of the code; it decodes as instructions (the junk after the code). From the first table
    // to the end of the zone: data lines, the tables by field (named, their pointers with the name of what they point to; labels stru_X),
    // the rest dwords. Only when the code before the first table ends there (a ret / jmp and padding) and no function of the plugin is
    // after it. The unwind funclets the tables point to are functions; the filters, the __except / catch blocks are code of their function
    void AddExceptionData()
    {
        exceptionFieldNames.clear();
        x86ScopeTables.clear();
        x86FuncInfos.clear();
        if (exceptionTableCandidates.empty())
            return;
        std::sort(exceptionTableCandidates.begin(), exceptionTableCandidates.end());
        exceptionTableCandidates.erase(std::unique(exceptionTableCandidates.begin(), exceptionTableCandidates.end()), exceptionTableCandidates.end());
        std::vector<ExceptionField> fields;
        std::vector<uint64> funclets, tables;
        std::map<uint64, std::vector<X86ScopeRecord>> scopeTables;
        std::map<uint64, X86FuncInfo> funcInfos;
        for (size_t index = 0; index < exceptionTableCandidates.size(); index++) {
            const uint64 candidate = exceptionTableCandidates[index].first;
            if (((labelBase + candidate) & 3) != 0 || (index > 0 && exceptionTableCandidates[index - 1].first == candidate))
                continue; // a table is aligned on 4; once
            X86FuncInfo info;
            std::vector<X86ScopeRecord> records;
            if (ReadFuncInfo(candidate, fields, funclets, tables, info)) {
                tables.push_back(candidate);
                funcInfos.emplace(candidate, std::move(info));
            } else if (ReadScopeTable(candidate, fields, records)) {
                tables.push_back(candidate);
                scopeTables.emplace(candidate, std::move(records));
            }
        }
        if (tables.empty())
            return;
        std::sort(tables.begin(), tables.end());
        tables.erase(std::unique(tables.begin(), tables.end()), tables.end());
        const uint64 first = tables.front();
        // the code before the first table ends there: its last flow record a ret / jmp / trap, then padding (an align line is a record of
        // an unknown flow: skipped)
        const auto isPadding = [this](uint64 from, uint64 to) {
            for (uint64 address = from; address < to; address++) {
                uint8 value = 0;
                if (!obj->GetData().Copy<uint8>(codeStart + address, value) || (value != 0xCC && value != 0x90 && value != 0))
                    return false;
            }
            return true;
        };
        size_t before = FirstRecordAt(first);
        while (before > 0 && flowRecords[before - 1].kind == FlowKind::Unknown && isPadding(flowRecords[before - 1].address, first))
            before--;
        if (before == 0)
            return;
        const auto& last = flowRecords[before - 1];
        if (last.kind != FlowKind::Return && last.kind != FlowKind::Jump && last.kind != FlowKind::Trap)
            return;
        if (!isPadding(last.address + last.size, first))
            return;
        if (functionEntries)
            for (auto it = functionEntries->lower_bound(codeStart + first); it != functionEntries->end() && it->first - codeStart < codeSize; ++it)
                return; // a function the plugin knows after it: the tables are not at the end
        if (zone->zoneDetails.HasEntryPoint() && zone->zoneDetails.entryPoint >= codeStart + first)
            return;
        // the fields, the dwords between them
        std::sort(fields.begin(), fields.end(), [](const auto& left, const auto& right) { return left.address < right.address; });
        uint64 position = first;
        const auto addGap = [this](uint64 from, uint64 to) { // dwords at the addresses (VA) aligned on 4
            const uint64 aligned = std::min<uint64>(to, ((labelBase + from + 3) & ~3ull) - labelBase);
            const uint64 end4    = std::max<uint64>(aligned, ((labelBase + to) & ~3ull) - labelBase);
            if (from < aligned)
                AddDataCandidate(from, aligned, 1);
            if (aligned < end4)
                AddDataCandidate(aligned, end4, 4);
            if (end4 < to)
                AddDataCandidate(end4, to, 1);
        };
        for (const auto& field : fields) {
            if (field.address < position || field.address + field.size > codeSize)
                continue; // before the first table, overlapping
            if (field.address > position)
                addGap(position, field.address);
            AddDataCandidate(field.address, field.address + field.size, field.size, field.pointer);
            exceptionFieldNames[field.address] = field.name;
            position = field.address + field.size;
        }
        addGap(position, codeSize);
        for (const uint64 table : tables)
            if (table >= first && callsMap.insert({ codeStart + table, true }).second)
                callsFound.emplace_back(codeStart + table, zone->GetLabelName("stru_", table));
        for (const uint64 funclet : funclets)
            if (funclet < first)
                AddTakenCodeAddress(funclet);
        // the blocks the tables point to in the code (reached by the unwinding only): the __except / __finally blocks, the filters, the
        // catch blocks; a label each (IDA: loc_)
        const auto addBlockLabel = [this, first](uint64 address) {
            if (address < first && address < blockStarts.size() && blockStarts[address] && callsMap.insert({ codeStart + address, true }).second)
                callsFound.emplace_back(codeStart + address, zone->GetLabelName("loc_", address));
        };
        for (const auto& [table, records] : scopeTables)
            for (const auto& record : records) {
                addBlockLabel(record.handler);
                if (const auto filter = record.filter > 1 ? CodeAddressOf(record.filter) : std::nullopt; filter.has_value())
                    addBlockLabel(filter.value());
            }
        for (const auto& [table, info] : funcInfos)
            for (const auto& block : info.tryBlocks)
                for (const auto& [handler, type] : block.catches)
                    if (handler != NO_TARGET)
                        addBlockLabel(handler);
        x86ScopeTables = std::move(scopeTables);
        x86FuncInfos   = std::move(funcInfos);
    }

    // a mark of an exception scope on an instruction (relative), not twice the same one
    void AddExceptionMark(uint64 address, const DissasmCodeZone::ExceptionMark& mark)
    {
        auto& marks = exceptionMarks[address];
        if (std::none_of(marks.begin(), marks.end(), [&mark](const auto& other) {
                return other.kind == mark.kind && other.begin == mark.begin && other.handler == mark.handler && other.target == mark.target &&
                       other.catchType == mark.catchType;
            }))
            marks.push_back(mark);
    }

    // 32 bit MSVC: the scopes of the exception tables (AddExceptionData) marked in their function, as 7o / 7p for x64. The try level of
    // SEH4 and the state of the C++ exception handling are stored in [ebp - 4] (mov dword ptr [ebp - 4], 0 / and [ebp - 4], 0 / or
    // [ebp - 4], -1): in the order of the addresses, a scope begins at the store that enters it (__try { / try {), ends at the one that
    // leaves it (} // starts at); its handlers are marked (__except(filter) / __finally / the filter / catch(type), owned by its first
    // begin). The function of a scope table pushes it (push offset stru; call __SEH_prolog4); the one of a FuncInfo refers to its
    // __ehhandler stub (mov eax, offset stub; call __EH_prolog3), the stub to the FuncInfo. The unwind funclets are named after the
    // function (sub_X$dtor$N, as MSVC's symbols)
    void MarkX86ExceptionScopes()
    {
        if (x86ScopeTables.empty() && x86FuncInfos.empty())
            return;
        if (functionEnds.size() != functionStarts.size())
            return;
        const auto functionOf = [this](uint64 address) -> std::optional<size_t> {
            const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), address);
            if (next == functionStarts.begin())
                return std::nullopt;
            const size_t index = static_cast<size_t>(next - functionStarts.begin()) - 1;
            return address < functionEnds[index] ? std::optional<size_t>(index) : std::nullopt;
        };
        csh decoder         = detailHandle;
        const bool ownsHandle = !hasDetailHandle;
        if (ownsHandle) {
            if (cs_open(zone->capstoneArch, static_cast<cs_mode>(internalArchitecture), &decoder) != CS_ERR_OK)
                return;
            if (cs_option(decoder, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
                cs_close(&decoder);
                return;
            }
        }
        cs_insn* decoded = cs_malloc(decoder);
        // the stores of [ebp - 4] of a function: their address, the value
        const auto storesOf = [&](size_t function) {
            std::vector<std::pair<uint64, int32>> stores;
            const uint64 start = functionStarts[function], end = std::min(functionEnds[function], codeSize);
            if (end <= start || !decoded)
                return stores;
            const auto bytes = obj->GetData().CopyToBuffer(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, DISSASM_MAX_ANALYZED_FUNCTION_SIZE)), false);
            const uint8* data = bytes.GetData();
            size_t size       = bytes.IsValid() ? bytes.GetLength() : 0;
            uint64 address    = start;
            // the constants in the registers (xor ebx, ebx; ...; mov [ebp - 4], ebx), by register family; in the order of the addresses
            std::unordered_map<int, int32> constants;
            while (size > 0 && cs_disasm_iter(decoder, &data, &size, &address, decoded)) {
                const cs_x86& x86   = decoded->detail->x86;
                // the state of the C++ exception handling is a byte when the states fit (mov byte ptr [ebp - 4], 2)
                const bool toLevel  = x86.op_count == 2 && x86.operands[0].type == X86_OP_MEM && x86.operands[0].mem.base == X86_REG_EBP &&
                                     x86.operands[0].mem.index == X86_REG_INVALID && x86.operands[0].mem.disp == -4 &&
                                     (x86.operands[0].size == 4 || x86.operands[0].size == 1);
                if (toLevel && x86.operands[1].type == X86_OP_IMM) {
                    const auto value = x86.operands[0].size == 1 ? static_cast<int32>(static_cast<int8>(x86.operands[1].imm)) : static_cast<int32>(x86.operands[1].imm);
                    if (decoded->id == X86_INS_MOV || (decoded->id == X86_INS_AND && value == 0) || (decoded->id == X86_INS_OR && value == -1))
                        stores.emplace_back(decoded->address, value);
                } else if (toLevel && decoded->id == X86_INS_MOV && x86.operands[1].type == X86_OP_REG) {
                    if (const auto known = constants.find(GetX64RegisterFamily(x86.operands[1].reg)); known != constants.end())
                        stores.emplace_back(decoded->address, x86.operands[0].size == 1 ? static_cast<int32>(static_cast<int8>(known->second)) : known->second);
                }
                // the registers written: their constant (xor r, r / mov r, imm / or r, -1) or none; a call: eax, ecx, edx
                const bool writesRegister = x86.op_count >= 1 && x86.operands[0].type == X86_OP_REG && (x86.operands[0].access & CS_AC_WRITE);
                const int family          = writesRegister ? GetX64RegisterFamily(x86.operands[0].reg) : -1;
                std::optional<int32> constant;
                if (writesRegister && x86.op_count == 2 && decoded->id == X86_INS_XOR && x86.operands[1].type == X86_OP_REG && x86.operands[1].reg == x86.operands[0].reg)
                    constant = 0;
                else if (writesRegister && x86.op_count == 2 && decoded->id == X86_INS_MOV && x86.operands[1].type == X86_OP_IMM)
                    constant = static_cast<int32>(x86.operands[1].imm);
                else if (writesRegister && x86.op_count == 2 && decoded->id == X86_INS_OR && x86.operands[1].type == X86_OP_IMM && static_cast<int32>(x86.operands[1].imm) == -1)
                    constant = -1;
                for (uint8 index = 0; index < x86.op_count; index++)
                    if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                        constants.erase(GetX64RegisterFamily(x86.operands[index].reg));
                for (uint8 index = 0; index < decoded->detail->regs_write_count; index++)
                    constants.erase(GetX64RegisterFamily(decoded->detail->regs_write[index]));
                if (decoded->id == X86_INS_CALL)
                    for (const x86_reg reg : { X86_REG_EAX, X86_REG_ECX, X86_REG_EDX })
                        constants.erase(GetX64RegisterFamily(reg));
                if (constant.has_value() && family >= 0)
                    constants[family] = constant.value();
            }
            return stores;
        };
        // the scopes of a function along its stores: begin(scope, address) / end(scope, address) where the scopes containing the level change
        const auto walk = [](const std::vector<std::pair<uint64, int32>>& stores, int32 initial, const std::function<std::vector<int32>(int32)>& scopesOf,
                             const std::function<void(int32, uint64)>& begin, const std::function<void(int32, uint64)>& end) {
            int32 current = initial;
            for (const auto& [address, value] : stores) {
                if (value == current)
                    continue;
                const auto before = scopesOf(current), after = scopesOf(value);
                for (const int32 scope : before)
                    if (std::find(after.begin(), after.end(), scope) == after.end())
                        end(scope, address);
                for (const int32 scope : after)
                    if (std::find(before.begin(), before.end(), scope) == before.end())
                        begin(scope, address);
                current = value;
            }
        };
        using Mark = DissasmCodeZone::ExceptionMark;
        constexpr uint32 MAX_DEPTH = 64;
        // the code the exception handling runs on the frame of the function (once each)
        std::set<std::pair<uint64, uint64>> funclets;
        x86FuncletsOfParent.clear();
        const auto addFunclet = [&](uint64 parent, uint64 funclet) {
            if (funclet != NO_TARGET && funclet < codeSize && funclet != parent && funclets.emplace(parent, funclet).second)
                x86FuncletsOfParent.emplace(parent, funclet);
        };
        // SEH4: the function that pushes the scope table
        std::set<uint64> markedTables;
        for (const auto& [value, from] : exceptionTableCandidates) {
            const auto table = x86ScopeTables.find(value);
            const auto function = functionOf(from);
            if (table == x86ScopeTables.end() || !function.has_value() || !markedTables.insert(value).second)
                continue;
            const auto& records = table->second;
            const auto scopesOf = [&records](int32 level) {
                std::vector<int32> chain;
                for (uint32 depth = 0; depth < MAX_DEPTH && level >= 0 && static_cast<size_t>(level) < records.size(); depth++) {
                    chain.push_back(level);
                    level = records[level].enclosing;
                }
                return chain;
            };
            std::map<int32, uint64> firstBegin;
            const auto scopeMark = [&](int32 level, Mark::Kind kind, uint64 begin) {
                const auto& record = records[level];
                Mark mark{ kind, begin, std::nullopt, std::nullopt, {}, true };
                if (record.filter == 0)
                    mark.handler = record.handler; // __finally
                else {
                    mark.target = record.handler;
                    if (record.filter > 1)
                        mark.handler = CodeAddressOf(record.filter);
                }
                return mark;
            };
            walk(
                  storesOf(function.value()),
                  -2,
                  scopesOf,
                  [&](int32 level, uint64 address) {
                      firstBegin.emplace(level, address);
                      AddExceptionMark(address, scopeMark(level, Mark::Kind::TryBegin, address));
                  },
                  [&](int32 level, uint64 address) {
                      const auto begin = firstBegin.find(level);
                      AddExceptionMark(address, Mark{ Mark::Kind::TryEnd, begin != firstBegin.end() ? begin->second : address, std::nullopt, std::nullopt, {}, true });
                  });
            for (int32 level = 0; static_cast<size_t>(level) < records.size(); level++) {
                const auto begin = firstBegin.find(level);
                auto mark        = scopeMark(level, records[level].filter == 0 ? Mark::Kind::Finally : Mark::Kind::Except, begin != firstBegin.end() ? begin->second : 0);
                mark.owned       = begin != firstBegin.end();
                AddExceptionMark(records[level].handler, mark);
                addFunclet(functionStarts[function.value()], records[level].handler);
                if (const auto filter = records[level].filter > 1 ? CodeAddressOf(records[level].filter) : std::nullopt; filter.has_value()) {
                    mark.kind = Mark::Kind::Filter;
                    AddExceptionMark(filter.value(), mark);
                    addFunclet(functionStarts[function.value()], filter.value());
                }
            }
        }
        // C++: the stub that loads the FuncInfo, the function that refers to the stub
        std::unordered_set<std::string> usedNames;
        for (const auto& call : callsFound)
            usedNames.insert(call.second);
        const auto labelOf = [this](uint64 fileOffset) -> std::pair<uint64, std::string>* {
            const auto call = std::lower_bound(
                  callsFound.begin(), callsFound.end(), fileOffset, [](const auto& item, uint64 value) { return item.first < value; });
            return call != callsFound.end() && call->first == fileOffset ? &*call : nullptr;
        };
        std::set<uint64> markedFuncInfos;
        for (const auto& [value, from] : exceptionTableCandidates) {
            const auto info = x86FuncInfos.find(value);
            const auto stub = functionOf(from);
            if (info == x86FuncInfos.end() || !stub.has_value() || !markedFuncInfos.insert(value).second)
                continue;
            const uint64 stubStart = functionStarts[stub.value()];
            std::optional<size_t> parent;
            for (const auto& [reference, referenceFrom] : exceptionTableCandidates)
                if (reference == stubStart)
                    if (const auto function = functionOf(referenceFrom); function.has_value() && function.value() != stub.value()) {
                        parent = function;
                        break;
                    }
            if (!parent.has_value())
                continue;
            const auto& tryBlocks = info->second.tryBlocks;
            const auto scopesOf   = [&tryBlocks](int32 state) {
                std::vector<int32> blocks;
                for (size_t index = 0; index < tryBlocks.size(); index++)
                    if (state >= tryBlocks[index].low && state <= tryBlocks[index].high)
                        blocks.push_back(static_cast<int32>(index));
                return blocks;
            };
            std::map<int32, uint64> firstBegin;
            walk(
                  storesOf(parent.value()),
                  -1,
                  scopesOf,
                  [&](int32 block, uint64 address) {
                      firstBegin.emplace(block, address);
                      AddExceptionMark(address, Mark{ Mark::Kind::CppTryBegin, address, std::nullopt, std::nullopt, {}, true });
                  },
                  [&](int32 block, uint64 address) {
                      const auto begin = firstBegin.find(block);
                      AddExceptionMark(address, Mark{ Mark::Kind::TryEnd, begin != firstBegin.end() ? begin->second : address, std::nullopt, std::nullopt, {}, true });
                  });
            for (size_t index = 0; index < tryBlocks.size(); index++) {
                const auto begin = firstBegin.find(static_cast<int32>(index));
                for (const auto& [handler, type] : tryBlocks[index].catches)
                    if (handler != NO_TARGET) {
                        AddExceptionMark(handler, Mark{ Mark::Kind::Catch, begin != firstBegin.end() ? begin->second : 0, std::nullopt, std::nullopt, type,
                                                        begin != firstBegin.end() });
                        addFunclet(functionStarts[parent.value()], handler);
                    }
            }
            for (const uint64 action : info->second.actions)
                addFunclet(functionStarts[parent.value()], action);
            // the unwind funclets: sub_X$dtor$N (once each, not over a name of the plugin)
            const auto* parentLabel = labelOf(codeStart + functionStarts[parent.value()]);
            if (!parentLabel)
                continue;
            const std::string parentName = parentLabel->second;
            uint32 unwinds               = 0;
            std::set<uint64> named;
            for (const uint64 action : info->second.actions) {
                if (action == NO_TARGET || !named.insert(action).second)
                    continue;
                auto* funclet = labelOf(codeStart + action);
                if (!funclet || GetLabelType(funclet->second) != SUB || (functionEntries && functionEntries->contains(codeStart + action)))
                    continue;
                std::string name = parentName + "$dtor$" + std::to_string(unwinds++);
                if (usedNames.insert(name).second)
                    funclet->second = std::move(name);
            }
        }
        if (decoded)
            cs_free(decoded, 1);
        if (ownsHandle)
            cs_close(&decoder);
    }

    // a value of a jump table (1, 2, 4 or 8 bytes) at an address of the labels
    std::optional<uint64> ReadTableValue(uint64 address, uint8 size)
    {
        const auto offset = addressToFileOffset(address);
        if (!offset.has_value())
            return {};
        if (size == (is64 ? 8 : 4) && zone->relocatedPointers) { // a pointer the loader writes (PIE): its bytes in the file are 0
            if (const auto relocated = zone->relocatedPointers->find(offset.value()); relocated != zone->relocatedPointers->end())
                return relocated->second;
        }
        uint64 value = 0;
        bool ok      = false;
        if (size == 1) {
            uint8 value8 = 0;
            ok           = obj->GetData().Copy<uint8>(offset.value(), value8);
            value        = value8;
        } else if (size == 2) {
            uint16 value16 = 0;
            ok             = obj->GetData().Copy<uint16>(offset.value(), value16);
            value          = value16;
        } else if (size == 4) {
            uint32 value32 = 0;
            ok             = obj->GetData().Copy<uint32>(offset.value(), value32);
            value          = value32;
        } else if (size == 8) {
            ok = obj->GetData().Copy<uint64>(offset.value(), value);
        }
        return ok ? std::optional<uint64>(value) : std::nullopt;
    }

    // one decoded instruction of the sweep
    void AnalyzeInstruction()
    {
        // functions that are not called directly (callbacks, virtual methods, exports): recognized by their prologue
        const uint64 instructionOffset = codeStart + insn->address; // decoded inside the code: can not overflow
        const DissasmArch insnArch     = zone->GetArchAt(insn->address); // 32 bit ARM: the mode of the line (ARM / Thumb)
        const bool isArm64             = insnArch == DissasmArch::Arm64;
        const bool isArm32             = insnArch == DissasmArch::Arm || insnArch == DissasmArch::Thumb;
        if (!isArm64 && !isArm32) { // the x86 / x64 prologues (the ARM functions: the calls, the plugin, IsArm*PrologueStart)
            const auto prologueStart = prologueDetector.Next(*insn, instructionOffset);
            if (prologueStart.has_value() && !IsInsidePluginFunction(prologueStart.value()))
                AddFunctionStart(prologueStart.value());
        }

        // the cross references, in the address space of the labels (VA)
        const auto flow     = GetInstructionFlow(*insn, insnArch);
        // the padding lines (align) and whether the line before goes on into them
        if (zone->paddingAlignmentBase != DISSASM_NO_PADDING_ALIGNMENT && !isArm32) {
            if (insn->id == 0 && std::string_view(insn->mnemonic) == "align")
                paddingRuns.push_back({ insn->address, insn->address + insn->size, previousFallsThrough, previousIsCall, previousAddress });
            previousAddress = insn->address;
            const bool isTrap = IsTrapInstruction(*insn, insnArch) || (isArm64 ? insn->id == ARM64_INS_HLT : (insn->id == X86_INS_INT3 || insn->id == X86_INS_HLT));
            previousFallsThrough = insn->id != 0 && flow != X86Flow::Jump && flow != X86Flow::Return && !isTrap;
            previousIsCall       = flow == X86Flow::Call;
        }
        auto operands       = GetInstructionOperands(*insn, insnArch, labelBase);
        const uint64 from   = labelBase + insn->address;
        if (isArm64 || isArm32) {
            // the addresses built in the registers (ARM64: the adrp pairs; ARM: movw / movt, add pc, the literal pools): the data of add /
            // ldr / str, the import slot of br / blr / bx / ldr pc (import stubs, import calls)
            // a call target starts a block too (the PLT stubs after the padding of PLT0, which decodes as an ARM instruction when the
            // mapping symbols are stripped)
            const auto called       = callsMap.find(instructionOffset);
            const bool isBlockStart = atBlockStart || (called != callsMap.end() && !called->second) ||
                                      std::binary_search(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), insn->address);
            auto pairOperands       = operands;
            auto pair = isArm64 ? adrpTracker.Next(*insn, isBlockStart) : arm32Tracker.Next(*insn, insnArch == DissasmArch::Thumb, isBlockStart);
            // movw / movt and the literal pools also hold constants (the magic numbers of the divisions): only an address of the file is
            // an address
            if (pair.has_value() && isArm32 && pair->absolute && isFileAddress && !isFileAddress(labelBase + pair->address))
                pair.reset();
            if (pair.has_value()) {
                resolvedAddresses[insn->address] = pair->address;
                if (isArm64)
                    adrpPages.emplace(pair->sequenceStart, pair->address); // the first pair names the adrp
                pairOperands.ripTarget           = pair->address;
                pairOperands.memoryAccess        = pair->memoryAccess;
                const auto* import = pair->throughSlot && (flow == X86Flow::Jump || flow == X86Flow::Call) && findImport ? findImport(pairOperands) : nullptr;
                // an import stub (j_Name): adrp x16, page; ldr x16, [x16, #off]; br x16 from a block start
                if (import && flow == X86Flow::Jump && pair->sequenceAtBlockStart) {
                    if (import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                        thunks.emplace_back(codeStart + pair->sequenceStart, import->name);
                        thunkImports[pair->sequenceStart] = import->name;
                        AddFunctionStart(codeStart + pair->sequenceStart);
                        if (IsNoReturnFunctionName(import->name))
                            noReturnStarts.insert(pair->sequenceStart);
                    } else if (
                          import->type == MemoryMappingType::TextMapping && (IsGuardPointerName(import->name) || IsArm64ECPointerName(import->name)) &&
                          insn->address == pair->sequenceStart + 8) {
                        // the same through a pointer of the guard / of the emulator: j___os_arm64x_check_icall_cfg (the check of the
                        // indirect calls of d3dcompiler: 1638 calls through a veneer of another zone, NameOtherZoneThunks); only the three
                        // instructions (__os_arm64x_check_icall_thunk moves x0 to x11 before its br: a function of its own)
                        thunks.emplace_back(codeStart + pair->sequenceStart, import->name);
                        AddFunctionStart(codeStart + pair->sequenceStart);
                    }
                }
                if (import && import->type == MemoryMappingType::TextMapping) {
                    if (flow == X86Flow::Call && import->name == "__os_arm64x_dispatch_call_no_redirect")
                        arm64ECThunkCalls.emplace_back(insn->address, true);
                    else if (flow == X86Flow::Jump && import->name == "__os_arm64x_dispatch_ret")
                        arm64ECThunkCalls.emplace_back(insn->address, false);
                }
            }
            // the jump table of a switch (br x10): the cases are read from the table
            if (const auto table = isArm64 ? adrpTracker.TakeJumpTable() : arm32Tracker.TakeJumpTable(); table.has_value() && addressToFileOffset) {
                std::vector<uint64> targets; // VA
                for (uint32 index = 0; index < table->count; index++) {
                    // no table (add pc, pc, r0, lsl #2: the cases are branches placed one after the other)
                    if (table->entrySize == 0) {
                        const uint64 target = table->base + (static_cast<uint64>(index) << table->shift);
                        if (target >= codeSize) {
                            targets.clear();
                            break;
                        }
                        targets.push_back(labelBase + target);
                        continue;
                    }
                    const auto value = ReadTableValue(labelBase + table->table + static_cast<uint64>(index) * table->entrySize, table->entrySize);
                    if (!value.has_value()) {
                        targets.clear();
                        break;
                    }
                    uint64 entry = value.value();
                    if (table->isSigned && table->entrySize < 8) {
                        const uint32 unused = 64 - 8u * table->entrySize;
                        entry               = static_cast<uint64>(static_cast<int64>(entry << unused) >> unused);
                    }
                    // the VA of the case (its Thumb bit cleared), or a base plus the entry
                    const uint64 target = table->absolute ? (entry & ~static_cast<uint64>(1)) - labelBase : table->base + (entry << table->shift);
                    if (target >= codeSize) { // not a table of this code
                        targets.clear();
                        break;
                    }
                    targets.push_back(labelBase + target);
                }
                AddSwitchTargets(insn->address, from, targets);
                // ARM64: the cases keep the bound of the index (a switch inside a case on the same index)
                if (isArm64)
                    for (const uint64 target : targets)
                        if (target - labelBase > insn->address && target - labelBase < codeSize)
                            adrpTracker.AddCaseBound(target - labelBase, table->count, table->indexRegister);
                if (!targets.empty() && table->entrySize > 0) // tbb / tbh / ldr pc, [pc, rN, lsl #2]: the table follows the jump
                    AddTable(insn->address, from, labelBase + table->table, table->entrySize, targets, insnArch == DissasmArch::Thumb);
            }
            // the anchor of a jump table (its table read or not): a label of the function, not a function whose address is taken
            if (const auto anchor = isArm64 ? adrpTracker.TakeAnchor() : std::nullopt; anchor.has_value() && anchor.value() < codeSize) {
                switchAnchors.insert(anchor.value());
                const auto anchorOffset = zone->GetFileOffsetOfAddress(anchor.value());
                if (anchorOffset.has_value() && callsMap.insert({ anchorOffset.value(), true }).second)
                    callsFound.emplace_back(anchorOffset.value(), zone->GetLabelName("loc_", anchor.value()));
            }
            // br x16 after adrp x16 / add x16: a jump to that address (its target a label, a chunk of the function when it is elsewhere)
            if (const auto farJump = isArm64 ? adrpTracker.TakeFarJump() : std::nullopt; farJump.has_value() && farJump.value() < codeSize) {
                farJumpTargets.insert(farJump.value());
                pairOperands.directTarget = farJump.value();
            }
            // b to the code of another zone from a block start (the veneers of an ARM64X image: b j___os_arm64x_check_icall_cfg of the
            // ARM64EC code): a thunk when the zones call it (NameOtherZoneThunks)
            if (isArm64 && isBlockStart && flow == X86Flow::Jump && operands.directTarget.has_value() && operands.directTarget.value() >= codeSize)
                otherZoneJumps[insn->address] = (labelBase + operands.directTarget.value()) & addressMask;
            // a prologue at a block start: a function (a candidate until the end of the sweep: a shrink wrapped prologue is reached by a
            // conditional branch of its own function)
            if (isBlockStart && insn->address < blockStarts.size() && insn->id != 0 && GetInstructionKind(insn->id, insn->mnemonic, insnArch) != X86InstructionKind::Padding)
                blockStarts[insn->address] = true; // not the padding (nop, the data lines)
            if (isBlockStart && (isArm64 ? IsArm64PrologueStart(*insn) : IsArm32PrologueStart(*insn)))
                prologueCandidates.push_back(instructionOffset);
            if (flow == X86Flow::ConditionalJump && operands.directTarget.has_value())
                conditionalTargets.insert(operands.directTarget.value());
            // ldr r0, [pc, #off] (32 bit ARM): the word read is a literal of a pool after the function, a data line (.word) after the next
            // sweep (without the mapping symbols the pools decode as instructions, the function after a pool does not start a block); an
            // absolute address of code there (ldr r0, =callback) takes the address of a function
            if (isArm32 && insn->id == ARM_INS_LDR && operands.ripTarget.has_value() && operands.memoryAccess == CS_AC_READ) {
                const uint64 literal = operands.ripTarget.value();
                if (literal > insn->address && literal < codeSize && ((labelBase + literal) & 3) == 0 &&
                    !std::binary_search(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), literal)) {
                    const auto word     = ReadTableValue(labelBase + literal, 4);
                    const bool isOffset = word.has_value() && word.value() >= 0x10000 && isFileAddress && isFileAddress(word.value());
                    AddDataCandidate(literal, literal + 4, 4, isOffset);
                    if (isOffset && word.value() >= labelBase)
                        AddTakenCodeAddress(word.value() - labelBase);
                }
            }
            const bool takesAddress = isArm64 ? insn->id == ARM64_INS_ADR || (insn->id == ARM64_INS_ADD && pair.has_value())
                                              : (pair.has_value() && pair->memoryAccess == 0) || insn->id == ARM_INS_ADR || insn->id == ARM_INS_ADD || insn->id == ARM_INS_SUB;
            AnalyzeBranchesAndData(flow, pairOperands, from, takesAddress);
            const bool isNop        = isArm64 ? insn->id == ARM64_INS_NOP : insn->id == ARM_INS_NOP;
            const bool noReturnCall = RecordFlow(flow, pairOperands, insnArch);
            atBlockStart = flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || isNop || insn->id == 0 || noReturnCall;
            if (noReturnCall)
                previousFallsThrough = false;
            return;
        }

        // an import thunk (IDA j_Name): a jmp through an import slot that starts a block, reached by calls instead of the import itself.
        // An endbr at the start of a block keeps it a block start: the CET stubs (ELF .plt.sec: endbr64; bnd jmp [rip + ...]) start with
        // it, the thunk (and the calls to it) is at the endbr
        // a boundary (a section start of the plugin, a function entry) starts a block
        const bool isBlockStart = atBlockStart || std::binary_search(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), insn->address);
        const bool isEndbr      = insn->id == X86_INS_ENDBR64 || insn->id == X86_INS_ENDBR32;
        if (!is64)
            TrackGlobalOffsetTable(isBlockStart, instructionOffset, flow, operands);
        else
            TrackImageBase(isBlockStart, instructionOffset, flow, operands);
        // not the padding (int3, nop, align, db); not the line after the endbr64 that starts the block (the lazy slots of .got.plt point to
        // the push of their .plt stub: endbr64; push 3; jmp the first stub, one function)
        if (isBlockStart && insn->address < blockStarts.size() && insn->id != X86_INS_INVALID && insn->id != X86_INS_INT3 && insn->id != X86_INS_NOP &&
            !blockEndbr.has_value())
            blockStarts[insn->address] = true;
        const uint64 thunkStart = blockEndbr.value_or(instructionOffset);
        blockEndbr              = isBlockStart && isEndbr ? std::optional<uint64>(instructionOffset) : std::nullopt;
        // the padding between the blocks: nop, int3 (an interrupt), the undecodable bytes (db)
        atBlockStart = flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || insn->id == X86_INS_NOP ||
                       insn->id == X86_INS_INVALID || (isBlockStart && isEndbr);
        if (isBlockStart && !isEndbr && flow == X86Flow::Jump && !operands.directTarget.has_value() && findImport) {
            const auto import = findImport(operands);
            if (import && import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                thunks.emplace_back(thunkStart, import->name);
                thunkImports[thunkStart - codeStart] = import->name;
                AddFunctionStart(thunkStart);
                if (IsNoReturnFunctionName(import->name))
                    noReturnStarts.insert(thunkStart - codeStart);
            } else if (import && import->type == MemoryMappingType::TextMapping && IsGuardPointerName(import->name)) {
                // jmp cs:__guard_dispatch_icall_fptr: the dispatch of the Control Flow Guard (the target in rax), called through the
                // function override thunks of fothk (shell32: 18918 calls): j___guard_dispatch_icall_fptr, as IDA names it
                thunks.emplace_back(thunkStart, import->name);
                AddFunctionStart(thunkStart);
            }
        }
        // jmp to the code of another zone from a block start: a thunk when the zones call it (NameOtherZoneThunks)
        if (isBlockStart && !isEndbr && flow == X86Flow::Jump && operands.directTarget.has_value() && operands.directTarget.value() >= codeSize)
            otherZoneJumps[thunkStart - codeStart] = (labelBase + operands.directTarget.value()) & addressMask;

        // mov eax, offset X; ret: the catch block of a C++ exception returns where its function continues, not a function
        if (returnedAddress.has_value()) {
            if (flow != X86Flow::Return)
                addressTakenTargets.push_back(returnedAddress.value());
            returnedAddress.reset();
        }

        // the jump table of a switch: every case is a jump target (loc_) referenced by the jmp
        const auto jumpTable = switchDetector.Next(*insn);
        if (jumpTable.has_value() && addressToFileOffset) {
            std::vector<uint64> entryTargets;
            const auto targets = ReadX86JumpTableTargets(
                  jumpTable.value(),
                  [this](uint64 address, uint8 size) { return ReadTableValue(address, size); },
                  [this](uint64 address) { return address >= labelBase && address - labelBase < codeSize; },
                  &entryTargets);
            AddSwitchTargets(insn->address, from, targets);
            // only a table with a bound (cmp / ja before the jump): the end of a table without one is a guess, the code after it would
            // become data
            if (!targets.empty() && jumpTable->casesCount.has_value()) {
                AddTable(insn->address, from, jumpTable->tableAddress, jumpTable->entrySize, entryTargets, false);
                const auto indexTable = jumpTable->indexTableAddress;
                if (indexTable.has_value() && indexTable.value() >= labelBase) // MSVC: the byte of the entry of every case
                    AddDataCandidate(indexTable.value() - labelBase, indexTable.value() - labelBase + jumpTable->casesCount.value(), 1);
            }
        }
        AnalyzeBranchesAndData(flow, operands, from, insn->id == X86_INS_LEA);
        // a call that does not return: the next instruction starts a block (a thunk, the code whose address is taken), the padding after
        // it is not reached. Not a prologue after padding: the endbr64 of a landing pad (CET) follows the call __stack_chk_fail of its
        // function
        if (RecordFlow(flow, operands, insnArch)) {
            atBlockStart         = true;
            previousFallsThrough = false;
        }
    }

    // an instruction that stops the program (a path of a function ends there): ud2, int 0x29 (__fastfail), brk / udf (__builtin_trap). Not
    // int3 / hlt / bkpt: a debugger / an interrupt continues after them (DebugBreak: int3; ret)
    static bool IsTrapInstruction(const cs_insn& instruction, DissasmArch instructionArch)
    {
        if (instructionArch == DissasmArch::Arm64)
            return instruction.id == ARM64_INS_BRK || instruction.id == ARM64_INS_UDF;
        if (instructionArch == DissasmArch::Arm || instructionArch == DissasmArch::Thumb)
            return instruction.id == ARM_INS_UDF;
        if (instruction.id == X86_INS_UD2)
            return true;
        return instruction.id == X86_INS_INT && instruction.detail && instruction.detail->x86.op_count == 1 &&
               instruction.detail->x86.operands[0].type == X86_OP_IMM && instruction.detail->x86.operands[0].imm == 0x29;
    }

    // a relative address of a call / jump target is a function that does not return: of this zone (noReturnStarts) or of another code zone
    // of the file (a PLT stub of .plt: its analysis or its name, j_exit)
    bool IsNoReturnTarget(uint64 target)
    {
        if (target < codeSize) {
            if (userReturns.contains(target))
                return false;
            if (noReturnStarts.contains(target))
                return true;
            const auto thunk = thunkImports.find(target);
            return thunk != thunkImports.end() && IsLocalNoReturnImport(thunk->second);
        }
        const uint64 address = (labelBase + target) & addressMask;
        const auto* other    = zone->FindCodeZoneOfAddress(address);
        if (!other || other == zone)
            return false;
        const uint64 start = address - other->labelAddressBase;
        if (std::binary_search(other->noReturnFunctions.begin(), other->noReturnFunctions.end(), start))
            return true;
        const auto thunk       = other->thunkImports.find(start);
        const std::string name = thunk != other->thunkImports.end() ? thunk->second : other->GetLabelNameAt(start);
        return !name.empty() && (IsNoReturnFunctionName(name) || IsLocalNoReturnImport(name));
    }

    // an import of the library itself (a PIC library calls its exported functions through the PLT / the GOT: fatal@plt) that does not
    // return: the function of the zone of that name
    bool IsLocalNoReturnImport(std::string_view name) const
    {
        if (name.starts_with("j_"))
            name.remove_prefix(2);
        if (const auto at = name.find('@'); at != std::string_view::npos && at > 0)
            name = name.substr(0, at);
        const auto local = localFunctionNames.find(std::string(name));
        return local != localFunctionNames.end() && noReturnStarts.contains(local->second);
    }

    // the callee of a call / the target of a jump of a record does not return
    bool RecordReachesNoReturn(const FlowRecord& record)
    {
        if (record.noReturnImport || (record.target != NO_TARGET && IsNoReturnTarget(record.target)))
            return true;
        if (!record.localImport)
            return false;
        const auto import = localImports.find(record.address);
        return import != localImports.end() && IsLocalNoReturnImport(import->second);
    }

    // the flow of the instruction for the functions that do not return (InferNoReturnFunctions); true for a call known now to not return
    // (a function of the zone named so, an import through its slot, a function of another zone)
    bool RecordFlow(X86Flow flow, const X86OperandsInfo& operands, DissasmArch instructionArch)
    {
        FlowKind kind;
        const bool isArm32 = instructionArch == DissasmArch::Arm || instructionArch == DissasmArch::Thumb;
        if (insn->id == 0)
            kind = FlowKind::Unknown; // a data line, an undecodable byte, the padding
        else if (IsTrapInstruction(*insn, instructionArch))
            kind = FlowKind::Trap;
        else if (flow == X86Flow::Call)
            kind = FlowKind::Call;
        else if (flow == X86Flow::Jump)
            kind = FlowKind::Jump;
        else if (flow == X86Flow::ConditionalJump)
            kind = FlowKind::ConditionalJump;
        else if (flow == X86Flow::Return)
            kind = FlowKind::Return;
        else if (isArm32 && insn->detail && insn->detail->arm.cc != ARM_CC_AL && insn->detail->arm.cc != ARM_CC_INVALID &&
                 (insn->id == ARM_INS_BX ||
                  std::any_of(insn->detail->arm.operands, insn->detail->arm.operands + insn->detail->arm.op_count, [](const cs_arm_op& op) {
                      return op.type == ARM_OP_REG && op.reg == ARM_REG_PC;
                  })))
            kind = FlowKind::MaybeReturn; // popne {r4, pc} / bxlt lr (an IT block): a conditional return
        else
            return false;
        FlowRecord record{ insn->address, NO_TARGET, static_cast<uint8>(insn->size), kind, false, false };
        if (IsX86Branch(flow) && operands.directTarget.has_value())
            record.target = operands.directTarget.value() & addressMask;
        if (kind == FlowKind::Call && record.target == insn->address + insn->size)
            return false; // call $+5: the address of the code
        if (record.target == NO_TARGET && (kind == FlowKind::Call || kind == FlowKind::Jump) && findImport) {
            const auto* import = findImport(operands);
            if (import && import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                record.noReturnImport = IsNoReturnFunctionName(import->name);
                if (const uint32 categories = GetApiCategories(import->name); categories != 0)
                    importCallCategories[insn->address] = categories; // call [__imp_connect]
                if (const auto* prototype = kind == FlowKind::Call ? FindApiPrototype(import->name) : nullptr)
                    (prototype->demangled ? demangledPrototypeCalls : knownPrototypeCalls).insert(insn->address);
                if (kind == FlowKind::Call && FindComProducer(import->name))
                    comProducerCalls.insert(insn->address);
                if (!record.noReturnImport && localFunctionNames.contains(import->name)) { // call [rip + fatal@GOTPCREL] (-fno-plt)
                    record.localImport          = true;
                    localImports[insn->address] = import->name;
                }
            }
        }
        flowRecords.push_back(record);
        if (kind != FlowKind::Call || !RecordReachesNoReturn(record))
            return false;
        noReturnCalls.insert(insn->address);
        return true;
    }

    // the first flow record at or after a relative address
    size_t FirstRecordAt(uint64 address) const
    {
        return static_cast<size_t>(
              std::lower_bound(flowRecords.begin(), flowRecords.end(), address, [](const FlowRecord& record, uint64 value) { return record.address < value; }) -
              flowRecords.begin());
    }

    // the cases of the switches: relative address of the indirect jump -> its cases (relative)
    std::unordered_map<uint64, std::vector<uint64>> SwitchCases() const
    {
        std::unordered_map<uint64, std::vector<uint64>> cases;
        for (const auto& xref : xrefs.byTarget)
            if (xref.kind == DissasmXrefKind::Switch && xref.from >= labelBase && xref.to >= labelBase)
                cases[xref.from - labelBase].push_back(xref.to - labelBase);
        return cases;
    }

    // the end of every function (functionEnds): the paths from its start (and from the code of the function whose address is taken: a
    // handler of its exceptions, a callback) through the flow records, up to a ret / a jump out / a trap / a call that does not return /
    // padding (an align line, undecodable bytes); a path that goes on into the next function (or past the record budget) ends there
    // the bytes [from, to) are nops: 0x90, 66 90, the long nops (66 0f 1f ...)
    bool IsNopPadding(uint64 from, uint64 to)
    {
        constexpr uint64 MAX_PADDING = 16;
        uint8 bytes[MAX_PADDING]     = {};
        if (to <= from || to - from > MAX_PADDING || to > codeSize)
            return false;
        for (uint64 address = from; address < to; address++)
            if (!obj->GetData().Copy<uint8>(codeStart + address, bytes[address - from]))
                return false;
        size_t index = 0;
        while (index < to - from && bytes[index] == 0x66)
            index++; // the operand size prefixes of the long nops
        if (index + 1 < to - from && bytes[index] == 0x0F && bytes[index + 1] == 0x1F)
            return true;
        for (; index < to - from; index++)
            if (bytes[index] != 0x90)
                return false;
        return true;
    }

    void ComputeFunctionEnds()
    {
        constexpr uint32 MAX_PATH_STEPS = 4096;
        functionEnds.assign(functionStarts.size(), 0);
        const auto switchCases = SwitchCases();
        std::vector<uint64> seeds = addressTakenTargets; // sorted by FinishSweep
        seeds.insert(seeds.end(), dataPointerTargets.begin(), dataPointerTargets.end());
        seeds.insert(seeds.end(), computedGotoTargets.begin(), computedGotoTargets.end()); // the code of a computed goto of the function
        std::sort(seeds.begin(), seeds.end());
        seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
        std::vector<size_t> pending;
        std::unordered_set<size_t> seen;
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            uint64 nextStart   = std::min<uint64>(index + 1 < functionStarts.size() ? functionStarts[index + 1] : codeSize, codeSize);
            // a code range of the plugin after the start (an FDE, a separated fragment of ARM64 .pdata: the cold code of another function)
            // is the code of another function or fragment, as a function start
            if (codeRanges)
                if (const auto range = codeRanges->upper_bound(codeStart + start); range != codeRanges->end() && range->first - codeStart < nextStart)
                    nextStart = range->first - codeStart;
            const auto firstPad    = std::upper_bound(landingPadSources.begin(), landingPadSources.end(), std::make_pair(start, UINT64_MAX));
            uint64 limit           = start;    // the code of the function is before it
            auto scan              = firstPad; // the pads before it are its own (once its own, a pad stays its own: the end only grows)
            std::vector<uint64> beyond;        // the targets past the end so far: walked once a pad of its own moves the end past them
            const auto follow = [&](uint64 target) {
                if (target >= start && target < limit)
                    pending.push_back(FirstRecordAt(target));
                else if (target >= limit && target < nextStart)
                    beyond.push_back(target);
            };
            uint64 end     = start;
            uint32 steps   = 0;
            bool intoLimit = false; // a path went past the end
            pending.assign(1, FirstRecordAt(start));
            seen.clear();
            for (;;) {
                // the function ends at the next start, or at the first landing pad that is not its own (no call site of it in the code walked
                // so far: stripped, a cold fragment of another function after it, as a function start); its own pads are its code too
                // (after its ret), walked with the seeds before the end
                uint64 newLimit = nextStart;
                while (scan != landingPadSources.end() && scan->first < nextStart) {
                    const uint64 address = scan->first;
                    bool own             = false;
                    auto next            = scan;
                    for (; next != landingPadSources.end() && next->first == address; ++next)
                        own = own || (next->second >= start && next->second < end);
                    if (!own) {
                        newLimit = address;
                        break;
                    }
                    scan = next;
                }
                if (newLimit > limit) {
                    for (auto seed = std::lower_bound(seeds.begin(), seeds.end(), std::max(limit, start + 1)); seed != seeds.end() && *seed < newLimit; ++seed)
                        pending.push_back(FirstRecordAt(*seed));
                    for (auto pad = std::lower_bound(
                               landingPadSources.begin(), landingPadSources.end(), std::make_pair(std::max(limit, start + 1), static_cast<uint64>(0)));
                         pad != landingPadSources.end() && pad->first < newLimit;
                         ++pad)
                        pending.push_back(FirstRecordAt(pad->first));
                    for (const uint64 target : beyond)
                        if (target < newLimit)
                            pending.push_back(FirstRecordAt(target));
                    beyond.erase(std::remove_if(beyond.begin(), beyond.end(), [newLimit](uint64 target) { return target < newLimit; }), beyond.end());
                    limit = newLimit;
                }
                if (pending.empty() || end >= limit)
                    break;
                while (!pending.empty() && end < limit) {
                    size_t position = pending.back();
                    pending.pop_back();
                    for (bool walking = true; walking; position++) {
                        if (position >= flowRecords.size() || flowRecords[position].address >= limit || ++steps > MAX_PATH_STEPS) {
                            end       = limit; // into the next function
                            intoLimit = true;
                            break;
                        }
                        if (!seen.insert(position).second)
                            break;
                        const auto& record = flowRecords[position];
                        if (record.kind == FlowKind::Unknown) {
                            // padding the code reaches (6f: instructions after the sweep, an align line in it) goes on; the other padding / the
                            // bytes after the code: the function ends before them. The nops at the entry of the function are its code (the
                            // __ehhandler stubs of MSVC x86: nop; nop shown as align 0x2)
                            if (std::binary_search(instructionSet.reachablePadding.begin(), instructionSet.reachablePadding.end(), record.address) ||
                                (record.address == start && IsNopPadding(record.address, record.address + record.size)))
                                continue;
                            end = std::max(end, record.address);
                            break;
                        }
                        end = std::max(end, record.address + record.size);
                        switch (record.kind) {
                        case FlowKind::Return:
                        case FlowKind::Trap:
                            walking = false;
                            break;
                        case FlowKind::Call:
                            walking = !RecordReachesNoReturn(record);
                            break;
                        case FlowKind::ConditionalJump:
                            if (record.target != NO_TARGET)
                                follow(record.target);
                            break;
                        case FlowKind::Jump:
                            walking = false;
                            if (const auto cases = switchCases.find(record.address); cases != switchCases.end()) {
                                for (const uint64 target : cases->second)
                                    follow(target);
                            } else if (record.target != NO_TARGET)
                                follow(record.target);
                            break;
                        default:
                            break;
                        }
                    }
                }
                if (intoLimit)
                    break; // into the next function: no pad of it is its own
            }
            functionEnds[index] = std::max(std::min(end, limit), std::min(start + 1, limit));
        }
    }

    // the functions that are blocks of another function (IDA: function chunks): a start the prologue rules (or a jump) found, that only
    // jumps / conditional jumps / switch cases of one other function reach, and whose code jumps back into that function. Not the entry
    // point, a function of the plugin or of the user, a thunk. They stop being functions: their label is a location, their code belongs to
    // the function (DissasmCodeZone::functionChunks), the ends of the functions are computed again
    void DetectFunctionChunks()
    {
        coldChunks.clear();
        coldChunksOf.clear();
        if (functionStarts.empty() || functionEnds.size() != functionStarts.size())
            return;
        const auto containing = [this](uint64 address) -> std::optional<size_t> {
            const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), address);
            return next == functionStarts.begin() ? std::nullopt : std::optional<size_t>(static_cast<size_t>(next - functionStarts.begin()) - 1);
        };
        // the chunks the plugin gives (x64 chained unwind data), exact: before the ones the jumps tell
        if (functionEntries)
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it)
                for (const auto& [chunk, size] : it->second.chunks) {
                    const uint64 function = it->first - codeStart;
                    if (chunk < codeStart || chunk - codeStart >= codeSize || size == 0 || chunk == it->first ||
                        !std::binary_search(functionStarts.begin(), functionStarts.end(), function))
                        continue;
                    chunks.push_back({ chunk - codeStart, std::min<uint64>(chunk - codeStart + size, codeSize), function });
                }
        std::sort(chunks.begin(), chunks.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
        const auto inPluginChunk = [this](uint64 address) {
            const auto next = std::upper_bound(chunks.begin(), chunks.end(), address, [](uint64 value, const auto& chunk) { return value < chunk.start; });
            return next != chunks.begin() && address < (next - 1)->end;
        };
        std::unordered_map<size_t, size_t> parentOf; // index of a chunk -> index of its function
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            if (inPluginChunk(start) || IsTakenAddress(start) || helperFrameStarts.contains(start)) // a vtable, a callback, a helper frame
                continue;
            // a function of the plugin: a part of another one when it is a cold partition of GCC (X.cold), or an unnamed one (an entry of the
            // x64 unwind data) whose code can not be the entry of a function (ReadsCalleeSavedAtEntry)
            const DissasmFunctionEntry* entry = nullptr;
            if (functionEntries)
                if (const auto found = functionEntries->find(codeStart + start); found != functionEntries->end())
                    entry = &found->second;
            const bool pluginKnown = entry != nullptr;
            const bool coldPart    = pluginKnown && IsColdPartitionName(entry->name);
            if ((zone->zoneDetails.HasEntryPoint() && codeStart + start == zone->zoneDetails.entryPoint) || thunkImports.contains(start) ||
                (pluginKnown && !coldPart && (!entry->name.empty() || entry->isExport)))
                continue;
            if (const auto user = zone->userFunctions.find(start); user != zone->userFunctions.end() && (user->second & USER_FUNCTION_CREATE))
                continue;
            const auto [first, last] = xrefs.To(labelBase + start);
            std::optional<size_t> parent;
            bool onlyJumps = first != last;
            for (auto xref = first; xref != last && onlyJumps; ++xref) {
                const bool isJump = xref->kind == DissasmXrefKind::Jump || xref->kind == DissasmXrefKind::ConditionalJump || xref->kind == DissasmXrefKind::Switch;
                const auto source = xref->from >= labelBase && xref->from - labelBase < codeSize ? containing(xref->from - labelBase) : std::nullopt;
                if (!isJump || !source.has_value()) {
                    onlyJumps = false;
                    break;
                }
                if (source.value() == index)
                    continue; // a loop of the block
                if (parent.has_value() && parent.value() != source.value())
                    onlyJumps = false;
                parent = source;
            }
            if (!onlyJumps || !parent.has_value())
                continue;
            // its code jumps back into the function; or it is a part of the function for sure (a cold partition, code that uses the callee
            // saved registers of the function: it may end its path elsewhere, a call that does not return). A function of the plugin: only
            // the latter
            const uint64 parentStart = functionStarts[parent.value()];
            const uint64 parentLimit = parent.value() + 1 < functionStarts.size() ? functionStarts[parent.value() + 1] : codeSize;
            bool jumpsBack           = false;
            for (size_t position = FirstRecordAt(start); position < flowRecords.size() && flowRecords[position].address < functionEnds[index] && !jumpsBack; position++) {
                const auto& record = flowRecords[position];
                jumpsBack = (record.kind == FlowKind::Jump || record.kind == FlowKind::ConditionalJump) && record.target != NO_TARGET &&
                            record.target >= parentStart && record.target < parentLimit;
            }
            if ((jumpsBack && !pluginKnown) || coldPart || ReadsCalleeSavedAtEntry(start))
                parentOf[index] = parent.value();
        }
        if (parentOf.empty() && chunks.empty())
            return;
        // a chunk of a chunk belongs to the function at the end of the chain
        for (const auto& [index, parent] : parentOf) {
            size_t root = parent;
            for (size_t steps = 0; parentOf.contains(root) && steps < parentOf.size(); steps++)
                root = parentOf.at(root);
            if (parentOf.contains(root))
                continue; // a cycle: none of them is a function's
            chunks.push_back({ functionStarts[index], functionEnds[index], functionStarts[root] });
            coldChunks.push_back(chunks.back()); // their slots on the frame of the function (AddColdChunkSlots)
        }
        std::sort(chunks.begin(), chunks.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
        // they are not functions any more: their labels are locations
        std::unordered_set<uint64> chunkStarts;
        for (const auto& chunk : chunks)
            chunkStarts.insert(chunk.start);
        functionStarts.erase(std::remove_if(functionStarts.begin(), functionStarts.end(), [&chunkStarts](uint64 start) { return chunkStarts.contains(start); }),
                             functionStarts.end());
        for (auto& call : callsFound)
            if (call.first >= codeStart && chunkStarts.contains(call.first - codeStart) && GetLabelType(call.second) == SUB) {
                call.second          = zone->GetLabelName("loc_", call.first - codeStart);
                callsMap[call.first] = true;
            }
        ComputeFunctionEnds(); // the functions before them reach further
    }

    // the cold code of the functions (MSVC PGO: blocks placed after other functions, far from theirs; 32 bit: no unwind data tells them): a
    // block past the end of every function and chunk that only the jumps of one function reach (from its code, its chunks, or other such
    // blocks of it), up to the end of its path (a ret / jmp / trap / call that does not return, the next function): a chunk of that function
    // (IDA: a function tail). A block reached otherwise (a call, a taken address, the jumps of two functions) stays code of nobody
    void DetectColdBlocks()
    {
        constexpr uint32 MAX_BLOCK_RECORDS = 4096;
        constexpr uint32 MAX_PASSES        = 8;
        if ((IsArmArch(arch) && arch != DissasmArch::Arm64) || functionStarts.empty() || functionEnds.size() != functionStarts.size())
            return;
        // the function whose code (its body up to its end, its chunks) contains an address
        const auto bodyOwner = [this](uint64 address) -> std::optional<uint64> {
            const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), address);
            if (next != functionStarts.begin() && address < functionEnds[static_cast<size_t>(next - functionStarts.begin()) - 1])
                return *(next - 1);
            const auto chunk = std::upper_bound(chunks.begin(), chunks.end(), address, [](uint64 value, const auto& item) { return value < item.start; });
            if (chunk != chunks.begin() && address < (chunk - 1)->end)
                return (chunk - 1)->function;
            return std::nullopt;
        };
        // a jump; the address of a code location taken by the code (lea rdx, loc_X; call _local_unwind: the code goes on there), the add of
        // an ARM64 veneer (adrp x16; add x16, x16, #off; br x16)
        const auto isJump = [this](const DissasmXref& xref) {
            return xref.kind == DissasmXrefKind::Jump || xref.kind == DissasmXrefKind::ConditionalJump || xref.kind == DissasmXrefKind::Switch ||
                   (xref.kind == DissasmXrefKind::Offset && xref.to >= labelBase &&
                    (IsCodeLocation(xref.to - labelBase) || farJumpTargets.contains(xref.to - labelBase)));
        };
        struct ColdBlock {
            uint64 start, end;
            std::optional<uint64> owner;
            bool rejected;
        };
        // the path from a target: up to a ret / jmp / trap / call that does not return / padding, the next function or chunk
        const auto pathEnd = [&](uint64 target) {
            const auto nextFunction = std::upper_bound(functionStarts.begin(), functionStarts.end(), target);
            const auto nextChunk    = std::upper_bound(chunks.begin(), chunks.end(), target, [](uint64 value, const auto& item) { return value < item.start; });
            const uint64 limit      = std::min<uint64>(
                  { nextFunction != functionStarts.end() ? *nextFunction : codeSize, nextChunk != chunks.end() ? nextChunk->start : codeSize, codeSize });
            uint64 end   = target;
            uint32 steps = 0;
            for (size_t position = FirstRecordAt(target);
                 position < flowRecords.size() && flowRecords[position].address < limit && ++steps <= MAX_BLOCK_RECORDS;
                 position++) {
                const auto& record = flowRecords[position];
                if (record.kind == FlowKind::Unknown) {
                    if (std::binary_search(instructionSet.reachablePadding.begin(), instructionSet.reachablePadding.end(), record.address))
                        continue;
                    end = std::max(end, record.address);
                    break;
                }
                end = std::min(std::max(end, record.address + record.size), limit);
                if (record.kind == FlowKind::Return || record.kind == FlowKind::Trap || record.kind == FlowKind::Jump ||
                    (record.kind == FlowKind::Call && RecordReachesNoReturn(record)))
                    break;
            }
            return end;
        };
        std::vector<ColdBlock> blocks; // by address, never overlapping
        // the targets of the jumps, the landing pads (the unwinder goes there from their call site)
        std::vector<uint64> targets;
        for (const auto& xref : xrefs.byTarget)
            if (isJump(xref) && xref.to >= labelBase && xref.to - labelBase < codeSize)
                targets.push_back(xref.to - labelBase);
        if (!landingPadSources.empty()) {
            for (const auto& source : landingPadSources)
                targets.push_back(source.first);
            std::sort(targets.begin(), targets.end());
        }
        for (const uint64 target : targets) {
            if ((!blocks.empty() && target < blocks.back().end) || bodyOwner(target).has_value())
                continue; // inside the previous block (sorted by target), or code of a function
            if (const uint64 end = pathEnd(target); end > target)
                blocks.push_back({ target, end, std::nullopt, false });
        }
        // the places the plugin knows inside the code of a function (an EH continuation target after its ret): their path on its frame
        // too (AddColdChunkSlots: the walks of the frame end at the ret before them), not chunks (the body of the function)
        if (codeLocations)
            for (auto location = codeLocations->lower_bound(codeStart); location != codeLocations->end() && *location - codeStart < codeSize; ++location)
                if (const auto owner = bodyOwner(*location - codeStart); owner.has_value())
                    if (const uint64 end = pathEnd(*location - codeStart); end > *location - codeStart)
                        coldChunks.push_back({ *location - codeStart, end, owner.value() });
        if (blocks.empty())
            return;
        const auto blockOf = [&blocks](uint64 address) -> ColdBlock* {
            const auto next = std::upper_bound(blocks.begin(), blocks.end(), address, [](uint64 value, const ColdBlock& block) { return value < block.start; });
            return next != blocks.begin() && address < (next - 1)->end ? &*(next - 1) : nullptr;
        };
        // the owners: from the references into each block; a source in a block not resolved yet waits for it (a pass later), once a
        // resolved source names one (a cycle of blocks reached from their function)
        const auto ownersOf = [&](const ColdBlock& block, bool& waits, bool& foreign) {
            std::set<uint64> owners;
            waits     = false;
            foreign   = false;
            // a jump from `source`: false when it is from code of nobody
            const auto addSource = [&](uint64 source) {
                if (const auto owner = bodyOwner(source); owner.has_value())
                    owners.insert(owner.value());
                else if (const auto* other = blockOf(source); !other || other->rejected)
                    return false;
                else if (other != &block) {
                    if (other->owner.has_value())
                        owners.insert(other->owner.value());
                    else
                        waits = true;
                }
                return true;
            };
            auto from = std::lower_bound(
                  xrefs.byTarget.begin(), xrefs.byTarget.end(), labelBase + block.start, [](const auto& item, uint64 value) { return item.to < value; });
            for (; from != xrefs.byTarget.end() && from->to < labelBase + block.end; ++from) {
                if (!isJump(*from) || from->from < labelBase || from->from - labelBase >= codeSize) {
                    foreign = true; // a call / a taken address / a read: not a tail of a function
                    return owners;
                }
                if (!addSource(from->from - labelBase)) {
                    foreign = true; // from code of nobody
                    return owners;
                }
            }
            for (auto pad = std::lower_bound(landingPadSources.begin(), landingPadSources.end(), std::make_pair(block.start, static_cast<uint64>(0)));
                 pad != landingPadSources.end() && pad->first < block.end;
                 ++pad)
                if (!addSource(pad->second)) {
                    foreign = true;
                    return owners;
                }
            return owners;
        };
        bool changed = true;
        for (uint32 pass = 0; changed && pass < MAX_PASSES; pass++) {
            changed = false;
            for (auto& block : blocks) {
                if (block.owner.has_value() || block.rejected)
                    continue;
                bool waits = false, foreign = false;
                const auto owners = ownersOf(block, waits, foreign);
                if (foreign || owners.size() > 1 || (owners.empty() && !waits)) {
                    block.rejected = true;
                    changed        = true;
                } else if (owners.size() == 1 && (!waits || pass > 0)) {
                    block.owner = *owners.begin();
                    changed     = true;
                }
            }
        }
        // the owners again, now that every block has one or none: a block whose sources disagree is nobody's (until nothing changes)
        changed = true;
        for (uint32 pass = 0; changed && pass < MAX_PASSES; pass++) {
            changed = false;
            for (auto& block : blocks) {
                if (!block.owner.has_value())
                    continue;
                bool waits = false, foreign = false;
                const auto owners = ownersOf(block, waits, foreign);
                if (foreign || waits || owners.size() != 1 || *owners.begin() != block.owner.value()) {
                    block.owner.reset();
                    block.rejected = true;
                    changed        = true;
                }
            }
        }
        const size_t firstBlock = coldChunks.size();
        for (const auto& block : blocks) {
            if (!block.owner.has_value())
                continue;
            if (coldChunks.size() > firstBlock && coldChunks.back().end == block.start && coldChunks.back().function == block.owner.value())
                coldChunks.back().end = block.end; // the next block of the same function: one chunk
            else
                coldChunks.push_back({ block.start, block.end, block.owner.value() });
        }
        chunks.insert(chunks.end(), coldChunks.begin() + static_cast<std::ptrdiff_t>(firstBlock), coldChunks.end());
        std::sort(chunks.begin(), chunks.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
    }

    // the chunks the jumps tell (DetectFunctionChunks, DetectColdBlocks) by their function: AddColdChunkSlots
    void IndexColdChunks()
    {
        coldChunksOf.clear();
        for (size_t index = 0; index < coldChunks.size(); index++)
            coldChunksOf.emplace(coldChunks[index].function, index);
    }

    // a start of the prologue rules strictly inside the code of a function whose size the plugin knows is code of that function: the
    // exception data (x64 .pdata: the unwinding needs the code of every function that is not a leaf, its prologue at its start: the push
    // rbp; mov rbp, rsp after the saves of the home space of MSVC x64), the symbols of ELF (a frame set up after the early exits: GCC
    // shrink wrapping, AnalyzeX86FunctionFrame walks them; the landing pads of the unwinding: endbr64; mov r12, rax; jmp f.cold)
    bool IsInsidePluginFunction(uint64 fileOffset) const
    {
        // the code ranges of the plugin (the FDEs of a stripped ELF: a function or a fragment of one) as well
        if (codeRanges && !codeRanges->empty())
            if (auto range = codeRanges->lower_bound(fileOffset); range != codeRanges->begin() && fileOffset - (--range)->first < range->second)
                return true;
        if (!functionEntries)
            return false;
        auto entry = functionEntries->lower_bound(fileOffset);
        if (entry == functionEntries->begin())
            return false;
        --entry;
        return entry->second.size != 0 && fileOffset - entry->first < entry->second.size;
    }

    // a place inside a function that the plugin knows (Settings::AddCodeLocation), relative
    bool IsCodeLocation(uint64 address) const
    {
        return codeLocations && codeLocations->contains(codeStart + address);
    }

    // the code whose address is taken (relative): by the code, by a pointer of a data zone (sorted by FinishSweep)
    bool IsTakenAddress(uint64 address) const
    {
        return std::binary_search(addressTakenTargets.begin(), addressTakenTargets.end(), address) ||
               std::binary_search(dataPointerTargets.begin(), dataPointerTargets.end(), address);
    }

    // a cold partition of GCC (-freorder-blocks-and-partition): its symbol is the one of its function + .cold (main.cold, f.cold.12)
    static bool IsColdPartitionName(std::string_view name)
    {
        const auto at = name.rfind(".cold");
        if (at == std::string_view::npos || at == 0)
            return false;
        const auto rest = name.substr(at + 5);
        return rest.empty() || (rest.size() > 1 && rest[0] == '.' && std::all_of(rest.begin() + 1, rest.end(), [](char c) { return c >= '0' && c <= '9'; }));
    }

    // the code at `start` (relative) reads a callee saved register of its convention before writing it (rbx, rbp, r12-r15; Windows x64 and
    // 32 bit: rsi, rdi too), as a pointer or as an operand (mov rcx, r14; test rbx, rbx), the first lines up to a jmp / ret / call (the jccs
    // fall through): it is no entry of a function (the registers hold the values of its caller), but the code of the function that set them.
    // Not their saves (push rbx, mov qword ptr [rsp + 0x18], rbx), the idioms that only write (xor ebx, ebx, or ebx, -1), mov edi, edi
    bool ReadsCalleeSavedAtEntry(uint64 start)
    {
        constexpr uint32 MAX_ENTRY_INSTRUCTIONS = 16;
        constexpr uint32 ENTRY_BYTES            = 128;
        if (IsArmArch(arch) || start >= codeSize)
            return false;
        const uint32 calleeSaved =
              is64 ? ((1u << 3) | (1u << 5) | (0xFu << 12) | (zone->systemVCalls ? 0u : (1u << 6) | (1u << 7))) : (1u << 3) | (1u << 5) | (1u << 6) | (1u << 7);
        const auto bytes = obj->GetData().CopyToBuffer(codeStart + start, static_cast<uint32>(std::min<uint64>(codeSize - start, ENTRY_BYTES)), false);
        cs_insn* decoded = bytes.IsValid() ? cs_malloc(handle) : nullptr;
        if (!decoded)
            return false;
        const uint8* data    = bytes.GetData();
        size_t size          = bytes.GetLength();
        uint64 address       = start;
        uint32 written       = 0;
        bool reads           = false;
        const auto unwritten = [&](unsigned int reg) {
            const int family = reg != X86_REG_INVALID ? GetX64RegisterFamily(reg) : -1;
            return family >= 0 && (calleeSaved & (1u << family)) && (written & (1u << family)) == 0;
        };
        for (uint32 count = 0; count < MAX_ENTRY_INSTRUCTIONS && !reads && cs_disasm_iter(handle, &data, &size, &address, decoded); count++) {
            const cs_x86& x86 = decoded->detail->x86;
            if (decoded->id == X86_INS_ENDBR64 || decoded->id == X86_INS_ENDBR32 || decoded->id == X86_INS_NOP || decoded->id == X86_INS_PUSH ||
                (decoded->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                 x86.operands[0].reg == x86.operands[1].reg))
                continue; // a push saves the register; mov edi, edi (hot patching)
            const bool sameRegisters =
                  x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG && x86.operands[0].reg == x86.operands[1].reg;
            const uint64 sizeMask = x86.op_count == 2 && x86.operands[0].size < 8 ? (1ull << (8 * x86.operands[0].size)) - 1 : ~0ull;
            const bool constant   = x86.op_count == 2 && x86.operands[1].type == X86_OP_IMM &&
                                  ((decoded->id == X86_INS_OR && (static_cast<uint64>(x86.operands[1].imm) & sizeMask) == sizeMask) ||
                                   (decoded->id == X86_INS_AND && (static_cast<uint64>(x86.operands[1].imm) & sizeMask) == 0));
            const bool zeroes = ((decoded->id == X86_INS_XOR || decoded->id == X86_INS_SUB) && sameRegisters) || constant; // or ebx, -1: writes only
            const bool stores = decoded->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_REG;
            for (uint8 index = 0; index < x86.op_count && !reads; index++) {
                const cs_x86_op& op = x86.operands[index];
                if (op.type == X86_OP_MEM)
                    reads = unwritten(op.mem.base) || unwritten(op.mem.index);
                else if (op.type == X86_OP_REG && (op.access & CS_AC_READ) && !zeroes && !(stores && index == 1))
                    reads = unwritten(op.reg);
            }
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                    if (const int family = GetX64RegisterFamily(x86.operands[index].reg); family >= 0)
                        written |= 1u << family;
            const auto flow = GetX86Flow(*decoded);
            if (flow != X86Flow::None && flow != X86Flow::ConditionalJump)
                break;
        }
        cs_free(decoded, 1);
        return reads;
    }

    // what the APIs every function calls / jumps to do (the triage: network, crypto, processes, ...): the imports through their slots, the
    // thunks of the imports (j_connect, a PLT stub of another zone) and the functions the plugin names (a static binary: connect), in the
    // code of the function (up to its end) and of its chunks; not through the functions it calls
    void ComputeApiCategories()
    {
        functionApiCategories.assign(functionStarts.size(), 0);
        if (functionEnds.size() != functionStarts.size())
            return;
        std::unordered_map<uint64, uint32> targetCategories; // relative target -> its categories (cached)
        const auto categoriesOfTarget = [this, &targetCategories](uint64 target) {
            if (const auto known = targetCategories.find(target); known != targetCategories.end())
                return known->second;
            uint32 categories = 0;
            if (target < codeSize) {
                if (const auto thunk = thunkImports.find(target); thunk != thunkImports.end())
                    categories = GetApiCategories(thunk->second);
                else if (functionEntries) {
                    const auto entry = functionEntries->find(codeStart + target);
                    if (entry != functionEntries->end() && !entry->second.name.empty())
                        categories = GetApiCategories(entry->second.name);
                }
            } else if (const auto* other = zone->FindCodeZoneOfAddress((labelBase + target) & addressMask); other && other != zone) {
                const uint64 start = ((labelBase + target) & addressMask) - other->labelAddressBase;
                const auto thunk   = other->thunkImports.find(start);
                categories         = GetApiCategories(thunk != other->thunkImports.end() ? thunk->second : other->GetLabelNameAt(start));
            }
            targetCategories.emplace(target, categories);
            return categories;
        };
        for (size_t index = 0; index < functionStarts.size(); index++) {
            std::vector<std::pair<uint64, uint64>> ranges{ { functionStarts[index], functionEnds[index] } };
            for (const auto& chunk : chunks)
                if (chunk.function == functionStarts[index])
                    ranges.emplace_back(chunk.start, chunk.end);
            uint32 categories = 0;
            for (const auto& [rangeStart, rangeEnd] : ranges)
                for (size_t position = FirstRecordAt(rangeStart); position < flowRecords.size() && flowRecords[position].address < rangeEnd; position++) {
                    const auto& record = flowRecords[position];
                    if (record.kind != FlowKind::Call && record.kind != FlowKind::Jump)
                        continue;
                    if (const auto import = importCallCategories.find(record.address); import != importCallCategories.end())
                        categories |= import->second;
                    else if (record.target != NO_TARGET)
                        categories |= categoriesOfTarget(record.target);
                }
            functionApiCategories[index] = categories;
        }
    }

    // the functions that do not return: named so (noReturnStarts), or none of whose paths returns: every path ends with a call / a jump to
    // such a function or to an import that does not return, or a trap (IDA: noreturn). The rounds end when no new one is found. Then the
    // calls to them (noReturnCalls); the instruction after each of them starts a block. A path that falls into the next function, an
    // indirect jump (not a switch), a ret, an undecodable byte: the function returns
    void InferNoReturnFunctions()
    {
        constexpr uint32 MAX_ROUNDS     = 8;
        constexpr uint32 MAX_PATH_STEPS = 4096;
        std::vector<uint64> starts;
        for (const auto& [offset, isJump] : callsMap)
            if (!isJump && offset >= codeStart && offset - codeStart < codeSize)
                starts.push_back(offset - codeStart);
        if (functionEntries)
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it)
                starts.push_back(it->first - codeStart);
        const auto& details = zone->zoneDetails;
        if (details.HasEntryPoint() && details.entryPoint >= codeStart && details.entryPoint - codeStart < codeSize)
            starts.push_back(details.entryPoint - codeStart); // _start: __libc_start_main does not return
        std::sort(starts.begin(), starts.end());
        starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
        // the user: a deleted function is not a function, the attributes are not inferred
        const auto userFlags = [this](uint64 start) {
            const auto found = zone->userFunctions.find(start);
            return found != zone->userFunctions.end() ? found->second : static_cast<uint8>(0);
        };
        starts.erase(std::remove_if(starts.begin(), starts.end(), [&userFlags](uint64 start) { return (userFlags(start) & USER_FUNCTION_DELETE) != 0; }),
                     starts.end());
        for (const uint64 start : userReturns)
            noReturnStarts.erase(start); // a name (exit) or a thunk of the sweep
        const auto switchCases = SwitchCases();
        std::vector<size_t> pending;
        std::unordered_set<size_t> seen; // the records of the function already walked
        const auto firstRecordAt = [this](uint64 address) { return FirstRecordAt(address); };
        const auto returns = [&](size_t index) {
            const uint64 start  = starts[index];
            const uint64 end    = index + 1 < starts.size() ? starts[index + 1] : codeSize;
            const auto inside   = [start, end](uint64 target) { return target >= start && target < end; };
            uint32 steps        = 0;
            pending.assign(1, firstRecordAt(start));
            seen.clear();
            while (!pending.empty()) {
                size_t position = pending.back();
                pending.pop_back();
                for (bool walking = true; walking; position++) {
                    if (position >= flowRecords.size() || flowRecords[position].address >= end || ++steps > MAX_PATH_STEPS)
                        return true; // into the next function
                    if (!seen.insert(position).second)
                        break; // walked from another path
                    const auto& record = flowRecords[position];
                    switch (record.kind) {
                    case FlowKind::Return:
                    case FlowKind::Unknown:
                    case FlowKind::MaybeReturn:
                        return true;
                    case FlowKind::Trap:
                        walking = false;
                        break;
                    case FlowKind::Call:
                        walking = !RecordReachesNoReturn(record);
                        break;
                    case FlowKind::ConditionalJump:
                        if (record.target != NO_TARGET && inside(record.target))
                            pending.push_back(firstRecordAt(record.target));
                        else if (record.target == NO_TARGET || !IsNoReturnTarget(record.target))
                            return true; // a conditional tail call
                        break;
                    case FlowKind::Jump:
                        walking = false;
                        if (const auto cases = switchCases.find(record.address); cases != switchCases.end()) {
                            for (const uint64 target : cases->second) {
                                if (!inside(target))
                                    return true;
                                pending.push_back(firstRecordAt(target));
                            }
                        } else if (record.target != NO_TARGET && inside(record.target))
                            pending.push_back(firstRecordAt(record.target));
                        else if (!RecordReachesNoReturn(record))
                            return true; // a tail call, an indirect jump
                        break;
                    }
                }
            }
            return false;
        };
        for (uint32 round = 0; round < MAX_ROUNDS && !flowRecords.empty(); round++) {
            bool found = false;
            for (size_t index = 0; index < starts.size(); index++)
                if (!noReturnStarts.contains(starts[index]) && (userFlags(starts[index]) & (USER_FUNCTION_NORETURN | USER_FUNCTION_RETURNS)) == 0 &&
                    !returns(index)) {
                    noReturnStarts.insert(starts[index]);
                    found = true;
                }
            if (!found)
                break;
        }
        noReturnCalls.clear();
        for (const auto& record : flowRecords) {
            if (record.kind != FlowKind::Call || !RecordReachesNoReturn(record))
                continue;
            noReturnCalls.insert(record.address);
            // the next instruction starts a block (the code whose address is taken there is a function), not the padding (int3, nop)
            const uint64 next = record.address + record.size;
            uint32 word       = 0;
            if (next < blockStarts.size() && obj->GetData().Copy<uint32>(codeStart + next, word)) {
                const bool padding = IsArmArch(arch) ? word == 0xD503201Fu || (word & 0xFFFF) == 0xBF00 || word == 0xE320F000u
                                                     : (word & 0xFF) == 0xCC || (word & 0xFF) == 0x90 || (word & 0xFFFF) == 0x9066;
                if (!padding)
                    blockStarts[next] = true;
            }
        }
    }

    // the cases of a switch (VA): every case is a jump target (loc_) referenced by the indirect jump
    void AddSwitchTargets(uint64 jumpAddress, uint64 from, const std::vector<uint64>& targets)
    {
        if (!targets.empty())
            switchJumps[jumpAddress] = static_cast<uint32>(targets.size());
        for (const uint64 target : targets) {
            xrefs.Add(from, target, DissasmXrefKind::Switch);
            const auto targetOffset = zone->GetFileOffsetOfAddress(target - labelBase);
            if (targetOffset.has_value() && !callsMap.contains(targetOffset.value())) {
                callsFound.emplace_back(targetOffset.value(), zone->GetLabelName("loc_", target - labelBase));
                callsMap.insert({ targetOffset.value(), true });
            }
        }
    }

    // the cross references of the branches and of the data, the labels of the branch targets
    void AnalyzeBranchesAndData(X86Flow flow, const X86OperandsInfo& operands, uint64 from, bool takesAddress)
    {
        // call $+5 (call next; pop ebx: the address of the code, 32 bit PIC): not a call of a function
        const bool callsNext = flow == X86Flow::Call && operands.directTarget == std::optional<uint64>(insn->address + insn->size);
        if (IsX86Branch(flow) && operands.directTarget.has_value() && !callsNext) {
            const auto kind = flow == X86Flow::Call ? DissasmXrefKind::Call : (flow == X86Flow::Jump ? DissasmXrefKind::Jump : DissasmXrefKind::ConditionalJump);
            xrefs.Add(from, (labelBase + operands.directTarget.value()) & addressMask, kind);
        }
        const auto dataKind = takesAddress ? DissasmXrefKind::Offset : ((operands.memoryAccess & CS_AC_WRITE) ? DissasmXrefKind::Write : DissasmXrefKind::Read);
        // x86 / x64: the size of the memory operand (the type of the data: byte_ / word_ / dword_ / qword_ / xmmword_)
        // ARM: the size of the load / store (ldrb: byte_, ldr w0: dword_, ldr x0: qword_)
        uint8 accessSize = 0;
        if (dataKind != DissasmXrefKind::Offset && (arch == DissasmArch::X86 || arch == DissasmArch::X64) && insn->detail)
            for (uint8 index = 0; index < insn->detail->x86.op_count; index++)
                if (insn->detail->x86.operands[index].type == X86_OP_MEM)
                    accessSize = insn->detail->x86.operands[index].size;
        if (dataKind != DissasmXrefKind::Offset && IsArmArch(arch))
            accessSize = arch == DissasmArch::Arm64 ? GetArm64AccessSize(*insn) : GetArm32AccessSize(*insn);
        if (operands.ripTarget.has_value())
            xrefs.Add(from, (labelBase + operands.ripTarget.value()) & addressMask, dataKind, accessSize);
        // ARM: the address of code built by adr / adrp + add / add pc / movw + movt (a callback stored, passed to a function)
        if (IsArmArch(arch) && takesAddress && operands.ripTarget.has_value())
            AddTakenCodeAddress(operands.ripTarget.value());
        // x86 / x64: the address of code taken by lea / push offset / mov reg, offset (a callback, a thread routine, a window procedure)
        if (arch == DissasmArch::X86 || arch == DissasmArch::X64) {
            if (takesAddress && operands.ripTarget.has_value() && operands.ripTarget.value() < codeSize)
                addressTakenTargets.push_back(operands.ripTarget.value());
            const bool toAccumulator = insn->id == X86_INS_MOV && insn->detail && insn->detail->x86.op_count == 2 &&
                                       insn->detail->x86.operands[0].type == X86_OP_REG &&
                                       (insn->detail->x86.operands[0].reg == X86_REG_EAX || insn->detail->x86.operands[0].reg == X86_REG_RAX);
            for (const uint64 value : operands.immediates) // small values are counters, sizes and flags
                if (value >= 0x10000 && value >= labelBase && value - labelBase < codeSize) {
                    if (!is64)
                        exceptionTableCandidates.emplace_back(value - labelBase, insn->address);
                    if (toAccumulator)
                        returnedAddress = value - labelBase; // decided by the next instruction
                    else
                        addressTakenTargets.push_back(value - labelBase);
                }
        }
        if (operands.absoluteMemory.has_value() && isFileAddress && isFileAddress(operands.absoluteMemory.value()))
            xrefs.Add(from, operands.absoluteMemory.value(), dataKind, accessSize);
        // a table at a fixed address indexed by registers (mov eax, [ecx*4 + 0x403000]); the jump table of a switch has its own reference
        if (operands.tableMemory.has_value() && operands.tableMemory.value() >= 0x10000 && flow != X86Flow::Jump && isFileAddress &&
            isFileAddress(operands.tableMemory.value()))
            xrefs.Add(from, operands.tableMemory.value(), dataKind, accessSize);
        if (!is64 && arch == DissasmArch::X86 && isFileAddress) { // push offset aText / mov ecx, offset aText (x64 uses lea [rip + ...])
            for (const uint64 value : operands.immediates)
                if (value >= 0x10000 && isFileAddress(value))
                    xrefs.Add(from, value, DissasmXrefKind::Offset);
        }

        if (IsX86Branch(flow) && !callsNext) {
            const bool isJump    = flow != X86Flow::Call;
            const auto target    = operands.directTarget;
            const auto offsetOpt = target.has_value() ? zone->GetFileOffsetOfAddress(target.value()) : std::nullopt;
            if (offsetOpt.has_value()) {
                const uint64 value = offsetOpt.value();
                const auto it      = callsMap.find(value);
                if (it != callsMap.end() && isJump == it->second)
                    return;
                callsFound.emplace_back(value, zone->GetLabelName(isJump ? "loc_" : "sub_", target.value()));
                callsMap.insert({ value, isJump });
            }
        }
    }

    // ARM: code whose address is taken (relative): a function when it starts a block (FinishSweep). The address of a Thumb function has
    // bit 0 set; the ARM64 instructions are 4 bytes aligned
    void AddTakenCodeAddress(uint64 target)
    {
        uint64 address = labelBase + target;
        if (arch == DissasmArch::Arm64 && (address & 3) != 0)
            return;
        address &= ~static_cast<uint64>(1);
        if (address >= labelBase && address - labelBase < codeSize)
            addressTakenTargets.push_back(address - labelBase);
    }

    // x64 (MSVC): a register loaded with the image base (lea rdx, [rip - 0x18657] = __ImageBase) makes the displacement of the memory
    // operands that use it (as the base, or as an index of scale 1) an RVA: movzx eax, byte ptr [rdx + rcx + 0x2d9f0] reads the table at
    // __ImageBase + 0x2d9f0. The registers are followed through a function (the linear sweep), a write forgets them, a call forgets the
    // volatile ones; a table is a cross reference (its label) and imageBaseTables (its name in the operands)
    void TrackImageBase(bool isBlockStart, uint64 instructionOffset, X86Flow flow, const X86OperandsInfo& operands)
    {
        if (!imageBase.has_value() || !insn->detail)
            return;
        if (isBlockStart) {
            const auto called = callsMap.find(instructionOffset);
            if ((called != callsMap.end() && !called->second) || (functionEntries && functionEntries->contains(instructionOffset)))
                imageBaseRegisters.fill(false); // another function
        }
        const cs_x86& x86 = insn->detail->x86;
        for (uint8 index = 0; index < x86.op_count; index++) {
            const auto& op = x86.operands[index];
            if (op.type != X86_OP_MEM || op.mem.disp <= 0 || op.mem.base == X86_REG_RIP || (op.mem.segment != X86_REG_INVALID && op.mem.segment != X86_REG_DS))
                continue;
            const int base        = GetX64RegisterFamily(op.mem.base);
            const int indexFamily = GetX64RegisterFamily(op.mem.index);
            const bool viaBase    = base >= 0 && imageBaseRegisters[base];
            const bool viaIndex   = indexFamily >= 0 && imageBaseRegisters[indexFamily] && op.mem.scale == 1;
            if (!viaBase && !viaIndex)
                continue;
            const uint64 table = imageBase.value() + static_cast<uint64>(op.mem.disp);
            if (!isFileAddress || !isFileAddress(table))
                break;
            imageBaseTables[insn->address] = table;
            if (flow != X86Flow::Jump) { // the jump table of a switch has its own reference
                const auto kind = insn->id == X86_INS_LEA ? DissasmXrefKind::Offset : ((op.access & CS_AC_WRITE) ? DissasmXrefKind::Write : DissasmXrefKind::Read);
                xrefs.Add(labelBase + insn->address, table, kind, insn->id == X86_INS_LEA ? 0 : op.size);
            }
            break;
        }
        // the writes: lea reg, __ImageBase sets the register, any other write forgets it; a call changes the volatile registers
        if (flow == X86Flow::Call) {
            for (const int family : { 0, 1, 2, 8, 9, 10, 11 })
                imageBaseRegisters[family] = false;
            return;
        }
        const bool loadsImageBase = insn->id == X86_INS_LEA && operands.ripTarget.has_value() && labelBase + operands.ripTarget.value() == imageBase.value();
        const int loaded = loadsImageBase && x86.op_count > 0 && x86.operands[0].type == X86_OP_REG && x86.operands[0].size == 8
                                 ? GetX64RegisterFamily(x86.operands[0].reg)
                                 : -1;
        for (uint8 index = 0; index < x86.op_count; index++)
            if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                if (const int family = GetX64RegisterFamily(x86.operands[index].reg); family >= 0)
                    imageBaseRegisters[family] = false;
        for (uint8 index = 0; index < insn->detail->regs_write_count; index++)
            if (const int family = GetX64RegisterFamily(insn->detail->regs_write[index]); family >= 0)
                imageBaseRegisters[family] = false;
        if (loaded >= 0)
            imageBaseRegisters[loaded] = true;
    }

    // 32 bit x86 PIC: ebx holds the global offset table in the functions that set it (call $+5; pop ebx / call __x86.get_pc_thunk.bx, then
    // add ebx, imm) and in the PLT stubs (the table of the plugin). An operand [ebx + disp] is then an address of the file: the instruction
    // gets it (resolvedAddresses: the import of a call / jmp [ebx + 0x10], the string of lea eax, [ebx - 0x31c0]) and so do the xrefs
    void TrackGlobalOffsetTable(bool isBlockStart, uint64 instructionOffset, X86Flow flow, X86OperandsInfo& operands)
    {
        if (isBlockStart) {
            const auto called = callsMap.find(instructionOffset);
            if ((called != callsMap.end() && !called->second) || (functionEntries && functionEntries->contains(instructionOffset)))
                functionEbx.reset(); // another function
            ebxValue = functionEbx;  // an epilogue (pop ebx; ret) ended the previous block, not the function
        }
        const cs_x86* x86 = insn->detail ? &insn->detail->x86 : nullptr;
        // the value of ebx used by this instruction (before its own write)
        std::optional<uint64> ebx = ebxValue;
        if (!ebx.has_value() && isBlockStart && flow == X86Flow::Jump && globalOffsetTable.has_value())
            ebx = globalOffsetTable; // a PLT stub: jmp dword ptr [ebx + 0xc]
        if (ebx.has_value() && x86) {
            for (uint8 index = 0; index < x86->op_count; index++) {
                const auto& op = x86->operands[index];
                if (op.type != X86_OP_MEM || op.mem.base != X86_REG_EBX || op.mem.index != X86_REG_INVALID || op.mem.segment != X86_REG_INVALID)
                    continue;
                const uint64 address = (ebx.value() + static_cast<uint64>(op.mem.disp)) & addressMask;
                if (!isFileAddress || !isFileAddress(address))
                    break;
                const uint64 relative          = (address - labelBase) & addressMask;
                resolvedAddresses[insn->address] = relative;
                operands.ripTarget               = relative; // the import of a stub / call, the data xref (AnalyzeBranchesAndData)
                operands.memoryAccess            = insn->id == X86_INS_LEA ? 0 : op.access;
                break;
            }
        }
        // the writes of ebx: the setup (pop ebx after call $+5, add / sub ebx, imm, lea ebx, [ebx + disp]), anything else forgets it
        const bool popsEbx = insn->id == X86_INS_POP && x86 && x86->op_count == 1 && x86->operands[0].type == X86_OP_REG && x86->operands[0].reg == X86_REG_EBX;
        if (popsEbx && pendingPopEbx.has_value()) {
            ebxValue = pendingPopEbx; // the address of the pop
            pendingPopEbx.reset();
            return;
        }
        pendingPopEbx.reset();
        if (flow == X86Flow::Call && operands.directTarget.has_value()) {
            const uint64 target = operands.directTarget.value();
            if (target == insn->address + insn->size)
                pendingPopEbx = labelBase + target; // call $+5: the next instruction pops its own address
            else if (target < codeSize) {
                uint32 thunk = 0; // __x86.get_pc_thunk.bx: mov ebx, dword ptr [esp]; ret
                if (obj->GetData().Copy<uint32>(codeStart + target, thunk) && thunk == 0xC3241C8Bu)
                    ebxValue = labelBase + insn->address + insn->size;
            }
            return;
        }
        if (!x86)
            return;
        bool writesEbx = false;
        for (uint8 index = 0; index < x86->op_count; index++)
            if (x86->operands[index].type == X86_OP_REG && (x86->operands[index].access & CS_AC_WRITE) &&
                (x86->operands[index].reg == X86_REG_EBX || x86->operands[index].reg == X86_REG_BX || x86->operands[index].reg == X86_REG_BL ||
                 x86->operands[index].reg == X86_REG_BH))
                writesEbx = true;
        for (uint8 index = 0; index < insn->detail->regs_write_count; index++)
            if (insn->detail->regs_write[index] == X86_REG_EBX)
                writesEbx = true;
        if (!writesEbx)
            return;
        const bool toEbx = x86->op_count == 2 && x86->operands[0].type == X86_OP_REG && x86->operands[0].reg == X86_REG_EBX;
        if (ebxValue.has_value() && toEbx && (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB) && x86->operands[1].type == X86_OP_IMM) {
            const uint64 imm = static_cast<uint64>(x86->operands[1].imm);
            ebxValue         = (insn->id == X86_INS_ADD ? ebxValue.value() + imm : ebxValue.value() - imm) & addressMask;
            functionEbx      = ebxValue;
        } else if (ebxValue.has_value() && toEbx && insn->id == X86_INS_LEA && x86->operands[1].mem.base == X86_REG_EBX &&
                   x86->operands[1].mem.index == X86_REG_INVALID) {
            ebxValue    = (ebxValue.value() + static_cast<uint64>(x86->operands[1].mem.disp)) & addressMask;
            functionEbx = ebxValue;
        } else
            ebxValue.reset();
    }

    // the first instructions at `target` look like code, not like the data that the code refers to (a string, a GUID kept in .text): no
    // data line, no opcode 00 (add byte ptr [...], r8: the zeros of data), none of the instructions that data decodes to and code never
    // uses (in / out, hlt, the BCD adjustments, arpl, bound, les / lds), until a return / a jump or 16 instructions
    // ARM: no data line (a literal pool), no zero word, no udf / bkpt / brk / hlt
    bool LooksLikeCode(uint64 target)
    {
        DissasmCodeLinesWalker probe(obj, codeStart, codeSize, handle, target, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
        if (IsArmArch(arch)) {
            for (uint32 count = 0; count < 16; count++) {
                if (!probe.Next(insn) || insn->id == 0 || std::all_of(insn->bytes, insn->bytes + insn->size, [](uint8 value) { return value == 0; }))
                    return false;
                const DissasmArch insnArch = zone->GetArchAt(insn->address);
                if (insnArch == DissasmArch::Arm64 ? insn->id == ARM64_INS_UDF || insn->id == ARM64_INS_BRK || insn->id == ARM64_INS_HLT
                                                   : insn->id == ARM_INS_UDF || insn->id == ARM_INS_BKPT)
                    return false;
                const auto flow = GetInstructionFlow(*insn, insnArch);
                if (flow == X86Flow::Return || flow == X86Flow::Jump)
                    return true;
            }
            return true;
        }
        for (uint32 count = 0; count < 16; count++) {
            if (!probe.Next(insn) || insn->id == X86_INS_INVALID || insn->bytes[0] == 0x00)
                return false;
            switch (insn->id) {
            case X86_INS_IN:
            case X86_INS_OUT:
            case X86_INS_INSB:
            case X86_INS_INSW:
            case X86_INS_INSD:
            case X86_INS_OUTSB:
            case X86_INS_OUTSW:
            case X86_INS_OUTSD:
            case X86_INS_HLT:
            case X86_INS_AAA:
            case X86_INS_AAS:
            case X86_INS_AAM:
            case X86_INS_AAD:
            case X86_INS_DAA:
            case X86_INS_DAS:
            case X86_INS_ARPL:
            case X86_INS_BOUND:
            case X86_INS_LES:
            case X86_INS_LDS:
            case X86_INS_INT3:
                return false;
            default:
                break;
            }
            const auto flow = GetX86Flow(*insn);
            if (flow == X86Flow::Return || flow == X86Flow::Jump)
                return true;
        }
        return true;
    }

    // the direct calls of the other code zones of the file (analyzed before this one) into this code: function starts, as the calls of the
    // zone are (shell32: the calls of .text to the function override thunk of its fothk section, a zone that calls nothing)
    void AddOtherZoneCallTargets()
    {
        for (const auto* sibling : zone->siblingZones) {
            if (sibling == zone || sibling->zoneDetails.isData)
                continue;
            const auto& byTarget = sibling->xrefs.byTarget; // sorted by target (Finish)
            auto reference =
                  std::lower_bound(byTarget.begin(), byTarget.end(), labelBase, [](const DissasmXref& xref, uint64 value) { return xref.to < value; });
            for (; reference != byTarget.end() && reference->to - labelBase < codeSize; ++reference) {
                const uint64 target = reference->to - labelBase;
                if (reference->kind == DissasmXrefKind::Call && target < blockStarts.size() && blockStarts[target])
                    AddFunctionStart(codeStart + target);
            }
        }
    }

    // a function that is a jmp to a named function of another code zone (the function override thunk of fothk: jmp
    // j___guard_dispatch_icall_fptr of .text): j_ and that name, as the thunks of the imports (a second one: j_Name_1)
    void NameOtherZoneThunks()
    {
        if (otherZoneJumps.empty())
            return;
        std::unordered_set<std::string> usedNames;
        for (const auto& call : callsFound)
            if (GetLabelType(call.second) != SUB)
                usedNames.insert(call.second);
        for (auto& call : callsFound) {
            if (call.first < codeStart || GetLabelType(call.second) != SUB)
                continue;
            const auto jump = otherZoneJumps.find(call.first - codeStart);
            if (jump == otherZoneJumps.end())
                continue;
            const auto* other = zone->FindCodeZoneOfAddress(jump->second);
            if (!other || other == zone)
                continue;
            const std::string target = other->GetLabelNameAt(jump->second - other->labelAddressBase);
            if (target.empty() || target == "EntryPoint" || target.starts_with("sub_") || target.starts_with("loc_"))
                continue;
            std::string name = "j_" + target;
            for (uint32 index = 1; usedNames.contains(name) && index < 1000; index++)
                name = "j_" + target + "_" + std::to_string(index);
            if (usedNames.insert(name).second)
                call.second = std::move(name);
        }
    }

    // the aligned values of the data zones of the file that point into this code (their bytes in the file: the data zones are analyzed
    // after the code)
    void AddDataZonePointerTargets()
    {
        constexpr uint64 MAX_DATA_ZONE_SIZE = 64ull * 1024 * 1024;
        const uint8 pointerSize             = is64 ? 8 : 4;
        const bool isArm                    = IsArmArch(arch);
        for (const auto* sibling : zone->siblingZones) {
            const auto& details = sibling->zoneDetails;
            if (!details.isData || details.startingZonePoint >= obj->GetData().GetSize())
                continue;
            const uint64 size  = std::min<uint64>({ details.size, MAX_DATA_ZONE_SIZE, obj->GetData().GetSize() - details.startingZonePoint });
            auto bytes         = obj->GetData().CopyToBuffer(details.startingZonePoint, static_cast<uint32>(size), false);
            ApplyRelocatedPointers(zone->relocatedPointers, details.startingZonePoint, bytes.GetData(), bytes.GetLength(), pointerSize);
            const uint8* data  = bytes.GetData();
            const auto readValue = [data, pointerSize](uint64 position) {
                uint64 value = 0;
                for (uint8 index = 0; index < pointerSize; index++)
                    value |= static_cast<uint64>(data[position + index]) << (8 * index);
                return value;
            };
            // x86: the exception tables point inside their functions (the __except filters and blocks, the catch blocks and the unwind
            // actions follow a jmp): the SEH scope records {EnclosingLevel, FilterFunc, HandlerFunc}, the C++ unwind map {toState, action},
            // the catch handlers {..., dispCatchObj, addressOfHandler}. A code pointer after a small (or small negative) number, or the
            // second pointer of such a record, is not a function
            const auto isSmallNumber = [](uint64 value) { return value < 0x10000 || value >= 0xFFFF0000; };
            for (uint64 position = 0; data && position + pointerSize <= bytes.GetLength(); position += pointerSize) {
                const uint64 value = readValue(position);
                if (value < labelBase || value - labelBase >= codeSize)
                    continue;
                if (isArm) { // a Thumb function: bit 0 set
                    AddTakenCodeAddress(value - labelBase);
                    continue;
                }
                dataPointerTargets.push_back(value - labelBase); // the SEH filters / handlers, the unwind actions
                if (!is64 && position >= 4 && isSmallNumber(readValue(position - 4)))
                    continue; // FilterFunc, action, addressOfHandler
                if (!is64 && position >= 8 && isSmallNumber(readValue(position - 8)))
                    continue; // HandlerFunc
                addressTakenTargets.push_back(value - labelBase);
            }
        }
    }

    // the end of the sweep: the labels are sorted, the functions and their names are known
    void FinishSweep()
    {
        // ARM64: the prologues that no conditional branch reaches are functions (the others are shrink wrapped, inside their function)
        for (const uint64 candidate : prologueCandidates)
            if (!conditionalTargets.contains(candidate - codeStart))
                AddFunctionStart(candidate);
        // the code whose address is taken, by the code or by the pointers of the data zones (the virtual methods of the vtables, the
        // callbacks): a function when it starts a block
        // (not a case of a switch, an absolute jump table of GCC in .rodata; not the target of a conditional jump, inside a function; not
        // the anchor of an ARM64 jump table, the target of a veneer)
        AddDataZonePointerTargets();
        AddOtherZoneCallTargets();
        // the targets of the veneers: jumps, not addresses taken (not the code of the function whose range they are in: ComputeFunctionEnds)
        addressTakenTargets.erase(
              std::remove_if(addressTakenTargets.begin(), addressTakenTargets.end(), [this](uint64 target) { return farJumpTargets.contains(target); }),
              addressTakenTargets.end());
        std::sort(dataPointerTargets.begin(), dataPointerTargets.end()); // IsTakenAddress
        dataPointerTargets.erase(std::unique(dataPointerTargets.begin(), dataPointerTargets.end()), dataPointerTargets.end());
        if (!addressTakenTargets.empty()) {
            std::unordered_set<uint64> insideFunctions = switchAnchors;
            for (const auto& xref : xrefs.byTarget)
                if ((xref.kind == DissasmXrefKind::Switch || xref.kind == DissasmXrefKind::ConditionalJump) && xref.to >= labelBase)
                    insideFunctions.insert(xref.to - labelBase);
            std::sort(addressTakenTargets.begin(), addressTakenTargets.end());
            addressTakenTargets.erase(std::unique(addressTakenTargets.begin(), addressTakenTargets.end()), addressTakenTargets.end());
            for (const uint64 target : addressTakenTargets)
                if (IsCodeLocation(target)) { // a place inside its function (an __except block, the continuation of a local unwind): a label
                    if (target < codeSize && callsMap.insert({ codeStart + target, true }).second)
                        callsFound.emplace_back(codeStart + target, zone->GetLabelName("loc_", target));
                } else if (target < blockStarts.size() && blockStarts[target] && !insideFunctions.contains(target) && LooksLikeCode(target))
                    AddFunctionStart(codeStart + target);
        }
        // 32 bit MSVC: a jump to the frame of a function built by a helper (push 0x28; mov eax, offset handler; call __EH_prolog3 / push
        // 0x10; push offset scopetable; call __SEH_prolog4) is a tail call: the target is a function (the entry point: jmp
        // __scrt_common_main_seh), not cold code of the function that jumps (DetectColdBlocks, DetectFunctionChunks)
        if (arch == DissasmArch::X86)
            for (const auto& xref : xrefs.byTarget)
                if ((xref.kind == DissasmXrefKind::Jump || xref.kind == DissasmXrefKind::ConditionalJump) && xref.to >= labelBase &&
                    xref.to - labelBase < blockStarts.size() && blockStarts[xref.to - labelBase] && !helperFrameStarts.contains(xref.to - labelBase) &&
                    StartsWithFrameHelper(xref.to - labelBase)) {
                    helperFrameStarts.insert(xref.to - labelBase);
                    AddFunctionStart(codeStart + xref.to - labelBase);
                }
        // the __except blocks of x64 SEH (reached by the unwinding only, after the jmp that ends their __try): a label, as IDA
        // the chunks of the functions (x64 chained unwind data) as well
        if (functionEntries)
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it) {
                for (const auto& scope : it->second.exceptionScopes) {
                    if (scope.target >= codeStart && scope.target - codeStart < blockStarts.size() && blockStarts[scope.target - codeStart] &&
                        callsMap.insert({ scope.target, true }).second)
                        callsFound.emplace_back(scope.target, zone->GetLabelName("loc_", scope.target - codeStart));
                    // a handler is a function (ARM64: a filter can be a leaf function without .pdata, not a function start yet)
                    if (scope.handler >= codeStart && scope.handler - codeStart < codeSize && callsMap.insert({ scope.handler, false }).second)
                        callsFound.emplace_back(scope.handler, zone->GetLabelName("sub_", scope.handler - codeStart));
                }
                for (const auto& chunk : it->second.chunks)
                    if (chunk.first >= codeStart && chunk.first - codeStart < blockStarts.size() && blockStarts[chunk.first - codeStart] &&
                        callsMap.insert({ chunk.first, true }).second)
                        callsFound.emplace_back(chunk.first, zone->GetLabelName("loc_", chunk.first - codeStart));
            }
        // the landing pads of the exception handling of GCC / clang (reached by the unwinding only): a label, as IDA
        if (landingPads) {
            for (const auto& landingPad : *landingPads) {
                if (landingPad.pad < codeStart || landingPad.pad - codeStart >= blockStarts.size() || !blockStarts[landingPad.pad - codeStart])
                    continue;
                if (callsMap.insert({ landingPad.pad, true }).second)
                    callsFound.emplace_back(landingPad.pad, zone->GetLabelName("loc_", landingPad.pad - codeStart));
                if (landingPad.begin >= codeStart && landingPad.begin - codeStart < codeSize)
                    landingPadSources.emplace_back(landingPad.pad - codeStart, landingPad.begin - codeStart);
            }
            std::sort(landingPadSources.begin(), landingPadSources.end());
            landingPadSources.erase(std::unique(landingPadSources.begin(), landingPadSources.end()), landingPadSources.end());
        }
        // every label found at the entry point (a call and a prologue can both find it): the entry point keeps its own name
        if (zone->zoneDetails.HasEntryPoint()) {
            callsFound.erase(
                  std::remove_if(callsFound.begin(), callsFound.end(), [this](const auto& call) { return call.first == zone->zoneDetails.entryPoint; }),
                  callsFound.end());
            callsFound.emplace_back(zone->zoneDetails.entryPoint, "EntryPoint");
        }
        std::stable_sort(callsFound.begin(), callsFound.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first)
                return a.first < b.first;
            return GetLabelType(a.second) < GetLabelType(b.second); // a function start wins over a jump target
        });
        callsFound.erase(
              std::unique(callsFound.begin(), callsFound.end(), [](const auto& left, const auto& right) { return left.first == right.first; }),
              callsFound.end());
        xrefs.Finish();

        // the functions deleted by the user: their label stays, a location (loc_); not the entry point
        for (auto& call : callsFound) {
            const auto user = call.first >= codeStart ? zone->userFunctions.find(call.first - codeStart) : zone->userFunctions.end();
            if (user != zone->userFunctions.end() && (user->second & USER_FUNCTION_DELETE) && GetLabelType(call.second) == SUB) {
                call.second            = zone->GetLabelName("loc_", call.first - codeStart);
                callsMap[call.first]   = true;
            }
        }
        // the places the plugin knows inside the functions (the EH continuation targets): locations, whatever found them
        if (codeLocations && !codeLocations->empty())
            for (auto& call : callsFound)
                if (call.first >= codeStart && IsCodeLocation(call.first - codeStart) && GetLabelType(call.second) == SUB &&
                    call.first != zone->zoneDetails.entryPoint && !(functionEntries && functionEntries->contains(call.first))) {
                    call.second          = zone->GetLabelName("loc_", call.first - codeStart);
                    callsMap[call.first] = true;
                }
        if (!IsArmArch(arch))
            DemoteComputedGotoTargets();

        // relative addresses, every function is bounded by the next one (or by its size, when the plugin knows it)
        for (const auto& call : callsFound)
            if (call.first >= codeStart && (GetLabelType(call.second) == SUB || call.second == "EntryPoint"))
                functionStarts.push_back(call.first - codeStart); // sorted: callsFound is sorted by address

        // the names given by the plugin (exports, TLS callbacks), then the names of the import thunks; the entry point keeps its name, a
        // name used twice is not applied again
        const bool hasFunctionEntries = functionEntries && !functionEntries->empty();
        if (hasFunctionEntries || !thunks.empty()) {
            std::unordered_set<std::string> usedNames;
            usedNames.reserve(callsFound.size());
            for (const auto& call : callsFound)
                usedNames.insert(call.second);
            std::unordered_set<uint64> namedByPlugin;
            for (auto& call : callsFound) {
                if (!hasFunctionEntries || call.first == zone->zoneDetails.entryPoint)
                    continue;
                const auto entry = functionEntries->find(call.first);
                if (entry == functionEntries->end() || entry->second.name.empty())
                    continue;
                if (usedNames.insert(entry->second.name).second) {
                    call.second = entry->second.name;
                    namedByPlugin.insert(call.first);
                }
            }
            for (const auto& [thunkOffset, importName] : thunks) {
                const auto call = std::lower_bound(
                      callsFound.begin(), callsFound.end(), thunkOffset, [](const auto& item, uint64 value) { return item.first < value; });
                if (call == callsFound.end() || call->first != thunkOffset || call->first == zone->zoneDetails.entryPoint ||
                    namedByPlugin.contains(thunkOffset))
                    continue;
                // a second thunk of the same import: j_Name_1, j_Name_2, ...
                std::string name = "j_" + importName;
                for (uint32 index = 1; usedNames.contains(name) && index < 1000; index++)
                    name = "j_" + importName + "_" + std::to_string(index);
                if (usedNames.insert(name).second)
                    call->second = std::move(name);
            }
            if (hasFunctionEntries && (!IsArmArch(arch) || arch == DissasmArch::Arm64)) // the exception data of x64 / ARM64 PE
                CollectExceptionScopes(usedNames, namedByPlugin);
        }
        if (landingPads && !landingPads->empty()) // the exception handling of GCC / clang (ELF)
            MarkLandingPads();

        // local variables: a dedicated handle with the instruction details (operands, registers access) enabled
        if (detectLocalVariables) {
            hasDetailHandle = cs_open(zone->capstoneArch, static_cast<cs_mode>(internalArchitecture), &detailHandle) == CS_ERR_OK;
            if (hasDetailHandle && cs_option(detailHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
                cs_close(&detailHandle);
                hasDetailHandle = false;
            }
        }
    }

    // GCC with CET (an endbr64 at every target of an indirect branch): the labels of a computed goto (glibc's printf: goto *(base +
    // table[i]), jmp rcx) start with an endbr64 after a jmp / the padding, as the functions do (X86PrologueDetector). Such a start is a
    // location of the function before it when its code can not be the entry of a function: it reads the memory through a callee saved
    // register before writing it (mov rdi, qword ptr [rbp - 0x498]: the frame of the function it belongs to), or it moves registers only and
    // jumps into the code of another function (mov r11d, 8; jmp loc_3E8F9: a shared tail). Not when the plugin / the user knows it, when its
    // address is taken, when something else than a jump from the code it joins refers to it (a call: a function)
    void DemoteComputedGotoTargets()
    {
        constexpr uint32 MAX_ENTRY_INSTRUCTIONS = 16;
        constexpr uint32 ENTRY_BYTES            = 128;
        std::vector<size_t> subs; // the indexes of the function starts in callsFound (sorted by address)
        for (size_t index = 0; index < callsFound.size(); index++)
            if (callsFound[index].first >= codeStart && (GetLabelType(callsFound[index].second) == SUB || callsFound[index].second == "EntryPoint"))
                subs.push_back(index);
        if (subs.size() < 2)
            return;
        const uint32 calleeSavedFamilies = is64 ? (1u << 3) | (1u << 5) | (0xFu << 12) : (1u << 3) | (1u << 5) | (1u << 6) | (1u << 7);
        cs_insn* decoded                 = cs_malloc(handle);
        if (!decoded)
            return;

        std::vector<size_t> candidates; // positions in subs
        for (size_t position = 0; position < subs.size(); position++) {
            const uint64 fileOffset = callsFound[subs[position]].first;
            const uint64 start      = fileOffset - codeStart;
            const uint64 nextStart  = position + 1 < subs.size() ? callsFound[subs[position + 1]].first - codeStart : codeSize;
            if (start >= codeSize || fileOffset == zone->zoneDetails.entryPoint || (functionEntries && functionEntries->contains(fileOffset)) ||
                zone->userFunctions.contains(start) || IsTakenAddress(start))
                continue;
            const auto bytes = obj->GetData().CopyToBuffer(fileOffset, static_cast<uint32>(std::min<uint64>(codeSize - start, ENTRY_BYTES)), false);
            if (!bytes.IsValid())
                continue;
            const uint8* data  = bytes.GetData();
            size_t size        = bytes.GetLength();
            uint64 address     = start;
            uint32 written     = 0;     // the families written so far
            bool touchesMemory = false; // a memory operand, a push / pop
            bool sawEndbr      = false;
            bool notEntry      = false;
            for (uint32 count = 0; count < MAX_ENTRY_INSTRUCTIONS && cs_disasm_iter(handle, &data, &size, &address, decoded); count++) {
                const cs_x86& x86 = decoded->detail->x86;
                if (decoded->id == X86_INS_ENDBR64 || decoded->id == X86_INS_ENDBR32) {
                    sawEndbr = true;
                    continue;
                }
                if (!sawEndbr)
                    break; // the endbr64 rule of X86PrologueDetector only
                for (uint8 index = 0; index < x86.op_count && !notEntry; index++) {
                    if (x86.operands[index].type != X86_OP_MEM)
                        continue;
                    touchesMemory = true;
                    for (const x86_reg reg : { x86.operands[index].mem.base, x86.operands[index].mem.index }) {
                        const int family = reg != X86_REG_INVALID ? GetX64RegisterFamily(reg) : -1;
                        if (family >= 0 && (calleeSavedFamilies & (1u << family)) && (written & (1u << family)) == 0)
                            notEntry = true; // [rbp - 0x498] before rbp is written: the frame of the caller
                    }
                }
                if (notEntry)
                    break;
                touchesMemory |= decoded->id == X86_INS_PUSH || decoded->id == X86_INS_POP; // the stubs of .plt: push 3; jmp the first one
                for (uint8 index = 0; index < x86.op_count; index++)
                    if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                        if (const int family = GetX64RegisterFamily(x86.operands[index].reg); family >= 0)
                            written |= 1u << family;
                const auto flow = GetX86Flow(*decoded);
                if (flow == X86Flow::Jump && !touchesMemory && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM) {
                    const uint64 target = static_cast<uint64>(x86.operands[0].imm);
                    const auto label    = callsMap.find(codeStart + target);
                    notEntry = target < codeSize && (target < start || target >= nextStart) && (label == callsMap.end() || label->second);
                }
                if (flow != X86Flow::None && flow != X86Flow::ConditionalJump)
                    break; // the fall through of a jcc goes on
            }
            if (notEntry)
                candidates.push_back(position);
        }
        cs_free(decoded, 1);

        // every reference to a candidate: a jump from another candidate (the code of the same computed goto); a jump from the function
        // before it makes it a chunk of that function (DetectFunctionChunks), a call / a taken address a function. A candidate joins the
        // function kept before it (none: it stays a function). The candidates that stay functions change the others: until nothing changes
        std::vector<uint64> subStarts(subs.size());
        for (size_t position = 0; position < subs.size(); position++)
            subStarts[position] = callsFound[subs[position]].first - codeStart;
        constexpr uint32 MAX_PASSES = 8; // a chain of candidates that stay functions (hostile code): the last state is kept
        std::vector<bool> demoted(subs.size(), false);
        for (const size_t position : candidates)
            demoted[position] = true;
        bool changed = !candidates.empty();
        for (uint32 pass = 0; changed && pass < MAX_PASSES; pass++) {
            changed = false;
            for (const size_t position : candidates) {
                if (!demoted[position])
                    continue;
                size_t previous = position;
                while (previous > 0 && demoted[previous - 1])
                    previous--;
                bool joins = previous > 0;
                for (auto [xref, last] = xrefs.To(labelBase + subStarts[position]); xref != last && joins; ++xref) {
                    const bool isJump = xref->kind == DissasmXrefKind::Jump || xref->kind == DissasmXrefKind::ConditionalJump ||
                                        xref->kind == DissasmXrefKind::Switch;
                    const auto source = isJump && xref->from >= labelBase + subStarts[0]
                                              ? std::upper_bound(subStarts.begin(), subStarts.end(), xref->from - labelBase)
                                              : subStarts.begin();
                    joins = source != subStarts.begin() && demoted[static_cast<size_t>(source - subStarts.begin()) - 1];
                }
                if (!joins) {
                    demoted[position] = false;
                    changed           = true;
                }
            }
        }
        for (const size_t position : candidates)
            if (demoted[position]) {
                auto& call           = callsFound[subs[position]];
                call.second          = zone->GetLabelName("loc_", call.first - codeStart);
                callsMap[call.first] = true;
                computedGotoTargets.push_back(call.first - codeStart);
            }
    }

    // the last instruction of [begin, end) (relative): } // starts at
    std::optional<uint64> LastInstructionOf(uint64 begin, uint64 end)
    {
        constexpr uint32 MAX_SCOPE_INSTRUCTIONS = 0x10000;
        DissasmCodeLinesWalker probe(obj, codeStart, codeSize, handle, begin, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
        std::optional<uint64> last;
        for (uint32 count = 0; count < MAX_SCOPE_INSTRUCTIONS && probe.Next(insn) && insn->address < end; count++)
            last = insn->address;
        return last;
    }

    // the exception handling of GCC / clang (Settings::AddLandingPads), as IDA: the code of each call site (try {, } // starts at) and its
    // landing pad (catch(type) in the order they are tried, cleanup(); owned by the first call site that goes to the pad)
    void MarkLandingPads()
    {
        constexpr uint64 MAX_CALL_SITE_SIZE = 0x10000;   // the ranges of GCC: a few KB
        constexpr uint64 MAX_WALKED_SIZE    = 0x1000000; // the code walked for the last instructions of the ranges, in all
        uint64 walked                       = 0;
        const auto inCode                   = [this](uint64 fileOffset) { return fileOffset >= codeStart && fileOffset - codeStart < codeSize; };
        // a mark of the pad once (the call sites of a pad share it)
        const auto addPadMark = [this](uint64 pad, const DissasmCodeZone::ExceptionMark& mark) {
            auto& marks = exceptionMarks[pad];
            if (std::none_of(marks.begin(), marks.end(), [&mark](const auto& other) { return other.kind == mark.kind && other.catchType == mark.catchType; }))
                marks.push_back(mark);
        };
        for (const auto& landingPad : *landingPads) {
            if (!inCode(landingPad.begin) || landingPad.end <= landingPad.begin || !inCode(landingPad.end - 1) || !inCode(landingPad.pad) ||
                landingPad.end - landingPad.begin > MAX_CALL_SITE_SIZE)
                continue;
            DissasmCodeZone::ExceptionMark mark{
                DissasmCodeZone::ExceptionMark::Kind::CppTryBegin, landingPad.begin - codeStart, std::nullopt, std::nullopt, {}, true
            };
            AddExceptionMark(mark.begin, mark);
            walked += landingPad.end - landingPad.begin;
            if (const auto last = walked <= MAX_WALKED_SIZE ? LastInstructionOf(mark.begin, landingPad.end - codeStart) : std::nullopt; last.has_value()) {
                mark.kind = DissasmCodeZone::ExceptionMark::Kind::TryEnd;
                AddExceptionMark(last.value(), mark);
            }
            for (const auto& type : landingPad.catchTypes)
                addPadMark(landingPad.pad - codeStart, { DissasmCodeZone::ExceptionMark::Kind::Catch, mark.begin, std::nullopt, std::nullopt, type, true });
            if (landingPad.isCleanup)
                addPadMark(landingPad.pad - codeStart, { DissasmCodeZone::ExceptionMark::Kind::Cleanup, mark.begin, std::nullopt, std::nullopt, {}, true });
        }
    }

    // x64 structured exception handling (Settings::AddExceptionScopes): the funclets named after their function as IDA (sub_X$fin$0: a
    // __finally, sub_X$filt$0: a filter), the marks of the scopes on their instructions (DissasmCodeZone::exceptionMarks), the funclets
    // that receive the frame of their function (LinkFuncletFrames)
    void CollectExceptionScopes(std::unordered_set<std::string>& usedNames, const std::unordered_set<uint64>& namedByPlugin)
    {
        const auto labelOf = [this](uint64 fileOffset) -> std::pair<uint64, std::string>* {
            const auto call = std::lower_bound(
                  callsFound.begin(), callsFound.end(), fileOffset, [](const auto& item, uint64 value) { return item.first < value; });
            return call != callsFound.end() && call->first == fileOffset ? &*call : nullptr;
        };
        const auto inCode = [this](uint64 fileOffset) { return fileOffset >= codeStart && fileOffset - codeStart < codeSize; };
        std::unordered_set<uint64> linkedFunclets;
        for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it) {
            const auto& entry  = it->second;
            const auto* parent = entry.exceptionScopes.empty() && entry.exceptionFunclets.empty() ? nullptr : labelOf(it->first);
            if (!parent)
                continue;
            const std::string parentName = parent->second;
            uint32 filters = 0, finallies = 0, catches = 0, unwinds = 0;
            // the funclet (once: the same __finally may guard several scopes): its name after the function, its link to the frame
            const auto addFunclet = [&](uint64 fileOffset, std::string_view kind, uint32& counter) {
                if (!linkedFunclets.insert(fileOffset).second)
                    return;
                auto* funclet           = labelOf(fileOffset);
                const auto funcletEntry = functionEntries->find(fileOffset);
                if (!funclet) // ARM64: a filter can be a leaf function without .pdata (named; no frame link)
                    return;
                if (GetLabelType(funclet->second) == SUB && !namedByPlugin.contains(fileOffset)) {
                    std::string name = parentName + std::string(kind) + std::to_string(counter++);
                    if (usedNames.insert(name).second)
                        funclet->second = std::move(name);
                }
                if (arch == DissasmArch::X64 && funcletEntry != functionEntries->end()) // the frame of the function: x64 (mov rbp, rdx)
                    funcletLinks.push_back(
                          { fileOffset - codeStart, it->first - codeStart, funcletEntry->second.size, entry.prologSize, entry.frameRegister, entry.frameOffset });
                else if (arch == DissasmArch::Arm64 && fileOffset != it->first) // ARM64: its x29 is the one of the function
                    arm64FuncletParents.emplace(fileOffset - codeStart, it->first - codeStart);
            };
            // a mark, not twice the same one (the ranges shared by the try blocks of a function)
            const auto addMark = [this](uint64 address, const DissasmCodeZone::ExceptionMark& mark) { AddExceptionMark(address, mark); };
            const auto lastInstruction = [this](uint64 begin, uint64 end) { return LastInstructionOf(begin, end); };
            for (const auto& funclet : entry.exceptionFunclets) {
                if (!inCode(funclet.fileOffset))
                    continue;
                if (!funclet.isCatch) {
                    addFunclet(funclet.fileOffset, "$dtor$", unwinds);
                    continue;
                }
                DissasmCodeZone::ExceptionMark catchMark{ DissasmCodeZone::ExceptionMark::Kind::Catch, 0, std::nullopt, std::nullopt, funclet.catchType, false };
                for (const auto& [begin, end] : funclet.tryRanges) {
                    if (!inCode(begin) || end <= begin || !inCode(end - 1))
                        continue;
                    DissasmCodeZone::ExceptionMark mark{ DissasmCodeZone::ExceptionMark::Kind::CppTryBegin, begin - codeStart, std::nullopt, std::nullopt, {}, true };
                    addMark(mark.begin, mark);
                    if (const auto last = lastInstruction(mark.begin, end - codeStart); last.has_value()) {
                        mark.kind = DissasmCodeZone::ExceptionMark::Kind::TryEnd;
                        addMark(last.value(), mark);
                    }
                    if (!catchMark.owned) {
                        catchMark.begin = mark.begin;
                        catchMark.owned = true;
                    }
                }
                // the catch block of a try of another list without a range here (ARM64: a catch funclet has the FuncInfo of its function
                // too): the mark of the function that has the try; an owned mark replaces the one without an owner
                auto& marks = exceptionMarks[funclet.fileOffset - codeStart];
                const auto sameCatch = [&catchMark](const DissasmCodeZone::ExceptionMark& mark) {
                    return mark.kind == DissasmCodeZone::ExceptionMark::Kind::Catch && mark.catchType == catchMark.catchType;
                };
                if (catchMark.owned)
                    marks.erase(std::remove_if(marks.begin(), marks.end(), [&](const auto& mark) { return sameCatch(mark) && !mark.owned; }), marks.end());
                if (catchMark.owned || std::none_of(marks.begin(), marks.end(), sameCatch))
                    addMark(funclet.fileOffset - codeStart, catchMark);
                if (marks.empty())
                    exceptionMarks.erase(funclet.fileOffset - codeStart);
                addFunclet(funclet.fileOffset, "$catch$", catches);
            }
            for (const auto& scope : entry.exceptionScopes) {
                if (!inCode(scope.begin) || scope.end <= scope.begin || !inCode(scope.end - 1) || (scope.handler != 0 && !inCode(scope.handler)) ||
                    (scope.target != 0 && !inCode(scope.target)))
                    continue;
                DissasmCodeZone::ExceptionMark mark{ DissasmCodeZone::ExceptionMark::Kind::TryBegin, scope.begin - codeStart, std::nullopt, std::nullopt };
                if (scope.handler != 0)
                    mark.handler = scope.handler - codeStart;
                if (scope.target != 0)
                    mark.target = scope.target - codeStart;
                exceptionMarks[mark.begin].push_back(mark);
                if (const auto last = lastInstruction(mark.begin, scope.end - codeStart); last.has_value()) {
                    auto end = mark;
                    end.kind = DissasmCodeZone::ExceptionMark::Kind::TryEnd;
                    exceptionMarks[last.value()].push_back(end);
                }
                // the __except block (once: the scopes of a __try split by MSVC share it)
                if (mark.target.has_value()) {
                    auto& marks = exceptionMarks[mark.target.value()];
                    if (std::none_of(marks.begin(), marks.end(), [&mark](const auto& other) {
                            return other.kind == DissasmCodeZone::ExceptionMark::Kind::Except && other.handler == mark.handler;
                        })) {
                        auto handler = mark;
                        handler.kind = DissasmCodeZone::ExceptionMark::Kind::Except;
                        marks.push_back(handler);
                    }
                }
                if (scope.handler != 0)
                    addFunclet(scope.handler, scope.target != 0 ? "$filt$" : "$fin$", scope.target != 0 ? filters : finallies);
            }
        }
        // a funclet of a funclet (a try inside a catch block): it gets the establisher frame of the function of the outer one
        std::unordered_map<uint64, size_t> linkOfFunclet;
        for (size_t index = 0; index < funcletLinks.size(); index++)
            linkOfFunclet.emplace(funcletLinks[index].funclet, index);
        const auto links = funcletLinks;
        for (auto& link : funcletLinks) {
            for (uint32 depth = 0; depth < 8; depth++) {
                const auto outer = linkOfFunclet.find(link.parent);
                if (outer == linkOfFunclet.end() || links[outer->second].parent == link.parent)
                    break;
                const auto& outerLink = links[outer->second];
                link.parent           = outerLink.parent;
                link.prologSize       = outerLink.prologSize;
                link.frameRegister    = outerLink.frameRegister;
                link.frameOffset      = outerLink.frameOffset;
            }
            funcletsOfParent.emplace(link.parent, &link - funcletLinks.data());
        }
        // ARM64: a funclet of a funclet has the x29 of the top function
        for (auto& [funclet, parent] : arm64FuncletParents) {
            for (uint32 depth = 0; depth < 8; depth++) {
                const auto outer = arm64FuncletParents.find(parent);
                if (outer == arm64FuncletParents.end() || outer->second == parent || outer->first == funclet)
                    break;
                parent = outer->second;
            }
            arm64FuncletsOfParent.emplace(parent, funclet);
        }
    }

    // the establisher frame of a funclet in the offsets of the frame of its function: - the rsp of the entry (a frame without a frame
    // register: the rsp after the prologue), - rbp (a frame register function: the frame register - 16 * its offset); none when the frame
    // does not tell
    static std::optional<int64> EstablisherFrameDelta(const DissasmFunctionFrame& parent, const FuncletLink& link)
    {
        constexpr uint8 UNWIND_RBP = 5; // the number of rbp in the unwind data
        const uint64 prologEnd     = link.parent + link.prologSize;
        if (prologEnd >= parent.endAddress)
            return std::nullopt; // the frame ends before the prologue does: its depths there are not known
        if (link.frameRegister == 0 && !parent.usesFrameRegister)
            return parent.StackDeltaAt(prologEnd);
        if (link.frameRegister == UNWIND_RBP && parent.usesFrameRegister)
            return -16 * static_cast<int64>(link.frameOffset);
        if (link.frameRegister == UNWIND_RBP)
            for (const auto& alias : parent.stackAliases)
                if (alias.reg == "rbp" && !alias.frameOf.has_value() && alias.start <= prologEnd && prologEnd < alias.end)
                    return alias.delta - 16 * static_cast<int64>(link.frameOffset);
        return std::nullopt;
    }

    // the alias of the establisher frame in a funclet (mov rbp, rdx), its delta in the offsets of the frame of its function
    std::optional<DissasmFunctionFrame::StackAlias> FuncletAlias(const DissasmFunctionFrame& parent, const FuncletLink& link, Buffer& functionData)
    {
        const auto establisher = EstablisherFrameDelta(parent, link);
        if (!establisher.has_value() || link.funclet >= codeSize)
            return std::nullopt;
        const uint64 bytesToRead = std::min<uint64>(link.size > 0 ? link.size : codeSize - link.funclet, DISSASM_MAX_ANALYZED_FUNCTION_SIZE);
        functionData = obj->GetData().CopyToBuffer(codeStart + link.funclet, static_cast<uint32>(std::min<uint64>(bytesToRead, codeSize - link.funclet)), false);
        if (!functionData.IsValid())
            return std::nullopt;
        auto alias = FindX64EstablisherFrameAlias(detailHandle, functionData.GetData(), functionData.GetLength(), link.funclet);
        if (!alias.has_value() || alias->end <= alias->start)
            return std::nullopt;
        alias->delta   = static_cast<int32>(alias->delta + establisher.value());
        alias->frameOf = link.parent;
        return alias;
    }

    // the chunks of a function without a frame register (its cold code: the chained unwind data elsewhere): their stack from the depth of
    // its body (after its prologue), its callee saved aliases there (lea rbp, [rsp - 0x5f]); their slots are its variables. Their frames
    // (no variable of their own: DissasmFunctionFrame::variablesOf) join the frames in Commit
    void AddChunkFrames(DissasmFunctionFrame& frame, const DissasmFunctionEntry& entry)
    {
        const uint64 prologEnd = frame.startAddress + entry.prologSize;
        const auto bodyDelta   = frame.StackDeltaAt(prologEnd);
        if (!bodyDelta.has_value() || prologEnd >= frame.endAddress)
            return;
        std::vector<DissasmFunctionFrame::StackAlias> aliases;
        for (const auto& alias : frame.stackAliases)
            if (!alias.frameOf.has_value() && alias.start <= prologEnd && prologEnd < alias.end)
                aliases.push_back(alias);
        for (const auto& [chunkOffset, chunkSize] : entry.chunks) {
            if (chunkOffset < codeStart || chunkOffset - codeStart >= codeSize || chunkSize == 0)
                continue;
            const uint64 start = chunkOffset - codeStart;
            const uint64 size  = std::min<uint64>({ chunkSize, codeSize - start, DISSASM_MAX_ANALYZED_FUNCTION_SIZE });
            const auto bytes   = obj->GetData().CopyToBuffer(chunkOffset, static_cast<uint32>(size), false);
            if (!bytes.IsValid())
                continue;
            DissasmFunctionFrame chunkFrame{};
            if (!AnalyzeX64ChunkFrame(detailHandle, bytes.GetData(), bytes.GetLength(), start, start + size, bodyDelta.value(), aliases, chunkFrame,
                                      [this](const cs_insn& call) { return noReturnCalls.contains(call.address); }))
                continue;
            MergeFrameVariables(frame, std::move(chunkFrame.variables));
            chunkFrame.variables.clear();
            chunkFrame.variablesOf = frame.startAddress;
            pendingChunkFrames.push_back(std::move(chunkFrame));
        }
    }

    // the type of an object from its destructor: an API that frees it (PropVariantClear(&object): PROPVARIANT; CloseHandle(slot): HANDLE),
    // a C++ destructor (X::~X: X); empty when the name does not tell
    static std::string ObjectTypeFromDestructor(std::string_view destructor, bool isPointer)
    {
        static constexpr std::array<std::tuple<std::string_view, std::string_view, bool>, 13> DESTRUCTORS = { {
              { "PropVariantClear", "PROPVARIANT", false },     { "VariantClear", "VARIANT", false },
              { "DeleteCriticalSection", "CRITICAL_SECTION", false }, { "FreePropVariantArray", "PROPVARIANT", false },
              { "SysFreeString", "BSTR", true },               { "CloseHandle", "HANDLE", true },
              { "RegCloseKey", "HKEY", true },                 { "LocalFree", "HLOCAL", true },
              { "GlobalFree", "HGLOBAL", true },               { "CoTaskMemFree", "LPVOID", true },
              { "FreeLibrary", "HMODULE", true },              { "ILFree", "PIDLIST_ABSOLUTE", true },
              { "DestroyIcon", "HICON", true },
        } };
        std::string_view name = destructor;
        if (name.starts_with("j_"))
            name.remove_prefix(2); // the thunk of an import
        for (const auto& [function, type, pointer] : DESTRUCTORS)
            if (name == function && pointer == isPointer)
                return std::string(type);
        // public: __cdecl wil::unique_any_t<...>::~unique_any_t<...>(void): the class before ::~
        const auto tilde = name.find("::~");
        if (tilde == std::string_view::npos || isPointer)
            return {};
        std::string_view qualified = name.substr(0, tilde);
        int32 depth                = 0;
        for (size_t index = qualified.size(); index > 0; index--) { // the start of the qualified name: the last space outside < >
            const char c = qualified[index - 1];
            depth += c == '>' ? 1 : (c == '<' ? -1 : 0);
            if (c == ' ' && depth == 0) {
                qualified = qualified.substr(index);
                break;
            }
        }
        return std::string(qualified);
    }

    // x64 FH4: the objects the unwinding of the function destroys (Settings::AddExceptionObjects): their slots (from the establisher
    // frame) are variables, destroyed on unwind by their destructor (the origin of the variable), typed after it when it tells the type
    void AddExceptionObjects(DissasmFunctionFrame& frame, const DissasmFunctionEntry& entry)
    {
        const FuncletLink link{ 0, frame.startAddress, 0, entry.prologSize, entry.frameRegister, entry.frameOffset };
        const auto establisher = EstablisherFrameDelta(frame, link);
        if (!establisher.has_value())
            return;
        std::vector<DissasmLocalVariable> added;
        for (const auto& object : entry.exceptionObjects) {
            const int64 offset = establisher.value() + object.frameOffset;
            if (offset < INT32_MIN || offset > INT32_MAX || (offset >= 0 && offset < (frame.usesFrameRegister ? 16 : 8)))
                continue; // the return address (and the saved rbp)
            if (!frame.FindVariableContaining(static_cast<int32>(offset))) {
                DissasmLocalVariable variable{ static_cast<int32>(offset), static_cast<uint16>(object.isPointer ? 8 : 0), {} };
                FormatDefaultLocalVariableName(
                      frame.usesFrameRegister || offset < 8 ? static_cast<int32>(offset) : static_cast<int32>(offset) + 8, true, variable.name);
                added.push_back(std::move(variable));
            }
        }
        MergeFrameVariables(frame, std::move(added));
        for (const auto& object : entry.exceptionObjects) {
            const int64 offset = establisher.value() + object.frameOffset;
            auto* variable     = offset >= INT32_MIN && offset <= INT32_MAX ? frame.FindVariable(static_cast<int32>(offset)) : nullptr;
            if (!variable)
                continue;
            std::string destructor;
            if (object.destructor >= codeStart && object.destructor - codeStart < codeSize) {
                destructor = zone->GetLabelNameAt(object.destructor - codeStart);
                const auto call = std::lower_bound(
                      callsFound.begin(), callsFound.end(), object.destructor, [](const auto& item, uint64 value) { return item.first < value; });
                if (call != callsFound.end() && call->first == object.destructor)
                    destructor = call->second; // the names of this scan (the labels are placed after)
                if (destructor.empty())
                    destructor = zone->GetLabelName("sub_", object.destructor - codeStart);
            }
            if (destructor.empty())
                continue;
            // the unwinding tells more than the first C++ method the object is passed to / returned by (its type kept)
            const bool cxxOrigin = variable->origin.starts_with("this of ") ||
                                   (variable->origin.starts_with("returned by ") && variable->origin.find("::") != std::string::npos);
            if (variable->origin.empty() || cxxOrigin)
                variable->origin = "destroyed on unwind by " + destructor;
            if (const std::string type = ObjectTypeFromDestructor(destructor, object.isPointer); !type.empty() && variable->type.empty() && !variable->structure) {
                if (const auto* structure = FindApiStructure(type, true); structure && ApplyFrameStructure(frame, *variable, structure, false))
                    variable->type = structure->name;
                else
                    variable->type = type;
            }
        }
    }

    // the frames of the chunks (AddChunkFrames) among the frames (sorted, never overlapping)
    void MergeChunkFrames()
    {
        std::sort(pendingChunkFrames.begin(), pendingChunkFrames.end(), [](const auto& left, const auto& right) { return left.startAddress < right.startAddress; });
        const auto byStart = [](const DissasmFunctionFrame& frame, uint64 value) { return frame.startAddress < value; };
        for (auto& chunk : pendingChunkFrames) {
            const auto next = std::lower_bound(frames.begin(), frames.end(), chunk.startAddress, byStart);
            if ((next != frames.end() && next->startAddress < chunk.endAddress) || (next != frames.begin() && (next - 1)->endAddress > chunk.startAddress))
                continue;
            frames.insert(next, std::move(chunk));
        }
        pendingChunkFrames.clear();
    }

    // 32 bit MSVC: the code the exception handling runs with the ebp of the function (x86FuncletsOfParent): its slots are variables of the
    // frame; the code outside of the frame gets a frame of its own without variables, the ones of the function (variablesOf)
    void AddX86FuncletSlots(DissasmFunctionFrame& frame)
    {
        const bool sehRecord = std::any_of(frame.variables.begin(), frame.variables.end(), [](const auto& variable) { return variable.name.starts_with("ms_exc."); });
        const auto [first, last] = x86FuncletsOfParent.equal_range(frame.startAddress);
        for (auto it = first; it != last; ++it) {
            const uint64 start = it->second;
            const auto next    = std::upper_bound(functionStarts.begin(), functionStarts.end(), start);
            const uint64 limit = std::min<uint64>({ next != functionStarts.end() ? *next : codeSize, codeSize, start + DISSASM_MAX_ANALYZED_FUNCTION_SIZE });
            const auto bytes   = obj->GetData().CopyToBuffer(codeStart + start, static_cast<uint32>(limit - start), false);
            DissasmFunctionFrame funclet{};
            if (!bytes.IsValid() ||
                !AnalyzeX86FuncletFrame(detailHandle, bytes.GetData(), bytes.GetLength(), start, limit, false, sehRecord, funclet, [this](const cs_insn& call) {
                    return noReturnCalls.contains(call.address);
                }))
                continue;
            if (!MergeFrameVariables(frame, std::move(funclet.variables)))
                return; // too many
            funclet.variables.clear();
            if (start >= frame.startAddress && start < frame.endAddress)
                continue; // the walk of the function reached it: its frame
            funclet.variablesOf = frame.startAddress;
            pendingChunkFrames.push_back(std::move(funclet));
        }
    }

    // the cold chunks of a function (DetectColdBlocks): with a frame register, their slots through it are variables of the frame (the
    // listing finds the frame through the chunk); without one (x64), their stack from the depth of the body, as the chunks of its unwind data
    void AddColdChunkSlots(DissasmFunctionFrame& frame)
    {
        const auto [first, last] = coldChunksOf.equal_range(frame.startAddress);
        if (!frame.usesFrameRegister) {
            if (is64)
                for (auto it = first; it != last; ++it)
                    AddColdChunkFrame(frame, coldChunks[it->second]);
            return; // x86 without a frame register: no walk of a chunk from a depth
        }
        for (auto it = first; it != last; ++it) {
            const auto& chunk = coldChunks[it->second];
            const auto bytes  = obj->GetData().CopyToBuffer(
                  codeStart + chunk.start, static_cast<uint32>(std::min<uint64>(chunk.end - chunk.start, DISSASM_MAX_ANALYZED_FUNCTION_SIZE)), false);
            if (!bytes.IsValid())
                continue;
            // its blocks one after the other (the walk ends with the path of each)
            for (uint64 start = chunk.start; start < chunk.start + bytes.GetLength();) {
                DissasmFunctionFrame walked{};
                const uint64 offset = start - chunk.start;
                if (!AnalyzeX86FuncletFrame(
                          detailHandle,
                          bytes.GetData() + offset,
                          bytes.GetLength() - offset,
                          start,
                          chunk.start + bytes.GetLength(),
                          is64,
                          false,
                          walked,
                          [this](const cs_insn& call) { return noReturnCalls.contains(call.address); }) ||
                    walked.endAddress <= start)
                    break;
                if (!MergeFrameVariables(frame, std::move(walked.variables)))
                    return; // too many
                start = walked.endAddress;
            }
            // the listing: the variables of the function there (a code location is no chunk of it); its stack pointer from the depth at a
            // jump of the body when the function follows it (the locals of an aligned frame through esp: [esp + 0x28 + var_18])
            DissasmFunctionFrame part{};
            const auto entry = ColdChunkEntry(frame, chunk);
            if (entry.has_value() && !frame.stackDeltas.empty() && frame.stackDeltas.front().first == frame.startAddress) {
                const int32 base = frame.stackDeltas.front().second; // the stack pointer of the entry - the frame register
                if (AnalyzeFrameRegisterChunk(
                          detailHandle,
                          bytes.GetData(),
                          bytes.GetLength(),
                          chunk.start,
                          chunk.start + bytes.GetLength(),
                          is64,
                          entry->second - base,
                          -base,
                          part,
                          is64 ? X86CalleeStackPurge{} : X86CalleeStackPurge([this](const cs_insn& call) { return CalleeStackPurge(call); }),
                          [this](const cs_insn& call) { return noReturnCalls.contains(call.address); })) {
                    if (!MergeFrameVariables(frame, std::move(part.variables)))
                        return; // too many
                    part.variables.clear();
                    part.alignedStack = frame.alignedStack;
                } else
                    part = {};
            }
            part.startAddress = chunk.start;
            part.endAddress   = chunk.end;
            part.variablesOf  = frame.startAddress;
            pendingChunkFrames.push_back(std::move(part));
        }
    }

    // the jump of the body of a function to the start of its cold chunk, the depth of the stack there (the stack pointer of the entry, or the
    // frame register after MergeStackPointerSlots); none when only another cold block reaches it or the depth is not known
    std::optional<std::pair<uint64, int32>> ColdChunkEntry(const DissasmFunctionFrame& frame, const DissasmFunctionChunk& chunk) const
    {
        auto xref = std::lower_bound(
              xrefs.byTarget.begin(), xrefs.byTarget.end(), labelBase + chunk.start, [](const auto& item, uint64 value) { return item.to < value; });
        for (; xref != xrefs.byTarget.end() && xref->to == labelBase + chunk.start; ++xref)
            if (xref->from >= labelBase + frame.startAddress && xref->from < labelBase + frame.endAddress)
                if (const auto delta = frame.StackDeltaAt(xref->from - labelBase); delta.has_value())
                    return std::pair<uint64, int32>(xref->from - labelBase, delta.value());
        return std::nullopt;
    }

    // x64 without a frame register: a cold chunk from the depth of the stack (and the callee saved aliases) at a jump of the function to it;
    // its slots are variables of the frame, its own frame has the variables of the function (variablesOf)
    void AddColdChunkFrame(DissasmFunctionFrame& frame, const DissasmFunctionChunk& chunk)
    {
        const auto entry = ColdChunkEntry(frame, chunk);
        if (!entry.has_value())
            return; // reached from another cold block only, or with a depth not known
        const auto [source, entryDelta] = entry.value();
        std::vector<DissasmFunctionFrame::StackAlias> aliases;
        for (const auto& alias : frame.stackAliases)
            if (!alias.frameOf.has_value() && alias.start <= source && source < alias.end)
                aliases.push_back(alias);
        const uint64 size = std::min<uint64>(chunk.end - chunk.start, DISSASM_MAX_ANALYZED_FUNCTION_SIZE);
        const auto bytes  = obj->GetData().CopyToBuffer(codeStart + chunk.start, static_cast<uint32>(size), false);
        DissasmFunctionFrame chunkFrame{};
        if (!bytes.IsValid() || !AnalyzeX64ChunkFrame(
                                      detailHandle,
                                      bytes.GetData(),
                                      bytes.GetLength(),
                                      chunk.start,
                                      chunk.start + size,
                                      entryDelta,
                                      aliases,
                                      chunkFrame,
                                      [this](const cs_insn& call) { return noReturnCalls.contains(call.address); }))
            return;
        MergeFrameVariables(frame, std::move(chunkFrame.variables));
        chunkFrame.variables.clear();
        chunkFrame.variablesOf = frame.startAddress;
        pendingChunkFrames.push_back(std::move(chunkFrame));
    }

    // ARM64: the slots the funclets of the function use through x29 (its frame: sub_X$dtor$0: ldr w8, [x29, #0x10]) are variables of its
    // frame (AddArm64FuncletSlots of DissasmX86LocalVariables)
    void AddArm64FuncletSlots(DissasmFunctionFrame& frame)
    {
        constexpr uint32 MAX_FUNCLET_SIZE = 0x1000;
        if (!frame.usesFrameRegister)
            return;
        const auto [first, last] = arm64FuncletsOfParent.equal_range(frame.startAddress);
        for (auto it = first; it != last; ++it) {
            const uint64 funclet = it->second;
            if (funclet >= codeSize)
                continue;
            const auto bytes =
                  obj->GetData().CopyToBuffer(codeStart + funclet, static_cast<uint32>(std::min<uint64>(codeSize - funclet, MAX_FUNCLET_SIZE)), false);
            if (bytes.IsValid() && !GView::View::DissasmViewer::AddArm64FuncletSlots(detailHandle, bytes.GetData(), bytes.GetLength(), funclet, frame))
                return;
        }
    }

    // ARM64: the cold chunks of the function (DetectColdBlocks: MSVC's separated cold code) run on its frame at the depth of its body: their
    // slots are variables of the frame (AddArm64ChunkSlots of DissasmX86LocalVariables)
    void AddArm64ColdChunkSlots(DissasmFunctionFrame& frame)
    {
        const auto [first, last] = coldChunksOf.equal_range(frame.startAddress);
        const auto movesStack    = [this](const cs_insn& call) {
            const auto helper = stackHelperCalls.find(call.address);
            return helper != stackHelperCalls.end() && helper->second != 0;
        };
        for (auto it = first; it != last; ++it) {
            const auto& chunk = coldChunks[it->second];
            const auto bytes  = obj->GetData().CopyToBuffer(
                  codeStart + chunk.start, static_cast<uint32>(std::min<uint64>(chunk.end - chunk.start, DISSASM_MAX_ANALYZED_FUNCTION_SIZE)), false);
            if (bytes.IsValid() &&
                !GView::View::DissasmViewer::AddArm64ChunkSlots(detailHandle, bytes.GetData(), bytes.GetLength(), chunk.start, frame, movesStack))
                return;
        }
    }

    // ARM64EC: the thunks between the ARM64EC code and the x64 code, named by the pointer of the emulator they go through (a stripped image
    // has no name for them; MSVC's are $iexit_thunk$cdecl$<signature> / $ientry_thunk$cdecl$<signature>):
    // - an exit thunk (exit_thunk_N): the call of x64 code, blr __os_arm64x_dispatch_call_no_redirect after the arguments moved to the x64
    //   convention; its address goes in x10 to every check of an indirect call (DbgHelp sub_1803447B0: 5862 checks, d3dcompiler 1414)
    // - an entry thunk (entry_thunk_N): the call of an ARM64EC function by x64 code, br __os_arm64x_dispatch_ret at its end
    // The function is the start before the call (a few instructions: the thunks are short), with an automatic name (sub_)
    void NameArm64ECThunks()
    {
        constexpr uint64 MAX_THUNK_BYTES = 0x100;
        if (arm64ECThunkCalls.empty())
            return;
        std::unordered_set<std::string> usedNames;
        for (const auto& call : callsFound)
            if (GetLabelType(call.second) != SUB)
                usedNames.insert(call.second);
        std::unordered_set<uint64> named;
        uint32 exits = 0, entries = 0;
        for (const auto& [address, isExit] : arm64ECThunkCalls) {
            // the last start before the call, past the labels inside the function
            auto call = std::upper_bound(
                  callsFound.begin(), callsFound.end(), codeStart + address, [](uint64 value, const auto& item) { return value < item.first; });
            while (call != callsFound.begin() && GetLabelType(std::prev(call)->second) == OFFSET)
                --call;
            if (call == callsFound.begin())
                continue;
            --call;
            if (GetLabelType(call->second) != SUB || codeStart + address - call->first > MAX_THUNK_BYTES || call->first == zone->zoneDetails.entryPoint ||
                !named.insert(call->first).second)
                continue;
            std::string name;
            do
                name = std::string(isExit ? "exit_thunk_" : "entry_thunk_") + std::to_string(isExit ? ++exits : ++entries);
            while (usedNames.contains(name) && (isExit ? exits : entries) < 100000);
            if (usedNames.insert(name).second)
                call->second = std::move(name);
        }
    }

    // MSVC /GS: the functions of the run-time that check the stack cookie, named by their code (a stripped image has no symbol for them; IDA
    // names them by its signatures): their first instructions compare the cookie (__security_cookie, the variable of the load config the
    // plugin names) with the cookie of the frame
    // - x64: cmp rcx, [__security_cookie]; jne; rol rcx, 0x10; test cx, 0xffff; jne; ret: __security_check_cookie (rcx)
    // - x86: cmp ecx, [__security_cookie]; jne; ret: @__security_check_cookie@4 (__fastcall: ecx, so no prototype of pushes)
    // - ARM64: the cookie loaded (adrp; ldr / add, ldr), cmp x0 with it; b.ne; ret: __security_check_cookie (x0); the cookie of the frame read
    //   at [sp, #8], its difference with sp compared; b.ne; add sp, sp, #0x10; ret: __security_pop_cookie; sub sp, sp, #0x10, the cookie loaded,
    //   its difference with sp stored at [sp, #8]; ret (no branch): __security_push_cookie (DbgHelp 1046 calls, d3dcompiler 1405)
    // Only a function with an automatic name (sub_), a name not given yet
    void NameSecurityCookieFunctions()
    {
        constexpr uint32 CHECK_BYTES      = 48;
        constexpr size_t MAX_INSTRUCTIONS = 10;
        if (!findImport || handle == 0 || zone->IsArm32Code())
            return;
        const bool isArm64 = zone->IsArm64Code();
        std::vector<size_t> candidates; // indexes in callsFound
        for (size_t index = 0; index < callsFound.size(); index++) {
            const auto& [fileOffset, name] = callsFound[index];
            if (fileOffset < codeStart || fileOffset - codeStart >= codeSize || GetLabelType(name) != SUB)
                continue;
            const uint64 start = fileOffset - codeStart;
            if (zone->GetArchAt(start) != arch)
                continue; // the x64 code of an ARM64X image
            // the first bytes: cmp rcx, [rip + n] (48 3B 0D), cmp ecx, [n] (3B 0D); ARM64: an adrp, sub sp, sp, #0x10 (FF 43 00 D1: the push)
            const auto head = obj->GetData().Get(fileOffset, 4, false);
            if (!head.IsValid() || head.GetLength() < 4)
                continue;
            const uint8* b      = head.GetData();
            const bool subsSp16 = b[0] == 0xFF && b[1] == 0x43 && b[2] == 0x00 && b[3] == 0xD1;
            const bool matches =
                  isArm64 ? (b[3] & 0x9F) == 0x90 || subsSp16 : (is64 ? b[0] == 0x48 && b[1] == 0x3B && b[2] == 0x0D : b[0] == 0x3B && b[1] == 0x0D);
            if (matches)
                candidates.push_back(index);
        }
        if (candidates.empty())
            return;
        std::unordered_set<std::string> usedNames;
        for (const auto& call : callsFound)
            if (GetLabelType(call.second) != SUB)
                usedNames.insert(call.second);
        const auto readsCookie = [this](const cs_insn& insn) {
            auto operands = GetInstructionOperands(insn, arch, labelBase);
            if (const auto resolved = resolvedAddresses.find(insn.address); resolved != resolvedAddresses.end())
                operands.ripTarget = resolved->second; // ARM64: the adrp pair
            const auto* mapping = findImport(operands);
            return mapping && std::string_view(mapping->name).starts_with("__security_cookie"); // the x64 view of an ARM64X image: _x64
        };
        for (const size_t index : candidates) {
            const uint64 start = callsFound[index].first - codeStart;
            const auto data = obj->GetData().CopyToBuffer(callsFound[index].first, static_cast<uint32>(std::min<uint64>(codeSize - start, CHECK_BYTES)), false);
            if (!data.IsValid())
                continue;
            cs_insn* decoded   = nullptr;
            const size_t count = cs_disasm(handle, data.GetData(), data.GetLength(), start, MAX_INSTRUCTIONS, &decoded);
            std::string_view name;
            if (count > 0 && !isArm64) {
                const auto& first   = *decoded[0].detail;
                const x86_reg reg   = is64 ? X86_REG_RCX : X86_REG_ECX;
                const bool compares = decoded[0].id == X86_INS_CMP && first.x86.op_count == 2 && first.x86.operands[0].type == X86_OP_REG &&
                                      first.x86.operands[0].reg == reg && first.x86.operands[1].type == X86_OP_MEM && readsCookie(decoded[0]);
                if (compares && count >= 3 && decoded[1].id == X86_INS_JNE) {
                    if (!is64 && decoded[2].id == X86_INS_RET)
                        name = "@__security_check_cookie@4";
                    else if (
                          is64 && decoded[2].id == X86_INS_ROL && decoded[2].detail->x86.op_count == 2 &&
                          decoded[2].detail->x86.operands[0].type == X86_OP_REG && decoded[2].detail->x86.operands[0].reg == X86_REG_RCX &&
                          decoded[2].detail->x86.operands[1].type == X86_OP_IMM && decoded[2].detail->x86.operands[1].imm == 0x10)
                        for (size_t position = 3; position < count && position < 6; position++) {
                            if (decoded[position].id == X86_INS_RET) {
                                name = "__security_check_cookie";
                                break;
                            }
                            if (decoded[position].id != X86_INS_TEST && decoded[position].id != X86_INS_JNE)
                                break;
                        }
                }
            } else if (count > 0) {
                // up to the first ret: the cookie read, one b.ne after the cmp, nothing else that branches
                bool cookie = false, framed = false, stored = false, valid = true;
                std::optional<size_t> branch;
                size_t ret = count;
                for (size_t position = 0; position < count && valid; position++) {
                    const cs_insn& insn   = decoded[position];
                    const cs_arm64& arm64 = insn.detail->arm64;
                    if (insn.id == ARM64_INS_RET) {
                        ret = position;
                        break;
                    }
                    if (insn.id == ARM64_INS_B && arm64.cc == ARM64_CC_NE && !branch.has_value() && position > 0 && decoded[position - 1].id == ARM64_INS_CMP)
                        branch = position;
                    else if (
                          insn.id == ARM64_INS_B || insn.id == ARM64_INS_BL || insn.id == ARM64_INS_BR || insn.id == ARM64_INS_BLR ||
                          insn.id == ARM64_INS_CBZ || insn.id == ARM64_INS_CBNZ || insn.id == ARM64_INS_TBZ || insn.id == ARM64_INS_TBNZ)
                        valid = false;
                    cookie = cookie || readsCookie(insn);
                    // ldr x16, [sp, #8]: the cookie the push stored; str x17, [sp, #8]: the push
                    framed = framed || (insn.id == ARM64_INS_LDR && arm64.op_count == 2 && arm64.operands[1].type == ARM64_OP_MEM &&
                                        arm64.operands[1].mem.base == ARM64_REG_SP && arm64.operands[1].mem.disp == 8);
                    stored = stored || (insn.id == ARM64_INS_STR && arm64.op_count == 2 && arm64.operands[1].type == ARM64_OP_MEM &&
                                        arm64.operands[1].mem.base == ARM64_REG_SP && arm64.operands[1].mem.disp == 8);
                }
                const cs_arm64& firstOps = decoded[0].detail->arm64;
                const bool movesSp       = decoded[0].id == ARM64_INS_SUB && firstOps.op_count == 3 && firstOps.operands[0].type == ARM64_OP_REG &&
                                     firstOps.operands[0].reg == ARM64_REG_SP && firstOps.operands[1].type == ARM64_OP_REG &&
                                     firstOps.operands[1].reg == ARM64_REG_SP && firstOps.operands[2].type == ARM64_OP_IMM && firstOps.operands[2].imm == 0x10;
                if (valid && cookie && movesSp && stored && !branch.has_value() && ret < count)
                    name = "__security_push_cookie";
                if (valid && cookie && branch.has_value() && ret < count) {
                    const cs_arm64& compared = decoded[branch.value() - 1].detail->arm64;
                    const cs_insn& last      = decoded[ret - 1];
                    const cs_arm64& lastOps  = last.detail->arm64;
                    if (ret == branch.value() + 1 && compared.op_count == 2 && compared.operands[0].type == ARM64_OP_REG &&
                        compared.operands[0].reg == ARM64_REG_X0)
                        name = "__security_check_cookie";
                    else if (
                          framed && ret == branch.value() + 2 && last.id == ARM64_INS_ADD && lastOps.op_count == 3 &&
                          lastOps.operands[0].type == ARM64_OP_REG && lastOps.operands[0].reg == ARM64_REG_SP && lastOps.operands[1].type == ARM64_OP_REG &&
                          lastOps.operands[1].reg == ARM64_REG_SP && lastOps.operands[2].type == ARM64_OP_IMM && lastOps.operands[2].imm == 0x10)
                        name = "__security_pop_cookie";
                }
            }
            if (count > 0)
                cs_free(decoded, count);
            if (!name.empty() && usedNames.insert(std::string(name)).second)
                callsFound[index].second = std::string(name);
        }
    }

    // the functions of the run-time linked statically, named by the first bytes of their code (a driver has no symbol for its memset; IDA names
    // them by its signatures): the bytes are those of the run-time itself, exact (a start with an automatic name only, a name given once)
    // - x64 memset of the CRT of the WDK: mov rax, rcx; movzx edx, dl; mov r9, 0x0101010101010101; imul rdx, r9 (405 of the 495 drivers of a
    //   Windows 11; ntfs 1004 calls)
    // - x64 memcpy (memmove, the same code): mov rax, rcx; cmp r8, 8; jb; cmp r8, 0x10; ja; mov r11, [rdx]; mov rdx, [rdx + r8 - 8]; mov [rcx],
    //   r11; mov [rcx + r8 - 8], rdx; ret (410 drivers, 28 DLLs; ntfs 629 calls)
    // - x64 RtlULongAdd / RtlULongLongAdd of ntintsafe.h (a function when not inlined; the ULONG / UINT / DWORD ones fold into one): lea eax,
    //   [rcx + rdx]; mov edx, -1; cmp eax, ecx; cmovae edx, eax; sbb eax, eax; and eax, STATUS_INTEGER_OVERFLOW; mov [r8], edx; ret (shell32
    //   2509 + 1910 calls, 17 other DLLs)
    void NameRunTimeFunctionsByCode()
    {
        struct RunTimeCode {
            DissasmArch arch;
            std::string_view name;
            std::span<const uint8> bytes;
        };
        static constexpr uint8 MEMSET_X64[]        = { 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0xD2, 0x49, 0xB9, 0x01, 0x01,
                                                       0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x49, 0x0F, 0xAF, 0xD1 };
        static constexpr uint8 MEMCPY_X64[]        = { 0x48, 0x8B, 0xC1, 0x49, 0x83, 0xF8, 0x08, 0x72, 0x37, 0x49, 0x83, 0xF8, 0x10, 0x77, 0x11, 0x4C,
                                                       0x8B, 0x1A, 0x4A, 0x8B, 0x54, 0x02, 0xF8, 0x4C, 0x89, 0x19, 0x4A, 0x89, 0x54, 0x01, 0xF8, 0xC3 };
        static constexpr uint8 ULONG_ADD_X64[]     = { 0x8D, 0x04, 0x11, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0x3B, 0xC1, 0x0F, 0x43,
                                                       0xD0, 0x1B, 0xC0, 0x25, 0x95, 0x00, 0x00, 0xC0, 0x41, 0x89, 0x10, 0xC3 };
        static constexpr uint8 ULONGLONG_ADD_X64[] = { 0x48, 0x8D, 0x04, 0x11, 0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x3B, 0xC1, 0x48,
                                                       0x0F, 0x43, 0xD0, 0x1B, 0xC0, 0x25, 0x95, 0x00, 0x00, 0xC0, 0x49, 0x89, 0x10, 0xC3 };

        static const RunTimeCode codes[] = {
            { DissasmArch::X64, "memset", MEMSET_X64 },
            { DissasmArch::X64, "memcpy", MEMCPY_X64 },
            { DissasmArch::X64, "RtlULongAdd", ULONG_ADD_X64 },
            { DissasmArch::X64, "RtlULongLongAdd", ULONGLONG_ADD_X64 },
        };
        constexpr uint32 MAX_BYTES = 32;
        if (arch != DissasmArch::X64 && !zone->IsArm64Code())
            return; // the table has x64 code only (an ARM64X zone has x64 ranges)
        std::unordered_set<std::string> usedNames;
        bool namesRead = false;
        for (auto& call : callsFound) {
            if (call.first < codeStart || call.first - codeStart >= codeSize || GetLabelType(call.second) != SUB)
                continue;
            const uint64 start          = call.first - codeStart;
            const DissasmArch startArch = zone->GetArchAt(start);
            const uint32 length         = static_cast<uint32>(std::min<uint64>(codeSize - start, MAX_BYTES));
            std::optional<BufferView> view;
            for (const auto& code : codes) {
                if (code.arch != startArch || code.bytes.size() > length)
                    continue;
                if (!view.has_value())
                    view = obj->GetData().Get(call.first, length, false);
                if (!view->IsValid() || view->GetLength() < code.bytes.size() || memcmp(view->GetData(), code.bytes.data(), code.bytes.size()) != 0)
                    continue;
                if (!namesRead) {
                    for (const auto& other : callsFound)
                        if (GetLabelType(other.second) != SUB)
                            usedNames.insert(other.second);
                    namesRead = true;
                }
                if (usedNames.insert(std::string(code.name)).second)
                    call.second = std::string(code.name);
                break;
            }
        }
    }

    // ARM64: the helpers of the zone that keep the registers of their caller and may move its sp (Arm64HelperStackChange: the cookie helpers
    // of MSVC /GS, __chkstk), the calls to them (stackHelperCalls); read once per callee before the frames (a read through the cache during
    // the walk of a frame would invalidate the bytes of its function)
    void FindArm64StackHelpers()
    {
        constexpr uint32 HELPER_BYTES = 64; // 16 instructions
        stackHelperCalls.clear();
        if (!hasDetailHandle || !zone->IsArm64Code())
            return;
        std::unordered_map<uint64, std::optional<int32>> changes; // by callee
        for (const auto& record : flowRecords) {
            if (record.kind != FlowKind::Call || record.target == NO_TARGET || record.target >= codeSize)
                continue;
            auto known = changes.find(record.target);
            if (known == changes.end()) {
                const auto bytes =
                      obj->GetData().Get(codeStart + record.target, static_cast<uint32>(std::min<uint64>(codeSize - record.target, HELPER_BYTES)), false);
                known = changes
                              .emplace(
                                    record.target,
                                    bytes.IsValid() ? Arm64HelperStackChange(detailHandle, bytes.GetData(), bytes.GetLength(), record.target) : std::nullopt)
                              .first;
            }
            if (known->second.has_value())
                stackHelperCalls.emplace(record.address, known->second.value());
        }
    }

    // ARM64: the frames of the funclets name their x29 slots with the variables of their function (DissasmFunctionFrame::frameRegisterOf);
    // a funclet without a frame of its own gets one (no slot of its own)
    void LinkArm64FuncletFrames()
    {
        const auto byStart = [](const DissasmFunctionFrame& frame, uint64 value) { return frame.startAddress < value; };
        for (const auto& [funclet, parent] : arm64FuncletParents) {
            const auto parentFrame = std::lower_bound(frames.begin(), frames.end(), parent, byStart);
            if (parentFrame == frames.end() || parentFrame->startAddress != parent || !parentFrame->usesFrameRegister)
                continue;
            auto funcletFrame = std::lower_bound(frames.begin(), frames.end(), funclet, byStart);
            if (funcletFrame != frames.end() && funcletFrame->startAddress == funclet) {
                funcletFrame->frameRegisterOf = parent;
                continue;
            }
            const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), funclet);
            if (next == functionStarts.begin() || *(next - 1) != funclet || functionEnds.size() != functionStarts.size())
                continue;
            const uint64 end = functionEnds[static_cast<size_t>(next - functionStarts.begin()) - 1];
            if ((funcletFrame != frames.end() && funcletFrame->startAddress < end) ||
                (funcletFrame != frames.begin() && (funcletFrame - 1)->endAddress > funclet))
                continue; // the ranges of the frames never overlap
            DissasmFunctionFrame frame{};
            frame.startAddress      = funclet;
            frame.endAddress        = end;
            frame.usesFrameRegister = false;
            frame.frameRegisterOf   = parent;
            frames.insert(funcletFrame, std::move(frame));
        }
    }

    // the slots the funclets of the function use (through the establisher frame) are variables of its frame
    void AddFuncletSlots(DissasmFunctionFrame& frame)
    {
        const auto [first, last] = funcletsOfParent.equal_range(frame.startAddress);
        for (auto it = first; it != last; ++it) {
            Buffer functionData;
            if (const auto alias = FuncletAlias(frame, funcletLinks[it->second], functionData); alias.has_value())
                AddX64FuncletSlots(detailHandle, functionData.GetData(), functionData.GetLength(), funcletLinks[it->second].funclet, alias.value(), frame);
        }
    }

    // the funclets of x64 SEH (a filter / a __finally gets the establisher frame of its function in rdx: mov rbp, rdx / lea rbp, [rdx + 0x20]):
    // rbp is an alias of the frame of the function there, its slots are the variables of the function (sub_X$fin$0: mov rcx, qword ptr
    // [rbp + 0x98 + var_68]). The establisher frame: the rsp after the prologue (no frame register), the frame register - 16 * its offset
    void LinkFuncletFrames()
    {
        if (!hasDetailHandle || funcletLinks.empty())
            return;
        const auto byStart = [](const DissasmFunctionFrame& frame, uint64 value) { return frame.startAddress < value; };
        for (const auto& link : funcletLinks) {
            const auto parent = std::lower_bound(frames.begin(), frames.end(), link.parent, byStart);
            if (parent == frames.end() || parent->startAddress != link.parent)
                continue;
            Buffer functionData;
            auto alias = FuncletAlias(*parent, link, functionData);
            if (!alias.has_value())
                continue;
            // the frame of the funclet: the one of its own slots, or one for the alias (a funclet without slots of its own)
            auto funcletFrame = std::lower_bound(frames.begin(), frames.end(), link.funclet, byStart);
            if (funcletFrame != frames.end() && funcletFrame->startAddress == link.funclet) {
                if (!funcletFrame->usesFrameRegister)
                    funcletFrame->stackAliases.push_back(std::move(alias.value()));
                continue;
            }
            if ((funcletFrame != frames.end() && funcletFrame->startAddress < alias->end) ||
                (funcletFrame != frames.begin() && (funcletFrame - 1)->endAddress > link.funclet))
                continue; // the ranges of the frames never overlap
            DissasmFunctionFrame frame{};
            frame.startAddress      = link.funclet;
            frame.endAddress        = alias->end;
            frame.usesFrameRegister = false;
            frame.stackAliases.push_back(std::move(alias.value()));
            frames.insert(funcletFrame, std::move(frame));
        }
    }

    // 32 bit: the bytes popped by an import: its decorated name (_CreateFileA@28), cdecl (0) for the C run-time (lowercase names: free,
    // memset, _wcsicmp) and the variadic functions of the Windows API; none for the other names (the Windows API is stdcall: CamelCase
    // names, and winsock)
    std::optional<uint32> ImportStackPurge(const X86OperandsInfo& operands) const
    {
        static constexpr std::array<std::string_view, 39> STDCALL_LOWERCASE_NAMES = {
            "accept",       "bind",          "closesocket",   "connect",          "freeaddrinfo",     "getaddrinfo",    "gethostbyaddr",
            "gethostbyname", "gethostname",  "getnameinfo",   "getpeername",      "getprotobyname",   "getprotobynumber", "getservbyname",
            "getservbyport", "getsockname",  "getsockopt",    "htonl",            "htons",            "inet_addr",      "inet_ntoa",
            "inet_ntop",    "inet_pton",     "ioctlsocket",   "listen",           "ntohl",            "ntohs",          "recv",
            "recvfrom",     "select",        "send",          "sendto",           "setsockopt",       "shutdown",       "socket",
            "freehostent",  "getipnodebyname", "gai_strerrora", "gai_strerrorw",
        };
        const auto* import = findImport ? findImport(operands) : nullptr;
        if (!import || import->type != MemoryMappingType::FunctionMapping || import->name.empty())
            return std::nullopt;
        const std::string& name = import->name;
        const auto at           = name.rfind('@');
        if (at != std::string::npos && at > 0 && at + 1 < name.size() && at + 4 >= name.size() &&
            std::all_of(name.begin() + at + 1, name.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }))
            return static_cast<uint32>(std::stoul(name.substr(at + 1)));
        if (name.find("__cdecl") != std::string::npos || name == "wsprintfA" || name == "wsprintfW" || name == "DbgPrint" || name == "DbgPrintEx")
            return 0u; // a demangled name with its convention (void * __cdecl operator new(unsigned int)), the variadic APIs
        const bool lowercase = std::all_of(name.begin(), name.end(), [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
        if (lowercase && std::find(STDCALL_LOWERCASE_NAMES.begin(), STDCALL_LOWERCASE_NAMES.end(), name) == STDCALL_LOWERCASE_NAMES.end())
            return 0u;
        return std::nullopt;
    }

    // 32 bit: the bytes a function of the zone pops from its caller's stack: its first ret (ret 8 -> 8), decoded from its start up to the
    // next function (the code after a jmp that a forward branch passes is the rest of the function); a jmp at the start (a thunk: jmp
    // [__imp_X] / jmp sub_X) or past every forward branch (a tail call) gives what the jumped to function pops. None when no ret is found
    // or the function moves esp otherwise (__chkstk: xchg eax, esp)
    std::optional<uint32> DecodeCalleePurge(uint64 target, bool followThunk = true)
    {
        constexpr uint64 MAX_CALLEE_SIZE = 0x10000;
        const auto nextFunction          = std::upper_bound(functionStarts.begin(), functionStarts.end(), target);
        const uint64 end                 = std::min<uint64>({ codeSize, target + MAX_CALLEE_SIZE, nextFunction != functionStarts.end() ? *nextFunction : codeSize });
        const auto calleeData            = obj->GetData().Get(codeStart + target, static_cast<uint32>(end - target), false);
        cs_insn* calleeInsn              = calleeData.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!calleeInsn)
            return std::nullopt;
        const uint8* data = calleeData.GetData();
        size_t size       = calleeData.GetLength();
        uint64 address    = target;
        std::optional<uint32> result;
        std::optional<uint64> thunkTarget;
        uint64 furthestBranchTarget = 0;
        while (cs_disasm_iter(detailHandle, &data, &size, &address, calleeInsn)) {
            const cs_x86& x86 = calleeInsn->detail->x86;
            if (cs_insn_group(detailHandle, calleeInsn, CS_GRP_JUMP) && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM &&
                static_cast<uint64>(x86.operands[0].imm) > calleeInsn->address)
                furthestBranchTarget = std::max(furthestBranchTarget, static_cast<uint64>(x86.operands[0].imm));
            // a jmp at the start (a thunk) or past every forward branch (a tail call: the callee pops what the jumped to function pops)
            if (calleeInsn->id == X86_INS_JMP && (calleeInsn->address == target || furthestBranchTarget < calleeInsn->address + calleeInsn->size)) {
                const auto operands = zone->GetOperandsInfo(*calleeInsn);
                if (operands.absoluteMemory.has_value())
                    result = ImportStackPurge(operands); // jmp [__imp_X]
                else if (operands.directTarget.has_value() && followThunk)
                    thunkTarget = operands.directTarget; // jmp sub_X
                break;
            }
            // the stack pointer written otherwise than by push / pop / sub / add / and esp, imm / lea / leave / mov esp, ebp
            bool movesStack = false;
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE) &&
                    (x86.operands[index].reg == X86_REG_ESP || x86.operands[index].reg == X86_REG_SP))
                    movesStack = true;
            const bool restoresFrame = calleeInsn->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[1].type == X86_OP_REG && x86.operands[1].reg == X86_REG_EBP;
            const bool immediateChange = (calleeInsn->id == X86_INS_SUB || calleeInsn->id == X86_INS_ADD || calleeInsn->id == X86_INS_AND) &&
                                         x86.op_count == 2 && x86.operands[1].type == X86_OP_IMM;
            if (movesStack && !restoresFrame && !immediateChange && calleeInsn->id != X86_INS_LEA && calleeInsn->id != X86_INS_LEAVE)
                break; // xchg eax, esp / mov esp, eax: not a plain function
            if (calleeInsn->id == X86_INS_RET) {
                result = x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM ? static_cast<uint32>(x86.operands[0].imm) : 0u;
                break;
            }
        }
        cs_free(calleeInsn, 1);
        if (thunkTarget.has_value() && thunkTarget.value() < codeSize && thunkTarget.value() != target)
            return DecodeCalleePurge(thunkTarget.value(), false);
        return result;
    }

    // 32 bit: a function that reads nothing of the stack (no [esp + n] / [ebp + n] operand, no frame register) in its code (up to the next
    // function, 4 KB at most): it takes no argument from the stack, whatever its ret (a __fastcall leaf with ecx / edx)
    bool TakesNoStackArguments(uint64 start)
    {
        const auto nextFunction = std::upper_bound(functionStarts.begin(), functionStarts.end(), start);
        const uint64 end        = std::min<uint64>({ codeSize, start + 0x1000, nextFunction != functionStarts.end() ? *nextFunction : codeSize });
        const auto data         = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(end - start), false) : BufferView{};
        cs_insn* insn           = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return false;
        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = start;
        bool usesStack     = false;
        while (!usesStack && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
            const cs_x86& x86 = insn->detail->x86;
            for (uint8 index = 0; index < x86.op_count && !usesStack; index++) {
                const auto& op = x86.operands[index];
                usesStack      = (op.type == X86_OP_MEM && (op.mem.base == X86_REG_ESP || op.mem.base == X86_REG_EBP)) ||
                            (op.type == X86_OP_REG && op.reg == X86_REG_EBP && (op.access & CS_AC_WRITE));
            }
        }
        cs_free(insn, 1);
        return !usesStack && address > start;
    }

    // 32 bit: the code at `start` (relative) builds its frame with a helper: push 0x28 / push 0x10; push offset scopetable / mov eax, offset
    // handler (one or two of them; __EH_prolog3_align: two pushes and the handler), then the call of a frame helper (IsFrameHelper)
    bool StartsWithFrameHelper(uint64 start)
    {
        constexpr uint32 PROLOGUE_BYTES = 20; // push imm32; push imm32; mov eax, imm32; call rel32
        std::array<uint8, PROLOGUE_BYTES> bytes{};
        if (start >= codeSize || codeSize - start < PROLOGUE_BYTES || !obj->GetData().Copy(codeStart + start, bytes))
            return false;
        cs_insn* prologue = cs_malloc(handle);
        if (!prologue)
            return false;
        const uint8* data = bytes.data();
        size_t size       = bytes.size();
        uint64 address    = start;
        uint32 setup      = 0;
        uint32 pushes     = 0;
        std::optional<uint64> helper;
        while (!helper.has_value() && setup <= 3 && cs_disasm_iter(handle, &data, &size, &address, prologue)) {
            const cs_x86& x86  = prologue->detail->x86;
            const bool hasImm  = x86.op_count >= 1 && x86.operands[x86.op_count - 1].type == X86_OP_IMM;
            const bool pushImm = prologue->id == X86_INS_PUSH && x86.op_count == 1 && hasImm;
            const bool movEax  = prologue->id == X86_INS_MOV && x86.op_count == 2 && IsRegisterOperandOf(x86, 0, X86_REG_EAX) && hasImm;
            if ((pushImm || movEax) && (setup < 2 || (setup == 2 && pushes == 2 && movEax))) {
                setup++;
                pushes += pushImm ? 1u : 0u;
            } else if (prologue->id == X86_INS_CALL && setup > 0 && x86.op_count == 1 && hasImm)
                helper = static_cast<uint64>(x86.operands[0].imm);
            else
                break;
        }
        cs_free(prologue, 1);
        return helper.has_value() && setup <= 3 && helper.value() < codeSize && IsFrameHelper(helper.value());
    }

    // 32 bit: a function of the zone that builds the ebp frame of its caller (MSVC __SEH_prolog4 / __EH_prolog3 / _EH_prolog): it stores
    // ebp in the stack (mov [esp + 0x10], ebp / mov [eax], ebp), points ebp into the stack (lea ebp, [esp + 0x10] / mov ebp, eax) and
    // returns without restoring it (decoded with the handle of the sweep: FinishSweep asks it before the local variables)
    bool IsFrameHelper(uint64 target)
    {
        constexpr uint32 MAX_HELPER_INSTRUCTIONS = 48;
        const auto known                         = frameHelpers.find(target);
        if (known != frameHelpers.end())
            return known->second;
        bool storesFrame = false, setsFrame = false, helper = false;
        const auto helperData = target < codeSize ? obj->GetData().Get(codeStart + target, static_cast<uint32>(std::min<uint64>(codeSize - target, 0x200)), false)
                                                  : BufferView{};
        cs_insn* helperInsn   = helperData.IsValid() ? cs_malloc(handle) : nullptr;
        if (helperInsn) {
            const uint8* data = helperData.GetData();
            size_t size       = helperData.GetLength();
            uint64 address    = target;
            for (uint32 decoded = 0; decoded < MAX_HELPER_INSTRUCTIONS && cs_disasm_iter(handle, &data, &size, &address, helperInsn); decoded++) {
                const cs_x86& x86 = helperInsn->detail->x86;
                if (helperInsn->id == X86_INS_RET) {
                    helper = storesFrame && setsFrame && x86.op_count == 0;
                    break;
                }
                if (helperInsn->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_REG &&
                    x86.operands[1].reg == X86_REG_EBP)
                    storesFrame = true; // mov [esp + 0x10], ebp
                else if ((helperInsn->id == X86_INS_LEA || helperInsn->id == X86_INS_MOV) && x86.op_count == 2 && IsRegisterOperandOf(x86, 0, X86_REG_EBP))
                    setsFrame = storesFrame; // lea ebp, [esp + 0x10] / mov ebp, eax: after the old one is stored
                else {
                    bool writesFrame = helperInsn->id == X86_INS_LEAVE;
                    for (uint8 index = 0; index < x86.op_count; index++)
                        writesFrame |= x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE) &&
                                       x86.operands[index].reg == X86_REG_EBP;
                    if (writesFrame || helperInsn->id == X86_INS_CALL || helperInsn->id == X86_INS_JMP || cs_insn_group(handle, helperInsn, CS_GRP_JUMP))
                        break; // pop ebp / a branch: a regular function
                }
            }
            cs_free(helperInsn, 1);
        }
        frameHelpers.emplace(target, helper);
        return helper;
    }

    static bool IsRegisterOperandOf(const cs_x86& x86, uint8 index, x86_reg reg)
    {
        return index < x86.op_count && x86.operands[index].type == X86_OP_REG && x86.operands[index].reg == reg;
    }

    // 32 bit: the bytes popped by the callee of a call: a function of the zone (its ret), an import (its decorated name), a function of
    // another zone (a PLT stub: cdecl); none for an indirect call
    std::optional<uint32> CalleeStackPurge(const cs_insn& call)
    {
        const auto operands = zone->GetOperandsInfo(call);
        if (operands.absoluteMemory.has_value())
            return ImportStackPurge(operands);
        if (!operands.directTarget.has_value())
            return std::nullopt;
        const uint64 target = operands.directTarget.value();
        if (target >= codeSize)
            return 0u;
        const auto known = calleePurges.find(target);
        if (known != calleePurges.end())
            return known->second;
        const auto purge = DecodeCalleePurge(target);
        calleePurges.emplace(target, purge);
        return purge;
    }

    // the name of the function a call / jmp of the code reaches (an import through its slot, a thunk, a PLT stub of another zone, a function
    // the plugin names); empty when it has none
    std::string CalleeName(const cs_insn& call, DissasmArch functionArch)
    {
        auto operands = GetInstructionOperands(call, functionArch, labelBase);
        if (const auto resolved = resolvedAddresses.find(call.address); resolved != resolvedAddresses.end())
            operands.ripTarget = resolved->second; // 32 bit PIC: [ebx + n]; ARM64: the adrp pair of a blr
        if (operands.directTarget.has_value()) {
            const uint64 target = operands.directTarget.value() & addressMask;
            if (target < codeSize) {
                if (const auto thunk = thunkImports.find(target); thunk != thunkImports.end())
                    return thunk->second;
                const auto label = std::lower_bound(
                      callsFound.begin(), callsFound.end(), codeStart + target, [](const auto& item, uint64 value) { return item.first < value; });
                return label != callsFound.end() && label->first == codeStart + target ? label->second : std::string();
            }
            const uint64 address = (labelBase + target) & addressMask;
            if (const auto* other = zone->FindCodeZoneOfAddress(address); other && other != zone) {
                const auto thunk = other->thunkImports.find(address - other->labelAddressBase);
                return thunk != other->thunkImports.end() ? thunk->second : other->GetLabelNameAt(address - other->labelAddressBase);
            }
            return {};
        }
        const auto* import = findImport ? findImport(operands) : nullptr;
        return import && import->type == MemoryMappingType::FunctionMapping ? import->name : std::string();
    }

    // a direct target in another code zone with a prototype there (OtherZonePrototype), by target: the gates of NameVariablesFromCalls and
    // CollectArgumentDefinitions ask it for every call out of the zone (the PLT stubs of an ELF file, another section)
    std::unordered_map<uint64, std::pair<DissasmArch, bool>> otherZoneTargets;
    bool HasOtherZonePrototype(uint64 target, DissasmArch functionArch)
    {
        if (target == NO_TARGET || target < codeSize)
            return false;
        const auto known = otherZoneTargets.find(target);
        if (known != otherZoneTargets.end() && known->second.first == functionArch)
            return known->second.second;
        const bool found = OtherZonePrototype(target, functionArch) != nullptr;
        otherZoneTargets.insert_or_assign(target, std::make_pair(functionArch, found));
        return found;
    }

    // a call of the method of a COM interface that has a prototype (TrackComInterfaces: CalleePrototype names its arguments)
    bool HasComMethodPrototype(uint64 callAddress) const
    {
        const auto method = interfaceCalls.find(callAddress);
        return method != interfaceCalls.end() && FindComMethodPrototype(method->second) != nullptr;
    }

    // the prototype of the callee of a call: the one the user gave to a function of the zone (Y), else the one of the API it is (libc's own
    // closedir: DIR* dirp, not the ptr of the free its body calls), else the one inferred
    const AsmFunctionDetails* CalleePrototype(const cs_insn& call, DissasmArch functionArch)
    {
        if (const auto method = interfaceCalls.find(call.address); method != interfaceCalls.end()) // a COM method (TrackComInterfaces)
            if (const auto* prototype = FindComMethodPrototype(method->second))
                return prototype;
        const auto operands = GetInstructionOperands(call, functionArch, labelBase);
        if (operands.directTarget.has_value())
            if (const uint64 target = operands.directTarget.value() & addressMask; target < codeSize) {
                if (const auto* user = zone->FindUserPrototype(target))
                    return user;
                if (const auto inferred = inferredPrototypes.find(target); inferred != inferredPrototypes.end()) {
                    const auto* api = FindApiPrototype(CalleeName(call, functionArch));
                    return api ? api : &inferred->second->details;
                }
            }
        const std::string name = CalleeName(call, functionArch);
        if (const auto* api = FindApiPrototype(name))
            return api;
        if (const auto* other = operands.directTarget.has_value() ? OtherZonePrototype(operands.directTarget.value() & addressMask, functionArch) : nullptr)
            return other;
        return FindMethodPrototypeByName(methodPrototypes, name);
    }

    // a direct target in another code zone of the file analyzed before this one (ntfs: a call from PAGE to .text): the prototype the user gave
    // there or the one that zone inferred, for the code of the same instruction set (not the ARM64 code an x64 zone of an ARM64X image calls)
    const AsmFunctionDetails* OtherZonePrototype(uint64 target, DissasmArch functionArch) const
    {
        if (target == NO_TARGET || target < codeSize)
            return nullptr;
        const uint64 address = (labelBase + target) & addressMask;
        const auto* other    = zone->FindCodeZoneOfAddress(address);
        if (!other || other == zone || other->GetArchAt(address - other->labelAddressBase) != functionArch)
            return nullptr;
        if (const auto* user = other->FindUserPrototype(address - other->labelAddressBase))
            return user;
        return other->FindInferredPrototype(address - other->labelAddressBase);
    }

    // GCC (System V x64): the functions of the zone named by a demangled C++ name that is no constructor / destructor
    // (std::istream::ignore(long)): the name tells neither a static method from a method nor the address of a class returned before this;
    // the highest argument register the entry of the function reads tells how many arguments come before its parameters
    // (MakeGccMethodPrototype); by the name of the function (its j_ thunks: FindMethodPrototypeByName)
    // a GCC method the reads of its entry do not decide (AddGccMethodPrototypes)
    struct UndecidedMethod {
        size_t index;    // of the function
        int32 highest;   // the highest argument register it reads
        uint64 passedTo; // the target of the call its first argument goes to first
    };
    void AddGccMethodPrototypes()
    {
        methodPrototypes.clear();
        std::vector<UndecidedMethod> undecided; // this or a result, not read first
        std::vector<UndecidedMethod> unknown;   // the reads of the entry decide nothing (DecideGccMethodsByCallers)
        if (!hasDetailHandle || !zone->systemVCalls || functionEnds.size() != functionStarts.size())
            return;
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            const auto label =
                  std::lower_bound(callsFound.begin(), callsFound.end(), codeStart + start, [](const auto& item, uint64 value) { return item.first < value; });
            if (label == callsFound.end() || label->first != codeStart + start)
                continue;
            const std::string& name = label->second;
            if (name.find('(') == std::string::npos || name.starts_with("j_") || methodPrototypes.contains(name) || zone->GetArchAt(start) != DissasmArch::X64)
                continue;
            const auto parameters = GetGccMethodParameters(name);
            if (!parameters.has_value())
                continue;
            const int32 highest = HighestArgumentRead(start, functionEnds[index], parameters.value());
            auto prototype      = MakeGccMethodPrototype(name, highest);
            if (!prototype) {
                unknown.push_back({ index, highest, NO_TARGET });
                continue;
            }
            if (prototype && !prototype->details.params.empty() && !prototype->details.params[0].name[0] && !prototype->details.params[0].type[0]) {
                uint64 passedTo = NO_TARGET;
                const auto use  = FirstUseOfFirstArgument(start, functionEnds[index], passedTo);
                // this or a result: the object it reads; an operator of its class; no address of a result returned, an object read on another path
                if (use == FirstArgumentUse::Read || IsGccMemberOperator(name) || FirstArgumentIsAnObject(start, functionEnds[index], GetGccMethodClass(name)))
                    prototype = MakeGccMethodPrototype(name, highest, true);
                else if (use == FirstArgumentUse::PassedToCall)
                    undecided.push_back({ index, highest, passedTo });
            }
            if (prototype)
                methodPrototypes.emplace(name, std::move(prototype));
        }
        DecideGccMethodsByCallers(unknown, undecided);
        // this or a result, not read before a call: passed first as the this of a method (a result is built first: a constructor); the
        // methods known by this round decide the next ones (3 rounds)
        for (uint32 round = 0; round < 3 && !undecided.empty(); round++) {
            std::vector<UndecidedMethod> left;
            for (const auto& method : undecided) {
                const uint64 start = functionStarts[method.index];
                const auto label   = std::lower_bound(
                      callsFound.begin(), callsFound.end(), codeStart + start, [](const auto& item, uint64 value) { return item.first < value; });
                if (TakesItsThis(method.passedTo))
                    methodPrototypes[label->second] = MakeGccMethodPrototype(label->second, method.highest, true);
                else
                    left.push_back(method);
            }
            if (left.size() == undecided.size())
                break;
            undecided = std::move(left);
        }
    }

    // the GCC methods the reads of their entry do not decide (an unused last parameter: std::string::_Rep::_M_destroy(std::allocator<char>
    // const&) reads rdi only): the highest argument register their callers write in the block of the call (through their j_ stubs too), as
    // the highest one read, when at least 4 in 5 of two or more calls agree and it is not below the one the entry reads; this or a result
    // then as the reads of the entry decide (FirstUseOfFirstArgument). As many registers as the parameters: a static method, when the
    // blocks that start right after another call (no label in them: every argument register written there) all write that many
    void DecideGccMethodsByCallers(const std::vector<UndecidedMethod>& unknown, std::vector<UndecidedMethod>& undecided)
    {
        constexpr uint64 MAX_BLOCK = 0x100; // the bytes decoded before a call
        if (unknown.empty())
            return;
        std::unordered_map<std::string, size_t> byName; // the name of the method (its j_ stub without the prefix) -> its entry of unknown
        for (size_t entry = 0; entry < unknown.size(); entry++)
            byName.emplace(TargetName(functionStarts[unknown[entry].index]), entry);
        std::vector<std::array<uint32, 7>> written(unknown.size(), std::array<uint32, 7>{}); // the calls by the highest register (-1 .. 5)
        // the same of the calls whose block starts right after another call: the argument registers of the call before are dead there
        std::vector<std::array<uint32, 7>> afterCall(unknown.size(), std::array<uint32, 7>{});
        std::unordered_map<uint64, size_t> entryOfTarget;                                    // a target -> its entry, SIZE_MAX: none
        cs_insn* insn = cs_malloc(detailHandle);
        if (!insn)
            return;
        for (size_t position = 0; position < flowRecords.size(); position++) {
            const auto& record = flowRecords[position];
            if (record.kind != FlowKind::Call || record.target == NO_TARGET)
                continue;
            auto known = entryOfTarget.find(record.target);
            if (known == entryOfTarget.end()) {
                std::string name = TargetName(record.target);
                if (name.starts_with("j_"))
                    name.erase(0, 2);
                const auto found = byName.find(name);
                known            = entryOfTarget.emplace(record.target, found != byName.end() ? found->second : SIZE_MAX).first;
            }
            if (known->second == SIZE_MAX)
                continue;
            // the block of the call: after the flow before it, not before the start of its function
            const auto function = std::upper_bound(functionStarts.begin(), functionStarts.end(), record.address);
            uint64 from         = function != functionStarts.begin() ? *(function - 1) : 0;
            if (position > 0)
                from = std::max(from, flowRecords[position - 1].address + flowRecords[position - 1].size);
            if (from > record.address || record.address - from > MAX_BLOCK)
                continue;
            const auto highest = HighestArgumentWritten(insn, from, record.address);
            if (!highest.has_value())
                continue;
            written[known->second][static_cast<size_t>(highest.value() + 1)]++;
            const auto& previous = flowRecords[position > 0 ? position - 1 : 0];
            if (position > 0 && previous.kind == FlowKind::Call && from == previous.address + previous.size) {
                const auto label = std::lower_bound(
                      callsFound.begin(), callsFound.end(), codeStart + from, [](const auto& item, uint64 value) { return item.first < value; });
                if (label == callsFound.end() || label->first > codeStart + record.address) // no jump reaches the block
                    afterCall[known->second][static_cast<size_t>(highest.value() + 1)]++;
            }
        }
        cs_free(insn, 1);
        for (size_t entry = 0; entry < unknown.size(); entry++) {
            const auto& counts = written[entry];
            uint32 total = 0, best = 0;
            size_t bestIndex = 0;
            for (size_t index = 0; index < counts.size(); index++) {
                total += counts[index];
                if (counts[index] > best) {
                    best      = counts[index];
                    bestIndex = index;
                }
            }
            const int32 highest = static_cast<int32>(bestIndex) - 1;
            if (total < 2 || best * 5 < total * 4 || highest < unknown[entry].highest)
                continue;
            const uint64 start     = functionStarts[unknown[entry].index];
            const std::string name = TargetName(start);
            auto prototype         = MakeGccMethodPrototype(name, highest);
            if (const auto& clean = afterCall[entry];
                !prototype && highest >= 0 && clean[bestIndex] > 0 && clean[bestIndex] == std::accumulate(clean.begin(), clean.end(), 0u))
                prototype = MakeGccMethodPrototype(name, highest, false, true); // a static method
            if (!prototype)
                continue;
            if (!prototype->details.params.empty() && !prototype->details.params[0].name[0] && !prototype->details.params[0].type[0]) {
                uint64 passedTo = NO_TARGET;
                const auto use  = FirstUseOfFirstArgument(start, functionEnds[unknown[entry].index], passedTo);
                if (use == FirstArgumentUse::Read || IsGccMemberOperator(name) ||
                    FirstArgumentIsAnObject(start, functionEnds[unknown[entry].index], GetGccMethodClass(name)))
                    prototype = MakeGccMethodPrototype(name, highest, true);
                else if (use == FirstArgumentUse::PassedToCall)
                    undecided.push_back({ unknown[entry].index, highest, passedTo });
            }
            methodPrototypes.emplace(name, std::move(prototype));
        }
    }

    // System V x64: the highest argument register (rdi 0 .. r9 5, -1: none) the instructions of [from, to) write; none when the code does not
    // end at `to`
    std::optional<int32> HighestArgumentWritten(cs_insn* insn, uint64 from, uint64 to)
    {
        static constexpr int SYSTEM_V[] = { 7, 6, 2, 1, 8, 9 }; // the families of rdi, rsi, rdx, rcx, r8, r9

        const auto data = obj->GetData().Get(codeStart + from, static_cast<uint32>(to - from), false);
        if (!data.IsValid() || data.GetLength() != to - from)
            return std::nullopt;
        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = from;
        int32 highest      = -1;
        const auto note    = [&highest](unsigned int reg) {
            const int family = GetX64RegisterFamily(reg);
            for (int32 argument = 0; argument < 6; argument++)
                if (SYSTEM_V[argument] == family)
                    highest = std::max(highest, argument);
        };
        while (address < to && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
            if (!insn->detail || GetInstructionFlow(*insn, DissasmArch::X64) != X86Flow::None)
                return std::nullopt;
            const auto& x86 = insn->detail->x86;
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                    note(x86.operands[index].reg);
        }
        if (address != to)
            return std::nullopt;
        return highest;
    }

    // how the entry of a function first uses its first argument (System V: rdi): memory read / written through it (or a copy of it: mov rbx,
    // rdi), passed in rdi to a direct call
    enum class FirstArgumentUse : uint8 { None, Read, Write, PassedToCall };

    // a function of the zone whose prototype takes its first argument as its this: a method, not a constructor / destructor (one builds
    // the address of a result there)
    bool TakesItsThis(uint64 target)
    {
        const std::string name = TargetName(target);
        const auto* callee     = target < codeSize ? zone->FindUserPrototype(target) : nullptr;
        if (!callee && !name.empty())
            callee = FindApiPrototype(name);
        if (!callee && !name.empty())
            callee = FindMethodPrototypeByName(methodPrototypes, name);
        return callee && !callee->params.empty() && callee->params[0].name && std::string_view(callee->params[0].name) == "this" &&
               !IsCxxConstructorOrDestructor(callee->functionName);
    }

    // System V x64: the first use of the first argument of a function (rdi, a copy of it: mov rbx, rdi) on the path of its entry that falls
    // through its conditional jumps, up to its first call / jmp / ret: memory read through it (an object, this: the address of a result is
    // written before it is read), written, or passed in rdi to the first call (its target in `passedTo`)
    FirstArgumentUse FirstUseOfFirstArgument(uint64 start, uint64 end, uint64& passedTo)
    {
        constexpr uint32 MAX_INSTRUCTIONS = 64;
        constexpr int FIRST               = 7; // the family of rdi (GetX64RegisterFamily)
        const auto data = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x400)), false) : BufferView{};
        cs_insn* insn   = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return FirstArgumentUse::None;
        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = start;
        uint32 holders     = 1u << FIRST; // the families of the registers that hold it
        std::optional<bool> reads;
        auto use = FirstArgumentUse::None;
        for (uint32 count = 0; count < MAX_INSTRUCTIONS && !reads.has_value() && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn); count++) {
            const auto flow = GetInstructionFlow(*insn, DissasmArch::X64);
            if (flow == X86Flow::Call && insn->detail && (holders & (1u << FIRST)) != 0) {
                if (const auto operands = GetInstructionOperands(*insn, DissasmArch::X64, labelBase); operands.directTarget.has_value()) {
                    passedTo = operands.directTarget.value() & addressMask;
                    use      = FirstArgumentUse::PassedToCall;
                }
                break;
            }
            if (flow == X86Flow::Call || flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || insn->id == X86_INS_UD2 ||
                insn->id == X86_INS_HLT || !insn->detail)
                break;
            const auto& x86 = insn->detail->x86;
            const auto held = [&holders](unsigned int reg) {
                const int family = GetX64RegisterFamily(reg);
                return family >= 0 && family < 32 && (holders & (1u << family)) != 0;
            };
            if (insn->id != X86_INS_LEA && insn->id != X86_INS_NOP)
                for (uint8 index = 0; index < x86.op_count && !reads.has_value(); index++)
                    if (const auto& op = x86.operands[index]; op.type == X86_OP_MEM && op.mem.base != X86_REG_INVALID && held(op.mem.base))
                        reads = (op.access & CS_AC_READ) != 0;
            if (x86.op_count == 2 && x86.operands[0].type == X86_OP_REG) {
                const int destination = GetX64RegisterFamily(x86.operands[0].reg);
                if (destination >= 0 && destination < 32) {
                    if (insn->id == X86_INS_MOV && x86.operands[1].type == X86_OP_REG && held(x86.operands[1].reg))
                        holders |= 1u << destination; // a copy
                    else if ((x86.operands[0].access & CS_AC_WRITE) != 0)
                        holders &= ~(1u << destination);
                }
            }
        }
        cs_free(insn, 1);
        return reads.has_value() ? (reads.value() ? FirstArgumentUse::Read : FirstArgumentUse::Write) : use;
    }

    // System V x64: the entry of a function shows that its first argument (rdi) is no address of a class it returns (this for a method whose
    // first use of rdi decides nothing): a ret returns something else than rdi (a function that returns a class in memory returns the
    // address it got at every ret: a setter writes through rdi first; basic_filebuf::open returns this or nullptr), or a path reads memory
    // through rdi before any write through it, any store of it, any call it is passed to (the memory of a result is written before it is
    // read: std::string::append returns *this on every path, one of them reads the string first). The paths of the entry: both sides of its
    // conditional jumps, its direct jumps inside the function, its calls (not the ones that do not return); a state (address, registers
    // holding rdi, rax, reads deciding, rdi stored) walked once, 256 instructions at most over all the paths. rax never written or written from
    // no register holding rdi (xor eax, eax; sete al; mov eax, dword ptr [rbx + 0x10]) decides, as the result of a call or a tail jmp to a
    // function that never got rdi (not in an argument register, never stored: _M_create returns what operator new returns); a copy of rdi
    // (mov rax, rbx after mov rbx, rdi), anything computed from it, a load from the stack (-O0 keeps rdi in a slot of the frame) do not
    // `objectClass`: the class of the method (GetGccMethodClass): rdi passed after the first argument of a call as a reference / pointer of it
    // (the stream of std::istream::sentry::sentry(std::istream&, bool), the source of a copy) is an object that exists
    bool FirstArgumentIsAnObject(uint64 start, uint64 end, std::string_view objectClass = {})
    {
        enum class Returned : uint8 { Nothing, First, Other, NotKnown };
        struct PathState {
            uint64 address;
            uint32 holders; // the families of the registers that hold it
            Returned rax;
            bool unwritten; // no write through it, no store of it, no call it is passed to yet: a read through it decides
            bool stored;    // stored to memory (mov [rsp + 8], rbx; push rbx): a callee may load it
        };
        constexpr uint32 MAX_INSTRUCTIONS = 256;
        constexpr uint64 MAX_BYTES        = 0x1000;
        // the families of GetX64RegisterFamily: rax, rdi; rbx, rbp, r12 .. r15
        constexpr int RAX = 0, FIRST = 7;
        constexpr uint32 CALLEE_SAVED = (1u << 3) | (1u << 5) | (1u << 12) | (1u << 13) | (1u << 14) | (1u << 15);
        constexpr uint32 ARGUMENTS    = (1u << 7) | (1u << 6) | (1u << 2) | (1u << 1) | (1u << 8) | (1u << 9); // rdi, rsi, rdx, rcx, r8, r9
        const auto data =
              start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, MAX_BYTES)), false) : BufferView{};
        cs_insn* insn = data.IsValid() && data.GetLength() > 0 ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return false;
        const uint64 limit = start + data.GetLength();
        std::vector<PathState> pending{ { start, 1u << FIRST, Returned::Nothing, true, false } };
        std::set<std::tuple<uint64, uint32, Returned, bool, bool>> seen;
        bool decided = false;
        uint32 count = 0;
        while (!pending.empty() && !decided && count < MAX_INSTRUCTIONS) {
            const PathState state = pending.back();
            pending.pop_back();
            uint64 address     = state.address;
            uint32 holders     = state.holders;
            Returned rax       = state.rax;
            bool unwritten     = state.unwritten;
            bool stored        = state.stored;
            const uint8* bytes = data.GetData() + (address - start);
            size_t size        = static_cast<size_t>(limit - address);
            const auto held    = [&holders](unsigned int reg) {
                const int family = GetX64RegisterFamily(reg);
                return family >= 0 && family < 32 && (holders & (1u << family)) != 0;
            };
            const auto jumpTo = [&](uint64 target) { // a direct branch inside the function
                bytes   = data.GetData() + (target - start);
                size    = static_cast<size_t>(limit - target);
                address = target;
            };
            while (count < MAX_INSTRUCTIONS && address < limit && seen.insert({ address, holders, rax, unwritten, stored }).second &&
                   cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
                count++;
                const auto flow = GetInstructionFlow(*insn, DissasmArch::X64);
                if (flow == X86Flow::Return) {
                    decided = rax == Returned::Nothing || rax == Returned::Other;
                    break;
                }
                if (flow == X86Flow::Interrupt || insn->id == X86_INS_UD2 || insn->id == X86_INS_HLT || !insn->detail)
                    break;
                if (flow == X86Flow::Jump || flow == X86Flow::ConditionalJump) {
                    const auto operands = GetInstructionOperands(*insn, DissasmArch::X64, labelBase);
                    const uint64 target = operands.directTarget.has_value() ? operands.directTarget.value() & addressMask : NO_TARGET;
                    const bool inside   = target >= start && target < limit;
                    if (flow == X86Flow::ConditionalJump) {
                        if (inside)
                            pending.push_back({ target, holders, rax, unwritten, stored });
                        continue;
                    }
                    if (!inside) { // a tail call (what the function returns: it never got rdi), a jump through a table
                        decided = target != NO_TARGET && (holders & ARGUMENTS) == 0 && !stored &&
                                  std::binary_search(functionStarts.begin(), functionStarts.end(), target);
                        break;
                    }
                    jumpTo(target);
                    continue;
                }
                if (flow == X86Flow::Call) {
                    if (noReturnCalls.contains(insn->address))
                        break;
                    if (!objectClass.empty() && (holders & ARGUMENTS & ~(1u << FIRST)) != 0 && PassesObjectOfClass(*insn, holders, objectClass)) {
                        decided = true;
                        break;
                    }
                    if ((holders & ARGUMENTS) != 0)
                        unwritten = false; // passed to the call: it may write it
                    rax = (holders & ARGUMENTS) == 0 && !stored ? Returned::Other : Returned::NotKnown;
                    holders &= CALLEE_SAVED;
                    continue;
                }
                const auto& x86 = insn->detail->x86;
                // the first access through it on this path: a read (cmp qword ptr [rdi], 0; mov rax, [rbx + 8]; add [rdi], 1) decides, a write
                // (mov qword ptr [rdi], 0) or a store of it (mov [rsp + 8], rbx; push rbx: a callee may write through it) ends the reads
                const bool accesses = insn->id != X86_INS_LEA && insn->id != X86_INS_NOP && !std::string_view(insn->mnemonic).starts_with("prefetch");
                bool storesIt = false, writesMemory = insn->id == X86_INS_PUSH;
                for (uint8 index = 0; index < x86.op_count; index++) {
                    const auto& op = x86.operands[index];
                    if (unwritten && accesses && op.type == X86_OP_MEM &&
                        ((op.mem.base != X86_REG_INVALID && held(op.mem.base)) || (op.mem.index != X86_REG_INVALID && held(op.mem.index)))) {
                        if (op.access & CS_AC_READ)
                            decided = true;
                        unwritten = false;
                    }
                    if (op.type == X86_OP_MEM && (op.access & CS_AC_WRITE))
                        writesMemory = true;
                    if (op.type == X86_OP_REG && (op.access & CS_AC_READ) && held(op.reg))
                        storesIt = true;
                }
                if (decided)
                    break;
                if (storesIt && writesMemory) {
                    unwritten = false;
                    stored    = true;
                }
                if (insn->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[0].size == 8 &&
                    x86.operands[1].type == X86_OP_REG && held(x86.operands[1].reg)) { // a copy: mov rbx, rdi
                    const int family = GetX64RegisterFamily(x86.operands[0].reg);
                    if (family >= 0 && family < 32) {
                        holders |= 1u << family;
                        if (family == RAX)
                            rax = Returned::First;
                        continue;
                    }
                }
                bool fromIt    = false; // computed from a register holding it (lea rax, [rdi + 8]; add rax, rdi; cmovne rax, rbx)
                bool fromStack = insn->id == X86_INS_POP;
                for (uint8 index = 0; index < x86.op_count; index++) {
                    const auto& op = x86.operands[index];
                    if (op.type == X86_OP_REG && (op.access & CS_AC_READ) && held(op.reg))
                        fromIt = true;
                    if (op.type == X86_OP_MEM && insn->id == X86_INS_LEA &&
                        ((op.mem.base != X86_REG_INVALID && held(op.mem.base)) || (op.mem.index != X86_REG_INVALID && held(op.mem.index))))
                        fromIt = true;
                    if (op.type == X86_OP_MEM && (op.access & CS_AC_READ) && (op.mem.base == X86_REG_RSP || op.mem.base == X86_REG_RBP))
                        fromStack = true;
                }
                cs_regs read, write;
                uint8 readCount = 0, writeCount = 0;
                if (cs_regs_access(detailHandle, insn, read, &readCount, write, &writeCount) != CS_ERR_OK)
                    break;
                for (uint8 index = 0; index < writeCount; index++) {
                    const int family = GetX64RegisterFamily(write[index]);
                    if (family < 0 || family >= 32)
                        continue;
                    if (family == RAX)
                        rax = fromIt || fromStack ? Returned::NotKnown : Returned::Other;
                    holders &= ~(1u << family);
                }
            }
        }
        cs_free(insn, 1);
        return decided;
    }

    // System V x64: a call passes a register of `holders` after its first argument (rsi .. r9) as a parameter typed as a reference / pointer of
    // `objectClass` (std::ostream&, std::ostream const&, std::ostream*), not as this or the address of a result
    bool PassesObjectOfClass(const cs_insn& call, uint32 holders, std::string_view objectClass)
    {
        static constexpr int SYSTEM_V[] = { 7, 6, 2, 1, 8, 9 };
        const auto trim                 = [](std::string_view text) {
            while (!text.empty() && text.front() == ' ')
                text.remove_prefix(1);
            while (!text.empty() && text.back() == ' ')
                text.remove_suffix(1);
            return text;
        };
        const auto* callee = CalleePrototype(call, DissasmArch::X64);
        if (!callee)
            return false;
        for (size_t argument = 1; argument < 6 && argument < callee->params.size(); argument++) {
            if ((holders & (1u << SYSTEM_V[argument])) == 0 || !callee->params[argument].type)
                continue;
            const std::string_view name = callee->params[argument].name ? callee->params[argument].name : "";
            std::string_view type       = trim(callee->params[argument].type);
            if (name == "this" || name == "result" || !(type.ends_with('&') || type.ends_with('*')))
                continue;
            type.remove_suffix(1);
            type = trim(type);
            if (type.ends_with(" const"))
                type.remove_suffix(6);
            if (type == objectClass)
                return true;
        }
        return false;
    }

    // System V x64: the highest argument register (0: rdi, rsi, rdx, rcx, r8, 5: r9) the entry of a function reads before writing it, on the
    // path that falls through its conditional jumps up to its first call / jmp / ret (one path: a parameter not read there is not seen); -1
    // for none. xor esi, esi writes only. The walk ends once the registers that decide (the parameters and two more) are read or written
    int32 HighestArgumentRead(uint64 start, uint64 end, uint32 parameters)
    {
        static constexpr int SYSTEM_V[]   = { 7, 6, 2, 1, 8, 9 };
        constexpr uint32 MAX_INSTRUCTIONS = 64;
        const auto data = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x400)), false) : BufferView{};
        cs_insn* insn   = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return -1;
        const auto argumentOf = [](uint16 reg) {
            const int family = GetX64RegisterFamily(reg);
            for (int argument = 0; argument < 6; argument++)
                if (SYSTEM_V[argument] == family)
                    return argument;
            return -1;
        };
        const uint8* bytes    = data.GetData();
        size_t size           = data.GetLength();
        uint64 address        = start;
        const uint32 deciding = (1u << std::min<uint32>(parameters + 2, 6)) - 1;
        uint32 written        = 0;
        uint32 seen           = 0; // read or written
        int32 highest         = -1;
        for (uint32 count = 0; count < MAX_INSTRUCTIONS && (seen & deciding) != deciding && highest <= static_cast<int32>(parameters) &&
                               cs_disasm_iter(detailHandle, &bytes, &size, &address, insn);
             count++) {
            const auto flow = GetInstructionFlow(*insn, DissasmArch::X64);
            if (flow == X86Flow::Call || flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || insn->id == X86_INS_UD2 ||
                insn->id == X86_INS_HLT)
                break;
            cs_regs read, write;
            uint8 readCount = 0, writeCount = 0;
            if (!insn->detail || cs_regs_access(detailHandle, insn, read, &readCount, write, &writeCount) != CS_ERR_OK)
                break;
            const auto& x86 = insn->detail->x86;
            const bool zeroing =
                  (insn->id == X86_INS_XOR || insn->id == X86_INS_SUB || insn->id == X86_INS_PXOR || insn->id == X86_INS_XORPS || insn->id == X86_INS_XORPD) &&
                  x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG && x86.operands[0].reg == x86.operands[1].reg;
            for (uint8 index = 0; index < readCount && !zeroing; index++)
                if (const int argument = argumentOf(read[index]); argument >= 0) {
                    if ((written & (1u << argument)) == 0)
                        highest = std::max(highest, argument);
                    seen |= 1u << argument;
                }
            for (uint8 index = 0; index < writeCount; index++)
                if (const int argument = argumentOf(write[index]); argument >= 0) {
                    written |= 1u << argument;
                    seen |= 1u << argument;
                }
        }
        cs_free(insn, 1);
        return highest;
    }

    // a callee whose prototype the inference uses: not one of a demangled C++ name (its parameters have types, no names to give; what it
    // returns would make a wrapper of every function that returns it)
    static const AsmFunctionDetails* IsInferenceCallee(const AsmFunctionDetails* prototype)
    {
        return prototype && !prototype->demangled ? prototype : nullptr;
    }

    // the name a direct target has for the prototypes: a thunk of an import, a label of the zone, a function of another zone
    std::string TargetName(uint64 target)
    {
        if (target < codeSize) {
            if (const auto thunk = thunkImports.find(target); thunk != thunkImports.end())
                return thunk->second;
            const auto label = std::lower_bound(
                  callsFound.begin(), callsFound.end(), codeStart + target, [](const auto& item, uint64 value) { return item.first < value; });
            return label != callsFound.end() && label->first == codeStart + target ? label->second : std::string();
        }
        if (const auto* other = zone->FindCodeZoneOfAddress((labelBase + target) & addressMask); other && other != zone) {
            const uint64 otherStart = ((labelBase + target) & addressMask) - other->labelAddressBase;
            const auto thunk        = other->thunkImports.find(otherStart);
            return thunk != other->thunkImports.end() ? thunk->second : other->GetLabelNameAt(otherStart);
        }
        return {};
    }

    // beyond IDA (its decompiler does it): the prototypes of the functions that pass their own arguments to a known prototype (an API, a
    // function of the user, one inferred in a round before: the wrappers of the wrappers, 3 rounds). The code of a function is followed in its
    // order with the incoming argument each register holds (rcx / rdx / r8 / r9, rdi / rsi / ..., x0 .. x7, r0 .. r3; copied by mov, kept by
    // the callee saved registers across the calls); at a branch target the state is the one every branch to it agrees on (the forward ones,
    // the fall through), a register written between the target and a branch back (a loop) is dropped. A call / tail jump with a prototype
    // names the incoming arguments it is passed. Not the user's functions (their prototype wins). 32 bit x86: InferX86FunctionPrototype
    void InferPrototypes()
    {
        inferredPrototypes.clear();
        comparisonsByFunction.clear();
        returnValueConstants.clear();
        if (!hasDetailHandle || functionEnds.size() != functionStarts.size())
            return;
        // the first round: the functions that call a prototype (an import slot, a target, a function inferred before them in the round);
        // the next ones: the functions that call one inferred / changed by the round before or by this one (the others would give the same
        // as before), the ones inferred already too (they did not see the callees inferred after them: a function inferred from a known API
        // gets the arguments it passes to a wrapper inferred later)
        std::unordered_set<uint64> inferredBefore;
        argumentStepsOf.clear();
        for (uint32 round = 0; round < 3; round++) {
            // the code CollectArgumentDefinitions follows: decoded once, by the last round that decodes the function (a caller of a function
            // inferred after it in the first round is decoded first by the second one)
            keepArgumentSteps = true;
            std::unordered_set<uint64> inferredNow;
            for (size_t index = 0; index < functionStarts.size(); index++) {
                const uint64 start = functionStarts[index];
                if (zone->userPrototypes.contains(start) || (round == 0 && inferredPrototypes.contains(start)))
                    continue;
                const auto arch = zone->GetArchAt(start);
                bool candidate  = false;
                for (size_t position = FirstRecordAt(start); position < flowRecords.size() && flowRecords[position].address < functionEnds[index] && !candidate;
                     position++) {
                    const auto& record = flowRecords[position];
                    if (record.kind != FlowKind::Call && record.kind != FlowKind::Jump)
                        continue;
                    const bool outside = record.target != NO_TARGET && (record.target < start || record.target >= functionEnds[index]);
                    if (round > 0)
                        candidate = outside && (inferredBefore.contains(record.target) || inferredNow.contains(record.target));
                    else
                        candidate = knownPrototypeCalls.contains(record.address) ||
                                    (outside && (inferredNow.contains(record.target) || zone->FindUserPrototype(record.target) ||
                                                 IsInferenceCallee(FindApiPrototype(TargetName(record.target))) ||
                                                 IsInferenceCallee(OtherZonePrototype(record.target, arch))));
                }
                if (!candidate)
                    continue;
                // inferred again: without its own prototype (a recursive call is not a callee that knows its arguments)
                std::shared_ptr<const DissasmUserPrototype> previous;
                if (const auto known = inferredPrototypes.find(start); known != inferredPrototypes.end()) {
                    previous = std::move(known->second);
                    inferredPrototypes.erase(known);
                }
                functionComparisons.clear();
                auto prototype = arch == DissasmArch::X86 ? InferX86FunctionPrototype(start, functionEnds[index]) : InferFunctionPrototype(start, functionEnds[index], arch);
                comparisonsByFunction[start] = std::move(functionComparisons); // the walk that knew the most callees
                if (prototype && (!previous || previous->details.prototype != prototype->details.prototype)) {
                    inferredPrototypes.emplace(start, std::move(prototype));
                    inferredNow.insert(start);
                } else if (previous) {
                    inferredPrototypes.emplace(start, std::move(previous)); // the same as before
                }
            }
            keepArgumentSteps = false;
            if (inferredNow.empty())
                break;
            inferredBefore = std::move(inferredNow);
        }
        for (auto& [start, comparisons] : comparisonsByFunction)
            for (auto& [address, text] : comparisons)
                returnValueConstants.emplace(address, std::move(text));
        comparisonsByFunction.clear();
    }

    // beyond IDA (its decompiler does it): the arguments of a call written in the blocks that jump to it (mov rcx, rbx; jmp loc_X, a write
    // before a jcc to it) or before a tail jump; the display names the ones of the block of the call and of the code that falls into it
    // (AnnounceCallInstruction). x64 / ARM64: the writes of the argument registers that reach each call with a prototype (the definitions of
    // the paths to it), followed in the order of the code and merged at the branch targets of the forward branches. Kept: a write that reaches
    // a call through a taken branch or a tail jump, never along the code that falls into a call, and that every call it reaches takes as the
    // same parameter; not one live at a branch back (a loop: the calls it reaches before) or at an indirect jump (a switch)
    std::vector<uint64> forwardTargets; // CollectArgumentDefinitions: the targets of the forward branches of a function (sorted)
    // a write that reaches the call along the code that falls into it farther than the walk of the display looks back (24 lines of x64 /
    // ARM64: more instructions are more lines; nearer: the display names it, its own way, once): named by CollectFunctionArgumentDefinitions;
    // a call with at least so many bytes of code before it in its block, in a function a round of InferPrototypes decoded (its steps kept: not
    // decoded again)
    static constexpr uint32 FAR_ARGUMENT_STEPS = 24;
    static constexpr uint64 FAR_CALL_BYTES     = 0x80;
    // an instruction of a function for CollectArgumentDefinitions: the argument registers it writes, its branch, its callee
    enum class ArgumentStepKind : uint8 { Other, Call, TailCall, Jump, ConditionalJump, Return, IndirectJump };
    struct ArgumentStep {
        uint64 address;
        uint64 target; // a branch inside of the function; NO_TARGET otherwise
        const AsmFunctionDetails* callee;
        uint64 callTarget; // the direct target of a call / a jump out of the function; NO_TARGET otherwise
        uint8 writes;      // a bit per argument register (Windows x64: 4 .. 7, the stack slots of the fifth .. eighth: [rsp + 0x20] ..)
        ArgumentStepKind kind;
        bool movesStack = false; // Windows x64: a write of rsp (push, sub rsp): the stack slots are others
    };
    // the steps of the x64 / ARM64 functions the rounds of InferPrototypes decode (the same code: not decoded again), by start
    std::unordered_map<uint64, std::vector<ArgumentStep>> argumentStepsOf;
    bool keepArgumentSteps = false;

    // the argument a register is (rcx .. r9 / rdi .. r9 / x0 .. x7: 0 ..), -1 for another one
    int ArgumentRegisterOf(unsigned int reg, DissasmArch arch) const
    {
        if (arch == DissasmArch::Arm64) {
            if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X7)
                return static_cast<int>(reg - ARM64_REG_X0);
            if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W7)
                return static_cast<int>(reg - ARM64_REG_W0);
            return -1;
        }
        static constexpr int WINDOWS[] = { 1, 2, 8, 9 }, SYSTEM_V[] = { 7, 6, 2, 1, 8, 9 };
        const std::span<const int> arguments = zone->systemVCalls ? std::span<const int>(SYSTEM_V) : std::span<const int>(WINDOWS);
        const int family                     = GetX64RegisterFamily(reg);
        for (size_t argument = 0; argument < arguments.size(); argument++)
            if (arguments[argument] == family)
                return static_cast<int>(argument);
        return -1;
    }

    // Windows x64: the stack slots of the arguments after the fourth an instruction writes (mov qword ptr [rsp + 0x20], rbx: the fifth, bit 4 ..
    // 7), whether it writes rsp (push, pop, sub / add rsp)
    std::pair<uint8, bool> ArgumentStackWrites(const cs_insn& insn, DissasmArch arch) const
    {
        if (arch != DissasmArch::X64 || zone->systemVCalls || !insn.detail)
            return { 0, false };
        uint8 writes      = 0;
        bool moves        = false;
        const cs_x86& x86 = insn.detail->x86;
        for (uint8 i = 0; i < x86.op_count; i++) {
            const auto& op = x86.operands[i];
            if (op.type == X86_OP_MEM && (op.access & CS_AC_WRITE) && op.mem.base == X86_REG_RSP && op.mem.index == X86_REG_INVALID && op.mem.disp >= 0x20 &&
                op.mem.disp < 0x40 && op.mem.disp % 8 == 0 && op.size >= 4)
                writes |= static_cast<uint8>(1u << (4 + (op.mem.disp - 0x20) / 8));
            if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE) && GetX64RegisterFamily(op.reg) == 4)
                moves = true;
        }
        for (uint8 i = 0; i < insn.detail->regs_write_count; i++)
            moves = moves || GetX64RegisterFamily(insn.detail->regs_write[i]) == 4;
        return { writes, moves };
    }

    // the prototype of the callee of a step kept by the first round of InferPrototypes, as CalleePrototype gives it now (the prototypes
    // inferred by the later rounds, the COM methods of TrackComInterfaces, the methods of GCC): the target again; an import slot: the API
    const AsmFunctionDetails* CurrentCalleeOf(const ArgumentStep& step)
    {
        if (const auto method = interfaceCalls.find(step.address); method != interfaceCalls.end())
            if (const auto* prototype = FindComMethodPrototype(method->second))
                return prototype;
        if (step.callTarget == NO_TARGET)
            return step.callee;
        if (step.callTarget < codeSize) {
            if (const auto* user = zone->FindUserPrototype(step.callTarget))
                return user;
            if (const auto inferred = inferredPrototypes.find(step.callTarget); inferred != inferredPrototypes.end()) {
                const auto* api = FindApiPrototype(TargetName(step.callTarget));
                return api ? api : &inferred->second->details;
            }
        }
        const std::string name = TargetName(step.callTarget);
        if (const auto* api = FindApiPrototype(name))
            return api;
        return FindMethodPrototypeByName(methodPrototypes, name);
    }

    // `callee`: the prototype of a call / a jump out of the function when the caller looked it up already (CalleePrototype)
    ArgumentStep DecodeArgumentStep(
          const cs_insn& insn, uint64 start, uint64 end, DissasmArch arch, std::optional<const AsmFunctionDetails*> callee = std::nullopt)
    {
        const bool isArm64 = arch == DissasmArch::Arm64;
        ArgumentStep step{ insn.address, NO_TARGET, nullptr, NO_TARGET, 0, ArgumentStepKind::Other };
        const auto flow = GetInstructionFlow(insn, arch);
        if (flow == X86Flow::Call && !(isArm64 && stackHelperCalls.contains(insn.address))) { // bl __chkstk keeps the arguments
            const auto operands = GetInstructionOperands(insn, arch, labelBase);
            step.kind           = ArgumentStepKind::Call;
            step.callee         = callee.has_value() ? callee.value() : CalleePrototype(insn, arch);
            step.callTarget     = operands.directTarget.has_value() ? operands.directTarget.value() & addressMask : NO_TARGET;
        } else if (flow == X86Flow::Jump || flow == X86Flow::ConditionalJump) {
            const auto operands = GetInstructionOperands(insn, arch, labelBase);
            const uint64 direct = operands.directTarget.has_value() ? operands.directTarget.value() & addressMask : NO_TARGET;
            const bool inside   = direct >= start && direct < end;
            step.callTarget     = inside ? NO_TARGET : direct;
            step.target         = inside ? direct : NO_TARGET;
            if (flow == X86Flow::ConditionalJump) {
                step.kind = ArgumentStepKind::ConditionalJump;
            } else if (inside) {
                step.kind = ArgumentStepKind::Jump;
            } else {
                step.callee = callee.has_value() ? callee.value() : CalleePrototype(insn, arch);
                step.kind   = direct != NO_TARGET || step.callee ? ArgumentStepKind::TailCall : ArgumentStepKind::IndirectJump;
            }
        } else if (flow == X86Flow::Return) {
            step.kind = ArgumentStepKind::Return;
        } else if (isArm64) {
            for (uint8 i = 0; i < insn.detail->arm64.op_count; i++)
                if (insn.detail->arm64.operands[i].type == ARM64_OP_REG && (insn.detail->arm64.operands[i].access & CS_AC_WRITE))
                    if (const int argument = ArgumentRegisterOf(insn.detail->arm64.operands[i].reg, arch); argument >= 0)
                        step.writes |= static_cast<uint8>(1u << argument);
        } else {
            const cs_x86& x86 = insn.detail->x86;
            for (uint8 i = 0; i < x86.op_count; i++)
                if (x86.operands[i].type == X86_OP_REG && (x86.operands[i].access & CS_AC_WRITE))
                    if (const int argument = ArgumentRegisterOf(x86.operands[i].reg, arch); argument >= 0)
                        step.writes |= static_cast<uint8>(1u << argument);
            for (uint8 i = 0; i < insn.detail->regs_write_count; i++)
                if (const int argument = ArgumentRegisterOf(insn.detail->regs_write[i], arch); argument >= 0)
                    step.writes |= static_cast<uint8>(1u << argument);
            const auto [stackWrites, movesStack] = ArgumentStackWrites(insn, arch);
            step.writes |= stackWrites;
            step.movesStack = movesStack;
        }
        return step;
    }

    void CollectArgumentDefinitions()
    {
        argumentDefinitions.clear();
        if (!hasDetailHandle || functionEnds.size() != functionStarts.size())
            return;
        std::unordered_map<uint64, bool> targetsWithPrototype; // a direct target (relative) -> it has a prototype (the user's, an API, inferred)
        const auto hasPrototype = [&](const FlowRecord& record) {
            if (knownPrototypeCalls.contains(record.address) || demangledPrototypeCalls.contains(record.address))
                return true; // through the slot of an import with a prototype (a demangled C++ name too)
            if (HasComMethodPrototype(record.address))
                return true; // the method of a COM interface (call [rax + 0x18], the CFG dispatch of x64)
            if (record.target == NO_TARGET)
                return false;
            if (HasOtherZonePrototype(record.target, zone->GetArchAt(record.address)))
                return true; // a function of another code zone (its inferred prototype, the user's)
            auto known = targetsWithPrototype.find(record.target);
            if (known == targetsWithPrototype.end()) {
                const std::string name = TargetName(record.target);
                const bool prototype   = inferredPrototypes.contains(record.target) || (record.target < codeSize && zone->FindUserPrototype(record.target)) ||
                                       (!name.empty() && (FindApiPrototype(name) || FindMethodPrototypeByName(methodPrototypes, name)));
                known = targetsWithPrototype.emplace(record.target, prototype).first;
            }
            return known->second;
        };
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index], end = functionEnds[index];
            const auto arch = zone->GetArchAt(start);
            if (arch == DissasmArch::X86) {
                CollectX86JumpedPushes(start, end, hasPrototype);
                continue;
            }
            if (arch != DissasmArch::X64 && arch != DissasmArch::Arm64)
                continue;
            // something to find: a tail jump with a prototype, or a call with one whose code after the call before it (the writes a call does
            // not end) holds the target of a forward branch: a branch carries arguments only there; the records are sorted by address
            bool found = false;
            forwardTargets.clear();
            const size_t first = FirstRecordAt(start);
            for (size_t position = first; position < flowRecords.size() && flowRecords[position].address < end; position++) {
                const auto& record = flowRecords[position];
                if ((record.kind == FlowKind::Jump || record.kind == FlowKind::ConditionalJump) && record.target != NO_TARGET &&
                    record.target > record.address && record.target < end)
                    forwardTargets.push_back(record.target);
            }
            std::sort(forwardTargets.begin(), forwardTargets.end());
            uint64 previousCall = start; // the code after it
            uint64 blockStart   = start; // after the last call / jmp / ret: the code the walk of the display goes through to a call
            for (size_t position = first; position < flowRecords.size() && flowRecords[position].address < end && !found; position++) {
                const auto& record = flowRecords[position];
                const bool inside  = record.target != NO_TARGET && record.target >= start && record.target < end;
                if (record.kind == FlowKind::Call) {
                    const auto target = std::upper_bound(forwardTargets.begin(), forwardTargets.end(), previousCall);
                    // a forward branch target before it, or more code before it than the walk of the display looks back through
                    const bool far = record.address - blockStart >= FAR_CALL_BYTES && argumentStepsOf.contains(start);
                    found          = ((target != forwardTargets.end() && *target <= record.address) || far) && hasPrototype(record);
                    previousCall   = record.address;
                } else if (record.kind == FlowKind::Jump && !inside) {
                    found = record.target == NO_TARGET || hasPrototype(record); // a tail jump (through an import slot: jmp TerminateProcess)
                }
                if (record.kind != FlowKind::ConditionalJump)
                    blockStart = record.address + record.size;
            }
            if (found)
                CollectFunctionArgumentDefinitions(start, end, arch);
        }
        argumentStepsOf.clear();
    }

    void CollectFunctionArgumentDefinitions(uint64 start, uint64 end, DissasmArch arch)
    {
        constexpr uint32 MAX_STEPS      = 4096; // as InferFunctionPrototype
        constexpr uint8 MAX_DEFINITIONS = 8;    // the writes of a register followed at once (more: forgotten, none of them named)
        // Windows x64: the four registers, then the stack slots of the fifth .. eighth arguments (ArgumentStackWrites)
        const size_t argumentsCount     = arch == DissasmArch::Arm64 ? 8u : (zone->systemVCalls ? 6u : 8u);
        const size_t registersCount     = arch == DissasmArch::Arm64 ? 8u : (zone->systemVCalls ? 6u : 4u);
        using Step                      = ArgumentStep;
        using StepKind                  = ArgumentStepKind;

        // the code of the function: the steps the first round of InferPrototypes kept, else decoded here
        std::vector<Step> decoded;
        const auto kept = argumentStepsOf.find(start);
        if (kept == argumentStepsOf.end()) {
            const auto data =
                  start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x10000)), false) : BufferView{};
            cs_insn* insn = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
            if (!insn)
                return;
            const uint8* bytes = data.GetData();
            size_t size        = data.GetLength();
            uint64 address     = start;
            while (decoded.size() < MAX_STEPS && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
                decoded.push_back(DecodeArgumentStep(*insn, start, end, arch));
                if (decoded.back().kind == StepKind::Return && insn->address + insn->size >= end)
                    break;
            }
            cs_free(insn, 1);
        }
        if (kept != argumentStepsOf.end()) // their callees as they are known now
            for (auto& step : kept->second)
                if (step.kind == StepKind::Call || step.kind == StepKind::TailCall)
                    step.callee = CurrentCalleeOf(step);
        const std::vector<Step>& steps = kept != argumentStepsOf.end() ? kept->second : decoded;

        // the branches inside of the function: the step of their target (a branch back: at most its own step; the steps are sorted by address),
        // the forward ones by target
        std::vector<size_t> targetOf(steps.size(), SIZE_MAX);
        std::unordered_map<size_t, std::vector<size_t>> branchesTo; // step of the target -> the steps of the forward branches
        for (size_t i = 0; i < steps.size(); i++)
            if (steps[i].target != NO_TARGET) {
                const auto target =
                      std::lower_bound(steps.begin(), steps.end(), steps[i].target, [](const Step& step, uint64 value) { return step.address < value; });
                if (target != steps.end() && target->address == steps[i].target) {
                    targetOf[i] = static_cast<size_t>(target - steps.begin());
                    if (targetOf[i] > i)
                        branchesTo[targetOf[i]].push_back(i);
                }
            }

        // what each write reaches: the parameter of the calls (one name, else a conflict), along the code that falls into them or through a jump
        struct Reach {
            std::string_view function, parameter;
            // linear: along the code that falls into a call within FAR_ARGUMENT_STEPS instructions (the display names it); far: farther
            bool linear = false, far = false, jumped = false, rejected = false;
        };
        std::unordered_map<uint32, Reach> reaches;
        struct Definitions { // the writes of a register that reach the current step, whether a branch was taken on the way (a bit each)
            std::array<uint32, MAX_DEFINITIONS> steps;
            uint8 count  = 0;
            uint8 jumped = 0;
        };
        using State       = std::array<Definitions, 8>;
        const auto reject = [&reaches](const Definitions& definitions) {
            for (uint8 k = 0; k < definitions.count; k++)
                reaches[definitions.steps[k]].rejected = true;
        };
        const auto add = [&](Definitions& into, uint32 step, bool jumped) {
            for (uint8 k = 0; k < into.count; k++)
                if (into.steps[k] == step) {
                    into.jumped |= static_cast<uint8>(jumped ? 1u << k : 0u);
                    return true;
                }
            if (into.count == MAX_DEFINITIONS)
                return false;
            into.steps[into.count] = step;
            into.jumped |= static_cast<uint8>(jumped ? 1u << into.count : 0u);
            into.count++;
            return true;
        };
        State state{};
        std::unordered_map<size_t, State> snapshots; // the state at each forward branch (before it)
        bool reachable = true;
        for (size_t i = 0; i < steps.size(); i++) {
            const auto& step = steps[i];
            if (const auto branches = branchesTo.find(i); branches != branchesTo.end()) {
                State merged{};
                if (reachable)
                    merged = state;
                uint8 overflow = 0; // the registers with too many writes: none of them is named
                for (const size_t source : branches->second) {
                    const State& from = snapshots.at(source);
                    for (size_t argument = 0; argument < argumentsCount; argument++) {
                        if (!(overflow & (1u << argument)))
                            for (uint8 k = 0; k < from[argument].count; k++)
                                if (!add(merged[argument], from[argument].steps[k], true)) {
                                    reject(merged[argument]);
                                    merged[argument] = Definitions{};
                                    overflow |= static_cast<uint8>(1u << argument);
                                    break;
                                }
                        if (overflow & (1u << argument))
                            reject(from[argument]);
                    }
                }
                state = merged;
            } else if (!reachable) {
                state = State{};
            }
            if ((step.kind == StepKind::Call || step.kind == StepKind::TailCall) && step.callee) {
                const auto& params = step.callee->params;
                // a tail jump: its stack arguments are above the return address of the caller (not followed)
                const size_t followed = step.kind == StepKind::TailCall ? registersCount : argumentsCount;
                for (size_t parameter = 0; parameter < params.size() && parameter < followed; parameter++) {
                    // the text the display shows: the name, else the type (a demangled C++ name: wchar_t*)
                    const char* text = params[parameter].name && params[parameter].name[0] ? params[parameter].name : params[parameter].type;
                    if (!text || !text[0])
                        continue; // a parameter an inferred prototype does not know
                    const auto& definitions = state[parameter];
                    for (uint8 k = 0; k < definitions.count; k++) {
                        auto& reach = reaches[definitions.steps[k]];
                        if (!reach.parameter.empty() && (reach.parameter != text || reach.function != step.callee->functionName))
                            reach.rejected = true; // two calls take it as two parameters
                        reach.function  = step.callee->functionName;
                        reach.parameter = text;
                        // the display names a write that falls into the block of a call (not past the lines it looks back through); a tail
                        // jump has no argument names of its own
                        if ((definitions.jumped & (1u << k)) || step.kind == StepKind::TailCall)
                            reach.jumped = true;
                        else if (i - definitions.steps[k] > FAR_ARGUMENT_STEPS)
                            reach.far = true;
                        else
                            reach.linear = true;
                    }
                }
            }
            if (step.kind == StepKind::IndirectJump || targetOf[i] <= i) // a switch / a branch back: the calls it reaches there are not followed
                for (size_t argument = 0; argument < argumentsCount; argument++)
                    reject(state[argument]);
            if (step.kind == StepKind::Call)
                state = State{}; // the argument registers are volatile (the stack slots: the frame of the callee)
            if (step.movesStack) // another depth: the writes of the stack slots before it are no arguments of the calls after it
                for (size_t argument = registersCount; argument < argumentsCount; argument++)
                    state[argument] = Definitions{};
            if (step.writes)
                for (size_t argument = 0; argument < argumentsCount; argument++)
                    if (step.writes & (1u << argument)) {
                        state[argument]          = Definitions{};
                        state[argument].steps[0] = static_cast<uint32>(i);
                        state[argument].count    = 1;
                    }
            if (targetOf[i] != SIZE_MAX && targetOf[i] > i)
                snapshots[i] = state;
            reachable = step.kind != StepKind::Return && step.kind != StepKind::Jump && step.kind != StepKind::TailCall && step.kind != StepKind::IndirectJump;
        }
        for (const auto& [index, reach] : reaches)
            if ((reach.jumped || reach.far) && !reach.linear && !reach.rejected && !reach.parameter.empty())
                argumentDefinitions.emplace(steps[index].address, std::make_pair(std::string(reach.function), std::string(reach.parameter)));
    }

    // 32 bit x86: the arguments of a call pushed in a block that jumps to it (push esi; push 0x6a012e; jmp loc_X ... loc_X: call
    // CSPrintErrorLineFile: the shared error paths of MSVC, before or after the block). The stack pointer at the jmp is the one at its target,
    // so the pushes of the block before the jmp are the arguments of the call after the ones pushed from the target on. The block: from the
    // branch / call before the jmp; the target: up to its first call, without another branch or write of the stack pointer on the way. The
    // walk of the display stops at the jmp (AnnounceCallInstruction): no push is named twice. A variadic callee whose format is pushed in the
    // block (push offset aWs; jmp loc_X ... loc_X: call sub_4CBAD9): the pushes after it take the conversions of the string (ReadFormatTexts)
    template <typename HasPrototype>
    void CollectX86JumpedPushes(uint64 start, uint64 end, const HasPrototype& hasPrototype)
    {
        constexpr uint64 MAX_BLOCK = 0x200; // the bytes decoded before a jmp, from its target to the call
        // the pushes of [from, to) as the walk sees them: a push, the pushes another instruction takes back (pop, add esp, imm), or a write of
        // the stack pointer that ends the walk; nothing when the code does not end at `to`
        enum class PushStepKind : uint8 { Push, Taken, Moved };
        struct PushStep {
            uint64 address;
            PushStepKind kind;
            uint32 taken;
            uint64 immediate = NO_TARGET; // push imm: the value pushed
        };
        std::vector<PushStep> pushSteps;
        cs_insn* insn = nullptr;
        // the call ending a decoded range of the target: its prototype
        const AsmFunctionDetails* callee = nullptr;

        const auto decode = [&](uint64 from, uint64 to, bool toCall) {
            pushSteps.clear();
            callee          = nullptr;
            const auto data = obj->GetData().Get(codeStart + from, static_cast<uint32>(to - from), false);
            if (!data.IsValid() || data.GetLength() != to - from)
                return false;
            const uint8* bytes = data.GetData();
            size_t size        = data.GetLength();
            uint64 address     = from;
            while (address < to && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
                const cs_x86& x86 = insn->detail->x86;
                if (toCall && address == to)
                    return insn->id == X86_INS_CALL && (callee = CalleePrototype(*insn, DissasmArch::X86)) != nullptr;
                if (insn->id == X86_INS_PUSH) {
                    const bool constant = x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM;
                    pushSteps.push_back(
                          { insn->address, PushStepKind::Push, 0, constant ? static_cast<uint64>(x86.operands[0].imm) & 0xFFFFFFFFull : NO_TARGET });
                    continue;
                }
                if (GetInstructionFlow(*insn, DissasmArch::X86) != X86Flow::None)
                    return false; // the decoding does not take the path of the records
                uint32 taken = insn->id == X86_INS_POP ? 1u : 0u;
                bool moved   = insn->id != X86_INS_POP && insn->id != X86_INS_PUSH && insn->id != X86_INS_LEA &&
                             std::find(insn->detail->regs_write, insn->detail->regs_write + insn->detail->regs_write_count, X86_REG_ESP) !=
                                   insn->detail->regs_write + insn->detail->regs_write_count; // pushad, leave, enter
                for (uint8 index = 0; index < x86.op_count; index++)
                    if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE) &&
                        (x86.operands[index].reg == X86_REG_ESP || x86.operands[index].reg == X86_REG_SP)) {
                        const bool added = insn->id == X86_INS_ADD && index == 0 && x86.op_count == 2 && x86.operands[1].type == X86_OP_IMM &&
                                           x86.operands[1].imm > 0 && x86.operands[1].imm % 4 == 0 && x86.operands[1].imm < 0x1000;
                        if (added)
                            taken = static_cast<uint32>(x86.operands[1].imm / 4);
                        else
                            moved = true;
                    }
                if (moved)
                    pushSteps.push_back({ insn->address, PushStepKind::Moved, 0 });
                else if (taken)
                    pushSteps.push_back({ insn->address, PushStepKind::Taken, taken });
            }
            return !toCall && address == to;
        };
        const size_t first = FirstRecordAt(start);
        for (size_t position = first; position < flowRecords.size() && flowRecords[position].address < end; position++) {
            const auto& jump = flowRecords[position];
            if (jump.kind != FlowKind::Jump || jump.target == NO_TARGET || jump.target < start || jump.target >= end)
                continue;
            // the call the target reaches first: no other branch on the way
            const size_t next = FirstRecordAt(jump.target);
            if (next >= flowRecords.size() || flowRecords[next].kind != FlowKind::Call || flowRecords[next].address >= end ||
                flowRecords[next].address - jump.target > MAX_BLOCK || !hasPrototype(flowRecords[next]))
                continue;
            const uint64 blockStart = position > first ? flowRecords[position - 1].address + flowRecords[position - 1].size : start;
            if (blockStart >= jump.address || jump.address - blockStart > MAX_BLOCK)
                continue; // no instruction before the jmp in its block
            if (!insn && !(insn = cs_malloc(detailHandle)))
                return;
            // the pushes from the target to the call: the first arguments
            const auto& call = flowRecords[next];
            if (!decode(jump.target, call.address + call.size, true) || !callee)
                continue;
            const AsmFunctionDetails* prototype = callee;
            uint32 slot                         = 0;
            bool plain                          = true;
            for (const auto& step : pushSteps)
                if (step.kind == PushStepKind::Push)
                    slot++;
                else
                    plain = false;
            if (!plain || slot >= prototype->params.size() || !decode(blockStart, jump.address, false))
                continue;
            // the block before the jmp, walked back: the next arguments (the pushes taken back by a pop / add esp are not); after the parameters
            // of a variadic callee, the conversions of its format when the block pushes it
            const bool variadic = std::string_view(prototype->prototype).find("...") != std::string_view::npos;
            std::vector<std::string> conversions;
            uint32 taken = 0;
            for (auto step = pushSteps.rbegin(); step != pushSteps.rend(); ++step) {
                if (step->kind == PushStepKind::Moved)
                    break;
                if (step->kind == PushStepKind::Taken) {
                    taken += step->taken;
                    continue;
                }
                if (taken > 0) {
                    taken--;
                    continue;
                }
                if (slot >= prototype->params.size()) {
                    const size_t index = slot++ - prototype->params.size();
                    if (index >= conversions.size())
                        break;
                    if (!conversions[index].empty())
                        argumentDefinitions.emplace(step->address, std::make_pair(std::string(prototype->functionName), conversions[index]));
                    continue;
                }
                const auto& parameter = prototype->params[slot++];
                if (parameter.name && parameter.name[0]) // not a parameter an inferred prototype does not know
                    argumentDefinitions.emplace(step->address, std::make_pair(std::string(prototype->functionName), std::string(parameter.name)));
                if (variadic && slot == prototype->params.size() && step->immediate != NO_TARGET)
                    conversions = ReadFormatTexts(step->immediate, parameter.type, prototype->functionName);
            }
        }
        if (insn)
            cs_free(insn, 1);
    }

    // 32 bit x86: the conversions of the format string at `address` (a VA of the file, pushed): one text per slot of the arguments after it
    // (GetFormatArgumentTexts); UTF-16 for a type of wide characters (wchar_t, WSTR, WCHAR); none when the string is not in the file
    std::vector<std::string> ReadFormatTexts(uint64 address, const char* type, std::string_view functionName)
    {
        constexpr uint32 MAX_BYTES = 0x200;
        const auto offset          = addressToFileOffset ? addressToFileOffset(address) : std::nullopt;
        if (!offset.has_value())
            return {};
        const std::string_view typeText = type ? type : "";
        const bool wide                 = typeText.find("wchar_t") != std::string_view::npos || typeText.find("WSTR") != std::string_view::npos ||
                          typeText.find("WCHAR") != std::string_view::npos;
        const auto data = obj->GetData().Get(offset.value(), MAX_BYTES, false);
        if (!data.IsValid())
            return {};
        std::string text;
        bool ended = false;
        for (size_t index = 0; index + (wide ? 1 : 0) < data.GetLength(); index += wide ? 2 : 1) {
            const uint8 c = data.GetData()[index];
            if (c == 0 && (!wide || data.GetData()[index + 1] == 0)) {
                ended = true;
                break;
            }
            if ((wide && data.GetData()[index + 1] != 0) || (c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c >= 0x7F)
                return {}; // not a text of the format
            text.push_back(static_cast<char>(c));
        }
        if (!ended)
            return {};
        return GetFormatArgumentTexts(text, functionName.find("scanf") != std::string_view::npos, true, false);
    }

    // a cmp of a register with a constant (cmp eax, 0x102 / cmp w0, #0x102 / cmn x0, #1: -1) when the register holds the return value of a
    // callee of the walk: the name of the constant after the callee (FormatApiReturnConstant)
    void RecordReturnComparison(uint64 address, int8 value, const std::vector<const AsmFunctionDetails*>& callees, int64 constant)
    {
        if (value > RETURNED_BY || static_cast<size_t>(RETURNED_BY - value) >= callees.size())
            return;
        if (auto text = FormatApiReturnConstant(*callees[RETURNED_BY - value], static_cast<uint64>(constant)); !text.empty())
            functionComparisons.emplace_back(address, std::move(text));
    }

    // beyond IDA (its decompiler with the types): the methods of the COM interfaces. A function that calls an API giving an interface
    // (FindComProducer: CoCreateInstance and its IID) is followed in its order (x86 / x64 Windows): the registers / the variables of the
    // frame hold an address of data (lea rdx, IID_X / push offset IID_X), the address of a variable (lea r9, [rbp + var_8]: the ppv), an
    // object of an interface, its vtable (mov rax, [rcx]) or one of its methods (mov rax, [rax + 0x18]: the CFG dispatch, call esi). A call
    // through the vtable names the method (FindComMethod), the interface it gives goes to the variable of its parameter (QueryInterface by
    // its IID, ConnectServer -> IWbemServices). An IID that is not known: IUnknown (QueryInterface, AddRef, Release are always known)
    struct ComValue {
        enum class Kind : uint8 { None, Data, SlotAddress, Object, Vtable, Method };
        Kind kind = Kind::None;
        uint64 data = 0;                    // Data: the VA; SlotAddress: the key of the variable
        std::string_view interfaceName;     // Object / Vtable / Method
        uint32 method = 0;                  // Method: its index
    };

    void TrackComInterfaces()
    {
        interfaceCalls.clear();
        comOutputs.clear();
        cfgCheckCalls.clear();
        if (!hasDetailHandle || functionEnds.size() != functionStarts.size() || zone->IsArmCode() || zone->systemVCalls || comProducerCalls.empty())
            return;
        std::unordered_set<uint64> producerTargets; // the thunks / functions of the file named after a producer
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            bool candidate     = false;
            for (size_t position = FirstRecordAt(start); position < flowRecords.size() && flowRecords[position].address < functionEnds[index] && !candidate;
                 position++) {
                const auto& record = flowRecords[position];
                candidate          = record.kind == FlowKind::Call && comProducerCalls.contains(record.address);
            }
            if (candidate)
                TrackComInterfacesOf(start, functionEnds[index]);
        }
    }

    void TrackComInterfacesOf(uint64 start, uint64 end)
    {
        constexpr uint32 MAX_INSTRUCTIONS = 8192;
        const uint32 pointerSize          = is64 ? 8 : 4;
        const auto data = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x20000)), false) : BufferView{};
        cs_insn* insn   = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return;
        std::array<ComValue, 16> registers{};
        std::map<uint64, ComValue> slots; // the variables of the frame: (base register, displacement)
        std::vector<ComValue> pushes;     // x86: the pushed arguments, in their order
        const auto slotKey = [this](const x86_op_mem& memory) -> std::optional<uint64> {
            if (memory.index != X86_REG_INVALID || memory.segment != X86_REG_INVALID)
                return std::nullopt;
            uint64 baseId = 0;
            if (memory.base == X86_REG_RBP || memory.base == X86_REG_EBP)
                baseId = 1;
            else if (memory.base == X86_REG_RSP && is64) // x86: esp moves with the pushes
                baseId = 2;
            else
                return std::nullopt;
            return (baseId << 48) | (static_cast<uint64>(memory.disp) & 0xFFFFFFFFFFFFull);
        };
        const auto family = [](unsigned int reg) { return GetX64RegisterFamily(reg); };
        const auto readGuidInterface = [this](const ComValue& value) -> std::string_view {
            if (value.kind != ComValue::Kind::Data)
                return {};
            // the file offset of the VA; inside of this zone without the translation of the plugin
            std::optional<uint64> offset = addressToFileOffset ? addressToFileOffset(value.data) : std::nullopt;
            if (!offset.has_value() && value.data >= labelBase && value.data - labelBase + 16 <= codeSize)
                offset = codeStart + (value.data - labelBase);
            if (!offset.has_value())
                return {};
            const auto bytes = obj->GetData().Get(offset.value(), 16, true);
            if (!bytes.IsValid() || bytes.GetLength() < 16)
                return {};
            const std::string_view known = FindInterfaceOfIid(bytes.GetData());
            return known.empty() ? std::string_view("IUnknown") : known; // an IID: a COM object at least
        };
        // the argument of a call (x64: rcx, rdx, r8, r9, then the stack; x86: the pushes, the last one first)
        const auto argument = [&](uint32 index) -> ComValue {
            if (is64) {
                static constexpr int REGISTERS[] = { 1, 2, 8, 9 };
                if (index < 4)
                    return registers[REGISTERS[index]];
                const auto slot = slots.find((2ull << 48) | ((0x20ull + 8ull * (index - 4)) & 0xFFFFFFFFFFFFull));
                return slot != slots.end() ? slot->second : ComValue{};
            }
            return index < pushes.size() ? pushes[pushes.size() - 1 - index] : ComValue{};
        };
        const auto giveInterface = [&](const ComValue& out, std::string_view interfaceName) {
            if (out.kind == ComValue::Kind::SlotAddress && !interfaceName.empty())
                slots[out.data] = ComValue{ ComValue::Kind::Object, 0, interfaceName, 0 };
        };
        const auto valueOfOperand = [&](const cs_x86_op& op) -> ComValue {
            if (op.type == X86_OP_REG) {
                const int reg = family(op.reg);
                return reg >= 0 && reg < 16 ? registers[reg] : ComValue{};
            }
            if (op.type == X86_OP_IMM && !is64 && isFileAddress && isFileAddress(static_cast<uint64>(op.imm) & 0xFFFFFFFFull))
                return ComValue{ ComValue::Kind::Data, static_cast<uint64>(op.imm) & 0xFFFFFFFFull, {}, 0 }; // push offset IID_X
            if (op.type == X86_OP_MEM)
                if (const auto key = slotKey(op.mem); key.has_value())
                    if (const auto slot = slots.find(key.value()); slot != slots.end())
                        return slot->second;
            return {};
        };
        const auto clobberVolatile = [&]() {
            // static arrays: the arrays of two braced lists in a ?: end with the expression, before the loop reads them
            static constexpr int VOLATILE_X64[] = { 0, 1, 2, 8, 9, 10, 11 }, VOLATILE_X86[] = { 0, 1, 2 };
            for (const int reg : is64 ? std::span<const int>(VOLATILE_X64) : std::span<const int>(VOLATILE_X86))
                registers[reg] = {};
        };

        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = start;
        for (uint32 decoded = 0; decoded < MAX_INSTRUCTIONS && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn); decoded++) {
            const cs_x86& x86 = insn->detail->x86;
            const auto flow   = GetInstructionFlow(*insn, is64 ? DissasmArch::X64 : DissasmArch::X86);
            if (flow == X86Flow::Call) {
                // the method of a vtable: call [rax + 0x18] / call rax / call esi, or the CFG dispatch of x64 (the target in rax)
                std::optional<std::pair<std::string_view, uint32>> method;
                const auto& target = x86.operands[0];
                if (x86.op_count == 1 && target.type == X86_OP_MEM && target.mem.index == X86_REG_INVALID && family(target.mem.base) >= 0 &&
                    family(target.mem.base) < 16 && registers[family(target.mem.base)].kind == ComValue::Kind::Vtable && target.mem.disp >= 0 &&
                    target.mem.disp % pointerSize == 0)
                    method = std::make_pair(registers[family(target.mem.base)].interfaceName, static_cast<uint32>(target.mem.disp / pointerSize));
                else if (x86.op_count == 1 && target.type == X86_OP_REG && family(target.reg) >= 0 && family(target.reg) < 16 &&
                         registers[family(target.reg)].kind == ComValue::Kind::Method)
                    method = std::make_pair(registers[family(target.reg)].interfaceName, registers[family(target.reg)].method);
                else if (is64 && registers[0].kind == ComValue::Kind::Method)
                    method = std::make_pair(registers[0].interfaceName, registers[0].method); // the CFG dispatch: call cs:__guard_dispatch_icall_fptr / its thunk
                else if (!is64 && target.type == X86_OP_MEM && registers[1].kind == ComValue::Kind::Method) {
                    cfgCheckCalls.insert(insn->address);
                    continue; // the CFG check of x86 (mov ecx, esi; call __guard_check_icall_fptr): it keeps the registers, the pushes are the method's
                }
                if (method.has_value()) {
                    if (const auto found = FindComMethod(method->first, method->second); found.has_value()) {
                        interfaceCalls[insn->address] = std::string(found->first) + "::" + std::string(found->second.name);
                        // the interface it gives (this is the argument 0 of the call)
                        const auto& described = found->second;
                        if (described.outParameter >= 0) {
                            std::string_view given = described.outInterface;
                            if (given.empty() && described.riidParameter >= 0)
                                given = readGuidInterface(argument(1u + described.riidParameter));
                            giveInterface(argument(1u + described.outParameter), given);
                            if (!given.empty())
                                comOutputs[insn->address] = { 1u + described.outParameter, given }; // This is the parameter 0
                        }
                    }
                } else if (comProducerCalls.contains(insn->address)) {
                    // CoCreateInstance / QueryService ...: the API by its name
                    if (const auto* producer = FindComProducer(CalleeName(*insn, is64 ? DissasmArch::X64 : DissasmArch::X86))) {
                        std::string_view given = producer->outInterface;
                        if (given.empty() && producer->riidParameter >= 0)
                            given = readGuidInterface(argument(producer->riidParameter));
                        if (producer->outParameter >= 0)
                            giveInterface(argument(producer->outParameter), given);
                        if (producer->outParameter >= 0 && !given.empty())
                            comOutputs[insn->address] = { static_cast<size_t>(producer->outParameter), given };
                        clobberVolatile();
                        pushes.clear();
                        if (producer->outParameter < 0 && !given.empty())
                            registers[0] = ComValue{ ComValue::Kind::Object, 0, given, 0 }; // SHCreateMemStream: in rax / eax
                        continue;
                    }
                }
                clobberVolatile();
                pushes.clear();
                continue;
            }
            if (flow == X86Flow::Jump || flow == X86Flow::Return) {
                registers.fill(ComValue{}); // the code after it comes from elsewhere; the variables stay
                pushes.clear();
                continue;
            }
            const auto destination = x86.op_count > 0 && x86.operands[0].type == X86_OP_REG ? family(x86.operands[0].reg) : -1;
            if (insn->id == X86_INS_PUSH && x86.op_count == 1) {
                pushes.push_back(valueOfOperand(x86.operands[0]));
                continue;
            }
            if (insn->id == X86_INS_LEA && x86.op_count == 2 && destination >= 0 && destination < 16) {
                const auto& memory = x86.operands[1].mem;
                ComValue value;
                if (const auto key = slotKey(memory); key.has_value())
                    value = ComValue{ ComValue::Kind::SlotAddress, key.value(), {}, 0 }; // lea r9, [rbp + var_8]
                else if (memory.base == X86_REG_RIP && memory.index == X86_REG_INVALID)
                    value = ComValue{ ComValue::Kind::Data, (labelBase + insn->address + insn->size + static_cast<uint64>(memory.disp)) & addressMask, {}, 0 };
                else if (!is64 && memory.base == X86_REG_INVALID && memory.index == X86_REG_INVALID)
                    value = ComValue{ ComValue::Kind::Data, static_cast<uint64>(memory.disp) & 0xFFFFFFFFull, {}, 0 };
                registers[destination] = value;
                continue;
            }
            if (insn->id == X86_INS_MOV && x86.op_count == 2) {
                const auto& to   = x86.operands[0];
                const auto& from = x86.operands[1];
                if (to.type == X86_OP_MEM) { // a variable written: what it holds now
                    if (const auto key = slotKey(to.mem); key.has_value()) {
                        const ComValue value = valueOfOperand(from);
                        if (value.kind == ComValue::Kind::None)
                            slots.erase(key.value());
                        else
                            slots[key.value()] = value;
                    }
                    continue;
                }
                if (destination >= 0 && destination < 16) {
                    ComValue value;
                    if (from.type == X86_OP_MEM && from.mem.index == X86_REG_INVALID && family(from.mem.base) >= 0 && family(from.mem.base) < 16 &&
                        !slotKey(from.mem).has_value()) {
                        const auto& baseValue = registers[family(from.mem.base)];
                        if (baseValue.kind == ComValue::Kind::Object && from.mem.disp == 0)
                            value = ComValue{ ComValue::Kind::Vtable, 0, baseValue.interfaceName, 0 }; // mov rax, [rcx]
                        else if (baseValue.kind == ComValue::Kind::Vtable && from.mem.disp >= 0 && from.mem.disp % pointerSize == 0)
                            value = ComValue{ ComValue::Kind::Method, 0, baseValue.interfaceName, static_cast<uint32>(from.mem.disp / pointerSize) };
                    } else {
                        value = valueOfOperand(from);
                    }
                    registers[destination] = value;
                    continue;
                }
            }
            // any other write: the register / the variable holds nothing known
            for (uint8 i = 0; i < x86.op_count; i++) {
                const auto& op = x86.operands[i];
                if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE))
                    if (const int reg = family(op.reg); reg >= 0 && reg < 16)
                        registers[reg] = {};
                if (op.type == X86_OP_MEM && (op.access & CS_AC_WRITE))
                    if (const auto key = slotKey(op.mem); key.has_value())
                        slots.erase(key.value());
            }
            for (uint8 i = 0; i < insn->detail->regs_write_count; i++)
                if (const int reg = family(insn->detail->regs_write[i]); reg >= 0 && reg < 16)
                    registers[reg] = {};
        }
        cs_free(insn, 1);
    }

    // the values of the registers / slots of the inference besides an incoming argument (0, 1, ...): nothing known, a constant (xor eax, eax /
    // mov eax, -1 / push 1; pop eax), the return value of a callee with a return type (RETURNED_BY - k: the callee k of the function)
    static constexpr int8 NO_VALUE = -1, CONSTANT_VALUE = -2, RETURNED_BY = -3;
    static constexpr size_t MAX_RETURNING_CALLEES = 100;

    // the value of the return value of a callee: a number for each of the callees of the function; none past MAX_RETURNING_CALLEES
    static int8 ReturnedValueOf(std::vector<const AsmFunctionDetails*>& callees, const AsmFunctionDetails* callee)
    {
        if (!callee || callee->returnType.empty())
            return NO_VALUE;
        auto found = std::find(callees.begin(), callees.end(), callee);
        if (found == callees.end()) {
            if (callees.size() >= MAX_RETURNING_CALLEES)
                return NO_VALUE;
            found = callees.insert(callees.end(), callee);
        }
        return static_cast<int8>(RETURNED_BY - (found - callees.begin()));
    }

    // the value of a register at a branch target from two of the branches to it: the same one, a return value with a constant (xor eax, eax;
    // jmp the epilogue: the error path) the return value; else nothing
    static int8 MergedValue(int8 first, int8 second)
    {
        if (first == second)
            return first;
        if (first == CONSTANT_VALUE && second <= RETURNED_BY)
            return second;
        if (second == CONSTANT_VALUE && first <= RETURNED_BY)
            return first;
        return NO_VALUE;
    }

    // what the function returns: the callee whose return value every return of it holds (a constant too: NULL, -1 on an error path); none
    // when a return holds something else / nothing known
    static const AsmFunctionDetails* AgreedReturn(const std::vector<int8>& returns, const std::vector<const AsmFunctionDetails*>& callees)
    {
        std::optional<int8> agreed;
        for (const int8 value : returns) {
            if (value == CONSTANT_VALUE)
                continue;
            if (value > RETURNED_BY || (agreed.has_value() && agreed.value() != value))
                return nullptr;
            agreed = value;
        }
        return agreed.has_value() ? callees[RETURNED_BY - agreed.value()] : nullptr;
    }

    // `variadicFrame`: the frame of an ARM64 variadic function (DissasmFunctionFrame::variadic, InferVariadicPrototype): its fixed arguments
    // only, the one it passes with its va_list in the next register (vsprintf(buffer, format, va): the format), through the slot it spills it
    // to too (str x1, [sp, #0x10] .. ldr x2, [sp, #0x10]); the depths of its frame give the address of the home of its first variadic
    // register (add x3, sp, #va_x2) or the moved x4 of ARM64EC
    std::shared_ptr<const DissasmUserPrototype> InferFunctionPrototype(
          uint64 start, uint64 end, DissasmArch arch, const DissasmFunctionFrame* variadicFrame = nullptr)
    {
        constexpr uint32 MAX_STEPS     = 4096;
        constexpr int REGISTERS        = 32;
        constexpr int32 UNKNOWN_DEPTH  = INT32_MIN; // the depth of rsp after a write of it that is not followed
        constexpr int32 NO_FRAME_POINTER = INT32_MIN, FRAME_POINTER_LOST = INT32_MIN + 1;
        const bool isArm64             = arch == DissasmArch::Arm64;
        const auto* variadic           = isArm64 && variadicFrame && variadicFrame->variadic.has_value() ? &variadicFrame->variadic.value() : nullptr;
        const bool isArm32             = arch == DissasmArch::Arm || arch == DissasmArch::Thumb;
        const bool systemV             = !isArm64 && !isArm32 && zone->systemVCalls;
        static constexpr int WINDOWS[] = { 1, 2, 8, 9 }, SYSTEM_V[] = { 7, 6, 2, 1, 8, 9 };
        const size_t argumentsCount    = isArm64 ? 8u : (isArm32 ? 4u : (systemV ? 6u : 4u));
        const auto argumentRegister    = [&](size_t argument) -> int {
            if (isArm64 || isArm32)
                return static_cast<int>(argument);
            return systemV ? SYSTEM_V[argument] : WINDOWS[argument];
        };
        const auto registerIndex = [&](unsigned int reg) -> int {
            if (isArm64) {
                if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
                    return static_cast<int>(reg - ARM64_REG_X0);
                if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
                    return static_cast<int>(reg - ARM64_REG_W0);
                return -1;
            }
            if (isArm32)
                return reg >= ARM_REG_R0 && reg <= ARM_REG_R12 ? static_cast<int>(reg - ARM_REG_R0) : -1;
            return GetX64RegisterFamily(reg);
        };
        // the registers a call changes (the volatile ones of the convention)
        static constexpr int VOLATILE_SYSTEM_V[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 }, VOLATILE_WINDOWS[] = { 0, 1, 2, 8, 9, 10, 11 };
        uint32 volatileMask = 0;
        if (isArm64)
            volatileMask = (1u << 19) - 1u; // x0 .. x18
        else if (isArm32)
            volatileMask = 0xFu | (1u << 12); // r0 .. r3, r12
        else
            for (const int reg : systemV ? std::span<const int>(VOLATILE_SYSTEM_V) : std::span<const int>(VOLATILE_WINDOWS))
                volatileMask |= 1u << reg;

        // the code of the function, once: what every instruction writes, its copy, its branch
        enum class StepKind : uint8 { Other, Call, TailCall, Jump, ConditionalJump, Return };
        struct Step {
            uint64 address;
            uint32 writes;
            int8 copyTo, copyFrom;
            int8 constantTo; // the register it sets to a constant (mov eax, 1 / xor eax, eax / mov w0, #0)
            StepKind kind;
            uint64 target; // a branch inside of the function (relative); NO_TARGET otherwise
            const AsmFunctionDetails* callee;
            int8 comparedRegister = -1; // cmp reg, imm: the register and the constant
            int64 comparedValue   = 0;
            // a variadic function: the register set to its va_list; the register stored to / loaded from a slot of its frame (its offset)
            int8 vaListTo  = -1;
            int8 storeFrom = -1, loadTo = -1;
            int32 slot = 0;
            // x64: a write of the slot [rsp + 8 * index] (index < 16), the register a mov stores there (an argument of the next call)
            int8 outgoingWritten = -1, outgoingFrom = -1;
            // Windows x64 / ARM64: the change of the stack pointer (push, pop, sub / add rsp, imm; sub / add sp, sp, #imm, the writeback of
            // stp x29, x30, [sp, #-0x20]!; UNKNOWN_DEPTH: another write of it); an access of [rsp + stackOffset] / [sp, #n] (stackBase 1) or
            // [x29, #n] (2): the registers it loads (stackLoadTo) or stores (stackStoreFrom; a pair of ARM64: the next slot of stackSize
            // bytes), a write of the slot (stackStore): the incoming arguments after the fourth (x64), the argument registers spilled
            int32 rspChange          = 0;
            int8 stackBase           = 0;
            bool stackStore          = false;
            uint8 stackSize          = 8;
            int32 stackOffset        = 0;
            int8 stackLoadTo[2]      = { -1, -1 };
            int8 stackStoreFrom[2]   = { -1, -1 };
            bool stackAddress        = false;            // lea rcx, [rsp + 0x30] / add x1, sp, #0x18: the address of the slot taken
            int32 framePointerFromSp = NO_FRAME_POINTER; // ARM64: mov x29, sp / add x29, sp, #n (n); FRAME_POINTER_LOST: another write of x29
        };
        std::vector<Step> steps;
        std::vector<std::pair<int32, uint32>> stores; // a variadic function: the slots its code writes (offset, size)
        std::array<std::optional<int64>, 2> scratchConstants; // a variadic function: mov x16, #0x1060 / x17 in the order of the code
        const auto data = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x10000)), false) : BufferView{};
        cs_insn* insn   = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return nullptr;
        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = start;
        const bool keepSteps = keepArgumentSteps && !variadic && (arch == DissasmArch::X64 || isArm64); // CollectArgumentDefinitions
        std::vector<ArgumentStep> argumentSteps;
        while (steps.size() < MAX_STEPS && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
            Step step{ insn->address, 0, -1, -1, -1, StepKind::Other, NO_TARGET, nullptr };
            const auto flow = GetInstructionFlow(*insn, arch);
            const auto operands = GetInstructionOperands(*insn, arch, labelBase);
            const auto inside = [&](uint64 target) { return target >= start && target < end; };
            const uint64 direct = operands.directTarget.has_value() ? operands.directTarget.value() & addressMask : NO_TARGET;
            std::optional<const AsmFunctionDetails*> callee; // CalleePrototype, once
            if (flow == X86Flow::Call && isArm64 && stackHelperCalls.contains(insn->address)) {
                step.writes = (1u << 16) | (1u << 17); // bl __security_push_cookie / __chkstk: x16 / x17 only, the arguments stay
            } else if (flow == X86Flow::Call) {
                step.kind   = StepKind::Call;
                callee      = CalleePrototype(*insn, arch);
                step.callee = IsInferenceCallee(callee.value());
                step.writes = volatileMask;
            } else if (flow == X86Flow::Jump) {
                if (direct != NO_TARGET && inside(direct)) {
                    step.kind   = StepKind::Jump;
                    step.target = direct;
                } else {
                    step.kind   = StepKind::TailCall; // jmp sub_X / jmp [__imp_X] / b sub_X: the arguments are passed on
                    callee      = CalleePrototype(*insn, arch);
                    step.callee = IsInferenceCallee(callee.value());
                }
            } else if (flow == X86Flow::ConditionalJump) {
                step.kind   = StepKind::ConditionalJump;
                step.target = direct != NO_TARGET && inside(direct) ? direct : NO_TARGET;
            } else if (flow == X86Flow::Return) {
                step.kind = StepKind::Return;
            }
            if (step.kind == StepKind::Other || step.kind == StepKind::ConditionalJump) {
                // the registers written (the operands, the implicit ones), a copy reg <- reg
                if (isArm64 || isArm32) {
                    const uint8 count = isArm64 ? insn->detail->arm64.op_count : insn->detail->arm.op_count;
                    for (uint8 i = 0; i < count; i++) {
                        const bool isRegister = isArm64 ? insn->detail->arm64.operands[i].type == ARM64_OP_REG : insn->detail->arm.operands[i].type == ARM_OP_REG;
                        const uint8 access    = isArm64 ? insn->detail->arm64.operands[i].access : insn->detail->arm.operands[i].access;
                        const unsigned int reg = isArm64 ? static_cast<unsigned int>(insn->detail->arm64.operands[i].reg) : static_cast<unsigned int>(insn->detail->arm.operands[i].reg);
                        if (const int index = isRegister ? registerIndex(reg) : -1; index >= 0 && index < REGISTERS && (access & CS_AC_WRITE))
                            step.writes |= 1u << index;
                    }
                    // a conditional move (movne r0, r4: an IT block / an ARM condition) is a write, not a copy
                    const bool conditional = isArm32 && insn->detail->arm.cc != ARM_CC_AL && insn->detail->arm.cc != ARM_CC_INVALID;
                    const bool isMove      = (isArm64 ? insn->id == ARM64_INS_MOV : insn->id == ARM_INS_MOV) && !conditional;
                    if (isMove && count == 2) {
                        const bool registers = isArm64 ? insn->detail->arm64.operands[1].type == ARM64_OP_REG : insn->detail->arm.operands[1].type == ARM_OP_REG;
                        const unsigned int to = isArm64 ? static_cast<unsigned int>(insn->detail->arm64.operands[0].reg) : static_cast<unsigned int>(insn->detail->arm.operands[0].reg);
                        const unsigned int from = isArm64 ? static_cast<unsigned int>(insn->detail->arm64.operands[1].reg) : static_cast<unsigned int>(insn->detail->arm.operands[1].reg);
                        if (registers && registerIndex(to) >= 0 && registerIndex(from) >= 0) {
                            step.copyTo   = static_cast<int8>(registerIndex(to));
                            step.copyFrom = static_cast<int8>(registerIndex(from));
                        }
                    }
                    // mov x0, #0 / mov w0, wzr / movn: a constant
                    if (isArm64 && count == 2 && (insn->id == ARM64_INS_MOV || insn->id == ARM64_INS_MOVZ || insn->id == ARM64_INS_MOVN) &&
                        (insn->detail->arm64.operands[1].type == ARM64_OP_IMM ||
                         (insn->detail->arm64.operands[1].type == ARM64_OP_REG &&
                          (insn->detail->arm64.operands[1].reg == ARM64_REG_WZR || insn->detail->arm64.operands[1].reg == ARM64_REG_XZR))))
                        if (const int index = registerIndex(static_cast<unsigned int>(insn->detail->arm64.operands[0].reg)); index >= 0 && index < REGISTERS)
                            step.constantTo = static_cast<int8>(index);
                    // cmp w0, #0x102 / cmn x0, #1
                    if (isArm64 && count == 2 && (insn->id == ARM64_INS_CMP || insn->id == ARM64_INS_CMN) && insn->detail->arm64.operands[0].type == ARM64_OP_REG &&
                        insn->detail->arm64.operands[1].type == ARM64_OP_IMM)
                        if (const int index = registerIndex(static_cast<unsigned int>(insn->detail->arm64.operands[0].reg)); index >= 0 && index < REGISTERS) {
                            step.comparedRegister = static_cast<int8>(index);
                            step.comparedValue    = insn->id == ARM64_INS_CMN ? -insn->detail->arm64.operands[1].imm : insn->detail->arm64.operands[1].imm;
                        }
                    if (variadic && step.kind == StepKind::Other)
                        DecodeVariadicStep(*insn, *variadicFrame, *variadic, step, stores, scratchConstants);
                    if (isArm64)
                        DecodeArm64StackStep(*insn, step);
                } else {
                    const cs_x86& x86 = insn->detail->x86;
                    for (uint8 i = 0; i < x86.op_count; i++)
                        if (x86.operands[i].type == X86_OP_REG && (x86.operands[i].access & CS_AC_WRITE))
                            if (const int index = registerIndex(x86.operands[i].reg); index >= 0 && index < REGISTERS)
                                step.writes |= 1u << index;
                    for (uint8 i = 0; i < insn->detail->regs_write_count; i++)
                        if (const int index = registerIndex(insn->detail->regs_write[i]); index >= 0 && index < REGISTERS)
                            step.writes |= 1u << index;
                    if (insn->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_REG &&
                        x86.operands[0].size >= 4 && x86.operands[1].size >= 4 && registerIndex(x86.operands[0].reg) >= 0 && registerIndex(x86.operands[1].reg) >= 0) {
                        step.copyTo   = static_cast<int8>(registerIndex(x86.operands[0].reg));
                        step.copyFrom = static_cast<int8>(registerIndex(x86.operands[1].reg));
                    }
                    if (const int index = x86.op_count > 0 && x86.operands[0].type == X86_OP_REG ? registerIndex(x86.operands[0].reg) : -1;
                        index >= 0 && index < REGISTERS && IsX86ConstantWrite(*insn))
                        step.constantTo = static_cast<int8>(index);
                    if (insn->id == X86_INS_CMP && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM)
                        if (const int index = registerIndex(x86.operands[0].reg); index >= 0 && index < REGISTERS) {
                            step.comparedRegister = static_cast<int8>(index);
                            step.comparedValue    = x86.operands[1].imm;
                        }
                    // the stack slots of the arguments of the next call: mov qword ptr [rsp + 0x28], rbx
                    for (uint8 i = 0; i < x86.op_count; i++)
                        if (const auto& op = x86.operands[i]; op.type == X86_OP_MEM && (op.access & CS_AC_WRITE) && op.mem.base == X86_REG_RSP &&
                                                              op.mem.index == X86_REG_INVALID && op.mem.disp >= 0 && op.mem.disp < 0x80) {
                            step.outgoingWritten = static_cast<int8>(op.mem.disp / 8);
                            if (insn->id == X86_INS_MOV && i == 0 && x86.op_count == 2 && op.mem.disp % 8 == 0 && x86.operands[1].type == X86_OP_REG &&
                                x86.operands[1].size >= 4)
                                if (const int index = registerIndex(x86.operands[1].reg); index >= 0 && index < REGISTERS)
                                    step.outgoingFrom = static_cast<int8>(index);
                        }
                    if (!systemV && arch == DissasmArch::X64) {
                        // the depth of rsp: push / pop, sub / add rsp, imm; another write of it is not followed
                        if (insn->id == X86_INS_PUSH || insn->id == X86_INS_PUSHFQ)
                            step.rspChange = -8;
                        else if (insn->id == X86_INS_POP || insn->id == X86_INS_POPFQ)
                            step.rspChange = 8;
                        else if (
                              (insn->id == X86_INS_SUB || insn->id == X86_INS_ADD) && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG &&
                              x86.operands[0].reg == X86_REG_RSP && x86.operands[1].type == X86_OP_IMM && x86.operands[1].imm >= 0 &&
                              x86.operands[1].imm < 0x100000)
                            step.rspChange = static_cast<int32>(insn->id == X86_INS_SUB ? -x86.operands[1].imm : x86.operands[1].imm);
                        else if (step.writes & (1u << 4))
                            step.rspChange = UNKNOWN_DEPTH;
                        // mov rbx, qword ptr [rsp + 0x70] / a write of a slot through rsp
                        for (uint8 i = 0; i < x86.op_count; i++)
                            if (const auto& op = x86.operands[i]; op.type == X86_OP_MEM && op.mem.base == X86_REG_RSP && op.mem.index == X86_REG_INVALID &&
                                                                  op.mem.disp >= 0 && op.mem.disp < 0x100000) {
                                step.stackOffset  = static_cast<int32>(op.mem.disp);
                                step.stackBase    = 1;
                                step.stackAddress = insn->id == X86_INS_LEA;
                                if (op.access & CS_AC_WRITE) {
                                    step.stackStore = true;
                                    if (insn->id == X86_INS_MOV && i == 0 && x86.op_count == 2 && x86.operands[1].type == X86_OP_REG &&
                                        x86.operands[1].size >= 4)
                                        if (const int index = registerIndex(x86.operands[1].reg); index >= 0 && index < REGISTERS)
                                            step.stackStoreFrom[0] = static_cast<int8>(index);
                                } else if (
                                      insn->id == X86_INS_MOV && i == 1 && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[0].size >= 4)
                                    if (const int index = registerIndex(x86.operands[0].reg); index >= 0 && index < REGISTERS)
                                        step.stackLoadTo[0] = static_cast<int8>(index);
                            }
                    }
                }
            }
            steps.push_back(step);
            if (keepSteps) { // the step of CollectArgumentDefinitions from this one (DecodeArgumentStep gives the same)
                ArgumentStep kept{ insn->address, NO_TARGET, nullptr, NO_TARGET, 0, ArgumentStepKind::Other };
                switch (step.kind) {
                case StepKind::Call:
                    kept.kind       = ArgumentStepKind::Call;
                    kept.callee     = callee.value_or(nullptr);
                    kept.callTarget = direct;
                    break;
                case StepKind::TailCall:
                    kept.callee     = callee.value_or(nullptr);
                    kept.callTarget = direct;
                    kept.kind       = direct != NO_TARGET || kept.callee ? ArgumentStepKind::TailCall : ArgumentStepKind::IndirectJump;
                    break;
                case StepKind::Jump:
                case StepKind::ConditionalJump:
                    kept.kind   = step.kind == StepKind::Jump ? ArgumentStepKind::Jump : ArgumentStepKind::ConditionalJump;
                    kept.target = step.target;
                    break;
                case StepKind::Return:
                    kept.kind = ArgumentStepKind::Return;
                    break;
                default: {
                    for (size_t argument = 0; argument < argumentsCount; argument++) // the writes of the argument registers
                        if (step.writes & (1u << argumentRegister(argument)))
                            kept.writes |= static_cast<uint8>(1u << argument);
                    const auto [stackWrites, movesStack] = ArgumentStackWrites(*insn, arch); // the stack slots of Windows x64
                    kept.writes |= stackWrites;
                    kept.movesStack = movesStack;
                    break;
                }
                }
                argumentSteps.push_back(kept);
            }
            if (step.kind == StepKind::Return && insn->address + insn->size >= end)
                break;
        }
        cs_free(insn, 1);
        if (keepSteps)
            argumentStepsOf[start] = std::move(argumentSteps);

        // the branches inside of the function, by target: their steps (the state they bring)
        std::unordered_map<uint64, size_t> stepOfAddress;
        for (size_t i = 0; i < steps.size(); i++)
            stepOfAddress.emplace(steps[i].address, i);
        std::unordered_map<size_t, std::vector<size_t>> branchesTo; // step of the target -> the steps of the branches
        for (size_t i = 0; i < steps.size(); i++)
            if (steps[i].target != NO_TARGET)
                if (const auto target = stepOfAddress.find(steps[i].target); target != stepOfAddress.end())
                    branchesTo[target->second].push_back(i);
        std::vector<std::vector<size_t>> writesOf(REGISTERS); // the steps that write each register (sorted)
        for (size_t i = 0; i < steps.size(); i++)
            for (int reg = 0; reg < REGISTERS; reg++)
                if (steps[i].writes & (1u << reg))
                    writesOf[reg].push_back(i);
        const auto writtenIn = [&](int reg, size_t from, size_t to) { // a write in steps [from, to]
            const auto found = std::lower_bound(writesOf[reg].begin(), writesOf[reg].end(), from);
            return found != writesOf[reg].end() && *found <= to;
        };

        using State = std::array<int8, REGISTERS>; // the incoming argument each register holds, -1: none
        State state;
        state.fill(-1);
        // a variadic function: the registers that hold its va_list (a bit each), the incoming arguments stored in the slots it writes once, the
        // last fixed argument passed with the va_list after it
        const int8 lastFixed = variadic && variadic->firstRegister > 0 ? static_cast<int8>(variadic->firstRegister - 1) : NO_VALUE;
        uint32 vaList        = 0;
        std::unordered_map<size_t, uint32> vaSnapshots;
        std::unordered_map<int32, int8> slotValues;
        bool passesFormat      = false;
        const auto writtenOnce = [&stores](int32 slot) {
            size_t writes = 0;
            for (const auto& [offset, size] : stores)
                writes += offset < slot + 8 && slot < offset + static_cast<int32>(size) ? 1u : 0u;
            return writes == 1;
        };
        for (size_t argument = 0; argument < argumentsCount; argument++)
            state[argumentRegister(argument)] = static_cast<int8>(argument);
        std::unordered_map<size_t, State> snapshots; // the state at each branch (before it)
        // Windows x64: the incoming arguments after the fourth ([rsp + 0x28] at the entry: the fifth), read through rsp at a known depth (the
        // bytes below the rsp of the entry) before the function writes their slot; up to MAX_STACK_PARAMETERS of them
        constexpr size_t MAX_STACK_PARAMETERS = 8;
        const bool stackParameters            = !isArm64 && !isArm32 && !systemV && arch == DissasmArch::X64;
        uint32 writtenStackParameters         = 0; // a bit each
        // the depth of the stack pointer before each step (Windows x64, ARM64): the bytes below the one of the entry, the one the code falling
        // into a branch target and every forward branch to it agree on (else not known), after a write of it not followed: not known
        const bool stackDepths = stackParameters || isArm64;
        std::vector<int32> depthAt;
        if (stackDepths) {
            depthAt.assign(steps.size(), UNKNOWN_DEPTH);
            std::unordered_map<size_t, int32> depthSnapshots;
            int32 depth    = 0;
            bool fallsInto = true;
            for (size_t i = 0; i < steps.size(); i++) {
                std::optional<int32> agreed;
                if (fallsInto)
                    agreed = depth;
                bool conflict = false;
                if (const auto branches = branchesTo.find(i); branches != branchesTo.end())
                    for (const size_t source : branches->second)
                        if (source < i) {
                            const int32 from = depthSnapshots.at(source);
                            conflict |= agreed.has_value() && agreed.value() != from;
                            agreed = from;
                        }
                depth      = agreed.has_value() && !conflict ? agreed.value() : UNKNOWN_DEPTH;
                depthAt[i] = depth;
                if (steps[i].target != NO_TARGET)
                    depthSnapshots[i] = depth;
                if (depth != UNKNOWN_DEPTH)
                    depth = steps[i].rspChange == UNKNOWN_DEPTH ? UNKNOWN_DEPTH : depth - steps[i].rspChange;
                fallsInto = steps[i].kind != StepKind::Return && steps[i].kind != StepKind::Jump && steps[i].kind != StepKind::TailCall;
            }
        }
        // the slot of a stack access from the stack pointer of the entry (x29 from the step that sets it from sp: ARM64); none when not known
        int32 framePointer = NO_FRAME_POINTER; // x29 - the sp of the entry
        const auto slotOf  = [&](size_t i) -> std::optional<int64> {
            const auto& step = steps[i];
            if (step.stackBase == 1 && depthAt[i] != UNKNOWN_DEPTH)
                return static_cast<int64>(step.stackOffset) - depthAt[i];
            if (step.stackBase == 2 && framePointer != NO_FRAME_POINTER && framePointer != FRAME_POINTER_LOST)
                return static_cast<int64>(step.stackOffset) + framePointer;
            return std::nullopt;
        };
        // the argument registers spilled: a slot the function writes once (in the order of the code), in its code before any branch, holds the
        // incoming argument the register had; a load of it gives that argument again (mov [rsp + 8], rcx .. mov rcx, [rsp + 0x30]; str x0, [sp,
        // #0x18] .. ldr x0, [sp, #0x18])
        std::unordered_map<int64, uint32> slotWrites;
        if (stackDepths) {
            for (size_t i = 0; i < steps.size(); i++) {
                if (steps[i].framePointerFromSp != NO_FRAME_POINTER)
                    framePointer = steps[i].framePointerFromSp == FRAME_POINTER_LOST || depthAt[i] == UNKNOWN_DEPTH || framePointer != NO_FRAME_POINTER
                                         ? FRAME_POINTER_LOST
                                         : steps[i].framePointerFromSp - depthAt[i];
                if (steps[i].stackStore || steps[i].stackAddress)
                    if (const auto slot = slotOf(i); slot.has_value()) {
                        // its address taken: a callee may write it (not followed)
                        slotWrites[slot.value()] += steps[i].stackAddress ? 2 : 1;
                        if (steps[i].stackStoreFrom[1] >= 0)
                            slotWrites[slot.value() + steps[i].stackSize]++;
                    }
            }
            framePointer = NO_FRAME_POINTER;
        }
        std::unordered_map<int64, int8> spilled;
        bool entryCode = true; // no branch, no branch target so far
        std::vector<std::optional<std::pair<std::string_view, std::string_view>>> parameters(argumentsCount + (stackParameters ? MAX_STACK_PARAMETERS : 0));
        std::vector<const AsmFunctionDetails*> returningCallees; // the callees of RETURNED_BY - k
        std::vector<int8> returns;                                // what each return / tail jump returns
        // Windows x64: the incoming argument the stack slots of the arguments of the next call hold ([rsp + 0x20]: the fifth), from the
        // stores after the last write of rsp, a branch target or a call
        std::array<int8, 16> outgoing;
        outgoing.fill(NO_VALUE);
        const bool outgoingSlots = !isArm64 && !isArm32 && !systemV;
        bool reachable           = true; // the step before falls through
        for (size_t i = 0; i < steps.size(); i++) {
            const auto& step = steps[i];
            if (branchesTo.contains(i) || !reachable)
                outgoing.fill(NO_VALUE);
            entryCode = entryCode && !branchesTo.contains(i) && step.target == NO_TARGET && step.kind != StepKind::Jump &&
                        step.kind != StepKind::ConditionalJump && step.kind != StepKind::Return && step.kind != StepKind::TailCall;
            if (const auto branches = branchesTo.find(i); branches != branchesTo.end()) {
                // a branch target: what every branch to it agrees on; a register written up to a branch back to it is not known
                State merged = state;
                uint32 mergedVaList = vaList;
                bool first   = !reachable;
                size_t lastBack = 0;
                for (const size_t source : branches->second) {
                    if (source >= i) {
                        lastBack = std::max(lastBack, source);
                        continue;
                    }
                    const auto& snapshot = snapshots.at(source);
                    for (int reg = 0; reg < REGISTERS; reg++)
                        merged[reg] = first ? snapshot[reg] : MergedValue(merged[reg], snapshot[reg]);
                    if (variadic)
                        mergedVaList = first ? vaSnapshots.at(source) : (mergedVaList & vaSnapshots.at(source));
                    first = false;
                }
                if (first) { // only branches back to it, after a ret / jmp: nothing is known
                    merged.fill(-1);
                    mergedVaList = 0;
                }
                if (lastBack > 0)
                    for (int reg = 0; reg < REGISTERS; reg++) {
                        if (merged[reg] != NO_VALUE && writtenIn(reg, i, lastBack))
                            merged[reg] = NO_VALUE;
                        if (writtenIn(reg, i, lastBack))
                            mergedVaList &= ~(1u << reg);
                    }
                state  = merged;
                vaList = mergedVaList;
            } else if (!reachable) {
                state.fill(-1); // code after a ret / jmp that no branch of the function reaches
                vaList = 0;
            }
            // vsprintf(buffer, format, va) / StringCchVPrintf(buffer, size, format, va): the last fixed argument before the va_list; the
            // printf of the UCRT has the locale between them (__stdio_common_vsprintf(options, buffer, count, format, locale, va))
            if (variadic && lastFixed >= 0 && (step.kind == StepKind::Call || step.kind == StepKind::TailCall))
                for (int reg = 1; reg < 8 && !passesFormat; reg++)
                    passesFormat = (vaList & (1u << reg)) != 0 && (state[reg - 1] == lastFixed || (reg >= 2 && state[reg - 2] == lastFixed));
            if (step.storeFrom >= 0 && step.storeFrom < REGISTERS && state[step.storeFrom] >= 0)
                slotValues[step.slot] = state[step.storeFrom];
            if ((step.kind == StepKind::Call || step.kind == StepKind::TailCall) && step.callee) {
                const auto& params = step.callee->params;
                for (size_t parameter = 0; parameter < params.size() && parameter < argumentsCount; parameter++) {
                    const int8 incoming = state[argumentRegister(parameter)];
                    if (incoming < 0 || parameters[incoming].has_value() || !params[parameter].name || !params[parameter].name[0])
                        continue;
                    parameters[incoming] = std::make_pair(std::string_view(params[parameter].name), std::string_view(params[parameter].type));
                }
                // the parameters after the fourth: the stack slots of the call (__stdio_common_vswprintf(..., argList): mov [rsp + 0x28], rbx)
                for (size_t parameter = argumentsCount;
                     outgoingSlots && step.kind == StepKind::Call && parameter < params.size() && parameter < outgoing.size();
                     parameter++) {
                    const int8 incoming = outgoing[parameter];
                    if (incoming < 0 || static_cast<size_t>(incoming) >= parameters.size() || parameters[incoming].has_value() || !params[parameter].name ||
                        !params[parameter].name[0])
                        continue;
                    parameters[incoming] = std::make_pair(std::string_view(params[parameter].name), std::string_view(params[parameter].type));
                }
            }
            if (outgoingSlots) {
                if (step.kind == StepKind::Call || (step.writes & (1u << 4))) // a call, a write of rsp (push, sub rsp): other slots
                    outgoing.fill(NO_VALUE);
                if (step.outgoingWritten >= 0)
                    outgoing[step.outgoingWritten] = step.outgoingFrom >= 0 ? state[step.outgoingFrom] : NO_VALUE;
            }
            if (step.target != NO_TARGET) {
                snapshots[i] = state;
                if (variadic)
                    vaSnapshots[i] = vaList;
            }
            if (step.comparedRegister >= 0)
                RecordReturnComparison(step.address, state[step.comparedRegister], returningCallees, step.comparedValue);
            // what the function returns: rax / x0 at a ret, the return value of the callee of a tail jump
            if (step.kind == StepKind::Return)
                returns.push_back(state[0]);
            else if (step.kind == StepKind::TailCall)
                returns.push_back(ReturnedValueOf(returningCallees, step.callee));
            const int8 stateBeforeStep[2] = { step.stackStoreFrom[0] >= 0 ? state[step.stackStoreFrom[0]] : NO_VALUE,
                                              step.stackStoreFrom[1] >= 0 ? state[step.stackStoreFrom[1]] : NO_VALUE };
            if (step.copyTo >= 0 && step.copyTo < REGISTERS && step.copyFrom >= 0 && step.copyFrom < REGISTERS) {
                state[step.copyTo] = state[step.copyFrom];
                vaList             = (vaList & ~(1u << step.copyTo)) | (((vaList >> step.copyFrom) & 1u) << step.copyTo);
            } else {
                for (int reg = 0; reg < REGISTERS; reg++)
                    if (step.writes & (1u << reg)) {
                        state[reg] = NO_VALUE;
                        vaList &= ~(1u << reg);
                    }
            }
            if (step.constantTo >= 0) {
                state[step.constantTo] = CONSTANT_VALUE;
                vaList &= ~(1u << step.constantTo);
            }
            if (stackDepths && step.framePointerFromSp != NO_FRAME_POINTER)
                framePointer = step.framePointerFromSp == FRAME_POINTER_LOST || depthAt[i] == UNKNOWN_DEPTH || framePointer != NO_FRAME_POINTER
                                     ? FRAME_POINTER_LOST
                                     : step.framePointerFromSp - depthAt[i];
            if (const auto slot = stackDepths && step.stackBase != 0 ? slotOf(i) : std::nullopt; slot.has_value()) {
                // the slot from the rsp of the entry: 0x28 + 8 * k is the incoming argument 4 + k (Windows x64)
                const int64 fromEntry = slot.value();
                if (stackParameters && fromEntry >= 0x28 && (fromEntry - 0x28) % 8 == 0 && (fromEntry - 0x28) / 8 < static_cast<int64>(MAX_STACK_PARAMETERS)) {
                    const auto k = static_cast<size_t>((fromEntry - 0x28) / 8);
                    if (step.stackStore)
                        writtenStackParameters |= 1u << k;
                    else if (step.stackLoadTo[0] >= 0 && !(writtenStackParameters & (1u << k)))
                        state[step.stackLoadTo[0]] = static_cast<int8>(argumentsCount + k);
                }
                for (uint8 half = 0; half < 2; half++) {
                    const int64 at = fromEntry + half * step.stackSize;
                    if (step.stackStoreFrom[half] >= 0 && entryCode && slotWrites[at] == 1 && stateBeforeStep[half] >= 0)
                        spilled[at] = stateBeforeStep[half];
                    if (step.stackLoadTo[half] >= 0)
                        if (const auto value = spilled.find(at); value != spilled.end())
                            state[step.stackLoadTo[half]] = value->second;
                }
            }
            if (step.vaListTo >= 0 && step.vaListTo < REGISTERS)
                vaList |= 1u << step.vaListTo;
            if (step.loadTo >= 0 && step.loadTo < REGISTERS && writtenOnce(step.slot))
                if (const auto stored = slotValues.find(step.slot); stored != slotValues.end())
                    state[step.loadTo] = stored->second; // the argument spilled to the slot
            if (step.kind == StepKind::Call)
                state[0] = ReturnedValueOf(returningCallees, step.callee); // rax / x0 / r0
            reachable = step.kind != StepKind::Return && step.kind != StepKind::Jump && step.kind != StepKind::TailCall;
        }

        // a variadic function: its fixed arguments only; the last one passed with the va_list is the format (its type from a callee that knows it)
        if (variadic) {
            parameters.resize(std::min<size_t>(variadic->firstRegister, parameters.size()));
            if (passesFormat && !parameters[lastFixed].has_value())
                parameters[lastFixed] = std::make_pair(std::string_view("format"), std::string_view());
        }
        // ARM: the conditional returns (popne {r4, pc}, bxlt lr in an IT block) are not steps: not what it returns
        return MakeInferredPrototype(start, parameters, {}, isArm32 ? nullptr : AgreedReturn(returns, returningCallees), variadic != nullptr);
    }

    // a step of the code of an ARM64 function (InferFunctionPrototype): the change of sp (sub / add sp, sp, #imm, the writeback of a stack
    // access: [sp, #-0x20]! / [sp], #0x20; another write of sp: not known), a load / store through sp or x29 (two registers of a pair), x29
    // set from sp (mov x29, sp / add x29, sp, #n)
    template <typename Step>
    static void DecodeArm64StackStep(const cs_insn& insn, Step& step)
    {
        constexpr int32 UNKNOWN_DEPTH = INT32_MIN, FRAME_POINTER_LOST = INT32_MIN + 1;
        const cs_arm64& arm64     = insn.detail->arm64;
        const auto shifted        = [](const cs_arm64_op& op) { return op.shift.type == ARM64_SFT_LSL ? op.imm << op.shift.value : op.imm; };
        const auto writesRegister = [&arm64](unsigned int reg) {
            for (uint8 i = 0; i < arm64.op_count; i++)
                if (arm64.operands[i].type == ARM64_OP_REG && arm64.operands[i].reg == reg && (arm64.operands[i].access & CS_AC_WRITE))
                    return true;
            return false;
        };
        const bool immediateOfSp = arm64.op_count == 3 && arm64.operands[1].type == ARM64_OP_REG && arm64.operands[1].reg == ARM64_REG_SP &&
                                   arm64.operands[2].type == ARM64_OP_IMM && shifted(arm64.operands[2]) >= 0 && shifted(arm64.operands[2]) < 0x1000000;
        if (writesRegister(ARM64_REG_SP)) {
            if ((insn.id == ARM64_INS_SUB || insn.id == ARM64_INS_ADD) && immediateOfSp)
                step.rspChange = static_cast<int32>(insn.id == ARM64_INS_SUB ? -shifted(arm64.operands[2]) : shifted(arm64.operands[2]));
            else
                step.rspChange = UNKNOWN_DEPTH;
        }
        if (writesRegister(ARM64_REG_X29)) {
            if (insn.id == ARM64_INS_MOV && arm64.op_count == 2 && arm64.operands[1].type == ARM64_OP_REG && arm64.operands[1].reg == ARM64_REG_SP)
                step.framePointerFromSp = 0;
            else if (insn.id == ARM64_INS_ADD && immediateOfSp)
                step.framePointerFromSp = static_cast<int32>(shifted(arm64.operands[2]));
            else if (insn.id != ARM64_INS_LDP && insn.id != ARM64_INS_LDR) // the restore of the epilogue: the code after it is another path
                step.framePointerFromSp = FRAME_POINTER_LOST;
        }
        // add x1, sp, #0x18 / add x0, x29, #0x10: the address of a slot
        if (insn.id == ARM64_INS_ADD && arm64.op_count == 3 && arm64.operands[0].type == ARM64_OP_REG && arm64.operands[0].reg != ARM64_REG_SP &&
            arm64.operands[0].reg != ARM64_REG_X29 && arm64.operands[1].type == ARM64_OP_REG &&
            (arm64.operands[1].reg == ARM64_REG_SP || arm64.operands[1].reg == ARM64_REG_X29) && arm64.operands[2].type == ARM64_OP_IMM &&
            shifted(arm64.operands[2]) >= 0 && shifted(arm64.operands[2]) < 0x1000000) {
            step.stackBase    = arm64.operands[1].reg == ARM64_REG_SP ? 1 : 2;
            step.stackOffset  = static_cast<int32>(shifted(arm64.operands[2]));
            step.stackAddress = true;
            return;
        }
        const bool load  = insn.id == ARM64_INS_LDR || insn.id == ARM64_INS_LDUR || insn.id == ARM64_INS_LDP;
        const bool store = insn.id == ARM64_INS_STR || insn.id == ARM64_INS_STUR || insn.id == ARM64_INS_STP;
        if (!load && !store)
            return;
        const uint8 registers = insn.id == ARM64_INS_LDP || insn.id == ARM64_INS_STP ? 2 : 1;
        if (arm64.op_count < registers + 1 || arm64.operands[registers].type != ARM64_OP_MEM)
            return;
        const auto& mem = arm64.operands[registers].mem;
        if (mem.index != ARM64_REG_INVALID || (mem.base != ARM64_REG_SP && mem.base != ARM64_REG_X29))
            return;
        int32 offset = mem.disp;
        if (arm64.writeback && mem.base == ARM64_REG_SP) {
            if (arm64.op_count > registers + 1 && arm64.operands[registers + 1].type == ARM64_OP_IMM) { // [sp], #0x20: the access at sp
                step.rspChange = static_cast<int32>(arm64.operands[registers + 1].imm);
            } else { // [sp, #-0x20]!: the access at the new sp
                step.rspChange = mem.disp;
                offset         = 0;
            }
        } else if (arm64.writeback) {
            return;
        }
        step.stackBase   = mem.base == ARM64_REG_SP ? 1 : 2;
        step.stackOffset = offset;
        step.stackStore  = store;
        for (uint8 i = 0; i < registers; i++) {
            const unsigned int reg = arm64.operands[i].reg;
            int index              = -1;
            if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
                index = static_cast<int>(reg - ARM64_REG_X0);
            else if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28) {
                index          = static_cast<int>(reg - ARM64_REG_W0);
                step.stackSize = 4;
            }
            if (index < 0)
                continue;
            if (store)
                step.stackStoreFrom[i] = static_cast<int8>(index);
            else
                step.stackLoadTo[i] = static_cast<int8>(index);
        }
    }

    // a step of the code of an ARM64 variadic function (InferFunctionPrototype): the address of the home of its first variadic register (add x3,
    // sp, #0x30 at the depth of the frame there; add x3, x29, #0x10; a large frame: mov x16, #0x1060; add x22, sp, x16) or the move of x4 of
    // ARM64EC is its va_list, add x20, x26, #0 a copy; str x1, [sp, #0x10] / ldr x2, [sp, #0x10]: a slot of the frame; `stores` receives the
    // slots every store of the code writes, `scratchConstants` the constants of x16 / x17 in the order of the code
    static void DecodeVariadicStep(
          const cs_insn& insn,
          const DissasmFunctionFrame& frame,
          const DissasmFunctionFrame::VariadicHomes& variadic,
          auto& step,
          std::vector<std::pair<int32, uint32>>& stores,
          std::array<std::optional<int64>, 2>& scratchConstants)
    {
        const cs_arm64& arm64 = insn.detail->arm64;
        const auto slotOf     = [&](unsigned int base, int64 displacement) -> std::optional<int32> {
            if (base == ARM64_REG_SP) {
                int32 depth = frame.stackOffset; // the depth at the instruction (the prologue), else the one of the body
                if (insn.address >= frame.startAddress && insn.address < frame.endAddress)
                    depth = frame.StackDeltaAt(insn.address).value_or(depth);
                return static_cast<int32>(displacement + depth);
            }
            if (base == ARM64_REG_X29 && frame.usesFrameRegister)
                return static_cast<int32>(displacement + frame.frameRegisterOffset);
            return std::nullopt;
        };
        const auto xRegister = [&arm64](uint8 index) -> int8 {
            return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_REG && arm64.operands[index].reg >= ARM64_REG_X0 &&
                               arm64.operands[index].reg <= ARM64_REG_X28
                         ? static_cast<int8>(arm64.operands[index].reg - ARM64_REG_X0)
                         : static_cast<int8>(-1);
        };
        const bool immediate = arm64.op_count == 3 && arm64.operands[2].type == ARM64_OP_IMM && arm64.operands[2].shift.value == 0;
        const int8 scratch   = xRegister(0) == 16 || xRegister(0) == 17 ? static_cast<int8>(xRegister(0) - 16) : static_cast<int8>(-1);
        if (scratch >= 0 && (arm64.operands[0].access & CS_AC_WRITE)) {
            // mov x16, #0x1060: the offset of a slot of a large frame; another write of x16 forgets it
            const bool constant = (insn.id == ARM64_INS_MOV || insn.id == ARM64_INS_MOVZ) && arm64.op_count == 2 && arm64.operands[1].type == ARM64_OP_IMM;
            scratchConstants[scratch] = constant ? std::optional<int64>(arm64.operands[1].imm) : std::nullopt;
            if (constant)
                return;
        }
        if (insn.id == ARM64_INS_ADD && arm64.op_count == 3 && !variadic.throughX4 && xRegister(0) >= 0 && arm64.operands[1].type == ARM64_OP_REG &&
            arm64.operands[1].reg == ARM64_REG_SP && arm64.operands[2].type == ARM64_OP_REG && arm64.operands[2].shift.value == 0 &&
            arm64.operands[2].ext == ARM64_EXT_INVALID && (arm64.operands[2].reg == ARM64_REG_X16 || arm64.operands[2].reg == ARM64_REG_X17)) {
            // add x22, sp, x16
            if (const auto& value = scratchConstants[arm64.operands[2].reg == ARM64_REG_X16 ? 0 : 1]; value.has_value())
                if (const auto slot = slotOf(ARM64_REG_SP, value.value()); slot.has_value() && slot.value() == variadic.frameOffset)
                    step.vaListTo = xRegister(0);
            return;
        }
        if ((insn.id == ARM64_INS_ADD || insn.id == ARM64_INS_SUB) && immediate && arm64.operands[1].type == ARM64_OP_REG) {
            const int8 to       = xRegister(0);
            const unsigned base = arm64.operands[1].reg;
            if (variadic.throughX4 && to == 4 && base == ARM64_REG_X4)
                step.vaListTo = 4; // sub x4, x4, #0x10: the stack arguments moved below the homes
            else if (insn.id == ARM64_INS_ADD && to >= 0 && arm64.operands[2].imm == 0 && xRegister(1) >= 0) {
                step.copyTo   = to; // add x20, x26, #0
                step.copyFrom = xRegister(1);
            } else if (insn.id == ARM64_INS_ADD && to >= 0 && !variadic.throughX4)
                if (const auto slot = slotOf(base, arm64.operands[2].imm); slot.has_value() && slot.value() == variadic.frameOffset)
                    step.vaListTo = to; // add x3, sp, #va_x2
            return;
        }
        for (uint8 index = 0; index < arm64.op_count; index++) {
            const cs_arm64_op& op = arm64.operands[index];
            if (op.type != ARM64_OP_MEM || op.mem.index != ARM64_REG_INVALID || arm64.writeback)
                continue;
            const auto slot = slotOf(op.mem.base, op.mem.disp);
            if (!slot.has_value())
                return;
            if (op.access & CS_AC_WRITE) {
                const uint32 size = insn.id == ARM64_INS_STP || insn.id == ARM64_INS_STNP ? 16u : 8u; // a narrower store counted as 8 bytes
                stores.emplace_back(slot.value(), size);
                if ((insn.id == ARM64_INS_STR || insn.id == ARM64_INS_STUR) && xRegister(0) >= 0) {
                    step.storeFrom = xRegister(0);
                    step.slot      = slot.value();
                }
            } else if ((insn.id == ARM64_INS_LDR || insn.id == ARM64_INS_LDUR) && xRegister(0) >= 0) {
                step.loadTo = xRegister(0);
                step.slot   = slot.value();
            }
            return;
        }
    }

    // x86 / x64 (NameVariablesFromCalls): a call passes the address of the incoming argument slot `offset` as its va_list (lea eax, [ebp + 0x14];
    // push eax / lea r9, [rsp + 0x48 + arg_18] after the homes of x64): the function is variadic from that argument on (va_start). 32 bit x86:
    // the format of the call (its parameter before the va_list) is the value of the argument right before it (`formatOffset`), which tells the slots apart (a
    // frame register: [ebp + 8] is the first argument, else [esp + 4] at the entry); x64 without a frame register: the home of rdx, r8, r9 or
    // a stack argument ([rsp + 8] is the home of rcx at the entry); not x64 with a frame register, nor System V (its va_list is a structure)
    void NoteVariadicArgumentSlot(
          const DissasmFunctionFrame& frame,
          const AsmFunctionDetails& prototype,
          size_t index,
          int32 offset,
          std::optional<int32> formatOffset,
          DissasmArch functionArch)
    {
        const bool isX86 = functionArch == DissasmArch::X86;
        if (!isX86 && (functionArch != DissasmArch::X64 || frame.usesFrameRegister || zone->systemVCalls))
            return;
        const int32 slotSize = isX86 ? 4 : 8;
        const int32 base     = isX86 && frame.usesFrameRegister ? 8 : (isX86 ? 4 : 8);
        if (offset < base + slotSize || (offset - base) % slotSize != 0)
            return; // the first argument can not be a variadic one
        const auto first = static_cast<uint32>((offset - base) / slotSize);
        if (first >= 16)
            return;
        const std::string_view formatName = index > 0 && prototype.params[index - 1].name ? prototype.params[index - 1].name : "";
        const bool passesFormat           = formatName.find("ormat") != std::string_view::npos || formatName.find("mt") != std::string_view::npos;
        if (isX86 && (!passesFormat || formatOffset != offset - slotSize))
            return;
        const std::string_view formatType = passesFormat && prototype.params[index - 1].type ? prototype.params[index - 1].type : "";
        if (variadicArgumentSlot.has_value()) {
            variadicArgumentSlot->conflict |= variadicArgumentSlot->first != first; // two calls with other va_lists
            return;
        }
        variadicArgumentSlot = VariadicArgumentSlot{ first, formatType, false };
    }

    // a format wrapper (NoteVariadicArgumentSlot): its prototype inferred again, its fixed arguments (the ones inferred before, the format of
    // its call for the last one) then ..., its return kept; not when the user gave one
    void InferFormatWrapperPrototype(uint64 start, DissasmArch functionArch)
    {
        if (zone->userPrototypes.contains(start))
            return;
        const auto& slot = variadicArgumentSlot.value();
        const auto known = inferredPrototypes.find(start);
        const auto* old  = known != inferredPrototypes.end() ? &known->second->details : nullptr;
        std::vector<std::optional<std::pair<std::string_view, std::string_view>>> parameters(slot.first);
        std::vector<bool> secondHalves(slot.first);
        if (old) { // the parameters inferred before, by slot (a 64 bit one of 32 bit x86 takes two)
            uint32 position = 0;
            for (const auto& parameter : old->params) {
                if (position >= slot.first)
                    break;
                if (parameter.name && parameter.name[0])
                    parameters[position] = std::make_pair(std::string_view(parameter.name), std::string_view(parameter.type));
                if (functionArch == DissasmArch::X86 && IsWideX86Type(parameter.type) && position + 1 < slot.first)
                    secondHalves[++position] = true;
                position++;
            }
        }
        if (!parameters[slot.first - 1].has_value() && !slot.formatType.empty() && !secondHalves[slot.first - 1])
            parameters[slot.first - 1] = std::make_pair(std::string_view("format"), slot.formatType);
        auto prototype = MakeInferredPrototype(start, parameters, secondHalves, old && !old->returnType.empty() ? old : nullptr, true, true);
        if (prototype) {
            inferredPrototypes[start] = std::move(prototype);
            formatWrappers.insert(start);
        }
    }
    std::unordered_set<uint64> formatWrappers; // InferFormatWrapperPrototype: the functions whose ... the labels phase found

    // ARM64: a variadic function (the homes of its variadic registers in its frame, DissasmFunctionFrame::variadic): its prototype inferred
    // again with its frame (InferFunctionPrototype: its fixed arguments, the format it passes with its va_list), unless the user gave one
    void InferVariadicPrototype(const DissasmFunctionFrame& frame)
    {
        const auto start = std::lower_bound(functionStarts.begin(), functionStarts.end(), frame.startAddress);
        if (!frame.variadic.has_value() || start == functionStarts.end() || *start != frame.startAddress || functionEnds.size() != functionStarts.size() ||
            zone->userPrototypes.contains(frame.startAddress))
            return;
        auto prototype =
              InferFunctionPrototype(frame.startAddress, functionEnds[static_cast<size_t>(start - functionStarts.begin())], DissasmArch::Arm64, &frame);
        functionComparisons.clear(); // the comparisons of its return values were kept by InferPrototypes
        if (prototype)
            inferredPrototypes[frame.startAddress] = std::move(prototype);
    }

    // 32 bit x86: the arguments are in the stack. The walk of InferFunctionPrototype follows esp and ebp from the esp of the entry (push /
    // pop, sub / add esp, mov ebp, esp, leave, the bytes the callees pop, a frame helper: ebp = the esp of the entry - 4), the incoming
    // argument slots ([esp + 4 + 4k] at the entry, [ebp + 8 + 4k] in a frame) while the function does not write them, what the registers and
    // the slots above esp hold (push [ebp + 8], mov eax, [esp + 8]; push eax, mov [esp + 4], eax). A call with a prototype names the incoming
    // arguments it is passed in [esp], [esp + 4], ... (8 bytes for the 64 bit types), a tail jump the ones in [esp + 4], ... Two passes: the
    // first one finds the incoming slots each instruction writes (a loop that writes one: not its argument at the loop start)
    std::shared_ptr<const DissasmUserPrototype> InferX86FunctionPrototype(uint64 start, uint64 end)
    {
        constexpr size_t MAX_STEPS     = 4096;
        constexpr int32 MAX_ARGUMENTS  = 16;
        constexpr int32 MAX_SLOT       = 0x1000; // the slots followed above esp
        constexpr int REGISTERS        = 8;      // eax .. edi
        constexpr uint32 VOLATILE_MASK = 0x7;    // eax, ecx, edx
        const auto data = start < end ? obj->GetData().Get(codeStart + start, static_cast<uint32>(std::min<uint64>(end - start, 0x10000)), false) : BufferView{};
        cs_insn* insn = data.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return nullptr;

        // the code of the function, once: its branches, its calls, its operands
        enum class StepKind : uint8 { Other, Call, TailCall, Jump, ConditionalJump, Return };
        struct Step {
            StepKind kind;
            uint64 target; // a branch inside of the function (relative); NO_TARGET otherwise
            uint32 writes; // the registers written
            const AsmFunctionDetails* callee;
            std::optional<uint32> purge; // a call: the bytes the callee pops
            bool frameHelper;
            unsigned int id;
            cs_x86 x86;
            uint64 address;
        };
        std::vector<Step> steps;
        std::unordered_map<uint64, size_t> stepOfAddress;
        const uint8* bytes = data.GetData();
        size_t size        = data.GetLength();
        uint64 address     = start;
        while (steps.size() < MAX_STEPS && cs_disasm_iter(detailHandle, &bytes, &size, &address, insn)) {
            auto& step = steps.emplace_back(Step{ StepKind::Other, NO_TARGET, 0, nullptr, std::nullopt, false, insn->id, insn->detail->x86, insn->address });
            stepOfAddress.emplace(insn->address, steps.size() - 1);
            const auto flow     = GetInstructionFlow(*insn, DissasmArch::X86);
            const auto operands = GetInstructionOperands(*insn, DissasmArch::X86, labelBase);
            const uint64 direct = operands.directTarget.has_value() ? operands.directTarget.value() & addressMask : NO_TARGET;
            const bool inside   = direct >= start && direct < end;
            if (flow == X86Flow::Call) {
                const auto* callee = CalleePrototype(*insn, DissasmArch::X86);
                step.kind          = StepKind::Call;
                step.callee        = IsInferenceCallee(callee);
                step.frameHelper   = direct < codeSize && IsFrameHelper(direct);
                step.purge         = CalleeStackPurge(*insn);
                if (!step.purge.has_value() && callee)
                    if (const auto pushes = GetX86StdcallPushes(*callee); pushes.has_value())
                        step.purge = pushes.value() * 4; // a method of __thiscall too
                step.writes = VOLATILE_MASK;
            } else if (flow == X86Flow::Jump) {
                step.kind   = inside ? StepKind::Jump : StepKind::TailCall;
                step.target = inside ? direct : NO_TARGET;
                step.callee = inside ? nullptr : IsInferenceCallee(CalleePrototype(*insn, DissasmArch::X86));
            } else if (flow == X86Flow::ConditionalJump) {
                step.kind   = StepKind::ConditionalJump;
                step.target = inside ? direct : NO_TARGET;
            } else if (flow == X86Flow::Return) {
                step.kind = StepKind::Return;
            }
            const cs_x86& x86 = insn->detail->x86;
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                    if (const int family = GetX64RegisterFamily(x86.operands[index].reg); family >= 0 && family < REGISTERS)
                        step.writes |= 1u << family;
            for (uint8 index = 0; index < insn->detail->regs_write_count; index++)
                if (const int family = GetX64RegisterFamily(insn->detail->regs_write[index]); family >= 0 && family < REGISTERS)
                    step.writes |= 1u << family;
        }
        cs_free(insn, 1);
        const size_t count = steps.size();
        // the locals of the frame ([ebp - 0x4c]) written once in the whole function (a write of more bytes: each slot it covers), whose address
        // is never taken (lea eax, [ebp - 0x4c]: a callee may write it); ebp set once (mov ebp, esp; not its restores): a copy of an incoming
        // argument stored there in the code before any branch (mov eax, [ebp + 0x10]; mov [ebp - 0x4c], eax) holds it for every later load
        std::unordered_map<int32, uint32> frameWrites;
        uint32 frameSets = 0;
        for (const auto& step : steps) {
            for (uint8 index = 0; index < step.x86.op_count; index++) {
                const auto& op = step.x86.operands[index];
                if (op.type != X86_OP_MEM || op.mem.base != X86_REG_EBP || op.mem.index != X86_REG_INVALID || op.mem.disp >= 0 || op.mem.disp <= -MAX_SLOT * 4)
                    continue;
                const auto disp = static_cast<int32>(op.mem.disp);
                if (step.id == X86_INS_LEA)
                    frameWrites[disp] += 2;
                else if (op.access & CS_AC_WRITE)
                    for (int32 offset = disp & ~3; offset < disp + std::max<int32>(op.size, 1); offset += 4)
                        frameWrites[offset]++;
            }
            if ((step.writes & (1u << 5)) && step.id != X86_INS_POP && step.id != X86_INS_LEAVE)
                frameSets++;
        }
        const bool followLocals = frameSets <= 1;
        std::unordered_map<size_t, std::vector<size_t>> branchesTo; // step of the target -> the steps of the branches
        bool hasLoop = false;
        for (size_t i = 0; i < count; i++)
            if (steps[i].target != NO_TARGET)
                if (const auto target = stepOfAddress.find(steps[i].target); target != stepOfAddress.end()) {
                    branchesTo[target->second].push_back(i);
                    hasLoop |= target->second <= i;
                }
        std::vector<std::vector<size_t>> writesOf(REGISTERS); // the steps that write each register (sorted)
        for (size_t i = 0; i < count; i++)
            for (int reg = 0; reg < REGISTERS; reg++)
                if (steps[i].writes & (1u << reg))
                    writesOf[reg].push_back(i);
        const auto writtenIn = [&](int reg, size_t from, size_t to) { // a write in steps [from, to]
            const auto found = std::lower_bound(writesOf[reg].begin(), writesOf[reg].end(), from);
            return found != writesOf[reg].end() && *found <= to;
        };

        struct State {
            std::array<int8, REGISTERS> registers; // the incoming argument each register holds, -1: none
            uint32 intact;                         // the incoming argument slots not written (bit k: [esp of the entry + 4 + 4k])
            std::optional<int32> esp, ebp;         // from the esp of the entry
            std::vector<std::pair<int32, int8>> slots; // [esp + key]: the incoming argument it holds (sorted by key)
        };
        struct Location {
            bool incoming;
            int32 offset; // incoming: from the esp of the entry; else: from esp
        };
        const auto shift = [](State& state, int32 delta) { // esp += delta
            if (state.esp.has_value())
                state.esp = state.esp.value() + delta;
            for (auto& slot : state.slots)
                slot.first -= delta;
            state.slots.erase(std::remove_if(state.slots.begin(), state.slots.end(), [](const auto& slot) { return slot.first < 0 || slot.first >= MAX_SLOT; }),
                              state.slots.end());
        };
        const auto slotAt = [](auto& slots, int32 key) {
            return std::lower_bound(slots.begin(), slots.end(), key, [](const auto& slot, int32 value) { return slot.first < value; });
        };
        const auto valueAt = [&slotAt](const State& state, int32 key) -> int8 {
            const auto found = slotAt(state.slots, key);
            return found != state.slots.end() && found->first == key ? found->second : -1;
        };
        const auto setSlot = [&slotAt](State& state, int32 key, int8 value) {
            const auto found = slotAt(state.slots, key);
            if (found != state.slots.end() && found->first == key)
                found->second = value;
            else
                state.slots.insert(found, { key, value });
        };
        const auto forgetStack = [](State& state) {
            state.esp.reset();
            state.slots.clear();
        };
        const auto locate = [](const State& state, unsigned int base, int64 disp) -> std::optional<Location> {
            if (disp <= -MAX_SLOT * 4 || disp >= MAX_SLOT * 4)
                return std::nullopt;
            std::optional<int32> entry, current;
            if (base == X86_REG_ESP) {
                current = static_cast<int32>(disp);
                if (state.esp.has_value())
                    entry = state.esp.value() + static_cast<int32>(disp);
            } else if (base == X86_REG_EBP && state.ebp.has_value()) {
                entry = state.ebp.value() + static_cast<int32>(disp);
                if (state.esp.has_value())
                    current = entry.value() - state.esp.value();
            }
            if (entry.has_value() && entry.value() >= 4) // above the return address: the incoming arguments
                return Location{ true, entry.value() };
            if (current.has_value() && current.value() >= 0 && current.value() < MAX_SLOT)
                return Location{ false, current.value() };
            return std::nullopt;
        };
        const auto read = [&valueAt](const State& state, const std::optional<Location>& location) -> int8 {
            if (!location.has_value())
                return NO_VALUE;
            if (location->incoming) {
                const int32 argument = (location->offset - 4) / 4;
                return (location->offset - 4) % 4 == 0 && argument < MAX_ARGUMENTS && (state.intact & (1u << argument)) ? static_cast<int8>(argument) : -1;
            }
            return valueAt(state, location->offset);
        };
        uint32 writtenNow = 0; // the incoming slots the current instruction writes
        const auto write  = [&writtenNow, &slotAt, &setSlot](State& state, const std::optional<Location>& location, int32 size, int8 value) {
            if (!location.has_value())
                return;
            if (location->incoming) {
                for (int32 offset = location->offset & ~3; offset < location->offset + size; offset += 4)
                    if (const int32 argument = (offset - 4) / 4; offset >= 4 && argument < MAX_ARGUMENTS) {
                        state.intact &= ~(1u << argument);
                        writtenNow |= 1u << argument;
                    }
                if (size == 4 && (location->offset - 4) % 4 == 0 && value == (location->offset - 4) / 4)
                    state.intact |= 1u << value; // mov [ebp + 8], eax: the argument it held
                return;
            }
            state.slots.erase(slotAt(state.slots, location->offset - 3), slotAt(state.slots, location->offset + size));
            if (size == 4 && value != NO_VALUE)
                setSlot(state, location->offset, value);
        };
        const auto merge = [&valueAt](State& into, const State& from) {
            for (int reg = 0; reg < REGISTERS; reg++)
                into.registers[reg] = MergedValue(into.registers[reg], from.registers[reg]);
            into.intact &= from.intact;
            if (into.esp != from.esp)
                into.esp.reset();
            if (into.ebp != from.ebp)
                into.ebp.reset();
            into.slots.erase(std::remove_if(into.slots.begin(), into.slots.end(), [&](const auto& slot) { return valueAt(from, slot.first) != slot.second; }),
                             into.slots.end());
        };
        const auto unknown = [](State& state) {
            state.registers.fill(-1);
            state.intact = 0;
            state.esp.reset();
            state.ebp.reset();
            state.slots.clear();
        };

        std::vector<uint32> writtenIncoming(count, 0); // the first pass (only for a loop): the incoming slots each step writes
        std::vector<std::optional<std::pair<std::string_view, std::string_view>>> parameters(MAX_ARGUMENTS);
        std::vector<bool> secondHalves(MAX_ARGUMENTS); // the second slot of a 64 bit parameter
        std::vector<const AsmFunctionDetails*> returningCallees; // the callees of RETURNED_BY - k
        std::vector<int8> returns;                                // what each return / tail jump returns (the last pass)
        for (uint32 pass = hasLoop ? 0 : 1; pass < 2; pass++) {
            State state;
            state.registers.fill(-1);
            state.intact = (1u << MAX_ARGUMENTS) - 1u;
            state.esp    = 0;
            std::unordered_map<size_t, State> snapshots; // the state at each branch (before it)
            bool reachable = true;                       // the step before falls through
            std::unordered_map<int32, int8> spilledLocals; // a local of the frame (followLocals) -> the incoming argument it holds
            bool entryCode = true;                         // no branch, no branch target so far
            for (size_t i = 0; i < count; i++) {
                const auto& step = steps[i];
                entryCode        = entryCode && !branchesTo.contains(i) && step.target == NO_TARGET && step.kind != StepKind::Jump &&
                            step.kind != StepKind::ConditionalJump && step.kind != StepKind::Return && step.kind != StepKind::TailCall;
                if (const auto branches = branchesTo.find(i); branches != branchesTo.end()) {
                    // a branch target: what every branch to it agrees on; what a loop back to it writes is not known
                    State merged    = state;
                    bool first      = !reachable;
                    size_t lastBack = 0;
                    for (const size_t source : branches->second) {
                        if (source >= i) {
                            lastBack = std::max(lastBack, source);
                            continue;
                        }
                        if (first)
                            merged = snapshots.at(source);
                        else
                            merge(merged, snapshots.at(source));
                        first = false;
                    }
                    if (first) // only branches back to it, after a ret / jmp: nothing is known
                        unknown(merged);
                    if (lastBack > 0) {
                        for (int reg = 0; reg < REGISTERS; reg++)
                            if (merged.registers[reg] != NO_VALUE && writtenIn(reg, i, lastBack))
                                merged.registers[reg] = NO_VALUE;
                        for (size_t loop = i; loop <= lastBack; loop++)
                            merged.intact &= ~writtenIncoming[loop];
                        merged.slots.clear();
                    }
                    state = std::move(merged);
                } else if (!reachable) {
                    unknown(state); // code after a ret / jmp that no branch of the function reaches
                }
                reachable = step.kind != StepKind::Return && step.kind != StepKind::Jump && step.kind != StepKind::TailCall;
                if (step.target != NO_TARGET)
                    snapshots[i] = state;
                writtenNow = 0;
                if (pass == 1 && step.kind == StepKind::Return)
                    returns.push_back(state.registers[0]); // eax
                else if (pass == 1 && step.kind == StepKind::TailCall)
                    returns.push_back(ReturnedValueOf(returningCallees, step.callee));

                // a call / tail jump with a prototype: the incoming arguments it is passed
                if (pass == 1 && (step.kind == StepKind::Call || step.kind == StepKind::TailCall) && step.callee) {
                    int32 offset = step.kind == StepKind::TailCall ? 4 : 0; // a tail jump: the return address of the caller at [esp]
                    for (const auto& parameter : step.callee->params) {
                        const bool wide      = IsWideX86Type(parameter.type);
                        const int8 incoming  = read(state, locate(state, X86_REG_ESP, offset));
                        const bool named     = parameter.name && parameter.name[0];
                        const bool secondOk  = !wide || (incoming >= 0 && incoming + 1 < MAX_ARGUMENTS &&
                                                        read(state, locate(state, X86_REG_ESP, offset + 4)) == incoming + 1 &&
                                                        !parameters[incoming + 1].has_value() && !secondHalves[incoming + 1]);
                        if (named && incoming >= 0 && !parameters[incoming].has_value() && !secondHalves[incoming] && secondOk) {
                            parameters[incoming] = std::make_pair(std::string_view(parameter.name), std::string_view(parameter.type));
                            if (wide)
                                secondHalves[incoming + 1] = true;
                        }
                        offset += wide ? 8 : 4;
                    }
                }

                const cs_x86& x86 = step.x86;
                const auto reg32  = [](const cs_x86_op& op) { return op.type == X86_OP_REG && op.size == 4 ? GetX64RegisterFamily(op.reg) : -1; };
                if (pass == 1 && step.id == X86_INS_CMP && x86.op_count == 2 && x86.operands[1].type == X86_OP_IMM) // cmp eax, 0x102
                    if (const int reg = reg32(x86.operands[0]); reg >= 0 && reg < REGISTERS)
                        RecordReturnComparison(step.address, state.registers[reg], returningCallees, x86.operands[1].imm);
                const auto memoryOf = [&](const cs_x86_op& op) -> std::optional<Location> {
                    return op.type == X86_OP_MEM && op.mem.index == X86_REG_INVALID ? locate(state, op.mem.base, op.mem.disp) : std::nullopt;
                };
                const auto valueOf = [&](const cs_x86_op& op) -> int8 {
                    if (const int reg = reg32(op); reg >= 0 && reg < REGISTERS)
                        return state.registers[reg];
                    if (op.type == X86_OP_IMM)
                        return CONSTANT_VALUE;
                    if (op.type == X86_OP_MEM && op.size == 4 && op.mem.base == X86_REG_EBP && op.mem.index == X86_REG_INVALID && state.ebp.has_value())
                        if (const auto spilled = spilledLocals.find(static_cast<int32>(op.mem.disp)); spilled != spilledLocals.end())
                            return spilled->second; // the copy of an incoming argument in a local of the frame
                    return op.size == 4 ? read(state, memoryOf(op)) : NO_VALUE;
                };
                const bool twoOperands = x86.op_count == 2;
                if (step.kind == StepKind::Call) {
                    if (step.frameHelper) { // __SEH_prolog4: the frame of the caller
                        forgetStack(state);
                        state.ebp = -4;
                    } else if (step.purge.has_value()) {
                        shift(state, static_cast<int32>(step.purge.value()));
                    } else {
                        forgetStack(state);
                    }
                    for (int reg = 0; reg < REGISTERS; reg++)
                        if (VOLATILE_MASK & (1u << reg))
                            state.registers[reg] = NO_VALUE;
                    state.registers[0] = ReturnedValueOf(returningCallees, step.callee); // eax
                } else if (step.kind == StepKind::Other || step.kind == StepKind::ConditionalJump) {
                    if (step.id == X86_INS_PUSH && x86.op_count == 1) {
                        const int8 value = valueOf(x86.operands[0]);
                        shift(state, -4);
                        if (value != NO_VALUE)
                            setSlot(state, 0, value);
                    } else if (step.id == X86_INS_POP && x86.op_count == 1) {
                        const int8 value = valueAt(state, 0);
                        shift(state, 4);
                        if (const int reg = reg32(x86.operands[0]); reg >= 0 && reg < REGISTERS) {
                            state.registers[reg] = value;
                            if (reg == 5)
                                state.ebp.reset();
                            else if (reg == 4)
                                forgetStack(state);
                        } else {
                            write(state, memoryOf(x86.operands[0]), x86.operands[0].size, -1);
                        }
                    } else if ((step.id == X86_INS_SUB || step.id == X86_INS_ADD) && twoOperands && IsRegisterOperandOf(x86, 0, X86_REG_ESP) &&
                               x86.operands[1].type == X86_OP_IMM) {
                        const int64 amount = step.id == X86_INS_SUB ? -x86.operands[1].imm : x86.operands[1].imm;
                        if (amount > -MAX_SLOT * 16 && amount < MAX_SLOT * 16)
                            shift(state, static_cast<int32>(amount));
                        else
                            forgetStack(state);
                    } else if (step.id == X86_INS_MOV && twoOperands && IsRegisterOperandOf(x86, 0, X86_REG_EBP) && IsRegisterOperandOf(x86, 1, X86_REG_ESP)) {
                        state.ebp          = state.esp;
                        state.registers[5] = -1;
                    } else if (step.id == X86_INS_MOV && twoOperands && IsRegisterOperandOf(x86, 0, X86_REG_ESP) && IsRegisterOperandOf(x86, 1, X86_REG_EBP)) {
                        state.slots.clear();
                        state.esp = state.ebp;
                    } else if (step.id == X86_INS_LEAVE) {
                        state.slots.clear();
                        state.esp = state.ebp.has_value() ? std::optional<int32>(state.ebp.value() + 4) : std::nullopt;
                        state.ebp.reset();
                        state.registers[5] = -1;
                    } else if (step.id == X86_INS_LEA && twoOperands && x86.operands[1].type == X86_OP_MEM && x86.operands[1].mem.index == X86_REG_INVALID &&
                               (IsRegisterOperandOf(x86, 0, X86_REG_ESP) || IsRegisterOperandOf(x86, 0, X86_REG_EBP))) {
                        const auto& memory = x86.operands[1].mem;
                        const auto disp    = static_cast<int32>(std::clamp<int64>(memory.disp, -MAX_SLOT * 16, MAX_SLOT * 16));
                        const auto from    = memory.base == X86_REG_ESP ? state.esp : (memory.base == X86_REG_EBP ? state.ebp : std::nullopt);
                        const auto value   = from.has_value() ? std::optional<int32>(from.value() + disp) : std::nullopt;
                        if (IsRegisterOperandOf(x86, 0, X86_REG_EBP)) {
                            state.ebp          = value;
                            state.registers[5] = -1;
                        } else if (memory.base == X86_REG_ESP) {
                            shift(state, disp); // lea esp, [esp + 8]
                        } else {
                            state.slots.clear();
                            state.esp = value; // lea esp, [ebp - 0x10]
                        }
                    } else {
                        // the value written to a register (mov reg, reg / mov reg, [ebp + 8]) or to the stack (mov [esp + 4], eax), read before
                        // the writes
                        std::optional<int8> copied;
                        if (step.id == X86_INS_MOV && twoOperands && reg32(x86.operands[0]) >= 0)
                            copied = valueOf(x86.operands[1]);
                        const int8 stored = step.id == X86_INS_MOV && twoOperands && x86.operands[0].type == X86_OP_MEM ? valueOf(x86.operands[1]) : -1;
                        if (const auto& to = x86.operands[0]; followLocals && entryCode && stored >= 0 && to.type == X86_OP_MEM && to.size == 4 &&
                                                              to.mem.base == X86_REG_EBP && to.mem.index == X86_REG_INVALID && state.ebp.has_value() &&
                                                              to.mem.disp < 0 && frameWrites[static_cast<int32>(to.mem.disp)] == 1)
                            spilledLocals[static_cast<int32>(to.mem.disp)] = stored;
                        for (uint8 index = 0; index < x86.op_count; index++)
                            if (x86.operands[index].type == X86_OP_MEM && (x86.operands[index].access & CS_AC_WRITE))
                                write(state, memoryOf(x86.operands[index]), x86.operands[index].size, stored);
                        for (int reg = 0; reg < REGISTERS; reg++)
                            if (step.writes & (1u << reg))
                                state.registers[reg] = -1;
                        if (step.writes & (1u << 4))
                            forgetStack(state); // xchg eax, esp / and esp, -8
                        if (step.writes & (1u << 5))
                            state.ebp.reset();
                        if (copied.has_value())
                            state.registers[reg32(x86.operands[0])] = copied.value();
                        else if (const int reg = reg32(x86.operands[0]); reg >= 0 && reg < REGISTERS && x86.op_count == 2 && IsX86ConstantOperation(step.id, x86))
                            state.registers[reg] = CONSTANT_VALUE; // xor eax, eax / or eax, -1
                    }
                }
                if (pass == 0)
                    writtenIncoming[i] = writtenNow;
            }
        }
        return MakeInferredPrototype(start, parameters, secondHalves, AgreedReturn(returns, returningCallees));
    }

    // an instruction that sets its first operand to a constant whatever it held: mov reg, imm, xor / sub reg, reg (0), or reg, -1, and
    // reg, 0
    static bool IsX86ConstantOperation(unsigned int id, const cs_x86& x86)
    {
        if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG)
            return false;
        const auto& source = x86.operands[1];
        if ((id == X86_INS_XOR || id == X86_INS_SUB) && source.type == X86_OP_REG && source.reg == x86.operands[0].reg)
            return true;
        return source.type == X86_OP_IMM && (id == X86_INS_MOV || (id == X86_INS_OR && source.imm == -1) || (id == X86_INS_AND && source.imm == 0));
    }
    static bool IsX86ConstantWrite(const cs_insn& insn)
    {
        return insn.detail && IsX86ConstantOperation(insn.id, insn.detail->x86);
    }

    // the prototype of an inferred function: the type it returns (the one of the callee whose return value it returns), the parameters up to
    // the last one known, the others without a name (a1, a2, ...); a 64 bit parameter of 32 bit x86 takes two slots; a name given twice (two
    // calls of memcmp) gets a number (buf1, buf1_2)
    std::shared_ptr<const DissasmUserPrototype> MakeInferredPrototype(
          uint64 start,
          const std::vector<std::optional<std::pair<std::string_view, std::string_view>>>& parameters,
          const std::vector<bool>& secondHalves,
          const AsmFunctionDetails* returns,
          bool variadic         = false,
          bool keepReturnedName = false)
    {
        size_t count = 0;
        for (size_t argument = 0; argument < parameters.size(); argument++)
            if (parameters[argument].has_value())
                count = argument + 1;
        if (variadic)
            count = parameters.size(); // every fixed argument, then ...
        if (count == 0 && !returns && !variadic)
            return nullptr;
        auto prototype = std::make_shared<DissasmUserPrototype>();
        const auto label = std::lower_bound(
              callsFound.begin(), callsFound.end(), codeStart + start, [](const auto& item, uint64 value) { return item.first < value; });
        const std::string name = label != callsFound.end() && label->first == codeStart + start ? label->second : zone->GetLabelName("sub_", start);
        std::string text       = name + "(";
        if (returns) { // HANDLE sub_X(...): the return value of the API it returns, its name for the variables of the callers (File)
            prototype->details.returnType = prototype->strings.emplace_back(returns->returnType);
            prototype->details.returnName = prototype->strings.emplace_back(keepReturnedName ? std::string(returns->returnName) : GetReturnValueName(*returns));
            text                          = std::string(returns->returnType) + " " + text;
        }
        for (size_t argument = 0; argument < count; argument++) {
            if (argument < secondHalves.size() && secondHalves[argument])
                continue;
            if (!prototype->details.params.empty())
                text += ", ";
            if (parameters[argument].has_value()) {
                std::string unique(parameters[argument]->first);
                const auto taken = [&prototype](const std::string& candidate) {
                    return std::any_of(prototype->details.params.begin(), prototype->details.params.end(), [&candidate](const auto& parameter) {
                        return parameter.name && candidate == parameter.name;
                    });
                };
                for (uint32 number = 2; taken(unique); number++)
                    unique = std::string(parameters[argument]->first) + "_" + std::to_string(number);
                text += parameters[argument]->second.empty() ? unique : std::string(parameters[argument]->second) + " " + unique; // format: no type known
                const auto& parameterName = prototype->strings.emplace_back(std::move(unique));
                const auto& parameterType = prototype->strings.emplace_back(parameters[argument]->second);
                prototype->details.params.push_back({ parameterName.c_str(), parameterType.c_str() });
            } else {
                text += "a" + std::to_string(prototype->details.params.size() + 1);
                const auto& empty = prototype->strings.emplace_back();
                prototype->details.params.push_back({ empty.c_str(), empty.c_str() });
            }
        }
        if (variadic)
            text += prototype->details.params.empty() ? "..." : ", ...";
        text += ")";
        prototype->details.prototype    = prototype->strings.emplace_back(std::move(text));
        prototype->details.functionName = prototype->strings.emplace_back(name);
        return prototype;
    }

    // x64 Windows: the arguments the prologue keeps in their home space (mov [rsp + 8], rcx / mov [rbp + 0x10], rcx after push rbp; mov rbp,
    // rsp), a bit for each of rcx, rdx, r8, r9. MSVC keeps the callee saved registers there too (mov [rsp + 8], rbx): not an argument
    uint32 SpilledHomeArguments(const uint8* code, size_t codeLength, uint64 start)
    {
        static constexpr int HOME_REGISTERS[] = { 1, 2, 8, 9 }; // rcx, rdx, r8, r9
        cs_insn* insn = code ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return 0;
        uint32 spilled     = 0;
        int64 delta        = 0; // rsp - the rsp of the entry
        std::optional<int64> frameDelta; // rbp - the rsp of the entry
        const uint8* data  = code;
        size_t size        = codeLength;
        uint64 address     = start;
        for (uint32 decoded = 0; decoded < 16 && cs_disasm_iter(detailHandle, &data, &size, &address, insn); decoded++) {
            const cs_x86& x86 = insn->detail->x86;
            if (cs_insn_group(detailHandle, insn, CS_GRP_CALL) || cs_insn_group(detailHandle, insn, CS_GRP_JUMP) || cs_insn_group(detailHandle, insn, CS_GRP_RET))
                break;
            if (insn->id == X86_INS_PUSH)
                delta -= 8;
            else if (insn->id == X86_INS_SUB && x86.op_count == 2 && IsRegisterOperandOf(x86, 0, X86_REG_RSP) && x86.operands[1].type == X86_OP_IMM)
                delta -= x86.operands[1].imm;
            else if (insn->id == X86_INS_MOV && x86.op_count == 2 && IsRegisterOperandOf(x86, 0, X86_REG_RBP) && IsRegisterOperandOf(x86, 1, X86_REG_RSP))
                frameDelta = delta;
            else if (insn->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_REG &&
                     x86.operands[0].mem.index == X86_REG_INVALID) {
                const auto& memory = x86.operands[0].mem;
                std::optional<int64> entry; // the offset from the rsp of the entry
                if (memory.base == X86_REG_RSP)
                    entry = memory.disp + delta;
                else if (memory.base == X86_REG_RBP && frameDelta.has_value())
                    entry = memory.disp + frameDelta.value();
                const int family = GetX64RegisterFamily(x86.operands[1].reg);
                for (int argument = 0; argument < 4 && entry.has_value(); argument++)
                    if (family == HOME_REGISTERS[argument] && entry.value() == 8 + 8 * argument)
                        spilled |= 1u << argument;
            }
        }
        cs_free(insn, 1);
        return spilled;
    }

    // the arguments of a function the user gave a prototype (Y), or one the analysis inferred: arg_0 .. are its parameters (x86: in the stack,
    // 4 bytes a parameter, 8 for the 64 bit types; x64 Windows: the home space then the stack, 8 bytes a parameter, the home slots only where
    // the prologue keeps their argument register); System V / ARM pass them in registers: none
    void NameArgumentsFromPrototype(DissasmFunctionFrame& frame, const AsmFunctionDetails& prototype, DissasmArch functionArch, const uint8* code, size_t codeLength, uint64 start)
    {
        const bool isX86     = functionArch == DissasmArch::X86;
        const bool windows64 = functionArch == DissasmArch::X64 && !zone->systemVCalls;
        if (!isX86 && !windows64)
            return;
        const uint32 spilled = windows64 ? SpilledHomeArguments(code, codeLength, start) : 0;
        std::vector<uint32> offsets; // of each parameter, from the first one
        uint32 offset = 0;
        for (const auto& parameter : prototype.params) {
            offsets.push_back(offset);
            offset += windows64 || IsWideX86Type(parameter.type) ? 8u : 4u;
        }
        for (auto& variable : frame.variables) {
            if (!variable.name.starts_with("arg_") || variable.name.size() <= 4)
                continue;
            char* end           = nullptr;
            const auto argument = std::strtoul(variable.name.c_str() + 4, &end, 16); // arg_8: 8 bytes after the first argument
            if (!end || *end != 0)
                continue;
            const auto found = std::find(offsets.begin(), offsets.end(), static_cast<uint32>(argument));
            if (found == offsets.end())
                continue;
            if (const size_t index = found - offsets.begin(); windows64 && index < 4 && (spilled & (1u << index)) == 0)
                continue; // a home slot that keeps something else (a callee saved register)
            const auto& parameter       = prototype.params[found - offsets.begin()];
            const std::string_view name = parameter.name;
            if (name.empty())
                continue; // a parameter an inferred prototype does not know
            if (variable.origin.empty()) {
                variable.type   = parameter.type;
                variable.origin = "argument of " + std::string(prototype.functionName);
            }
            if (IsValidLocalVariableName(name) && !frame.HasVariableNamed(name))
                variable.name = std::string(name);
        }
    }

    // IDA (its type libraries): a variable of the frame passed to a known API (FindApiPrototype) gets the name of that argument: lea rax,
    // [rbp + var_79] then the phkResult of RegOpenKeyExW -> phkResult; mov eax, [ebp + var_8]; push eax as the hFile of CloseHandle -> hFile.
    // The code of the function is followed in its order: the frame slot a register holds (its address or its value: lea / mov / ldr / add
    // x0, sp, #n), the arguments stored in the stack (mov [rsp + 0x20] / [esp + n], str [sp, #n]) and the pushes (x86), until the call;
    // only a variable with its default name (var_ / arg_) is named, never two with the same name. The variable gets the type of the
    // argument too (the pointed type when its address is passed: PHKEY -> HKEY). Beyond IDA (its decompiler does it): the value an API
    // returns (rax / x0 / r0 after the call, copied by mov) stored in a slot gives the slot the type of the return and, when no argument
    // names it, a name after the API (mov [rbp + var_8], rax after CreateFileW -> File). The first use of a slot in the code (passed or
    // stored) gives its type, as the first call gives its name: a slot the compiler reuses for other values keeps one meaning. A slot
    // whose address is passed loses the lp of the argument (IDA: lpNumberOfBytesRead -> NumberOfBytesRead); when the argument points to a
    // structure (FindApiStructure: lpStartupInfo -> STARTUPINFOW), the slot is that structure and the slots inside it are its fields
    void NameVariablesFromCalls(DissasmFunctionFrame& frame, const uint8* code, size_t codeLength, uint64 start, uint64 limit, DissasmArch functionArch)
    {
        // only a function that calls a known API is decoded again (its calls: the flow records of the sweep)
        bool callsKnownApi = false;
        for (size_t position = FirstRecordAt(start); position < flowRecords.size() && flowRecords[position].address < limit && !callsKnownApi; position++) {
            const auto& record = flowRecords[position];
            if (record.kind != FlowKind::Call)
                continue;
            if (knownPrototypeCalls.contains(record.address) || demangledPrototypeCalls.contains(record.address) || HasComMethodPrototype(record.address) ||
                HasOtherZonePrototype(record.target, functionArch)) {
                callsKnownApi = true; // an API, a COM method, a function of another code zone (CalleePrototype)
                break;
            }
            if (record.target == NO_TARGET)
                continue;
            auto known = knownPrototypeTargets.find(record.target);
            if (known == knownPrototypeTargets.end()) {
                std::string name;
                if (record.target < codeSize) {
                    if (const auto thunk = thunkImports.find(record.target); thunk != thunkImports.end())
                        name = thunk->second;
                    else if (const auto label = std::lower_bound(callsFound.begin(), callsFound.end(), codeStart + record.target,
                                                                 [](const auto& item, uint64 value) { return item.first < value; });
                             label != callsFound.end() && label->first == codeStart + record.target)
                        name = label->second;
                } else if (const auto* other = zone->FindCodeZoneOfAddress((labelBase + record.target) & addressMask); other && other != zone) {
                    const uint64 otherStart = ((labelBase + record.target) & addressMask) - other->labelAddressBase;
                    const auto thunk        = other->thunkImports.find(otherStart);
                    name                    = thunk != other->thunkImports.end() ? thunk->second : other->GetLabelNameAt(otherStart);
                }
                const bool userPrototype = record.target < codeSize && (zone->FindUserPrototype(record.target) != nullptr || inferredPrototypes.contains(record.target)); // Y, inferred
                known = knownPrototypeTargets
                              .emplace(
                                    record.target,
                                    userPrototype || (!name.empty() &&
                                                      (FindApiPrototype(name) != nullptr || FindMethodPrototypeByName(methodPrototypes, name) != nullptr)))
                              .first;
            }
            callsKnownApi = known->second;
        }
        if (!callsKnownApi)
            return;
        constexpr uint32 MAX_INSTRUCTIONS = 20000;
        constexpr size_t MAX_SLOTS        = 32;
        const bool isArm64 = functionArch == DissasmArch::Arm64;
        const bool isArm32 = functionArch == DissasmArch::Arm || functionArch == DissasmArch::Thumb;
        const bool isX64   = functionArch == DissasmArch::X64;
        const bool isX86   = functionArch == DissasmArch::X86;
        struct SlotValue {
            int32 offset;
            bool isAddress; // lea rax, [rbp - 8]: the address of the slot; mov rax, [rbp - 8]: its value
        };
        std::array<std::optional<SlotValue>, 32> registers{};        // the frame slot a register holds: its address or its value
        std::array<const AsmFunctionDetails*, 32> returned{};         // the API whose return value a register holds
        std::array<std::optional<SlotValue>, MAX_SLOTS> stackArgs{}; // the arguments stored in the stack, by argument index
        std::vector<std::optional<SlotValue>> pushes;                // x86, System V x64: the pushed arguments, in their order
        std::vector<std::pair<int32, const AsmFunctionDetails*>> returnStores; // the slots whose first use is a return value stored there
        const auto slotValue = [](std::optional<int32> offset, bool isAddress) {
            return offset.has_value() ? std::optional<SlotValue>(SlotValue{ offset.value(), isAddress }) : std::nullopt;
        };
        // the structure of the type of the variable (ApplyFrameStructure); not for a variable the user gave a structure (or none) to
        const auto ApplyStructure = [&](DissasmLocalVariable& variable) {
            if (!zone->userVariableStructures.contains({ start, variable.frameOffset }))
                ApplyFrameStructure(frame, variable, FindApiStructure(variable.type, functionArch == DissasmArch::X64 || functionArch == DissasmArch::Arm64), false);
        };
        // a variable typed as the object of a C++ method (this of ...): any other argument / return value tells more (a slot reused)
        const auto unnamedOrigin = [](const DissasmLocalVariable& variable) { return variable.origin.empty() || variable.origin.starts_with("this of "); };
        const auto storeReturn = [&](std::optional<int32> offset, const AsmFunctionDetails* function) {
            auto* variable = offset.has_value() ? frame.FindVariable(offset.value()) : nullptr;
            if (!variable || !unnamedOrigin(*variable))
                return;
            variable->type   = std::string(function->returnType);
            variable->origin = "returned by " + std::string(function->functionName);
            returnStores.emplace_back(offset.value(), function);
        };
        const auto registerIndex = [&](unsigned int reg) -> int {
            if (isArm64) {
                if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
                    return static_cast<int>(reg - ARM64_REG_X0);
                if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
                    return static_cast<int>(reg - ARM64_REG_W0);
                return -1;
            }
            if (isArm32)
                return reg >= ARM_REG_R0 && reg <= ARM_REG_R12 ? static_cast<int>(reg - ARM_REG_R0) : -1;
            return GetX64RegisterFamily(reg);
        };
        // the register of an argument of the register conventions
        const auto argumentRegister = [&](size_t index) -> int {
            if (isArm64)
                return index < 8 ? static_cast<int>(index) : -1;
            if (isArm32)
                return index < 4 ? static_cast<int>(index) : -1;
            if (isX64) {
                static constexpr int WINDOWS[] = { 1, 2, 8, 9 }, SYSTEM_V[] = { 7, 6, 2, 1, 8, 9 };
                if (zone->systemVCalls)
                    return index < std::size(SYSTEM_V) ? SYSTEM_V[index] : -1;
                return index < std::size(WINDOWS) ? WINDOWS[index] : -1;
            }
            return -1;
        };
        // the frame offset of a memory operand of the frame (the frame register, or the stack pointer with its depth)
        const auto frameOffsetOf = [&](unsigned int base, unsigned int index, int64 disp, uint64 address) -> std::optional<int32> {
            if (isArm64) {
                if (base == ARM64_REG_X29 && frame.usesFrameRegister)
                    return static_cast<int32>(disp + frame.frameRegisterOffset);
                if (base == ARM64_REG_SP)
                    return static_cast<int32>(disp + frame.stackOffset);
                return {};
            }
            if (isArm32) {
                const unsigned int frameRegister = frame.frameRegister == 11 ? ARM_REG_R11 : (frame.frameRegister == 7 ? ARM_REG_R7 : ARM_REG_INVALID);
                if (frame.usesFrameRegister && base == frameRegister && frameRegister != ARM_REG_INVALID)
                    return static_cast<int32>(disp);
                if (base == ARM_REG_SP)
                    return static_cast<int32>(disp + frame.stackOffset);
                return {};
            }
            if (index != X86_REG_INVALID)
                return {};
            if (frame.usesFrameRegister && (base == X86_REG_RBP || base == X86_REG_EBP))
                return static_cast<int32>(disp);
            // the stack pointer: from the one of the entry, or from the frame register (MergeStackPointerSlots)
            if (base == X86_REG_RSP || base == X86_REG_ESP)
                if (const auto delta = frame.StackDeltaAt(address); delta.has_value())
                    return static_cast<int32>(disp + delta.value());
            // an alias of the stack pointer (mov r11, rsp / the biased rbp of MSVC x64: lea rbp, [rsp - 0x5f])
            if (!frame.usesFrameRegister && !frame.stackAliases.empty())
                if (const char* name = cs_reg_name(detailHandle, static_cast<x86_reg>(base)))
                    for (const auto& alias : frame.stackAliases)
                        if (address >= alias.start && address < alias.end && alias.reg == name && !alias.frameOf.has_value())
                            return static_cast<int32>(disp + alias.delta);
            return {};
        };
        uint64 callAddress         = 0;
        // the text buffers a formatting / copying function writes (swprintf_s(buffer, ...): a character pointer before its format, or named
        // buffer / dest; an API or a wrapper inferred from one): the next call that takes them names them again (the buffer then passed to
        // RegOpenKeyExW is its SubKey); so is the text an error print of the certificate services reports (CSPrintErrorLineFileData: its
        // pwszData, before the LocalFree of its hMem)
        std::unordered_set<int32> formattedBuffers;
        const auto formatsInto = [](const AsmFunctionDetails& prototype, size_t index) {
            static constexpr std::string_view TEXT_BUFFERS[] = { "char*", "wchar_t*", "LPSTR", "LPWSTR", "PSTR", "PWSTR", "STRSAFE_LPSTR", "STRSAFE_LPWSTR" };
            const std::string_view own                       = prototype.params[index].name ? prototype.params[index].name : "";
            if (own == "pwszData")
                return true;
            if (std::find(std::begin(TEXT_BUFFERS), std::end(TEXT_BUFFERS), std::string_view(prototype.params[index].type)) == std::end(TEXT_BUFFERS))
                return false;
            if (own == "buffer" || own == "dest") // a wrapper that formats / copies into its argument (its format inside: sub_X(a1, wchar_t* buffer))
                return true;
            for (size_t next = index + 1; next < prototype.params.size(); next++) {
                const std::string_view name = prototype.params[next].name ? prototype.params[next].name : "";
                if (name == "format" || name == "Format" || name.ends_with("Format"))
                    return true;
            }
            return false;
        };
        // where an argument of the call comes from: the frame slot the register / the push / the stack store holds
        const auto argumentSource = [&](size_t index) -> std::optional<SlotValue> {
            std::optional<SlotValue> source;
            if (const int reg = argumentRegister(index); reg >= 0 && reg < static_cast<int>(registers.size()))
                source = registers[reg];
            else if (isX86 && index < pushes.size())
                source = pushes[pushes.size() - 1 - index]; // the last push is the first argument
            else if (isX64 && zone->systemVCalls && index >= 6 && index - 6 < pushes.size())
                source = pushes[pushes.size() - 1 - (index - 6)]; // System V: the last push is the seventh
            if (!source.has_value() && index < MAX_SLOTS)
                source = stackArgs[index];
            return source;
        };
        const auto nameArguments = [&](const AsmFunctionDetails& prototype) {
            // the variable that receives an interface (TrackComInterfaces): typed and named after it (pWbemLocator, IWbemLocator*)
            const auto output = comOutputs.find(callAddress);
            for (size_t index = 0; index < prototype.params.size(); index++) {
                if (!prototype.params[index].name || !prototype.params[index].name[0])
                    continue; // a parameter an inferred prototype does not know
                if (std::string_view(prototype.params[index].name) == "This")
                    continue; // the object of a method: not named after it
                const bool object                     = std::string_view(prototype.params[index].name) == "this"; // of a C++ method: typed, not named
                const std::optional<SlotValue> source = argumentSource(index);
                if (!source.has_value())
                    continue;
                if (source->isAddress && prototype.params[index].type && std::string_view(prototype.params[index].type) == "va_list") {
                    const auto format = index > 0 ? argumentSource(index - 1) : std::nullopt; // the value of an argument of the function
                    NoteVariadicArgumentSlot(
                          frame,
                          prototype,
                          index,
                          source->offset,
                          format.has_value() && !format->isAddress ? std::optional<int32>(format->offset) : std::nullopt,
                          functionArch);
                }
                auto* variable                 = frame.FindVariable(source->offset);
                if (object) {
                    if (variable && variable->origin.empty()) { // the first call that passes it: the object (lea rcx, [rsp + 0x38 + var_18]), a pointer to it
                        variable->type   = source->isAddress ? GetPointedType(prototype.params[index].type) : std::string(prototype.params[index].type);
                        variable->origin = "this of " + std::string(prototype.functionName);
                    }
                    continue;
                }
                const std::string_view argument = prototype.params[index].name;
                std::string_view name           = argument;
                if (source->isAddress && name.size() > 2 && name.starts_with("lp") && std::isalpha(static_cast<unsigned char>(name[2])))
                    name.remove_prefix(2); // the variable is what the argument points to
                const bool receivesInterface = source->isAddress && output != comOutputs.end() && output->second.first == index;
                std::string interfaceVariable;
                if (receivesInterface) {
                    interfaceVariable = "p" + std::string(output->second.second.substr(output->second.second.starts_with('I') ? 1 : 0));
                    name              = interfaceVariable;
                }
                const bool formatted = formatsInto(prototype, index);
                const bool renamed   = variable && !formatted && formattedBuffers.contains(variable->frameOffset) && IsValidLocalVariableName(name) &&
                                     !frame.HasVariableNamed(name);
                if (variable && (unnamedOrigin(*variable) || renamed)) { // the first call that passes it
                    variable->type   = receivesInterface ? std::string(output->second.second) + "*"
                                       : source->isAddress ? GetPointedType(prototype.params[index].type) : std::string(prototype.params[index].type);
                    variable->origin = std::string(argument) + " of " + std::string(prototype.functionName);
                    if (source->isAddress)
                        ApplyStructure(*variable);
                }
                if (!variable || (!renamed && !(variable->name.starts_with("var_") || variable->name.starts_with("arg_"))) || !IsValidLocalVariableName(name) ||
                    frame.HasVariableNamed(name))
                    continue;
                variable->name = std::string(name);
                if (formatted)
                    formattedBuffers.insert(variable->frameOffset);
                else
                    formattedBuffers.erase(variable->frameOffset);
            }
        };

        cs_insn* insn = code ? cs_malloc(detailHandle) : nullptr;
        if (!insn)
            return;
        const uint8* data = code;
        size_t size       = static_cast<size_t>(std::min<uint64>(codeLength, limit - start));
        uint64 address    = start;
        for (uint32 decoded = 0; decoded < MAX_INSTRUCTIONS && cs_disasm_iter(detailHandle, &data, &size, &address, insn); decoded++) {
            const cs_insn& current = *insn;
            const auto flow        = GetInstructionFlow(current, functionArch);
            if (flow == X86Flow::Call) {
                if (cfgCheckCalls.contains(current.address))
                    continue; // the CFG check of the call of a method: the registers and the pushes stay
                callAddress           = current.address;
                const auto* prototype = CalleePrototype(current, functionArch);
                if (prototype)
                    nameArguments(*prototype);
                registers.fill(std::nullopt); // the callee changes the volatile registers; the arguments are consumed
                returned.fill(nullptr);
                stackArgs.fill(std::nullopt);
                // x86: the pushes the callee takes (its ret n, a stdcall API: its parameters; cdecl: 0, its caller removes them after it);
                // the ones pushed before for an outer call stay (push eax; push 0; call GetProcessHeap; push eax; call HeapAlloc)
                std::optional<uint32> taken;
                if (isX86) {
                    if (const auto purge = CalleeStackPurge(current); purge.has_value())
                        taken = purge.value() / 4;
                    else if (prototype)
                        taken = GetX86StdcallPushes(*prototype);
                }
                if (taken.has_value())
                    pushes.resize(pushes.size() - std::min<size_t>(pushes.size(), taken.value()));
                else
                    pushes.clear();
                if (prototype && !prototype->returnType.empty())
                    returned[0] = prototype; // rax / x0 / r0
                continue;
            }
            if (flow == X86Flow::Jump || flow == X86Flow::Return) {
                registers.fill(std::nullopt);
                returned.fill(nullptr);
                stackArgs.fill(std::nullopt);
                pushes.clear();
                continue;
            }
            // the register written by the instruction and what it holds then
            int destination = -1;
            std::optional<SlotValue> held;
            const AsmFunctionDetails* heldReturn = nullptr;
            bool knownEffect                     = false;
            if (isArm64 || isArm32) {
                const uint8 count = isArm64 ? current.detail->arm64.op_count : current.detail->arm.op_count;
                if (count == 0)
                    continue;
                const auto opType = [&](uint8 i) { return isArm64 ? static_cast<int>(current.detail->arm64.operands[i].type) : static_cast<int>(current.detail->arm.operands[i].type); };
                const auto opReg  = [&](uint8 i) { return isArm64 ? static_cast<unsigned int>(current.detail->arm64.operands[i].reg) : static_cast<unsigned int>(current.detail->arm.operands[i].reg); };
                const auto opImm  = [&](uint8 i) { return isArm64 ? static_cast<int64>(current.detail->arm64.operands[i].imm) : static_cast<int64>(current.detail->arm.operands[i].imm); };
                const int REG = isArm64 ? ARM64_OP_REG : ARM_OP_REG, IMM = isArm64 ? ARM64_OP_IMM : ARM_OP_IMM, MEM = isArm64 ? ARM64_OP_MEM : ARM_OP_MEM;
                const bool isStore = isArm64 ? (current.id == ARM64_INS_STR || current.id == ARM64_INS_STUR) : current.id == ARM_INS_STR;
                const bool isLoad  = isArm64 ? (current.id == ARM64_INS_LDR || current.id == ARM64_INS_LDUR) : current.id == ARM_INS_LDR;
                const bool isAdd   = isArm64 ? current.id == ARM64_INS_ADD : current.id == ARM_INS_ADD;
                const bool isSub   = isArm64 ? current.id == ARM64_INS_SUB : current.id == ARM_INS_SUB;
                const bool isMove  = isArm64 ? current.id == ARM64_INS_MOV : current.id == ARM_INS_MOV;
                if (isStore && count == 2 && opType(1) == MEM) {
                    // str x1, [sp, #8]: an argument in the stack
                    const int source = registerIndex(opReg(0));
                    if (const auto slot = GetArgumentSlot(current, functionArch, false); slot.has_value() && slot.value() < MAX_SLOTS)
                        stackArgs[slot.value()] = source >= 0 ? registers[source] : std::nullopt;
                    // str x0, [x29, #-8] after the call: the return value kept in a variable
                    if (source >= 0 && source < static_cast<int>(returned.size()) && returned[source]) {
                        const unsigned int base = isArm64 ? static_cast<unsigned int>(current.detail->arm64.operands[1].mem.base)
                                                          : static_cast<unsigned int>(current.detail->arm.operands[1].mem.base);
                        const bool noIndex = isArm64 ? current.detail->arm64.operands[1].mem.index == ARM64_REG_INVALID
                                                     : current.detail->arm.operands[1].mem.index == ARM_REG_INVALID;
                        const int64 disp   = isArm64 ? current.detail->arm64.operands[1].mem.disp : current.detail->arm.operands[1].mem.disp;
                        if (noIndex)
                            storeReturn(frameOffsetOf(base, isArm64 ? ARM64_REG_INVALID : ARM_REG_INVALID, disp, current.address), returned[source]);
                    }
                    continue;
                }
                // every register the instruction writes forgets what it held (ldp x0, x1 / ldm)
                for (uint8 i = 0; i < count; i++) {
                    const uint8 access = isArm64 ? current.detail->arm64.operands[i].access : current.detail->arm.operands[i].access;
                    if (opType(i) == REG && (access & CS_AC_WRITE))
                        if (const int reg = registerIndex(opReg(i)); reg >= 0 && reg < static_cast<int>(registers.size())) {
                            registers[reg].reset();
                            returned[reg] = nullptr;
                        }
                }
                if (opType(0) == REG)
                    destination = registerIndex(opReg(0));
                if (isLoad && count == 2 && opType(1) == MEM) {
                    const auto& base = isArm64 ? static_cast<unsigned int>(current.detail->arm64.operands[1].mem.base) : static_cast<unsigned int>(current.detail->arm.operands[1].mem.base);
                    const auto& indexRegister = isArm64 ? static_cast<unsigned int>(current.detail->arm64.operands[1].mem.index) : static_cast<unsigned int>(current.detail->arm.operands[1].mem.index);
                    const int64 disp = isArm64 ? current.detail->arm64.operands[1].mem.disp : current.detail->arm.operands[1].mem.disp;
                    const bool noIndex = isArm64 ? indexRegister == ARM64_REG_INVALID : indexRegister == ARM_REG_INVALID;
                    if (noIndex) // the value of the slot
                        held = slotValue(frameOffsetOf(base, isArm64 ? ARM64_REG_INVALID : ARM_REG_INVALID, disp, current.address), false);
                    knownEffect = true;
                } else if ((isAdd || isSub) && count == 3 && opType(1) == REG && opType(2) == IMM) {
                    const int64 value = isSub ? -opImm(2) : opImm(2);
                    held        = slotValue(frameOffsetOf(opReg(1), isArm64 ? ARM64_REG_INVALID : ARM_REG_INVALID, value, current.address), true); // its address
                    knownEffect = true;
                } else if (isMove && count == 2 && opType(1) == REG) {
                    const int source = registerIndex(opReg(1));
                    held             = source >= 0 && source < static_cast<int>(registers.size()) ? registers[source] : std::nullopt;
                    heldReturn       = source >= 0 && source < static_cast<int>(returned.size()) ? returned[source] : nullptr;
                    knownEffect      = true;
                }
                if (destination >= 0 && destination < static_cast<int>(registers.size())) {
                    registers[destination] = knownEffect ? held : std::nullopt;
                    returned[destination]  = heldReturn;
                }
                continue;
            }
            // x86 / x64
            const cs_x86& x86 = current.detail->x86;
            // the clean up of a cdecl call: pop ecx / add esp, 8 removes the last pushes
            if (isX86 && current.id == X86_INS_POP && !pushes.empty())
                pushes.pop_back();
            if (isX86 && current.id == X86_INS_ADD && x86.op_count == 2 && IsRegisterOperandOf(x86, 0, X86_REG_ESP) && x86.operands[1].type == X86_OP_IMM)
                pushes.resize(pushes.size() - std::min<size_t>(pushes.size(), static_cast<size_t>(x86.operands[1].imm) / 4));
            if (isX64 && current.id != X86_INS_PUSH && x86.op_count >= 1 &&
                (IsRegisterOperandOf(x86, 0, X86_REG_RSP) ||
                 (x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && IsRegisterOperandOf(x86, 1, X86_REG_RSP))))
                pushes.clear(); // sub rsp, 8 / mov rbp, rsp of the prologue: the pushes before it are no arguments
            if (current.id == X86_INS_PUSH && x86.op_count == 1) {
                const auto& op = x86.operands[0];
                if (op.type == X86_OP_REG) {
                    const int source = registerIndex(op.reg);
                    pushes.push_back(source >= 0 ? registers[source] : std::nullopt);
                } else if (op.type == X86_OP_MEM)
                    pushes.push_back(slotValue(frameOffsetOf(op.mem.base, op.mem.index, op.mem.disp, current.address), false));
                else
                    pushes.push_back(std::nullopt);
                continue;
            }
            if ((current.id == X86_INS_MOV || current.id == X86_INS_LEA) && x86.op_count == 2) {
                const auto& to   = x86.operands[0];
                const auto& from = x86.operands[1];
                if (to.type == X86_OP_MEM) {
                    // mov [rsp + 0x20], rax / mov [esp + 4], eax: an argument in the stack
                    const int source = from.type == X86_OP_REG ? registerIndex(from.reg) : -1;
                    if (const auto slot = GetArgumentSlot(current, functionArch, zone->systemVCalls); slot.has_value() && slot.value() < MAX_SLOTS)
                        stackArgs[slot.value()] = source >= 0 ? registers[source] : std::nullopt;
                    // mov [rbp - 8], rax after the call: the return value kept in a variable
                    if (source >= 0 && source < static_cast<int>(returned.size()) && returned[source])
                        storeReturn(frameOffsetOf(to.mem.base, to.mem.index, to.mem.disp, current.address), returned[source]);
                    continue;
                }
                if (to.type == X86_OP_REG) {
                    destination = registerIndex(to.reg);
                    if (from.type == X86_OP_MEM) // lea: the address; mov: the value
                        held = slotValue(frameOffsetOf(from.mem.base, from.mem.index, from.mem.disp, current.address), current.id == X86_INS_LEA);
                    else if (from.type == X86_OP_REG) {
                        const int source = registerIndex(from.reg);
                        held             = source >= 0 && source < static_cast<int>(registers.size()) ? registers[source] : std::nullopt;
                        heldReturn       = source >= 0 && source < static_cast<int>(returned.size()) ? returned[source] : nullptr;
                    }
                    if (destination >= 0 && destination < static_cast<int>(registers.size())) {
                        registers[destination] = held;
                        returned[destination]  = heldReturn;
                    }
                    continue;
                }
            }
            // any other write forgets what the register held
            const auto forget = [&](unsigned int reg) {
                if (const int index = registerIndex(reg); index >= 0 && index < static_cast<int>(registers.size())) {
                    registers[index].reset();
                    returned[index] = nullptr;
                }
            };
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                    forget(x86.operands[index].reg);
            for (uint8 index = 0; index < current.detail->regs_write_count; index++)
                forget(current.detail->regs_write[index]);
        }
        cs_free(insn, 1);

        // the variables of the return values that no argument named: a name after the API (a second variable of the same API: File_2)
        for (const auto& [offset, function] : returnStores) {
            auto* variable = frame.FindVariable(offset);
            if (!variable || !(variable->name.starts_with("var_") || variable->name.starts_with("arg_")))
                continue;
            const std::string name = GetReturnValueName(*function);
            for (uint32 copy = 1; copy <= 9; copy++) {
                const std::string candidate = copy == 1 ? name : name + "_" + std::to_string(copy);
                if (!IsValidLocalVariableName(candidate))
                    break;
                if (!frame.HasVariableNamed(candidate)) {
                    variable->name = candidate;
                    break;
                }
            }
        }
    }

    // a label on the line of its instruction, the local variables of a function below its label
    void PlaceLabel(const std::pair<uint64, std::string>& call)
    {
        const uint64 callValue = call.first;
        const auto line        = LineOfOffset(callValue);
        if (!line.has_value() || line.value() >= lines)
            return; // the target is after the last decoded instruction (trailing data), it has no line
        const uint32 diffLines = line.value();

        const uint64 relativeAddress = callValue - codeStart;
        annotations.insert({ diffLines + extraLines, { call.second, relativeAddress } });
        annotations.add_initial_name(call.second);
        extraLines++;

        // the variable annotations pack the function start on 32 bits (the zone sizes are 32 bits)
        if (!hasDetailHandle || relativeAddress >= codeSize || relativeAddress > 0xFFFFFFFFull ||
            !std::binary_search(functionStarts.begin(), functionStarts.end(), relativeAddress))
            return;
        const auto nextFunction = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
        uint64 limit            = nextFunction != functionStarts.end() ? *nextFunction : codeSize;
        if (functionEntries) {
            const auto entry = functionEntries->find(callValue);
            if (entry != functionEntries->end() && entry->second.size > 0 && entry->second.size < limit - relativeAddress)
                limit = relativeAddress + entry->second.size;
        }
        if (const auto table = instructionSet.NextDataRangeStart(relativeAddress); table.has_value() && table.value() < limit)
            limit = table.value(); // the jump table after the code of the function
        const uint64 bytesToRead = std::min<uint64>(limit - relativeAddress, DISSASM_MAX_ANALYZED_FUNCTION_SIZE);
        auto functionData        = obj->GetData().Get(codeStart + relativeAddress, static_cast<uint32>(bytesToRead), false);
        if (!functionData.IsValid())
            return;

        DissasmFunctionFrame frame{};
        const auto functionArch = zone->GetArchAt(relativeAddress);
        bool analyzed           = false;
        if (functionArch == DissasmArch::Arm64) {
            // the end of its paths (ComputeFunctionEnds: the cases of its switches): the code after its rets before it is its own
            const auto start      = std::lower_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
            const uint64 pathsEnd = start != functionStarts.end() && *start == relativeAddress && functionEnds.size() == functionStarts.size()
                                          ? std::min<uint64>(functionEnds[static_cast<size_t>(start - functionStarts.begin())], limit)
                                          : 0;
            analyzed              = AnalyzeArm64FunctionFrame(
                  detailHandle,
                  functionData.GetData(),
                  functionData.GetLength(),
                  relativeAddress,
                  limit,
                  frame,
                  [this](const cs_insn& call) { return noReturnCalls.contains(call.address); },
                  pathsEnd,
                  [this](const cs_insn& call) {
                      const auto helper = stackHelperCalls.find(call.address);
                      return helper != stackHelperCalls.end() ? helper->second : 0;
                  });
        } else if (functionArch == DissasmArch::Arm || functionArch == DissasmArch::Thumb)
            analyzed = AnalyzeArm32FunctionFrame(
                  detailHandle,
                  functionData.GetData(),
                  functionData.GetLength(),
                  relativeAddress,
                  limit,
                  functionArch == DissasmArch::Thumb,
                  frame,
                  [this](const cs_insn& call) { return noReturnCalls.contains(call.address); });
        else {
            const auto noReturn    = [this](const cs_insn& call) { return noReturnCalls.contains(call.address); };
            const auto switchCases = [this](const cs_insn& jump) -> const std::vector<uint64>* {
                const auto cases = switchCaseTargets.find(jump.address);
                return cases != switchCaseTargets.end() ? &cases->second : nullptr;
            };
            analyzed = AnalyzeX86FunctionFrame(
                  detailHandle,
                  functionData.GetData(),
                  functionData.GetLength(),
                  relativeAddress,
                  limit,
                  is64,
                  frame,
                  is64 ? X86FrameHelperCheck{} : X86FrameHelperCheck([this](const cs_insn& call) {
                      return IsFrameHelper(static_cast<uint64>(call.detail->x86.operands[0].imm));
                  }),
                  noReturn,
                  switchCases);
            const auto stackPurge = is64 ? X86CalleeStackPurge{} : X86CalleeStackPurge([this](const cs_insn& call) { return CalleeStackPurge(call); });
            if (!analyzed) // no frame register (MSVC x64, x86 FPO / GCC -O2): the slots through the stack pointer
                analyzed = AnalyzeX86StackFrame(
                      detailHandle, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, is64, frame, stackPurge, noReturn, switchCases);
            else if (frame.usesFrameRegister) {
                // its stack pointer too: the slots through rsp / esp (the arguments stored for the calls, the locals of an aligned frame:
                // and esp, -8; IDA: [esp+1F8h+var_1F4]) in the offsets of the frame register
                DissasmFunctionFrame stackFrame{};
                if (AnalyzeX86StackFrame(
                          detailHandle, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, is64, stackFrame, stackPurge, noReturn, switchCases))
                    MergeStackPointerSlots(frame, std::move(stackFrame), is64);
            }
        }
        bool readOtherCode = false;
        if (analyzed && functionArch == DissasmArch::Arm64 && arm64FuncletsOfParent.contains(relativeAddress)) {
            AddArm64FuncletSlots(frame); // ARM64 SEH / C++ EH: the slots of the frame the funclets use through x29
            readOtherCode = true;
        }
        if (analyzed && functionArch == DissasmArch::Arm64 && coldChunksOf.contains(relativeAddress)) {
            AddArm64ColdChunkSlots(frame); // the cold blocks of the function (DetectColdBlocks)
            readOtherCode = true;
        }
        if (analyzed && functionArch == DissasmArch::Arm64 && frame.variadic.has_value()) {
            InferVariadicPrototype(frame); // its fixed arguments, its format
            readOtherCode = true;
        }
        if (analyzed && functionArch == DissasmArch::X64 && funcletsOfParent.contains(relativeAddress)) {
            AddFuncletSlots(frame); // x64 SEH / C++ EH: the slots of the frame only the funclets use
            readOtherCode = true;
        }
        if (analyzed && functionArch == DissasmArch::X86 && frame.usesFrameRegister && x86FuncletsOfParent.contains(relativeAddress)) {
            AddX86FuncletSlots(frame); // 32 bit C++ EH / SEH: the code run on the frame of the function, its slots
            readOtherCode = true;
        }
        if (analyzed && functionArch == DissasmArch::X64 && !frame.usesFrameRegister && functionEntries)
            if (const auto entry = functionEntries->find(callValue); entry != functionEntries->end() && !entry->second.chunks.empty()) {
                AddChunkFrames(frame, entry->second); // x64: the chunks of the function (its cold code), on its frame
                readOtherCode = true;
            }
        if (analyzed && (functionArch == DissasmArch::X86 || functionArch == DissasmArch::X64) && coldChunksOf.contains(relativeAddress)) {
            AddColdChunkSlots(frame); // the cold blocks of the function (DetectColdBlocks)
            readOtherCode = true;
        }
        if (readOtherCode) { // the bytes of the funclets / chunks were read through the same cache: the view of the function is read again
            functionData = obj->GetData().Get(codeStart + relativeAddress, static_cast<uint32>(bytesToRead), false);
            if (!functionData.IsValid())
                return;
        }
        if (!analyzed || (frame.variables.empty() && frame.savedRegistersSize == 0 && !frame.readsReturnAddress))
            return;
        if (frame.variables.empty()) { // a frame with saved registers only (their var_s0), or its return address read: nothing to name
            frames.push_back(std::move(frame));
            return;
        }
        // the prototype the user gave the function (Y): its arguments first (the names of the calls do not replace them)
        if (const auto* prototype = zone->FindUserPrototype(relativeAddress))
            NameArgumentsFromPrototype(frame, *prototype, functionArch, functionData.GetData(), functionData.GetLength(), relativeAddress);
        else if (const auto inferred = inferredPrototypes.find(relativeAddress); inferred != inferredPrototypes.end())
            NameArgumentsFromPrototype(frame, inferred->second->details, functionArch, functionData.GetData(), functionData.GetLength(), relativeAddress);
        variadicArgumentSlot.reset();
        NameVariablesFromCalls(frame, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, functionArch);
        if (variadicArgumentSlot.has_value() && !variadicArgumentSlot->conflict)
            InferFormatWrapperPrototype(relativeAddress, functionArch); // its fixed arguments, its format, ...
        if (functionArch == DissasmArch::X64 && functionEntries) // x64 FH4: the objects the unwinding destroys
            if (const auto entry = functionEntries->find(callValue); entry != functionEntries->end() && !entry->second.exceptionObjects.empty())
                AddExceptionObjects(frame, entry->second);
        // the structures the user gave (Alt+Q), over the variables and the structures of the analysis
        const auto& userStructures = zone->userVariableStructures;
        for (auto user = userStructures.lower_bound({ relativeAddress, INT32_MIN }); user != userStructures.end() && user->first.first == relativeAddress; ++user) {
            auto* variable = frame.FindVariable(user->first.second);
            const auto* structure =
                  user->second.empty() ? nullptr : FindApiStructure(user->second, functionArch == DissasmArch::X64 || functionArch == DissasmArch::Arm64);
            if (variable && structure && ApplyFrameStructure(frame, *variable, structure, true))
                variable->type = structure->name;
        }
        for (auto& variable : frame.variables)
            variable.analysisName = variable.name; // a name different from it is the user's (the annotations)
        // IDA like: the variables are listed right below the function label
        for (const auto& variable : frame.variables) {
            annotations.insert({ diffLines + extraLines, { std::string{}, PackLocalVariableAnnotation(relativeAddress, variable.frameOffset) } });
            extraLines++;
        }
        frames.push_back(std::move(frame));
    }

    // runs until the scan ends (true) or the deadline is reached (false: Run continues later from the same point)
    bool Run(std::chrono::steady_clock::time_point deadline)
    {
        constexpr uint32 INSTRUCTIONS_BETWEEN_CLOCK_CHECKS = 512;
        constexpr uint32 LABELS_BETWEEN_CLOCK_CHECKS       = 16;
        uint32 counter                                     = 0;
        for (;;) {
            switch (phase) {
            case Phase::Sweep:
                if (linesToDecode == 0 || !walker.Next(insn)) {
                    EndSweep();
                    break;
                }
                linesToDecode--;
                AnalyzeInstruction();
                if (++counter % INSTRUCTIONS_BETWEEN_CLOCK_CHECKS == 0 && std::chrono::steady_clock::now() >= deadline)
                    return false;
                break;
            case Phase::Recount:
                if (!recounter->Run(deadline))
                    return false;
                lines = recounter->lines;
                recounter.reset();
                recounted = true;
                if (recountOnly) { // the reached padding: the sweep is done (FinishSweep ran), the labels follow
                    recountOnly = false;
                    phase       = Phase::Labels;
                    break;
                }
                ResetSweep();
                phase = Phase::Sweep;
                break;
            case Phase::Labels:
                if (labelIndex >= callsFound.size()) {
                    phase = Phase::Done;
                    break;
                }
                PlaceLabel(callsFound[labelIndex++]);
                if (++counter % LABELS_BETWEEN_CLOCK_CHECKS == 0 && std::chrono::steady_clock::now() >= deadline)
                    return false;
                break;
            case Phase::Done:
                return true;
            }
        }
    }

    // the padding (align lines) that the code reaches: a fall through (after a call only when no function starts after the padding: a
    // call to a function that does not return, then the padding of the next function) or a branch into it. Its instruction starts are
    // added to the instruction set; true when there are new ones
    bool AddReachedPadding()
    {
        if (paddingRuns.empty())
            return false;
        std::vector<uint64> targets; // the code that a branch reaches (relative)
        for (const auto& xref : xrefs.byTarget)
            if ((xref.kind == DissasmXrefKind::Call || xref.kind == DissasmXrefKind::Jump || xref.kind == DissasmXrefKind::ConditionalJump ||
                 xref.kind == DissasmXrefKind::Switch) &&
                xref.to >= labelBase && xref.to - labelBase < codeSize)
                targets.push_back(xref.to - labelBase);
        std::sort(targets.begin(), targets.end());
        std::vector<uint64> starts;
        for (const auto& run : paddingRuns) {
            std::optional<uint64> from;
            if (run.fallsThrough && !noReturnCalls.contains(run.previousAddress) && !(run.afterCall && callsMap.contains(codeStart + run.end)))
                from = run.start;
            else if (const auto target = std::lower_bound(targets.begin(), targets.end(), run.start); target != targets.end() && *target < run.end)
                from = *target;
            if (!from.has_value())
                continue;
            // its instructions, decoded one by one
            const auto bytes = obj->GetData().Get(codeStart + from.value(), static_cast<uint32>(run.end - from.value()), false);
            if (!bytes.IsValid())
                continue;
            const uint8* data = bytes.GetData();
            size_t size       = bytes.GetLength();
            uint64 address    = from.value();
            while (size > 0 && address < run.end) {
                starts.push_back(address);
                if (zone->IsArm64Code()) {
                    const size_t step = std::min<size_t>(4, size);
                    data += step;
                    size -= step;
                    address += step;
                } else if (!DecodeX86Line(handle, &data, &size, &address, insn, nullptr, DISSASM_NO_PADDING_ALIGNMENT, nullptr))
                    break;
            }
        }
        auto& reached        = instructionSet.reachablePadding;
        const size_t before  = reached.size();
        reached.insert(reached.end(), starts.begin(), starts.end());
        std::sort(reached.begin(), reached.end());
        reached.erase(std::unique(reached.begin(), reached.end()), reached.end());
        return reached.size() != before;
    }

    // the end of a sweep: the new tables become data lines (the lines are counted again, then a new sweep), the padding that the code
    // reaches becomes instructions (the lines are counted again), then the labels are placed
    void EndSweep()
    {
        if (!is64 && arch == DissasmArch::X86)
            AddExceptionData(); // before the new tables become data lines
        InferNoReturnFunctions();
        const auto reachedBefore = instructionSet.reachablePadding;
        const bool paddingReached = passes < DISSASM_MAX_TABLE_PASSES && AddReachedPadding();
        if (!pendingRanges.empty() && passes < DISSASM_MAX_TABLE_PASSES) {
            auto ranges = instructionSet.dataRanges;
            for (const auto& range : pendingRanges)
                instructionSet.AddDataRange(range);
            pendingRanges.clear();
            recountedOffsets.clear();
            recounter = std::make_unique<DissasmLineCounter>(recountedOffsets, zone->zoneDetails, obj, &zone->instructionBoundaries, zone->paddingAlignmentBase);
            if (recounter->Start(zone->capstoneArch, internalArchitecture, &instructionSet)) {
                passes++;
                phase = Phase::Recount;
                return;
            }
            recounter.reset();
            instructionSet.dataRanges = std::move(ranges); // the lines can not be counted again: the tables stay instructions
            instructionSet.reachablePadding = reachedBefore;
        }
        FinishSweep();
        NameSecurityCookieFunctions();
        NameArm64ECThunks();
        NameOtherZoneThunks();
        NameRunTimeFunctionsByCode();
        switchCaseTargets = SwitchCases();
        ComputeFunctionEnds();
        DetectFunctionChunks();
        DetectColdBlocks();
        IndexColdChunks();
        FindArm64StackHelpers();
        ComputeApiCategories();
        InferPrototypes();
        AddGccMethodPrototypes();
        TrackComInterfaces();
        CollectArgumentDefinitions();
        if (!is64 && arch == DissasmArch::X86)
            MarkX86ExceptionScopes();
        if (paddingReached && pendingRanges.empty()) {
            // the reached padding only: the lines are counted again, the instructions and the analysis stay
            recountedOffsets.clear();
            recounter = std::make_unique<DissasmLineCounter>(recountedOffsets, zone->zoneDetails, obj, &zone->instructionBoundaries, zone->paddingAlignmentBase);
            if (recounter->Start(zone->capstoneArch, internalArchitecture, &instructionSet)) {
                passes++;
                recountOnly = true;
                phase       = Phase::Recount;
                return;
            }
            recounter.reset();
            instructionSet.reachablePadding = reachedBefore;
        }
        phase = Phase::Labels;
    }

    float GetProgress() const
    {
        // the sweep is most of the work
        const float sweepDone = lines == 0 ? 1.0f : static_cast<float>(lines - linesToDecode) / static_cast<float>(lines);
        // the sweeps after the first one (the tables became data lines) and their line counts: 0.8 .. 0.9, every pass after the previous one
        const auto rescanProgress = [this](float fraction) {
            return 0.8f + 0.1f * (static_cast<float>(passes - 2) + fraction) / static_cast<float>(DISSASM_MAX_TABLE_PASSES - 1);
        };
        if (phase == Phase::Recount)
            return rescanProgress(0.5f * (recounter ? recounter->GetProgress() : 1.0f));
        if (phase == Phase::Sweep)
            return passes == 1 ? 0.8f * sweepDone : rescanProgress(0.5f + 0.5f * sweepDone);
        if (phase == Phase::Labels) {
            const float start = passes == 1 ? 0.8f : 0.9f;
            return callsFound.empty() ? 1.0f : start + (1.0f - start) * static_cast<float>(labelIndex) / static_cast<float>(callsFound.size());
        }
        return 1.0f;
    }

    // the last instruction of every chunk (DissasmCodeZone::chunkEnds): not its padding (int3, nop, align)
    std::unordered_map<uint64, uint64> LastInstructionsOfChunks()
    {
        constexpr uint32 MAX_CHUNK_INSTRUCTIONS = 0x10000;
        std::unordered_map<uint64, uint64> ends;
        for (const auto& chunk : chunks) {
            DissasmCodeLinesWalker probe(
                  obj, codeStart, codeSize, handle, chunk.start, &zone->instructionBoundaries, zone->paddingAlignmentBase, &instructionSet);
            std::optional<uint64> last;
            for (uint32 count = 0; count < MAX_CHUNK_INSTRUCTIONS && probe.Next(insn) && insn->address < chunk.end; count++)
                if (insn->id != 0 && (IsArmArch(arch) || (insn->id != X86_INS_INT3 && insn->id != X86_INS_NOP)))
                    last = insn->address;
            if (last.has_value())
                ends[last.value()] = chunk.function;
        }
        return ends;
    }

    // the results become the analysis of the zone; the number of lines added to the instructions (labels, local variables)
    uint32 Commit()
    {
        // 32 bit: what every function takes from the stack of its caller (ret 8; a plain ret: 0 only when it reads no stack argument, else it
        // may be a cdecl one cleaned up later); the listing leaves to such a call the pushes it takes when they are between the arguments of
        // another call
        zone->calleeStackPurges.clear();
        // 32 bit x86: the format wrappers known since the labels phase only (sub_4CBAD9(const wchar_t* format, ...)): the pushes of the blocks
        // that jump to their calls, as CollectArgumentDefinitions does for the callees known before it (their format, its conversions)
        if (!is64 && !zone->IsArmCode() && hasDetailHandle && !formatWrappers.empty() && functionEnds.size() == functionStarts.size()) {
            const auto toWrapper = [this](const FlowRecord& record) { return record.target != NO_TARGET && formatWrappers.contains(record.target); };
            for (size_t index = 0; index < functionStarts.size(); index++)
                if (zone->GetArchAt(functionStarts[index]) == DissasmArch::X86)
                    CollectX86JumpedPushes(functionStarts[index], functionEnds[index], toWrapper);
        }
        if (!is64 && !zone->IsArmCode() && hasDetailHandle)
            for (const uint64 start : functionStarts) {
                auto known = calleePurges.find(start);
                if (known == calleePurges.end())
                    known = calleePurges.emplace(start, DecodeCalleePurge(start)).first;
                if (!known->second.has_value() || known->second.value() > 0x400)
                    continue;
                if (known->second.value() > 0 || TakesNoStackArguments(start))
                    zone->calleeStackPurges[start] = known->second.value();
            }
        zone->xrefs                     = std::move(xrefs);
        zone->thunkImports              = std::move(thunkImports);
        zone->switchJumps               = std::move(switchJumps);
        zone->resolvedAddresses         = std::move(resolvedAddresses);
        zone->adrpPages                 = std::move(adrpPages);
        zone->imageBaseTables           = std::move(imageBaseTables);
        zone->functionStarts            = std::move(functionStarts);
        zone->functionEnds              = std::move(functionEnds);
        zone->chunkEnds                 = LastInstructionsOfChunks();
        zone->functionChunks            = std::move(chunks);
        zone->functionApiCategories     = std::move(functionApiCategories);
        zone->inferredPrototypes        = std::move(inferredPrototypes);
        zone->methodPrototypes          = std::move(methodPrototypes);
        zone->returnValueConstants      = std::move(returnValueConstants);
        zone->argumentDefinitions       = std::move(argumentDefinitions);
        zone->interfaceCalls            = std::move(interfaceCalls);
        zone->noReturnFunctions.assign(noReturnStarts.begin(), noReturnStarts.end());
        std::sort(zone->noReturnFunctions.begin(), zone->noReturnFunctions.end());
        zone->noReturnCalls = std::move(noReturnCalls);
        zone->dissasmType.annotations   = std::move(annotations);
        MergeChunkFrames();
        LinkFuncletFrames();
        LinkArm64FuncletFrames();
        zone->localVariables.functions  = std::move(frames);
        zone->exceptionMarks            = std::move(exceptionMarks);
        for (auto& [address, name] : exceptionFieldNames) // 32 bit: the fields of the exception tables (AddExceptionData)
            zone->fieldNames.emplace(address, std::move(name));
        // the tables that became data lines: their entries show the names of their cases
        zone->tableEntries.clear();
        for (const auto& [entry, target] : tableEntries)
            if (instructionSet.DataRangeAt(entry))
                zone->tableEntries.emplace(entry, target);
        zone->instructionSet = std::move(instructionSet);
        if (recounted) {
            zone->cachedCodeOffsets = std::move(recountedOffsets);
            zone->asmLinesCount     = lines;
        }
        return extraLines;
    }
};

// The zone must have bytes in the file and its entry point inside it
inline bool IsValidCodeZone(const DisassemblyZone& zoneDetails, Reference<GView::Object> obj)
{
    if (zoneDetails.size == 0 || zoneDetails.size > UINT64_MAX - zoneDetails.startingZonePoint)
        return false;
    // the lines end with the file when the zone goes past it; an uninitialized zone has no bytes in the file
    if (zoneDetails.startingZonePoint >= obj->GetData().GetSize() && !zoneDetails.isUninitialized)
        return false;
    // the entry point may be after the end of the file (a truncated file): the lines are counted until there, the entry point simply has
    // no line (the init must not fail on every paint). A zone without an entry point (another executable section) is valid.
    return zoneDetails.HasEntryPoint() || zoneDetails.entryPoint == NO_ENTRY_POINT;
}

DissasmCodeZone::DissasmCodeZone() = default;

DissasmCodeZone::~DissasmCodeZone()
{
    deepScan.reset(); // before the decode handle
    if (decodeHandle != 0)
        cs_close(&decodeHandle);
}

csh DissasmCodeZone::GetDecodeHandle() const
{
    // opening a handle allocates the capstone tables: it was done for every decoded line before. The instruction details (groups,
    // operands) give the meaning of the instructions (GetX86Flow / GetX86OperandsInfo).
    if (decodeHandle == 0 && hasDecoder) {
        if (cs_open(capstoneArch, static_cast<cs_mode>(internalArchitecture), &decodeHandle) != CS_ERR_OK)
            decodeHandle = 0;
        else if (cs_option(decodeHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
            cs_close(&decodeHandle); // sets the handle to 0
    }
    return decodeHandle;
}

std::string DissasmCodeZone::GetLabelName(std::string_view prefix, uint64 address) const
{
    LocalString<64> name;
    name.SetFormat("%.*s%llX", static_cast<int>(prefix.size()), prefix.data(), static_cast<unsigned long long>(labelAddressBase + address));
    return name.GetText();
}

void DissasmCodeZone::MigrateLegacyLabelNames()
{
    if (cachedCodeOffsets.empty())
        return;
    auto& annotations      = dissasmType.annotations;
    const uint64 codeStart = cachedCodeOffsets[0].offset;
    for (auto& [line, details] : annotations.mappings) {
        if (IsLocalVariableAnnotation(details))
            continue;
        // the initial name of the label (its name before any rename of the user)
        std::string initialName = details.first;
        const auto initial      = annotations.current_name_to_initial_name.find(details.first);
        if (initial != annotations.current_name_to_initial_name.end())
            initialName = initial->second;

        std::string newInitialName;
        if (initialName == FormatFunctionName(codeStart + details.second, "sub_0x").GetText())
            newInitialName = GetLabelName("sub_", details.second);
        else if (initialName == FormatFunctionName(codeStart + details.second, "offset_0x").GetText())
            newInitialName = GetLabelName("loc_", details.second);
        else
            continue; // EntryPoint, or already a VA name

        const bool isRenamed           = details.first != initialName;
        const std::string currentName  = isRenamed ? details.first : newInitialName;
        annotations.initial_name_to_current_name.erase(initialName);
        annotations.current_name_to_initial_name.erase(details.first);
        annotations.initial_name_to_current_name[newInitialName] = currentName;
        annotations.current_name_to_initial_name[currentName]    = newInitialName;
        details.first                                            = currentName;
    }
}

DissasmCommentAnchor DissasmCodeZone::GetLineAnchor(const DissasmAsmPreCacheLine& line)
{
    DissasmCommentAnchor anchor;
    if (line.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition) {
        anchor.kind        = DissasmCommentAnchor::Kind::Variable;
        anchor.address     = line.localVariableFunction;
        anchor.frameOffset = line.localVariableOffset;
    } else if (line.size == 0) {
        anchor.kind    = DissasmCommentAnchor::Kind::Label; // a label line (or a collapsed zone that starts with a label)
        anchor.address = line.address;
    } else {
        anchor.kind    = DissasmCommentAnchor::Kind::Instruction;
        anchor.address = line.address;
    }
    return anchor;
}

std::optional<DissasmCommentAnchor> DissasmCodeZone::GetAnchorOfLine(uint32 line)
{
    if (!CanReachAsmLines() || !zoneObject.IsValid() || line >= GetCodeZoneLinesCount(*this))
        return {};
    return GetLineAnchor(GetCurrentAsmLine(line, zoneObject, nullptr));
}

bool DissasmCodeZone::GetComment(const DissasmAsmPreCacheLine& line, std::string& comment) const
{
    return userComments.Get(GetLineAnchor(line), comment);
}

bool DissasmCodeZone::GetComment(uint32 line, std::string& comment)
{
    const auto anchor = GetAnchorOfLine(line);
    return anchor.has_value() && userComments.Get(anchor.value(), comment);
}

bool DissasmCodeZone::AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr)
{
    const auto anchor = GetAnchorOfLine(line);
    if (!anchor.has_value()) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Failed to find the required line!");
        return false;
    }
    DissasmEdit edit;
    edit.kind   = DissasmEdit::Kind::Comment;
    edit.anchor = anchor.value();
    std::string previous;
    if (userComments.Get(anchor.value(), previous)) {
        if (previous == comment)
            return true;
        edit.before = std::move(previous);
    }
    edit.after = comment;
    userComments.Set(anchor.value(), comment);
    RecordEdit(std::move(edit));
    return true;
}

bool DissasmCodeZone::RemoveComment(uint32 line, bool showErr)
{
    const auto anchor = GetAnchorOfLine(line);
    std::string previous;
    if (!anchor.has_value() || !userComments.Get(anchor.value(), previous) || !userComments.Remove(anchor.value())) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Could not find the comment!");
        return false;
    }
    DissasmEdit edit;
    edit.kind   = DissasmEdit::Kind::Comment;
    edit.anchor = anchor.value();
    edit.before = std::move(previous);
    RecordEdit(std::move(edit));
    return true;
}

void DissasmCodeZone::MoveLineCommentsToAnchors()
{
    // loaded right after the initialization: the lines are the lines of the root type (no collapsible zones). The cache replaced the
    // annotations: the line walk starts again from the zone start.
    auto& lineComments = dissasmType.commentsData.comments;
    if (lineComments.empty())
        return;
    RebuildLineIndex();
    for (auto& [key, text] : lineComments) {
        const auto anchor = GetAnchorOfLine(key + 1u); // keyed by line - 1 (line 0 wraps around)
        if (anchor.has_value())
            userComments.Set(anchor.value(), std::move(text));
    }
    lineComments.clear();
}

std::vector<std::pair<uint64, std::string>> DissasmCodeZone::GetUserLabelNames() const
{
    std::vector<std::pair<uint64, std::string>> names;
    const auto& annotations = dissasmType.annotations;
    for (const auto& [line, details] : annotations.mappings) {
        if (IsLocalVariableAnnotation(details))
            continue;
        const auto initial = annotations.current_name_to_initial_name.find(details.first);
        if (initial != annotations.current_name_to_initial_name.end() && initial->second != details.first)
            names.emplace_back(details.second, details.first);
    }
    for (const auto& [address, name] : orphanLabelNames)
        names.emplace_back(address, name);
    return names;
}

bool DissasmCodeZone::ApplyUserLabelName(uint64 address, const std::string& name)
{
    auto& annotations = dissasmType.annotations;
    for (const auto& [line, details] : annotations.mappings) {
        if (IsLocalVariableAnnotation(details) || details.second != address)
            continue;
        if (details.first == name)
            return true;
        const std::string currentName = details.first; // add_name_change replaces it
        if (!annotations.add_name_change(currentName, name, line))
            break; // another label has this name: kept as an orphan
        orphanLabelNames.erase(address);
        return true;
    }
    orphanLabelNames[address] = name;
    return false;
}

bool GView::View::DissasmViewer::DissasmCodeZone::InitZone(DissasmCodeZoneInitData& initData)
{
    initTried = true;
    labelAddressBase = initData.labelAddressBase.value_or(zoneDetails.startingZonePoint); // the first decoded instruction is the zone start
    paddingAlignmentBase = initData.alignPadding ? labelAddressBase : DISSASM_NO_PADDING_ALIGNMENT;
    zoneObject       = initData.obj;
    // the calling convention of x64 code: Windows for a PE, System V for the others (ELF, Mach-O)
    {
        auto contentType         = initData.obj.IsValid() ? initData.obj->GetContentType() : Reference<GView::TypeInterface>();
        const bool notPE         = contentType.IsValid() && contentType->GetTypeName() != "PE";
        systemVCalls             = zoneDetails.language == DisassemblyLanguage::x64 && notPE;
        variadicArgumentsInStack = zoneDetails.language == DisassemblyLanguage::ARM64 && contentType.IsValid() && contentType->GetTypeName() == "Mach-O";
        variadicFloatsInVectors  = notPE;
    }
    relocatedPointers = initData.relocatedPointers;

    // TODO: move this on init
    if (!cs_support(CS_ARCH_X86)) {
        if (initData.dli.IsValid())
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("Capstone does not support X86");
        initData.adjustedZoneSize = 1;
        initData.hasAdjustedSize  = true;
        return false;
    }

    switch (zoneDetails.language) {
    case DisassemblyLanguage::x86:
        capstoneArch         = CS_ARCH_X86;
        internalArchitecture = CS_MODE_32;
        break;
    case DisassemblyLanguage::x64:
        capstoneArch         = CS_ARCH_X86;
        internalArchitecture = CS_MODE_64;
        break;
    case DisassemblyLanguage::ARM64:
        capstoneArch         = CS_ARCH_ARM64;
        internalArchitecture = CS_MODE_ARM; // little endian
        if (!cs_support(CS_ARCH_ARM64)) {
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("Capstone does not support ARM64");
            return false;
        }
        break;
    case DisassemblyLanguage::ARM:
    case DisassemblyLanguage::Thumb:
        // the mode of every line is set by DecodeX86Line (the mode changes of the zone)
        capstoneArch         = CS_ARCH_ARM;
        internalArchitecture = zoneDetails.language == DisassemblyLanguage::Thumb ? CS_MODE_THUMB : CS_MODE_ARM;
        if (!cs_support(CS_ARCH_ARM)) {
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("Capstone does not support ARM");
            return false;
        }
        break;
    default: {
        if (initData.dli.IsValid())
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("ERROR: unsupported language!");
        return false;
    }
    }
    hasDecoder = true;

    // the places where an instruction starts (the function entries, the section starts of the plugin), relative to the zone start
    instructionBoundaries.clear();
    auto addBoundary = [this](uint64 fileOffset) {
        if (fileOffset > zoneDetails.startingZonePoint && fileOffset - zoneDetails.startingZonePoint < zoneDetails.size)
            instructionBoundaries.push_back(fileOffset - zoneDetails.startingZonePoint);
    };
    if (initData.functionEntries)
        for (const auto& [fileOffset, entry] : *initData.functionEntries)
            addBoundary(fileOffset);
    if (initData.instructionBoundaries)
        for (const uint64 fileOffset : *initData.instructionBoundaries)
            addBoundary(fileOffset);
    // the instruction set; 32 bit ARM: the mode changes inside the zone (a change is an instruction start)
    instructionSet             = {};
    instructionSet.kind        = IsArm64Code() ? DissasmInstructionSet::Kind::Arm64 : (IsArm32Code() ? DissasmInstructionSet::Kind::Arm32 : DissasmInstructionSet::Kind::X86);
    instructionSet.defaultMode = zoneDetails.language == DisassemblyLanguage::Thumb ? ArmCodeMode::Thumb : ArmCodeMode::Arm;
    instructionSet.uninitialized = zoneDetails.isUninitialized;
    if (IsArm32Code() && initData.armCodeModes) {
        for (const auto& [fileOffset, mode] : *initData.armCodeModes) {
            if (fileOffset <= zoneDetails.startingZonePoint)
                instructionSet.defaultMode = mode; // the last change before the zone: the mode of its start
            else if (fileOffset - zoneDetails.startingZonePoint < zoneDetails.size) {
                instructionSet.modeChanges.emplace_back(fileOffset - zoneDetails.startingZonePoint, mode);
                addBoundary(fileOffset);
            }
        }
    }
    std::sort(instructionBoundaries.begin(), instructionBoundaries.end());
    instructionBoundaries.erase(std::unique(instructionBoundaries.begin(), instructionBoundaries.end()), instructionBoundaries.end());

    localVariables.functions.clear();
    tableEntries.clear();
    if (zoneDetails.isData) {
        // a data zone: every byte is a data line; the places the code refers to (the xrefs of the other zones) start their lines
        constexpr uint64 MAX_DATA_ZONE_SIZE = 64ull * 1024 * 1024;
        // the places named by the plugin (import slots, Objective-C references and structures): labels too
        namedSlots.clear();
        if (initData.memoryMappings && initData.findImport) {
            const uint64 rvaBase = initData.imageBase.value_or(0); // the mappings are keyed by RVA
            for (const auto& [key, entry] : *initData.memoryMappings) {
                const uint64 address = key + rvaBase;
                if (!entry.name.empty() && address >= labelAddressBase && address - labelAddressBase < zoneDetails.size)
                    namedSlots.push_back(address - labelAddressBase);
            }
            std::sort(namedSlots.begin(), namedSlots.end());
        }
        std::vector<uint64> targets;
        std::vector<uint8> targetSizes;
        CollectDataZoneTargets(targets, targetSizes);
        std::vector<DissasmInstructionSet::DataRange> fixedRanges;
        for (const auto& range : userDataRanges)
            if (range.end <= zoneDetails.size)
                fixedRanges.push_back(range);
        // the fields of the structures (the load config directory, the RTTI, the Objective-C metadata): a line each, named
        fieldNames.clear();
        if (initData.dataFields && !initData.dataFields->empty()) {
            std::vector<DissasmInstructionSet::DataRange> fields;
            uint64 fieldsEnd = 0;
            for (auto it = initData.dataFields->lower_bound(labelAddressBase);
                 it != initData.dataFields->end() && it->first - labelAddressBase < zoneDetails.size;
                 ++it) {
                const uint64 position = it->first - labelAddressBase;
                const auto& field     = it->second;
                if (position < fieldsEnd || position + field.size > zoneDetails.size)
                    continue; // overlaps the previous field
                const bool overlaps = std::any_of(fixedRanges.begin(), fixedRanges.end(), [&](const auto& range) {
                    return range.start < position + field.size && position < range.end;
                });
                if (overlaps)
                    continue;
                DissasmInstructionSet::DataRange range{ position, position + field.size, DissasmInstructionSet::BYTES_ROW };
                if (field.type == DataFieldType::String)
                    range.unit = DissasmInstructionSet::ASCII_STRING;
                else if (field.size == 1 || field.size == 2 || field.size == 4 || field.size == 8)
                    range.unit = static_cast<uint8>(field.size);
                range.isOffset  = field.type == DataFieldType::Pointer || field.type == DataFieldType::RVA || field.type == DataFieldType::Relative;
                range.reference = field.type == DataFieldType::RVA        ? DissasmInstructionSet::REFERENCE_RVA
                                  : field.type == DataFieldType::Relative ? DissasmInstructionSet::REFERENCE_RELATIVE
                                                                          : DissasmInstructionSet::REFERENCE_VA;
                fields.push_back(range);
                fieldNames[position] = field.name;
                fieldsEnd            = position + field.size;
            }
            fixedRanges.insert(fixedRanges.end(), fields.begin(), fields.end());
            std::sort(fixedRanges.begin(), fixedRanges.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
        }
        // the import slots the code uses (call [__imp_CreateFileW]): a pointer each, named after the import
        const uint8 slotSize = Is64BitCode() ? 8 : 4;
        if (initData.findImport) {
            std::vector<DissasmInstructionSet::DataRange> slots;
            for (const uint64 target : targets) {
                X86OperandsInfo operands;
                operands.absoluteMemory = labelAddressBase + target;
                const bool overlapsUser = std::any_of(fixedRanges.begin(), fixedRanges.end(), [target, slotSize](const auto& range) {
                    return range.start < target + slotSize && target < range.end;
                });
                const bool overlapsSlot = !slots.empty() && slots.back().end > target;
                const auto* import      = !overlapsUser && !overlapsSlot && target + slotSize <= zoneDetails.size ? initData.findImport(operands) : nullptr;
                if (import)
                    slots.push_back({ target, target + slotSize, slotSize, import->type == MemoryMappingType::TextMapping });
            }
            fixedRanges.insert(fixedRanges.end(), slots.begin(), slots.end());
            std::sort(fixedRanges.begin(), fixedRanges.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
        }
        // the pointers the loader writes: pointers for sure (isPointer rejects the small addresses of an image linked at 0), a run of
        // them is a range of pointers
        if (relocatedPointers && !relocatedPointers->empty()) {
            std::vector<DissasmInstructionSet::DataRange> relocated;
            const auto overlapsFixed = [&fixedRanges](uint64 start, uint64 end) {
                const auto next = std::upper_bound(
                      fixedRanges.begin(), fixedRanges.end(), start, [](uint64 value, const auto& range) { return value < range.start; });
                return (next != fixedRanges.end() && next->start < end) || (next != fixedRanges.begin() && (next - 1)->end > start);
            };
            for (auto it = relocatedPointers->lower_bound(zoneDetails.startingZonePoint);
                 it != relocatedPointers->end() && it->first - zoneDetails.startingZonePoint + slotSize <= zoneDetails.size;
                 ++it) {
                const uint64 position = it->first - zoneDetails.startingZonePoint;
                if (overlapsFixed(position, position + slotSize) || (!relocated.empty() && relocated.back().end > position))
                    continue;
                if (!relocated.empty() && relocated.back().end == position)
                    relocated.back().end += slotSize;
                else
                    relocated.push_back({ position, position + slotSize, slotSize, true });
            }
            fixedRanges.insert(fixedRanges.end(), relocated.begin(), relocated.end());
            std::sort(fixedRanges.begin(), fixedRanges.end(), [](const auto& left, const auto& right) { return left.start < right.start; });
        }
        const uint64 fileSize = initData.obj->GetData().GetSize();
        const uint64 dataSize = zoneDetails.isUninitialized ? std::min<uint64>(zoneDetails.size, MAX_DATA_ZONE_SIZE)
                                : zoneDetails.startingZonePoint < fileSize ? std::min<uint64>({ zoneDetails.size, MAX_DATA_ZONE_SIZE, fileSize - zoneDetails.startingZonePoint })
                                                                           : 0;
        // an uninitialized zone: zeros (no strings, no pointers; the variables the code uses and rows)
        std::vector<uint8> zeros;
        AppCUI::Utils::Buffer fileBytes;
        if (zoneDetails.isUninitialized)
            zeros.assign(static_cast<size_t>(dataSize), 0);
        else
            fileBytes = initData.obj->GetData().CopyToBuffer(zoneDetails.startingZonePoint, static_cast<uint32>(dataSize), false);
        uint8* bytesData       = zoneDetails.isUninitialized ? zeros.data() : fileBytes.GetData();
        const uint64 bytesSize = zoneDetails.isUninitialized ? zeros.size() : fileBytes.GetLength();
        ApplyRelocatedPointers(relocatedPointers, zoneDetails.startingZonePoint, bytesData, bytesSize, Is64BitCode() ? 8 : 4);
        // the pointers: only with the addresses of the plugin (the VAs), every small number is a file offset otherwise; and not the small
        // values (a position independent image loaded at 0: its first VAs are counters and sizes too)
        const uint8 pointerSize = Is64BitCode() ? 8 : 4;
        std::function<bool(uint64)> isPointer;
        if (initData.labelAddressBase.has_value() && initData.isFileAddress)
            isPointer = [isFileAddress = initData.isFileAddress](uint64 value) { return value >= 0x10000 && isFileAddress(value); };
        instructionSet.dataRanges = BuildDataZoneRanges(bytesData, bytesSize, targets, targetSizes, fixedRanges, pointerSize, isPointer);
        if (bytesSize < zoneDetails.size) // the bytes past the limit: rows
            instructionSet.dataRanges.push_back({ bytesSize, zoneDetails.size, DissasmInstructionSet::BYTES_ROW });
    } else {
        // the data defined by the user: the lines are counted with them (a range that does not fit any more is dropped)
        for (const auto& range : userDataRanges)
            if (range.end <= zoneDetails.size)
                instructionSet.AddDataRange(range);
    }
    deepScan.reset();
    deepScanInitData.reset();
    lineCounter.reset();
    if (IsValidCodeZone(zoneDetails, initData.obj)) {
        lineCounter = std::make_unique<DissasmLineCounter>(cachedCodeOffsets, zoneDetails, initData.obj, &instructionBoundaries, paddingAlignmentBase);
        if (!lineCounter->Start(capstoneArch, internalArchitecture, &instructionSet))
            lineCounter.reset();
    }
    if (!lineCounter) {
        if (initData.dli.IsValid())
            initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    if (initData.enableDeepScanDissasmOnStart) {
        deepScanInitData     = initData;
        deepScanInitData->dli = nullptr; // the line of the paint that initializes the zone
    }
    // a big zone: its lines are counted after the budget (ContinueDeepScan), the lines counted so far are shown at once
    const auto countDeadline = initData.lineCountBudget.has_value() ? std::chrono::steady_clock::now() + initData.lineCountBudget.value()
                                                                    : std::chrono::steady_clock::time_point::max();
    uint32 totalLines = 0;
    if (lineCounter->Run(countDeadline)) {
        if (!FinishLineCount()) {
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
            return false;
        }
        totalLines = asmLinesCount;
        // a big zone: the scan continues after its budget (ContinueDeepScan), the instructions are shown without labels until it ends
        const auto deadline = initData.deepScanBudget.has_value() ? std::chrono::steady_clock::now() + initData.deepScanBudget.value()
                                                                  : std::chrono::steady_clock::time_point::max();
        if (deepScan && deepScan->Run(deadline)) {
            const uint32 extraLines = deepScan->Commit(); // the jump tables inside the code may have changed the lines count
            totalLines              = asmLinesCount + extraLines;
            deepScan.reset();
        }
    } else {
        asmLinesCount = lineCounter->lines;
        totalLines    = asmLinesCount;
    }
    totalLines++; //+1 for title
    initData.adjustedZoneSize = totalLines;
    initData.hasAdjustedSize  = true;
    // AdjustZoneExtendedSize(zone, totalLines);
    lastDrawnLine          = 0;
    offsetCacheMaxLine     = 0; // the first decoded line searches its closest cached offset
    const auto closestData = SearchForClosestAsmOffsetLineByLine(cachedCodeOffsets, lastDrawnLine);
    lastClosestLine        = closestData.line;
    isInit                 = true;

    if (!FetchCodeWindow(initData.obj, 0, DISSASM_INSTRUCTION_OFFSET_MARGIN + DISSASM_MAX_LINE_SIZE)) {
        if (initData.dli.IsValid())
            if (initData.dli.IsValid())
                initData.dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        return false;
    }

    const uint32 preReverseSize = std::min<uint32>(initData.visibleRows, extendedSize);
    asmPreCacheData.cachedAsmLines.reserve(preReverseSize);

    collapsibleZones.clear();
    RebuildLineIndex();
    linesReady = true;
    return true;
}

bool DissasmCodeZone::FinishLineCount()
{
    asmLinesCount = lineCounter->lines;
    lineCounter.reset();
    RebuildLineIndex(); // the trailing zeros are not lines: the drawn lines are prepared again
    if (!deepScanInitData.has_value())
        return true;
    deepScan = std::make_unique<DissasmDeepScan>(this, deepScanInitData.value(), internalArchitecture, asmLinesCount);
    deepScanInitData.reset();
    if (!deepScan->Start()) {
        deepScan.reset();
        return false;
    }
    return true;
}

bool DissasmCodeZone::ContinueDeepScan(std::chrono::steady_clock::time_point deadline)
{
    if (lineCounter) {
        const bool counted = lineCounter->Run(deadline);
        asmLinesCount      = lineCounter->lines;
        if (!counted)
            return false;
        if (!FinishLineCount() || !deepScan)
            return true; // no deep scan: the zone has its instructions without labels
    }
    return deepScan && deepScan->Run(deadline);
}

void DissasmCodeZone::CommitDeepScan()
{
    if (!deepScan || deepScan->phase != DissasmDeepScan::Phase::Done)
        return;
    deepScan->Commit();
    deepScan.reset();
    RebuildLineIndex();
}

void DissasmCodeZone::CancelDeepScan()
{
    deepScanInitData.reset(); // no deep scan after the line count
    if (lineCounter) {        // the lines are needed: the count ends now
        lineCounter->Run(std::chrono::steady_clock::time_point::max());
        FinishLineCount();
    }
    deepScan.reset();
}

float DissasmCodeZone::GetDeepScanProgress() const
{
    if (lineCounter)
        return lineCounter->GetProgress();
    return deepScan ? deepScan->GetProgress() : 1.0f;
}

void DissasmCodeZone::RebuildLineIndex()
{
    annotationLines.clear();
    annotationLines.reserve(dissasmType.annotations.size());
    labelLineOfAddress.clear();
    for (const auto& [line, details] : dissasmType.annotations.mappings) {
        annotationLines.push_back(line); // the map is ordered: the vector is sorted
        if (!IsLocalVariableAnnotation(details))
            labelLineOfAddress.try_emplace(details.second, line);
    }
    sortedLabelAddresses.clear();
    sortedLabelAddresses.reserve(labelLineOfAddress.size());
    for (const auto& [address, line] : labelLineOfAddress)
        sortedLabelAddresses.push_back(address);
    std::sort(sortedLabelAddresses.begin(), sortedLabelAddresses.end());
    offsetCacheMaxLine = 0; // the next decoded line searches its closest cached offset
    ResetZoneCaching();
}

std::string DissasmCodeZone::GetLabelNameAt(uint64 relativeAddress) const
{
    const auto line = labelLineOfAddress.find(relativeAddress);
    if (line == labelLineOfAddress.end())
        return {};
    const auto annotation = dissasmType.annotations.find(line->second);
    return annotation != dissasmType.annotations.end() ? annotation->second.first : std::string{};
}

std::optional<uint64> DissasmCodeZone::FindLabelByName(std::string_view name) const
{
    if (name.empty())
        return {};
    const auto sameIgnoringCase = [](std::string_view left, std::string_view right) {
        return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) {
                   return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
               });
    };
    std::optional<uint64> ignoringCase;
    for (const auto& [line, details] : dissasmType.annotations.mappings) {
        if (IsLocalVariableAnnotation(details))
            continue;
        if (details.first == name)
            return details.second;
        if (!ignoringCase.has_value() && sameIgnoringCase(details.first, name))
            ignoringCase = details.second;
    }
    return ignoringCase;
}

std::vector<DissasmFunctionInfo> DissasmCodeZone::GetFunctions(const std::map<uint64, DissasmFunctionEntry>* functionEntries) const
{
    std::vector<DissasmFunctionInfo> functions;
    if (cachedCodeOffsets.empty())
        return functions;
    const uint64 codeStart = cachedCodeOffsets[0].offset;
    const uint64 codeSize  = GetCodeSize();
    functions.reserve(functionStarts.size());
    for (size_t index = 0; index < functionStarts.size(); index++) {
        DissasmFunctionInfo function;
        function.start    = functionStarts[index];
        const uint64 end  = GetFunctionEnd(function.start); // the reachable code (the plugin size wins below)
        function.size     = end > function.start ? end - function.start : 0;
        function.name     = GetLabelNameAt(function.start);
        if (function.name.empty())
            function.name = GetLabelName("sub_", function.start);
        function.xrefs           = static_cast<uint32>(GetXrefsTo(labelAddressBase + function.start).size());
        function.isThunk         = thunkImports.contains(function.start);
        function.isNoReturn      = std::binary_search(noReturnFunctions.begin(), noReturnFunctions.end(), function.start);
        for (const auto& chunk : functionChunks)
            if (chunk.function == function.start)
                function.chunks.emplace_back(chunk.start, chunk.end);
        if (functionApiCategories.size() == functionStarts.size())
            function.apiCategories = functionApiCategories[index];
        function.isEntryPoint    = codeStart + function.start == zoneDetails.entryPoint;
        if (functionEntries) {
            const auto entry = functionEntries->find(codeStart + function.start);
            if (entry != functionEntries->end()) {
                function.isExport = entry->second.isExport;
                if (entry->second.size > 0)
                    function.size = entry->second.size;
            }
        }
        functions.push_back(std::move(function));
    }
    return functions;
}

std::optional<DissasmGoToRequest> GView::View::DissasmViewer::ParseDissasmGoToText(std::string_view text, DissasmPEConversionType shownAddressType)
{
    const auto isSpace = [](char c) { return c == ' ' || c == '\t'; };
    while (!text.empty() && isSpace(text.front()))
        text.remove_prefix(1);
    while (!text.empty() && isSpace(text.back()))
        text.remove_suffix(1);
    if (text.empty())
        return {};

    // hexadecimal: 140001000, 0x140001000, 140001000h
    const auto parseHex = [](std::string_view number) -> std::optional<uint64> {
        if (number.size() > 2 && number[0] == '0' && (number[1] == 'x' || number[1] == 'X'))
            number.remove_prefix(2);
        else if (number.size() > 1 && (number.back() == 'h' || number.back() == 'H'))
            number.remove_suffix(1);
        if (number.empty() || number.size() > 16)
            return {};
        uint64 value = 0;
        for (const char c : number) {
            uint64 digit = 0;
            if (c >= '0' && c <= '9')
                digit = static_cast<uint64>(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = static_cast<uint64>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                digit = static_cast<uint64>(c - 'A' + 10);
            else
                return {};
            value = value * 16 + digit;
        }
        return value;
    };
    const auto startsWithPrefix = [&text](std::string_view prefix) {
        if (text.size() < prefix.size())
            return false;
        for (size_t index = 0; index < prefix.size(); index++)
            if (std::tolower(static_cast<unsigned char>(text[index])) != prefix[index])
                return false;
        return true;
    };

    DissasmGoToRequest request;
    if (startsWithPrefix("line:")) {
        uint64 line = 0;
        const auto number = text.substr(5);
        if (number.empty() || number.size() > 10)
            return {};
        for (const char c : number) {
            if (c < '0' || c > '9')
                return {};
            line = line * 10 + static_cast<uint64>(c - '0');
        }
        if (line > UINT32_MAX)
            return {};
        request.line = static_cast<uint32>(line);
        return request;
    }
    struct Prefix {
        std::string_view text;
        DissasmPEConversionType type;
    };
    for (const auto& prefix : { Prefix{ "va:", DissasmPEConversionType::VA },
                                Prefix{ "rva:", DissasmPEConversionType::RVA },
                                Prefix{ "offset:", DissasmPEConversionType::FileOffset },
                                Prefix{ "off:", DissasmPEConversionType::FileOffset } }) {
        if (!startsWithPrefix(prefix.text))
            continue;
        request.address = parseHex(text.substr(prefix.text.size()));
        if (!request.address.has_value())
            return {};
        request.addressType = prefix.type;
        return request;
    }
    request.name        = std::string(text);
    request.address     = parseHex(text);
    request.addressType = shownAddressType;
    return request;
}

std::optional<std::vector<int16>> GView::View::DissasmViewer::ParseDissasmBytePattern(std::string_view text)
{
    constexpr size_t MAX_PATTERN_SIZE = 256;
    const auto hexValue               = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<int16> pattern;
    size_t position = 0;
    while (position < text.size()) {
        // the tokens are separated by spaces: 48 8B ?? 05 / 488B??05 / 48 8B ? 05
        while (position < text.size() && (text[position] == ' ' || text[position] == '\t'))
            position++;
        const size_t start = position;
        while (position < text.size() && text[position] != ' ' && text[position] != '\t')
            position++;
        const auto token = text.substr(start, position - start);
        if (token.empty())
            break;
        if (token == "?" || token == "??") {
            pattern.push_back(-1);
            continue;
        }
        if (token.size() % 2 != 0)
            return {};
        for (size_t index = 0; index < token.size(); index += 2) {
            if (token[index] == '?' && token[index + 1] == '?') {
                pattern.push_back(-1);
                continue;
            }
            const int high = hexValue(token[index]);
            const int low  = hexValue(token[index + 1]);
            if (high < 0 || low < 0)
                return {};
            pattern.push_back(static_cast<int16>(high * 16 + low));
        }
    }
    if (pattern.empty() || pattern.size() > MAX_PATTERN_SIZE)
        return {};
    return pattern;
}

std::optional<uint64> GView::View::DissasmViewer::ParseDissasmSearchNumber(std::string_view text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    const bool negative = !text.empty() && text.front() == '-';
    if (negative)
        text.remove_prefix(1);
    uint32 base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    } else if (text.size() > 1 && (text.back() == 'h' || text.back() == 'H')) {
        base = 16;
        text.remove_suffix(1);
    }
    if (text.empty())
        return {};
    uint64 value = 0;
    for (const char c : text) {
        uint64 digit = 0;
        if (c >= '0' && c <= '9')
            digit = static_cast<uint64>(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f')
            digit = static_cast<uint64>(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F')
            digit = static_cast<uint64>(c - 'A' + 10);
        else
            return {};
        if (value > (UINT64_MAX - digit) / base)
            return {}; // does not fit in 64 bits
        value = value * base + digit;
    }
    return negative ? static_cast<uint64>(0) - value : value;
}

const DissasmFunctionChunk* DissasmCodeZone::FindChunkContaining(uint64 relativeAddress) const
{
    const auto next = std::upper_bound(
          functionChunks.begin(), functionChunks.end(), relativeAddress, [](uint64 value, const DissasmFunctionChunk& chunk) { return value < chunk.start; });
    if (next == functionChunks.begin())
        return nullptr;
    const auto& chunk = *(next - 1);
    return relativeAddress < chunk.end ? &chunk : nullptr;
}

std::vector<std::pair<uint64, uint64>> DissasmCodeZone::GetFunctionRanges(uint64 functionStart, uint64 end) const
{
    std::vector<std::pair<uint64, uint64>> ranges{ { functionStart, end } };
    for (const auto& chunk : functionChunks)
        if (chunk.function == functionStart && (chunk.start < functionStart || chunk.start >= end)) // a chunk inside the range: already there
            ranges.emplace_back(chunk.start, chunk.end);
    std::sort(ranges.begin(), ranges.end());
    return ranges;
}

const DissasmFunctionFrame* DissasmCodeZone::FindFrameOfAddress(uint64 relativeAddress) const
{
    if (const auto* frame = localVariables.FindFunctionByAddress(relativeAddress))
        return frame;
    const auto* chunk = FindChunkContaining(relativeAddress);
    const auto* frame = chunk ? localVariables.FindFunctionByStart(chunk->function) : nullptr;
    return frame && frame->usesFrameRegister ? frame : nullptr;
}

uint64 DissasmCodeZone::GetFunctionEnd(uint64 functionStart) const
{
    const auto found = std::lower_bound(functionStarts.begin(), functionStarts.end(), functionStart);
    const uint64 codeSize = GetCodeSize();
    if (found == functionStarts.end() || *found != functionStart)
        return std::min(functionStart + 1, codeSize);
    const size_t index = static_cast<size_t>(found - functionStarts.begin());
    if (index < functionEnds.size() && functionEnds.size() == functionStarts.size())
        return functionEnds[index];
    return index + 1 < functionStarts.size() ? functionStarts[index + 1] : codeSize;
}

std::string DissasmCodeZone::FormatFunctionAttributes(uint64 relativeAddress) const
{
    if (!std::binary_search(functionStarts.begin(), functionStarts.end(), relativeAddress))
        return {};
    std::string text;
    const auto add = [&text](std::string_view attribute) {
        if (!text.empty())
            text += ' ';
        text += attribute;
    };
    if (thunkImports.contains(relativeAddress))
        add("thunk");
    if (std::binary_search(noReturnFunctions.begin(), noReturnFunctions.end(), relativeAddress))
        add("noreturn");
    const auto* frame = localVariables.FindFunctionByStart(relativeAddress);
    if (frame && frame->usesFrameRegister && (!frame->variables.empty() || frame->savedRegistersSize != 0))
        add("bp-based frame");
    return text;
}

std::optional<uint64> DissasmCodeZone::GetFunctionContaining(uint64 relativeAddress) const
{
    if (const auto* chunk = FindChunkContaining(relativeAddress))
        return chunk->function; // a block of a function placed apart
    const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
    if (next == functionStarts.begin())
        return {};
    return *(next - 1);
}

namespace
{
// the segments of the forward edges between two consecutive layers: (upper node, lower node), the dummies included
std::vector<std::pair<size_t, size_t>> GraphSegments(const DissasmGraphLayout& layout, const DissasmFunctionGraph& graph)
{
    std::vector<std::pair<size_t, size_t>> segments;
    for (size_t index = 0; index < graph.blocks.size(); index++) {
        const auto& successors = graph.blocks[index].successors;
        for (size_t edgeIndex = 0; edgeIndex < successors.size(); edgeIndex++) {
            if (successors[edgeIndex].target <= index)
                continue;
            size_t previous     = index;
            const auto dummies  = layout.edgeDummies.find({ index, edgeIndex });
            if (dummies != layout.edgeDummies.end())
                for (const size_t dummy : dummies->second) {
                    segments.emplace_back(previous, dummy);
                    previous = dummy;
                }
            segments.emplace_back(previous, successors[edgeIndex].target);
        }
    }
    return segments;
}

// the crossings of the segments for the positions of the nodes in their layers
size_t CountCrossings(const std::vector<std::pair<size_t, size_t>>& segments, const std::vector<double>& position, const std::vector<int>& layerOf)
{
    // the segments of the same pair of layers only (grouped by the layer of their upper node)
    std::map<int, std::vector<std::pair<size_t, size_t>>> byLayer;
    for (const auto& segment : segments)
        byLayer[layerOf[segment.first]].push_back(segment);
    size_t crossings = 0;
    for (const auto& [layer, group] : byLayer)
        for (size_t first = 0; first < group.size(); first++)
            for (size_t second = first + 1; second < group.size(); second++) {
                const auto [a1, b1] = group[first];
                const auto [a2, b2] = group[second];
                if (a1 == a2 || b1 == b2)
                    continue; // a shared end
                if ((position[a1] < position[a2]) != (position[b1] < position[b2]))
                    crossings++;
            }
    return crossings;
}
} // namespace

DissasmGraphLayout GView::View::DissasmViewer::LayoutFunctionGraph(const DissasmFunctionGraph& graph, const std::vector<std::pair<int, int>>& blockSizes)
{
    constexpr int GAP_X = 6, GAP_DUMMY = 2, GAP_Y = 5, MARGIN = 2;
    constexpr uint32 SWEEPS           = 8;
    constexpr size_t MAX_ORDERED_NODES = 6000; // a bigger graph keeps the order of the addresses (the crossings are counted at each sweep)
    DissasmGraphLayout layout;
    const size_t count = graph.blocks.size();
    layout.nodes.resize(count);
    for (size_t index = 0; index < count && index < blockSizes.size(); index++) {
        layout.nodes[index].width  = blockSizes[index].first;
        layout.nodes[index].height = blockSizes[index].second;
    }
    // the layers: the longest path from the entry
    int layersCount = count > 0 ? 1 : 0;
    for (size_t index = 0; index < count; index++)
        for (const auto& edge : graph.blocks[index].successors)
            if (edge.target > index && edge.target < count) {
                layout.nodes[edge.target].layer = std::max(layout.nodes[edge.target].layer, layout.nodes[index].layer + 1);
                layersCount                     = std::max(layersCount, layout.nodes[edge.target].layer + 1);
            }
    // the dummies of the long edges
    for (size_t index = 0; index < count; index++) {
        const auto& successors = graph.blocks[index].successors;
        for (size_t edgeIndex = 0; edgeIndex < successors.size(); edgeIndex++) {
            const size_t target = successors[edgeIndex].target;
            if (target <= index || target >= count)
                continue;
            for (int layer = layout.nodes[index].layer + 1; layer < layout.nodes[target].layer; layer++) {
                DissasmGraphLayout::Node dummy;
                dummy.layer   = layer;
                dummy.isDummy = true;
                dummy.width   = 1;
                layout.edgeDummies[{ index, edgeIndex }].push_back(layout.nodes.size());
                layout.nodes.push_back(dummy);
            }
        }
    }
    const size_t nodesCount = layout.nodes.size();
    std::vector<std::vector<size_t>> layers(layersCount);
    std::vector<int> layerOf(nodesCount);
    for (size_t node = 0; node < nodesCount; node++) {
        layerOf[node] = layout.nodes[node].layer;
        layers[layout.nodes[node].layer].push_back(node); // the blocks by address, then the dummies
    }
    const auto segments = GraphSegments(layout, graph);
    std::vector<std::vector<size_t>> upper(nodesCount), lower(nodesCount);
    for (const auto& [from, to] : segments) {
        lower[from].push_back(to);
        upper[to].push_back(from);
    }
    std::vector<double> position(nodesCount);
    const auto updatePositions = [&]() {
        for (const auto& layer : layers)
            for (size_t index = 0; index < layer.size(); index++)
                position[layer[index]] = static_cast<double>(index);
    };
    updatePositions();
    // the order of the layers: barycenter sweeps down and up, the order with the fewest crossings kept
    auto bestLayers       = layers;
    size_t bestCrossings  = nodesCount <= MAX_ORDERED_NODES ? CountCrossings(segments, position, layerOf) : 0;
    for (uint32 sweep = 0; sweep < SWEEPS && bestCrossings > 0 && nodesCount <= MAX_ORDERED_NODES; sweep++) {
        const bool down = sweep % 2 == 0;
        for (int step = 1; step < layersCount; step++) {
            auto& layer = layers[down ? step : layersCount - 1 - step];
            std::vector<std::pair<double, size_t>> keyed;
            for (const size_t node : layer) {
                const auto& neighbors = down ? upper[node] : lower[node];
                double key            = position[node];
                if (!neighbors.empty()) {
                    double sum = 0;
                    for (const size_t neighbor : neighbors)
                        sum += position[neighbor];
                    key = sum / static_cast<double>(neighbors.size());
                }
                keyed.emplace_back(key, node);
            }
            std::stable_sort(keyed.begin(), keyed.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
            for (size_t index = 0; index < keyed.size(); index++) {
                layer[index]                = keyed[index].second;
                position[keyed[index].second] = static_cast<double>(index);
            }
        }
        const size_t crossings = CountCrossings(segments, position, layerOf);
        if (crossings < bestCrossings) {
            bestCrossings = crossings;
            bestLayers    = layers;
        }
    }
    layers = std::move(bestLayers);

    // the places: the order kept, each node under the middle of the nodes above it
    layout.layerTop.assign(layersCount, MARGIN);
    layout.layerHeight.assign(layersCount, 0);
    int top = MARGIN;
    for (int layer = 0; layer < layersCount; layer++) {
        int right            = MARGIN;
        bool first           = true;
        bool previousIsDummy = false;
        for (const size_t node : layers[layer]) {
            auto& item     = layout.nodes[node];
            double desired = MARGIN + item.width / 2.0;
            if (!upper[node].empty()) {
                double sum = 0;
                for (const size_t neighbor : upper[node])
                    sum += layout.nodes[neighbor].x + layout.nodes[neighbor].width / 2.0;
                desired = sum / static_cast<double>(upper[node].size());
            }
            const int gap = first ? 0 : (item.isDummy || previousIsDummy ? GAP_DUMMY : GAP_X);
            item.x        = std::max({ static_cast<int>(desired) - item.width / 2, right + gap, MARGIN });
            item.y        = top;
            right         = item.x + item.width;
            layout.width  = std::max(layout.width, right);
            if (!item.isDummy)
                layout.layerHeight[layer] = std::max(layout.layerHeight[layer], item.height);
            first           = false;
            previousIsDummy = item.isDummy;
        }
        layout.layerHeight[layer] = std::max(layout.layerHeight[layer], 1);
        layout.layerTop[layer]    = top;
        top += layout.layerHeight[layer] + GAP_Y;
    }
    for (auto& node : layout.nodes)
        if (node.isDummy)
            node.height = layout.layerHeight[node.layer]; // a column through the whole layer
    layout.width += MARGIN;
    layout.height = top + MARGIN;
    return layout;
}

size_t GView::View::DissasmViewer::CountGraphCrossings(const DissasmGraphLayout& layout, const DissasmFunctionGraph& graph)
{
    std::vector<double> position(layout.nodes.size());
    std::vector<int> layerOf(layout.nodes.size());
    for (size_t node = 0; node < layout.nodes.size(); node++) {
        position[node] = layout.nodes[node].x;
        layerOf[node]  = layout.nodes[node].layer;
    }
    return CountCrossings(GraphSegments(layout, graph), position, layerOf);
}

DissasmFunctionGraph DissasmCodeZone::BuildFunctionGraph(uint64 functionStart) const
{
    DissasmFunctionGraph graph;
    graph.functionStart = functionStart;
    if (cachedCodeOffsets.empty() || !zoneObject.IsValid() || !hasDecoder)
        return graph;
    constexpr uint64 MAX_FUNCTION_SIZE  = 0x40000;
    constexpr size_t MAX_INSTRUCTIONS   = 20000;
    constexpr size_t MAX_BLOCKS         = 400;
    const uint64 codeSize               = GetCodeSize();
    uint64 end                          = std::min<uint64>(GetFunctionEnd(functionStart), codeSize); // the code its paths reach
    if (end - std::min(end, functionStart) > MAX_FUNCTION_SIZE) {
        end             = functionStart + MAX_FUNCTION_SIZE;
        graph.truncated = true;
    }
    if (functionStart >= end)
        return graph;
    const auto ranges = GetFunctionRanges(functionStart, end);

    // the instructions of the function, in the order of the listing
    struct Instruction {
        uint64 address, size;
        X86Flow flow;
        std::optional<uint64> target;
    };
    std::vector<Instruction> instructions;
    const csh handle = GetDecodeHandle(); // the handle of the zone (details on): no capstone tables allocated per call
    if (handle == 0)
        return graph;
    {
        cs_insn* insn                = cs_malloc(handle);
        Reference<GView::Object> obj = zoneObject;
        for (const auto& [rangeStart, rangeEnd] : ranges) { // the function, then its chunks (by address)
            DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, codeSize, handle, rangeStart, &instructionBoundaries, paddingAlignmentBase, &instructionSet);
            while (walker.Next(insn) && insn->address < rangeEnd) {
                if (instructions.size() == MAX_INSTRUCTIONS) {
                    graph.truncated = true;
                    break;
                }
                const auto flow     = GetInstructionFlow(*insn, GetArch());
                const auto operands = IsX86Branch(flow) ? GetInstructionOperands(*insn, GetArch()) : X86OperandsInfo{};
                instructions.push_back({ insn->address, insn->size, flow, operands.directTarget });
            }
        }
        cs_free(insn, 1);
    }
    if (instructions.empty())
        return graph;

    // the cases of the switches of the function
    std::unordered_map<uint64, std::vector<uint64>> switchTargets;
    for (const auto& xref : xrefs.byTarget)
        if (xref.kind == DissasmXrefKind::Switch && xref.from >= labelAddressBase)
            switchTargets[xref.from - labelAddressBase].push_back(xref.to - labelAddressBase); // used only for the jumps of the function

    // the leaders: the start, the targets of the branches, the instruction after a jump / ret
    const auto inside = [&ranges](uint64 address) {
        return std::any_of(ranges.begin(), ranges.end(), [address](const auto& range) { return address >= range.first && address < range.second; });
    };
    std::set<uint64> leaders{ functionStart };
    for (size_t index = 0; index < instructions.size(); index++) {
        const auto& instruction = instructions[index];
        const bool isJump       = instruction.flow == X86Flow::Jump || instruction.flow == X86Flow::ConditionalJump;
        if (isJump && instruction.target.has_value() && inside(instruction.target.value()))
            leaders.insert(instruction.target.value());
        if (const auto cases = switchTargets.find(instruction.address); cases != switchTargets.end())
            for (const uint64 target : cases->second)
                if (inside(target))
                    leaders.insert(target);
        const bool noReturnCall = instruction.flow == X86Flow::Call && noReturnCalls.contains(instruction.address);
        if ((isJump || instruction.flow == X86Flow::Return || noReturnCall) && index + 1 < instructions.size())
            leaders.insert(instructions[index + 1].address);
    }

    // the blocks: from a leader to the next one; their edges
    std::vector<DissasmGraphBlock> blocks;
    std::map<uint64, size_t> blockOfAddress;
    for (size_t index = 0; index < instructions.size(); index++) {
        if (leaders.contains(instructions[index].address) || blocks.empty()) {
            blockOfAddress[instructions[index].address] = blocks.size();
            blocks.emplace_back();
            blocks.back().start = instructions[index].address;
        }
        auto& block = blocks.back();
        block.instructions.push_back(static_cast<uint32>(index));
        block.addresses.push_back(instructions[index].address);
        block.end = instructions[index].address + instructions[index].size;
    }
    const auto blockAt = [&blockOfAddress](uint64 address) -> std::optional<size_t> {
        const auto it = blockOfAddress.find(address);
        return it != blockOfAddress.end() ? std::optional<size_t>(it->second) : std::nullopt;
    };
    for (size_t index = 0; index < blocks.size(); index++) {
        auto& block             = blocks[index];
        const auto& last        = instructions[block.instructions.back()];
        const auto nextBlock    = index + 1 < blocks.size() && blocks[index + 1].start == block.end ? std::optional<size_t>(index + 1) : std::nullopt;
        const auto targetBlock  = last.target.has_value() ? blockAt(last.target.value()) : std::nullopt;
        if (const auto cases = switchTargets.find(last.address); cases != switchTargets.end()) {
            std::set<size_t> targets;
            for (const uint64 target : cases->second)
                if (const auto caseBlock = blockAt(target); caseBlock.has_value() && targets.insert(caseBlock.value()).second)
                    block.successors.push_back({ caseBlock.value(), DissasmGraphBlock::EdgeKind::Switch });
            continue;
        }
        switch (last.flow) {
        case X86Flow::ConditionalJump:
            if (targetBlock.has_value())
                block.successors.push_back({ targetBlock.value(), DissasmGraphBlock::EdgeKind::True });
            else
                block.exits = true; // a conditional tail call
            if (nextBlock.has_value())
                block.successors.push_back({ nextBlock.value(), DissasmGraphBlock::EdgeKind::False });
            break;
        case X86Flow::Jump:
            if (targetBlock.has_value())
                block.successors.push_back({ targetBlock.value(), DissasmGraphBlock::EdgeKind::Jump });
            else
                block.exits = true; // a tail call / an indirect jmp
            break;
        case X86Flow::Return:
            block.exits = true;
            break;
        case X86Flow::Call:
            if (noReturnCalls.contains(last.address))
                break; // exit, abort, __stack_chk_fail: the block ends there, nothing follows
            if (nextBlock.has_value())
                block.successors.push_back({ nextBlock.value(), DissasmGraphBlock::EdgeKind::Jump });
            else
                block.exits = true;
            break;
        default:
            if (nextBlock.has_value())
                block.successors.push_back({ nextBlock.value(), DissasmGraphBlock::EdgeKind::Jump });
            else
                block.exits = true;
            break;
        }
    }

    // only the blocks reached from the entry (not the padding between the functions), renumbered in the order of the addresses
    std::vector<bool> reached(blocks.size(), false);
    std::vector<size_t> pending{ 0 };
    reached[0] = true;
    while (!pending.empty()) {
        const size_t index = pending.back();
        pending.pop_back();
        for (const auto& edge : blocks[index].successors)
            if (!reached[edge.target]) {
                reached[edge.target] = true;
                pending.push_back(edge.target);
            }
    }
    std::vector<size_t> newIndex(blocks.size(), SIZE_MAX);
    for (size_t index = 0; index < blocks.size(); index++) {
        if (!reached[index])
            continue;
        if (graph.blocks.size() == MAX_BLOCKS) {
            graph.truncated = true;
            break;
        }
        newIndex[index] = graph.blocks.size();
        graph.blocks.push_back(std::move(blocks[index]));
    }
    for (auto& block : graph.blocks) {
        std::vector<DissasmGraphBlock::Edge> edges;
        for (const auto& edge : block.successors)
            if (newIndex[edge.target] != SIZE_MAX)
                edges.push_back({ newIndex[edge.target], edge.kind });
        block.successors = std::move(edges);
    }
    return graph;
}

std::vector<DissasmCallReference> DissasmCodeZone::GetCallers(uint64 functionStart) const
{
    std::vector<DissasmCallReference> callers;
    // the calls from this zone, then from the other code zones of the file (a function of PAGE called from .text)
    for (const auto& [xref, source] : GetXrefsTo(labelAddressBase + functionStart)) {
        if (xref->kind != DissasmXrefKind::Call && xref->kind != DissasmXrefKind::Jump)
            continue;
        DissasmCallReference caller;
        caller.zone          = source != this ? source : nullptr;
        caller.site          = xref->from - source->labelAddressBase;
        caller.functionStart = source->GetFunctionContaining(caller.site);
        if (xref->kind == DissasmXrefKind::Jump) {
            // a jump from the same function is a loop, not a call
            if ((source == this && caller.functionStart == std::optional<uint64>(functionStart)) || !caller.functionStart.has_value())
                continue;
            caller.isTailJump = true;
        }
        if (caller.functionStart.has_value()) {
            caller.function = source->GetLabelNameAt(caller.functionStart.value());
            if (caller.function.empty())
                caller.function = source->GetLabelName("sub_", caller.functionStart.value());
        } else {
            caller.function = source->FormatCodeAddress(caller.site); // before the first function
        }
        callers.push_back(std::move(caller));
    }
    return callers;
}

void GView::View::DissasmViewer::ApplyRelocatedPointers(
      const std::map<uint64, uint64>* relocations, uint64 fileOffset, uint8* bytes, uint64 size, uint8 pointerSize)
{
    if (!relocations || !bytes || size < pointerSize)
        return;
    for (auto it = relocations->lower_bound(fileOffset); it != relocations->end() && it->first - fileOffset <= size - pointerSize; ++it)
        for (uint8 index = 0; index < pointerSize; index++)
            bytes[it->first - fileOffset + index] = static_cast<uint8>(it->second >> (8 * index));
}

std::vector<DissasmInstructionSet::DataRange> GView::View::DissasmViewer::BuildDataZoneRanges(
      const uint8* bytes,
      uint64 size,
      const std::vector<uint64>& targets,
      const std::vector<uint8>& targetSizes,
      const std::vector<DissasmInstructionSet::DataRange>& fixedRanges,
      uint8 pointerSize,
      const std::function<bool(uint64)>& isPointer)
{
    using DataRange                   = DissasmInstructionSet::DataRange;
    constexpr uint64 MIN_STRING_CHARS = 4;
    std::vector<DataRange> ranges;
    if (!bytes)
        return ranges;
    const auto isText = [](uint8 value) { return (value >= 0x20 && value < 0x7F) || value == '\t' || value == '\r' || value == '\n'; };
    const auto readPointer = [bytes, pointerSize](uint64 position) {
        uint64 value = 0;
        for (uint8 index = 0; index < pointerSize; index++)
            value |= static_cast<uint64>(bytes[position + index]) << (8 * index);
        return value;
    };
    size_t nextTarget = 0, nextFixed = 0;
    uint64 rowStart   = UINT64_MAX;
    const auto closeRow = [&](uint64 end) {
        if (rowStart != UINT64_MAX && end > rowStart)
            ranges.push_back({ rowStart, end, DissasmInstructionSet::BYTES_ROW });
        rowStart = UINT64_MAX;
    };
    uint64 position = 0;
    while (position < size) {
        // a range of the user: as it is
        if (nextFixed < fixedRanges.size() && fixedRanges[nextFixed].start <= position) {
            closeRow(position);
            DataRange range = fixedRanges[nextFixed++];
            if (range.end > position) {
                range.start = position;
                ranges.push_back(range);
                position = range.end;
            }
            continue;
        }
        while (nextTarget < targets.size() && targets[nextTarget] < position)
            nextTarget++;
        const bool isTarget = nextTarget < targets.size() && targets[nextTarget] == position;
        if (isTarget)
            closeRow(position); // a label starts its line
        // the end of the item: the next target, the next range of the user, the end of the zone
        uint64 limit = nextTarget + (isTarget ? 1 : 0) < targets.size() ? targets[nextTarget + (isTarget ? 1 : 0)] : size;
        if (nextFixed < fixedRanges.size())
            limit = std::min(limit, fixedRanges[nextFixed].start);
        limit = std::min(limit, size);

        // a string ended by its zero: UTF-16 (the text of the Windows APIs), then ASCII. A place whose address the code takes is a string
        // from its first character (L":"), the other ones from 4 characters (a variable the code reads holds a number, even 0x41)
        const uint8 accessSize    = isTarget && nextTarget < targetSizes.size() ? targetSizes[nextTarget] : 0;
        const uint64 minimumChars = isTarget && accessSize == 0 ? 1 : MIN_STRING_CHARS;
        uint64 characters         = 0;
        while (position + 2 * characters + 1 < limit && isText(bytes[position + 2 * characters]) && bytes[position + 2 * characters + 1] == 0)
            characters++;
        if (characters >= minimumChars && position + 2 * characters + 1 < limit && bytes[position + 2 * characters] == 0 &&
            bytes[position + 2 * characters + 1] == 0) {
            closeRow(position);
            ranges.push_back({ position, position + 2 * characters + 2, DissasmInstructionSet::UTF16_STRING });
            position += 2 * characters + 2;
            continue;
        }
        uint64 length = 0;
        while (position + length < limit && isText(bytes[position + length]))
            length++;
        if (length >= minimumChars && position + length < limit && bytes[position + length] == 0) {
            closeRow(position);
            ranges.push_back({ position, position + length + 1, DissasmInstructionSet::ASCII_STRING });
            position += length + 1;
            continue;
        }
        // a run of pointers
        if (isPointer && position % pointerSize == 0 && position + pointerSize <= limit && isPointer(readPointer(position))) {
            closeRow(position);
            const uint64 start = position;
            while (position + pointerSize <= limit && isPointer(readPointer(position)))
                position += pointerSize;
            ranges.push_back({ start, position, pointerSize, true });
            continue;
        }
        // a variable the code reads / writes: a value of its size (dd for mov eax, dword ptr [X])
        if ((accessSize == 1 || accessSize == 2 || accessSize == 4 || accessSize == 8) && position + accessSize <= limit) {
            closeRow(position);
            ranges.push_back({ position, position + accessSize, accessSize });
            position += accessSize;
            continue;
        }
        // a byte of a row; a text that is not a string stays in the row (it is not read again from every byte)
        if (rowStart == UINT64_MAX)
            rowStart = position;
        position += length >= MIN_STRING_CHARS ? length : 1;
    }
    closeRow(size);
    return ranges;
}

std::string GView::View::DissasmViewer::MakeStringLabelName(std::string_view text, uint64 address)
{
    constexpr size_t MAX_NAME_CHARS = 24;
    std::string name = "a";
    bool newWord     = true;
    for (const char c : text) {
        if (name.size() > MAX_NAME_CHARS)
            break;
        if (std::isalnum(static_cast<unsigned char>(c))) {
            name.push_back(newWord ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : c);
            newWord = false;
        } else
            newWord = true;
    }
    if (name.size() > 1)
        return name;
    LocalString<32> fallback;
    fallback.SetFormat("asc_%llX", static_cast<unsigned long long>(address));
    return fallback.GetText();
}

void DissasmCodeZone::CollectDataZoneTargets(std::vector<uint64>& targets, std::vector<uint8>& sizes) const
{
    std::map<uint64, uint8> found; // relative address -> the largest access
    const auto collect = [&](const DissasmCodeZone* source) {
        for (const auto& xref : source->xrefs.byTarget)
            if (xref.to >= labelAddressBase && xref.to - labelAddressBase < zoneDetails.size) {
                auto& size = found[xref.to - labelAddressBase];
                size       = std::max(size, xref.size);
            }
    };
    for (const auto* sibling : siblingZones)
        collect(sibling);
    if (zoneDetails.isData)
        collect(this); // its own pointers (the fields of a structure to a string of the same section): known from its previous analysis
    for (const uint64 slot : namedSlots)
        found.try_emplace(slot, 0);
    targets.clear();
    sizes.clear();
    for (const auto& [target, size] : found) {
        targets.push_back(target);
        sizes.push_back(size);
    }
}

void DissasmCodeZone::SetUserDataRange(const DissasmInstructionSet::DataRange& range)
{
    userDataRanges.erase(std::remove_if(userDataRanges.begin(), userDataRanges.end(),
                                        [&range](const auto& item) { return item.start < range.end && range.start < item.end; }),
                         userDataRanges.end());
    const auto next = std::upper_bound(
          userDataRanges.begin(), userDataRanges.end(), range.start, [](uint64 value, const auto& item) { return value < item.start; });
    userDataRanges.insert(next, range);
}

bool DissasmCodeZone::DefineUserData(uint64 address)
{
    const uint64 codeSize = GetCodeSize();
    if (address >= codeSize)
        return false;
    uint64 start = address;
    uint8 unit   = 1;
    const auto found =
          std::find_if(userDataRanges.begin(), userDataRanges.end(), [address](const auto& range) { return address >= range.start && address < range.end; });
    if (found != userDataRanges.end()) {
        start = found->start;
        unit  = found->unit == DissasmInstructionSet::ASCII_STRING || found->unit >= 8 ? 1 : static_cast<uint8>(found->unit * 2); // db -> dw -> dd -> dq -> db; a string -> db
    }
    if (start + unit > codeSize)
        unit = 1;
    SetUserDataRange({ start, start + unit, unit });
    return true;
}

bool DissasmCodeZone::DefineUserString(uint64 address)
{
    constexpr uint32 MAX_STRING_SIZE = 1024;
    const uint64 codeSize            = GetCodeSize();
    if (address >= codeSize || cachedCodeOffsets.empty() || !zoneObject.IsValid())
        return false;
    Reference<GView::Object> obj = zoneObject;
    const auto view = GetZoneBytes(obj, cachedCodeOffsets[0].offset + address, static_cast<uint32>(std::min<uint64>(codeSize - address, MAX_STRING_SIZE)));
    if (!view.IsValid())
        return false;
    const auto isText = [](uint8 value) { return (value >= 0x20 && value < 0x7F) || value == '\t' || value == '\r' || value == '\n'; };
    const uint8* bytes = view.GetData();
    const size_t size  = view.GetLength();
    // UTF-16 (the text of the Windows APIs): a character, a zero, at least 2 of them
    size_t characters = 0;
    while (2 * characters + 1 < size && isText(bytes[2 * characters]) && bytes[2 * characters + 1] == 0)
        characters++;
    if (characters >= 2) {
        const bool endsWithZero = 2 * characters + 1 < size && bytes[2 * characters] == 0 && bytes[2 * characters + 1] == 0;
        SetUserDataRange({ address, address + 2 * characters + (endsWithZero ? 2u : 0u), DissasmInstructionSet::UTF16_STRING });
        return true;
    }
    size_t length = 0;
    while (length < size && isText(bytes[length]))
        length++;
    if (length == 0)
        return false;
    const bool endsWithZero = length < size && bytes[length] == 0;
    SetUserDataRange({ address, address + length + (endsWithZero ? 1u : 0u), DissasmInstructionSet::ASCII_STRING });
    return true;
}

bool DissasmCodeZone::CreateUserFunction(uint64 address)
{
    if (address >= GetCodeSize() || std::binary_search(functionStarts.begin(), functionStarts.end(), address))
        return false;
    uint8& flags = userFunctions[address];
    flags        = static_cast<uint8>((flags & ~USER_FUNCTION_DELETE) | USER_FUNCTION_CREATE);
    return true;
}

bool DissasmCodeZone::DeleteUserFunction(uint64 functionStart)
{
    if (!std::binary_search(functionStarts.begin(), functionStarts.end(), functionStart) ||
        (zoneDetails.HasEntryPoint() && !cachedCodeOffsets.empty() && cachedCodeOffsets[0].offset + functionStart == zoneDetails.entryPoint))
        return false;
    const auto found = userFunctions.find(functionStart);
    if (found != userFunctions.end() && (found->second & USER_FUNCTION_CREATE)) {
        userFunctions.erase(found); // a function of the user: nothing is left of it
        return true;
    }
    userFunctions[functionStart] = USER_FUNCTION_DELETE;
    return true;
}

bool DissasmCodeZone::ToggleUserNoReturn(uint64 functionStart)
{
    if (!std::binary_search(functionStarts.begin(), functionStarts.end(), functionStart))
        return false;
    const bool noReturn = std::binary_search(noReturnFunctions.begin(), noReturnFunctions.end(), functionStart);
    uint8& flags        = userFunctions[functionStart];
    flags               = static_cast<uint8>((flags & ~(USER_FUNCTION_NORETURN | USER_FUNCTION_RETURNS)) | (noReturn ? USER_FUNCTION_RETURNS : USER_FUNCTION_NORETURN));
    return true;
}

bool DissasmCodeZone::UndefineUserData(uint64 address)
{
    const auto found =
          std::find_if(userDataRanges.begin(), userDataRanges.end(), [address](const auto& range) { return address >= range.start && address < range.end; });
    if (found == userDataRanges.end())
        return false;
    userDataRanges.erase(found);
    return true;
}

std::vector<DissasmZoneXref> DissasmCodeZone::GetXrefsTo(uint64 address) const
{
    std::vector<DissasmZoneXref> references;
    const auto addZone = [&references, address](DissasmCodeZone* zone) {
        const auto [first, last] = zone->xrefs.To(address);
        for (auto it = first; it != last; ++it)
            references.push_back({ &*it, zone });
    };
    addZone(const_cast<DissasmCodeZone*>(this));
    for (auto* sibling : siblingZones)
        addZone(sibling);
    return references;
}

DissasmCodeZone* DissasmCodeZone::FindCodeZoneOfAddress(uint64 address) const
{
    const auto contains = [address](const DissasmCodeZone* zone) {
        return zone->CanReachAsmLines() && address >= zone->labelAddressBase && address - zone->labelAddressBase < zone->GetCodeSize();
    };
    if (contains(this))
        return const_cast<DissasmCodeZone*>(this);
    for (auto* sibling : siblingZones)
        if (contains(sibling))
            return sibling;
    return nullptr;
}

void GView::View::DissasmViewer::LinkCodeZones(const std::vector<std::unique_ptr<ParseZone>>& zones)
{
    std::vector<DissasmCodeZone*> codeZones;
    for (const auto& zone : zones)
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
            codeZones.push_back(static_cast<DissasmCodeZone*>(zone.get()));
    for (auto* zone : codeZones) {
        zone->siblingZones.clear();
        for (auto* other : codeZones)
            if (other != zone)
                zone->siblingZones.push_back(other);
    }
}

std::vector<DissasmCallReference> DissasmCodeZone::GetCallees(
      uint64 functionStart, const std::function<const MemoryMappingEntry*(const X86OperandsInfo&)>& findImport) const
{
    std::vector<DissasmCallReference> callees;
    if (cachedCodeOffsets.empty() || !zoneObject.IsValid() || !hasDecoder)
        return callees;
    // the function ends with the next one (the size of a function is not known for every function)
    constexpr uint64 MAX_FUNCTION_SIZE = 0x100000;
    const uint64 codeSize              = GetCodeSize();
    const auto next                    = std::upper_bound(functionStarts.begin(), functionStarts.end(), functionStart);
    const uint64 end                   = std::min<uint64>({ next != functionStarts.end() ? *next : codeSize, codeSize, functionStart + MAX_FUNCTION_SIZE });
    if (functionStart >= end)
        return callees;

    const csh handle = GetDecodeHandle(); // the handle of the zone (details on): no capstone tables allocated per call
    if (handle == 0)
        return callees;
    {
        cs_insn* insn                = cs_malloc(handle);
        Reference<GView::Object> obj = zoneObject;
        const auto ranges            = GetFunctionRanges(functionStart, end);
        const auto inside            = [&ranges](uint64 address) {
            return std::any_of(ranges.begin(), ranges.end(), [address](const auto& range) { return address >= range.first && address < range.second; });
        };
        for (const auto& [rangeStart, rangeEnd] : ranges) // the function, then its chunks
        for (DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, codeSize, handle, rangeStart, &instructionBoundaries, paddingAlignmentBase, &instructionSet);
             walker.Next(insn) && insn->address < rangeEnd;) {
            const auto flow = GetInstructionFlow(*insn, GetArch());
            if (flow != X86Flow::Call && flow != X86Flow::Jump)
                continue;
            const auto operands = GetInstructionOperands(*insn, GetArch());
            DissasmCallReference callee;
            callee.site = insn->address;
            if (operands.directTarget.has_value()) {
                const uint64 target = operands.directTarget.value();
                // a jmp inside the function is not a call; a jmp to another function is a tail call; call $+5 takes the address of the code
                if ((flow == X86Flow::Jump && inside(target)) || (flow == X86Flow::Call && target == insn->address + insn->size))
                    continue;
                callee.isTailJump = flow == X86Flow::Jump;
                // a function of another code zone of the file (.text calls PAGE): its address and its name there
                const uint64 addressMask = Is64BitCode() ? UINT64_MAX : 0xFFFFFFFFull;
                auto* targetZone         = target < codeSize ? const_cast<DissasmCodeZone*>(this) : FindCodeZoneOfAddress((labelAddressBase + target) & addressMask);
                if (!targetZone)
                    targetZone = const_cast<DissasmCodeZone*>(this); // outside of the code zones: as before (its name after its address)
                const uint64 targetStart = targetZone == this ? target : ((labelAddressBase + target) & addressMask) - targetZone->labelAddressBase;
                callee.zone              = targetZone != this ? targetZone : nullptr;
                callee.functionStart     = targetStart;
                callee.function          = targetZone->GetLabelNameAt(targetStart);
                if (callee.function.empty())
                    callee.function = targetZone->GetLabelName("sub_", targetStart);
            } else {
                // through an import slot (call [rip + ...]), or an indirect call (call rax): a jmp rax is a switch, not a call
                const auto import = findImport ? findImport(operands) : nullptr;
                if (import)
                    callee.function = import->name;
                else if (flow == X86Flow::Call)
                    callee.function = std::string(insn->mnemonic) + " " + insn->op_str;
                else
                    continue;
                callee.isTailJump = flow == X86Flow::Jump;
            }
            callees.push_back(std::move(callee));
        }
        cs_free(insn, 1);
    }
    return callees;
}

std::vector<DissasmStringReference> DissasmCodeZone::GetReferencedStrings(const std::function<std::optional<uint64>(uint64)>& addressToFileOffset) const
{
    std::vector<DissasmStringReference> strings;
    if (!addressToFileOffset || !zoneObject.IsValid())
        return strings;
    Reference<GView::Object> obj = zoneObject;
    const uint64 fileSize        = obj->GetData().GetSize();
    const auto& references       = xrefs.byTarget; // sorted by target
    for (size_t index = 0; index < references.size();) {
        const uint64 target = references[index].to;
        uint32 dataReferences = 0;
        for (; index < references.size() && references[index].to == target; index++)
            if (references[index].kind == DissasmXrefKind::Read || references[index].kind == DissasmXrefKind::Offset)
                dataReferences++;
        if (dataReferences == 0)
            continue;
        const auto offset = addressToFileOffset(target);
        if (!offset.has_value() || offset.value() >= fileSize)
            continue;
        auto text = TryExtractStringPreview(obj, offset.value());
        if (text.has_value())
            strings.push_back({ target, std::move(text.value()), dataReferences });
    }
    return strings;
}

std::vector<DissasmStringReference> DissasmCodeZone::GetReferencedStringsOfFile(const std::function<std::optional<uint64>(uint64)>& addressToFileOffset) const
{
    auto strings = GetReferencedStrings(addressToFileOffset);
    if (siblingZones.empty())
        return strings;
    std::map<uint64, DissasmStringReference> byAddress;
    for (auto& string : strings)
        byAddress.emplace(string.address, std::move(string));
    for (const auto* sibling : siblingZones) {
        if (!sibling->CanReachAsmLines())
            continue;
        for (auto& string : sibling->GetReferencedStrings(addressToFileOffset)) {
            auto [item, added] = byAddress.try_emplace(string.address, string);
            if (!added)
                item->second.xrefs += string.xrefs; // the same string used by .text and PAGE
        }
    }
    strings.clear();
    strings.reserve(byAddress.size());
    for (auto& [address, string] : byAddress)
        strings.push_back(std::move(string));
    return strings;
}

std::optional<DissasmSearchHit> GView::View::DissasmViewer::SearchCodeZones(
      const std::vector<DissasmCodeZone*>& zones,
      size_t startZone,
      uint64 from,
      const DissasmSearch& search,
      const std::function<DissasmInsnExtractLineParams*(DissasmCodeZone*)>& makeParams)
{
    if (startZone >= zones.size())
        return {};
    std::vector<int16> pattern;
    uint64 value = 0;
    if (search.kind == DissasmSearchKind::Bytes) {
        auto parsed = ParseDissasmBytePattern(search.text);
        if (!parsed.has_value() || parsed->empty())
            return {};
        pattern = std::move(parsed.value());
    } else if (search.kind == DissasmSearchKind::Immediate) {
        const auto parsed = ParseDissasmSearchNumber(search.text);
        if (!parsed.has_value())
            return {};
        value = parsed.value();
    }
    // [begin, end): lines of the zone (a text), relative addresses (bytes, an immediate)
    const auto searchZone = [&](DissasmCodeZone* zone, uint64 begin, uint64 end) -> std::optional<uint64> {
        switch (search.kind) {
        case DissasmSearchKind::Text: {
            end              = std::min<uint64>(end, zone->GetDisplayLinesCount());
            const auto found = begin < end ? zone->FindText(search.text, search.matchCase, static_cast<uint32>(begin), static_cast<uint32>(end),
                                                            makeParams ? makeParams(zone) : nullptr)
                                           : std::nullopt;
            return found.has_value() ? std::optional<uint64>(found.value()) : std::nullopt;
        }
        case DissasmSearchKind::Bytes:
            return zone->FindBytes(pattern, begin, end);
        default:
            return zone->FindImmediate(value, begin, end);
        }
    };
    const auto zoneEnd = [&search](const DissasmCodeZone* zone) -> uint64 {
        return search.kind == DissasmSearchKind::Text ? zone->GetDisplayLinesCount() : zone->GetCodeSize();
    };
    for (size_t step = 0; step < zones.size(); step++) {
        auto* zone = zones[(startZone + step) % zones.size()];
        if (const auto found = searchZone(zone, step == 0 ? from : 0, zoneEnd(zone)); found.has_value())
            return DissasmSearchHit{ zone, found.value() };
    }
    // the start of the first zone, up to `from` (a byte pattern that starts before it may end after it)
    if (from > 0) {
        auto* zone       = zones[startZone];
        const uint64 end = search.kind == DissasmSearchKind::Bytes ? std::min<uint64>(zone->GetCodeSize(), from + pattern.size() - 1) : from;
        if (const auto found = searchZone(zone, 0, end); found.has_value())
            return DissasmSearchHit{ zone, found.value() };
    }
    return {};
}

std::optional<uint64> DissasmCodeZone::FindBytes(const std::vector<int16>& pattern, uint64 from, uint64 to) const
{
    if (pattern.empty() || cachedCodeOffsets.empty() || !zoneObject.IsValid())
        return {};
    to = std::min(to, GetCodeSize());
    if (from >= to || to - from < pattern.size())
        return {};
    Reference<GView::Object> obj = zoneObject;
    const uint64 codeStart       = cachedCodeOffsets[0].offset;
    // the code is read window after window; two windows overlap with the size of the pattern
    constexpr uint64 WINDOW = 0x10000;
    uint64 position         = from;
    while (to - position >= pattern.size()) {
        const auto requested = static_cast<uint32>(std::min<uint64>(to - position, WINDOW + pattern.size() - 1));
        const auto view      = GetZoneBytes(obj, codeStart + position, requested);
        if (!view.IsValid() || view.GetLength() < pattern.size())
            return {};
        const uint8* data   = view.GetData();
        const size_t length = std::min<size_t>(view.GetLength(), requested);
        for (size_t index = 0; index + pattern.size() <= length; index++) {
            bool matches = true;
            for (size_t patternIndex = 0; patternIndex < pattern.size() && matches; patternIndex++)
                matches = pattern[patternIndex] < 0 || data[index + patternIndex] == static_cast<uint8>(pattern[patternIndex]);
            if (matches)
                return position + index;
        }
        position += length - pattern.size() + 1;
    }
    return {};
}

std::optional<uint64> DissasmCodeZone::FindImmediate(uint64 value, uint64 from, uint64 to) const
{
    if (cachedCodeOffsets.empty() || !zoneObject.IsValid() || !hasDecoder)
        return {};
    to = std::min(to, GetCodeSize());
    if (from >= to)
        return {};
    const csh handle = GetDecodeHandle(); // the handle of the zone (details on)
    if (handle == 0)
        return {};
    std::optional<uint64> result;
    {
        cs_insn* insn           = cs_malloc(handle);
        const uint64 mask       = Is64BitCode() ? UINT64_MAX : 0xFFFFFFFFull;
        const uint64 wanted     = value & mask;
        Reference<GView::Object> obj = zoneObject;
        DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, GetCodeSize(), handle, from, &instructionBoundaries, paddingAlignmentBase, &instructionSet);
        while (!result.has_value() && walker.Next(insn) && insn->address < to) {
            if (insn->id == X86_INS_INVALID || !insn->detail)
                continue; // a data line (db)
            if (IsArm32Code()) { // mov r0, #0x10 / cmp r1, #0x20
                const cs_arm& arm = insn->detail->arm;
                for (uint8 index = 0; index < arm.op_count && !result.has_value(); index++)
                    if (arm.operands[index].type == ARM_OP_IMM && (static_cast<uint64>(static_cast<uint32>(arm.operands[index].imm)) & mask) == wanted)
                        result = insn->address;
                continue;
            }
            if (IsArm64Code()) { // mov x0, #0x10 / cmp w1, #0x20 / add x0, x1, #0x8
                const cs_arm64& arm64 = insn->detail->arm64;
                for (uint8 index = 0; index < arm64.op_count && !result.has_value(); index++)
                    if (arm64.operands[index].type == ARM64_OP_IMM && static_cast<uint64>(arm64.operands[index].imm) == wanted)
                        result = insn->address;
                continue;
            }
            const cs_x86& x86 = insn->detail->x86;
            for (uint8 index = 0; index < x86.op_count; index++) {
                const cs_x86_op& op = x86.operands[index];
                // the immediates, and the displacements that are written ([rbp - 0x10], [0x402010]; not the 0 of [rax])
                const bool isImmediate    = op.type == X86_OP_IMM && (static_cast<uint64>(op.imm) & mask) == wanted;
                const bool isDisplacement = op.type == X86_OP_MEM && op.mem.disp != 0 && (static_cast<uint64>(op.mem.disp) & mask) == wanted;
                if (isImmediate || isDisplacement) {
                    result = insn->address;
                    break;
                }
            }
        }
        cs_free(insn, 1);
    }
    return result;
}

std::optional<uint32> DissasmCodeZone::FindText(std::string_view text, bool matchCase, uint32 fromLine, uint32 toLine, DissasmInsnExtractLineParams* params)
{
    if (text.empty() || !CanReachAsmLines() || !zoneObject.IsValid())
        return {};
    const auto lower = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    };
    const std::string wanted = matchCase ? std::string(text) : lower(std::string(text));
    toLine                   = std::min(toLine, GetDisplayLinesCount());
    std::string lineText, comment;
    for (uint32 line = fromLine; line < toLine; line++) {
        const auto asmLine = GetCurrentAsmLine(line, zoneObject, params);
        // the text of the line as it is shown: a label, a variable, or the mnemonic and its operands, then the comments
        lineText.assign(asmLine.GetMnemonicText());
        if (asmLine.op_str) {
            lineText += ' ';
            lineText.append(asmLine.op_str, asmLine.op_str_size);
        } else if (asmLine.mapping) {
            lineText += ' ';
            lineText += static_cast<const MemoryMappingEntry*>(asmLine.mapping)->name;
        }
        if (GetComment(asmLine, comment))
            lineText.append(" ; ").append(comment);
        if (GetRepeatableComment(asmLine, comment))
            lineText.append(" ; ").append(comment);
        if (!asmLine.autoComment.empty())
            lineText.append(" ; ").append(asmLine.autoComment);
        if ((matchCase ? lineText : lower(lineText)).find(wanted) != std::string::npos)
            return line;
    }
    return {};
}

std::string DissasmCodeZone::FormatCodeAddress(uint64 relativeAddress) const
{
    LocalString<64> text;
    // outside of the code (a branch to another section): the name in the code zone that has it, else the address
    if (!cachedCodeOffsets.empty() && relativeAddress >= GetCodeSize()) {
        const uint64 addressMask = Is64BitCode() ? UINT64_MAX : 0xFFFFFFFFull; // 32 bit addresses wrap around
        const uint64 address     = (labelAddressBase + relativeAddress) & addressMask;
        if (const auto other = FindCodeZoneOfAddress(address); other && other != this)
            return other->FormatCodeAddress(address - other->labelAddressBase);
        text.SetFormat("0x%llx", static_cast<unsigned long long>(address));
        return text.GetText();
    }
    // a data zone: the label placed before the address, when the item at the label covers it (off_1048+0x8, aText+0x3); not past it (a
    // variable of the uninitialized part of the section after the last label is not qword_X+0x40)
    if (zoneDetails.isData) {
        const auto label = std::upper_bound(sortedLabelAddresses.begin(), sortedLabelAddresses.end(), relativeAddress);
        const auto* item = label != sortedLabelAddresses.begin() ? instructionSet.DataRangeAt(*(label - 1)) : nullptr;
        if (label != sortedLabelAddresses.begin() && (relativeAddress == *(label - 1) || (item && relativeAddress < item->end))) {
            const uint64 labelAddress = *(label - 1);
            std::string name          = GetLabelNameAt(labelAddress);
            if (relativeAddress == labelAddress)
                return name;
            text.SetFormat("+0x%llX", static_cast<unsigned long long>(relativeAddress - labelAddress));
            return name + text.GetText();
        }
        text.SetFormat("0x%llx", static_cast<unsigned long long>(labelAddressBase + relativeAddress));
        return text.GetText();
    }
    // a chunk: the function it belongs to (IDA: sub_X+0x4D5B2; a chunk placed before its function: sub_X-0x120)
    if (const auto* chunk = FindChunkContaining(relativeAddress)) {
        std::string name = GetLabelNameAt(chunk->function);
        if (name.empty())
            name = GetLabelName("sub_", chunk->function);
        const bool before = relativeAddress < chunk->function;
        text.SetFormat(before ? "-0x%llX" : "+0x%llX", static_cast<unsigned long long>(before ? chunk->function - relativeAddress : relativeAddress - chunk->function));
        return name + text.GetText();
    }
    // the function that contains the address: the last function start placed before it
    const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
    if (next == functionStarts.begin()) {
        const std::string label = GetLabelNameAt(relativeAddress);
        if (!label.empty())
            return label;
        text.SetFormat("0x%llx", static_cast<unsigned long long>(labelAddressBase + relativeAddress));
        return text.GetText();
    }
    const uint64 functionStart = *(next - 1);
    std::string name           = GetLabelNameAt(functionStart);
    if (name.empty())
        name = GetLabelName("sub_", functionStart);
    if (relativeAddress == functionStart)
        return name;
    text.SetFormat("+0x%llX", static_cast<unsigned long long>(relativeAddress - functionStart));
    return name + text.GetText();
}

std::string DissasmCodeZone::FormatExceptionMarks(uint64 relativeAddress) const
{
    const auto marks = exceptionMarks.find(relativeAddress);
    if (marks == exceptionMarks.end())
        return {};
    const auto nameOf = [this](uint64 address) {
        std::string name = GetLabelNameAt(address);
        return name.empty() ? FormatCodeAddress(address) : name;
    };
    std::string text;
    for (const auto& mark : marks->second) {
        if (!text.empty())
            text += "; ";
        const std::string handler = mark.handler.has_value() ? nameOf(mark.handler.value()) : std::string("EXCEPTION_EXECUTE_HANDLER");
        switch (mark.kind) {
        case ExceptionMark::Kind::TryBegin:
            text += mark.target.has_value() ? "__try { // __except at " + nameOf(mark.target.value()) : "__try { // __finally(" + handler + ")";
            break;
        case ExceptionMark::Kind::TryEnd:
            text += "} // starts at " + FormatCodeAddress(mark.begin);
            break;
        case ExceptionMark::Kind::Except:
            text += "__except(" + handler + ")" + (mark.owned ? " // owned by " + FormatCodeAddress(mark.begin) : std::string());
            break;
        case ExceptionMark::Kind::Finally:
            text += "__finally" + (mark.owned ? " // owned by " + FormatCodeAddress(mark.begin) : std::string());
            break;
        case ExceptionMark::Kind::Filter:
            text += "__except filter" + (mark.owned ? " // owned by " + FormatCodeAddress(mark.begin) : std::string());
            break;
        case ExceptionMark::Kind::CppTryBegin:
            text += "try {";
            break;
        case ExceptionMark::Kind::Catch:
            text += "catch(" + mark.catchType + ")" + (mark.owned ? " // owned by " + FormatCodeAddress(mark.begin) : std::string());
            break;
        case ExceptionMark::Kind::Cleanup:
            text += "cleanup() // owned by " + FormatCodeAddress(mark.begin);
            break;
        }
    }
    return text;
}

std::string DissasmCodeZone::FormatXrefsSummary(uint64 relativeAddress) const
{
    constexpr size_t SHOWN_XREFS = 2;
    const auto references        = GetXrefsTo(labelAddressBase + relativeAddress); // the other sections of the file too
    const auto count             = references.size();
    if (count == 0)
        return {};
    std::string text = count == 1 ? "xref: " : "xrefs: ";
    for (size_t index = 0; index < count && index < SHOWN_XREFS; index++) {
        const auto& [xref, source] = references[index];
        if (index > 0)
            text += ", ";
        text += source->FormatCodeAddress(xref->from - source->labelAddressBase);
        text += " (";
        text += GetXrefKindName(xref->kind);
        text += ')';
    }
    if (count > SHOWN_XREFS) {
        LocalString<32> more;
        more.SetFormat(" +%zu more", count - SHOWN_XREFS);
        text += more.GetText();
    }
    return text;
}

bool DissasmCodeZone::IsAnnotationLine(uint32 expandedLine) const
{
    return std::binary_search(annotationLines.begin(), annotationLines.end(), expandedLine);
}

uint32 DissasmCodeZone::ExpandedToInstructionIndex(uint32 expandedLine) const
{
    const auto annotationsBefore = std::lower_bound(annotationLines.begin(), annotationLines.end(), expandedLine) - annotationLines.begin();
    return expandedLine - static_cast<uint32>(annotationsBefore);
}

uint32 DissasmCodeZone::InstructionIndexToExpanded(uint32 instructionIndex) const
{
    // f(line) = line - annotations before it never decreases: the first line with f >= instructionIndex, an annotation line has the f
    // of the instruction that follows it (the labels / variables are placed right before their instruction)
    uint32 low  = instructionIndex;
    uint32 high = instructionIndex + static_cast<uint32>(annotationLines.size());
    while (low < high) {
        const uint32 middle = low + (high - low) / 2u;
        if (ExpandedToInstructionIndex(middle) < instructionIndex)
            low = middle + 1u;
        else
            high = middle;
    }
    while (IsAnnotationLine(low))
        low++;
    return low;
}

uint32 DissasmCodeZone::GetDisplayLinesCount() const
{
    // the collapsed zones that are shown (not inside another collapsed zone) hide every line of their range but the first one
    uint32 hidden = 0, hiddenUntil = 0;
    for (const auto& zone : collapsibleZones) {
        if (!zone.isCollapsed || zone.start < hiddenUntil)
            continue;
        hidden += zone.end - zone.start - 1u;
        hiddenUntil = zone.end;
    }
    const uint32 expandedLines = GetExpandedLinesCount();
    return expandedLines > hidden ? expandedLines - hidden : 0u;
}

std::optional<DissasmCodeZone::LinePlace> DissasmCodeZone::DisplayToExpanded(uint32 displayLine) const
{
    uint32 hidden = 0, hiddenUntil = 0;
    for (const auto& zone : collapsibleZones) {
        if (!zone.isCollapsed || zone.start < hiddenUntil)
            continue;
        const uint32 shownStart = zone.start - hidden;
        if (displayLine < shownStart)
            break;
        if (displayLine == shownStart)
            return LinePlace{ zone.start, &zone };
        hidden += zone.end - zone.start - 1u;
        hiddenUntil = zone.end;
    }
    const uint32 expandedLine = displayLine + hidden;
    if (expandedLine >= GetExpandedLinesCount())
        return {};
    return LinePlace{ expandedLine, nullptr };
}

uint32 DissasmCodeZone::ExpandedToDisplay(uint32 expandedLine) const
{
    uint32 hidden = 0, hiddenUntil = 0;
    for (const auto& zone : collapsibleZones) {
        if (!zone.isCollapsed || zone.start < hiddenUntil)
            continue;
        if (expandedLine < zone.start)
            break;
        if (expandedLine < zone.end)
            return zone.start - hidden; // hidden by the zone: its line
        hidden += zone.end - zone.start - 1u;
        hiddenUntil = zone.end;
    }
    return expandedLine - hidden;
}

DissasmCollapsibleZone* DissasmCodeZone::FindInnermostZone(uint32 expandedLine)
{
    // sorted by start and the outer zone first: the last zone that contains the line is the innermost one
    DissasmCollapsibleZone* result = nullptr;
    for (auto& zone : collapsibleZones) {
        if (zone.start > expandedLine)
            break;
        if (zone.Contains(expandedLine))
            result = &zone;
    }
    return result;
}

const DissasmCollapsibleZone* DissasmCodeZone::FindInnermostZoneStartingAt(uint32 expandedLine) const
{
    const DissasmCollapsibleZone* result = nullptr;
    for (const auto& zone : collapsibleZones) {
        if (zone.start > expandedLine)
            break;
        if (zone.start == expandedLine)
            result = &zone;
    }
    return result;
}

bool DissasmCodeZone::CanPlaceZone(const DissasmCollapsibleZone& zone) const
{
    if (zone.start >= zone.end || zone.end > GetExpandedLinesCount())
        return false;
    for (const auto& other : collapsibleZones) {
        if (other.start == zone.start && other.end == zone.end)
            return false; // the same zone
        const bool disjoint = zone.end <= other.start || other.end <= zone.start;
        if (!disjoint && !other.Contains(zone) && !zone.Contains(other))
            return false; // partially overlapping
    }
    return true;
}

void DissasmCodeZone::InsertZone(DissasmCollapsibleZone zone)
{
    const auto position = std::upper_bound(collapsibleZones.begin(), collapsibleZones.end(), zone, [](const auto& left, const auto& right) {
        return left.start < right.start || (left.start == right.start && left.end > right.end);
    });
    collapsibleZones.insert(position, std::move(zone));
}

void DissasmCodeZone::ResetZoneCaching()
{
    asmPreCacheData.Clear();
}

bool DissasmCodeZone::GetAIComment(const DissasmAsmPreCacheLine& line, std::string& comment) const
{
    return !line.isCollapsedLine && aiComments.Get(GetLineAnchor(line), comment);
}

bool DissasmCodeZone::SetAIComment(uint32 line, std::string comment)
{
    const auto anchor = GetAnchorOfLine(line);
    if (!anchor.has_value() || comment.empty())
        return false;
    aiComments.Set(anchor.value(), std::move(comment));
    ResetZoneCaching();
    return true;
}

std::optional<std::string> DissasmCodeZone::GetSuggestedName(const DissasmAsmPreCacheLine& line) const
{
    // the label lines only (not the variables, not a collapsed zone)
    if (line.size != 0 || line.isCollapsedLine || line.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition)
        return {};
    const auto name = suggestedNames.find(line.address);
    if (name == suggestedNames.end())
        return {};
    return name->second;
}

GStatus DissasmCodeZone::AcceptAISuggestion(uint32 line)
{
    if (!CanReachAsmLines() || !zoneObject.IsValid() || line >= GetDisplayLinesCount())
        return GStatus::Error("Please select a line of the disassembly!");
    const auto asmLine = GetCurrentAsmLine(line, zoneObject, nullptr);

    // a label with a suggested name: its new name
    if (const auto name = GetSuggestedName(asmLine); name.has_value()) {
        const auto labelLine = labelLineOfAddress.find(asmLine.address);
        if (labelLine == labelLineOfAddress.end())
            return GStatus::Error("The label of the suggestion was not found!");
        const std::string currentName = GetLabelNameAt(asmLine.address);
        if (currentName != name.value() && !RenameLabel(labelLine->second, currentName, name.value()))
            return GStatus::Error("Another label already has this name!");
        suggestedNames.erase(asmLine.address);
        ResetZoneCaching();
        return GStatus{ .ok = true, .message = "renamed" };
    }

    // the comment of the assistant: the comment of the user (after the one the user wrote)
    std::string aiComment;
    if (!GetAIComment(asmLine, aiComment))
        return GStatus::Error("There is no suggestion of the assistant on this line!");
    const auto anchor = GetLineAnchor(asmLine);
    std::string userComment;
    const std::string text = userComments.Get(anchor, userComment) ? userComment + "; " + aiComment : aiComment;
    if (!AddOrUpdateComment(line, text, false))
        return GStatus::Error("Failed to add the comment!");
    aiComments.Remove(anchor);
    ResetZoneCaching();
    return GStatus{ .ok = true, .message = "commented" };
}

bool DissasmCodeZone::DismissAISuggestion(uint32 line)
{
    if (!CanReachAsmLines() || !zoneObject.IsValid() || line >= GetDisplayLinesCount())
        return false;
    const auto asmLine = GetCurrentAsmLine(line, zoneObject, nullptr);
    bool removed       = false;
    if (GetSuggestedName(asmLine).has_value())
        removed = suggestedNames.erase(asmLine.address) > 0;
    if (!asmLine.isCollapsedLine)
        removed = aiComments.Remove(GetLineAnchor(asmLine)) || removed;
    if (removed)
        ResetZoneCaching();
    return removed;
}

std::optional<uint32> DissasmCodeZone::GetLabelDisplayLine(uint64 relativeAddress) const
{
    const auto line = labelLineOfAddress.find(relativeAddress);
    if (line == labelLineOfAddress.end())
        return {};
    return ExpandedToDisplay(line->second);
}

std::string DissasmCodeZone::BuildAssistantFunctionText(uint64 functionStart, DissasmInsnExtractLineParams* params)
{
    constexpr uint32 MAX_LINES_ANALYSED = 150; // the lines read, the instructions sent and the calls listed after them
    constexpr uint32 MAX_LINES_SENT     = 100;
    constexpr uint32 MAX_API_CALLS      = 10;
    const auto labelLine                = GetLabelDisplayLine(functionStart);
    if (!labelLine.has_value() || !zoneObject.IsValid())
        return {};
    std::string text = std::string("Here is ") + GetArchitectureName() + " assembly code:\n";
    std::vector<std::string> calls;
    uint32 sentLines        = 0;
    const uint32 linesCount = GetDisplayLinesCount();
    for (uint32 line = labelLine.value() + 1u, read = 0; line < linesCount && read < MAX_LINES_ANALYSED; line++, read++) {
        const auto asmLine = GetCurrentAsmLine(line, zoneObject, params);
        if (asmLine.isCollapsedLine)
            continue;
        if (asmLine.size == 0) {
            if (asmLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition) {
                if (asmLine.op_str && sentLines < MAX_LINES_SENT) {
                    text.append(asmLine.op_str, asmLine.op_str_size);
                    if (!asmLine.autoComment.empty()) // its type and where it comes from
                        text.append(" ; ").append(asmLine.autoComment);
                    text.append("\n");
                    sentLines++;
                }
                continue;
            }
            // the label of the next function ends this one
            if (asmLine.address != functionStart && std::binary_search(functionStarts.begin(), functionStarts.end(), asmLine.address))
                break;
            if (sentLines < MAX_LINES_SENT) {
                text.append(asmLine.GetMnemonicText()).append(":\n");
                sentLines++;
            }
            continue;
        }
        // the instruction with the names of its targets / imports and the generated comment (string, import, argument)
        std::string instruction = std::string("   ") + asmLine.mnemonic;
        if (asmLine.op_str)
            instruction.append(" ").append(asmLine.op_str, asmLine.op_str_size);
        else if (asmLine.mapping)
            instruction.append(" ").append(static_cast<const MemoryMappingEntry*>(asmLine.mapping)->name);
        if (!asmLine.autoComment.empty())
            instruction.append(" ; ").append(asmLine.autoComment);
        if (sentLines < MAX_LINES_SENT) {
            text.append(instruction).append("\n");
            sentLines++;
        } else if (strcmp(asmLine.mnemonic, "call") == 0 && calls.size() < MAX_API_CALLS) {
            calls.push_back(std::move(instruction));
        }
        if (strcmp(asmLine.mnemonic, "ret") == 0)
            break;
    }
    if (!calls.empty()) {
        text.append("The function also makes these calls:\n");
        for (const auto& call : calls)
            text.append(call).append("\n");
    }
    return text;
}

std::string GView::View::DissasmViewer::ParseAssistantSuggestedName(std::string_view answer)
{
    // the first name of the answer: names separated by commas / new lines, maybe numbered (1. ParseHeader) or quoted (`ParseHeader`)
    size_t start = 0;
    while (start < answer.size()) {
        size_t end = answer.find_first_of(",\n", start);
        if (end == std::string_view::npos)
            end = answer.size();
        auto token = answer.substr(start, end - start);
        start      = end + 1;
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t' || token.front() == '-' || token.front() == '*' ||
                                  (token.front() >= '0' && token.front() <= '9') || token.front() == '.' || token.front() == ')'))
            token.remove_prefix(1);
        std::string name;
        for (const char c : token) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
                name += c;
            else if (c == ' ' || c == '\t' || c == '`' || c == '"' || c == '\'' || c == '(' || c == ')' || c == '\r')
                continue; // spaces and quotes around the name
            else
                break;
        }
        constexpr size_t MAX_NAME_SIZE = 64;
        if (!name.empty() && !(name.front() >= '0' && name.front() <= '9') && name.size() <= MAX_NAME_SIZE)
            return name;
    }
    return {};
}

void DissasmCodeZone::RecordEdit(DissasmEdit edit)
{
    constexpr size_t MAX_EDITS = 256;
    if (undoEdits.size() == MAX_EDITS)
        undoEdits.erase(undoEdits.begin());
    undoEdits.push_back(std::move(edit));
    redoEdits.clear(); // a new edit: the undone ones can not be redone any more
}

void DissasmCodeZone::ClearEditHistory()
{
    undoEdits.clear();
    redoEdits.clear();
}

DissasmEditHistory DissasmCodeZone::TakeEditHistory()
{
    const auto byLine = [](const DissasmEdit& edit) { return edit.kind == DissasmEdit::Kind::AddZone || edit.kind == DissasmEdit::Kind::RemoveZone; };
    DissasmEditHistory history{ std::move(undoEdits), std::move(redoEdits) };
    history.undo.erase(std::remove_if(history.undo.begin(), history.undo.end(), byLine), history.undo.end());
    history.redo.erase(std::remove_if(history.redo.begin(), history.redo.end(), byLine), history.redo.end());
    undoEdits.clear();
    redoEdits.clear();
    return history;
}

void DissasmCodeZone::RestoreEditHistory(DissasmEditHistory history)
{
    undoEdits = std::move(history.undo);
    redoEdits = std::move(history.redo);
}

void DissasmCodeZone::RecordUserFunctionsEdit(std::map<uint64, uint8> before, uint64 address)
{
    DissasmEdit edit;
    edit.kind            = DissasmEdit::Kind::UserFunctions;
    edit.address         = address;
    edit.functionsBefore = std::move(before);
    edit.functionsAfter  = userFunctions;
    RecordEdit(std::move(edit));
}

const AsmFunctionDetails* DissasmCodeZone::FindUserPrototype(uint64 functionStart) const
{
    if (userPrototypes.empty())
        return nullptr;
    const auto text = userPrototypes.find(functionStart);
    if (text == userPrototypes.end())
        return nullptr;
    auto& parsed = parsedUserPrototypes[functionStart];
    if (parsed.first != text->second || (!parsed.second && parsed.first.empty())) {
        parsed.first  = text->second;
        parsed.second = ParseUserPrototype(text->second);
    }
    return parsed.second ? &parsed.second->details : nullptr;
}

const AsmFunctionDetails* DissasmCodeZone::FindInferredPrototype(uint64 functionStart) const
{
    const auto found = inferredPrototypes.find(functionStart);
    return found != inferredPrototypes.end() && found->second ? &found->second->details : nullptr;
}

const AsmFunctionDetails* DissasmCodeZone::FindMethodPrototype(std::string_view name) const
{
    return FindMethodPrototypeByName(methodPrototypes, name);
}

const AsmFunctionDetails* DissasmCodeZone::FindNamedPrototype(uint64 functionStart) const
{
    const auto thunk       = thunkImports.find(functionStart);
    const std::string name = thunk != thunkImports.end() ? thunk->second : GetLabelNameAt(functionStart);
    if (name.empty())
        return nullptr;
    if (const auto* api = FindApiPrototype(name))
        return api;
    return FindMethodPrototype(name);
}

const AsmFunctionDetails* DissasmCodeZone::FindFunctionPrototype(uint64 functionStart) const
{
    if (const auto* user = FindUserPrototype(functionStart))
        return user;
    return FindInferredPrototype(functionStart);
}

void DissasmCodeZone::RecordUserPrototypesEdit(std::map<uint64, std::string> before, uint64 address)
{
    DissasmEdit edit;
    edit.kind             = DissasmEdit::Kind::UserPrototypes;
    edit.address          = address;
    edit.prototypesBefore = std::move(before);
    edit.prototypesAfter  = userPrototypes;
    RecordEdit(std::move(edit));
}

bool DissasmCodeZone::SetRepeatableComment(uint64 address, const std::string& text)
{
    const auto found = repeatableComments.find(address);
    std::optional<std::string> before;
    if (found != repeatableComments.end())
        before = found->second;
    const std::optional<std::string> after = text.empty() ? std::nullopt : std::optional<std::string>(text);
    if (before == after)
        return false;
    if (after.has_value())
        repeatableComments[address] = after.value();
    else
        repeatableComments.erase(address);
    DissasmEdit edit;
    edit.kind    = DissasmEdit::Kind::RepeatableComment;
    edit.address = address;
    edit.before  = std::move(before);
    edit.after   = after;
    RecordEdit(std::move(edit));
    ResetZoneCaching();
    return true;
}

bool DissasmCodeZone::HasOwnRepeatableComment(const DissasmAsmPreCacheLine& line) const
{
    if (line.isCollapsedLine || line.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition || !repeatableComments.contains(line.address))
        return false;
    // a label line shows the comment of its address; the instruction only when the address has no label
    return line.size == 0 || !labelLineOfAddress.contains(line.address);
}

bool DissasmCodeZone::GetRepeatableComment(const DissasmAsmPreCacheLine& line, std::string& text) const
{
    text.clear();
    if (HasOwnRepeatableComment(line)) {
        text = repeatableComments.at(line.address);
        return true;
    }
    if (line.size == 0 || line.isCollapsedLine)
        return false;
    // the places the instruction refers to (a zone without repeatable comments is not looked at)
    bool any = !repeatableComments.empty();
    for (const auto* sibling : siblingZones)
        any = any || !sibling->repeatableComments.empty();
    if (!any)
        return false;
    for (const auto* xref : xrefs.From(labelAddressBase + line.address)) {
        const auto* zone = FindCodeZoneOfAddress(xref->to);
        if (!zone)
            continue;
        const auto comment = zone->repeatableComments.find(xref->to - zone->labelAddressBase);
        if (comment == zone->repeatableComments.end() || text.find(comment->second) != std::string::npos)
            continue;
        if (!text.empty())
            text += " ; ";
        text += comment->second;
    }
    return !text.empty();
}

bool DissasmCodeZone::SetOperandConstant(uint64 address, const std::string& set)
{
    const auto found = operandConstants.find(address);
    std::optional<std::string> before;
    if (found != operandConstants.end())
        before = found->second;
    const std::optional<std::string> after = set.empty() ? std::nullopt : std::optional<std::string>(set);
    if (before == after)
        return false;
    if (after.has_value())
        operandConstants[address] = after.value();
    else
        operandConstants.erase(address);
    DissasmEdit edit;
    edit.kind    = DissasmEdit::Kind::OperandConstant;
    edit.address = address;
    edit.before  = std::move(before);
    edit.after   = after;
    RecordEdit(std::move(edit));
    ResetZoneCaching(); // the lines are drawn again with the name
    return true;
}

bool DissasmCodeZone::SetOperandStructure(uint64 address, const std::string& structure)
{
    const auto found = operandStructures.find(address);
    std::optional<std::string> before;
    if (found != operandStructures.end())
        before = found->second;
    const std::optional<std::string> after = structure.empty() ? std::nullopt : std::optional<std::string>(structure);
    if (before == after)
        return false;
    if (after.has_value())
        operandStructures[address] = after.value();
    else
        operandStructures.erase(address);
    DissasmEdit edit;
    edit.kind    = DissasmEdit::Kind::OperandStructure;
    edit.address = address;
    edit.before  = std::move(before);
    edit.after   = after;
    RecordEdit(std::move(edit));
    ResetZoneCaching(); // the lines are drawn again with the field
    return true;
}

void DissasmCodeZone::RecordUserVariableStructuresEdit(std::map<std::pair<uint64, int32>, std::string> before, uint64 address)
{
    DissasmEdit edit;
    edit.kind             = DissasmEdit::Kind::VariableStructures;
    edit.address          = address;
    edit.structuresBefore = std::move(before);
    edit.structuresAfter  = userVariableStructures;
    RecordEdit(std::move(edit));
}

void DissasmCodeZone::RecordUserDataEdit(std::vector<DissasmInstructionSet::DataRange> before, uint64 address)
{
    DissasmEdit edit;
    edit.kind         = DissasmEdit::Kind::DataRanges;
    edit.address      = address;
    edit.rangesBefore = std::move(before);
    edit.rangesAfter  = userDataRanges;
    RecordEdit(std::move(edit));
}

bool DissasmCodeZone::RenameLabel(uint32 expandedLine, const std::string& currentName, const std::string& newName)
{
    auto& annotations = dissasmType.annotations;
    const auto label  = annotations.find(expandedLine);
    if (label == annotations.end() || IsLocalVariableAnnotation(label->second) || newName.empty())
        return false;
    const uint64 address = label->second.second;
    if (!annotations.add_name_change(currentName, newName, expandedLine))
        return false;
    DissasmEdit edit;
    edit.kind    = DissasmEdit::Kind::LabelName;
    edit.address = address;
    edit.before  = currentName;
    edit.after   = newName;
    RecordEdit(std::move(edit));
    return true;
}

bool DissasmCodeZone::ApplyEdit(const DissasmEdit& edit, bool forward)
{
    const auto& value = forward ? edit.after : edit.before;
    switch (edit.kind) {
    case DissasmEdit::Kind::Comment:
        if (value.has_value())
            userComments.Set(edit.anchor, value.value());
        else
            userComments.Remove(edit.anchor);
        break;
    case DissasmEdit::Kind::LabelName: {
        const auto line = labelLineOfAddress.find(edit.address);
        if (line == labelLineOfAddress.end() || !value.has_value())
            return false;
        const std::string currentName = dissasmType.annotations.find(line->second)->second.first;
        if (currentName != value.value() && !dissasmType.annotations.add_name_change(currentName, value.value(), line->second))
            return false; // another label has this name now
        break;
    }
    case DissasmEdit::Kind::VariableName: {
        const auto function = localVariables.FindFunctionByStart(edit.address);
        const auto variable = function ? function->FindVariable(edit.frameOffset) : nullptr;
        if (!variable || !value.has_value())
            return false;
        if (variable->name != value.value() && function->HasVariableNamed(value.value()))
            return false;
        variable->name = value.value();
        break;
    }
    case DissasmEdit::Kind::DecimalOperand: {
        const uint32 mask = GetDecimalOperandsMask(edit.address) ^ (1u << edit.numberIndex); // a switch: the same in both directions
        if (mask == 0)
            decimalOperands.erase(edit.address);
        else
            decimalOperands[edit.address] = mask;
        break;
    }
    case DissasmEdit::Kind::DataRanges:
        userDataRanges = forward ? edit.rangesAfter : edit.rangesBefore; // the caller analyzes the zone again (DissasmEditPlace::reanalyze)
        break;
    case DissasmEdit::Kind::UserFunctions:
        userFunctions = forward ? edit.functionsAfter : edit.functionsBefore; // the caller analyzes the zone again
        break;
    case DissasmEdit::Kind::VariableStructures:
        userVariableStructures = forward ? edit.structuresAfter : edit.structuresBefore; // the caller analyzes the zone again
        break;
    case DissasmEdit::Kind::UserPrototypes:
        userPrototypes = forward ? edit.prototypesAfter : edit.prototypesBefore; // the caller analyzes the zone again
        break;
    case DissasmEdit::Kind::RepeatableComment: {
        const auto& text = forward ? edit.after : edit.before;
        if (text.has_value())
            repeatableComments[edit.address] = text.value();
        else
            repeatableComments.erase(edit.address);
        break;
    }
    case DissasmEdit::Kind::OperandStructure: {
        const auto& structure = forward ? edit.after : edit.before;
        if (structure.has_value())
            operandStructures[edit.address] = structure.value();
        else
            operandStructures.erase(edit.address);
        break;
    }
    case DissasmEdit::Kind::OperandConstant: {
        const auto& set = forward ? edit.after : edit.before;
        if (set.has_value())
            operandConstants[edit.address] = set.value();
        else
            operandConstants.erase(edit.address);
        break;
    }
    case DissasmEdit::Kind::AddZone:
    case DissasmEdit::Kind::RemoveZone: {
        const bool add = (edit.kind == DissasmEdit::Kind::AddZone) == forward;
        if (add) {
            if (!CanPlaceZone(edit.zone))
                return false;
            InsertZone(edit.zone);
        } else {
            const auto zone = std::find_if(collapsibleZones.begin(), collapsibleZones.end(), [&edit](const DissasmCollapsibleZone& item) {
                return item.start == edit.zone.start && item.end == edit.zone.end;
            });
            if (zone == collapsibleZones.end())
                return false;
            collapsibleZones.erase(zone);
        }
        break;
    }
    }
    ResetZoneCaching();
    return true;
}

static DissasmEditPlace GetEditPlace(const DissasmEdit& edit)
{
    DissasmEditPlace place;
    if (edit.kind == DissasmEdit::Kind::AddZone || edit.kind == DissasmEdit::Kind::RemoveZone)
        place.expandedLine = edit.zone.start;
    else if (edit.kind == DissasmEdit::Kind::Comment)
        place.address = edit.anchor.address;
    else
        place.address = edit.address;
    place.onLabel   = edit.kind == DissasmEdit::Kind::LabelName || edit.kind == DissasmEdit::Kind::VariableName ||
                    (edit.kind == DissasmEdit::Kind::Comment && edit.anchor.kind != DissasmCommentAnchor::Kind::Instruction);
    place.reanalyze = edit.kind == DissasmEdit::Kind::DataRanges || edit.kind == DissasmEdit::Kind::UserFunctions ||
                      edit.kind == DissasmEdit::Kind::VariableStructures || edit.kind == DissasmEdit::Kind::UserPrototypes;
    return place;
}

std::optional<DissasmEditPlace> DissasmCodeZone::UndoEdit()
{
    if (undoEdits.empty())
        return {};
    DissasmEdit edit = std::move(undoEdits.back());
    undoEdits.pop_back();
    if (!ApplyEdit(edit, false))
        return {}; // its place has changed: it is dropped
    const auto place = GetEditPlace(edit);
    redoEdits.push_back(std::move(edit));
    return place;
}

std::optional<DissasmEditPlace> DissasmCodeZone::RedoEdit()
{
    if (redoEdits.empty())
        return {};
    DissasmEdit edit = std::move(redoEdits.back());
    redoEdits.pop_back();
    if (!ApplyEdit(edit, true))
        return {};
    const auto place = GetEditPlace(edit);
    undoEdits.push_back(std::move(edit));
    return place;
}

bool DissasmCodeZone::AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd)
{
    if (zoneLineStart >= zoneLineEnd)
        return false;
    const auto first = DisplayToExpanded(zoneLineStart);
    const auto last  = DisplayToExpanded(zoneLineEnd - 1u);
    if (!first.has_value() || !last.has_value())
        return false;
    DissasmCollapsibleZone zone;
    zone.start = first->expandedLine;
    zone.end   = last->collapsedZone ? last->collapsedZone->end : last->expandedLine + 1u; // a collapsed line: its whole zone
    LocalString<128> zoneName;
    zoneName.SetFormat("Zone-IndexStart %u -IndexEnd %u", zoneLineStart, zoneLineEnd);
    zone.name = zoneName.GetText();
    if (!CanPlaceZone(zone))
        return false;
    DissasmEdit edit;
    edit.kind = DissasmEdit::Kind::AddZone;
    edit.zone = zone;
    InsertZone(std::move(zone));
    RecordEdit(std::move(edit));
    ResetZoneCaching();
    return true;
}

bool DissasmCodeZone::CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference)
{
    difference       = 0;
    const auto place = DisplayToExpanded(zoneLine);
    if (!place.has_value())
        return false;
    DissasmCollapsibleZone* zone = place->collapsedZone ? &collapsibleZones[place->collapsedZone - collapsibleZones.data()]
                                                        : FindInnermostZone(place->expandedLine);
    if (!zone)
        return false;
    switch (collapse) {
    case CollapseExpandType::Collapse:
        if (zone->isCollapsed)
            return false;
        zone->isCollapsed = true;
        break;
    case CollapseExpandType::Expand:
        if (!zone->isCollapsed)
            return false;
        zone->isCollapsed = false;
        break;
    case CollapseExpandType::NegateCurrentState:
        zone->isCollapsed = !zone->isCollapsed;
        break;
    }
    ResetZoneCaching();
    difference = static_cast<int32>(GetDisplayLinesCount() + 1u); // the new size of the zone: its lines and the title
    return true;
}

bool DissasmCodeZone::RemoveCollapsibleZone(uint32 zoneLine)
{
    const auto place = DisplayToExpanded(zoneLine);
    if (!place.has_value() || place->collapsedZone)
        return false; // a collapsed zone is expanded before it is removed
    const auto zone = FindInnermostZone(place->expandedLine);
    if (!zone)
        return false;
    DissasmEdit edit;
    edit.kind = DissasmEdit::Kind::RemoveZone;
    edit.zone = *zone;
    collapsibleZones.erase(collapsibleZones.begin() + (zone - collapsibleZones.data()));
    RecordEdit(std::move(edit));
    ResetZoneCaching();
    return true;
}

DissasmAsmPreCacheLine DissasmCodeZone::BuildExpandedLine(uint32 expandedLine, uint32 displayLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params)
{
    DissasmAsmPreCacheLine line{};
    line.currentLine      = displayLine;
    const auto annotation = dissasmType.annotations.find(expandedLine);
    if (annotation != dissasmType.annotations.end()) {
        line.size = 0;
        if (IsLocalVariableAnnotation(annotation->second)) {
            const uint64 functionStart = GetLocalVariableAnnotationFunction(annotation->second.second);
            const int32 frameOffset    = GetLocalVariableAnnotationOffset(annotation->second.second);
            const auto function        = localVariables.FindFunctionByStart(functionStart);
            const auto variable        = function ? function->FindVariable(frameOffset) : nullptr;
            line.address               = functionStart;
            std::string text           = "<unknown local variable>"; // the lines and the variables are always updated together
            uint32 nameSize            = 0;
            if (variable) {
                FormatLocalVariableDefinition(*variable, text, nameSize);
                line.autoComment = FormatLocalVariableOrigin(*variable); // HKEY, phkResult of RegOpenKeyExW
                line.localVariableKind     = DissasmAsmPreCacheLine::LocalVariableKind::Definition;
                line.localVariableFunction = functionStart;
                line.localVariableOffset   = frameOffset;
                line.localVariableNameSize = nameSize;
            }
            line.op_str      = portable_strdup(text.c_str());
            line.op_str_size = static_cast<uint32>(text.size());
            return line;
        }
        line.address = annotation->second.second; // a label: its name, the address of its instruction
        line.label   = annotation->second.first;
        line.SetMnemonic(line.label);
        line.autoComment = FormatXrefsSummary(line.address); // who uses it
        if (const auto attributes = FormatFunctionAttributes(line.address); !attributes.empty()) // IDA: ; Attributes: noreturn
            line.autoComment = "Attributes: " + attributes + (line.autoComment.empty() ? std::string() : "; " + line.autoComment);
        if (const auto* prototype = FindUserPrototype(line.address)) // IDA: the prototype of the function above it (Y)
            line.autoComment = std::string(prototype->prototype) + (line.autoComment.empty() ? std::string() : "; " + line.autoComment);
        else if (const auto* inferred = FindInferredPrototype(line.address)) // inferred from what it passes to the APIs
            line.autoComment = "inferred: " + std::string(inferred->prototype) + (line.autoComment.empty() ? std::string() : "; " + line.autoComment);
        if (const auto* chunk = FindChunkContaining(line.address); chunk && chunk->start == line.address) { // IDA: START OF FUNCTION CHUNK FOR
            std::string function = GetLabelNameAt(chunk->function);
            if (function.empty())
                function = GetLabelName("sub_", chunk->function);
            line.autoComment = "Chunk of " + function + (line.autoComment.empty() ? std::string() : "; " + line.autoComment);
        }
        return line;
    }

    const uint32 instructionIndex = ExpandedToInstructionIndex(expandedLine);
    DissasmInsnExtractLineParams localParams{};
    DissasmInsnExtractLineParams* paramsPtr = params ? params : &localParams;
    paramsPtr->asmLine                      = instructionIndex;
    paramsPtr->obj                          = obj;
    paramsPtr->actualLine                   = displayLine;
    paramsPtr->zone                         = this;
    [[maybe_unused]] const bool decoded     = line.TryGetDataFromInsn(*paramsPtr);
    assert(decoded);
    if (!exceptionMarks.empty()) // x64 SEH: the __try scopes (__try { // __except at loc_X)
        if (auto marks = FormatExceptionMarks(line.address); !marks.empty()) {
            line.autoComment     = line.autoComment.empty() ? std::move(marks) : marks + "; " + line.autoComment;
            line.constantComment = false; // the comment is not only the constant (the value of an argument) any more
        }
    if (!chunkEnds.empty()) // IDA: END OF FUNCTION CHUNK FOR sub_X
        if (const auto chunkEnd = chunkEnds.find(line.address); chunkEnd != chunkEnds.end()) {
            std::string function = GetLabelNameAt(chunkEnd->second);
            if (function.empty())
                function = GetLabelName("sub_", chunkEnd->second);
            const std::string mark = "end of chunk of " + function;
            line.autoComment       = line.autoComment.empty() ? mark : line.autoComment + "; " + mark;
            line.constantComment   = false;
        }
    lastDrawnLine = instructionIndex;
    return line;
}

DissasmAsmPreCacheLine DissasmCodeZone::GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params)
{
    if (!CanReachAsmLines())
        return {}; // not an initialized x86/x64 zone: there are no lines to decode
    const auto place = DisplayToExpanded(currentLine);
    if (!place.has_value())
        return {};

    auto line = BuildExpandedLine(place->expandedLine, currentLine, obj, params);
    if (place->collapsedZone) {
        // the line of a collapsed zone: its name, the address (and the anchor) of its first line
        const auto& zone = *place->collapsedZone;
        if (line.op_str)
            free(line.op_str);
        line.op_str                = portable_strdup(zone.name.c_str());
        line.op_str_size           = static_cast<uint32>(zone.name.size());
        line.localVariableKind     = DissasmAsmPreCacheLine::LocalVariableKind::None;
        line.localVariableNameSize = 0;
        line.flags                 = 0;
        line.branchTarget.reset();
        line.mapping = nullptr;
        line.autoComment.clear();
        line.SetMnemonic("collapsed");
        line.isCollapsedLine = true;
        line.shouldAddButton = true;
        line.isZoneCollapsed = true;
    } else if (FindInnermostZoneStartingAt(place->expandedLine)) {
        line.shouldAddButton = true; // the first line of an expanded zone
        line.isZoneCollapsed = false;
    }
    return line;
}

std::vector<DissasmCodeZone::CollapsibleZoneAnchors> DissasmCodeZone::GetCollapsibleZoneAnchors()
{
    std::vector<CollapsibleZoneAnchors> result;
    if (!CanReachAsmLines() || !zoneObject.IsValid())
        return result;
    result.reserve(collapsibleZones.size());
    const auto zones = collapsibleZones; // building the lines does not change the zones, a copy keeps it obvious
    for (const auto& zone : zones) {
        const auto first = BuildExpandedLine(zone.start, 0, zoneObject, nullptr);
        const auto last  = BuildExpandedLine(zone.end - 1u, 0, zoneObject, nullptr);
        result.push_back({ GetLineAnchor(first), GetLineAnchor(last), zone.name, zone.isCollapsed });
    }
    offsetCacheMaxLine = 0; // the decoding position moved
    ResetZoneCaching();
    return result;
}

std::optional<uint32> DissasmCodeZone::GetExpandedLineOfAnchor(const DissasmCommentAnchor& anchor)
{
    if (anchor.kind != DissasmCommentAnchor::Kind::Instruction) {
        const bool isVariable = anchor.kind == DissasmCommentAnchor::Kind::Variable;
        const uint64 value    = isVariable ? PackLocalVariableAnnotation(anchor.address, anchor.frameOffset) : anchor.address;
        for (const auto& [line, details] : dissasmType.annotations.mappings)
            if (IsLocalVariableAnnotation(details) == isVariable && details.second == value)
                return line;
        return {};
    }
    // an instruction: the instruction that starts at the address
    if (cachedCodeOffsets.empty() || !zoneObject.IsValid() || !GetFileOffsetOfAddress(anchor.address).has_value())
        return {};
    uint32 instructionIndex = 0;
    cs_insn* insn           = GetCurrentInstructionByOffset(cachedCodeOffsets[0].offset + anchor.address, this, zoneObject, instructionIndex);
    if (!insn)
        return {};
    const bool startsThere = insn->address == anchor.address;
    cs_free(insn, 1);
    if (!startsThere || instructionIndex >= asmLinesCount)
        return {};
    return InstructionIndexToExpanded(instructionIndex);
}

bool DissasmCodeZone::ApplyCollapsibleZoneAnchors(const std::vector<CollapsibleZoneAnchors>& zones)
{
    bool linesChanged = false;
    for (const auto& anchors : zones) {
        const auto first = GetExpandedLineOfAnchor(anchors.first);
        const auto last  = GetExpandedLineOfAnchor(anchors.last);
        if (!first.has_value() || !last.has_value() || first.value() > last.value())
            continue; // this analysis does not have its lines
        DissasmCollapsibleZone zone{ first.value(), last.value() + 1u, anchors.name, anchors.isCollapsed };
        if (!CanPlaceZone(zone))
            continue;
        linesChanged |= zone.isCollapsed;
        InsertZone(std::move(zone));
    }
    offsetCacheMaxLine = 0;
    ResetZoneCaching();
    return linesChanged;
}

uint64 DissasmCodeZone::GetCodeSize() const
{
    if (cachedCodeOffsets.empty())
        return 0;
    const uint64 codeStart = cachedCodeOffsets[0].offset;
    if (zoneDetails.size > UINT64_MAX - zoneDetails.startingZonePoint)
        return 0;
    const uint64 zoneEnd = zoneDetails.startingZonePoint + zoneDetails.size;
    if (codeStart < zoneDetails.startingZonePoint || codeStart >= zoneEnd)
        return 0;
    return zoneEnd - codeStart;
}

std::optional<uint64> DissasmCodeZone::GetFileOffsetOfAddress(uint64 address) const
{
    if (address >= GetCodeSize()) // GetCodeSize is 0 for an invalid zone, cachedCodeOffsets[0].offset + address can not overflow
        return {};
    return cachedCodeOffsets[0].offset + address;
}

bool DissasmCodeZone::FetchCodeWindow(Reference<GView::Object> obj, uint64 relativeStart, uint64 relativeEnd)
{
    relativeEnd = std::min<uint64>(relativeEnd, GetCodeSize());
    if (relativeStart >= relativeEnd)
        return false;
    // windows are small (the distance between two cached offsets): fetching again is O(1) while the bytes are cached and it never
    // decodes stale bytes after another reader (string preview, other views) refilled the data cache
    const uint32 requested = static_cast<uint32>(std::min<uint64>(relativeEnd - relativeStart, DISSASM_MAX_CODE_WINDOW_SIZE));
    lastData               = GetZoneBytes(obj, cachedCodeOffsets[0].offset + relativeStart, requested);
    if (!lastData.IsValid() || lastData.GetLength() == 0) {
        asmData = nullptr;
        asmSize = 0;
        return false;
    }
    asmData    = lastData.GetData();
    asmSize    = std::min<uint64>(lastData.GetLength(), requested);
    asmAddress = relativeStart;
    return true;
}

bool DissasmCodeZone::GetLocalVariableFromLine(uint32 line, Reference<GView::Object> obj, uint64& functionStart, int32& frameOffset)
{
    if (localVariables.Empty())
        return false;
    // no settings / asm data: the line is decoded without side effects (no string preview or call comments)
    const auto asmLine = GetCurrentAsmLine(line, obj, nullptr);
    if (asmLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::None)
        return false;
    functionStart = asmLine.localVariableFunction;
    frameOffset   = asmLine.localVariableOffset;
    return true;
}

GStatus DissasmCodeZone::RenameLocalVariable(uint64 functionStart, int32 frameOffset, std::string_view newName)
{
    if (!IsValidLocalVariableName(newName)) {
        LocalString<160> message;
        message.SetFormat(
              "Invalid name! Use letters, digits and '_', '@', '$', '?', '.' (it can not start with a digit or '.'), maximum %u characters.",
              DISSASM_MAX_LOCAL_VARIABLE_NAME_SIZE);
        return GStatus::Error(message.GetText());
    }
    auto function = localVariables.FindFunctionByStart(functionStart);
    auto variable = function ? function->FindVariable(frameOffset) : nullptr;
    if (!variable)
        return GStatus::Error("Failed to find the local variable!");
    if (variable->name == newName)
        return GStatus::Ok();
    if (function->HasVariableNamed(newName))
        return GStatus::Error("This function already has a variable with this name!");
    DissasmEdit edit;
    edit.kind        = DissasmEdit::Kind::VariableName;
    edit.address     = functionStart;
    edit.frameOffset = frameOffset;
    edit.before      = variable->name;
    edit.after       = std::string(newName);
    variable->name   = newName;
    RecordEdit(std::move(edit));
    return GStatus::Ok();
}

GStatus DissasmCodeZone::RemoveLocalVariable(uint64 functionStart, int32 frameOffset, bool& lineRemoved)
{
    lineRemoved   = false;
    auto function = localVariables.FindFunctionByStart(functionStart);
    auto variable = function ? function->FindVariable(frameOffset) : nullptr;
    if (!variable)
        return GStatus::Error("Failed to find the local variable!");
    const auto annotationValue = PackLocalVariableAnnotation(functionStart, frameOffset);
    uint32 variableLine        = UINT32_MAX;
    for (const auto& [line, details] : dissasmType.annotations.mappings) {
        if (IsLocalVariableAnnotation(details) && details.second == annotationValue) {
            variableLine = line;
            break;
        }
    }

    function->variables.erase(function->variables.begin() + (variable - function->variables.data()));
    if (function->variables.empty())
        localVariables.functions.erase(localVariables.functions.begin() + (function - localVariables.functions.data()));
    removedLocalVariables.emplace(functionStart, frameOffset);

    if (variableLine != UINT32_MAX) {
        RemoveRootAnnotationLines({ variableLine });
        lineRemoved = true;
        ClearEditHistory(); // the lines of the zones of the recorded edits moved: they can not be undone any more
    }
    return GStatus::Ok();
}

void DissasmCodeZone::RemoveRootAnnotationLines(const std::vector<uint32>& sortedLines)
{
    if (sortedLines.empty())
        return;
    assert(std::is_sorted(sortedLines.begin(), sortedLines.end()));

    // every line after a removed one moves up by the number of removed lines placed before it
    auto removedBefore = [&sortedLines](uint32 line) {
        return static_cast<uint32>(std::lower_bound(sortedLines.begin(), sortedLines.end(), line) - sortedLines.begin());
    };
    auto isRemoved = [&sortedLines](uint32 line) { return std::binary_search(sortedLines.begin(), sortedLines.end(), line); };

    auto& annotations = dissasmType.annotations;
    AnnotationContainer::AnnotationMap shiftedAnnotations;
    for (auto& [line, details] : annotations.mappings) {
        if (isRemoved(line))
            continue;
        shiftedAnnotations.emplace_hint(shiftedAnnotations.end(), line - removedBefore(line), std::move(details));
    }
    annotations.mappings = std::move(shiftedAnnotations);

    // comments are keyed by line - 1 (line 0 lives at UINT32_MAX)
    decltype(dissasmType.commentsData.comments) shiftedComments;
    for (auto& [key, text] : dissasmType.commentsData.comments) {
        const uint32 line = key + 1u;
        if (isRemoved(line))
            continue;
        shiftedComments.insert({ key - removedBefore(line), std::move(text) });
    }
    dissasmType.commentsData.comments = std::move(shiftedComments);

    // the collapsible zones keep their lines: their ranges move with them (an emptied zone, or a zone that became the copy of another
    // one, is removed)
    std::vector<DissasmCollapsibleZone> zones;
    zones.reserve(collapsibleZones.size());
    for (auto& zone : collapsibleZones) {
        zone.start -= removedBefore(zone.start);
        zone.end -= removedBefore(zone.end);
        const bool isDuplicate = !zones.empty() && zones.back().start == zone.start && zones.back().end == zone.end;
        if (zone.start < zone.end && !isDuplicate)
            zones.push_back(std::move(zone));
    }
    collapsibleZones = std::move(zones);
    RebuildLineIndex();
}

void DissasmCodeZone::ToggleDecimalOperand(uint64 address, uint32 numberIndex)
{
    if (numberIndex >= 32u)
        return;
    const uint32 mask = GetDecimalOperandsMask(address) ^ (1u << numberIndex);
    if (mask == 0)
        decimalOperands.erase(address);
    else
        decimalOperands[address] = mask;
    DissasmEdit edit;
    edit.kind        = DissasmEdit::Kind::DecimalOperand;
    edit.address     = address;
    edit.numberIndex = numberIndex;
    RecordEdit(std::move(edit));
}

DissasmBandCell GView::View::DissasmViewer::GetDissasmBandCellOfCategory(uint32 category)
{
    switch (category) {
    case API_INJECTION:
        return BAND_INJECTION;
    case API_ANTIDEBUG:
        return BAND_ANTIDEBUG;
    case API_PROCESS:
        return BAND_PROCESS;
    case API_NETWORK:
        return BAND_NETWORK;
    case API_CRYPTO:
        return BAND_CRYPTO;
    case API_SERVICE:
        return BAND_SERVICE;
    case API_REGISTRY:
        return BAND_REGISTRY;
    case API_LOADING:
        return BAND_LOADING;
    case API_FILE:
        return BAND_FILE;
    default:
        return BAND_FUNCTION;
    }
}

std::vector<uint8> GView::View::DissasmViewer::BuildDissasmNavigationBand(const std::vector<const ParseZone*>& zones, uint64 totalLines, uint32 rows)
{
    std::vector<uint8> band(rows, BAND_EMPTY);
    if (rows == 0 || totalLines == 0)
        return band;
    const auto rowOf = [&](uint64 line) { return static_cast<uint32>(std::min<uint64>(rows - 1u, line * rows / totalLines)); };
    const auto mark  = [&](uint64 from, uint64 to, uint8 cell) { // the lines [from, to)
        if (to <= from)
            return;
        for (uint32 row = rowOf(from), last = rowOf(to - 1); row <= last; row++)
            band[row] = std::max(band[row], cell);
    };
    for (const auto* zone : zones) {
        if (!zone || zone->endingLineIndex <= zone->startLineIndex)
            continue;
        const auto* code = zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone ? static_cast<const DissasmCodeZone*>(zone) : nullptr;
        if (!code || code->zoneDetails.isData) {
            mark(zone->startLineIndex, zone->endingLineIndex, BAND_DATA);
            continue;
        }
        mark(zone->startLineIndex, zone->endingLineIndex, BAND_CODE);
        if (code->isCollapsed || !code->isInit)
            continue;
        // a function from its label to the label of the next one (a hidden label: inside a collapsed zone, the function goes on)
        const uint64 linesStart = zone->startLineIndex + 2ull; // the title and the header of the columns
        std::optional<uint64> previous;
        uint8 previousCell = BAND_FUNCTION;
        for (size_t index = 0; index < code->functionStarts.size(); index++) {
            const auto line = code->GetLabelDisplayLine(code->functionStarts[index]);
            if (!line.has_value() || (previous.has_value() && linesStart + line.value() < previous.value()))
                continue;
            const uint64 absolute = linesStart + line.value();
            if (previous.has_value())
                mark(previous.value(), absolute, previousCell);
            previous               = absolute;
            const uint32 categories = index < code->functionApiCategories.size() ? code->functionApiCategories[index] : 0u;
            previousCell           = GetDissasmBandCellOfCategory(GetMainApiCategory(categories));
        }
        if (previous.has_value())
            mark(previous.value(), std::max<uint64>(previous.value() + 1, zone->endingLineIndex), previousCell);
    }
    // the bookmarks, once the cells are known (the flag is above every cell)
    for (const auto* zone : zones) {
        const auto* code = zone && zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone ? static_cast<const DissasmCodeZone*>(zone) : nullptr;
        if (!code || code->isCollapsed || !code->isInit || code->bookmarks.empty())
            continue;
        for (const auto& [address, description] : code->bookmarks) {
            auto line = code->GetLabelDisplayLine(address);
            if (!line.has_value())
                if (const auto function = code->GetFunctionContaining(address); function.has_value())
                    line = code->GetLabelDisplayLine(function.value());
            if (line.has_value())
                band[rowOf(zone->startLineIndex + 2ull + line.value())] |= BAND_BOOKMARK;
        }
    }
    return band;
}
