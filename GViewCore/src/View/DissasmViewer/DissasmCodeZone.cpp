#include "DissasmCodeZone.hpp"
#include "DissasmAnnotations.hpp"
#include "DissasmFunctionUtils.hpp"
#include "x86_x64/DissasmX86LocalVariables.hpp"
#include "x86_x64/X86InstructionInfo.hpp"
#include "x86_x64/X86SwitchTables.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <set>
#include <map>

using namespace GView::View::DissasmViewer;
using GView::Utils::GStatus;

constexpr uint64 DISSASM_MAX_ANALYZED_FUNCTION_SIZE = 0x1000000; // 16 MB, larger functions are analyzed only partially

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
    std::unordered_map<std::string, uint64> localFunctionNames; // the names of the plugin of the functions of the zone -> relative start
    std::unordered_set<uint64> noReturnStarts; // relative starts of the functions that do not return: their names, then InferNoReturnFunctions
    std::unordered_set<uint64> userReturns;    // the functions the user says return (USER_FUNCTION_RETURNS): never noreturn
    std::unordered_set<uint64> noReturnCalls;  // relative addresses of the calls to them
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

    // the results, given to the zone by Commit
    DissasmXrefs xrefs;
    std::unordered_map<uint64, std::string> thunkImports;
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
    AnnotationContainer annotations;
    std::vector<DissasmFunctionFrame> frames;
    std::vector<uint64> functionEnds; // ComputeFunctionEnds
    std::vector<DissasmFunctionChunk> chunks; // DetectFunctionChunks
    size_t labelIndex = 0; // the next label placed on its line
    uint32 extraLines = 0;

    DissasmDeepScan(DissasmCodeZone* zone, const DissasmCodeZoneInitData& initData, int internalArchitecture, uint32 asmLines)
        : zone(zone), obj(initData.obj), internalArchitecture(internalArchitecture),
          detectLocalVariables(initData.enableLocalVariablesDetection),
          isFileAddress(initData.isFileAddress), functionEntries(initData.functionEntries), findImport(initData.findImport),
          addressToFileOffset(initData.addressToFileOffset), codeStart(zone->cachedCodeOffsets[0].offset), codeSize(zone->GetCodeSize()),
          lines(asmLines), linesToDecode(asmLines), is64(zone->Is64BitCode()), addressMask(is64 ? UINT64_MAX : 0xFFFFFFFFull),
          labelBase(zone->labelAddressBase), arch(zone->GetArch()), imageBase(initData.imageBase), instructionSet(zone->instructionSet),
          walker(initData.obj, codeStart, codeSize, 0), prologueDetector(is64),
          switchDetector(is64, zone->labelAddressBase, initData.imageBase), adrpTracker(zone->labelAddressBase),
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
        xrefs = DissasmXrefs{};
        thunkImports.clear();
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
        returnedAddress.reset();
        ebxValue.reset();
        functionEbx.reset();
        pendingPopEbx.reset();
        blockStarts.assign(blockStarts.size(), false);
        tableEntries.clear();
        pendingRanges.clear();
        paddingRuns.clear();
        previousFallsThrough = previousIsCall = false;
        previousAddress = 0;
        flowRecords.clear();
        localImports.clear();
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
            if (prologueStart.has_value())
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
                // an import stub (j_Name): adrp x16, page; ldr x16, [x16, #off]; br x16 from a block start
                if (pair->throughSlot && flow == X86Flow::Jump && pair->sequenceAtBlockStart && findImport) {
                    const auto import = findImport(pairOperands);
                    if (import && import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                        thunks.emplace_back(codeStart + pair->sequenceStart, import->name);
                        thunkImports[pair->sequenceStart] = import->name;
                        AddFunctionStart(codeStart + pair->sequenceStart);
                        if (IsNoReturnFunctionName(import->name))
                            noReturnStarts.insert(pair->sequenceStart);
                    }
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
                if (!targets.empty() && table->entrySize > 0) // tbb / tbh / ldr pc, [pc, rN, lsl #2]: the table follows the jump
                    AddTable(insn->address, from, labelBase + table->table, table->entrySize, targets, insnArch == DissasmArch::Thumb);
            }
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
        if (isBlockStart && insn->address < blockStarts.size() && insn->id != X86_INS_INVALID && insn->id != X86_INS_INT3 && insn->id != X86_INS_NOP)
            blockStarts[insn->address] = true; // not the padding (int3, nop, align, db)
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
            }
        }

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
    void ComputeFunctionEnds()
    {
        constexpr uint32 MAX_PATH_STEPS = 4096;
        functionEnds.assign(functionStarts.size(), 0);
        const auto switchCases = SwitchCases();
        std::vector<uint64> seeds = addressTakenTargets; // sorted by FinishSweep
        seeds.insert(seeds.end(), dataPointerTargets.begin(), dataPointerTargets.end());
        std::sort(seeds.begin(), seeds.end());
        seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
        std::vector<size_t> pending;
        std::unordered_set<size_t> seen;
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            const uint64 limit = std::min<uint64>(index + 1 < functionStarts.size() ? functionStarts[index + 1] : codeSize, codeSize);
            const auto inside  = [start, limit](uint64 target) { return target >= start && target < limit; };
            uint64 end         = start;
            uint32 steps       = 0;
            pending.assign(1, FirstRecordAt(start));
            for (auto seed = std::upper_bound(seeds.begin(), seeds.end(), start); seed != seeds.end() && *seed < limit; ++seed)
                pending.push_back(FirstRecordAt(*seed));
            seen.clear();
            while (!pending.empty() && end < limit) {
                size_t position = pending.back();
                pending.pop_back();
                for (bool walking = true; walking; position++) {
                    if (position >= flowRecords.size() || flowRecords[position].address >= limit || ++steps > MAX_PATH_STEPS) {
                        end = limit; // into the next function
                        break;
                    }
                    if (!seen.insert(position).second)
                        break;
                    const auto& record = flowRecords[position];
                    if (record.kind == FlowKind::Unknown) {
                        // padding the code reaches (6f: instructions after the sweep, an align line in it) goes on; the other padding / the
                        // bytes after the code: the function ends before them
                        if (std::binary_search(instructionSet.reachablePadding.begin(), instructionSet.reachablePadding.end(), record.address))
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
                        if (record.target != NO_TARGET && inside(record.target))
                            pending.push_back(FirstRecordAt(record.target));
                        break;
                    case FlowKind::Jump:
                        walking = false;
                        if (const auto cases = switchCases.find(record.address); cases != switchCases.end()) {
                            for (const uint64 target : cases->second)
                                if (inside(target))
                                    pending.push_back(FirstRecordAt(target));
                        } else if (record.target != NO_TARGET && inside(record.target))
                            pending.push_back(FirstRecordAt(record.target));
                        break;
                    default:
                        break;
                    }
                }
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
        if (functionStarts.size() < 2 || functionEnds.size() != functionStarts.size())
            return;
        const auto containing = [this](uint64 address) -> std::optional<size_t> {
            const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), address);
            return next == functionStarts.begin() ? std::nullopt : std::optional<size_t>(static_cast<size_t>(next - functionStarts.begin()) - 1);
        };
        std::unordered_map<size_t, size_t> parentOf; // index of a chunk -> index of its function
        for (size_t index = 0; index < functionStarts.size(); index++) {
            const uint64 start = functionStarts[index];
            if ((zone->zoneDetails.HasEntryPoint() && codeStart + start == zone->zoneDetails.entryPoint) ||
                (functionEntries && functionEntries->contains(codeStart + start)) || thunkImports.contains(start))
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
            // its code jumps back into the function
            const uint64 parentStart = functionStarts[parent.value()];
            const uint64 parentLimit = parent.value() + 1 < functionStarts.size() ? functionStarts[parent.value() + 1] : codeSize;
            bool jumpsBack           = false;
            for (size_t position = FirstRecordAt(start); position < flowRecords.size() && flowRecords[position].address < functionEnds[index] && !jumpsBack; position++) {
                const auto& record = flowRecords[position];
                jumpsBack = (record.kind == FlowKind::Jump || record.kind == FlowKind::ConditionalJump) && record.target != NO_TARGET &&
                            record.target >= parentStart && record.target < parentLimit;
            }
            if (jumpsBack)
                parentOf[index] = parent.value();
        }
        if (parentOf.empty())
            return;
        // a chunk of a chunk belongs to the function at the end of the chain
        for (const auto& [index, parent] : parentOf) {
            size_t root = parent;
            for (size_t steps = 0; parentOf.contains(root) && steps < parentOf.size(); steps++)
                root = parentOf.at(root);
            if (parentOf.contains(root))
                continue; // a cycle: none of them is a function's
            chunks.push_back({ functionStarts[index], functionEnds[index], functionStarts[root] });
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
        // (not a case of a switch, an absolute jump table of GCC in .rodata; not the target of a conditional jump, inside a function)
        AddDataZonePointerTargets();
        if (!addressTakenTargets.empty()) {
            std::unordered_set<uint64> insideFunctions;
            for (const auto& xref : xrefs.byTarget)
                if ((xref.kind == DissasmXrefKind::Switch || xref.kind == DissasmXrefKind::ConditionalJump) && xref.to >= labelBase)
                    insideFunctions.insert(xref.to - labelBase);
            std::sort(addressTakenTargets.begin(), addressTakenTargets.end());
            addressTakenTargets.erase(std::unique(addressTakenTargets.begin(), addressTakenTargets.end()), addressTakenTargets.end());
            for (const uint64 target : addressTakenTargets)
                if (target < blockStarts.size() && blockStarts[target] && !insideFunctions.contains(target) && LooksLikeCode(target))
                    AddFunctionStart(codeStart + target);
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
        }

        // local variables: a dedicated handle with the instruction details (operands, registers access) enabled
        if (detectLocalVariables) {
            hasDetailHandle = cs_open(zone->capstoneArch, static_cast<cs_mode>(internalArchitecture), &detailHandle) == CS_ERR_OK;
            if (hasDetailHandle && cs_option(detailHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
                cs_close(&detailHandle);
                hasDetailHandle = false;
            }
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

    // 32 bit: a function of the zone that builds the ebp frame of its caller (MSVC __SEH_prolog4 / __EH_prolog3 / _EH_prolog): it stores
    // ebp in the stack (mov [esp + 0x10], ebp / mov [eax], ebp), points ebp into the stack (lea ebp, [esp + 0x10] / mov ebp, eax) and
    // returns without restoring it
    bool IsFrameHelper(uint64 target)
    {
        constexpr uint32 MAX_HELPER_INSTRUCTIONS = 48;
        const auto known                         = frameHelpers.find(target);
        if (known != frameHelpers.end())
            return known->second;
        bool storesFrame = false, setsFrame = false, helper = false;
        const auto helperData = target < codeSize ? obj->GetData().Get(codeStart + target, static_cast<uint32>(std::min<uint64>(codeSize - target, 0x200)), false)
                                                  : BufferView{};
        cs_insn* helperInsn = helperData.IsValid() ? cs_malloc(detailHandle) : nullptr;
        if (helperInsn) {
            const uint8* data = helperData.GetData();
            size_t size       = helperData.GetLength();
            uint64 address    = target;
            for (uint32 decoded = 0; decoded < MAX_HELPER_INSTRUCTIONS && cs_disasm_iter(detailHandle, &data, &size, &address, helperInsn); decoded++) {
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
                    if (writesFrame || helperInsn->id == X86_INS_CALL || helperInsn->id == X86_INS_JMP || cs_insn_group(detailHandle, helperInsn, CS_GRP_JUMP))
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
        const auto functionData  = obj->GetData().Get(codeStart + relativeAddress, static_cast<uint32>(bytesToRead), false);
        if (!functionData.IsValid())
            return;

        DissasmFunctionFrame frame{};
        const auto functionArch = zone->GetArchAt(relativeAddress);
        bool analyzed           = false;
        if (functionArch == DissasmArch::Arm64)
            analyzed = AnalyzeArm64FunctionFrame(
                  detailHandle, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, frame, [this](const cs_insn& call) {
                      return noReturnCalls.contains(call.address);
                  });
        else if (functionArch == DissasmArch::Arm || functionArch == DissasmArch::Thumb)
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
                  [this](const cs_insn& call) { return noReturnCalls.contains(call.address); });
            if (!analyzed) // no frame register (MSVC x64, x86 FPO / GCC -O2): the slots through the stack pointer
                analyzed = AnalyzeX86StackFrame(
                      detailHandle,
                      functionData.GetData(),
                      functionData.GetLength(),
                      relativeAddress,
                      limit,
                      is64,
                      frame,
                      is64 ? X86CalleeStackPurge{} : X86CalleeStackPurge([this](const cs_insn& call) { return CalleeStackPurge(call); }),
                      [this](const cs_insn& call) { return noReturnCalls.contains(call.address); });
        }
        if (!analyzed || frame.variables.empty())
            return;
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
        ComputeFunctionEnds();
        DetectFunctionChunks();
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

    // the results become the analysis of the zone; the number of lines added to the instructions (labels, local variables)
    uint32 Commit()
    {
        zone->xrefs                     = std::move(xrefs);
        zone->thunkImports              = std::move(thunkImports);
        zone->switchJumps               = std::move(switchJumps);
        zone->resolvedAddresses         = std::move(resolvedAddresses);
        zone->adrpPages                 = std::move(adrpPages);
        zone->imageBaseTables           = std::move(imageBaseTables);
        zone->functionStarts            = std::move(functionStarts);
        zone->functionEnds              = std::move(functionEnds);
        zone->functionChunks            = std::move(chunks);
        zone->noReturnFunctions.assign(noReturnStarts.begin(), noReturnStarts.end());
        std::sort(zone->noReturnFunctions.begin(), zone->noReturnFunctions.end());
        zone->noReturnCalls = std::move(noReturnCalls);
        zone->dissasmType.annotations   = std::move(annotations);
        zone->localVariables.functions  = std::move(frames);
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
    if (frame && frame->usesFrameRegister && !frame->variables.empty())
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
                    text.append(asmLine.op_str, asmLine.op_str_size).append("\n");
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
    place.reanalyze = edit.kind == DissasmEdit::Kind::DataRanges || edit.kind == DissasmEdit::Kind::UserFunctions;
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
