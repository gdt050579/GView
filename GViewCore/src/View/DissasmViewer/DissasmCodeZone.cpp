#include "DissasmCodeZone.hpp"
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

// The deep scan of a code zone: the labels (calls, jumps, functions, import thunks, switch cases), the cross references and the local
// variables. It runs in steps, each one until a deadline: a big zone is analyzed while its linear listing is already shown. The results
// stay here until the scan ends and are given to the zone at once (Commit): the drawn lines never see a partial analysis.
struct GView::View::DissasmViewer::DissasmDeepScan {
    enum class Phase : uint8 { Sweep, Labels, Done };
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
    const uint32 asmLines;
    uint32 linesToDecode;
    const bool is64;
    const uint64 addressMask; // the addresses of 32 bit code wrap around at 4 GB
    const uint64 labelBase;
    const DissasmArch arch;

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
    Arm64AdrpTracker adrpTracker;
    std::vector<uint64> prologueCandidates;         // ARM64: file offsets of the prologues at a block start
    std::unordered_set<uint64> conditionalTargets;  // ARM64: relative targets of the conditional branches
    std::vector<uint64> functionStarts;
    AnnotationContainer annotations;
    std::vector<DissasmFunctionFrame> frames;
    size_t labelIndex = 0; // the next label placed on its line
    uint32 extraLines = 0;

    DissasmDeepScan(DissasmCodeZone* zone, const DissasmCodeZoneInitData& initData, int internalArchitecture, uint32 asmLines)
        : zone(zone), obj(initData.obj), internalArchitecture(internalArchitecture),
          detectLocalVariables(initData.enableLocalVariablesDetection && !zone->IsArm64Code()), // the frames of the x86 / x64 code only
          isFileAddress(initData.isFileAddress), functionEntries(initData.functionEntries), findImport(initData.findImport),
          addressToFileOffset(initData.addressToFileOffset), codeStart(zone->cachedCodeOffsets[0].offset), codeSize(zone->GetCodeSize()),
          asmLines(asmLines), linesToDecode(asmLines), is64(zone->Is64BitCode()), addressMask(is64 ? UINT64_MAX : 0xFFFFFFFFull),
          labelBase(zone->labelAddressBase), arch(zone->GetArch()), walker(initData.obj, codeStart, codeSize, 0), prologueDetector(is64),
          switchDetector(is64, zone->labelAddressBase, initData.imageBase), adrpTracker(zone->labelAddressBase)
    {
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
        walker = DissasmCodeLinesWalker(obj, codeStart, codeSize, handle, 0, &zone->instructionBoundaries, zone->paddingAlignmentBase, zone->IsArm64Code());
        callsFound.reserve(16);

        // the functions known by the plugin (exports, exception data, TLS callbacks): functions even when nothing calls them directly
        if (functionEntries) {
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it)
                AddFunctionStart(it->first);
        }
        return true;
    }

    // a value of a jump table (1, 2, 4 or 8 bytes) at an address of the labels
    std::optional<uint64> ReadTableValue(uint64 address, uint8 size)
    {
        const auto offset = addressToFileOffset(address);
        if (!offset.has_value())
            return {};
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
        const bool isArm64             = arch == DissasmArch::Arm64;
        if (!isArm64) { // the x86 / x64 prologues (the ARM64 functions come from the calls and from the plugin)
            const auto prologueStart = prologueDetector.Next(*insn, instructionOffset);
            if (prologueStart.has_value())
                AddFunctionStart(prologueStart.value());
        }

        // the cross references, in the address space of the labels (VA)
        const auto flow     = GetInstructionFlow(*insn, arch);
        const auto operands = GetInstructionOperands(*insn, arch);
        const uint64 from   = labelBase + insn->address;
        if (isArm64) {
            // the adrp pairs: the address of add / ldr / str [page + offset], the import slot of br / blr (import stubs, import calls)
            const bool isBlockStart = atBlockStart || std::binary_search(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), insn->address);
            auto pairOperands       = operands;
            const auto pair         = adrpTracker.Next(*insn, isBlockStart);
            if (pair.has_value()) {
                resolvedAddresses[insn->address] = pair->address;
                pairOperands.ripTarget           = pair->address;
                pairOperands.memoryAccess        = pair->memoryAccess;
                // an import stub (j_Name): adrp x16, page; ldr x16, [x16, #off]; br x16 from a block start
                if (pair->throughSlot && flow == X86Flow::Jump && pair->sequenceAtBlockStart && findImport) {
                    const auto import = findImport(pairOperands);
                    if (import && import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                        thunks.emplace_back(codeStart + pair->sequenceStart, import->name);
                        thunkImports[pair->sequenceStart] = import->name;
                        AddFunctionStart(codeStart + pair->sequenceStart);
                    }
                }
            }
            // the jump table of a switch (br x10): the cases are read from the table
            if (const auto table = adrpTracker.TakeJumpTable(); table.has_value() && addressToFileOffset) {
                std::vector<uint64> targets; // VA
                for (uint32 index = 0; index < table->count; index++) {
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
                    const uint64 target = table->base + (entry << table->shift);
                    if (target >= codeSize) { // not a table of this code
                        targets.clear();
                        break;
                    }
                    targets.push_back(labelBase + target);
                }
                AddSwitchTargets(insn->address, from, targets);
            }
            // a prologue at a block start: a function (a candidate until the end of the sweep: a shrink wrapped prologue is reached by a
            // conditional branch of its own function)
            if (isBlockStart && IsArm64PrologueStart(*insn))
                prologueCandidates.push_back(instructionOffset);
            if (flow == X86Flow::ConditionalJump && operands.directTarget.has_value())
                conditionalTargets.insert(operands.directTarget.value());
            const bool takesAddress = insn->id == ARM64_INS_ADR || (insn->id == ARM64_INS_ADD && pair.has_value());
            AnalyzeBranchesAndData(flow, pairOperands, from, takesAddress);
            atBlockStart = flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || insn->id == ARM64_INS_NOP ||
                           insn->id == ARM64_INS_INVALID;
            return;
        }

        // an import thunk (IDA j_Name): a jmp through an import slot that starts a block, reached by calls instead of the import itself.
        // An endbr at the start of a block keeps it a block start: the CET stubs (ELF .plt.sec: endbr64; bnd jmp [rip + ...]) start with
        // it, the thunk (and the calls to it) is at the endbr
        // a boundary (a section start of the plugin, a function entry) starts a block
        const bool isBlockStart = atBlockStart || std::binary_search(zone->instructionBoundaries.begin(), zone->instructionBoundaries.end(), insn->address);
        const bool isEndbr      = insn->id == X86_INS_ENDBR64 || insn->id == X86_INS_ENDBR32;
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
            }
        }

        // the jump table of a switch: every case is a jump target (loc_) referenced by the jmp
        const auto jumpTable = switchDetector.Next(*insn);
        if (jumpTable.has_value() && addressToFileOffset) {
            const auto targets = ReadX86JumpTableTargets(
                  jumpTable.value(),
                  [this](uint64 address, uint8 size) { return ReadTableValue(address, size); },
                  [this](uint64 address) { return address >= labelBase && address - labelBase < codeSize; });
            AddSwitchTargets(insn->address, from, targets);
        }
        AnalyzeBranchesAndData(flow, operands, from, insn->id == X86_INS_LEA);
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
        if (IsX86Branch(flow) && operands.directTarget.has_value()) {
            const auto kind = flow == X86Flow::Call ? DissasmXrefKind::Call : (flow == X86Flow::Jump ? DissasmXrefKind::Jump : DissasmXrefKind::ConditionalJump);
            xrefs.Add(from, (labelBase + operands.directTarget.value()) & addressMask, kind);
        }
        const auto dataKind = takesAddress ? DissasmXrefKind::Offset : ((operands.memoryAccess & CS_AC_WRITE) ? DissasmXrefKind::Write : DissasmXrefKind::Read);
        if (operands.ripTarget.has_value())
            xrefs.Add(from, (labelBase + operands.ripTarget.value()) & addressMask, dataKind);
        if (operands.absoluteMemory.has_value() && isFileAddress && isFileAddress(operands.absoluteMemory.value()))
            xrefs.Add(from, operands.absoluteMemory.value(), dataKind);
        if (!is64 && isFileAddress) { // push offset aText / mov ecx, offset aText (x64 uses lea [rip + ...])
            for (const uint64 value : operands.immediates)
                if (value >= 0x10000 && isFileAddress(value))
                    xrefs.Add(from, value, DissasmXrefKind::Offset);
        }

        if (IsX86Branch(flow)) {
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

    // the end of the sweep: the labels are sorted, the functions and their names are known
    void FinishSweep()
    {
        // ARM64: the prologues that no conditional branch reaches are functions (the others are shrink wrapped, inside their function)
        for (const uint64 candidate : prologueCandidates)
            if (!conditionalTargets.contains(candidate - codeStart))
                AddFunctionStart(candidate);
        // every label found at the entry point (a call and a prologue can both find it): the entry point keeps its own name
        callsFound.erase(
              std::remove_if(callsFound.begin(), callsFound.end(), [this](const auto& call) { return call.first == zone->zoneDetails.entryPoint; }),
              callsFound.end());
        callsFound.emplace_back(zone->zoneDetails.entryPoint, "EntryPoint");
        std::stable_sort(callsFound.begin(), callsFound.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first)
                return a.first < b.first;
            return GetLabelType(a.second) < GetLabelType(b.second); // a function start wins over a jump target
        });
        callsFound.erase(
              std::unique(callsFound.begin(), callsFound.end(), [](const auto& left, const auto& right) { return left.first == right.first; }),
              callsFound.end());
        xrefs.Finish();

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

    // a label on the line of its instruction, the local variables of a function below its label
    void PlaceLabel(const std::pair<uint64, std::string>& call)
    {
        const uint64 callValue = call.first;
        uint32 diffLines       = 0;
        auto callInsn          = GetCurrentInstructionByOffset(callValue, zone, obj, diffLines);
        if (!callInsn)
            return;
        cs_free(callInsn, 1);
        if (diffLines >= asmLines)
            return; // the target is after the last decoded instruction (trailing data), it has no line

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
        const uint64 bytesToRead = std::min<uint64>(limit - relativeAddress, DISSASM_MAX_ANALYZED_FUNCTION_SIZE);
        const auto functionData  = obj->GetData().Get(codeStart + relativeAddress, static_cast<uint32>(bytesToRead), false);
        if (!functionData.IsValid())
            return;

        DissasmFunctionFrame frame{};
        if (!AnalyzeX86FunctionFrame(detailHandle, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, is64, frame) ||
            frame.variables.empty())
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
        while (phase == Phase::Sweep) {
            if (linesToDecode == 0 || !walker.Next(insn)) {
                FinishSweep();
                phase = Phase::Labels;
                break;
            }
            linesToDecode--;
            AnalyzeInstruction();
            if (++counter % INSTRUCTIONS_BETWEEN_CLOCK_CHECKS == 0 && std::chrono::steady_clock::now() >= deadline)
                return false;
        }
        while (phase == Phase::Labels) {
            if (labelIndex >= callsFound.size()) {
                phase = Phase::Done;
                break;
            }
            PlaceLabel(callsFound[labelIndex++]);
            if (++counter % LABELS_BETWEEN_CLOCK_CHECKS == 0 && std::chrono::steady_clock::now() >= deadline)
                return false;
        }
        return true;
    }

    float GetProgress() const
    {
        // the sweep is most of the work
        if (phase == Phase::Sweep)
            return asmLines == 0 ? 0.0f : 0.8f * static_cast<float>(asmLines - linesToDecode) / static_cast<float>(asmLines);
        if (phase == Phase::Labels)
            return callsFound.empty() ? 1.0f : 0.8f + 0.2f * static_cast<float>(labelIndex) / static_cast<float>(callsFound.size());
        return 1.0f;
    }

    // the results become the analysis of the zone; the number of lines added to the instructions (labels, local variables)
    uint32 Commit()
    {
        zone->xrefs                     = std::move(xrefs);
        zone->thunkImports              = std::move(thunkImports);
        zone->switchJumps               = std::move(switchJumps);
        zone->resolvedAddresses         = std::move(resolvedAddresses);
        zone->functionStarts            = std::move(functionStarts);
        zone->dissasmType.annotations   = std::move(annotations);
        zone->localVariables.functions  = std::move(frames);
        return extraLines;
    }
};

// The zone must have bytes in the file and its entry point inside it
inline bool IsValidCodeZone(const DisassemblyZone& zoneDetails, Reference<GView::Object> obj)
{
    if (zoneDetails.size == 0 || zoneDetails.size > UINT64_MAX - zoneDetails.startingZonePoint)
        return false;
    // the lines end with the file when the zone goes past it
    if (zoneDetails.startingZonePoint >= obj->GetData().GetSize())
        return false;
    // the entry point may be after the end of the file (a truncated file): the lines are counted until there, the entry point simply has
    // no line (the init must not fail on every paint)
    return zoneDetails.entryPoint >= zoneDetails.startingZonePoint && zoneDetails.entryPoint - zoneDetails.startingZonePoint < zoneDetails.size;
}

// The lines of the zone, counted by a linear sweep (DecodeX86Line) that stops at a deadline and continues later: a big zone shows its first
// lines before the end of its code is read. A cached offset (file offset, line) is kept every DISSASM_INSTRUCTION_OFFSET_MARGIN bytes.
// The code is decoded from the start of the zone: every decoded address (and every branch target) is relative to it. An undecodable byte
// is a data line (db) and the decoding continues after it (inline data, jump tables); a zone bigger than the data cache window is decoded
// window after window.
struct GView::View::DissasmViewer::DissasmLineCounter {
    // the zero bytes at the end of the section (file alignment padding) decode as "add byte ptr [rax], al": a trailing run of them is not
    // shown. A run inside the code (between functions, data) is decoded as it is
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

    DissasmLineCounter(
          vector<AsmOffsetLine>& offsets,
          const DisassemblyZone& zoneDetails,
          Reference<GView::Object> obj,
          const std::vector<uint64>* boundaries,
          uint64 alignmentBase)
        : offsets(offsets), obj(obj), zoneStart(zoneDetails.startingZonePoint), zoneSize(zoneDetails.size), boundaries(boundaries),
          alignmentBase(alignmentBase), walker(obj, zoneDetails.startingZonePoint, zoneDetails.size, 0, 0, boundaries, alignmentBase)
    {
    }

    ~DissasmLineCounter()
    {
        if (insn)
            cs_free(insn, 1);
        if (handle != 0)
            cs_close(&handle);
    }

    bool Start(cs_arch arch, int internalArchitecture)
    {
        if (cs_open(arch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK) {
            handle = 0;
            return false;
        }
        insn   = cs_malloc(handle);
        walker = DissasmCodeLinesWalker(obj, zoneStart, zoneSize, handle, 0, boundaries, alignmentBase, arch == CS_ARCH_ARM64);
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
        if (zeroRunLines >= TRAILING_ZEROS_MINIMUM_LINES && zeroRunLines < lines) {
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

DissasmCodeZone::DissasmCodeZone() = default;

DissasmCodeZone::~DissasmCodeZone()
{
    deepScan.reset(); // before the decode handle
    if (decodeHandle != 0)
        cs_close(&decodeHandle);
}

csh DissasmCodeZone::GetDecodeHandle()
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
    labelAddressBase = initData.labelAddressBase.value_or(zoneDetails.startingZonePoint); // the first decoded instruction is the zone start
    paddingAlignmentBase = initData.alignPadding ? labelAddressBase : DISSASM_NO_PADDING_ALIGNMENT;
    zoneObject       = initData.obj;

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
    std::sort(instructionBoundaries.begin(), instructionBoundaries.end());
    instructionBoundaries.erase(std::unique(instructionBoundaries.begin(), instructionBoundaries.end()), instructionBoundaries.end());

    localVariables.functions.clear();
    deepScan.reset();
    deepScanInitData.reset();
    lineCounter.reset();
    if (IsValidCodeZone(zoneDetails, initData.obj)) {
        lineCounter = std::make_unique<DissasmLineCounter>(cachedCodeOffsets, zoneDetails, initData.obj, &instructionBoundaries, paddingAlignmentBase);
        if (!lineCounter->Start(capstoneArch, internalArchitecture))
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
            totalLines += deepScan->Commit();
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
        const uint64 next = index + 1 < functionStarts.size() ? functionStarts[index + 1] : codeSize;
        function.size     = next > function.start ? next - function.start : 0;
        function.name     = GetLabelNameAt(function.start);
        if (function.name.empty())
            function.name = GetLabelName("sub_", function.start);
        const auto [first, last] = xrefs.To(labelAddressBase + function.start);
        function.xrefs           = static_cast<uint32>(last - first);
        function.isThunk         = thunkImports.contains(function.start);
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

std::optional<uint64> DissasmCodeZone::GetFunctionContaining(uint64 relativeAddress) const
{
    const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
    if (next == functionStarts.begin())
        return {};
    return *(next - 1);
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
    const auto next                     = std::upper_bound(functionStarts.begin(), functionStarts.end(), functionStart);
    uint64 end                          = std::min<uint64>(next != functionStarts.end() ? *next : codeSize, codeSize);
    if (end - std::min(end, functionStart) > MAX_FUNCTION_SIZE) {
        end             = functionStart + MAX_FUNCTION_SIZE;
        graph.truncated = true;
    }
    if (functionStart >= end)
        return graph;

    // the instructions of the function, in the order of the listing
    struct Instruction {
        uint64 address, size;
        X86Flow flow;
        std::optional<uint64> target;
    };
    std::vector<Instruction> instructions;
    csh handle = 0;
    if (cs_open(capstoneArch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK)
        return graph;
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK) {
        cs_insn* insn                = cs_malloc(handle);
        Reference<GView::Object> obj = zoneObject;
        DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, codeSize, handle, functionStart, &instructionBoundaries, paddingAlignmentBase, IsArm64Code());
        while (walker.Next(insn) && insn->address < end) {
            if (instructions.size() == MAX_INSTRUCTIONS) {
                graph.truncated = true;
                break;
            }
            const auto flow     = GetInstructionFlow(*insn, GetArch());
            const auto operands = IsX86Branch(flow) ? GetInstructionOperands(*insn, GetArch()) : X86OperandsInfo{};
            instructions.push_back({ insn->address, insn->size, flow, operands.directTarget });
        }
        cs_free(insn, 1);
    }
    cs_close(&handle);
    if (instructions.empty())
        return graph;

    // the cases of the switches of the function
    std::unordered_map<uint64, std::vector<uint64>> switchTargets;
    for (const auto& xref : xrefs.byTarget)
        if (xref.kind == DissasmXrefKind::Switch && xref.from - labelAddressBase >= functionStart && xref.from - labelAddressBase < end)
            switchTargets[xref.from - labelAddressBase].push_back(xref.to - labelAddressBase);

    // the leaders: the start, the targets of the branches, the instruction after a jump / ret
    const auto inside = [functionStart, end](uint64 address) { return address >= functionStart && address < end; };
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
        if ((isJump || instruction.flow == X86Flow::Return) && index + 1 < instructions.size())
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
    const auto [first, last] = xrefs.To(labelAddressBase + functionStart);
    for (auto it = first; it != last; ++it) {
        if (it->kind != DissasmXrefKind::Call && it->kind != DissasmXrefKind::Jump)
            continue;
        DissasmCallReference caller;
        caller.site          = it->from - labelAddressBase;
        caller.functionStart = GetFunctionContaining(caller.site);
        if (it->kind == DissasmXrefKind::Jump) {
            // a jump from the same function is a loop, not a call
            if (caller.functionStart == std::optional<uint64>(functionStart) || !caller.functionStart.has_value())
                continue;
            caller.isTailJump = true;
        }
        if (caller.functionStart.has_value()) {
            caller.function = GetLabelNameAt(caller.functionStart.value());
            if (caller.function.empty())
                caller.function = GetLabelName("sub_", caller.functionStart.value());
        } else {
            caller.function = FormatCodeAddress(caller.site); // before the first function
        }
        callers.push_back(std::move(caller));
    }
    return callers;
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

    csh handle = 0;
    if (cs_open(capstoneArch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK)
        return callees;
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK) {
        cs_insn* insn                = cs_malloc(handle);
        Reference<GView::Object> obj = zoneObject;
        DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, codeSize, handle, functionStart, &instructionBoundaries, paddingAlignmentBase, IsArm64Code());
        while (walker.Next(insn) && insn->address < end) {
            const auto flow = GetInstructionFlow(*insn, GetArch());
            if (flow != X86Flow::Call && flow != X86Flow::Jump)
                continue;
            const auto operands = GetInstructionOperands(*insn, GetArch());
            DissasmCallReference callee;
            callee.site = insn->address;
            if (operands.directTarget.has_value()) {
                const uint64 target = operands.directTarget.value();
                // a jmp inside the function is not a call; a jmp to another function is a tail call
                if (flow == X86Flow::Jump && target >= functionStart && target < end)
                    continue;
                callee.isTailJump    = flow == X86Flow::Jump;
                callee.functionStart = target;
                callee.function      = GetLabelNameAt(target);
                if (callee.function.empty())
                    callee.function = GetLabelName("sub_", target);
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
    cs_close(&handle);
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
        const auto view      = obj->GetData().Get(codeStart + position, requested, false);
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
    csh handle = 0;
    if (cs_open(capstoneArch, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK)
        return {};
    std::optional<uint64> result;
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK) {
        cs_insn* insn           = cs_malloc(handle);
        const uint64 mask       = Is64BitCode() ? UINT64_MAX : 0xFFFFFFFFull;
        const uint64 wanted     = value & mask;
        Reference<GView::Object> obj = zoneObject;
        DissasmCodeLinesWalker walker(obj, cachedCodeOffsets[0].offset, GetCodeSize(), handle, from, &instructionBoundaries, paddingAlignmentBase, IsArm64Code());
        while (!result.has_value() && walker.Next(insn) && insn->address < to) {
            if (insn->id == X86_INS_INVALID || !insn->detail)
                continue; // a data line (db)
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
    cs_close(&handle);
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
    // the function that contains the address: the last function start placed before it
    const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
    LocalString<64> text;
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
    const auto [first, last]     = xrefs.To(labelAddressBase + relativeAddress);
    const auto count             = static_cast<size_t>(last - first);
    if (count == 0)
        return {};
    std::string text = count == 1 ? "xref: " : "xrefs: ";
    size_t index     = 0;
    for (auto it = first; it != last && index < SHOWN_XREFS; ++it, ++index) {
        if (index > 0)
            text += ", ";
        text += FormatCodeAddress(it->from - labelAddressBase);
        text += " (";
        text += GetXrefKindName(it->kind);
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
    place.onLabel = edit.kind == DissasmEdit::Kind::LabelName || edit.kind == DissasmEdit::Kind::VariableName ||
                    (edit.kind == DissasmEdit::Kind::Comment && edit.anchor.kind != DissasmCommentAnchor::Kind::Instruction);
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
    lastData               = obj->GetData().Get(cachedCodeOffsets[0].offset + relativeStart, requested, false);
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
