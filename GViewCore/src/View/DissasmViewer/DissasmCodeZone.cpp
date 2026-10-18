#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include "x86_x64/DissasmX86LocalVariables.hpp"
#include "x86_x64/X86InstructionInfo.hpp"
#include "x86_x64/X86SwitchTables.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>

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
    // the code is [codeStart, codeStart + codeSize): the same lines as the ones counted by populateOffsetsVector
    const uint64 codeStart;
    const uint64 codeSize;
    const uint32 asmLines;
    uint32 linesToDecode;
    const bool is64;
    const uint64 addressMask; // the addresses of 32 bit code wrap around at 4 GB
    const uint64 labelBase;

    csh handle           = 0;
    cs_insn* insn        = nullptr;
    csh detailHandle     = 0;
    bool hasDetailHandle = false;
    // the same addresses as the drawn lines: 0 is the first decoded instruction; the undecodable bytes are data lines
    DissasmCodeLinesWalker walker;
    X86PrologueDetector prologueDetector;
    X86SwitchDetector switchDetector;
    bool atBlockStart = true; // the previous instruction does not continue into the current one (ret, jmp, int3, nop padding)

    std::vector<std::pair<uint64, std::string>> callsFound; // file offset of a label, its name
    std::unordered_map<uint64, bool> callsMap;              // true for loc, false for sub
    std::vector<std::pair<uint64, std::string>> thunks;     // file offset of an import thunk, the import

    // the results, given to the zone by Commit
    DissasmXrefs xrefs;
    std::unordered_map<uint64, std::string> thunkImports;
    std::unordered_map<uint64, uint32> switchJumps;
    std::vector<uint64> functionStarts;
    AnnotationContainer annotations;
    std::vector<DissasmFunctionFrame> frames;
    size_t labelIndex = 0; // the next label placed on its line
    uint32 extraLines = 0;

    DissasmDeepScan(DissasmCodeZone* zone, const DissasmCodeZoneInitData& initData, int internalArchitecture, uint32 asmLines)
        : zone(zone), obj(initData.obj), internalArchitecture(internalArchitecture), detectLocalVariables(initData.enableLocalVariablesDetection),
          isFileAddress(initData.isFileAddress), functionEntries(initData.functionEntries), findImport(initData.findImport),
          addressToFileOffset(initData.addressToFileOffset), codeStart(zone->cachedCodeOffsets[0].offset), codeSize(zone->GetCodeSize()),
          asmLines(asmLines), linesToDecode(asmLines), is64(zone->Is64BitCode()), addressMask(is64 ? UINT64_MAX : 0xFFFFFFFFull),
          labelBase(zone->labelAddressBase), walker(initData.obj, codeStart, codeSize, 0), prologueDetector(is64),
          switchDetector(is64, zone->labelAddressBase, initData.imageBase)
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
        if (cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle) != CS_ERR_OK) {
            handle = 0;
            return false;
        }
        if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
            return false;
        insn   = cs_malloc(handle);
        walker = DissasmCodeLinesWalker(obj, codeStart, codeSize, handle);
        callsFound.reserve(16);

        // the functions known by the plugin (exports, exception data, TLS callbacks): functions even when nothing calls them directly
        if (functionEntries) {
            for (auto it = functionEntries->lower_bound(codeStart); it != functionEntries->end() && it->first - codeStart < codeSize; ++it)
                AddFunctionStart(it->first);
        }
        return true;
    }

    // a value of a jump table (1, 4 or 8 bytes) at an address of the labels
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
        const auto prologueStart       = prologueDetector.Next(*insn, instructionOffset);
        if (prologueStart.has_value())
            AddFunctionStart(prologueStart.value());

        // the cross references, in the address space of the labels (VA)
        const auto flow     = GetX86Flow(*insn);
        const auto operands = GetX86OperandsInfo(*insn, is64);
        const uint64 from   = labelBase + insn->address;

        // an import thunk (IDA j_Name): a jmp through an import slot that starts a block, reached by calls instead of the import itself
        const bool isBlockStart = atBlockStart;
        atBlockStart            = flow == X86Flow::Jump || flow == X86Flow::Return || flow == X86Flow::Interrupt || insn->id == X86_INS_NOP;
        if (isBlockStart && flow == X86Flow::Jump && !operands.directTarget.has_value() && findImport) {
            const auto import = findImport(operands);
            if (import && import->type == MemoryMappingType::FunctionMapping && !import->name.empty()) {
                thunks.emplace_back(instructionOffset, import->name);
                thunkImports[insn->address] = import->name;
                AddFunctionStart(instructionOffset);
            }
        }

        // the jump table of a switch: every case is a jump target (loc_) referenced by the jmp
        const auto jumpTable = switchDetector.Next(*insn);
        if (jumpTable.has_value() && addressToFileOffset) {
            const auto targets = ReadX86JumpTableTargets(
                  jumpTable.value(),
                  [this](uint64 address, uint8 size) { return ReadTableValue(address, size); },
                  [this](uint64 address) { return address >= labelBase && address - labelBase < codeSize; });
            if (!targets.empty())
                switchJumps[insn->address] = static_cast<uint32>(targets.size());
            for (const uint64 target : targets) {
                xrefs.Add(from, target, DissasmXrefKind::Switch);
                const auto targetOffset = zone->GetFileOffsetOfAddress(target - labelBase);
                if (targetOffset.has_value() && !callsMap.contains(targetOffset.value())) {
                    callsFound.emplace_back(targetOffset.value(), zone->GetLabelName("loc_", target - labelBase));
                    callsMap.insert({ targetOffset.value(), true });
                }
            }
        }
        if (IsX86Branch(flow) && operands.directTarget.has_value()) {
            const auto kind = flow == X86Flow::Call ? DissasmXrefKind::Call : (flow == X86Flow::Jump ? DissasmXrefKind::Jump : DissasmXrefKind::ConditionalJump);
            xrefs.Add(from, (labelBase + operands.directTarget.value()) & addressMask, kind);
        }
        const auto dataKind =
              insn->id == X86_INS_LEA ? DissasmXrefKind::Offset : ((operands.memoryAccess & CS_AC_WRITE) ? DissasmXrefKind::Write : DissasmXrefKind::Read);
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
            hasDetailHandle = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &detailHandle) == CS_ERR_OK;
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
        zone->functionStarts            = std::move(functionStarts);
        zone->dissasmType.annotations   = std::move(annotations);
        zone->localVariables.functions  = std::move(frames);
        return extraLines;
    }
};

inline bool populateOffsetsVector(
      vector<AsmOffsetLine>& offsets, DisassemblyZone& zoneDetails, Reference<GView::Object> obj, int internalArchitecture, uint32& totalLines)
{
    if (zoneDetails.size == 0 || zoneDetails.size > UINT64_MAX - zoneDetails.startingZonePoint)
        return false;
    // the zone must have bytes in the file; the lines end with the file when the zone goes past it
    if (zoneDetails.startingZonePoint >= obj->GetData().GetSize())
        return false;
    // the entry point must be inside the zone; it may be after the end of the file (a truncated file): the lines are counted until
    // there, the entry point simply has no line (the init must not fail on every paint)
    if (zoneDetails.entryPoint < zoneDetails.startingZonePoint || zoneDetails.entryPoint - zoneDetails.startingZonePoint >= zoneDetails.size)
        return false;

    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    // The code is decoded from the start of the zone: every decoded address (and every branch target) is relative to it.
    // The previous backward search for the lowest branch target below the entry point read any operand that is not a hex number
    // (registers, memory) as the zone start, so the zone start was already the first decoded instruction for nearly every binary;
    // the cached zones (labels, comments) are keyed on these lines.
    // An undecodable byte is a data line (db) and the decoding continues after it (inline data, jump tables); a zone bigger than the
    // data cache window is decoded window after window.
    DissasmCodeLinesWalker walker(obj, zoneDetails.startingZonePoint, zoneDetails.size, handle);

    // The zero bytes at the end of the section (file alignment padding) decode as "add byte ptr [rax], al": a trailing run of them is
    // not shown. A run inside the code (between functions, data) is decoded as it is: stopping at the first long run of zeros hid the
    // rest of the code.
    constexpr uint32 trailingZerosMinimumLines = 4;
    uint32 zeroRunLines                        = 0;
    uint32 lineIndex                           = 0;
    uint64 lastOffset                          = 0;
    offsets.clear();
    offsets.push_back({ zoneDetails.startingZonePoint, 0 });

    cs_insn* insn = cs_malloc(handle);
    while (walker.Next(insn)) {
        lineIndex++;
        const uint64 address = walker.GetAddress(); // the next line
        if (address - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
            lastOffset = address;
            offsets.push_back({ address + zoneDetails.startingZonePoint, lineIndex });
        }

        // 00 00 (add byte ptr [rax], al), or a last single 00 byte (a data line: db 0x00)
        const bool isZeroPadding = (insn->id == X86_INS_ADD && insn->size == 2 && insn->bytes[0] == 0 && insn->bytes[1] == 0) ||
                                   (insn->id == X86_INS_INVALID && insn->size == 1 && insn->bytes[0] == 0);
        zeroRunLines             = isZeroPadding ? zeroRunLines + 1u : 0u;
    }
    if (zeroRunLines >= trailingZerosMinimumLines && zeroRunLines < lineIndex) {
        lineIndex -= zeroRunLines;
        // the cached offsets placed inside the removed lines point to lines that do not exist
        while (offsets.size() > 1 && offsets.back().line >= lineIndex)
            offsets.pop_back();
    }

    totalLines = lineIndex;
    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}

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
    if (decodeHandle == 0 && internalArchitecture != 0) {
        if (cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &decodeHandle) != CS_ERR_OK)
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
    userComments.Set(anchor.value(), comment);
    return true;
}

bool DissasmCodeZone::RemoveComment(uint32 line, bool showErr)
{
    const auto anchor = GetAnchorOfLine(line);
    if (!anchor.has_value() || !userComments.Remove(anchor.value())) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Could not find the comment!");
        return false;
    }
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
    zoneObject       = initData.obj;

    // TODO: move this on init
    if (!cs_support(CS_ARCH_X86)) {
        initData.dli->WriteErrorToScreen("Capstone does not support X86");
        initData.adjustedZoneSize = 1;
        initData.hasAdjustedSize  = true;
        return false;
    }

    switch (zoneDetails.language) {
    case DisassemblyLanguage::x86:
        internalArchitecture = CS_MODE_32;
        break;
    case DisassemblyLanguage::x64:
        internalArchitecture = CS_MODE_64;
        break;
    default: {
        initData.dli->WriteErrorToScreen("ERROR: unsupported language!");
        return false;
    }
    }

    uint32 totalLines = 0;
    if (!populateOffsetsVector(cachedCodeOffsets, zoneDetails, initData.obj, internalArchitecture, totalLines)) {
        initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    asmLinesCount = totalLines;
    localVariables.functions.clear();
    deepScan.reset();
    if (initData.enableDeepScanDissasmOnStart) {
        // a big zone: the scan continues after its budget (ContinueDeepScan), the instructions are shown without labels until it ends
        deepScan = std::make_unique<DissasmDeepScan>(this, initData, internalArchitecture, totalLines);
        if (!deepScan->Start()) {
            deepScan.reset();
            initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
            return false;
        }
        const auto deadline = initData.deepScanBudget.has_value() ? std::chrono::steady_clock::now() + initData.deepScanBudget.value()
                                                                  : std::chrono::steady_clock::time_point::max();
        if (deepScan->Run(deadline)) {
            totalLines += deepScan->Commit();
            deepScan.reset();
        }
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

    if (!FetchCodeWindow(initData.obj, 0, DISSASM_INSTRUCTION_OFFSET_MARGIN + DISSASM_MAX_INSTRUCTION_SIZE)) {
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

bool DissasmCodeZone::ContinueDeepScan(std::chrono::steady_clock::time_point deadline)
{
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
    deepScan.reset();
}

float DissasmCodeZone::GetDeepScanProgress() const
{
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
    InsertZone(std::move(zone));
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
    collapsibleZones.erase(collapsibleZones.begin() + (zone - collapsibleZones.data()));
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
    variable->name = newName;
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
}
