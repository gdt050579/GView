#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include "x86_x64/DissasmX86LocalVariables.hpp"

#include <algorithm>

using namespace GView::View::DissasmViewer;
using GView::Utils::GStatus;

constexpr uint64 DISSASM_MAX_ANALYZED_FUNCTION_SIZE = 0x1000000; // 16 MB, larger functions are analyzed only partially

const uint8 HEX_MAPPER[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };

inline bool ExtractCallsToInsertFunctionNames(
      vector<AsmOffsetLine>& offsets,
      DissasmCodeZone* zone,
      Reference<GView::Object> obj,
      int internalArchitecture,
      uint32& totalLines,
      uint64 maxLocationMemoryMappingSize,
      bool detectLocalVariables)
{
    DisassemblyZone& zoneDetails = zone->zoneDetails;
    const auto instructionData   = obj->GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);
    uint64 address               = offsets[0].offset - zoneDetails.startingZonePoint;
    // the data cache may return less than requested (end of file, zone bigger than the cache): never decode past what was returned
    if (!instructionData.IsValid() || address >= instructionData.GetLength())
        return false;

    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    cs_insn* insn = cs_malloc(handle);

    const uint32 asmLines = totalLines;
    uint32 linesToDecode  = totalLines;
    size_t size           = static_cast<size_t>(instructionData.GetLength() - address);
    auto data             = instructionData.GetData() + address;

    std::vector<std::pair<uint64, std::string>> callsFound;
    std::unordered_map<uint64, bool> callsMap; // true for offset, false for sub
    callsFound.reserve(16);
    bool foundCall     = false;
    uint64 callAddress = 0;
    while (cs_disasm_iter(handle, &data, &size, &address, insn) && linesToDecode > 0) {
        linesToDecode--;
        const bool isJump = insn->mnemonic[0] == 'j';
        if (*(uint32*) insn->mnemonic == callOP || isJump) {
            uint64 value;
            const bool foundValue = CheckExtractInsnHexValue(insn->op_str, value, maxLocationMemoryMappingSize);
            if (foundValue && value < zoneDetails.startingZonePoint + zoneDetails.size) {
                if (value < offsets[0].offset)
                    value += offsets[0].offset;
                const char* prefix = isJump ? "offset_0x" : "sub_0x";
                const auto it      = callsMap.find(value);
                if (it != callsMap.end()) {
                    if (isJump == it->second)
                        continue;
                }
                auto callName = FormatFunctionName(value, prefix);
                callsFound.emplace_back(value, callName.GetText());
                callsMap.insert({ value, isJump });
            }
        } else {
            const auto mnemonicVal = *(uint32*) insn->mnemonic;
            if (foundCall) {
                if (mnemonicVal == movOP && strcmp(insn->op_str, "ebp, esp") == 0) {
                    if (callAddress < offsets[0].offset)
                        callAddress += offsets[0].offset;
                    const auto it = callsMap.find(callAddress);
                    if (it != callsMap.end()) {
                        if (!it->second)
                            continue;
                    }
                    const char* prefix = "sub_0x";
                    auto callName      = FormatFunctionName(callAddress, prefix);
                    callsFound.emplace_back(callAddress, callName.GetText());
                    callsMap.insert({ callAddress, true });
                }
                foundCall = false;
            } else {
                if (mnemonicVal == pushOP) {
                    if (strcmp(insn->op_str, "ebp") == 0) {
                        callAddress = insn->address;
                        foundCall   = true;
                    }
                }
            }
        }
    }

    if (callsFound.empty()) {
        cs_free(insn, 1);
        cs_close(&handle);
        return false;
    }

    auto val = callsFound[0].first;

    enum labelType { SUB, OFFSET, OTHER };
    auto getLabelType = [](const std::string& s) -> labelType {
        assert(!s.empty());
        if (s.size() < 4)
            return OTHER;
        if (memcmp(s.c_str(), "sub_", 4) == 0)
            return SUB;
        if (s.size() < 7)
            return OTHER;
        if (memcmp(s.c_str(), "offset_", 7) == 0)
            return OFFSET;
        return OTHER;
    };

    std::vector<uint32> indexesToErase;
    for (int32 i = static_cast<int32>(callsFound.size()) - 1; i >= 0; i--) {
        const auto& call = callsFound[i];
        if (call.first == zone->zoneDetails.entryPoint) {
            indexesToErase.push_back(i);
            break;
        }
    }
    for (const auto indexToErase : indexesToErase)
        callsFound.erase(callsFound.begin() + indexToErase);

    callsFound.emplace_back(zone->zoneDetails.entryPoint, "EntryPoint");
    // TODO: this can be extracted for the user to add / delete its own operations
    std::sort(callsFound.begin(), callsFound.end(), [getLabelType](const auto& a, const auto& b) {
        if (a.first < b.first)
            return true;
        if (a.first > b.first)
            return false;
        return getLabelType(a.second) < getLabelType(b.second);

        // return a.second.compare(b.second) > 0; // move sub instructions first
    });

    // TODO: if there are missing called improve predicate to delele only sub and offset
    callsFound.erase(
          std::unique(callsFound.begin(), callsFound.end(), [](const auto& left, const auto& right) { return left.first == right.first; }), callsFound.end());

    cs_free(insn, 1);
    cs_close(&handle);

    const auto isFunctionLabel = [&getLabelType](const std::string& name) { return getLabelType(name) == SUB || name == "EntryPoint"; };
    const uint64 codeSize      = zone->GetCodeSize();

    // local variables: a dedicated handle with the instruction details (operands, registers access) enabled
    csh detailHandle     = 0;
    bool hasDetailHandle = false;
    std::vector<uint64> functionStarts; // relative addresses, every function is bounded by the next one
    if (detectLocalVariables && codeSize > 0) {
        hasDetailHandle = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &detailHandle) == CS_ERR_OK;
        if (hasDetailHandle && cs_option(detailHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
            cs_close(&detailHandle);
            hasDetailHandle = false;
        }
        if (hasDetailHandle) {
            functionStarts.reserve(callsFound.size());
            for (const auto& call : callsFound)
                if (call.first >= offsets[0].offset && isFunctionLabel(call.second))
                    functionStarts.push_back(call.first - offsets[0].offset);
        }
    }

    auto& annotations = zone->dissasmType.annotations;
    uint32 extraLines = 0;
    for (const auto& call : callsFound) {
        const uint64 callValue = call.first;
        uint32 diffLines       = 0;
        auto callInsn          = GetCurrentInstructionByOffset(callValue, zone, obj, diffLines);
        if (!callInsn)
            continue;
        cs_free(callInsn, 1);
        if (diffLines >= asmLines)
            continue; // the target is after the last decoded instruction (trailing data), it has no line

        const uint64 relativeAddress = callValue - offsets[0].offset;
        annotations.insert({ diffLines + extraLines, { call.second, relativeAddress } });
        annotations.add_initial_name(call.second);
        extraLines++;

        // the variable annotations pack the function start on 32 bits (the zone sizes are 32 bits)
        if (!hasDetailHandle || !isFunctionLabel(call.second) || relativeAddress >= codeSize || relativeAddress > 0xFFFFFFFFull)
            continue;
        const auto nextFunction  = std::upper_bound(functionStarts.begin(), functionStarts.end(), relativeAddress);
        const uint64 limit       = nextFunction != functionStarts.end() ? *nextFunction : codeSize;
        const uint64 bytesToRead = std::min<uint64>(limit - relativeAddress, DISSASM_MAX_ANALYZED_FUNCTION_SIZE);
        const auto functionData  = obj->GetData().Get(offsets[0].offset + relativeAddress, static_cast<uint32>(bytesToRead), false);
        if (!functionData.IsValid())
            continue;

        DissasmFunctionFrame frame{};
        if (!AnalyzeX86FunctionFrame(
                  detailHandle, functionData.GetData(), functionData.GetLength(), relativeAddress, limit, zone->Is64BitCode(), frame) ||
            frame.variables.empty())
            continue;
        // IDA like: the variables are listed right below the function label
        for (const auto& variable : frame.variables) {
            annotations.insert({ diffLines + extraLines, { std::string{}, PackLocalVariableAnnotation(relativeAddress, variable.frameOffset) } });
            extraLines++;
        }
        zone->localVariables.functions.push_back(std::move(frame));
    }
    if (hasDetailHandle)
        cs_close(&detailHandle);

    totalLines += extraLines; // only the annotations that were really inserted are zone lines
    return true;
}

inline bool populateOffsetsVector(
      vector<AsmOffsetLine>& offsets, DisassemblyZone& zoneDetails, GView::Object& obj, int internalArchitecture, uint32& totalLines)
{
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    const auto instructionData = obj.GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);
    if (!instructionData.IsValid()) {
        cs_close(&handle);
        return false;
    }
    // the data cache may return less than requested (end of file, zone bigger than the cache): never decode past what was returned
    const uint64 availableSize = std::min<uint64>(zoneDetails.size, instructionData.GetLength());

    if (offsets.empty()) {
        offsets.reserve(256);
        offsets.push_back({ zoneDetails.entryPoint, 0 });
    }

    size_t minimalValue = offsets[0].offset;

    cs_insn* insn     = cs_malloc(handle);
    size_t lastOffset = offsets[0].offset;

    constexpr uint32 addInstructionsStop = 30; // TODO: update this -> for now it stops, later will fold

    std::list<uint64> finalOffsets;

    if (zoneDetails.entryPoint < zoneDetails.startingZonePoint) {
        cs_close(&handle);
        return false;
    }
    uint64 address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    uint64 endAddress = availableSize;

    if (address >= endAddress) {
        cs_close(&handle);
        return false;
    }
    size_t size = static_cast<size_t>(availableSize - address);

    auto data = instructionData.GetData() + address;

    // std::string saved1 = "s1", saved2 = "s2";
    uint64 startingOffset = offsets[0].offset;

    size_t lastSize = size;
    // std::vector<uint64> tempStorage;
    // tempStorage.push_back(lastOffset);

    do {
        if (size > lastSize) {
            lastSize = size;
            // tempStorage.reserve(size / DISSASM_INSTRUCTION_OFFSET_MARGIN + 1);
        }

        while (address < endAddress) {
            if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                break;

            if ((insn->mnemonic[0] == 'j' || *(uint32*) insn->mnemonic == callOP)) // && insn->op_str[0] == '0' /* && insn->op_str[1] == 'x'*/)
            {
                uint64 computedValue = 0;
                if (insn->op_str[1] == 'x') {
                    // uint64 computedValue = 0;
                    char* ptr = &insn->op_str[2];
                    // TODO: also check not to overflow access!
                    while (*ptr && *ptr != ' ' && *ptr != ',') {
                        if (!(*ptr >= 'a' && *ptr <= 'f' || *ptr >= '0' && *ptr <= '9')) {
                            computedValue = 0;
                            break;
                        }
                        computedValue = computedValue * 16 + HEX_MAPPER[static_cast<uint8>(*ptr)];
                        ptr++;
                    }
                } else {
                    char* ptr = &insn->op_str[0];
                    while (*ptr && *ptr != ' ' && *ptr != ',') {
                        if (*ptr < '0' || *ptr > '9') {
                            computedValue = 0;
                            break;
                        }
                        computedValue = computedValue * 10 + (static_cast<uint8>(*ptr) - '0');
                        ptr++;
                    }
                    if (computedValue < zoneDetails.startingZonePoint)
                        computedValue += zoneDetails.startingZonePoint;
                    // if (insn->op_str[1] == '\0') {
                    //     computedValue = zoneDetails.startingZonePoint;
                    // }
                }

                if (computedValue < minimalValue && computedValue >= zoneDetails.startingZonePoint) {
                    minimalValue = computedValue;
                    // saved1       = insn->mnemonic;
                    // saved2       = insn->op_str;
                }
            }
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            if (adjustedSize - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
                lastOffset = adjustedSize;
            }
        }
        if (minimalValue >= startingOffset)
            break;

        // pushBack                       = false;
        const size_t zoneSizeToAnalyze = startingOffset - minimalValue;
        // finalOffsets.push_front(minimalValue);

        address        = minimalValue - zoneDetails.startingZonePoint;
        endAddress     = zoneSizeToAnalyze + address;
        size           = static_cast<size_t>(availableSize - address); // the loop stops at endAddress, the last instruction may cross it
        data           = instructionData.GetData() + address;
        lastOffset     = minimalValue;
        startingOffset = minimalValue;
    } while (true);

    address    = minimalValue - zoneDetails.startingZonePoint;
    size       = static_cast<size_t>(availableSize - address);
    data       = instructionData.GetData() + address;
    lastOffset = address;

    uint32 lineIndex = 0;
    offsets.clear();
    offsets.push_back({ minimalValue, 0 });

    constexpr uint32 alOpStr         = 7102752u; //* (uint32*) " al";
    uint32 continuousAddInstructions = 0;

    while (cs_disasm_iter(handle, &data, &size, &address, insn)) {
        lineIndex++;
        if (address - lastOffset >= DISSASM_INSTRUCTION_OFFSET_MARGIN) {
            lastOffset                = address;
            const size_t adjustedSize = address + zoneDetails.startingZonePoint;
            offsets.push_back({ adjustedSize, lineIndex });
        }

        if (*(uint32*) insn->mnemonic == addOP && insn->op_str[0] == 'b' && *(uint32*) &insn->op_str[15] == alOpStr) {
            if (++continuousAddInstructions == addInstructionsStop) {
                lineIndex -= continuousAddInstructions;
                break;
            }
        } else
            continuousAddInstructions = 0;
    }

    totalLines = lineIndex;
    cs_free(insn, 1);
    cs_close(&handle);
    return true;
}

bool GView::View::DissasmViewer::DissasmCodeZone::InitZone(DissasmCodeZoneInitData& initData)
{
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
    if (initData.enableDeepScanDissasmOnStart) {
        const bool scanned = ExtractCallsToInsertFunctionNames(
              cachedCodeOffsets,
              this,
              initData.obj,
              internalArchitecture,
              totalLines,
              initData.maxLocationMemoryMappingSize,
              initData.enableLocalVariablesDetection);
        if (!scanned) {
            initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
            return false;
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

    structureIndex = 0;
    types.push_back(dissasmType);
    levels.push_back(0);

    dissasmType.indexZoneStart = 0; //+1 for the title
    dissasmType.indexZoneEnd   = totalLines + 1;
    // dissasmType.annotations.insert({ 2, "loc fn" });

    return true;
}

void DissasmCodeZone::ReachZoneLine(uint32 line)
{
    changedLevel = false;
    if (lastReachedLine == line)
        return;

    const uint32 levelToReach = line;
    uint32& levelNow          = this->structureIndex;
    bool reAdapt              = false;
    while (true) {
        const DissasmCodeInternalType& currentType = types.back();
        if (currentType.indexZoneStart <= levelToReach && levelToReach < currentType.indexZoneEnd) {
            if (!currentType.internalTypes.empty())
                reAdapt = true;
            break;
        }
        types.pop_back();
        levels.pop_back();
        reAdapt = true;
    }

    while (reAdapt && !types.back().get().internalTypes.empty()) {
        DissasmCodeInternalType& currentType = types.back();
        for (uint32 i = 0; i < currentType.internalTypes.size(); i++) {
            auto& internalType = currentType.internalTypes[i];
            if (internalType.indexZoneStart <= levelToReach && levelToReach < internalType.indexZoneEnd) {
                types.emplace_back(internalType);
                levels.push_back(i);
                changedLevel                   = true;
                newLevelChangeData.hasName     = !internalType.name.empty();
                newLevelChangeData.isCollapsed = internalType.isCollapsed;
                break;
            }
        }
    }

    DissasmCodeInternalType& currentType = types.back();
    // TODO: do a faster search using a binary search using the annotations and start from there
    // TODO: maybe use some caching here?
    if (reAdapt || levelNow < levelToReach && levelNow + 1 != levelToReach || levelNow > levelToReach && levelNow - 1 != levelToReach) {
        currentType.textLinesPassed = 0;
        currentType.asmLinesPassed  = 0;
        for (uint32 i = currentType.indexZoneStart; i <= levelToReach; i++) {
            if (currentType.annotations.contains(i)) {
                currentType.textLinesPassed++;
                continue;
            }
            currentType.asmLinesPassed++;
        }
    } else {
        if (currentType.annotations.contains(levelToReach))
            currentType.textLinesPassed++;
        else
            currentType.asmLinesPassed++;
    }

    levelNow        = levelToReach;
    lastReachedLine = levelToReach;

    // if (currentType.annotations.contains(levelToReach))
    //     return {};

    // const uint32 value = currentType.GetCurrentAsmLine();
    // if (value == 0)
    //     return {};

    // return value - 1u;
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
    // the collapsible zones keep their own copies of the lines, removing a line inside them is not supported
    if (!dissasmType.internalTypes.empty())
        return GStatus::Error("Please remove the collapsible zones of this dissasm zone before removing local variables!");

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
    assert(dissasmType.internalTypes.empty());
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

    const auto removedCount = static_cast<uint32>(sortedLines.size());
    dissasmType.indexZoneEnd -= std::min(removedCount, dissasmType.indexZoneEnd);
    dissasmType.workingIndexZoneEnd = dissasmType.indexZoneEnd;
    offsetCacheMaxLine              = 0;
    ResetTypesReferenceList();
}

bool DissasmCodeZone::ResetTypesReferenceList()
{
    types.clear();
    levels.clear();
    structureIndex  = 0;
    lastReachedLine = static_cast<uint32>(-1);
    types.emplace_back(dissasmType);
    levels.push_back(0);
    ResetZoneCaching();
    return true;
}