#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"

using namespace GView::View::DissasmViewer;

constexpr size_t DISSASM_INSTRUCTION_OFFSET_MARGIN = 500;

const uint8 HEX_MAPPER[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };

inline bool ExtractCallsToInsertFunctionNames(
      vector<AsmOffsetLine>& offsets,
      DissasmCodeZone* zone,
      Reference<GView::Object> obj,
      int internalArchitecture,
      uint32& totalLines,
      uint64 maxLocationMemoryMappingSize)
{
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        // WriteErrorToScreen(dli, cs_strerror(resCode));
        return false;
    }

    cs_insn* insn = cs_malloc(handle);

    DisassemblyZone& zoneDetails = zone->zoneDetails;
    const auto instructionData   = obj->GetData().Get(zoneDetails.startingZonePoint, static_cast<uint32>(zoneDetails.size), false);

    uint32 linesToDecode = totalLines;
    size_t size          = zoneDetails.size;
    uint64 address       = offsets[0].offset - zoneDetails.startingZonePoint;
    auto data            = instructionData.GetData() + address;

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

    // callsFound.push_back({ 1030, "call2" });
    // callsFound.push_back({ 1130, "call 3" });
    // callsFound.push_back({ 1140, "call 5" });
    uint32 extraLines = 0;
    for (const auto& call : callsFound) {
        const uint64 callValue = call.first;
        uint32 diffLines       = 0;
        auto callInsn          = GetCurrentInstructionByOffset(callValue, zone, obj, diffLines);
        if (callInsn) {
            auto& annotations = zone->dissasmType.annotations;
            annotations.insert({ diffLines + extraLines, { call.second, callValue - offsets[0].offset } });
            annotations.add_initial_name(call.second);
            cs_free(callInsn, 1);
            extraLines++;
        }
    }
    totalLines += static_cast<uint32>(callsFound.size());
    cs_free(insn, 1);
    cs_close(&handle);

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

    if (offsets.empty()) {
        offsets.reserve(256);
        offsets.push_back({ zoneDetails.entryPoint, 0 });
    }

    size_t minimalValue = offsets[0].offset;

    cs_insn* insn     = cs_malloc(handle);
    size_t lastOffset = offsets[0].offset;

    constexpr uint32 addInstructionsStop = 30; // TODO: update this -> for now it stops, later will fold

    std::list<uint64> finalOffsets;

    size_t size       = zoneDetails.startingZonePoint + zoneDetails.size;
    uint64 address    = zoneDetails.entryPoint - zoneDetails.startingZonePoint;
    uint64 endAddress = zoneDetails.size;

    if (address >= endAddress) {
        cs_close(&handle);
        return false;
    }

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
        size           = address + zoneSizeToAnalyze;
        data           = instructionData.GetData() + address;
        lastOffset     = minimalValue;
        startingOffset = minimalValue;
    } while (true);

    size       = zoneDetails.size;
    address    = minimalValue - zoneDetails.startingZonePoint;
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
    if (initData.enableDeepScanDissasmOnStart &&
        !ExtractCallsToInsertFunctionNames(cachedCodeOffsets, this, initData.obj, internalArchitecture, totalLines, initData.maxLocationMemoryMappingSize)) {
        initData.dli->WriteErrorToScreen("ERROR: failed to populate offsets vector!");
        return false;
    }
    totalLines++; //+1 for title
    initData.adjustedZoneSize = totalLines;
    initData.hasAdjustedSize  = true;
    // AdjustZoneExtendedSize(zone, totalLines);
    lastDrawnLine          = 0;
    const auto closestData = SearchForClosestAsmOffsetLineByLine(cachedCodeOffsets, lastDrawnLine);
    lastClosestLine        = closestData.line;
    isInit                 = true;

    asmAddress = 0;
    asmSize    = zoneDetails.size - asmAddress;

    const auto instructionData = initData.obj->GetData().Get(cachedCodeOffsets[0].offset + asmAddress, static_cast<uint32>(asmSize), false);
    lastData                   = instructionData;
    if (!instructionData.IsValid()) {
        initData.dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        return false;
    }
    asmData = const_cast<uint8*>(instructionData.GetData());

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