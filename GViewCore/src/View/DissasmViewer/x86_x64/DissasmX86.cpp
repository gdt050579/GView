#include "DissasmViewer.hpp"
#include "DissasmX86.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include "DissasmX86LocalVariables.hpp"
#include <capstone/capstone.h>
#include <cassert>
#include <ranges>
#include <utility>
#include <list>
#include <algorithm>
#include <sstream>

using GView::Utils::GStatus;

// #define DISSASM_DISABLE_STRING_PREVIEW

constexpr uint32 DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT     = 100;
constexpr uint32 DISSASM_ASSISTANT_MAX_DISSASM_LINES_ANALYSED = 150;
constexpr uint32 DISSASM_ASSISTANT_MAX_API_CALLS              = 10;
constexpr uint32 DISSASM_ASSISTANT_MAX_BYTE_TO_SEND           = 640;

#pragma warning(disable : 4996) // The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

// TODO: performance improvements
//  consider using the same cs_insn and cs handle for all instructions that are on the same thread instead of creating new ones

// Dissasm menu configuration
constexpr uint32 addressTotalLength                 = 16;
constexpr uint32 opCodesGroupsShown                 = 8;
constexpr uint32 opCodesTotalLength                 = opCodesGroupsShown * 3 + 1;
constexpr uint32 textColumnTextLength               = opCodesGroupsShown;
constexpr uint32 textColumnSpacesLength             = 4;
constexpr uint32 textColumnTotalLength              = textColumnTextLength + textColumnSpacesLength;
constexpr uint32 textColumnIndicatorArrowLinesSpace = 3;
constexpr uint32 textAndOpCodesTotalLength          = opCodesTotalLength + textColumnTotalLength;
constexpr uint32 textTotalColumnLength =
      addressTotalLength + textColumnTextLength + opCodesTotalLength + textColumnTotalLength + textColumnIndicatorArrowLinesSpace;
constexpr uint32 commentPaddingLength   = 10;
constexpr uint32 textPaddingLabelsSpace = 3;

// TODO: to be moved inside plugin for some sort of API for token<->color
inline ColorPair GetASMColorPairByKeyword(std::string_view keyword, DissasmColors& colors, const AsmData& data)
{
    if (keyword.empty())
        return colors.AsmDefaultColor;
    if (keyword[0] == 'j')
        return colors.AsmJumpInstruction;

    LocalString<4> holder;
    holder.Set(keyword);
    const uint32 val = *reinterpret_cast<const uint32*>(holder.GetText());

    const auto it = data.instructionToColor.find(val);
    if (it != data.instructionToColor.end()) {
        return it->second;
    }

    if (keyword.size() < 4) {
        // General registers: EAX EBX ECX EDX -> AsmWorkRegisterColor
        // 16 bits: AX BX CX DX -> AsmWorkRegisterColor
        // 8 bits: AH AL BH BL CH CL DH DL -> AsmWorkRegisterColor
        // Segment registers: CS DS ES FS GS SS -> AsmWorkRegisterColor
        // Index and pointers: ESI EDI EBP EIP ESP along with variations (ESI, SI) AsmStackRegisterColor
        switch (keyword[keyword.size() - 1]) {
        case 'x':
        case 's':
        case 'l':
        case 'h':
            return colors.AsmWorkRegisterColor;
        case 'p':
        case 'i':
            return colors.AsmStackRegisterColor;
        default:
            break;
        }
    }

    return colors.AsmDefaultColor;
}

// TODO: to be moved inside plugin for some sort of API for token<->color
inline void DissasmAddColorsToInstruction(
      DissasmAsmPreCacheLine& insn, CharacterBuffer& cb, Config& cfg, DissasmColors& colors, AsmData& data, const CodePage& codePage, uint64 addressPadding = 0)
{
    // TODO: replace CharacterBuffer with Canvas;

    const MemoryMappingEntry* mappingPtr = (const MemoryMappingEntry*) insn.mapping;
    // cb.Clear();

    // TODO: Unicode --> alt caracter
    // AppCUI::Graphics:: GetCharacterCode
    // TODO: in loc de label jmp_address:
    LocalString<128> string;
    string.SetFormat("0x%08" PRIx64 "     ", insn.address + addressPadding);
    cb.Add(string, colors.AsmOffsetColor);

    if (!cfg.ShowOnlyDissasm) {
        cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

        for (uint32 i = 0; i < opCodesGroupsShown; i++) {
            if (i >= insn.size) {
                string.Clear();
                const uint32 remaining = opCodesGroupsShown - i;
                // const uint32 spaces    = remaining >= 2 ? remaining - 2 : 0;
                string.SetChars(' ', remaining * 3);
                cb.Add(string, colors.AsmDefaultColor);
                break;
            }
            const uint8 byte = insn.bytes[i];
            string.SetFormat("%02x ", byte);
            cb.Add(string, colors.AsmDefaultColor);
        }

        cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

        for (uint32 i = 0; i < textColumnTextLength; i++) {
            if (i >= insn.size) {
                string.Clear();
                const uint32 remaining = textColumnTextLength - i - 1;
                string.SetChars(' ', remaining);
                cb.Add(string, colors.AsmDefaultColor);
                break;
            }
            if (i != textColumnTextLength - 1) {
                const uint8 byte = insn.bytes[i];
                cb.InsertChar(codePage[byte], cb.Len(), colors.AsmDefaultColor);
            }
        }

        string.Clear();
        string.SetChars(' ', textColumnSpacesLength);
        cb.Add(string, colors.AsmDefaultColor);
    }

    cb.InsertChar('|', cb.Len(), colors.AsmTitleColumnColor);

    string.Clear();
    string.SetChars(' ', textColumnIndicatorArrowLinesSpace);

    if (insn.lineArrowToDraw && cfg.EnableDeepScanDissasmOnStart) {
        // string.SetChars(' ', textColumnIndicatorArrowLinesSpace);
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine1)
            string[0] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine2)
            string[1] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine3)
            string[2] = '|';
        if (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine ||
            insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawEndingLine) {
            for (int32 i = 0; i < static_cast<int32>(textColumnIndicatorArrowLinesSpace); i++)
                if (string[i] == ' ')
                    string[i] = '-';
            const bool is_start = (insn.lineArrowToDraw & DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine) > 0;
            string[2]           = is_start ? '<' : '>';
        }
    }

    cb.Add(string, colors.AsmDefaultColor);

    if (insn.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition && insn.op_str) {
        // IDA like variable line, below the function label: "var_8 = dword ptr -8"
        string.Clear();
        string.SetChars(' ', textPaddingLabelsSpace * 2);
        cb.Add(string, colors.AsmDefaultColor);
        const std::string_view text = { insn.op_str, insn.op_str_size };
        const size_t nameSize       = std::min<size_t>(insn.localVariableNameSize, text.size());
        cb.Add(text.substr(0, nameSize), colors.AsmLocalVariableColor);
        cb.Add(text.substr(nameSize), colors.AsmLocationInstruction);
        return;
    }

    if (insn.size > 0) {
        string.Clear();
        string.SetChars(' ', textPaddingLabelsSpace);

        cb.Add(string, colors.AsmDefaultColor);
    }

    string.SetFormat("%-6s", insn.mnemonic);
    const ColorPair color = GetASMColorPairByKeyword(insn.mnemonic, colors, data);
    cb.Add(string, color);

    if (insn.op_str) {
        const std::string_view op_str = insn.op_str;
        // TODO: add checks to verify  lambdaBuffer.Set, for x86 it's possible to be fine but not for other languages
        LocalString<32> lambdaBuffer;
        auto checkValidAndAdd = [&cb, &colors, &lambdaBuffer, &data](std::string_view token) {
            lambdaBuffer.Clear();
            if (token.length() > 2 && token[0] == '0' && token[1] == 'x') {
                cb.Add(token.data(), colors.AsmOffsetColor);
                return;
            }
            lambdaBuffer.Set(token.data());
            const ColorPair color = GetASMColorPairByKeyword(token, colors, data);
            cb.Add(token, color);
        };

        if (op_str.length() > 2 && op_str[0] == '0' && op_str[1] == 'x') {
            cb.Add(" ");
            checkValidAndAdd(op_str);
            return;
        }

        // the local variable used by the instruction ([ebp + var_8]) is the token placed at localVariableNameStart
        const bool hasVariableToken = insn.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Reference && insn.localVariableNameSize > 0;
        size_t tokenStart           = 0;
        LocalString<32> buffer;
        auto addToken = [&]() {
            if (hasVariableToken && tokenStart == insn.localVariableNameStart)
                cb.Add(buffer.GetText(), colors.AsmLocalVariableColor);
            else
                checkValidAndAdd(buffer.GetText());
            buffer.Clear();
        };

        char lastOp = ' ';
        for (size_t i = 0; i < op_str.size(); i++) {
            const char c = op_str[i];
            if (c == ' ' || c == ',' || c == '[' || c == ']') {
                if (buffer.Len() > 0) {
                    if (lastOp != '[')
                        cb.Add(" ");
                    addToken();
                }
                if (c != ' ') {
                    const char tmp[3] = { ' ', c, '\0' };
                    const char* start = (c == '[') ? tmp : tmp + 1;
                    cb.Add(start, colors.AsmCompareInstructionColor);
                }
                lastOp = c;
                continue;
            }
            if (buffer.Len() == 0)
                tokenStart = i;
            buffer.AddChar(c);
        }
        if (buffer.Len() > 0) {
            cb.Add(" ");
            addToken();
        }
    } else {
        if (mappingPtr) {
            string.SetFormat("%s", mappingPtr->name.data());
            const ColorPair mapColor = mappingPtr->type == MemoryMappingType::TextMapping ? colors.AsmLocationInstruction : colors.AsmFunctionColor;
            cb.Add(string, mapColor);
        }
        // assert(mappingPtr);
    }

    // string.SetFormat("0x%" PRIx64 ":           %s %s", insn[j].address, insn[j].mnemonic, insn[j].op_str);
}

inline cs_insn* GetCurrentInstructionByLine(
      uint32 lineToReach, DissasmCodeZone* zone, Reference<GView::Object> obj, uint32& diffLines, DrawLineInfo* dli = nullptr)
{
    uint32 lineDifferences = 1;
    // only the line right after the previous decoded one continues from the current position (same cached offset window),
    // any other line (including the same line again) restarts from its closest cached offset
    const bool isNextLine = lineToReach == zone->lastDrawnLine + 1u && lineToReach < zone->offsetCacheMaxLine;
    uint64 windowStart    = zone->asmAddress;
    if (!isNextLine) {
        uint32 codeOffsetIndex = 0;
        const auto closestData = SearchForClosestAsmOffsetLineByLine(zone->cachedCodeOffsets, lineToReach, &codeOffsetIndex);
        zone->lastClosestLine  = closestData.line;
        windowStart            = closestData.offset - zone->cachedCodeOffsets[0].offset;
        zone->asmWindowEnd     = GetCachedOffsetWindowEnd(zone, codeOffsetIndex);
        if (static_cast<size_t>(codeOffsetIndex) + 1u < zone->cachedCodeOffsets.size())
            zone->offsetCacheMaxLine = zone->cachedCodeOffsets[static_cast<size_t>(codeOffsetIndex) + 1u].line;
        else
            zone->offsetCacheMaxLine = UINT32_MAX;
        lineDifferences = lineToReach - closestData.line + 1;
    }

    if (diffLines == 1) {
        diffLines = lineDifferences;
        return nullptr;
    }

    // the window is fetched again even for the next line: O(1) while cached, and other readers may have refilled the data cache
    if (!zone->FetchCodeWindow(obj, windowStart, zone->asmWindowEnd)) {
        zone->offsetCacheMaxLine = 0;
        if (dli)
            dli->WriteErrorToScreen("ERROR: extract valid data from file!");
        diffLines = UINT32_MAX;
        return nullptr;
    }

    // TODO: keep the handle open and insn open until the program ends
    csh handle;
    const auto resCode = cs_open(CS_ARCH_X86, static_cast<cs_mode>(zone->internalArchitecture), &handle);
    if (resCode != CS_ERR_OK) {
        zone->offsetCacheMaxLine = 0;
        if (dli)
            dli->WriteErrorToScreen(cs_strerror(resCode));
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);

    while (lineDifferences > 0) {
        if (!cs_disasm_iter(handle, &zone->asmData, (size_t*) &zone->asmSize, &zone->asmAddress, insn)) {
            zone->offsetCacheMaxLine = 0;
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            cs_close(&handle);
            return nullptr;
        }
        lineDifferences--;
    }

    cs_close(&handle);
    return insn;
}

inline const MemoryMappingEntry* TryExtractMemoryMapping(const Pointer<SettingsData>& settings, uint64 initialLocation, const uint64 possibleLocationAdjustment)
{
    const auto& mapping = settings->memoryMappings.find(initialLocation);
    if (mapping != settings->memoryMappings.end())
        return &mapping->second;
    const auto& mapping2 = settings->memoryMappings.find(initialLocation + possibleLocationAdjustment);
    if (mapping2 != settings->memoryMappings.end())
        return &mapping2->second;
    return nullptr;
}

inline optional<vector<uint8>> TryExtractPushText(Reference<GView::Object> obj, const uint64_t offset)
{
    const auto stringBuffer = obj->GetData().Get(offset, DISSAM_MAXIMUM_STRING_PREVIEW * 2, false);
    if (!stringBuffer.IsValid())
        return {};

    auto dataStart = stringBuffer.GetData();
    auto dataEnd   = dataStart + stringBuffer.GetLength();

    std::vector<uint8> textFound;
    textFound.reserve(DISSAM_MAXIMUM_STRING_PREVIEW * 2);
    textFound.push_back('"');
    bool wasZero = true;

    while (dataStart < dataEnd) {
        if (*dataStart >= 32 && *dataStart <= 126) {
            textFound.push_back(*dataStart);
            wasZero = false;
        } else if (*dataStart == '\0') {
            if (wasZero)
                break;
            wasZero = true;
        } else {
            break;
        }
        dataStart++;
    }

    if (textFound.size() >= DISSAM_MAXIMUM_STRING_PREVIEW) {
        while (textFound.size() > DISSAM_MAXIMUM_STRING_PREVIEW)
            textFound.erase(textFound.begin() + textFound.size() - 1);
        textFound.push_back('.');
        textFound.push_back('.');
        textFound.push_back('.');
    }
    textFound.push_back('"');
    textFound.push_back('\0');
    return textFound;
}

std::optional<uint32> DissasmGetCurrentAsmLineAndPrepareCodeZone(DissasmCodeZone* zone, uint32 currentLine)
{
    const uint32 levelToReach = currentLine;
    uint32& levelNow          = zone->structureIndex;
    bool reAdapt              = false;
    while (true) {
        const DissasmCodeInternalType& currentType = zone->types.back();
        if (currentType.indexZoneStart <= levelToReach && currentType.indexZoneEnd >= levelToReach)
            break;
        zone->types.pop_back();
        zone->levels.pop_back();
        reAdapt = true;
    }

    while (reAdapt && !zone->types.back().get().internalTypes.empty()) {
        DissasmCodeInternalType& currentType = zone->types.back();
        for (uint32 i = 0; i < currentType.internalTypes.size(); i++) {
            auto& internalType = currentType.internalTypes[i];
            if (internalType.indexZoneStart <= levelToReach && internalType.indexZoneEnd >= levelToReach) {
                zone->types.push_back(internalType);
                zone->levels.push_back(i);
                break;
            }
        }
    }

    DissasmCodeInternalType& currentType = zone->types.back();
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

    levelNow = levelToReach;

    if (currentType.annotations.contains(levelToReach))
        return {};

    const uint32 value = currentType.GetCurrentAsmLine();
    if (value == 0)
        return {};

    return value - 1u;
}

bool DissasmAsmPreCacheLine::TryGetDataFromAnnotations(const DissasmCodeInternalType& currentType, uint32 lineToSearch, DrawLineInfo* dli)
{
    const auto foundAnnotation = currentType.annotations.find(lineToSearch);
    if (foundAnnotation == currentType.annotations.end()) {
        if (dli)
            dli->WriteErrorToScreen("ERROR: failed to find annotation for line!");
        return false;
    }

    size        = 0;
    currentLine = lineToSearch;
    address     = foundAnnotation->second.second;

    if (currentType.isCollapsed) {
        op_str      = strdup(currentType.name.c_str());
        op_str_size = static_cast<uint32>(currentType.name.size());
        SetMnemonic("collapsed");
        return true;
    }

    // labels can be renamed to any length, the mnemonic is always NUL terminated
    SetMnemonic(foundAnnotation->second.first);
    // strncpy((char*) bytes, "------", sizeof(bytes));
    // size        = static_cast<uint32>(strlen((char*) bytes));

    // op_str      = strdup("<--");
    // op_str_size = static_cast<uint32>(strlen(op_str));
    op_str      = nullptr;
    op_str_size = 0;
    return true;
}

struct CsInsnDeleter {
    void operator()(cs_insn* insn) const
    {
        cs_free(insn, 1);
    }
};

void DissasmAsmPreCacheLine::SetMnemonic(std::string_view text)
{
    const size_t length = std::min<size_t>(text.size(), sizeof(mnemonic) - 1u);
    memcpy(mnemonic, text.data(), length);
    mnemonic[length] = '\0';
}

void DissasmAsmPreCacheLine::SetOperands(const char* operands, const DissasmCodeZone* zone)
{
    if (op_str) {
        free(op_str);
        op_str = nullptr;
    }
    const std::string_view text = operands ? operands : "";

    // [ebp - 8] -> [ebp + var_8] when the slot is a recognized variable of the function that contains the instruction
    const DissasmFunctionFrame* function = nullptr;
    const DissasmLocalVariable* variable = nullptr;
    X86FrameOperand frameOperand{};
    if (zone && !zone->localVariables.Empty() && FindX86FrameOperand(text, zone->Is64BitCode(), frameOperand)) {
        function = zone->localVariables.FindFunctionByAddress(address);
        variable = function ? function->FindVariable(frameOperand.frameOffset) : nullptr;
    }
    if (!variable) {
        op_str      = portable_strdup(operands ? operands : "");
        op_str_size = static_cast<uint32>(text.size());
        return;
    }

    std::string rewritten;
    rewritten.reserve(text.size() + variable->name.size() + 3u);
    rewritten.append(text.substr(0, frameOperand.replaceStart));
    rewritten.append(" + ");
    localVariableNameStart = static_cast<uint32>(rewritten.size());
    rewritten.append(variable->name);
    rewritten.append(text.substr(frameOperand.replaceEnd));

    op_str                = portable_strdup(rewritten.c_str());
    op_str_size           = static_cast<uint32>(rewritten.size());
    localVariableKind     = LocalVariableKind::Reference;
    localVariableFunction = function->startAddress;
    localVariableOffset   = frameOperand.frameOffset;
    localVariableNameSize = static_cast<uint32>(variable->name.size());
}

bool DissasmAsmPreCacheLine::TryGetDataFromInsn(DissasmInsnExtractLineParams& params)
{
    uint32 diffLines = 0;
    cs_insn* insnPtr = GetCurrentInstructionByLine(params.asmLine, params.zone, params.obj, diffLines, params.dli);
    if (!insnPtr)
        return false;
    const std::unique_ptr<cs_insn, CsInsnDeleter> insn(insnPtr); // released on every return path

    address = insn->address;
    memcpy(bytes, insn->bytes, std::min<uint32>(sizeof(bytes), sizeof(insn->bytes)));
    size        = insn->size;
    currentLine = params.actualLine;

    if (params.isCollapsed && params.zoneName) {
        op_str      = strdup(params.zoneName->c_str());
        op_str_size = static_cast<uint32>(params.zoneName->size());
        SetMnemonic("collapsed");
        return true;
    }

    SetMnemonic(insn->mnemonic);

    if (!params.settings || !params.asmData) {
        SetOperands(insn->op_str, params.zone);
        return true;
    }

    switch (*((uint32*) insn->mnemonic)) {
    case pushOP:
        flags = DissasmAsmPreCacheLine::InstructionFlag::PushFlag;
        break;
    case callOP:
        flags = DissasmAsmPreCacheLine::InstructionFlag::CallFlag;
        break;
    default:
        if (insn->mnemonic[0] == 'j') {
            flags = DissasmAsmPreCacheLine::InstructionFlag::JmpFlag;
        } else {
            SetOperands(insn->op_str, params.zone);
            return true;
        }
    }

    // TODO: improve efficiency by filtering instructions
    uint64 hexVal = 0;
    if (CheckExtractInsnHexValue(insn->op_str, hexVal, params.settings->maxLocationMemoryMappingSize)) {
        hexValue = hexVal;
        if (flags & (DissasmAsmPreCacheLine::InstructionFlag::JmpFlag | DissasmAsmPreCacheLine::InstructionFlag::CallFlag))
            branchTarget = hexVal; // same base as the decoded addresses, used by the jump arrows
        if (hexVal == 0 && flags != DissasmAsmPreCacheLine::InstructionFlag::PushFlag)
            hexValue = params.zone->cachedCodeOffsets[0].offset;
        else if (hexVal < params.zone->cachedCodeOffsets[0].offset)
            hexValue = hexVal + params.zone->cachedCodeOffsets[0].offset;
    }
    bool alreadyInitComment = false;
    if (params.zone->asmPreCacheData.HasAnyFlag(params.asmLine))
        alreadyInitComment = true;

    const uint64 finalIndex = params.zone->asmAddress + params.settings->offsetTranslateCallback->TranslateFromFileOffset(
                                                              params.zone->zoneDetails.entryPoint, (uint32) DissasmPEConversionType::RVA);
    auto& lastZone          = params.zone->types.back().get();
    bool shouldConsiderCall = false;
    if (flags & DissasmAsmPreCacheLine::InstructionFlag::CallFlag) {
        const MemoryMappingEntry* mappingPtr = nullptr; // TryExtractMemoryMapping(params.settings, hexVal, finalIndex);

        const auto& mapping_ptr = params.settings->memoryMappings.find(hexVal);
        if (mapping_ptr != params.settings->memoryMappings.end())
            mappingPtr = &mapping_ptr->second;
        else {
            const auto& mapping2 = params.settings->memoryMappings.find(hexVal + finalIndex);
            if (mapping2 != params.settings->memoryMappings.end())
                mappingPtr = &mapping2->second;
        }

        if (mappingPtr) {
            mapping     = mappingPtr;
            op_str_size = (uint32) mappingPtr->name.size();
            if (mappingPtr->type == MemoryMappingType::FunctionMapping) {
                if (!alreadyInitComment) {
                    // TODO: add functions to the obj AsmData to search for name instead of manually doing CRC
                    GView::Hashes::CRC32 crc32{};
                    uint32 hash    = 0;
                    const bool res = crc32.Init(GView::Hashes::CRC32Type::JAMCRC) &&
                                     crc32.Update(reinterpret_cast<const uint8*>(mappingPtr->name.data()), static_cast<uint32>(mappingPtr->name.size())) &&
                                     crc32.Final(hash);
                    if (res) {
                        const auto it = params.asmData->functions.find(hash);
                        if (it != params.asmData->functions.end()) {
                            params.zone->asmPreCacheData.AnnounceCallInstruction(params.zone, it->second, lastZone.commentsData);
                            params.zone->asmPreCacheData.AddInstructionFlag(params.asmLine, DissasmAsmPreCacheLine::CallFlag);
                        }
                    }
                } else {
                    op_str      = strdup(mappingPtr->name.data());
                    op_str_size = (uint32) mappingPtr->name.size();
                }
            }
        } else {
            shouldConsiderCall = true;
        }
    } else if (flags & DissasmAsmPreCacheLine::InstructionFlag::PushFlag) {
#ifndef DISSASM_DISABLE_STRING_PREVIEW
        if (!alreadyInitComment && !lastZone.commentsData.comments.contains(params.actualLine)) {
            const auto offset = params.settings->offsetTranslateCallback->TranslateToFileOffset(hexVal, (uint32) DissasmPEConversionType::RVA);
            if (offset != static_cast<uint64>(-1) && offset + DISSAM_MAXIMUM_STRING_PREVIEW < params.obj->GetData().GetSize()) {
                const auto textFoundOption = TryExtractPushText(params.obj, offset);
                if (textFoundOption.has_value()) {
                    const auto& textFound = textFoundOption.value();
                    if (textFound.size() > 3) {
                        lastZone.commentsData.AddOrUpdateComment(params.actualLine, (const char*) textFound.data());
                        params.zone->asmPreCacheData.AddInstructionFlag(params.asmLine, DissasmAsmPreCacheLine::PushFlag);
                    }
                }
            }
        }
#endif
    }

    if (flags & DissasmAsmPreCacheLine::InstructionFlag::JmpFlag || shouldConsiderCall) {
        if (!hexValue.has_value()) {
            flags = 0;
            SetOperands(insn->op_str, params.zone);
            return true;
        }

        const char* prefix = !shouldConsiderCall ? "offset_0x" : "sub_0x";

        NumericFormatter n;
        const auto res = n.ToString(hexValue.value(), { NumericFormatFlags::HexPrefix, 16 });

        auto fnName = FormatFunctionName(hexValue.value(), prefix);
        // fnName.AddFormat(" (%s)", res.data());

        if (parent) {
            auto new_name = parent->annotations.get_name_change(fnName.GetText());
            if (!new_name.empty())
                fnName.Set(new_name.c_str(), (uint32) new_name.size());
        }

        op_str      = strdup(fnName.GetText());
        op_str_size = static_cast<uint32>(fnName.Len());
    }

    if (!op_str && !mapping)
        SetOperands(insn->op_str, params.zone);
    return true;
}

// bool DissasmAsmPreCacheLine::TryGetDataFromInsn(cs_insn* insn, uint32 currentLine)
//{
//     if (!insn)
//         return false;
//     this->address     = insn->address;
//     memcpy(bytes, insn->bytes, std::min<uint32>(sizeof(bytes), sizeof(insn->bytes)));
//     this->size        = insn->size;
//     memcpy(mnemonic, insn->mnemonic, CS_MNEMONIC_SIZE);
//     this->currentLine = currentLine;
//
//     this->op_str      = strdup(insn->op_str);
//     this->op_str_size = (uint32) strlen(this->op_str);
//     strcpy(this->mnemonic, insn->mnemonic);
//
//     this->hexValue = currentLine; //??
//     return true;
// }

void DissasmAsmPreCacheData::PrepareLabelArrows()
{
    for (auto& line : cachedAsmLines)
        line.lineArrowToDraw = 0;
    if (cachedAsmLines.empty())
        return;

    const uint64 minimalAddress = cachedAsmLines.front().address;
    const uint64 maximalAddress = cachedAsmLines.back().address;

    constexpr uint8 ARROW_COLUMNS[textColumnIndicatorArrowLinesSpace] = { DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine1,
                                                                          DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine2,
                                                                          DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawLine3 };
    uint32 arrowsCount                                                = 0;
    for (size_t sourceIndex = 0; sourceIndex < cachedAsmLines.size() && arrowsCount < textColumnIndicatorArrowLinesSpace; sourceIndex++) {
        const auto& source = cachedAsmLines[sourceIndex];
        if (source.flags != DissasmAsmPreCacheLine::InstructionFlag::CallFlag && source.flags != DissasmAsmPreCacheLine::InstructionFlag::JmpFlag)
            continue;
        if (!source.branchTarget.has_value())
            continue;
        const uint64 target = source.branchTarget.value();
        if (target < minimalAddress || target > maximalAddress)
            continue;
        // first visible line placed at the target (its label when it has one); a target in the middle of an instruction has no line
        const auto targetIt =
              std::find_if(cachedAsmLines.begin(), cachedAsmLines.end(), [target](const DissasmAsmPreCacheLine& line) { return line.address == target; });
        if (targetIt == cachedAsmLines.end())
            continue;

        const size_t targetIndex = static_cast<size_t>(targetIt - cachedAsmLines.begin());
        const size_t firstIndex  = std::min(sourceIndex, targetIndex);
        const size_t lastIndex   = std::max(sourceIndex, targetIndex);
        cachedAsmLines[firstIndex].lineArrowToDraw |= DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawStartingLine;
        cachedAsmLines[lastIndex].lineArrowToDraw |= DissasmAsmPreCacheLine::LineArrowToDrawFlag::DrawEndingLine;
        for (size_t i = firstIndex; i <= lastIndex; i++)
            cachedAsmLines[i].lineArrowToDraw |= ARROW_COLUMNS[arrowsCount];
        arrowsCount++;
    }
}

bool Instance::DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0) {
        dli.WriteErrorToScreen("No data available!");
        return true;
    }

    chars.Clear();

    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    LocalString<256> spaces;
    spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
    chars.Set(spaces);

    if (dli.textLineToDraw == 0) {
        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), ColorMan.Colors.StructureColor);

        HighlightSelectionAndDrawCursorText(dli, static_cast<uint32>(zoneName.size()), static_cast<uint32>(zoneName.size()) + Layout.startingTextLineOffset);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);

        if (!zone->isInit && !InitDissasmCodeZone(dli, zone))
            return false;

        return true;
    }

    const bool firstLineToDraw = dli.screenLineToDraw == 0;
    if (dli.textLineToDraw == 1 || firstLineToDraw) {
        const ColorPair titleColumnColor = { ColorMan.Colors.AsmTitleColumnColor.Foreground, ColorMan.Colors.AsmTitleColor.Background };

        constexpr std::string_view address = "File address";
        chars.Add(address.data(), ColorMan.Colors.AsmTitleColor);

        spaces.Clear();
        spaces.SetChars(' ', addressTotalLength - static_cast<uint32>(address.size()) - 1u);
        chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

        chars.InsertChar('|', chars.Len(), titleColumnColor);

        if (!config.ShowOnlyDissasm) {
            constexpr std::string_view opCodes = "Op Codes";
            chars.Add(opCodes.data(), ColorMan.Colors.AsmTitleColor);
            spaces.Clear();
            spaces.SetChars(' ', opCodesTotalLength - static_cast<uint32>(opCodes.size()) - 1u);
            chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

            chars.InsertChar('|', chars.Len(), titleColumnColor);

            constexpr std::string_view textTitle = "Text";
            chars.Add(textTitle.data(), ColorMan.Colors.AsmTitleColor);
            spaces.Clear();
            spaces.SetChars(' ', textColumnTotalLength - static_cast<uint32>(textTitle.size()) - 1u);
            chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

            chars.InsertChar('|', chars.Len(), titleColumnColor);
        }

        constexpr std::string_view dissasmTitle = "Dissasm";
        chars.Add(dissasmTitle.data(), ColorMan.Colors.AsmTitleColor);
        uint32 titleColorRemaining = Layout.totalCharactersPerLine - chars.Len();
        if (chars.Len() > Layout.totalCharactersPerLine)
            titleColorRemaining = 0;
        spaces.Clear();
        spaces.SetChars(' ', titleColorRemaining);
        chars.Add(spaces, ColorMan.Colors.AsmTitleColor);

        HighlightSelectionAndDrawCursorText(dli, chars.Len() - Layout.startingTextLineOffset, chars.Len());

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);
        return true;
    }

    uint32 currentLine = dli.textLineToDraw - 2u;
    if (firstLineToDraw)
        --currentLine;

    if (!zone->isInit && !InitDissasmCodeZone(dli, zone))
        return false;

    auto& asmPreCacheData = zone->asmPreCacheData;
    if (asmPreCacheData.cachedAsmLines.empty()) {
        uint32 linesToPrepare       = std::min<uint32>(Layout.visibleRows, zone->extendedSize);
        const uint32 remainingLines = zone->extendedSize - currentLine + 1;
        linesToPrepare              = std::min<uint32>(linesToPrepare, remainingLines);
        const uint32 endingLine     = currentLine + linesToPrepare;

        DissasmInsnExtractLineParams params{};
        params.obj      = obj;
        params.settings = settings.get();
        params.asmData  = &asmData;
        params.dli      = &dli;
        params.zone     = zone;

        uint32 currentLineAux = currentLine;
        while (currentLineAux < endingLine) {
            auto asmCacheLine = zone->GetCurrentAsmLine(currentLineAux, obj, &params);
            asmPreCacheData.cachedAsmLines.push_back(std::move(asmCacheLine));
            currentLineAux++;
        }

        asmPreCacheData.ComputeMaxLine();
        if (config.EnableDeepScanDissasmOnStart)
            asmPreCacheData.PrepareLabelArrows();
    }

    const auto asmCacheLine = zone->asmPreCacheData.GetLine();
    if (!asmCacheLine)
        return false;
    if (asmCacheLine->shouldAddButton) {
        RegisterStructureCollapseButton(
              dli.screenLineToDraw + 1, asmCacheLine->isZoneCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone, true);
    }
    DissasmAddColorsToInstruction(*asmCacheLine, chars, config, ColorMan.Colors, asmData, codePage, zone->cachedCodeOffsets[0].offset);
    std::string comment;
    if (!asmCacheLine->parent)
        return false;
    if (asmCacheLine->parent && !asmCacheLine->parent->isCollapsed && asmCacheLine->parent->commentsData.GetComment(currentLine, comment)) {
        uint32 diffLine = zone->asmPreCacheData.maxLineSize + textTotalColumnLength + commentPaddingLength;
        if (config.ShowOnlyDissasm)
            diffLine -= textAndOpCodesTotalLength;
        if (chars.Len() > diffLine)
            diffLine = commentPaddingLength;
        else
            diffLine -= chars.Len();
        LocalString<DISSAM_MINIMUM_COMMENTS_X> spaces;
        spaces.AddChars(' ', diffLine);
        spaces.AddChars(';', 1);
        chars.Add(spaces, ColorMan.Colors.AsmComment);
        chars.Add(comment, ColorMan.Colors.AsmComment);
    }

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };

    /*if (isCursorLine)
        chars.SetColor(Layout.startingTextLineOffset, chars.Len(), config.Colors.HighlightCursorLine);*/

    HighlightSelectionAndDrawCursorText(
          dli, static_cast<uint32>(bufferToDraw.length() - Layout.startingTextLineOffset), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    // poolBuffer.lineToDrawOnScreen = dli.screenLineToDraw + 1;
    bool foundZone = false;
    for (const auto& z : asmData.zonesToClear)
        if (z == zone) {
            foundZone = true;
            break;
        }
    if (!foundZone)
        asmData.zonesToClear.push_back(zone);
    return true;
}

bool Instance::InitDissasmCodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    DissasmCodeZoneInitData initData{};
    // the local variables are recognized inside the functions found by the deep scan
    initData.enableDeepScanDissasmOnStart  = config.EnableDeepScanDissasmOnStart;
    initData.enableLocalVariablesDetection = config.EnableDeepScanDissasmOnStart;
    initData.obj                           = obj;
    initData.dli                           = &dli;
    initData.maxLocationMemoryMappingSize  = settings->maxLocationMemoryMappingSize;
    initData.visibleRows                   = Layout.visibleRows;

    if (!zone->InitZone(initData))
        return false;
    if (initData.hasAdjustedSize)
        AdjustZoneExtendedSize(zone, initData.adjustedZoneSize);

    bool zoneLinesChanged = false;
    if (!zone->TryLoadDataFromCache(cacheData, zoneLinesChanged)) {
        // TODO: will enable errors in the next version
        // dli.WriteErrorToScreen("ERROR: failed to load data from cache!");
        // return false;
    }
    if (zoneLinesChanged)                                                 // local variables removed by the user in a previous session
        AdjustZoneExtendedSize(zone, zone->GetRootZoneLinesCount() + 1u); // +1 for the title
    return true;
}

void Instance::CommandExportAsmFile()
{
    if (GView::App::IsExportBlockedFor(obj, "exporting the disassembly to .asm files"))
        return;
    int zoneIndex = 0;
    LocalString<128> string;
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone) {
            AppCUI::Utils::UnicodeStringBuilder sb;
            sb.Add(obj->GetPath());
            LocalString<32> fileName;
            fileName.SetFormat(".x86.z%d.asm", zoneIndex);
            sb.Add(fileName);

            AppCUI::OS::File f;
            if (!f.Create(sb.ToStringView(), true)) {
                continue;
            }
            if (!f.OpenWrite(sb.ToStringView())) {
                f.Close();
                continue;
            }

            f.Write("ASMZoneZone\n", sizeof("ASMZoneZone\n") - 1);

            const auto dissamZone = static_cast<DissasmCodeZone*>(zone.get());
            const auto language   = dissamZone->zoneDetails.language;
            if (language != DisassemblyLanguage::x86 && language != DisassemblyLanguage::x64) {
                f.Write("Only x86/x64 zones can be exported!");
                f.Close();
                continue;
            }
            const uint64 staringOffset = dissamZone->cachedCodeOffsets[0].offset;
            if (staringOffset < dissamZone->zoneDetails.startingZonePoint ||
                staringOffset - dissamZone->zoneDetails.startingZonePoint >= dissamZone->zoneDetails.size) {
                f.Write("Invalid zone!");
                f.Close();
                continue;
            }
            size_t size = dissamZone->zoneDetails.size - (staringOffset - dissamZone->zoneDetails.startingZonePoint);

            const auto dataBuffer = obj->GetData().Get(staringOffset, static_cast<uint32>(size), false);
            if (!dataBuffer.IsValid()) {
                f.Write("Failed to get data from file!");
                f.Close();
                continue;
            }
            // the data cache may return less than requested
            size                    = dataBuffer.GetLength();
            uint64 address          = 0;
            const uint64 endAddress = size;
            auto data               = dataBuffer.GetData();

            csh handle;
            const auto resCode = cs_open(CS_ARCH_X86, language == DisassemblyLanguage::x64 ? CS_MODE_64 : CS_MODE_32, &handle);
            if (resCode != CS_ERR_OK) {
                f.Write(cs_strerror(resCode));
                f.Close();
                continue;
            }

            cs_insn* insn = cs_malloc(handle);

            while (address < endAddress) {
                if (!cs_disasm_iter(handle, &data, &size, &address, insn))
                    break;

                string.SetFormat("0x%" PRIx64 ":     %-10s %s\n", insn->address + staringOffset, insn->mnemonic, insn->op_str);
                f.Write(string.GetText(), string.Len());
            }

            cs_free(insn, 1);
            cs_close(&handle);
            f.Close();
            zoneIndex++;

            GView::App::OpenFile(sb.ToStringView(), App::OpenMethod::BestMatch);
        }
    }
}

void Instance::DissasmZoneProcessSpaceKey(DissasmCodeZone* zone, uint32 line, uint64* offsetToReach)
{
    uint32 diffLines     = 0;
    uint64 computedValue = 0;
    cs_insn* insn;
    // learning telemetry: source address + mnemonic of a followed jump/call (never operands or bytes)
    uint64 jumpFromAddress = 0;
    char jumpMnemonic[16]  = {};
    if (!offsetToReach) {
        if (line <= 1)
            return;

        const decltype(DissasmCodeZone::structureIndex) index = zone->structureIndex;
        decltype(DissasmCodeZone::types) types                = zone->types;
        decltype(DissasmCodeZone::levels) levels              = zone->levels;

        const auto adjustedLine = DissasmGetCurrentAsmLineAndPrepareCodeZone(zone, line - 2);

        zone->structureIndex = index;
        zone->types          = std::move(types);
        zone->levels         = std::move(levels);

        if (!adjustedLine.has_value())
            return;

        insn = GetCurrentInstructionByLine(adjustedLine.value(), zone, obj, diffLines);
        if (!insn) {
            Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
            return;
        }
        if (insn->mnemonic[0] == 'j' || insn->mnemonic[0] == 'c' && *(uint32*) insn->mnemonic == callOP) {
            jumpFromAddress = insn->address;
            for (size_t i = 0; i + 1 < sizeof(jumpMnemonic) && insn->mnemonic[i] != 0; i++)
                jumpMnemonic[i] = insn->mnemonic[i];
            if (insn->op_str[0] == '0' && insn->op_str[1] == 'x') {
                char* val = &insn->op_str[2];

                while (*val && *val != ',' && *val != ' ') {
                    if (*val >= '0' && *val <= '9')
                        computedValue = computedValue * 16 + (*val - '0');
                    else if (*val >= 'a' && *val <= 'f')
                        computedValue = computedValue * 16 + (*val - 'a' + 10);
                    else {
                        Dialogs::MessageBox::ShowNotification("Warning", "Invalid jump value!");
                        computedValue = 0;
                        break;
                    }
                    val++;
                }
            } else if (insn->op_str[0] >= '0' && insn->op_str[0] <= '9' && insn->op_str[1] == '\0') {
                computedValue = zone->cachedCodeOffsets[0].offset + (insn->op_str[0] - '0');
            } else {
                cs_free(insn, 1);
                return;
            }
            cs_free(insn, 1);
        } else {
            cs_free(insn, 1);
            return;
        }
    } else
        computedValue = *offsetToReach;

    if (computedValue == 0 || computedValue > zone->zoneDetails.startingZonePoint + zone->zoneDetails.size)
        return;

    if (computedValue < zone->zoneDetails.startingZonePoint)
        computedValue += zone->zoneDetails.startingZonePoint;

    // computedValue = 1064;

    diffLines = 0;
    insn      = GetCurrentInstructionByOffset(computedValue, zone, obj, diffLines);
    if (!insn) {
        Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
        return;
    }
    cs_free(insn, 1);

    // diffLines++; // increased because of the menu bar

    const decltype(DissasmCodeZone::structureIndex) index = zone->structureIndex;
    decltype(DissasmCodeZone::types) types                = zone->types;
    decltype(DissasmCodeZone::levels) levels              = zone->levels;

    // TODO: can be improved by extracting the common part of the calculation of the actual line and to search for the closest zone directly
    const auto adjustedLine = DissasmGetCurrentAsmLineAndPrepareCodeZone(zone, diffLines);
    const auto& targetType  = zone->types.back().get();

    // diffLines is the instruction index: every text line (label, local variable) placed before the instruction moves it down
    uint32 instructionLine = diffLines + targetType.beforeTextLines;
    for (const auto& entry : targetType.annotations.mappings) { // no std::views::keys on mac
        if (entry.first > instructionLine)
            break;
        instructionLine++;
    }
    // land on the label (and the local variables) placed right above the instruction
    uint32 landingLine = instructionLine;
    while (landingLine > 0 && targetType.annotations.contains(landingLine - 1u))
        landingLine--;

    // if (adjustedLine.has_value())
    //     actualLine += adjustedLine.value() + 1;

    zone->structureIndex = index;
    zone->types          = std::move(types);
    zone->levels         = std::move(levels);

    diffLines = landingLine + 2u; //+1 for menu, +1 for title

    jumps_holder.insert(Cursor.saveState());
    Cursor.lineInView    = std::min<uint32>(5, diffLines);
    Cursor.startViewLine = diffLines + zone->startLineIndex - Cursor.lineInView;
    Cursor.hasMovedView  = true;
    if (offsetToReach != nullptr)
        GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::GotoEntrypoint);
    else
        GView::Security::Learning::Hooks::OnJumpFollow(obj, jumpFromAddress, computedValue, jumpMnemonic);
}

void Instance::EditDissasmCodeZoneCommand()
{
    AppCUI::Dialogs::MessageBox::ShowError("Error", "Not implemented yet !");
}

void Instance::CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation operation)
{
    if (operation == CollapsibleZoneOperation::Add && !selection.HasSelection(0)) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a single selection on a dissasm zone to add a zone!");
        return;
    }

    uint32 lineStart;
    uint32 lineEnd;
    if (selection.HasSelection(0)) {
        lineStart = selection.GetSelectionStart(0).line;
        lineEnd   = selection.GetSelectionEnd(0).line;
    } else {
        lineStart = Cursor.lineInView + Cursor.startViewLine;
        lineEnd   = lineStart + 1;
    }

    const auto zonesFound = GetZonesIndexesFromLinePosition(lineStart, lineEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    if (zonesFound[0].startingLine <= 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please do not select the title in the collapsible zones!");
        return;
    }

    auto zone = static_cast<DissasmCodeZone*>(parseZone.get());

    const uint32 zoneLineStart  = zonesFound[0].startingLine - 2; // 2 for title and menu -- need to be adjusted
    const uint32 zoneLinesCount = lineEnd - lineStart + 1u;
    const uint32 zoneLineEnd    = zoneLineStart + zoneLinesCount;

    int32 difference          = 0;
    const char* operationName = nullptr;
    switch (operation) {
    case CollapsibleZoneOperation::Add:
        if (!zone->AddCollapsibleZone(zoneLineStart, zoneLineEnd))
            operationName = "Add";
        break;
    case CollapsibleZoneOperation::Expand:
        if (!zone->CollapseOrExtendZone(zoneLineStart, DissasmCodeZone::CollapseExpandType::Expand, difference))
            operationName = "Expand";
        break;
    case CollapsibleZoneOperation::Collapse:
        if (!zone->CollapseOrExtendZone(zoneLineStart, DissasmCodeZone::CollapseExpandType::Collapse, difference))
            operationName = "Collapse";
        break;
    case CollapsibleZoneOperation::Remove:
        if (!zone->RemoveCollapsibleZone(zoneLineStart))
            operationName = "Collapse";
        break;
    default:
        Dialogs::MessageBox::ShowNotification("Warning", "Unimplemented!");
        break;
    }

    if (operationName) {
        LocalString<64> message;
        message.SetFormat("Failed to %s to zone!", operationName);
        Dialogs::MessageBox::ShowNotification("Error", message);
    } else {
        zone->ResetZoneCaching();
        if (difference) {
            AdjustZoneExtendedSize(zone, difference);
        }
    }
}

using ValidChildCallback = bool(DissasmCodeInternalType*, void*);

DissasmCodeInternalType* SearchBottomWithFnUpCollapsibleZoneRecursive(
      DissasmCodeInternalType& parent, uint32 line, ValidChildCallback isValidChild, void* context = nullptr)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            auto child = SearchBottomWithFnUpCollapsibleZoneRecursive(zone, line, isValidChild, context);
            if (child && isValidChild(child, context))
                return child;
            if (isValidChild(&zone, context))
                return &zone;
            return nullptr;
        }
    }

    return nullptr;
}

DissasmCodeInternalType* SearchBottomWithFnUpCollapsibleZone(
      DissasmCodeInternalType& parent, uint32 line, ValidChildCallback isValidChild, void* context = nullptr)
{
    if (parent.internalTypes.empty()) {
        if (isValidChild(&parent, context))
            return &parent;
        return nullptr;
    }
    return SearchBottomWithFnUpCollapsibleZoneRecursive(parent, line, isValidChild, context);
}

DissasmCodeInternalType* GetRecursiveCollpasedZoneByLineRecursive(DissasmCodeInternalType& parent, uint32 line)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            auto child = GetRecursiveCollpasedZoneByLineRecursive(zone, line);
            if (child)
                return child;
            return &zone;
        }
    }

    return nullptr;
}

DissasmCodeInternalType* GView::View::DissasmViewer::GetRecursiveCollpasedZoneByLine(DissasmCodeInternalType& parent, uint32 line)
{
    if (parent.internalTypes.empty())
        return &parent;
    return GetRecursiveCollpasedZoneByLineRecursive(parent, line);
}

GStatus DissasmCodeZone::TryRenameLine(
      uint32 line, Reference<GView::Object> obj, std::string_view* newName, DissasmInsnExtractLineParams* params)
{
    if (!newName) {
        // local variable: its definition line or an instruction that uses it
        uint64 functionStart = 0;
        int32 frameOffset    = 0;
        if (GetLocalVariableFromLine(line, obj, functionStart, frameOffset)) {
            const auto function = localVariables.FindFunctionByStart(functionStart);
            const auto variable = function ? function->FindVariable(frameOffset) : nullptr;
            if (!variable)
                return GStatus::Error("Failed to find the local variable!");
            SingleLineEditWindow dlg(variable->name, "Rename local variable");
            if (dlg.Show() != Dialogs::Result::Ok)
                return GStatus::Ok();
            const auto res = dlg.GetResult();
            if (res.empty() || res == variable->name)
                return GStatus::Ok();
            auto status = RenameLocalVariable(functionStart, frameOffset, res);
            if (!status.ok)
                return status;
            return GStatus{ .ok = true, .message = "renamed local variable" };
        }
    }

    // TODO: improve, add searching function to search inside types for the current annotation
    std::string currentName = {};
    auto& annotations = dissasmType.annotations;
    {
        auto it = annotations.find(line);
        if (it != annotations.end()) {
            if (newName) {
                it->second.first = newName->data();
                return GStatus::Ok();
            }
            currentName = it->second.first;
        }
    }

    if (currentName.empty()) {
        auto asmLine = GetCurrentAsmLine(line, obj, params);
        if (asmLine.flags == DissasmAsmPreCacheLine::InstructionFlag::JmpFlag) {
            //TODO: change to std::sting_view
            std::string annotation_name = std::string(asmLine.op_str, asmLine.op_str_size);
            auto res                    = annotations.get_line_by_annotation_name(annotation_name);
            if (res.has_value()) {
                currentName = std::move(annotation_name);
                line = res.value();
            }
        }
    }

    if (!currentName.empty()) {
        SingleLineEditWindow dlg(currentName, "Edit label");
        if (dlg.Show() == Dialogs::Result::Ok) {
            const auto res = dlg.GetResult();
            if (!res.empty()) {
                if (!annotations.add_name_change(currentName, res, line)) {
                    // TODO: do this check inside the SingleLineEditWindow
                    return GStatus::Error("Name already exists!");
                }
                return GStatus{ .ok = true, .message = "renamed" };
            }
        }
        return GStatus::Ok();
    }

    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->isCollapsed; };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (collapsedZone) {
        SingleLineEditWindow dlg(collapsedZone->name, "Edit collapsed zone label");
        if (dlg.Show() == Dialogs::Result::Ok) {
            const auto res = dlg.GetResult();
            if (!res.empty()) {
                collapsedZone->name = res;
                return GStatus{ .ok = true, .message = "renamed" };
            }
        }
        return GStatus::Ok();
    }

    return GStatus::Error("Failed to rename line");
}

bool DissasmCodeZone::GetComment(uint32 line, std::string& comment)
{
    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->commentsData.HasComment(*((uint32*) ctx)); };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (collapsedZone) {
        if (!collapsedZone->commentsData.GetComment(line, comment)) {
            Dialogs::MessageBox::ShowError("Error processing comments", "Invalid behaviour");
            return false;
        }
        return true;
    }

    return false;
}

bool DissasmCodeZone::AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr)
{
    const auto collapsedZone = GetRecursiveCollpasedZoneByLine(dissasmType, line);

    if (!collapsedZone) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Failed to find the required line!");
        return false;
    }

    collapsedZone->commentsData.AddOrUpdateComment(line, comment);
    return true;
}

bool DissasmCodeZone::RemoveComment(uint32 line, bool showErr)
{
    auto fnHasComments       = [](DissasmCodeInternalType* child, void* ctx) { return child->commentsData.HasComment(*((uint32*) ctx)); };
    const auto collapsedZone = SearchBottomWithFnUpCollapsibleZone(dissasmType, line, fnHasComments, &line);
    if (!collapsedZone) {
        if (showErr)
            Dialogs::MessageBox::ShowError("Error at processing comments", "Could not find the comment!");
        return false;
    }

    collapsedZone->commentsData.RemoveComment(line);
    return true;
}

DissasmAsmPreCacheLine DissasmCodeZone::GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params)
{
    ReachZoneLine(currentLine);

    const DissasmCodeInternalType& currentType = types.back();

    DissasmAsmPreCacheLine asmCacheLine{};
    asmCacheLine.parent = &currentType;
    if (changedLevel && newLevelChangeData.hasName) {
        asmCacheLine.shouldAddButton = true;
        asmCacheLine.isZoneCollapsed = newLevelChangeData.isCollapsed;
    }

    if (currentType.isCollapsed) {
        assert(!currentType.name.empty());
    }

    if (!currentType.isCollapsed) {
        const auto annotation = currentType.annotations.find(currentLine);
        if (annotation != currentType.annotations.end() && IsLocalVariableAnnotation(annotation->second)) {
            const uint64 functionStart = GetLocalVariableAnnotationFunction(annotation->second.second);
            const int32 frameOffset    = GetLocalVariableAnnotationOffset(annotation->second.second);
            const auto function        = localVariables.FindFunctionByStart(functionStart);
            const auto variable        = function ? function->FindVariable(frameOffset) : nullptr;

            asmCacheLine.size        = 0;
            asmCacheLine.currentLine = currentLine;
            asmCacheLine.address     = functionStart;
            std::string text         = "<unknown local variable>"; // the lines and the variables are always updated together
            uint32 nameSize          = 0;
            if (variable) {
                FormatLocalVariableDefinition(*variable, text, nameSize);
                asmCacheLine.localVariableKind     = DissasmAsmPreCacheLine::LocalVariableKind::Definition;
                asmCacheLine.localVariableFunction = functionStart;
                asmCacheLine.localVariableOffset   = frameOffset;
                asmCacheLine.localVariableNameSize = nameSize;
            }
            asmCacheLine.op_str      = portable_strdup(text.c_str());
            asmCacheLine.op_str_size = static_cast<uint32>(text.size());
            return asmCacheLine;
        }
    }

    if (asmCacheLine.TryGetDataFromAnnotations(currentType, currentLine)) {
        return asmCacheLine;
    }

    const uint32 value = currentType.GetCurrentAsmLine();
    assert(value != 0);

    uint32 asmLine = value - 1u;

    DissasmInsnExtractLineParams* paramsPtr = params;
    DissasmInsnExtractLineParams newParams{};
    if (paramsPtr == nullptr) {
        paramsPtr = &newParams;
    }
    paramsPtr->asmLine     = asmLine;
    paramsPtr->obj         = obj;
    paramsPtr->actualLine  = currentLine;
    paramsPtr->zone        = this;
    paramsPtr->isCollapsed = currentType.isCollapsed;
    paramsPtr->zoneName    = &currentType.name;

    const auto isValidData = asmCacheLine.TryGetDataFromInsn(*paramsPtr);
    assert(isValidData);
    lastDrawnLine = asmLine;

    // uint32 difflines = 0;
    // auto insn        = GetCurrentInstructionByLine(value - 1, this, obj, difflines);

    // assert(asmCacheLine.TryGetDataFromInsn(insn, currentLine));
    // cs_free(insn, 1);
    return asmCacheLine;
}

#pragma region CollapsibleZoneOperations

bool GetRecursiveZoneByLine(DissasmCodeInternalType& parent, uint32 line, DissasmCodeZone::CollapseExpandType collapse, int32& difference)
{
    for (auto& zone : parent.internalTypes) {
        if (zone.indexZoneStart <= line && line < zone.indexZoneEnd) {
            if (GetRecursiveZoneByLine(zone, line, collapse, difference)) {
                zone.indexZoneEnd += difference;
                continue;
            }

            if (!zone.internalTypes.empty() || zone.name.empty())
                return false;

            if (collapse == DissasmCodeZone::CollapseExpandType::Collapse && zone.isCollapsed ||
                collapse == DissasmCodeZone::CollapseExpandType::Expand && !zone.isCollapsed)
                return false;

            if (collapse == DissasmCodeZone::CollapseExpandType::NegateCurrentState)
                collapse = zone.isCollapsed ? DissasmCodeZone::CollapseExpandType::Expand : DissasmCodeZone::CollapseExpandType::Collapse;

            difference = static_cast<int32>(zone.workingIndexZoneEnd - zone.workingIndexZoneStart - 1);
            if (collapse == DissasmCodeZone::CollapseExpandType::Collapse)
                difference = -difference;
            zone.isCollapsed = collapse == DissasmCodeZone::CollapseExpandType::Collapse;
            zone.indexZoneEnd += difference;
            continue;
        }
        if (difference && line < zone.indexZoneStart) {
            zone.indexZoneStart += difference;
            zone.indexZoneEnd += difference;

            AnnotationContainer zoneAnnotations = std::move(zone.annotations);
            zone.annotations                    = {};
            for (auto& annotation : zoneAnnotations.mappings) {
                zone.annotations.insert({ annotation.first + difference, std::move(annotation.second) });
            }

            DissasmComments odlComments = std::move(zone.commentsData);
            zone.commentsData           = {};
            for (auto& comment : odlComments.comments) {
                zone.commentsData.comments.insert({ comment.first + difference, std::move(comment.second) });
            }
        }
    }
    return difference != 0;
}

bool DissasmCodeZone::CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference)
{
    difference = 0;
    if (!GetRecursiveZoneByLine(dissasmType, zoneLine, collapse, difference))
        return false;

    if (difference) {
        difference += (int32) this->dissasmType.indexZoneEnd - 1;
    }

    return true;
}

bool DissasmCodeZone::RemoveCollapsibleZone(uint32 zoneLine)
{
    const auto zoneDetailsData = dissasmType.GetRemoveZoneCollapsibleDetails(zoneLine);
    if (!zoneDetailsData.zone)
        return false;
    if (!dissasmType.RemoveCollapsibleZone(zoneLine, zoneDetailsData))
        return false;
    ResetTypesReferenceList();
    return true;
}

void DissasmCodeZone::ResetZoneCaching()
{
    asmPreCacheData.Clear();
    for (auto& type : types) {
        type.get().asmLinesPassed  = 0;
        type.get().textLinesPassed = 0;
    }
}

bool DissasmCodeZone::AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd)
{
    if (!this->CanAddNewZone(zoneLineStart, zoneLineEnd)) {
        return false;
    }

    if (!dissasmType.AddNewZone(zoneLineStart, zoneLineEnd))
        return false;
    ResetTypesReferenceList();
    return true;
}

bool DissasmCodeInternalType::CanAddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd) const
{
    // TODO: add similar optimization like GetRemoveZoneCollapsibleDetails to end when too big interval is given
    for (const auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLineStart && zoneLineStart < zone.indexZoneEnd) {
            if (zone.indexZoneStart <= zoneLineStart && zoneLineEnd <= zone.indexZoneEnd) {
                if (!zone.name.empty() && zone.indexZoneStart == zoneLineStart && zone.indexZoneEnd == zoneLineEnd)
                    return false;
                return zone.CanAddNewZone(zoneLineStart, zoneLineEnd);
            }
            return false;
        }
    }
    return true;
}

bool DissasmCodeInternalType::AddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd)
{
    Reference<DissasmCodeInternalType> parentZone     = this;
    uint32 indexFound                                 = 0;
    bool doNotDeleteOldZone                           = internalTypes.empty();
    bool hasParent                                    = false;
    std::vector<DissasmCodeInternalType>* zonesHolder = &internalTypes;
    for (auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLineStart && zoneLineEnd <= zone.indexZoneEnd) {
            if (zone.name.empty() && zone.indexZoneStart == zoneLineStart && zone.indexZoneEnd == zoneLineEnd) {
                LocalString<128> zoneName;
                zoneName.SetFormat("Zone-IndexStart %u -IndexEnd %u", zoneLineStart, zoneLineEnd);
                zone.name = zoneName.GetText();
                return true;
            }
            parentZone = &zone;
            if (!zone.name.empty()) {
                zonesHolder        = &zone.internalTypes;
                indexFound         = 0;
                doNotDeleteOldZone = true;
                hasParent          = true;
            }
            break;
        }
        indexFound++;
    }

    LocalString<128> zoneName;
    zoneName.SetFormat("Zone-IndexStart %u -IndexEnd %u", zoneLineStart, zoneLineEnd);

    DissasmCodeInternalType newZone = {};
    newZone.name                    = zoneName.GetText();
    newZone.indexZoneStart          = zoneLineStart;
    newZone.workingIndexZoneStart   = newZone.indexZoneStart;
    newZone.indexZoneEnd            = zoneLineEnd;
    newZone.workingIndexZoneEnd     = newZone.indexZoneEnd;

    // TODO: improve annotations moving
    decltype(annotations) annotationsBefore, annotationCurrent, annotationAfter;
    // TODO: check this ??
    for (const auto& zoneVal : parentZone->annotations.mappings) {
        if (zoneVal.first < zoneLineStart)
            annotationsBefore.insert(zoneVal);
        else if (zoneVal.first >= zoneLineStart && zoneVal.first < zoneLineEnd)
            annotationCurrent.insert(zoneVal);
        else if (zoneVal.first >= zoneLineEnd)
            annotationAfter.insert(zoneVal);
    }

    // TODO: improve annotations moving
    uint32 commentsZoneLineStart = zoneLineStart - 1;
    if (zoneLineStart == 0)
        commentsZoneLineStart = 0;
    uint32 commentsZoneLineEnd = zoneLineEnd - 1;
    decltype(commentsData.comments) commentsBefore, commentsCurrent, commentsAfter;
    for (const auto& commentsVal : parentZone->commentsData.comments) {
        if (commentsVal.first < commentsZoneLineStart)
            commentsBefore.insert(commentsVal);
        else if (commentsVal.first >= commentsZoneLineStart && commentsVal.first < commentsZoneLineEnd)
            commentsCurrent.insert(commentsVal);
        else if (commentsVal.first >= commentsZoneLineEnd)
            commentsAfter.insert(commentsVal);
    }

    newZone.annotations           = std::move(annotationCurrent);
    newZone.commentsData.comments = std::move(commentsCurrent);

    DissasmCodeInternalType firstZone = {};
    firstZone.indexZoneStart          = std::min(parentZone->indexZoneStart, zoneLineStart);
    firstZone.workingIndexZoneStart   = firstZone.indexZoneStart;
    firstZone.annotations             = std::move(annotationsBefore);
    firstZone.commentsData.comments   = std::move(commentsBefore);

    DissasmCodeInternalType lastZone = {};

    if (indexFound > 0) {
        const auto& prevZone = internalTypes[indexFound - 1];
        firstZone.UpdateDataLineFromPrevious(prevZone);
    }
    if (hasParent) {
        firstZone.beforeAsmLines  = parentZone->beforeAsmLines;
        firstZone.beforeTextLines = parentZone->beforeTextLines;
    }

    if (zoneLineStart == parentZone->indexZoneStart) { // first line
        firstZone.name                = newZone.name;
        firstZone.indexZoneEnd        = zoneLineEnd;
        firstZone.workingIndexZoneEnd = firstZone.indexZoneEnd;
        firstZone.annotations.populate_annotations_from_other_storage(newZone.annotations);
        firstZone.commentsData.comments.insert(newZone.commentsData.comments.begin(), newZone.commentsData.comments.end());
        // newZone.UpdateDataLineFromPrevious(firstZone);
        lastZone.UpdateDataLineFromPrevious(firstZone);
        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(firstZone));
    } else {
        firstZone.indexZoneEnd        = zoneLineStart;
        firstZone.workingIndexZoneEnd = firstZone.indexZoneEnd;

        newZone.UpdateDataLineFromPrevious(firstZone);
        lastZone.UpdateDataLineFromPrevious(newZone);

        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(firstZone));
        zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(newZone));
    }

    lastZone.annotations           = std::move(annotationAfter);
    lastZone.commentsData.comments = std::move(commentsAfter);
    lastZone.indexZoneEnd          = indexZoneEnd;
    lastZone.workingIndexZoneEnd   = lastZone.indexZoneEnd;
    if (zoneLineEnd == indexZoneEnd) {
        lastZone.indexZoneStart        = zoneLineStart;
        lastZone.workingIndexZoneStart = lastZone.indexZoneStart;
    } else {
        lastZone.indexZoneStart        = zoneLineEnd;
        lastZone.workingIndexZoneStart = lastZone.indexZoneStart;
        lastZone.indexZoneEnd          = indexZoneEnd;
        lastZone.workingIndexZoneEnd   = lastZone.indexZoneEnd;

        if (indexFound + 1 < internalTypes.size()) {
            auto& nextZone               = internalTypes[indexFound + 1];
            lastZone.indexZoneEnd        = nextZone.indexZoneStart;
            lastZone.workingIndexZoneEnd = lastZone.indexZoneEnd;
        }
    }

    zonesHolder->insert(zonesHolder->begin() + indexFound++, std::move(lastZone));

    if (indexFound < internalTypes.size() && !doNotDeleteOldZone) {
        internalTypes.erase(internalTypes.begin() + indexFound);
    }
    return true;
}

DissasmCodeRemovableZoneDetails DissasmCodeInternalType::GetRemoveZoneCollapsibleDetails(uint32 zoneLine, uint32 depthLevel)
{
    if (internalTypes.empty())
        return {};
    if (zoneLine > internalTypes.back().indexZoneEnd)
        return {};
    uint32 zoneIndex = 0;
    for (auto& zone : internalTypes) {
        if (zone.indexZoneStart <= zoneLine && zoneLine < zone.indexZoneEnd) {
            if (!zone.name.empty() && !zone.isCollapsed) {
                return { &zone, depthLevel == 0 ? this : nullptr, zoneIndex };
            }
            const auto result = zone.GetRemoveZoneCollapsibleDetails(zoneLine, depthLevel + 1);
            if (!result.zone)
                return {};
            if (result.parent)
                return result;
            return { result.zone, &zone, result.zoneIndex };
        }
        zoneIndex++;
    }
    return {};
}

bool DissasmCodeInternalType::RemoveCollapsibleZone(uint32 zoneLine, const DissasmCodeRemovableZoneDetails& removableDetails)
{
    auto& parentInternalTypes = removableDetails.parent->internalTypes;
    if (parentInternalTypes.size() == 2) { // last two zone, we clear them
        for (const auto& zone : parentInternalTypes) {
            if (zone.isCollapsed)
                return false; // TODO: remove special case for the last two zones when one of them is collapsed
        }
        parentInternalTypes.clear();
        return true;
    }

    // special case: when we have 3 zones and only the middle one is collpasible
    // after we remove it, we need to merge the first and the last one since they are not collapsible
    // so having only 3 zones => we can remove all since we never have only one zone
    if (parentInternalTypes.size() == 3 && removableDetails.zoneIndex == 1) {
        for (const auto& zone : parentInternalTypes) {
            if (zone.isCollapsed)
                return false; // TODO: remove special case when we have 3 zones and only the middle one is collapsible and some of them are collapsed
        }
        if (parentInternalTypes[0].name.empty() && parentInternalTypes[2].name.empty()) {
            parentInternalTypes.clear();
            return true;
        }
    }

    // TODO: optimize this
    std::vector<uint32> indexesToRemove;
    indexesToRemove.reserve(2);

    DissasmCodeInternalType* zoneToUpdate = removableDetails.zone;
    if (removableDetails.zoneIndex > 0)
        zoneToUpdate = &parentInternalTypes[removableDetails.zoneIndex - 1];

    if (removableDetails.zoneIndex < static_cast<uint32>(parentInternalTypes.size()) - 1) {
        const auto& nextZone = parentInternalTypes[removableDetails.zoneIndex + 1];
        if (nextZone.name.empty()) {
            {
                indexesToRemove.push_back(removableDetails.zoneIndex + 1);
                zoneToUpdate->indexZoneEnd        = nextZone.indexZoneEnd;
                zoneToUpdate->workingIndexZoneEnd = nextZone.workingIndexZoneEnd;
                zoneToUpdate->annotations.populate_annotations_from_other_storage(nextZone.annotations);
            }
        }
    }
    if (removableDetails.zoneIndex > 0) {
        const auto& prevZone = parentInternalTypes[removableDetails.zoneIndex - 1];
        if (prevZone.name.empty()) {
            {
                indexesToRemove.push_back(removableDetails.zoneIndex);
                zoneToUpdate->indexZoneStart        = prevZone.indexZoneStart;
                zoneToUpdate->workingIndexZoneStart = prevZone.workingIndexZoneStart;
                zoneToUpdate->annotations.populate_annotations_from_other_storage(prevZone.annotations);
            }
        }
    }
    for (const auto index : indexesToRemove) {
        parentInternalTypes.erase(parentInternalTypes.begin() + index);
    }

    zoneToUpdate->name.clear();

    return true;
}

#pragma endregion

constexpr uint32 BTN_CLOSE_ID   = 0;
constexpr uint32 BTN_APPLY_ID   = 1;
constexpr uint32 RADIO_GROUP_ID = 2;

class QueryFunctionNameDialog : public AppCUI::Controls::Window, Handlers::OnCheckInterface
{
    uint32 selectedIndex;

  public:
    QueryFunctionNameDialog(const std::vector<std::string>& names) : Window("Name selector", "d:c,w:30%,h:40%", WindowFlags::Sizeable)
    {
        selectedIndex    = UINT32_MAX;
        uint32 yLocation = 1;
        LocalString<32> location;

        int32 radioBoxIndex = 0;
        for (auto& name : names) {
            location.SetFormat("x:5,y:%d,w:50,h:1", yLocation);
            auto radioBox                 = Factory::RadioBox::Create(this, name, location.GetText(), RADIO_GROUP_ID, radioBoxIndex++);
            radioBox->Handlers()->OnCheck = this;
            yLocation += 2;
        }

        location.SetFormat("x:15%,y:%d,w:10,h:1", yLocation);
        Factory::Button::Create(this, "Apply", location.GetText(), BTN_APPLY_ID);

        location.SetFormat("x:25%,y:%d,w:10,h:1", yLocation);
        Factory::Button::Create(this, "Close", location.GetText(), BTN_CLOSE_ID);
    }

    virtual void OnCheck(Reference<Controls::Control> control, bool value) override
    {
        selectedIndex = control->GetControlID();
    }

    bool IsValidApply() const
    {
        if (selectedIndex == UINT32_MAX) {
            AppCUI::Dialogs::MessageBox::ShowWarning("Make selection", "Please select a name before applying it");
            return false;
        }
        return true;
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (Window::OnEvent(control, eventType, ID))
            return true;
        if (eventType == Event::ButtonClicked) {
            if (ID == BTN_CLOSE_ID) {
                selectedIndex = UINT32_MAX;
                Exit(Dialogs::Result::Ok);
                return true;
            }
            // BTN_APPLY_ID
            if (IsValidApply())
                Exit(Dialogs::Result::Ok);
            return true;
        }
        return false;
    }
    std::optional<uint32> GetSelectedIndex() const
    {
        if (selectedIndex == UINT32_MAX)
            return {};
        return selectedIndex;
    }
};

constexpr uint32 QueryShowCodeDialog_BTN_CLOSE                  = 0;
constexpr uint32 QueryShowCodeDialog_BTN_OPEN_OR_APPLY_COMMENTS = 0;

inline void ltrim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

// trim from end (in place)
inline void rtrim(std::string& s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

inline void trim(std::string& s)
{
    rtrim(s);
    ltrim(s);
}

std::string wrapText(const std::string& code, size_t windowWidth)
{
    String wrappedLines;
    if (!wrappedLines.Realloc((uint32) code.length()))
        return {};
    std::istringstream codeStream(code);
    std::string line;
    std::string word;
    LocalString<2048> currentLine;

    bool lastLineWasEmpty = false;
    while (std::getline(codeStream, line)) {
        if (line.empty()) {
            if (currentLine.Len()) {
                wrappedLines.AddFormat("%s\n\n", currentLine.GetText());
                currentLine.Clear();
            } else {
                wrappedLines.AddFormat("\n");
            }
            lastLineWasEmpty = true;
            continue;
        }
        lastLineWasEmpty = false;
        std::istringstream lineStream(line);
        while (lineStream >> word) {
            if (currentLine.Len() + word.length() + 1 > windowWidth) {
                wrappedLines.AddFormat("%s\n", currentLine.GetText());
                currentLine.SetFormat("%s", word.data());
            } else {
                if (currentLine.Len() && currentLine[currentLine.Len() - 1u] != '\n') {
                    currentLine.AddChar(' ');
                }
                currentLine.AddFormat("%s", word.data());
            }
        }
    }
    if (currentLine.Len()) {
        wrappedLines.AddFormat("%s\n", currentLine.GetText());
    }
    std::string result = wrappedLines.GetText();
    return result;
}

void TextHighligh(Reference<Control>, Graphics::Character* chars, uint32 charsCount)
{
    Graphics::Character* end   = chars + charsCount;
    Graphics::Character* start = nullptr;
    // ColorPair col;
    while (chars < end) {
        if (chars->Code == '*') // Check for '**'
        {
            start = chars;
            chars++;
            if ((chars < end) && (chars->Code == '*')) // Confirm second '*'
            {
                chars++;
                start += 2; // Move past '**'
                while ((chars < end) && !(chars->Code == '*' && (chars + 1 < end) && (chars + 1)->Code == '*')) {
                    chars->Color = ColorPair{ Color::Yellow, Color::Transparent }; // Color for '**...**'
                    chars++;
                }
                if (chars < end && (chars + 1 < end) && (chars + 1)->Code == '*') {
                    chars += 2; // Move past closing '**'
                }
            }
        } else if (chars->Code == '`') // Check for backticks '`'
        {
            start = chars;
            chars++;
            while ((chars < end) && (chars->Code != '`')) {
                chars->Color = ColorPair{ Color::Green, Color::Transparent }; // Color for `...`
                chars++;
            }
            if (chars < end && chars->Code == '`') {
                chars++; // Move past closing backtick
            }
        } else if (chars->Code == '"') // Check for double quotes '"'
        {
            start = chars;
            chars++;
            while ((chars < end) && (chars->Code != '"')) {
                chars->Color = ColorPair{ Color::DarkRed, Color::Transparent }; // Color for "..."
                chars++;
            }
            if (chars < end && chars->Code == '"') {
                chars++; // Move past closing double quote
            }
        } else {
            chars++; // Move to the next character for non-matching cases
        }
    }
}

class QueryShowCodeDialog : public AppCUI::Controls::Window
{
    Reference<AppCUI::Controls::TextArea> codeArea;
    std::vector<std::pair<std::string, std::string>> result;
    bool OpenOrApply = false;
    bool isDecompilation;
    std::string codeString;

  public:
    QueryShowCodeDialog(const std::string& code, std::string_view windowName, bool decompile, bool needComments)
        : Window(windowName, "d:c,w:80%,h:80%", WindowFlags::Sizeable)
    {
        codeArea = Factory::TextArea::Create(this, "", "l:1,t:2,r:1,b:5", TextAreaFlags::SyntaxHighlighting | TextAreaFlags::ScrollBars);
        codeArea->Handlers()->OnTextColor = TextHighligh;

        std::string wrappedCode = wrapText(code, codeArea->GetWidth() - 2);
        codeArea->SetText(wrappedCode);
        isDecompilation = decompile;

        if (!decompile) {
            result.reserve(16);

            std::istringstream stream(code);
            std::string line;
            bool foundCommentsZone = false;

            while (std::getline(stream, line)) {
                if (!foundCommentsZone) {
                    if (line.find("CommentsZoneExplained") != std::string::npos) {
                        foundCommentsZone = true;
                    }
                    continue;
                }
                const size_t pos = line.rfind('#');
                if (pos != std::string::npos) {
                    std::string codePart = line.substr(0, pos);
                    rtrim(codePart);

                    std::string commentPart = line.substr(pos + 1);
                    trim(commentPart);
                    result.emplace_back(codePart, commentPart);
                }
            }
        }

        Factory::Button::Create(this, "Close", "l:45%,b:1,w:10", QueryShowCodeDialog_BTN_CLOSE);

        if (!decompile && result.empty()) {
            if (needComments)
                Factory::Label::Create(this, "No comments found", "l:10,b:3,w:25");
            return;
        }
        const char* labelText = decompile ? "Open in new tab" : "Apply comments found";
        Factory::Label::Create(this, labelText, "l:10,b:3,w:25");

        const char* buttonText = decompile ? "Open" : "Apply";
        auto btn               = Factory::Button::Create(this, buttonText, "l:35,b:2,w:10", QueryShowCodeDialog_BTN_OPEN_OR_APPLY_COMMENTS);

        if (decompile) {
            auto codeStart = code.find("```");
            if (codeStart == std::string::npos) {
                btn->SetEnabled(false);
                return;
            }
            codeStart += 3;
            if (codeStart + 4 >= code.size()) {
                btn->SetEnabled(false);
                return;
            }
            if (code[codeStart] == 'c')
                codeStart++;
            if (code[codeStart] == '+')
                codeStart++;
            if (code[codeStart] == '+')
                codeStart++;
            auto codeEnd = code.find("```", codeStart + 3);
            if (codeEnd == std::string::npos) {
                btn->SetEnabled(false);
                return;
            }
            codeString = code.substr(codeStart, codeEnd - codeStart - 3);
        }
    }
    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (Window::OnEvent(control, eventType, ID))
            return true;
        if (eventType == Event::ButtonClicked) {
            if (ID == QueryShowCodeDialog_BTN_OPEN_OR_APPLY_COMMENTS)
                OpenOrApply = true;
            Exit(Dialogs::Result::Ok);
            return true;
        }
        return false;
    }

    const std::vector<std::pair<std::string, std::string>>& GetAppliedComments() const
    {
        return result;
    }

    std::string GetDecompiledCode() const
    {
        return codeString;
    }

    bool GetOpenOrApply() const
    {
        return OpenOrApply;
    }
};

std::vector<std::string> findMostCommonNames(const std::vector<std::string>& names, size_t numToReturn)
{
    if (names.empty() || numToReturn == 0) {
        return {};
    }

    std::unordered_map<std::string, int> nameFrequency;
    for (const auto& name : names) {
        nameFrequency[name]++;
    }

    std::vector<std::pair<std::string, int>> nameFreqPairs;
    for (const auto& entry : nameFrequency) {
        nameFreqPairs.emplace_back(entry);
    }

    std::sort(nameFreqPairs.begin(), nameFreqPairs.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });

    std::vector<std::string> result;
    for (size_t i = 0; i < std::min(numToReturn, nameFreqPairs.size()); ++i) {
        result.push_back(nameFreqPairs[i].first);
    }

    if (result.size() < numToReturn) {
        for (const auto& name : names) {
            if (std::find(result.begin(), result.end(), name) == result.end()) {
                result.push_back(name);
                if (result.size() == numToReturn) {
                    break;
                }
            }
        }
    }

    return result;
}

// calls to imported functions keep the API name in the mapping instead of the operands
static const char* GetAssistantOperands(const DissasmAsmPreCacheLine& line)
{
    if (line.op_str)
        return line.op_str;
    if (line.mapping)
        return static_cast<const MemoryMappingEntry*>(line.mapping)->name.c_str();
    return "";
}

void Instance::QuerySmartAssistantX86X64(
      DissasmCodeZone* codeZone, uint32 line, const QuerySmartAssistantParams& queryParams, QueryTypeSmartAssistant queryType)
{
    assert(line >= 2); // 2 for title and menu
    line -= 2;

    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.settings = settings.get();
    params.asmData  = &asmData;
    params.dli      = nullptr;
    params.zone     = codeZone;

    LocalString<128> displayPrompt;

    displayPrompt.SetFormat(queryParams.displayPrompt.data());
    if (!queryParams.mnemonicStarsWith.empty()) {
        auto data = codeZone->GetCurrentAsmLine(line, obj, &params);
        if (memcmp(data.mnemonic, queryParams.mnemonicStarsWith.data(), queryParams.mnemonicStarsWith.size()) != 0) {
            Dialogs::MessageBox::ShowNotification("Warning", queryParams.mnemonicStartsWithError);
            return;
        }
        if (queryParams.displayPromptUsesMnemonicParam)
            displayPrompt.AddFormat("%s", data.mnemonic);
    }

    const auto assistantInterface = queryInterface->GetSmartAssistantInterface();
    if (!assistantInterface) {
        return;
    }

    uint32 actualLineInDocument = line + codeZone->startLineIndex + 1; // +1 for the function
    uint32 lineIndex            = 0;
    uint32 currentDissasmLine   = line + 1; // +1 for the function

    std::vector<std::string> apisInstructions;
    apisInstructions.reserve(DISSASM_ASSISTANT_MAX_API_CALLS / 2);

    std::vector<std::string> assemblyLines;
    apisInstructions.reserve(DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT);

    LocalString<64> currentBuffer;
    std::string comment;
    while (actualLineInDocument < codeZone->endingLineIndex && lineIndex < DISSASM_ASSISTANT_MAX_DISSASM_LINES_ANALYSED) {
        auto currentLine = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
        if (currentLine.size > 0) {
            currentBuffer.SetFormat("   %s %s", currentLine.mnemonic, GetAssistantOperands(currentLine));
            if (assemblyLines.size() < DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT) {
                if (queryParams.includeComments) {
                    if (codeZone->GetComment(currentDissasmLine, comment)) {
                        currentBuffer.AddFormat(" ; %s", comment.data());
                    }
                }
                assemblyLines.emplace_back(currentBuffer.GetText());
            } else if (currentLine.mnemonic[0] == 'c' && memcmp(currentLine.mnemonic, "call", 4) == 0) {
                if (apisInstructions.size() < DISSASM_ASSISTANT_MAX_API_CALLS)
                    apisInstructions.emplace_back(currentBuffer.GetText());
            }
        } else {
            if (assemblyLines.size() < DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT) {
                // labels are sent by name, the local variables with their definition
                const bool isVariable = currentLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition && currentLine.op_str;
                assemblyLines.emplace_back(isVariable ? currentLine.op_str : currentLine.mnemonic);
            }
        }
        if (queryParams.stopAtTheEndOfTheFunction && *(uint32*) currentLine.mnemonic == retOP)
            break;
        actualLineInDocument++;
        lineIndex++;
        currentDissasmLine++;
    }
    if (assemblyLines.empty()) {
        Dialogs::MessageBox::ShowNotification("Warning", "No instructions found!");
        return;
    }

    LocalString<DISSASM_ASSISTANT_MAX_BYTE_TO_SEND> bufferToSendToAssistant;
    bufferToSendToAssistant.AddFormat("%s", queryParams.prompt.data());
    bufferToSendToAssistant.AddFormat("Here is x86 assembly code: \n");
    // bufferToSendToAssistant.SetFormat("I am going to provide a list of assembly instructions and some OS functions used. The list of instructions is: ");
    // bufferToSendToAssistant.SetFormat("I am going to provide a list of assembly instructions and some OS functions used. The list of instructions is: ");
    for (const auto& asmLine : assemblyLines) {
        bufferToSendToAssistant.AddFormat("%s\n", asmLine.data());
    }
    if (!apisInstructions.empty()) {
        bufferToSendToAssistant.AddFormat("The function also makes these API calls: ");
        for (const auto& apiCall : apisInstructions) {
            bufferToSendToAssistant.AddFormat("%s\n", apiCall.data());
        }
    }

    // bufferToSendToAssistant.AddFormat("%s", queryParams.prompt.data());
    auto textData = bufferToSendToAssistant.GetText();

    bool isSuccess = false;
    auto result    = assistantInterface->AskSmartAssistant(textData, displayPrompt, isSuccess);
    if (!isSuccess) {
        bufferToSendToAssistant.SetFormat("The assistant did not provide a result: %s", result.data());
        Dialogs::MessageBox::ShowNotification("Warning", bufferToSendToAssistant.GetText());
        return;
    }

    // std::string_view sv = result;
    if (queryType == QueryTypeSmartAssistant::FunctionName) {
        uint32 retriesNumber            = queryInterface->GetPromptRetriesCount();
        bool isSingleRetry              = retriesNumber == 1;
        const uint32 namesToShowReserve = DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST * retriesNumber;
        std::vector<std::string> namesToShow;
        namesToShow.reserve(namesToShowReserve);

        std::vector<std::string> names;
        names.reserve(DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST);

        while (retriesNumber) {
            std::stringstream ss(result);
            std::string name;

            while (std::getline(ss, name, ',')) {
                trim(name);
                names.push_back(name);
            }

            namesToShow.insert(namesToShow.end(), names.begin(), names.end());

            if (--retriesNumber == 0)
                break;
            names.clear();
            result = assistantInterface->AskSmartAssistant(textData, displayPrompt, isSuccess);
            if (!isSuccess) {
                bufferToSendToAssistant.SetFormat("The assistant did not provide a result: %s", result.data());
                Dialogs::MessageBox::ShowNotification("Warning", bufferToSendToAssistant.GetText());
                return;
            }
        }

        if (!isSingleRetry) {
            namesToShow = findMostCommonNames(namesToShow, DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST);
        }

        // if (name.size() != DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST) {
        //     Dialogs::MessageBox::ShowNotification("Warning", "The assistant did not provide the expected number of names!");
        //     return;
        // }

        QueryFunctionNameDialog dlg(namesToShow);
        dlg.Show();

        auto indexResult = dlg.GetSelectedIndex();
        // the dialog shows namesToShow (all the retries merged), `names` holds only the last answer
        if (indexResult.has_value() && indexResult.value() < namesToShow.size()) {
            auto sv = std::string_view(namesToShow[indexResult.value()]);
            codeZone->TryRenameLine(line, obj, &sv, nullptr);
        }
    } else if (queryType == QueryTypeSmartAssistant::ExplainCode) {
        QueryShowCodeDialog dlg(result, "Code explanation", false, true);
        dlg.Show();

        if (dlg.GetOpenOrApply()) {
            const auto& resultValue = dlg.GetAppliedComments();
            if (resultValue.empty()) {
                Dialogs::MessageBox::ShowNotification("Warning", "No comments found!");
                return;
            }
            currentDissasmLine = line + 1;
            auto initialLine   = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
            if (initialLine.size == 0) {
                Dialogs::MessageBox::ShowNotification("Warning", "No instructions found!");
                return;
            }
            currentBuffer.SetFormat("%s %s", initialLine.mnemonic, GetAssistantOperands(initialLine));
            if (resultValue[0].first != currentBuffer.GetText()) {
                Dialogs::MessageBox::ShowNotification("Warning", "The assistant did not provide the expected comments!");
            }
            for (const auto& [asmLine, comment] : resultValue) {
                do {
                    auto currentLine = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
                    if (currentLine.op_str && currentLine.localVariableKind != DissasmAsmPreCacheLine::LocalVariableKind::Definition)
                        break;
                    if (++currentDissasmLine >= codeZone->endingLineIndex)
                        return; // todo: check in the future
                } while (true);

                std::string initialComment;
                if (codeZone->GetComment(currentDissasmLine, initialComment)) {
                    bufferToSendToAssistant.SetFormat("%s; %s", comment.data(), initialComment.data());
                    initialComment = bufferToSendToAssistant.GetText();
                } else {
                    initialComment = comment;
                }
                codeZone->AddOrUpdateComment(currentDissasmLine, initialComment, false);
                currentDissasmLine++;
            }
            selection.Clear();
        }
    } else if (queryType == QueryTypeSmartAssistant::ConvertToHighLevel) {
        QueryShowCodeDialog dlg(result, "Code explanation", true, false);
        dlg.Show();

        if (dlg.GetOpenOrApply()) {
            LocalUnicodeStringBuilder<512> fullPath;
            fullPath.Add(this->obj->GetPath());
            fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
            fullPath.Add("temp_dissasm");

            auto code         = dlg.GetDecompiledCode();
            BufferView buffer = { code.data(), code.size() };
            GView::App::OpenBuffer(buffer, "temp_decompile.cpp", fullPath, GView::App::OpenMethod::Select, "CPP");
        }
    } else if (queryType == QueryTypeSmartAssistant::MitreTechiques) {
        QueryShowCodeDialog dlg(result, "MITRE techniques", false, false);
        dlg.Show();
    } else if (queryType == QueryTypeSmartAssistant::FunctionNameAndExplanation) {
        QueryShowCodeDialog dlg(result, "Code explanation", false, true);
        dlg.Show();
    }

    codeZone->asmPreCacheData.Clear();
}