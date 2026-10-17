#include "DissasmViewer.hpp"
#include "DissasmX86.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include "DissasmX86LocalVariables.hpp"
#include "X86InstructionInfo.hpp"
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

#ifdef _MSC_VER
#pragma warning(disable : 4996) // The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name
#endif

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
constexpr uint32 textColumnIndicatorArrowLinesSpace = DissasmAsmPreCacheLine::ARROW_COLUMNS;
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
    uint32 val;
    memcpy(&val, holder.GetText(), sizeof(val));

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

struct ArrowCellCharacter {
    SpecialChars special; // drawn on the screen, from the character set of the terminal
    char ascii;           // kept in the line text (selection copy, column computations)
};

// indexed by the ArrowUp | ArrowDown | ArrowLeft | ArrowRight sides of an arrow cell
constexpr ArrowCellCharacter ARROW_CELL_CHARACTERS[16] = {
    { SpecialChars::Block0, ' ' },                         // none
    { SpecialChars::BoxVerticalSingleLine, '|' },          // up
    { SpecialChars::BoxVerticalSingleLine, '|' },          // down
    { SpecialChars::BoxVerticalSingleLine, '|' },          // up, down
    { SpecialChars::BoxHorizontalSingleLine, '-' },        // left
    { SpecialChars::BoxBottomRightCornerSingleLine, '+' }, // up, left
    { SpecialChars::BoxTopRightCornerSingleLine, '+' },    // down, left
    { SpecialChars::BoxMidleRight, '+' },                  // up, down, left
    { SpecialChars::BoxHorizontalSingleLine, '-' },        // right
    { SpecialChars::BoxBottomLeftCornerSingleLine, '+' },  // up, right
    { SpecialChars::BoxTopLeftCornerSingleLine, '+' },     // down, right
    { SpecialChars::BoxMidleLeft, '+' },                   // up, down, right
    { SpecialChars::BoxHorizontalSingleLine, '-' },        // left, right
    { SpecialChars::BoxMidleBottom, '+' },                 // up, left, right
    { SpecialChars::BoxMidleTop, '+' },                    // down, left, right
    { SpecialChars::BoxCrossSingleLine, '+' },             // up, down, left, right
};

inline ArrowCellCharacter GetArrowCellCharacter(uint8 cell)
{
    if (cell & DissasmAsmPreCacheLine::ArrowHead)
        return { SpecialChars::TriangleRight, '>' };
    return ARROW_CELL_CHARACTERS[cell & 0x0F];
}

// TODO: to be moved inside plugin for some sort of API for token<->color
// `opStrColumns` (optional) receives the column (inside `cb`) where every character of insn.op_str is drawn
// (UINT32_MAX for the separators that are not drawn at a fixed place)
// `arrowsColumn` (optional) receives the column (inside `cb`) of the first arrow cell
inline void DissasmAddColorsToInstruction(
      DissasmAsmPreCacheLine& insn,
      CharacterBuffer& cb,
      Config& cfg,
      DissasmColors& colors,
      AsmData& data,
      const CodePage& codePage,
      uint64 addressPadding             = 0,
      std::vector<uint32>* opStrColumns = nullptr,
      uint32* arrowsColumn              = nullptr)
{
    // TODO: replace CharacterBuffer with Canvas;

    const MemoryMappingEntry* mappingPtr = (const MemoryMappingEntry*) insn.mapping;
    // cb.Clear();

    // TODO: Unicode --> alt caracter
    // AppCUI::Graphics:: GetCharacterCode
    // TODO: in loc de label jmp_address:
    LocalString<128> string;
    // the address column: VA / RVA / file offset (addressPadding is the address of the first decoded instruction)
    string.SetFormat("0x%08" PRIx64, insn.address + addressPadding);
    string.AddChars(' ', string.Len() + 1u < addressTotalLength ? addressTotalLength - 1u - string.Len() : 1u);
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
            if (i == opCodesGroupsShown - 1 && insn.size > opCodesGroupsShown) {
                cb.Add(".. ", colors.AsmDefaultColor); // the instruction is longer than the column: the last bytes are not shown
                continue;
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

    // the ASCII form of the arrows, the screen shows their box characters (see DrawDissasmX86AndX64CodeZone)
    if (cfg.EnableDeepScanDissasmOnStart) {
        for (uint32 i = 0; i < textColumnIndicatorArrowLinesSpace; i++)
            if (insn.arrowCells[i] != DissasmAsmPreCacheLine::ArrowNone)
                string[i] = GetArrowCellCharacter(insn.arrowCells[i]).ascii;
    }

    if (arrowsColumn)
        *arrowsColumn = cb.Len();
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
        if (opStrColumns)
            opStrColumns->assign(op_str.size(), UINT32_MAX);
        auto recordColumns = [opStrColumns, &cb](size_t opStrStart, size_t count) {
            if (!opStrColumns)
                return;
            for (size_t i = 0; i < count && opStrStart + i < opStrColumns->size(); i++)
                (*opStrColumns)[opStrStart + i] = cb.Len() + static_cast<uint32>(i);
        };
        // TODO: add checks to verify  lambdaBuffer.Set, for x86 it's possible to be fine but not for other languages
        LocalString<32> lambdaBuffer;
        auto checkValidAndAdd = [&cb, &colors, &lambdaBuffer, &data](std::string_view token) {
            lambdaBuffer.Clear();
            // numbers: hexadecimal (0x...) or decimal (small values, or switched to decimal with the H key)
            if (!token.empty() && token[0] >= '0' && token[0] <= '9') {
                cb.Add(token.data(), colors.AsmOffsetColor);
                return;
            }
            lambdaBuffer.Set(token.data());
            const ColorPair color = GetASMColorPairByKeyword(token, colors, data);
            cb.Add(token, color);
        };

        if (op_str.length() > 2 && op_str[0] == '0' && op_str[1] == 'x') {
            cb.Add(" ");
            recordColumns(0, op_str.size());
            checkValidAndAdd(op_str);
            return;
        }

        // the local variable used by the instruction ([ebp + var_8]) is the token placed at localVariableNameStart
        const bool hasVariableToken = insn.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Reference && insn.localVariableNameSize > 0;
        size_t tokenStart           = 0;
        LocalString<32> buffer;
        auto addToken = [&]() {
            recordColumns(tokenStart, buffer.Len());
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
            string.SetFormat(" %s", mappingPtr->name.data()); // separated from the mnemonic as the operands are
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

    const csh handle = zone->GetDecodeHandle();
    if (handle == 0) {
        zone->offsetCacheMaxLine = 0;
        if (dli)
            dli->WriteErrorToScreen("ERROR: capstone could not be initialized!");
        return nullptr;
    }

    cs_insn* insn = cs_malloc(handle);

    // cs_disasm_iter takes a size_t (32 bits on 32 bit targets), asmSize is 64 bits: never alias it through a size_t pointer
    size_t remainingSize = static_cast<size_t>(zone->asmSize);
    while (lineDifferences > 0) {
        // undecodable bytes are data lines (db): the same lines as the ones counted by the zone initialization
        const bool decoded = DecodeX86Line(handle, &zone->asmData, &remainingSize, &zone->asmAddress, insn);
        zone->asmSize      = remainingSize;
        if (!decoded) { // no bytes left: the line is after the decoded code
            zone->offsetCacheMaxLine = 0;
            if (dli)
                dli->WriteErrorToScreen("Failed to dissasm!");
            cs_free(insn, 1);
            return nullptr;
        }
        lineDifferences--;
    }
    zone->lastDrawnLine = lineToReach; // the decoding position is right after this line, whoever asked for it

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

// the text found at `offset`, quoted: "ascii" or L"utf-16" (printable characters only, at least DISSASM_MINIMUM_STRING_PREVIEW of them,
// ended by a NUL or by the first non printable character); none when the bytes do not look like a string
std::optional<std::string> TryExtractStringPreview(Reference<GView::Object> obj, const uint64 offset)
{
    const auto stringBuffer = obj->GetData().Get(offset, DISSAM_MAXIMUM_STRING_PREVIEW * 2, false);
    if (!stringBuffer.IsValid() || stringBuffer.GetLength() < 2)
        return {};

    const uint8* data  = stringBuffer.GetData();
    const size_t size  = stringBuffer.GetLength();
    const bool isWide  = data[1] == 0 && data[0] != 0;
    const size_t step  = isWide ? 2 : 1;
    auto isPrintable   = [](uint8 c) { return c >= 32 && c <= 126; };
    std::string text;
    bool truncated = false;
    for (size_t i = 0; i + step <= size; i += step) {
        if (isWide && data[i + 1] != 0)
            break; // not a latin UTF-16 character
        const uint8 c = data[i];
        if (!isPrintable(c))
            break;
        if (text.size() == DISSAM_MAXIMUM_STRING_PREVIEW) {
            truncated = true;
            break;
        }
        text.push_back(static_cast<char>(c));
    }
    if (text.size() < DISSASM_MINIMUM_STRING_PREVIEW)
        return {};
    std::string result = isWide ? "L\"" : "\"";
    result += text;
    if (truncated)
        result += "...";
    result += '"';
    return result;
}

// file offset of an address used by the operands: a VA in 32 bit code (push offset aText / call [__imp_X]), an RVA otherwise
static std::optional<uint64> TranslateOperandAddressToFileOffset(SettingsData* settings, uint64 value, bool isVA)
{
    if (!settings || !settings->offsetTranslateCallback.IsValid())
        return {};
    const auto type   = isVA ? DissasmPEConversionType::VA : DissasmPEConversionType::RVA;
    const auto offset = settings->offsetTranslateCallback->TranslateToFileOffset(value, static_cast<uint32>(type));
    if (offset == static_cast<uint64>(-1))
        return {};
    return offset;
}

// RVA of the first decoded instruction (cachedCodeOffsets[0]): the decoded addresses are relative to it
static uint64 GetCodeStartRVA(SettingsData* settings, const DissasmCodeZone* zone)
{
    return settings->offsetTranslateCallback->TranslateFromFileOffset(zone->cachedCodeOffsets[0].offset, static_cast<uint32>(DissasmPEConversionType::RVA));
}

std::optional<uint32> DissasmGetCurrentAsmLineAndPrepareCodeZone(DissasmCodeZone* zone, uint32 currentLine)
{
    // the instruction index of a shown line; none for a label / variable line, a collapsed zone or a line after the zone
    if (!zone->CanReachAsmLines())
        return {};
    const auto place = zone->DisplayToExpanded(currentLine);
    if (!place.has_value() || place->collapsedZone || zone->IsAnnotationLine(place->expandedLine))
        return {};
    return zone->ExpandedToInstructionIndex(place->expandedLine);
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
    // numbers the user switched to decimal (H key)
    const uint32 decimalMask = zone ? zone->GetDecimalOperandsMask(address) : 0u;

    if (!variable) {
        if (decimalMask != 0) {
            const auto formatted = FormatOperandNumbers(text, decimalMask);
            op_str               = portable_strdup(formatted.c_str());
            op_str_size          = static_cast<uint32>(formatted.size());
            return;
        }
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
    if (decimalMask != 0)
        rewritten = FormatOperandNumbers(rewritten, decimalMask, &localVariableNameStart);

    op_str                = portable_strdup(rewritten.c_str());
    op_str_size           = static_cast<uint32>(rewritten.size());
    localVariableKind     = LocalVariableKind::Reference;
    localVariableFunction = function->startAddress;
    localVariableOffset   = frameOperand.frameOffset;
    localVariableNameSize = static_cast<uint32>(variable->name.size());
}

// the import (memory mapping, keyed by the RVA of its slot) used by the operands of a call / jmp: [rip + 0x...] on x64, the VA of the
// slot ([0x402010]) on x86
static const MemoryMappingEntry* FindOperandsMemoryMapping(DissasmInsnExtractLineParams& params, const X86OperandsInfo& operands)
{
    const auto& mappings = params.settings->memoryMappings;
    if (mappings.empty())
        return nullptr;
    auto find = [&mappings](uint64 key) -> const MemoryMappingEntry* {
        const auto it = mappings.find(key);
        return it != mappings.end() ? &it->second : nullptr;
    };

    // the plugins without an offset translation (RVA) do not set the callback: only an absolute address can be looked up as it is
    if (!params.settings->offsetTranslateCallback.IsValid())
        return operands.absoluteMemory.has_value() ? find(operands.absoluteMemory.value()) : nullptr;

    if (operands.ripTarget.has_value()) // the decoded addresses are relative to the first decoded instruction
        return find(GetCodeStartRVA(params.settings, params.zone) + operands.ripTarget.value());
    if (operands.absoluteMemory.has_value()) {
        const auto offset = TranslateOperandAddressToFileOffset(params.settings, operands.absoluteMemory.value(), true);
        if (!offset.has_value())
            return nullptr;
        return find(params.settings->offsetTranslateCallback->TranslateFromFileOffset(offset.value(), static_cast<uint32>(DissasmPEConversionType::RVA)));
    }
    return nullptr;
}

// the data referenced by the operands, shown as an automatic comment (never saved): the import loaded by mov rax, [rip + 0x...] or the
// string of lea rcx, [rip + 0x...] on x64, the string of push / mov offset aText (an immediate VA) on x86
static void AddReferencedDataComment(DissasmAsmPreCacheLine& line, const cs_insn& insn, const X86OperandsInfo& operands, DissasmInsnExtractLineParams& params)
{
    const auto settings = params.settings;
    if (!settings->offsetTranslateCallback.IsValid() || params.zone->cachedCodeOffsets.empty())
        return;

    std::optional<uint64> fileOffset;
    if (params.zone->Is64BitCode()) {
        if (!operands.ripTarget.has_value())
            return;
        const uint64 rva   = GetCodeStartRVA(settings, params.zone) + operands.ripTarget.value();
        const auto mapping = settings->memoryMappings.find(rva);
        if (mapping != settings->memoryMappings.end()) {
            line.autoComment = mapping->second.name;
            return;
        }
        if (insn.id != X86_INS_LEA)
            return; // the other instructions read / write the data (a variable, a pointer), only lea takes the address of a string
        fileOffset = TranslateOperandAddressToFileOffset(settings, rva, false);
    } else {
        // the immediates only: a memory operand ([0x403000]) reads a variable, it is not the string itself
        for (const uint64 value : operands.immediates) {
            if (value < 0x10000)
                continue; // small values are counters, sizes or flags
            fileOffset = TranslateOperandAddressToFileOffset(settings, value, true);
            if (fileOffset.has_value())
                break;
        }
    }
    if (!fileOffset.has_value() || fileOffset.value() >= params.obj->GetData().GetSize())
        return;
    auto text = TryExtractStringPreview(params.obj, fileOffset.value());
    if (text.has_value())
        line.autoComment = std::move(text.value());
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

    SetMnemonic(insn->mnemonic);

    if (!params.settings || !params.asmData) {
        SetOperands(insn->op_str, params.zone);
        return true;
    }

    // the meaning of the instruction from the capstone details (groups, operands), not from its text
    const auto flow     = GetX86Flow(*insn);
    const auto operands = GetX86OperandsInfo(*insn, params.zone->Is64BitCode());
    if (flow == X86Flow::Call)
        flags = DissasmAsmPreCacheLine::InstructionFlag::CallFlag;
    else if (flow == X86Flow::Jump || flow == X86Flow::ConditionalJump)
        flags = DissasmAsmPreCacheLine::InstructionFlag::JmpFlag;
    else if (insn->id == X86_INS_PUSH)
        flags = DissasmAsmPreCacheLine::InstructionFlag::PushFlag;
    else {
        SetOperands(insn->op_str, params.zone);
#ifndef DISSASM_DISABLE_STRING_PREVIEW
        AddReferencedDataComment(*this, *insn, operands, params); // lea rcx, [rip + 0x...] / mov ecx, 0x403000
#endif
        return true;
    }

    // direct jump / call: the target has the same base as `address`; only a target inside the decoded code has a file offset
    std::optional<uint64> targetFileOffset;
    if (operands.directTarget.has_value() && flags != DissasmAsmPreCacheLine::InstructionFlag::PushFlag) {
        targetFileOffset = params.zone->GetFileOffsetOfAddress(operands.directTarget.value());
        if (targetFileOffset.has_value())
            branchTarget = operands.directTarget; // used by the jump arrows
    }

    bool shouldConsiderCall = false;
    if (flags & (DissasmAsmPreCacheLine::InstructionFlag::CallFlag | DissasmAsmPreCacheLine::InstructionFlag::JmpFlag) && !targetFileOffset.has_value()) {
        // call / jmp through an import slot: call qword ptr [rip + 0x...], jmp dword ptr [0x402010] (import thunks)
        const auto mappingPtr = FindOperandsMemoryMapping(params, operands);
        if (mappingPtr) {
            mapping     = mappingPtr;
            op_str_size = (uint32) mappingPtr->name.size();
            // the arguments are pushed only by 32 bit code (x64 passes them in registers, its pushes save registers)
            if (flags & DissasmAsmPreCacheLine::InstructionFlag::CallFlag && mappingPtr->type == MemoryMappingType::FunctionMapping &&
                !params.zone->Is64BitCode()) {
                // TODO: add functions to the obj AsmData to search for name instead of manually doing CRC
                GView::Hashes::CRC32 crc32{};
                uint32 hash    = 0;
                const bool res = crc32.Init(GView::Hashes::CRC32Type::JAMCRC) &&
                                 crc32.Update(reinterpret_cast<const uint8*>(mappingPtr->name.data()), static_cast<uint32>(mappingPtr->name.size())) &&
                                 crc32.Final(hash);
                if (res) {
                    const auto it = params.asmData->functions.find(hash);
                    if (it != params.asmData->functions.end())
                        params.zone->asmPreCacheData.AnnounceCallInstruction(it->second);
                }
            }
            return true; // the import name is drawn instead of the operands
        }
    }
    if (flags & DissasmAsmPreCacheLine::InstructionFlag::CallFlag) {
        shouldConsiderCall = true;
    } else if (flags & DissasmAsmPreCacheLine::InstructionFlag::PushFlag) {
#ifndef DISSASM_DISABLE_STRING_PREVIEW
        AddReferencedDataComment(*this, *insn, operands, params); // push offset aText
#endif
    }

    if (flags & DissasmAsmPreCacheLine::InstructionFlag::JmpFlag || shouldConsiderCall) {
        if (!targetFileOffset.has_value()) {
            flags = 0;
            if (operands.directTarget.has_value()) {
                // outside of the decoded code (another section): its address (VA), the decoded addresses are relative to the zone
                LocalString<32> target;
                const uint64 addressMask = params.zone->Is64BitCode() ? UINT64_MAX : 0xFFFFFFFFull; // 32 bit addresses wrap around
                target.SetFormat("0x%llx", static_cast<unsigned long long>((params.zone->labelAddressBase + operands.directTarget.value()) & addressMask));
                SetOperands(target.GetText(), params.zone);
            } else {
                SetOperands(insn->op_str, params.zone); // indirect: the operands are shown as they are
            }
            return true;
        }

        // the label of the target, renamed or not (the renames are kept by the root type, the collapsible zones are its children): a
        // function reached by a jmp (tail call, thunk) keeps its sub_ label, a jump target reached by a call its loc_ label
        const auto& rootAnnotations = params.zone->dissasmType.annotations;
        const std::string subName   = params.zone->GetLabelName("sub_", operands.directTarget.value());
        const std::string locName   = params.zone->GetLabelName("loc_", operands.directTarget.value());
        std::string labelName       = rootAnnotations.get_name_change(subName);
        if (labelName.empty())
            labelName = rootAnnotations.get_name_change(locName);
        if (labelName.empty())
            labelName = shouldConsiderCall ? subName : locName;
        op_str      = portable_strdup(labelName.c_str());
        op_str_size = static_cast<uint32>(labelName.size());
    }

    if (!op_str && !mapping)
        SetOperands(insn->op_str, params.zone);
    return true;
}

void DissasmAsmPreCacheData::PrepareLabelArrows()
{
    using Line = DissasmAsmPreCacheLine;
    for (auto& line : cachedAsmLines)
        memset(line.arrowCells, 0, sizeof(line.arrowCells));
    const size_t linesCount = cachedAsmLines.size();
    if (linesCount < 2)
        return;

    const uint64 minimalAddress = cachedAsmLines.front().address;
    const uint64 maximalAddress = cachedAsmLines.back().address;

    // the branches going to the same line share one arrow: its lane spans the target and all its sources
    constexpr uint32 NO_LANE = UINT32_MAX;
    struct Arrow {
        size_t first, last, target;
        uint32 lane;
    };
    std::vector<Arrow> arrows;
    std::vector<size_t> targetOfLine(linesCount, SIZE_MAX);
    for (size_t sourceIndex = 0; sourceIndex < linesCount; sourceIndex++) {
        const auto& source = cachedAsmLines[sourceIndex];
        if (source.flags != Line::InstructionFlag::CallFlag && source.flags != Line::InstructionFlag::JmpFlag)
            continue;
        if (!source.branchTarget.has_value())
            continue;
        const uint64 target = source.branchTarget.value();
        if (target < minimalAddress || target > maximalAddress)
            continue;
        // first visible line placed at the target (its label when it has one); a target in the middle of an instruction has no line
        const auto targetIt = std::find_if(cachedAsmLines.begin(), cachedAsmLines.end(), [target](const Line& line) { return line.address == target; });
        if (targetIt == cachedAsmLines.end())
            continue;
        const size_t targetIndex = static_cast<size_t>(targetIt - cachedAsmLines.begin());
        if (targetIndex == sourceIndex)
            continue;

        targetOfLine[sourceIndex] = targetIndex;
        const auto arrow          = std::find_if(arrows.begin(), arrows.end(), [targetIndex](const Arrow& a) { return a.target == targetIndex; });
        if (arrow == arrows.end()) {
            arrows.push_back({ std::min(sourceIndex, targetIndex), std::max(sourceIndex, targetIndex), targetIndex, NO_LANE });
        } else {
            arrow->first = std::min(arrow->first, sourceIndex);
            arrow->last  = std::max(arrow->last, sourceIndex);
        }
    }

    // the shortest arrows get the lanes next to the code and the longer ones go around them; arrows sharing a line never share a
    // lane, the ones that do not fit are not drawn
    std::sort(arrows.begin(), arrows.end(), [](const Arrow& a, const Arrow& b) {
        if (a.last - a.first != b.last - b.first)
            return a.last - a.first < b.last - b.first;
        return a.target < b.target; // one arrow per target
    });
    for (size_t i = 0; i < arrows.size(); i++) {
        for (uint32 lane = Line::ARROW_LANES; lane-- > 0;) {
            bool isFree = true;
            for (size_t j = 0; j < i && isFree; j++)
                isFree = arrows[j].lane != lane || arrows[j].last < arrows[i].first || arrows[i].last < arrows[j].first;
            if (isFree) {
                arrows[i].lane = lane;
                break;
            }
        }
    }

    // the horizontal line from the lane to the code, ending with the arrow head on the target
    auto addHorizontalLine = [](Line& line, uint32 lane, bool isTarget) {
        line.arrowCells[lane] |= Line::ArrowRight;
        for (uint32 column = lane + 1; column < Line::ARROW_LANES; column++)
            line.arrowCells[column] |= Line::ArrowLeft | Line::ArrowRight;
        line.arrowCells[Line::ARROW_LANES] |= Line::ArrowLeft | (isTarget ? Line::ArrowHead : Line::ArrowNone);
    };
    std::vector<uint32> laneOfTarget(linesCount, NO_LANE);
    for (const auto& arrow : arrows) {
        if (arrow.lane == NO_LANE)
            continue;
        laneOfTarget[arrow.target] = arrow.lane;
        for (size_t i = arrow.first; i <= arrow.last; i++) {
            if (i > arrow.first)
                cachedAsmLines[i].arrowCells[arrow.lane] |= Line::ArrowUp;
            if (i < arrow.last)
                cachedAsmLines[i].arrowCells[arrow.lane] |= Line::ArrowDown;
        }
        addHorizontalLine(cachedAsmLines[arrow.target], arrow.lane, true);
    }
    for (size_t i = 0; i < linesCount; i++)
        if (targetOfLine[i] != SIZE_MAX && laneOfTarget[targetOfLine[i]] != NO_LANE)
            addHorizontalLine(cachedAsmLines[i], laneOfTarget[targetOfLine[i]], false);
}

bool Instance::DrawDissasmX86AndX64CodeZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (obj->GetData().GetSize() == 0) {
        dli.WriteErrorToScreen("No data available!");
        return true;
    }

    chars.Clear();

    // chars.Set/Add can reallocate the buffer (long lines): the line pointers are taken again once the line is built
    auto updateLinePointers = [this, &dli]() {
        dli.chLineStart   = this->chars.GetBuffer();
        dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
        dli.chText        = dli.chNameAndSize;
    };
    updateLinePointers();

    LocalString<256> spaces;
    spaces.SetChars(' ', std::min<uint16>(256, Layout.startingTextLineOffset));
    chars.Set(spaces);

    if (dli.textLineToDraw == 0) {
        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), ColorMan.Colors.StructureColor);
        uint32 titleSize = static_cast<uint32>(zoneName.size());
        if (zone->cacheRecordRejected) {
            // the saved annotations do not match this analysis: they are kept aside in the cache file, the user must know they are not shown
            constexpr std::string_view warning = " - the saved comments and labels could not be applied (kept in the cache file)";
            chars.Add(warning.data(), ColorMan.Colors.AsmComment);
            titleSize += static_cast<uint32>(warning.size());
        }

        updateLinePointers();
        HighlightSelectionAndDrawCursorText(dli, titleSize, titleSize + Layout.startingTextLineOffset);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);

        if (!zone->isInit && !InitDissasmCodeZone(dli, zone))
            return false;

        return true;
    }

    const bool firstLineToDraw = dli.screenLineToDraw == 0;
    if (dli.textLineToDraw == 1 || firstLineToDraw) {
        const ColorPair titleColumnColor = { ColorMan.Colors.AsmTitleColumnColor.Foreground, ColorMan.Colors.AsmTitleColor.Background };

        const std::string_view address = !settings->offsetTranslateCallback.IsValid() || config.AddressMode == static_cast<uint8>(DissasmPEConversionType::FileOffset)
                                               ? "File offset"
                                               : (config.AddressMode == static_cast<uint8>(DissasmPEConversionType::RVA) ? "Address (RVA)" : "Address (VA)");
        chars.Add(address, ColorMan.Colors.AsmTitleColor);

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

        updateLinePointers();
        HighlightSelectionAndDrawCursorText(dli, chars.Len() - Layout.startingTextLineOffset, chars.Len());

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);
        return true;
    }

    uint32 currentLine = dli.textLineToDraw - 2u;
    if (firstLineToDraw)
        --currentLine;

    if (!zone->isInit && !InitDissasmCodeZone(dli, zone))
        return false;
    if (!zone->CanReachAsmLines()) { // the initialization failed after the zone was marked as initialized
        dli.WriteErrorToScreen("ERROR: the dissasm zone could not be initialized!");
        return false;
    }

    auto& asmPreCacheData = zone->asmPreCacheData;
    if (asmPreCacheData.cachedAsmLines.empty()) {
        uint32 linesToPrepare = std::min<uint32>(Layout.visibleRows, zone->extendedSize);
        // the zone lines are the extended size without the title: [currentLine, extendedSize - 1)
        const uint32 zoneLinesCount = zone->extendedSize > 0 ? zone->extendedSize - 1u : 0u;
        const uint32 remainingLines = currentLine < zoneLinesCount ? zoneLinesCount - currentLine : 0u;
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
        drawnLinesGeneration++; // the lines may have changed (renames, collapsed zones, numbers base)
    }

    const auto asmCacheLine = zone->asmPreCacheData.GetLine();
    if (!asmCacheLine)
        return false;
    if (asmCacheLine->shouldAddButton) {
        RegisterStructureCollapseButton(
              dli.screenLineToDraw + 1, asmCacheLine->isZoneCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone, true);
    }
    uint32 arrowsColumn = UINT32_MAX;
    DissasmAddColorsToInstruction(*asmCacheLine, chars, config, ColorMan.Colors, asmData, codePage, GetDisplayAddressBase(zone), nullptr, &arrowsColumn);
    std::string comment;
    const bool showComments   = !asmCacheLine->isCollapsedLine;
    const bool hasUserComment = showComments && zone->GetComment(*asmCacheLine, comment);
    const bool hasAutoComment = showComments && !asmCacheLine->autoComment.empty();
    if (hasUserComment || hasAutoComment) {
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
        if (hasUserComment)
            chars.Add(comment, ColorMan.Colors.AsmComment);
        if (hasAutoComment) {
            // the generated text after the comment of the user, in the color of the referenced locations
            if (hasUserComment)
                chars.Add(" ;", ColorMan.Colors.AsmComment);
            chars.Add(" ", ColorMan.Colors.AsmComment);
            chars.Add(asmCacheLine->autoComment, ColorMan.Colors.AsmLocationInstruction);
        }
    }

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), chars.Len() };

    /*if (isCursorLine)
        chars.SetColor(Layout.startingTextLineOffset, chars.Len(), config.Colors.HighlightCursorLine);*/

    updateLinePointers();
    HighlightSelectionAndDrawCursorText(
          dli, static_cast<uint32>(bufferToDraw.length() - Layout.startingTextLineOffset), static_cast<uint32>(bufferToDraw.length()));

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    if (config.EnableDeepScanDissasmOnStart && arrowsColumn != UINT32_MAX) {
        // the arrows with the box characters of the terminal character set, in the colors of the line (cursor, selection)
        for (uint32 i = 0; i < textColumnIndicatorArrowLinesSpace; i++) {
            const uint8 cell    = asmCacheLine->arrowCells[i];
            const uint32 column = arrowsColumn + i;
            if (cell == DissasmAsmPreCacheLine::ArrowNone || column >= bufferToDraw.length())
                continue;
            dli.renderer.WriteSpecialCharacter(
                  static_cast<int>(column), static_cast<int>(dli.screenLineToDraw) + 1, GetArrowCellCharacter(cell).special, bufferToDraw[column].Color);
        }
    }
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
    initData.visibleRows                   = Layout.visibleRows;
    // the labels are named after the VA (as IDA), when the plugin translates the file offsets
    if (settings->offsetTranslateCallback.IsValid()) {
        const auto va = settings->offsetTranslateCallback->TranslateFromFileOffset(zone->zoneDetails.startingZonePoint, static_cast<uint32>(DissasmPEConversionType::VA));
        if (va != static_cast<uint64>(-1))
            initData.labelAddressBase = va;
    }
    // the cross references of the immediates / absolute operands: only the addresses that are locations of the file
    if (initData.labelAddressBase.has_value()) {
        auto* settingsData     = settings.get();
        initData.isFileAddress = [settingsData](uint64 va) {
            return settingsData->offsetTranslateCallback->TranslateToFileOffset(va, static_cast<uint32>(DissasmPEConversionType::VA)) != static_cast<uint64>(-1);
        };
    } else {
        const uint64 fileSize  = obj->GetData().GetSize();
        initData.isFileAddress = [fileSize](uint64 offset) { return offset < fileSize; };
    }

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
        AdjustZoneExtendedSize(zone, zone->GetDisplayLinesCount() + 1u); // +1 for the title
    return true;
}

uint32 GView::View::DissasmViewer::GetCodeZoneLinesCount(const DissasmCodeZone& zone)
{
    return zone.GetDisplayLinesCount();
}

bool GView::View::DissasmViewer::BuildX86AsmListing(
      DissasmCodeZone& zone, Reference<GView::Object> obj, SettingsData* settings, AsmData* asmData, std::string& listing)
{
    listing.clear();
    if (!zone.CanReachAsmLines() || zone.cachedCodeOffsets.empty())
        return false;

    const uint64 codeStart  = zone.labelAddressBase; // the addresses of the labels: VA (or file offset when there is no translation)
    const uint32 linesCount = GetCodeZoneLinesCount(zone);

    LocalString<256> text;
    text.SetFormat(
          "; GView disassembly listing (%s)\n; code: file offset 0x%" PRIx64 ", size 0x%" PRIx64 ", entry point 0x%" PRIx64 "\n"
          "; the addresses are %s\n",
          zone.Is64BitCode() ? "x64" : "x86",
          zone.zoneDetails.startingZonePoint,
          zone.zoneDetails.size,
          zone.zoneDetails.entryPoint,
          zone.labelAddressBase != zone.zoneDetails.startingZonePoint ? "virtual addresses (VA)" : "file offsets");
    listing.append(text.GetText(), text.Len());

    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.settings = settings;
    params.asmData  = asmData;
    params.zone     = &zone;

    // address + mnemonic + operands, then the comments (user first, generated after)
    constexpr size_t commentsColumn = 60;
    std::string comment;
    bool hasCollapsedZones = false;
    for (uint32 line = 0; line < linesCount; line++) {
        const auto asmLine = zone.GetCurrentAsmLine(line, obj, &params);
        const std::string_view operands =
              asmLine.op_str ? std::string_view{ asmLine.op_str, asmLine.op_str_size }
                             : (asmLine.mapping ? std::string_view{ static_cast<const MemoryMappingEntry*>(asmLine.mapping)->name } : std::string_view{});

        const size_t lineStart = listing.size();
        if (strcmp(asmLine.mnemonic, "collapsed") == 0) {
            hasCollapsedZones = true;
            listing.append("; collapsed zone: ").append(operands);
        } else if (asmLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition) {
            listing.append("                    ").append(operands); // var_8 = dword ptr -8
        } else if (asmLine.size == 0) {
            listing.append("\n").append(asmLine.mnemonic).append(":"); // label
        } else {
            if (operands.empty()) // ret, int3: no padding after the mnemonic
                text.SetFormat("0x%08" PRIx64 "  %s", asmLine.address + codeStart, asmLine.mnemonic);
            else
                text.SetFormat("0x%08" PRIx64 "  %-7s", asmLine.address + codeStart, asmLine.mnemonic);
            listing.append(text.GetText(), text.Len()).append(operands);
        }

        const bool hasComment = !asmLine.isCollapsedLine && zone.GetComment(asmLine, comment);
        if (hasComment || !asmLine.autoComment.empty()) {
            const size_t written = listing.size() - lineStart;
            listing.append(written < commentsColumn ? commentsColumn - written : 1, ' ').append(";");
            if (hasComment)
                listing.append(" ").append(comment);
            if (hasComment && !asmLine.autoComment.empty())
                listing.append(" ;");
            if (!asmLine.autoComment.empty())
                listing.append(" ").append(asmLine.autoComment);
        }
        listing.append("\n");
    }
    if (hasCollapsedZones)
        listing.append("; some zones are collapsed: expand them in the viewer to export their lines\n");
    zone.asmPreCacheData.Clear(); // the drawn lines are prepared again (the decoding position moved)
    return true;
}

void Instance::CommandExportAsmFile()
{
    if (GView::App::IsExportBlockedFor(obj, "exporting the disassembly to .asm files"))
        return;
    uint32 zoneIndex = 0;
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto codeZone = static_cast<DissasmCodeZone*>(zone.get());
        const uint32 index  = zoneIndex++; // every code zone keeps its own number, the files of two zones never overwrite each other
        const auto language = codeZone->zoneDetails.language;
        if (language != DisassemblyLanguage::x86 && language != DisassemblyLanguage::x64) {
            Dialogs::MessageBox::ShowNotification("Warning", "Only the x86/x64 zones can be exported!");
            continue;
        }
        if (!codeZone->CanReachAsmLines()) {
            Dialogs::MessageBox::ShowNotification("Warning", "The dissasm zone is not analysed yet: scroll to it once and export it again!");
            continue;
        }

        // the default file: next to the analysed file, the user picks the location (the folder of the file can be read only)
        const std::filesystem::path filePath = obj->GetPath();
        LocalString<256> fileName;
        fileName.SetFormat("%s.z%u.%s.asm", reinterpret_cast<const char*>(filePath.filename().u8string().c_str()), index, language == DisassemblyLanguage::x64 ? "x64" : "x86");
        const auto selectedPath = Dialogs::FileDialog::ShowSaveFileWindow(fileName, "Assembly:asm", filePath.parent_path());
        if (!selectedPath.has_value())
            continue;

        std::string listing;
        if (!BuildX86AsmListing(*codeZone, obj, settings.get(), &asmData, listing)) {
            Dialogs::MessageBox::ShowError("Error", "Failed to build the listing of the dissasm zone!");
            continue;
        }

        AppCUI::OS::File f;
        if (!f.Create(selectedPath.value(), true) || !f.Write(listing.data(), static_cast<uint32>(listing.size()))) {
            f.Close();
            Dialogs::MessageBox::ShowError("Error", "Failed to write the .asm file!");
            continue;
        }
        f.Close();
        GView::App::OpenFile(selectedPath.value(), App::OpenMethod::BestMatch);
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
    if (!zone->CanReachAsmLines()) {
        Dialogs::MessageBox::ShowNotification("Warning", "This dissasm zone is not an initialized x86/x64 zone!");
        return;
    }
    if (!offsetToReach) {
        if (line <= 1)
            return;

        // the reached line state (structureIndex, types, levels and the counters inside the types) is kept as a whole: restoring
        // only a part of it desynchronized the counters from the line they belong to
        const auto adjustedLine = DissasmGetCurrentAsmLineAndPrepareCodeZone(zone, line - 2);
        if (!adjustedLine.has_value())
            return;

        insn = GetCurrentInstructionByLine(adjustedLine.value(), zone, obj, diffLines);
        if (!insn) {
            Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
            return;
        }
        if (!IsX86Branch(GetX86Flow(*insn))) {
            cs_free(insn, 1);
            return;
        }
        // file offsets, like the displayed operand (TryGetDataFromInsn): the decoded addresses start at the first decoded instruction
        jumpFromAddress = zone->GetFileOffsetOfAddress(insn->address).value_or(0);
        for (size_t i = 0; i + 1 < sizeof(jumpMnemonic) && insn->mnemonic[i] != 0; i++)
            jumpMnemonic[i] = insn->mnemonic[i];
        const auto target       = GetX86OperandsInfo(*insn, zone->Is64BitCode()).directTarget;
        const auto targetOffset = target.has_value() ? zone->GetFileOffsetOfAddress(target.value()) : std::nullopt;
        cs_free(insn, 1);
        if (!targetOffset.has_value()) {
            if (target.has_value())
                Dialogs::MessageBox::ShowNotification("Warning", "The target is outside of this dissasm zone!");
            return; // indirect jump / call: nothing to follow
        }
        computedValue = targetOffset.value();
    } else {
        computedValue = *offsetToReach;
        if (computedValue < zone->cachedCodeOffsets[0].offset || !zone->GetFileOffsetOfAddress(computedValue - zone->cachedCodeOffsets[0].offset))
            return;
    }

    if (!MoveCursorToZoneFileOffset(zone, computedValue, true))
        return;
    if (offsetToReach != nullptr)
        GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::GotoEntrypoint);
    else
        GView::Security::Learning::Hooks::OnJumpFollow(obj, jumpFromAddress, computedValue, jumpMnemonic);
}

uint64 Instance::GetDisplayAddressBase(DissasmCodeZone* zone)
{
    const uint64 codeStart = zone->cachedCodeOffsets[0].offset;
    if (!settings->offsetTranslateCallback.IsValid() || config.AddressMode == static_cast<uint8>(DissasmPEConversionType::FileOffset))
        return codeStart;
    // inside the zone (one section) the addresses grow with the file offsets: the address of the first instruction is enough
    const auto address = settings->offsetTranslateCallback->TranslateFromFileOffset(codeStart, config.AddressMode);
    return address != static_cast<uint64>(-1) ? address : codeStart;
}

void Instance::ChangeAddressMode()
{
    if (!settings->offsetTranslateCallback.IsValid()) {
        Dialogs::MessageBox::ShowNotification("Info", "This file has only file offsets!");
        return;
    }
    switch (static_cast<DissasmPEConversionType>(config.AddressMode)) {
    case DissasmPEConversionType::VA:
        config.AddressMode = static_cast<uint8>(DissasmPEConversionType::RVA);
        break;
    case DissasmPEConversionType::RVA:
        config.AddressMode = static_cast<uint8>(DissasmPEConversionType::FileOffset);
        break;
    default:
        config.AddressMode = static_cast<uint8>(DissasmPEConversionType::VA);
        break;
    }
    RefreshDrawnLines(); // the address column changes its width: the columns of the numbers move
}

bool Instance::MoveCursorToZoneFileOffset(DissasmCodeZone* zone, uint64 fileOffset, bool landOnLabels)
{
    uint32 instructionIndex = 0;
    cs_insn* insn           = GetCurrentInstructionByOffset(fileOffset, zone, obj, instructionIndex);
    if (!insn) {
        Dialogs::MessageBox::ShowNotification("Warning", "There was an error reaching that line!");
        return false;
    }
    cs_free(insn, 1);

    // the line of the instruction, or (landOnLabels) the label / local variables placed right above it; a hidden line: the line of the
    // collapsed zone that hides it
    uint32 landingExpandedLine = zone->InstructionIndexToExpanded(instructionIndex);
    while (landOnLabels && landingExpandedLine > 0 && zone->IsAnnotationLine(landingExpandedLine - 1u))
        landingExpandedLine--;
    const uint32 zoneLine = zone->ExpandedToDisplay(landingExpandedLine) + 2u; // +1 for the title, +1 for the columns header

    const auto from      = SaveCursorState();
    Cursor.lineInView    = std::min<uint32>(5, zoneLine);
    Cursor.startViewLine = zoneLine + zone->startLineIndex - Cursor.lineInView;
    Cursor.hasMovedView  = true;
    RecordJump(from);
    return true;
}

void Instance::RefreshCursorLineNumbers()
{
    const uint32 line = Cursor.startViewLine + Cursor.lineInView;
    if (cursorLineNumbers.computed && cursorLineNumbers.line == line && cursorLineNumbers.generation == drawnLinesGeneration)
        return;
    cursorLineNumbers.computed   = true;
    cursorLineNumbers.line       = line;
    cursorLineNumbers.generation = drawnLinesGeneration;
    cursorLineNumbers.valid      = false;
    cursorLineNumbers.zone       = nullptr;
    cursorLineNumbers.numbers.clear();

    const auto zonesFound = GetZonesIndexesFromLinePosition(line);
    if (zonesFound.size() != 1)
        return;
    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone || parseZone->isCollapsed)
        return;
    const auto zone     = static_cast<DissasmCodeZone*>(parseZone.get());
    const auto language = zone->zoneDetails.language;
    if (!zone->isInit || zone->cachedCodeOffsets.empty() || (language != DisassemblyLanguage::x86 && language != DisassemblyLanguage::x64))
        return;
    // zone line 0 is the title and line 1 the columns header; when the zone title is scrolled out, the first row shows the header
    const uint32 zoneLine = zonesFound[0].startingLine;
    if (zoneLine < 2 || Cursor.lineInView == 0)
        return;

    // the same line (and layout) as the one that is drawn
    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.settings = settings.get();
    params.asmData  = &asmData;
    params.dli      = nullptr;
    params.zone     = zone;
    auto asmLine    = zone->GetCurrentAsmLine(zoneLine - 2u, obj, &params);

    // only instructions: not labels, local variable lines or collapsed zones
    const bool isCollapsedZoneLine = asmLine.isCollapsedLine;
    if (!asmLine.op_str || asmLine.size == 0 || isCollapsedZoneLine || asmLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition)
        return;

    CharacterBuffer lineText; // drawn without the left margin: its columns have the same base as Cursor.offset
    std::vector<uint32> opStrColumns;
    DissasmAddColorsToInstruction(asmLine, lineText, config, ColorMan.Colors, asmData, codePage, GetDisplayAddressBase(zone), &opStrColumns);
    if (opStrColumns.size() != asmLine.op_str_size)
        return;

    cursorLineNumbers.valid   = true;
    cursorLineNumbers.zone    = zone;
    cursorLineNumbers.address = asmLine.address;

    const auto numbers = FindOperandNumbers({ asmLine.op_str, asmLine.op_str_size });
    for (uint32 index = 0; index < static_cast<uint32>(numbers.size()) && index < 32u; index++) {
        const auto& number  = numbers[index];
        const uint32 column = opStrColumns[number.start];
        if (column != UINT32_MAX)
            cursorLineNumbers.numbers.push_back({ column, number.length, index, number.value, number.isHex });
    }
}

bool Instance::TryGetCodeZoneSelectionText(uint32 index, std::string& text)
{
    text.clear();
    const auto selectionStart = selection.GetSelectionStart(index);
    const auto selectionEnd   = selection.GetSelectionEnd(index);
    const auto zonesFound     = GetZonesIndexesFromLinePosition(selectionStart.line, selectionEnd.line);
    if (zonesFound.size() != 1)
        return false;
    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone || parseZone->isCollapsed)
        return false;
    const auto zone = static_cast<DissasmCodeZone*>(parseZone.get());
    if (!zone->CanReachAsmLines() || zone->cachedCodeOffsets.empty())
        return false;

    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.settings = settings.get();
    params.asmData  = &asmData;
    params.zone     = zone;

    // zone line 0 is the title, 1 the columns header; the selected text of a line starts at the selection offset on its first line (on
    // every line for a column selection) and ends with the line, as the drawn selection
    const bool isColumnSelection = selection.IsAltPressed(index);
    const uint32 zoneLinesCount  = GetCodeZoneLinesCount(*zone);
    std::string comment;
    for (uint32 line = selectionStart.line; line <= selectionEnd.line; line++) {
        const uint32 zoneLine = zonesFound[0].startingLine + (line - selectionStart.line);
        if (zoneLine < 2 || zoneLine - 2 >= zoneLinesCount)
            continue;
        auto asmLine = zone->GetCurrentAsmLine(zoneLine - 2, obj, &params);
        CharacterBuffer lineText;
        DissasmAddColorsToInstruction(asmLine, lineText, config, ColorMan.Colors, asmData, codePage, GetDisplayAddressBase(zone));

        std::string lineString;
        lineString.reserve(lineText.Len() + 32);
        for (uint32 i = 0; i < lineText.Len(); i++) {
            const auto code = lineText.GetBuffer()[i].Code;
            lineString.push_back(code < 128 ? static_cast<char>(code) : '?');
        }
        const bool hasComment = !asmLine.isCollapsedLine && zone->GetComment(asmLine, comment);
        if (hasComment || !asmLine.autoComment.empty()) {
            lineString += "  ;";
            if (hasComment)
                lineString += ' ' + comment;
            if (hasComment && !asmLine.autoComment.empty())
                lineString += " ;";
            if (!asmLine.autoComment.empty())
                lineString += ' ' + asmLine.autoComment;
        }
        const uint32 startOffset = (line == selectionStart.line || isColumnSelection) ? selectionStart.offset : 0;
        if (startOffset < lineString.size())
            text.append(lineString, startOffset, std::string::npos);
        text.push_back('\n');
    }
    zone->asmPreCacheData.Clear(); // the decoding position moved: the drawn lines are prepared again
    return true;
}

const Instance::CursorLineNumber* Instance::GetCursorLineNumber()
{
    RefreshCursorLineNumbers();
    if (!cursorLineNumbers.valid)
        return nullptr;
    for (const auto& number : cursorLineNumbers.numbers)
        if (Cursor.offset >= number.column && Cursor.offset < number.column + number.length)
            return &number;
    // most instructions have a single number (mov eax, 0x10 / push 0x40): no need to place the cursor on it
    if (cursorLineNumbers.numbers.size() == 1)
        return &cursorLineNumbers.numbers[0];
    return nullptr;
}

void Instance::ToggleNumberBase()
{
    const auto number = GetCursorLineNumber();
    if (!number) {
        if (cursorLineNumbers.numbers.size() > 1)
            Dialogs::MessageBox::ShowNotification("Warning", "Please move the cursor on the number to convert!");
        else
            Dialogs::MessageBox::ShowNotification("Warning", "There is no number on this line!");
        return;
    }
    const auto zone        = cursorLineNumbers.zone;
    const bool isConverted = (zone->GetDecimalOperandsMask(cursorLineNumbers.address) & (1u << number->index)) != 0;
    if (!number->isHex && !isConverted) {
        Dialogs::MessageBox::ShowNotification("Info", "Values below 10 look the same in both bases!");
        return;
    }

    zone->ToggleDecimalOperand(cursorLineNumbers.address, number->index);
    zone->asmPreCacheData.Clear(); // the lines are rebuilt with the new operands
    drawnLinesGeneration++;
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

GStatus DissasmCodeZone::TryRenameLine(
      uint32 line, Reference<GView::Object> obj, std::string_view* newName, DissasmInsnExtractLineParams* params)
{
    if (!CanReachAsmLines())
        return GStatus::Error("Renaming is available only for the initialized x86/x64 dissasm zones!");
    const auto place = DisplayToExpanded(line);
    if (!place.has_value())
        return GStatus::Error("Failed to rename line");

    // the line of a collapsed zone: the name of the zone
    if (place->collapsedZone) {
        auto& zone = collapsibleZones[place->collapsedZone - collapsibleZones.data()];
        std::string name;
        if (newName) {
            name = std::string(*newName);
        } else {
            SingleLineEditWindow dlg(zone.name, "Edit collapsed zone label");
            if (dlg.Show() != Dialogs::Result::Ok)
                return GStatus::Ok();
            name = dlg.GetResult();
        }
        if (name.empty() || name == zone.name)
            return GStatus::Ok();
        zone.name = std::move(name);
        ResetZoneCaching();
        return GStatus{ .ok = true, .message = "renamed" };
    }

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

    // a label line (the annotations are keyed by the expanded lines)
    std::string currentName;
    uint32 labelLine  = place->expandedLine;
    auto& annotations = dissasmType.annotations;
    const auto label  = annotations.find(labelLine);
    if (label != annotations.end() && !IsLocalVariableAnnotation(label->second)) {
        if (newName) {
            // through the name links, as the dialog rename: the jumps / calls to the label show the new name as well
            const std::string newNameText(*newName);
            if (newNameText.empty() || newNameText == label->second.first)
                return GStatus::Ok();
            const std::string labelName = label->second.first;
            if (!annotations.add_name_change(labelName, newNameText, labelLine))
                return GStatus::Error("Name already exists!");
            return GStatus{ .ok = true, .message = "renamed" };
        }
        currentName = label->second.first;
    }

    // a jump / call: the label of its target
    if (currentName.empty()) {
        const auto asmLine = GetCurrentAsmLine(line, obj, params);
        if (asmLine.op_str && (asmLine.flags & (DissasmAsmPreCacheLine::InstructionFlag::JmpFlag | DissasmAsmPreCacheLine::InstructionFlag::CallFlag))) {
            std::string targetName(asmLine.op_str, asmLine.op_str_size);
            const auto targetLine = annotations.get_line_by_annotation_name(targetName);
            if (targetLine.has_value()) {
                currentName = std::move(targetName);
                labelLine   = targetLine.value();
            }
        }
    }

    if (!currentName.empty()) {
        SingleLineEditWindow dlg(currentName, "Edit label");
        if (dlg.Show() == Dialogs::Result::Ok) {
            const auto res = dlg.GetResult();
            if (!res.empty()) {
                if (!annotations.add_name_change(currentName, res, labelLine)) {
                    // TODO: do this check inside the SingleLineEditWindow
                    return GStatus::Error("Name already exists!");
                }
                return GStatus{ .ok = true, .message = "renamed" };
            }
        }
        return GStatus::Ok();
    }

    return GStatus::Error("Failed to rename line");
}

// the cross references to an address: one row per reference, Enter (or Go) closes the window on the selected reference
class XrefsWindow : public AppCUI::Controls::Window
{
  public:
    struct Row {
        uint64 from; // relative address of the instruction
        std::string address, kind, function, instruction;
    };

  private:
    static constexpr int BTN_GO    = 1;
    static constexpr int BTN_CLOSE = 2;
    Reference<ListView> list;
    std::optional<size_t> selectedRow;

  public:
    XrefsWindow(const std::string& title, const std::vector<Row>& rows) : Window(title, "d:c,w:90%,h:60%", WindowFlags::Sizeable)
    {
        list = Factory::ListView::Create(
              this, "l:1,t:1,r:1,b:3", { "n:Address,w:20", "n:Type,w:8", "n:From,w:40", "n:Instruction,w:80" }, ListViewFlags::PopupSearchBar);
        for (size_t i = 0; i < rows.size(); i++) {
            const auto& row = rows[i];
            auto item       = list->AddItem({ std::string_view(row.address), std::string_view(row.kind), std::string_view(row.function), std::string_view(row.instruction) });
            item.SetData(static_cast<uint64>(i));
        }
        Factory::Button::Create(this, "&Go", "l:1,b:0,w:10", BTN_GO);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:10", BTN_CLOSE);
        list->SetFocus();
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (Window::OnEvent(control, eventType, ID))
            return true;
        if (eventType == Event::ListViewItemPressed || (eventType == Event::ButtonClicked && ID == BTN_GO)) {
            auto item = list->GetCurrentItem();
            if (item.IsValid())
                selectedRow = static_cast<size_t>(item.GetData(UINT64_MAX));
            Exit(selectedRow.has_value() ? Dialogs::Result::Ok : Dialogs::Result::Cancel);
            return true;
        }
        if (eventType == Event::ButtonClicked && ID == BTN_CLOSE) {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return false;
    }

    std::optional<size_t> GetSelectedRow() const
    {
        return selectedRow;
    }
};

void Instance::ShowXrefs()
{
    const auto linePos    = Cursor.ToLinePosition();
    const auto zonesFound = GetZonesIndexesFromLinePosition(linePos.line);
    if (zonesFound.size() != 1 || zonesFound[0].startingLine < 2) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line of a dissasm zone!");
        return;
    }
    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone || parseZone->isCollapsed) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line of an expanded dissasm code zone!");
        return;
    }
    const auto zone = static_cast<DissasmCodeZone*>(parseZone.get());
    if (!zone->CanReachAsmLines())
        return;
    if (zone->xrefs.byTarget.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The cross references are found by the deep scan (Config.DeepScanDissasmOnStart)!");
        return;
    }

    // a label (or a collapsed zone): its address; a jump / call: its target; another instruction: its address
    DissasmInsnExtractLineParams params{};
    params.obj         = obj;
    params.zone        = zone;
    params.settings    = settings.get();
    params.asmData     = &asmData;
    const auto asmLine = zone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params);
    uint64 target      = asmLine.address;
    if (asmLine.size > 0 && asmLine.branchTarget.has_value())
        target = asmLine.branchTarget.value();
    std::string targetName = zone->GetLabelNameAt(target);
    if (targetName.empty())
        targetName = zone->FormatCodeAddress(target);

    const auto [first, last] = zone->xrefs.To(zone->labelAddressBase + target);
    if (first == last) {
        Dialogs::MessageBox::ShowNotification("Info", "There are no cross references to " + targetName);
        return;
    }

    constexpr size_t MAX_ROWS = 5000;
    std::vector<XrefsWindow::Row> rows;
    rows.reserve(std::min<size_t>(static_cast<size_t>(last - first), MAX_ROWS));
    LocalString<64> text;
    for (auto it = first; it != last && rows.size() < MAX_ROWS; ++it) {
        XrefsWindow::Row row;
        row.from = it->from - zone->labelAddressBase;
        text.SetFormat("0x%llx", static_cast<unsigned long long>(it->from));
        row.address  = text.GetText();
        row.kind     = std::string(GetXrefKindName(it->kind));
        row.function = zone->FormatCodeAddress(row.from);
        // the instruction as capstone writes it, a branch with the name of its target (capstone writes the zone relative address)
        uint32 instructionIndex = 0;
        if (const auto fileOffset = zone->GetFileOffsetOfAddress(row.from); fileOffset.has_value()) {
            if (cs_insn* insn = GetCurrentInstructionByOffset(fileOffset.value(), zone, obj, instructionIndex)) {
                row.instruction = std::string(insn->mnemonic) + " ";
                const auto operands =
                      IsX86Branch(GetX86Flow(*insn)) ? GetX86OperandsInfo(*insn, zone->zoneDetails.language == DisassemblyLanguage::x64) : X86OperandsInfo{};
                if (operands.directTarget.has_value()) {
                    std::string branchName = zone->GetLabelNameAt(operands.directTarget.value());
                    row.instruction += branchName.empty() ? zone->FormatCodeAddress(operands.directTarget.value()) : branchName;
                } else {
                    row.instruction += insn->op_str;
                }
                cs_free(insn, 1);
            }
        }
        rows.push_back(std::move(row));
    }
    zone->asmPreCacheData.Clear(); // the decoding position moved: the drawn lines are prepared again

    LocalString<256> title;
    title.SetFormat("Cross references to %s (%zu)", targetName.c_str(), static_cast<size_t>(last - first));
    XrefsWindow dlg(title.GetText(), rows);
    if (dlg.Show() != Dialogs::Result::Ok)
        return;
    const auto selected = dlg.GetSelectedRow();
    if (selected.has_value() && selected.value() < rows.size())
        MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + rows[selected.value()].from, false);
}

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
constexpr uint32 QueryShowCodeDialog_BTN_OPEN_OR_APPLY_COMMENTS = 1; // distinct from Close: Close must not apply the comments

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

    while (std::getline(codeStream, line)) {
        if (line.empty()) {
            if (currentLine.Len()) {
                wrappedLines.AddFormat("%s\n\n", currentLine.GetText());
                currentLine.Clear();
            } else {
                wrappedLines.AddFormat("\n");
            }
            continue;
        }
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
    Graphics::Character* end = chars + charsCount;
    // ColorPair col;
    while (chars < end) {
        if (chars->Code == '*') // Check for '**'
        {
            chars++;
            if ((chars < end) && (chars->Code == '*')) // Confirm second '*'
            {
                chars++;
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
            // codeEnd is the position of the closing fence: the code is everything before it
            auto codeEnd = code.find("```", codeStart);
            if (codeEnd == std::string::npos) {
                btn->SetEnabled(false);
                return;
            }
            codeString = code.substr(codeStart, codeEnd - codeStart);
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

    displayPrompt.Set(queryParams.displayPrompt); // not a format string: the prompts can contain '%'
    if (!queryParams.mnemonicStarsWith.empty()) {
        auto data = codeZone->GetCurrentAsmLine(line, obj, &params);
        if (memcmp(data.mnemonic, queryParams.mnemonicStarsWith.data(), queryParams.mnemonicStarsWith.size()) != 0) {
            Dialogs::MessageBox::ShowNotification("Warning", queryParams.mnemonicStartsWithError);
            return;
        }
        if (queryParams.displayPromptUsesMnemonicParam)
            displayPrompt.AddFormat("%s", data.mnemonic);
    }

    const auto assistantInterface = queryInterface ? queryInterface->GetSmartAssistantInterface() : nullptr;
    if (!assistantInterface) {
        Dialogs::MessageBox::ShowNotification("Warning", "There is no digital assistant available!");
        return;
    }

    // the code starts below the function label, or at the first selected line
    const uint32 firstLine      = queryParams.startsAtSelectedLine ? line : line + 1u;
    uint32 actualLineInDocument = firstLine + codeZone->startLineIndex;
    uint32 lineIndex            = 0;
    uint32 currentDissasmLine   = firstLine;
    // zone lines (relative to the zone, without the title): the extended size counts the title as well
    const uint32 zoneLinesCount = codeZone->extendedSize > 0 ? codeZone->extendedSize - 1u : 0u;
    const uint32 linesToAnalyse = queryParams.maxLines > 0 ? std::min(queryParams.maxLines, DISSASM_ASSISTANT_MAX_DISSASM_LINES_ANALYSED)
                                                           : DISSASM_ASSISTANT_MAX_DISSASM_LINES_ANALYSED;

    std::vector<std::string> apisInstructions;
    apisInstructions.reserve(DISSASM_ASSISTANT_MAX_API_CALLS);

    std::vector<std::string> assemblyLines;
    assemblyLines.reserve(DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT);

    LocalString<64> currentBuffer;
    std::string comment;
    while (actualLineInDocument < codeZone->endingLineIndex && currentDissasmLine < zoneLinesCount && lineIndex < linesToAnalyse) {
        auto currentLine = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
        if (currentLine.size > 0) {
            currentBuffer.SetFormat("   %s %s", currentLine.mnemonic, GetAssistantOperands(currentLine));
            if (!currentLine.autoComment.empty()) // the referenced string / import helps the assistant
                currentBuffer.AddFormat(" ; %s", currentLine.autoComment.c_str());
            if (assemblyLines.size() < DISSASM_ASSISTANT_MAX_DISSASM_LINES_SENT) {
                if (queryParams.includeComments) {
                    if (codeZone->GetComment(currentLine, comment)) {
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
        if (queryParams.stopAtTheEndOfTheFunction && strcmp(currentLine.mnemonic, "ret") == 0)
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
    bufferToSendToAssistant.AddFormat("Here is %s assembly code: \n", codeZone->Is64BitCode() ? "x64" : "x86");
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
            const auto renameResult = codeZone->TryRenameLine(line, obj, &sv, nullptr);
            if (!renameResult.ok)
                Dialogs::MessageBox::ShowNotification("Warning", renameResult.message);
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
            currentDissasmLine = firstLine;
            if (currentDissasmLine >= zoneLinesCount) {
                Dialogs::MessageBox::ShowNotification("Warning", "No instructions found!");
                return;
            }
            auto initialLine = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
            if (initialLine.size == 0) {
                Dialogs::MessageBox::ShowNotification("Warning", "No instructions found!");
                return;
            }
            currentBuffer.SetFormat("%s %s", initialLine.mnemonic, GetAssistantOperands(initialLine));
            if (resultValue[0].first != currentBuffer.GetText()) {
                Dialogs::MessageBox::ShowNotification("Warning", "The assistant did not provide the expected comments!");
            }
            bool reachedZoneEnd = false;
            for (const auto& [asmLine, comment] : resultValue) {
                do {
                    if (currentDissasmLine >= zoneLinesCount) { // more comments than the instructions left in the zone
                        reachedZoneEnd = true;
                        break;
                    }
                    auto currentLine = codeZone->GetCurrentAsmLine(currentDissasmLine, obj, &params);
                    if (currentLine.op_str && currentLine.localVariableKind != DissasmAsmPreCacheLine::LocalVariableKind::Definition)
                        break;
                    ++currentDissasmLine;
                } while (true);
                if (reachedZoneEnd)
                    break;

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
        QueryShowCodeDialog dlg(result, "High level code", true, false);
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