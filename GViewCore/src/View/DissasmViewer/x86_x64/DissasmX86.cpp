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

ColorPair GView::View::DissasmViewer::GetX86MnemonicColor(X86InstructionKind kind, const DissasmColors& colors)
{
    switch (kind) {
    case X86InstructionKind::Call:
    case X86InstructionKind::Return:
        return colors.AsmFunctionColor;
    case X86InstructionKind::Jump:
    case X86InstructionKind::ConditionalJump:
        return colors.AsmJumpInstruction;
    case X86InstructionKind::Compare:
        return colors.AsmCompareInstructionColor;
    case X86InstructionKind::Stack:
        return colors.AsmStackRegisterColor;
    case X86InstructionKind::Padding:
        return colors.AsmIrrelevantInstructionColor;
    case X86InstructionKind::Data:
        return colors.AsmLocationInstruction;
    case X86InstructionKind::System:
        return colors.AsmSystemInstructionColor;
    default:
        return colors.AsmDefaultColor;
    }
}

ColorPair GView::View::DissasmViewer::GetX86TokenColor(std::string_view token, const DissasmColors& colors)
{
    switch (GetX86RegisterKind(token)) {
    case X86RegisterKind::General:
        return colors.AsmWorkRegisterColor;
    case X86RegisterKind::Pointer:
        return colors.AsmStackRegisterColor;
    default:
        break;
    }
    static constexpr std::string_view SIZE_KEYWORDS[] = { "byte", "word", "dword", "fword", "qword", "tbyte", "xmmword", "ymmword", "zmmword", "ptr" };
    for (const auto keyword : SIZE_KEYWORDS)
        if (token == keyword)
            return colors.AsmLocationInstruction;
    if (token.size() > 2 && token[0] == 'j' && token[1] == '_') // j_CreateFileW: an import thunk
        return colors.AsmJumpInstruction;
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

    const ColorPair color = insn.label.empty() ? GetX86MnemonicColor(static_cast<X86InstructionKind>(insn.instructionKind), colors)
                                               : GetX86TokenColor(insn.label, colors);
    if (insn.label.empty()) {
        string.SetFormat("%-6s", insn.mnemonic);
        cb.Add(string, color);
    } else {
        cb.Add(insn.label, color); // a label: its whole name
        if (insn.label.size() < 6) {
            string.SetChars(' ', static_cast<uint32>(6 - insn.label.size()));
            cb.Add(string, color);
        }
    }

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
        auto checkValidAndAdd = [&cb, &colors, &lambdaBuffer](std::string_view token) {
            lambdaBuffer.Clear();
            // numbers: hexadecimal (0x...) or decimal (small values, or switched to decimal with the H key)
            if (!token.empty() && ((token[0] >= '0' && token[0] <= '9') || (token[0] == '#' && token.size() > 1))) { // ARM64: #0x10
                cb.Add(token.data(), colors.AsmOffsetColor);
                return;
            }
            lambdaBuffer.Set(token.data());
            cb.Add(token, GetX86TokenColor(token, colors));
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
            const bool isWriteback = lastOp == ']' && buffer.Len() == 1 && buffer.GetText()[0] == '!'; // ARM64: [sp, #-0x10]!
            if (!isWriteback)
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
        const bool decoded =
              DecodeX86Line(handle, &zone->asmData, &remainingSize, &zone->asmAddress, insn, &zone->instructionBoundaries, zone->paddingAlignmentBase,
                            zone->IsArm64Code());
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

const MemoryMappingEntry* GView::View::DissasmViewer::FindX86OperandsImport(SettingsData* settings, const DissasmCodeZone* zone, const X86OperandsInfo& operands)
{
    if (!settings || zone->cachedCodeOffsets.empty())
        return nullptr;
    const auto& mappings = settings->memoryMappings;
    if (mappings.empty())
        return nullptr;
    auto find = [&mappings](uint64 key) -> const MemoryMappingEntry* {
        const auto it = mappings.find(key);
        return it != mappings.end() ? &it->second : nullptr;
    };

    // the plugins without an offset translation (RVA) do not set the callback: only an absolute address can be looked up as it is
    if (!settings->offsetTranslateCallback.IsValid())
        return operands.absoluteMemory.has_value() ? find(operands.absoluteMemory.value()) : nullptr;

    if (operands.ripTarget.has_value()) // the decoded addresses are relative to the first decoded instruction
        return find(GetCodeStartRVA(settings, zone) + operands.ripTarget.value());
    if (operands.absoluteMemory.has_value()) {
        const auto offset = TranslateOperandAddressToFileOffset(settings, operands.absoluteMemory.value(), true);
        if (!offset.has_value())
            return nullptr;
        return find(settings->offsetTranslateCallback->TranslateFromFileOffset(offset.value(), static_cast<uint32>(DissasmPEConversionType::RVA)));
    }
    return nullptr;
}

// an address of the listing (VA) as text: 0x...
static std::string FormatAddress(uint64 address)
{
    LocalString<32> text;
    text.SetFormat("0x%llx", static_cast<unsigned long long>(address));
    return text.GetText();
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
        const bool takesAddress = params.zone->IsArm64Code() ? insn.id == ARM64_INS_ADR || insn.id == ARM64_INS_ADD : insn.id == X86_INS_LEA;
        if (!takesAddress) {
            // the other instructions read / write the data (a variable, a pointer), only lea / adr / add take the address of a string. The
            // address of an ARM64 adrp pair is not in the operands: it is shown
            if (params.zone->IsArm64Code() && params.zone->resolvedAddresses.contains(insn.address))
                line.autoComment = FormatAddress(params.zone->labelAddressBase + operands.ripTarget.value());
            return;
        }
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
    const bool isAdrpPair = params.zone->IsArm64Code() && params.zone->resolvedAddresses.contains(insn.address);
    if (isAdrpPair && operands.ripTarget.has_value())
        line.autoComment = FormatAddress(params.zone->labelAddressBase + operands.ripTarget.value()); // add x0, x0, #off: the address, when it is not a string
    if (!fileOffset.has_value() || fileOffset.value() >= params.obj->GetData().GetSize())
        return;
    auto text = TryExtractStringPreview(params.obj, fileOffset.value());
    if (text.has_value())
        line.autoComment = std::move(text.value());
}

// ARM64: the operands before the last one, the address (cbz x0, / tbnz w1, #3, / adr x0,). Empty for x86 / x64
static std::string GetArm64BranchOperandsPrefix(const cs_insn& insn, const DissasmCodeZone* zone)
{
    if (!zone->IsArm64Code())
        return {};
    const std::string_view operands = insn.op_str;
    const auto separator            = operands.rfind(", ");
    return separator == std::string_view::npos ? std::string() : std::string(operands.substr(0, separator + 2));
}

// a call to a known Windows API (KNOWN_FUNCTIONS): its arguments are named on the lines prepared before the call (x86 / x64 calling
// conventions)
static void AnnounceKnownFunctionCall(DissasmInsnExtractLineParams& params, std::string_view functionName)
{
    if (params.zone->IsArm64Code())
        return;
    GView::Hashes::CRC32 crc32{};
    uint32 hash = 0;
    if (!crc32.Init(GView::Hashes::CRC32Type::JAMCRC) || !crc32.Update(reinterpret_cast<const uint8*>(functionName.data()), static_cast<uint32>(functionName.size())) ||
        !crc32.Final(hash))
        return;
    const auto it = params.asmData->functions.find(hash);
    if (it != params.asmData->functions.end())
        params.zone->asmPreCacheData.AnnounceCallInstruction(it->second, params.zone->Is64BitCode());
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
    instructionKind = static_cast<uint8>(GetInstructionKind(insn->id, insn->mnemonic, params.zone->GetArch()));

    if (!params.settings || !params.asmData) {
        SetOperands(insn->op_str, params.zone);
        return true;
    }

    // the meaning of the instruction from the capstone details (groups, operands), not from its text
    const auto flow     = GetInstructionFlow(*insn, params.zone->GetArch());
    const auto operands = params.zone->GetOperandsInfo(*insn);
    if (params.zone->GetArch() == DissasmArch::X64) {
        const auto slot = GetX64ArgumentSlot(*insn); // mov rcx, ... / mov [rsp + 0x20], ...: an argument of the next call
        argumentSlot    = slot.has_value() ? slot.value() : NO_ARGUMENT;
    }
    if (flow == X86Flow::Call)
        flags = DissasmAsmPreCacheLine::InstructionFlag::CallFlag;
    else if (flow == X86Flow::Jump || flow == X86Flow::ConditionalJump)
        flags = DissasmAsmPreCacheLine::InstructionFlag::JmpFlag;
    else if (insn->id == X86_INS_PUSH && !params.zone->IsArm64Code())
        flags = DissasmAsmPreCacheLine::InstructionFlag::PushFlag;
    else {
        if (params.zone->IsArm64Code() && insn->id == ARM64_INS_ADRP) {
            // adrp x0, page: the page of the VA (capstone decodes from the zone start)
            const uint64 page = params.zone->labelAddressBase + GetArm64AdrpPage(*insn, params.zone->labelAddressBase);
            SetOperands((GetArm64BranchOperandsPrefix(*insn, params.zone) + FormatAddress(page)).c_str(), params.zone);
        } else if (params.zone->IsArm64Code() && GetArm64OperandsInfo(*insn).ripTarget.has_value()) {
            // adr x0, label / ldr x0, label: capstone writes the address relative to the zone start, the listing shows the VA
            LocalString<32> target;
            target.SetFormat("0x%llx", static_cast<unsigned long long>(params.zone->labelAddressBase + operands.ripTarget.value()));
            SetOperands((GetArm64BranchOperandsPrefix(*insn, params.zone) + target.GetText()).c_str(), params.zone);
        } else
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
        const auto mappingPtr = FindX86OperandsImport(params.settings, params.zone, operands);
        if (mappingPtr) {
            mapping     = mappingPtr;
            op_str_size = (uint32) mappingPtr->name.size();
            if (flags & DissasmAsmPreCacheLine::InstructionFlag::CallFlag && mappingPtr->type == MemoryMappingType::FunctionMapping)
                AnnounceKnownFunctionCall(params, mappingPtr->name);
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
                SetOperands((GetArm64BranchOperandsPrefix(*insn, params.zone) + target.GetText()).c_str(), params.zone);
            } else {
                SetOperands(insn->op_str, params.zone); // indirect: the operands are shown as they are
                const auto switchJump = params.zone->switchJumps.find(address);
                if (switchJump != params.zone->switchJumps.end())
                    autoComment = "switch: " + std::to_string(switchJump->second) + " cases";
            }
            return true;
        }

        // a call through an import thunk (call j_CreateFileW): the arguments of the import
        if (shouldConsiderCall) {
            const auto thunk = params.zone->thunkImports.find(operands.directTarget.value());
            if (thunk != params.zone->thunkImports.end())
                AnnounceKnownFunctionCall(params, thunk->second);
        }

        // the label of the target with its current name (renamed, an export, a function reached by a jmp keeps its sub_ label); a target
        // without a label (the deep scan is disabled): the name it would have
        std::string labelName = params.zone->GetLabelNameAt(operands.directTarget.value());
        if (labelName.empty())
            labelName = params.zone->GetLabelName(shouldConsiderCall ? "sub_" : "loc_", operands.directTarget.value());
        labelName = GetArm64BranchOperandsPrefix(*insn, params.zone) + labelName; // cbz x0, loc_... / tbnz w1, #3, loc_...
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

    // the branches going to the same line share one arrow: its lane spans the target and all its sources. A jump to a line that is not
    // drawn (above or below the view) gets an arrow to the edge of the view, without a head (IDA like)
    constexpr uint32 NO_LANE = UINT32_MAX;
    enum class Edge : uint8 { None, Above, Below };
    struct Arrow {
        size_t first, last;
        size_t target;        // the target line (Edge::None)
        uint64 targetAddress; // the target of the arrows that go to an edge
        Edge edge;
        uint32 lane;
        std::vector<size_t> sources;
    };
    std::vector<Arrow> arrows;
    for (size_t sourceIndex = 0; sourceIndex < linesCount; sourceIndex++) {
        const auto& source = cachedAsmLines[sourceIndex];
        if (source.flags != Line::InstructionFlag::CallFlag && source.flags != Line::InstructionFlag::JmpFlag)
            continue;
        if (!source.branchTarget.has_value())
            continue;
        const uint64 target = source.branchTarget.value();
        if (target < minimalAddress || target > maximalAddress) {
            // only the jumps (the calls go to other functions, their arrows would cover the view)
            if (source.flags != Line::InstructionFlag::JmpFlag)
                continue;
            const Edge edge = target < minimalAddress ? Edge::Above : Edge::Below;
            auto arrow      = std::find_if(arrows.begin(), arrows.end(), [&](const Arrow& a) { return a.edge == edge && a.targetAddress == target; });
            if (arrow == arrows.end()) {
                const size_t first = edge == Edge::Above ? 0 : sourceIndex;
                const size_t last  = edge == Edge::Above ? sourceIndex : linesCount - 1;
                arrows.push_back({ first, last, SIZE_MAX, target, edge, NO_LANE, { sourceIndex } });
            } else {
                arrow->first = std::min(arrow->first, sourceIndex);
                arrow->last  = std::max(arrow->last, sourceIndex);
                arrow->sources.push_back(sourceIndex);
            }
            continue;
        }
        // first visible line placed at the target (its label when it has one); a target in the middle of an instruction has no line
        const auto targetIt = std::find_if(cachedAsmLines.begin(), cachedAsmLines.end(), [target](const Line& line) { return line.address == target; });
        if (targetIt == cachedAsmLines.end())
            continue;
        const size_t targetIndex = static_cast<size_t>(targetIt - cachedAsmLines.begin());
        if (targetIndex == sourceIndex)
            continue;

        const auto arrow = std::find_if(arrows.begin(), arrows.end(), [targetIndex](const Arrow& a) { return a.edge == Edge::None && a.target == targetIndex; });
        if (arrow == arrows.end()) {
            arrows.push_back({ std::min(sourceIndex, targetIndex), std::max(sourceIndex, targetIndex), targetIndex, target, Edge::None, NO_LANE, { sourceIndex } });
        } else {
            arrow->first = std::min(arrow->first, sourceIndex);
            arrow->last  = std::max(arrow->last, sourceIndex);
            arrow->sources.push_back(sourceIndex);
        }
    }

    // the arrows that are drawn whole get the lanes first; the shortest arrows get the lanes next to the code and the longer ones go
    // around them; arrows sharing a line never share a lane, the ones that do not fit are not drawn
    std::sort(arrows.begin(), arrows.end(), [](const Arrow& a, const Arrow& b) {
        if ((a.edge == Edge::None) != (b.edge == Edge::None))
            return a.edge == Edge::None;
        if (a.last - a.first != b.last - b.first)
            return a.last - a.first < b.last - b.first;
        return a.targetAddress < b.targetAddress;
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
    for (const auto& arrow : arrows) {
        if (arrow.lane == NO_LANE)
            continue;
        for (size_t i = arrow.first; i <= arrow.last; i++) {
            if (i > arrow.first)
                cachedAsmLines[i].arrowCells[arrow.lane] |= Line::ArrowUp;
            if (i < arrow.last)
                cachedAsmLines[i].arrowCells[arrow.lane] |= Line::ArrowDown;
        }
        // the line continues out of the view
        if (arrow.edge == Edge::Above)
            cachedAsmLines[arrow.first].arrowCells[arrow.lane] |= Line::ArrowUp;
        else if (arrow.edge == Edge::Below)
            cachedAsmLines[arrow.last].arrowCells[arrow.lane] |= Line::ArrowDown;
        else
            addHorizontalLine(cachedAsmLines[arrow.target], arrow.lane, true);
        for (const size_t source : arrow.sources)
            addHorizontalLine(cachedAsmLines[source], arrow.lane, false);
    }
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
        // the zone is prepared before its title is drawn: the title shows the progress of the deep scan from the first paint
        if (!zone->isInit && !InitDissasmCodeZone(dli, zone))
            return false;
        // a GoTo that waited for the zone (GoToFileOffset): the cursor moves now, the lines are drawn again at the next frame
        if (pendingGoTo.has_value() && pendingGoTo.value() >= zone->zoneDetails.startingZonePoint &&
            pendingGoTo.value() - zone->zoneDetails.startingZonePoint < zone->zoneDetails.size) {
            const uint64 fileOffset = pendingGoTo.value();
            pendingGoTo.reset();
            MoveCursorToZoneFileOffset(zone, fileOffset, true);
            repaintRequested = true;
        }

        constexpr std::string_view zoneName = "Dissasm zone";
        chars.Add(zoneName.data(), ColorMan.Colors.StructureColor);
        uint32 titleSize = static_cast<uint32>(zoneName.size());
        if (zone->cacheRecordRejected) {
            // the saved annotations do not match this analysis: they are kept aside in the cache file, the user must know they are not shown
            constexpr std::string_view warning = " - the saved comments and labels could not be applied (kept in the cache file)";
            chars.Add(warning.data(), ColorMan.Colors.AsmComment);
            titleSize += static_cast<uint32>(warning.size());
        }
        if (aiNaming.zone == zone) {
            LocalString<64> progress;
            progress.SetFormat(" - assistant naming %u/%u (Esc stops it)", aiNaming.answered, aiNaming.total);
            chars.Add(progress, ColorMan.Colors.AsmComment);
            titleSize += progress.Len();
        }
        if (zone->IsDeepScanPending()) {
            LocalString<64> progress;
            progress.SetFormat(zone->IsCountingLines() ? " - reading the code %u%% (Esc: no analysis)" : " - analyzing %u%% (Esc stops it)",
                               static_cast<uint32>(zone->GetDeepScanProgress() * 100.0f));
            chars.Add(progress, ColorMan.Colors.AsmComment);
            titleSize += progress.Len();
        }

        updateLinePointers();
        HighlightSelectionAndDrawCursorText(dli, titleSize, titleSize + Layout.startingTextLineOffset);

        dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, false);

        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);
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
    std::string comment, aiComment;
    const bool showComments   = !asmCacheLine->isCollapsedLine;
    const bool hasUserComment = showComments && zone->GetComment(*asmCacheLine, comment);
    const bool hasAutoComment = showComments && !asmCacheLine->autoComment.empty();
    // the suggestions of the assistant (Ctrl+Shift+A hides them): a comment, a name for a label
    const auto suggestedName = showAISuggestions ? zone->GetSuggestedName(*asmCacheLine) : std::nullopt;
    if (showAISuggestions && zone->GetAIComment(*asmCacheLine, aiComment))
        aiComment = "AI: " + aiComment;
    else
        aiComment.clear();
    if (suggestedName.has_value())
        aiComment = "AI name: " + suggestedName.value() + " (A accepts)" + (aiComment.empty() ? "" : " ; " + aiComment);
    const bool hasAIComment = !aiComment.empty();
    if (hasUserComment || hasAutoComment || hasAIComment) {
        // the comments are aligned after the longest line, up to a limit: a long operand (a demangled import name) would push the comments
        // of all the drawn lines out of the screen; a longer line has its comment right after it
        constexpr uint32 MAX_ALIGNED_LINE_SIZE = 64;
        uint32 diffLine = std::min(zone->asmPreCacheData.maxLineSize, MAX_ALIGNED_LINE_SIZE) + textTotalColumnLength + commentPaddingLength;
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
        if (hasAIComment) {
            // the suggestion of the assistant after the comment of the user, in the color of the local variables (not the user's text)
            if (hasUserComment)
                chars.Add(" ;", ColorMan.Colors.AsmComment);
            chars.Add(" ", ColorMan.Colors.AsmComment);
            chars.Add(aiComment, ColorMan.Colors.AsmLocalVariableColor);
        }
        if (hasAutoComment) {
            // the generated text after the comment of the user, in the color of the referenced locations
            if (hasUserComment || hasAIComment)
                chars.Add(" ;", ColorMan.Colors.AsmComment);
            chars.Add(" ", ColorMan.Colors.AsmComment);
            chars.Add(asmCacheLine->autoComment, ColorMan.Colors.AsmLocationInstruction);
        }
    }

    // every occurrence of the name / register / number under the cursor (IDA like), in the instructions and the comments
    if (arrowsColumn != UINT32_MAX) {
        const std::string token = GetCursorToken();
        if (!token.empty())
            HighlightTokenOccurrences(chars, arrowsColumn + DissasmAsmPreCacheLine::ARROW_COLUMNS, token, ColorMan.Colors.Highlight);
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
    // the label of a function: a line in the empty columns of the bytes, it separates the functions
    const bool isFunctionLabel = asmCacheLine->size == 0 && !asmCacheLine->isCollapsedLine &&
                                 asmCacheLine->localVariableKind != DissasmAsmPreCacheLine::LocalVariableKind::Definition &&
                                 std::binary_search(zone->functionStarts.begin(), zone->functionStarts.end(), asmCacheLine->address);
    if (isFunctionLabel && arrowsColumn != UINT32_MAX) {
        const uint32 columnsStart = Layout.startingTextLineOffset + addressTotalLength;
        for (uint32 column = columnsStart; column < arrowsColumn && column < bufferToDraw.length(); column++)
            if (bufferToDraw[column].Code == ' ')
                dli.renderer.WriteSpecialCharacter(
                      static_cast<int>(column), static_cast<int>(dli.screenLineToDraw) + 1, SpecialChars::BoxHorizontalSingleLine, ColorMan.Colors.AsmTitleColumnColor);
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
    initData.alignPadding                  = config.AlignPadding;
    initData.obj                           = obj;
    initData.dli                           = &dli;
    initData.visibleRows                   = Layout.visibleRows;
    // a big zone is shown before its deep scan ends: the scan continues in the frame updates (OnFrameUpdate)
    constexpr auto DEEP_SCAN_BUDGET_IN_INIT = std::chrono::milliseconds(150);
    initData.deepScanBudget                 = DEEP_SCAN_BUDGET_IN_INIT;
    // a big zone shows its first lines before the end of its code is read: the count continues in the frame updates (a frontend without
    // frame updates ends it at the first key, as the deep scan)
    constexpr auto LINE_COUNT_BUDGET_IN_INIT = std::chrono::milliseconds(100);
    initData.lineCountBudget                 = LINE_COUNT_BUDGET_IN_INIT;
    PrepareCodeZoneInitData(settings.get(), obj, zone, initData);

    if (!zone->InitZone(initData))
        return false;
    if (initData.hasAdjustedSize)
        AdjustZoneExtendedSize(zone, initData.adjustedZoneSize);
    if (zone->IsDeepScanPending())
        return true; // the user data of the cache needs the labels: applied when the scan ends (EndDeepScan)

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

void GView::View::DissasmViewer::PrepareCodeZoneInitData(SettingsData* settings, Reference<GView::Object> obj, DissasmCodeZone* zone, DissasmCodeZoneInitData& initData)
{
    initData.obj = obj;
    // the labels are named after the VA (as IDA), when the plugin translates the file offsets
    if (settings->offsetTranslateCallback.IsValid()) {
        const auto va = settings->offsetTranslateCallback->TranslateFromFileOffset(zone->zoneDetails.startingZonePoint, static_cast<uint32>(DissasmPEConversionType::VA));
        if (va != static_cast<uint64>(-1))
            initData.labelAddressBase = va;
    }
    // the cross references of the immediates / absolute operands: only the addresses that are locations of the file
    const uint64 fileSize = obj->GetData().GetSize();
    if (initData.labelAddressBase.has_value()) {
        auto* settingsData           = settings;
        initData.addressToFileOffset = [settingsData, fileSize](uint64 va) -> std::optional<uint64> {
            const auto offset = settingsData->offsetTranslateCallback->TranslateToFileOffset(va, static_cast<uint32>(DissasmPEConversionType::VA));
            return offset < fileSize ? std::optional<uint64>(offset) : std::nullopt;
        };
        // the image base: the VA of the zone start minus its RVA
        const auto rva = settings->offsetTranslateCallback->TranslateFromFileOffset(zone->zoneDetails.startingZonePoint, static_cast<uint32>(DissasmPEConversionType::RVA));
        if (rva != static_cast<uint64>(-1) && rva <= initData.labelAddressBase.value())
            initData.imageBase = initData.labelAddressBase.value() - rva;
    } else {
        initData.addressToFileOffset = [fileSize](uint64 offset) -> std::optional<uint64> {
            return offset < fileSize ? std::optional<uint64>(offset) : std::nullopt;
        };
    }
    initData.isFileAddress = [toFileOffset = initData.addressToFileOffset](uint64 address) { return toFileOffset(address).has_value(); };
    initData.functionEntries       = &settings->functionEntries;
    initData.instructionBoundaries = &settings->instructionBoundaries;
    if (!settings->memoryMappings.empty()) {
        auto* settingsData  = settings;
        initData.findImport = [settingsData, zone](const X86OperandsInfo& operands) { return FindX86OperandsImport(settingsData, zone, operands); };
    }

}

bool Instance::HasPendingDeepScans() const
{
    for (const auto& zone : settings->parseZones)
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone && static_cast<const DissasmCodeZone*>(zone.get())->IsDeepScanPending())
            return true;
    return false;
}

void Instance::EndDeepScan(DissasmCodeZone* zone, bool cancel)
{
    // until the scan ends the lines of the zone are its instructions: the cursor stays on the same instruction (the view moves with it)
    const uint32 cursorLine = Cursor.startViewLine + Cursor.lineInView;
    const uint32 firstLine  = zone->startLineIndex + 2u; // +1 for the title, +1 for the columns header
    std::optional<uint32> cursorInstruction;
    if (cursorLine >= firstLine && cursorLine - firstLine < zone->asmLinesCount)
        cursorInstruction = cursorLine - firstLine;

    if (cancel)
        zone->CancelDeepScan();
    else
        zone->CommitDeepScan();
    AdjustZoneExtendedSize(zone, zone->GetDisplayLinesCount() + 1u); // +1 for the title
    bool zoneLinesChanged = false;
    zone->TryLoadDataFromCache(cacheData, zoneLinesChanged); // the user data was waiting for the labels
    if (zoneLinesChanged)
        AdjustZoneExtendedSize(zone, zone->GetDisplayLinesCount() + 1u);

    if (cursorInstruction.has_value()) {
        const uint32 newLine = firstLine + zone->ExpandedToDisplay(zone->InstructionIndexToExpanded(cursorInstruction.value()));
        if (newLine >= cursorLine)
            Cursor.startViewLine += newLine - cursorLine;
        else
            Cursor.startViewLine -= std::min(Cursor.startViewLine, cursorLine - newLine);
        Cursor.hasMovedView = true;
    }
    zone->asmPreCacheData.Clear();
}

void Instance::FinishDeepScans()
{
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto codeZone = static_cast<DissasmCodeZone*>(zone.get());
        if (!codeZone->IsDeepScanPending())
            continue;
        codeZone->ContinueDeepScan(std::chrono::steady_clock::time_point::max());
        EndDeepScan(codeZone, false);
    }
}

void Instance::CancelDeepScans()
{
    for (const auto& zone : settings->parseZones)
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone && static_cast<DissasmCodeZone*>(zone.get())->IsDeepScanPending())
            EndDeepScan(static_cast<DissasmCodeZone*>(zone.get()), true);
}

bool Instance::OnFrameUpdate()
{
    frameUpdatesSeen   = true;
    bool repaintAsked  = repaintRequested;
    repaintRequested   = false;
    if (aiNaming.zone && !HasPendingDeepScans()) { // the requests of the assistant (the labels must be known)
        const uint32 answered = aiNaming.answered;
        if (!RunAINamingStep(false) || aiNaming.answered != answered) {
            RefreshDrawnLines(); // a new suggestion, the progress in the title
            repaintAsked = true;
        }
    }
    if (!HasPendingDeepScans())
        return repaintAsked;
    // a slice of every frame (~30 per second): the UI stays responsive while the scan runs
    constexpr auto DEEP_SCAN_SLICE = std::chrono::milliseconds(12);
    constexpr uint32 PROGRESS_REPAINT_FRAMES = 8; // the progress in the title of the zone
    bool repaint = repaintAsked || ++deepScanFrames % PROGRESS_REPAINT_FRAMES == 0;
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto codeZone = static_cast<DissasmCodeZone*>(zone.get());
        if (!codeZone->IsDeepScanPending())
            continue;
        const bool counting = codeZone->IsCountingLines();
        const bool ended    = codeZone->ContinueDeepScan(std::chrono::steady_clock::now() + DEEP_SCAN_SLICE);
        if (ended) {
            EndDeepScan(codeZone, false);
            repaint = true;
        } else if (counting) {
            AdjustZoneExtendedSize(codeZone, codeZone->GetDisplayLinesCount() + 1u); // the lines read in this frame (+1 for the title)
            repaint = true;
        }
    }
    return repaint;
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
          zone.GetArchitectureName(),
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
    auto appendLine        = [&](const DissasmAsmPreCacheLine& asmLine) {
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
            listing.append("\n").append(asmLine.GetMnemonicText()).append(":"); // label
        } else {
            if (operands.empty()) // ret, int3: no padding after the mnemonic
                text.SetFormat("0x%08" PRIx64 "  %s", asmLine.address + codeStart, asmLine.mnemonic);
            else
                text.SetFormat("0x%08" PRIx64 "  %-7s", asmLine.address + codeStart, asmLine.mnemonic);
            listing.append(text.GetText(), text.Len()).append(operands);
        }

        bool hasComment = !asmLine.isCollapsedLine && zone.GetComment(asmLine, comment);
        // the suggestions of the assistant, marked, after the comment of the user
        std::string aiComment;
        if (zone.GetAIComment(asmLine, aiComment))
            aiComment = "AI: " + aiComment;
        if (const auto name = zone.GetSuggestedName(asmLine); name.has_value())
            aiComment = "AI name: " + name.value() + (aiComment.empty() ? "" : " ; " + aiComment);
        if (!aiComment.empty()) {
            comment    = hasComment ? comment + " ; " + aiComment : aiComment;
            hasComment = true;
        }
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
    };

    // the lines wait in the drawn lines cache before they are written: a call names its arguments on the lines placed before it (as on
    // the screen, AnnounceCallInstruction)
    constexpr size_t WAITING_LINES = 24;
    auto& waitingLines             = zone.asmPreCacheData.cachedAsmLines;
    waitingLines.clear();
    auto writeWaitingLines = [&](size_t linesToKeep) {
        if (waitingLines.size() <= linesToKeep)
            return;
        const size_t linesToWrite = waitingLines.size() - linesToKeep;
        for (size_t index = 0; index < linesToWrite; index++)
            appendLine(waitingLines[index]);
        std::vector<DissasmAsmPreCacheLine> kept; // the lines can not be assigned (they own their operands): moved in a new vector
        kept.reserve(WAITING_LINES * 2);
        for (size_t index = linesToWrite; index < waitingLines.size(); index++)
            kept.emplace_back(std::move(waitingLines[index]));
        waitingLines.swap(kept);
    };
    for (uint32 line = 0; line < linesCount; line++) {
        auto asmLine = zone.GetCurrentAsmLine(line, obj, &params);
        waitingLines.emplace_back(std::move(asmLine));
        if (waitingLines.size() >= WAITING_LINES * 2)
            writeWaitingLines(WAITING_LINES);
    }
    writeWaitingLines(0);
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
        if (!DissasmCodeZone::IsNativeCodeLanguage(language)) {
            Dialogs::MessageBox::ShowNotification("Warning", "Only the x86 / x64 / ARM64 zones can be exported!");
            continue;
        }
        if (!codeZone->CanReachAsmLines()) {
            Dialogs::MessageBox::ShowNotification("Warning", "The dissasm zone is not analysed yet: scroll to it once and export it again!");
            continue;
        }

        // the default file: next to the analysed file, the user picks the location (the folder of the file can be read only)
        const std::filesystem::path filePath = obj->GetPath();
        LocalString<256> fileName;
        fileName.SetFormat("%s.z%u.%s.asm", reinterpret_cast<const char*>(filePath.filename().u8string().c_str()), index, codeZone->GetArchitectureName());
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
        if (!IsX86Branch(GetInstructionFlow(*insn, zone->GetArch()))) {
            cs_free(insn, 1);
            return;
        }
        // file offsets, like the displayed operand (TryGetDataFromInsn): the decoded addresses start at the first decoded instruction
        jumpFromAddress = zone->GetFileOffsetOfAddress(insn->address).value_or(0);
        for (size_t i = 0; i + 1 < sizeof(jumpMnemonic) && insn->mnemonic[i] != 0; i++)
            jumpMnemonic[i] = insn->mnemonic[i];
        const auto target       = GetInstructionOperands(*insn, zone->GetArch()).directTarget;
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
    cursorLineNumbers.location.clear();
    cursorLineNumbers.operands.clear();
    cursorLineNumbers.operandColumns.clear();

    const auto zonesFound = GetZonesIndexesFromLinePosition(line);
    if (zonesFound.size() != 1)
        return;
    const auto& parseZone = settings->parseZones[zonesFound[0].zoneIndex];
    if (parseZone->zoneType != DissasmParseZoneType::DissasmCodeParseZone || parseZone->isCollapsed)
        return;
    const auto zone     = static_cast<DissasmCodeZone*>(parseZone.get());
    const auto language = zone->zoneDetails.language;
    if (!zone->isInit || zone->cachedCodeOffsets.empty() || !DissasmCodeZone::IsNativeCodeLanguage(language))
        return;
    // zone line 0 is the title and line 1 the columns header; when the zone title is scrolled out, the first row shows the header
    const uint32 zoneLine = zonesFound[0].startingLine;
    if (zoneLine < 2 || Cursor.lineInView == 0)
        return;

    // the same line (and layout) as the one that is drawn; without the known functions: a call would name the arguments on the drawn lines
    // (AnnounceCallInstruction), this line is built while they are drawn
    AsmData withoutKnownFunctions;
    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.settings = settings.get();
    params.asmData  = &withoutKnownFunctions;
    params.dli      = nullptr;
    params.zone     = zone;
    auto asmLine    = zone->GetCurrentAsmLine(zoneLine - 2u, obj, &params);

    // where the cursor is: sub_140001010+0x1A, the file offset (labels and local variables included)
    if (!asmLine.isCollapsedLine) {
        LocalString<32> fileOffset;
        fileOffset.SetFormat("  file offset 0x%llX", static_cast<unsigned long long>(zone->cachedCodeOffsets[0].offset + asmLine.address));
        cursorLineNumbers.location = zone->FormatCodeAddress(asmLine.address) + fileOffset.GetText();
    }

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
    cursorLineNumbers.operands.assign(asmLine.op_str, asmLine.op_str_size);
    cursorLineNumbers.operandColumns = opStrColumns;

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

std::string Instance::GetCursorToken()
{
    RefreshCursorLineNumbers();
    if (!cursorLineNumbers.valid)
        return {};
    const auto& operands = cursorLineNumbers.operands;
    const auto& columns  = cursorLineNumbers.operandColumns;
    size_t position      = SIZE_MAX;
    for (size_t index = 0; index < columns.size() && index < operands.size(); index++)
        if (columns[index] == Cursor.offset) {
            position = index;
            break;
        }
    if (position == SIZE_MAX || !IsTokenCharacter(static_cast<unsigned char>(operands[position])))
        return {};
    size_t start = position, end = position + 1;
    while (start > 0 && IsTokenCharacter(static_cast<unsigned char>(operands[start - 1])))
        start--;
    while (end < operands.size() && IsTokenCharacter(static_cast<unsigned char>(operands[end])))
        end++;
    return operands.substr(start, end - start);
}

int Instance::PrintCursorLocationInfo(int x, int y, Renderer& r)
{
    RefreshCursorLineNumbers();
    if (cursorLineNumbers.location.empty())
        return x;
    r.WriteSingleLineText(x, y, "At:", this->ColorMan.Colors.CursorHighlighted);
    r.WriteSingleLineText(x + 4, y, cursorLineNumbers.location, this->ColorMan.Colors.CursorNormal);
    return x + 4 + static_cast<int>(cursorLineNumbers.location.size()) + 1;
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
            if (!RenameLabel(labelLine, labelName, newNameText))
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
                if (!RenameLabel(labelLine, currentName, res)) {
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
    ShowXrefsTo(zone, zone->labelAddressBase + target, targetName);
}

void Instance::ShowXrefsTo(DissasmCodeZone* zone, uint64 target, const std::string& targetName)
{
    const auto [first, last] = zone->xrefs.To(target);
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
                      IsX86Branch(GetInstructionFlow(*insn, zone->GetArch())) ? GetInstructionOperands(*insn, zone->GetArch()) : X86OperandsInfo{};
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

// The functions of the analysis (IDA Shift+F3): name, address, size, references; the search bar filters them, Enter / Go jumps to one
class FunctionsWindow : public AppCUI::Controls::Window
{
    static constexpr int BTN_GO    = 1;
    static constexpr int BTN_CLOSE = 2;
    Reference<ListView> list;
    std::optional<size_t> selectedRow;

  public:
    FunctionsWindow(const std::vector<DissasmFunctionInfo>& functions, uint64 labelAddressBase)
        : Window("Functions", "d:c,w:90%,h:80%", WindowFlags::Sizeable)
    {
        list = Factory::ListView::Create(
              this,
              "l:1,t:1,r:1,b:3",
              { "n:Name,w:50", "n:Address,w:20", "n:Size,w:12,a:r", "n:Xrefs,w:8,a:r", "n:Kind,w:10" },
              ListViewFlags::PopupSearchBar | ListViewFlags::Sortable);
        LocalString<32> address, size, xrefs;
        for (size_t index = 0; index < functions.size(); index++) {
            const auto& function = functions[index];
            // the numbers are padded: the columns are sorted by their text
            address.SetFormat("0x%016llx", static_cast<unsigned long long>(labelAddressBase + function.start));
            size.SetFormat("%10llu", static_cast<unsigned long long>(function.size));
            xrefs.SetFormat("%6u", function.xrefs);
            const std::string_view kind = function.isEntryPoint ? "entry" : (function.isExport ? "export" : (function.isThunk ? "thunk" : ""));
            auto item = list->AddItem({ std::string_view(function.name), address.ToStringView(), size.ToStringView(), xrefs.ToStringView(), kind });
            item.SetData(static_cast<uint64>(index));
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

void Instance::ShowFunctions()
{
    // the code zone of the cursor, or the first code zone
    DissasmCodeZone* zone = nullptr;
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex]->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
        zone = static_cast<DissasmCodeZone*>(settings->parseZones[zonesFound[0].zoneIndex].get());
    for (size_t index = 0; !zone && index < settings->parseZones.size(); index++)
        if (settings->parseZones[index]->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
            zone = static_cast<DissasmCodeZone*>(settings->parseZones[index].get());
    if (!zone || !zone->isInit || !zone->CanReachAsmLines()) {
        Dialogs::MessageBox::ShowNotification("Info", "The functions are found when the disassembly zone is shown!");
        return;
    }
    const auto functions = zone->GetFunctions(&settings->functionEntries);
    if (functions.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The functions are found by the deep scan (Config.DeepScanDissasmOnStart)!");
        return;
    }
    FunctionsWindow window(functions, zone->labelAddressBase);
    if (window.Show() != Dialogs::Result::Ok || !window.GetSelectedRow().has_value())
        return;
    MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + functions[window.GetSelectedRow().value()].start, true);
}

// The search (Ctrl+F): the text of the listing, a byte pattern or an immediate value; F6 finds the next match
class FindDialog : public AppCUI::Controls::Window
{
    static constexpr int BTN_OK         = 1;
    static constexpr int BTN_CANCEL     = 2;
    static constexpr int KIND_GROUP     = 3;
    static constexpr int KIND_TEXT      = 10;
    static constexpr int KIND_BYTES     = 11;
    static constexpr int KIND_IMMEDIATE = 12;
    Reference<TextField> textField;
    Reference<RadioBox> textKind, bytesKind, immediateKind;
    Reference<CheckBox> matchCase;
    DissasmSearch result;

    void Validate()
    {
        LocalString<256> text;
        if (!text.Set(textField->GetText()) || text.Len() == 0) {
            Dialogs::MessageBox::ShowError("Error", "Please write what to search!");
            textField->SetFocus();
            return;
        }
        result.text      = text.GetText();
        result.matchCase = matchCase->IsChecked();
        result.kind      = bytesKind->IsChecked() ? DissasmSearchKind::Bytes
                                                  : (immediateKind->IsChecked() ? DissasmSearchKind::Immediate : DissasmSearchKind::Text);
        if (result.kind == DissasmSearchKind::Bytes && !ParseDissasmBytePattern(result.text).has_value()) {
            Dialogs::MessageBox::ShowError("Error", "Expecting hexadecimal bytes, ?? for any byte (48 8B ?? 05)!");
            textField->SetFocus();
            return;
        }
        if (result.kind == DissasmSearchKind::Immediate && !ParseDissasmSearchNumber(result.text).has_value()) {
            Dialogs::MessageBox::ShowError("Error", "Expecting a decimal number, or hexadecimal with 0x / h (0x1000, 1000h)!");
            textField->SetFocus();
            return;
        }
        Exit(Dialogs::Result::Ok);
    }

  public:
    FindDialog(const std::optional<DissasmSearch>& last) : Window("Find", "d:c,w:70,h:13", WindowFlags::ProcessReturn)
    {
        Factory::Label::Create(this, "&Find:", "x:1,y:1,w:8");
        textField = Factory::TextField::Create(this, last.has_value() ? std::string_view(last->text) : std::string_view(), "x:10,y:1,w:56");
        textField->SetHotKey('F');
        const auto kind = last.has_value() ? last->kind : DissasmSearchKind::Text;
        textKind  = Factory::RadioBox::Create(this, "&Text of the listing (labels, instructions, comments)", "x:1,y:3,w:64", KIND_GROUP, KIND_TEXT,
                                             kind == DissasmSearchKind::Text);
        bytesKind = Factory::RadioBox::Create(this, "&Bytes (48 8B ?? 05, ?? is any byte)", "x:1,y:4,w:64", KIND_GROUP, KIND_BYTES,
                                              kind == DissasmSearchKind::Bytes);
        immediateKind = Factory::RadioBox::Create(this, "&Immediate value (4096, 0x1000, 1000h)", "x:1,y:5,w:64", KIND_GROUP, KIND_IMMEDIATE,
                                                  kind == DissasmSearchKind::Immediate);
        matchCase = Factory::CheckBox::Create(this, "&Match case (text)", "x:1,y:7,w:30");
        matchCase->SetChecked(last.has_value() && last->matchCase);
        Factory::Label::Create(this, "The search starts after the cursor; F6 finds the next match", "x:1,y:8,w:66");
        Factory::Button::Create(this, "&OK", "l:21,b:0,w:13", BTN_OK);
        Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_CANCEL);
        textField->SetFocus();
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (eventType == Event::ButtonClicked && ID == BTN_OK) {
            Validate();
            return true;
        }
        if ((eventType == Event::ButtonClicked && ID == BTN_CANCEL) || eventType == Event::WindowClose) {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        if (eventType == Event::WindowAccept) {
            Validate();
            return true;
        }
        return Window::OnEvent(control, eventType, ID);
    }

    const DissasmSearch& GetResult() const
    {
        return result;
    }
};

bool Instance::ShowFindDialog()
{
    FindDialog dialog(lastSearch);
    if (dialog.Show() != Dialogs::Result::Ok)
        return true;
    lastSearch = dialog.GetResult();
    RunSearch(lastSearch.value(), true);
    return true;
}

void Instance::FindNext()
{
    if (!lastSearch.has_value()) {
        ShowFindDialog();
        return;
    }
    RunSearch(lastSearch.value(), true);
}

bool Instance::RunSearch(const DissasmSearch& search, bool showErrors)
{
    FinishDeepScans(); // the labels are searched too

    // the code zone of the cursor (or the first one); the search starts after the cursor and continues from the start of the zone
    DissasmCodeZone* zone = nullptr;
    std::optional<uint32> cursorZoneLine;
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex]->zoneType == DissasmParseZoneType::DissasmCodeParseZone) {
        zone = static_cast<DissasmCodeZone*>(settings->parseZones[zonesFound[0].zoneIndex].get());
        if (zonesFound[0].startingLine >= 2)
            cursorZoneLine = zonesFound[0].startingLine - 2u; // the title and the columns header
    }
    for (size_t index = 0; !zone && index < settings->parseZones.size(); index++)
        if (settings->parseZones[index]->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
            zone = static_cast<DissasmCodeZone*>(settings->parseZones[index].get());
    if (!zone || !zone->isInit || !zone->CanReachAsmLines() || zone->isCollapsed) {
        if (showErrors)
            Dialogs::MessageBox::ShowNotification("Info", "The search needs a shown disassembly zone!");
        return false;
    }

    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.zone     = zone;
    params.settings = settings.get();
    params.asmData  = &asmData;
    const uint32 linesCount = zone->GetDisplayLinesCount();
    bool found              = false;
    if (search.kind == DissasmSearchKind::Text) {
        const uint32 from = cursorZoneLine.has_value() ? cursorZoneLine.value() + 1u : 0u;
        auto line         = zone->FindText(search.text, search.matchCase, from, linesCount, &params);
        if (!line.has_value() && from > 0)
            line = zone->FindText(search.text, search.matchCase, 0, from, &params);
        if (line.has_value()) {
            // the found line gets the cursor, a few lines below the top of the view
            const uint32 zoneLine = line.value() + 2u;
            const auto from       = SaveCursorState();
            Cursor.lineInView     = std::min<uint32>(5, zoneLine);
            Cursor.startViewLine  = zoneLine + zone->startLineIndex - Cursor.lineInView;
            Cursor.hasMovedView   = true;
            RecordJump(from);
            found = true;
        }
    } else {
        // the instruction of the cursor: the bytes are searched after its first byte, the immediates from the next instruction
        uint64 from = 0;
        if (cursorZoneLine.has_value() && cursorZoneLine.value() < linesCount) {
            const auto cursorLine = zone->GetCurrentAsmLine(cursorZoneLine.value(), obj, &params);
            from                  = cursorLine.address + (cursorLine.size == 0 ? 0u : (search.kind == DissasmSearchKind::Bytes ? 1u : cursorLine.size));
        }
        const uint64 codeSize = zone->GetCodeSize();
        std::optional<uint64> address;
        if (search.kind == DissasmSearchKind::Bytes) {
            const auto pattern = ParseDissasmBytePattern(search.text);
            if (pattern.has_value()) {
                address = zone->FindBytes(pattern.value(), from, codeSize);
                if (!address.has_value() && from > 0)
                    address = zone->FindBytes(pattern.value(), 0, std::min<uint64>(codeSize, from + pattern->size() - 1));
            }
        } else {
            const auto value = ParseDissasmSearchNumber(search.text);
            if (value.has_value()) {
                address = zone->FindImmediate(value.value(), from, codeSize);
                if (!address.has_value() && from > 0)
                    address = zone->FindImmediate(value.value(), 0, from);
            }
        }
        if (address.has_value())
            found = MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + address.value(), false);
    }
    zone->asmPreCacheData.Clear(); // the decoding position moved: the drawn lines are prepared again
    if (!found && showErrors)
        Dialogs::MessageBox::ShowNotification("Find", "`" + search.text + "` was not found!");
    return found;
}

// The strings used by the code (IDA Shift+F12): the search bar filters them, Enter shows the instructions that use the selected one
class StringsWindow : public AppCUI::Controls::Window
{
    static constexpr int BTN_GO    = 1;
    static constexpr int BTN_CLOSE = 2;
    Reference<ListView> list;
    std::optional<size_t> selectedRow;

  public:
    StringsWindow(const std::vector<DissasmStringReference>& strings) : Window("Strings", "d:c,w:90%,h:80%", WindowFlags::Sizeable)
    {
        list = Factory::ListView::Create(
              this, "l:1,t:1,r:1,b:3", { "n:String,w:90", "n:Address,w:20", "n:Xrefs,w:8,a:r" }, ListViewFlags::PopupSearchBar | ListViewFlags::Sortable);
        LocalString<32> address, xrefs;
        for (size_t index = 0; index < strings.size(); index++) {
            address.SetFormat("0x%016llx", static_cast<unsigned long long>(strings[index].address));
            xrefs.SetFormat("%6u", strings[index].xrefs); // padded: the columns are sorted by their text
            auto item = list->AddItem({ std::string_view(strings[index].text), address.ToStringView(), xrefs.ToStringView() });
            item.SetData(static_cast<uint64>(index));
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

void Instance::ShowStrings()
{
    DissasmCodeZone* zone = nullptr;
    for (size_t index = 0; !zone && index < settings->parseZones.size(); index++)
        if (settings->parseZones[index]->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
            zone = static_cast<DissasmCodeZone*>(settings->parseZones[index].get());
    if (!zone || !zone->isInit || !zone->CanReachAsmLines()) {
        Dialogs::MessageBox::ShowNotification("Info", "The strings are found when the disassembly zone is shown!");
        return;
    }
    // the addresses of the labels are VAs when the plugin translates the offsets, file offsets otherwise
    const uint64 fileSize          = obj->GetData().GetSize();
    auto* settingsData             = settings.get();
    const bool labelsAreVirtual    = settingsData->offsetTranslateCallback.IsValid() && zone->labelAddressBase != zone->zoneDetails.startingZonePoint;
    const auto addressToFileOffset = [settingsData, fileSize, labelsAreVirtual](uint64 address) -> std::optional<uint64> {
        const uint64 offset =
              labelsAreVirtual ? settingsData->offsetTranslateCallback->TranslateToFileOffset(address, static_cast<uint32>(DissasmPEConversionType::VA))
                               : address;
        return offset < fileSize ? std::optional<uint64>(offset) : std::nullopt;
    };
    const auto strings = zone->GetReferencedStrings(addressToFileOffset);
    if (strings.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "No strings are used by the code (they are found by the deep scan)!");
        return;
    }
    StringsWindow window(strings);
    if (window.Show() != Dialogs::Result::Ok || !window.GetSelectedRow().has_value())
        return;
    const auto& selected     = strings[window.GetSelectedRow().value()];
    const auto [first, last] = zone->xrefs.To(selected.address);
    if (last - first == 1) // used once: the instruction that uses it
        MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + (first->from - zone->labelAddressBase), false);
    else
        ShowXrefsTo(zone, selected.address, selected.text);
}

DissasmCodeZone* Instance::GetCursorOrFirstCodeZone()
{
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex]->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
        return static_cast<DissasmCodeZone*>(settings->parseZones[zonesFound[0].zoneIndex].get());
    for (const auto& zone : settings->parseZones)
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone)
            return static_cast<DissasmCodeZone*>(zone.get());
    return nullptr;
}

void Instance::UndoOrRedo(bool redo)
{
    const auto zone = GetCursorOrFirstCodeZone();
    if (!zone || !zone->isInit || !zone->CanReachAsmLines())
        return;
    if (redo ? !zone->CanRedoEdit() : !zone->CanUndoEdit()) {
        Dialogs::MessageBox::ShowNotification(redo ? "Redo" : "Undo", redo ? "There is nothing to redo!" : "There is nothing to undo!");
        return;
    }
    const auto place = redo ? zone->RedoEdit() : zone->UndoEdit();
    if (!place.has_value()) {
        Dialogs::MessageBox::ShowNotification(redo ? "Redo" : "Undo", "The edit can not be applied any more (its line changed)!");
        return;
    }
    AdjustZoneExtendedSize(zone, zone->GetDisplayLinesCount() + 1u); // +1 for the title: a zone added / removed changes the lines
    zone->asmPreCacheData.Clear();

    // the cursor goes to the edit
    if (place->address.has_value()) {
        MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + place->address.value(), place->onLabel);
    } else if (place->expandedLine.has_value()) {
        const uint32 zoneLine = zone->ExpandedToDisplay(place->expandedLine.value()) + 2u; // +1 for the title, +1 for the columns header
        const auto from       = SaveCursorState();
        Cursor.lineInView     = std::min<uint32>(5, zoneLine);
        Cursor.startViewLine  = zoneLine + zone->startLineIndex - Cursor.lineInView;
        Cursor.hasMovedView   = true;
        RecordJump(from);
    }
}

// Every action of the view with its key (Ctrl+P): the search bar filters them, Enter runs the selected one
class CommandPaletteWindow : public AppCUI::Controls::Window
{
    static constexpr int BTN_RUN   = 1;
    static constexpr int BTN_CLOSE = 2;
    Reference<ListView> list;
    std::optional<size_t> selectedRow;

  public:
    struct Row {
        std::string key, caption, explanation;
    };

    CommandPaletteWindow(const std::vector<Row>& rows) : Window("Commands", "d:c,w:90%,h:80%", WindowFlags::Sizeable)
    {
        list = Factory::ListView::Create(
              this, "l:1,t:1,r:1,b:3", { "n:Key,w:16", "n:Command,w:28", "n:Description,w:100" }, ListViewFlags::PopupSearchBar | ListViewFlags::Sortable);
        for (size_t index = 0; index < rows.size(); index++) {
            auto item = list->AddItem({ std::string_view(rows[index].key), std::string_view(rows[index].caption), std::string_view(rows[index].explanation) });
            item.SetData(static_cast<uint64>(index));
        }
        Factory::Button::Create(this, "&Run", "l:1,b:0,w:10", BTN_RUN);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:10", BTN_CLOSE);
        list->SetFocus();
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (Window::OnEvent(control, eventType, ID))
            return true;
        if (eventType == Event::ListViewItemPressed || (eventType == Event::ButtonClicked && ID == BTN_RUN)) {
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

void Instance::ShowCommandPalette()
{
    // the commands of the command bar, the keys of the view (comments, rename, zones) and the GoTo / Find of the window
    enum class Target : uint8 { Command, KeyCommand, GoTo, Find };
    struct Action {
        Target target;
        uint32 commandId;
    };
    std::vector<CommandPaletteWindow::Row> rows;
    std::vector<Action> actions;
    LocalString<64> keyName;
    auto add = [&](const KeyboardControl& control, Target target) {
        if (!KeyUtils::ToString(control.Key, keyName))
            keyName.Clear();
        rows.push_back({ keyName.GetText(), control.Caption ? control.Caption : "", control.Explanation ? control.Explanation : "" });
        actions.push_back({ target, control.CommandId });
    };
    for (const auto& control : config.AllKeyboardCommands)
        add(control.get(), Target::Command);
    for (const auto* control : config.KeyEventCommands) {
        const bool isMove = control->CommandId >= COMMAND_NAV_DOWN && control->CommandId <= COMMAND_NAV_SCROLL_RIGHT;
        const bool listed = std::any_of(config.AllKeyboardCommands.begin(), config.AllKeyboardCommands.end(), [control](const auto& other) {
            return other.get().CommandId == control->CommandId;
        });
        if (!isMove && !listed) // the moves are not actions; a key of both lists is listed once
            add(*control, Target::KeyCommand);
    }
    rows.push_back({ "F5", "GoTo", "Go to an address (VA / RVA / file offset) or a label name" });
    actions.push_back({ Target::GoTo, 0 });
    rows.push_back({ "Ctrl+F", "Find", "Find a text, a byte pattern or an immediate value" });
    actions.push_back({ Target::Find, 0 });

    CommandPaletteWindow window(rows);
    if (window.Show() != Dialogs::Result::Ok || !window.GetSelectedRow().has_value())
        return;
    const auto& action = actions[window.GetSelectedRow().value()];
    switch (action.target) {
    case Target::Command:
        OnEvent(nullptr, Event::Command, static_cast<int>(action.commandId));
        break;
    case Target::KeyCommand:
        FinishDeepScans();
        ExecuteNavigationCommand(action.commandId, false);
        break;
    case Target::GoTo:
        ShowGoToDialog();
        break;
    case Target::Find:
        ShowFindDialog();
        break;
    }
}

// The callers and the callees of a function (Ctrl+R): Enter on a function shows its own calls (Back returns), Go jumps to the selected
// function, Call site to the instruction of the call
class CallTreeWindow : public AppCUI::Controls::Window
{
    static constexpr int BTN_GO        = 1;
    static constexpr int BTN_CALL_SITE = 2;
    static constexpr int BTN_BACK      = 3;
    static constexpr int BTN_CLOSE     = 4;

    DissasmCodeZone* zone;
    std::function<const MemoryMappingEntry*(const X86OperandsInfo&)> findImport;
    Reference<Label> title;
    Reference<ListView> callersList, calleesList, lastList;
    std::vector<DissasmCallReference> callers, callees;
    std::vector<uint64> history; // the functions shown before the current one
    uint64 current = 0;
    std::optional<uint64> result;
    bool resultIsCallSite = false;

    static void Fill(Reference<ListView> list, const std::vector<DissasmCallReference>& references, const DissasmCodeZone* zone)
    {
        list->DeleteAllItems();
        for (size_t index = 0; index < references.size(); index++) {
            const auto& reference  = references[index];
            const std::string site = zone->FormatCodeAddress(reference.site) + (reference.isTailJump ? " (jmp)" : "");
            auto item              = list->AddItem({ std::string_view(reference.function), std::string_view(site) });
            item.SetData(static_cast<uint64>(index));
        }
    }

    void ShowFunction(uint64 functionStart)
    {
        current = functionStart;
        callers = zone->GetCallers(functionStart);
        callees = zone->GetCallees(functionStart, findImport);
        Fill(callersList, callers, zone);
        Fill(calleesList, callees, zone);
        std::string name = zone->GetLabelNameAt(functionStart);
        if (name.empty())
            name = zone->GetLabelName("sub_", functionStart);
        LocalString<256> text;
        text.SetFormat("%s: called by %zu, calls %zu", name.c_str(), callers.size(), callees.size());
        title->SetText(text.GetText());
    }

    // the reference selected in the list used last
    const DissasmCallReference* GetSelected()
    {
        const bool fromCallees = lastList == calleesList;
        auto item              = (fromCallees ? calleesList : callersList)->GetCurrentItem();
        if (!item.IsValid())
            return nullptr;
        const auto index = static_cast<size_t>(item.GetData(UINT64_MAX));
        const auto& list = fromCallees ? callees : callers;
        return index < list.size() ? &list[index] : nullptr;
    }

  public:
    CallTreeWindow(DissasmCodeZone* zone, std::function<const MemoryMappingEntry*(const X86OperandsInfo&)> findImport, uint64 functionStart)
        : Window("Call tree", "d:c,w:90%,h:80%", WindowFlags::Sizeable), zone(zone), findImport(std::move(findImport))
    {
        title = Factory::Label::Create(this, "", "l:1,t:0,r:1,h:1");
        Factory::Label::Create(this, "Called by", "l:1,t:1,w:20");
        Factory::Label::Create(this, "Calls", "l:51%,t:1,w:20");
        callersList = Factory::ListView::Create(this, "l:1,t:2,r:51%,b:3", { "n:Function,w:40", "n:Call site,w:30" }, ListViewFlags::PopupSearchBar);
        calleesList = Factory::ListView::Create(this, "l:51%,t:2,r:1,b:3", { "n:Function,w:40", "n:Call site,w:30" }, ListViewFlags::PopupSearchBar);
        Factory::Button::Create(this, "&Go", "l:1,b:0,w:10", BTN_GO);
        Factory::Button::Create(this, "Call &site", "l:13,b:0,w:14", BTN_CALL_SITE);
        Factory::Button::Create(this, "&Back", "l:29,b:0,w:10", BTN_BACK);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:10", BTN_CLOSE);
        ShowFunction(functionStart);
        lastList = callees.empty() && !callers.empty() ? callersList : calleesList;
        lastList->SetFocus();
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if (Window::OnEvent(control, eventType, ID))
            return true;
        if (eventType == Event::ListViewCurrentItemChanged) {
            lastList = control == calleesList.ToBase<Control>() ? calleesList : callersList;
            return false;
        }
        if (eventType == Event::ListViewItemPressed) {
            // the calls of the selected function (an import or an indirect call has none)
            lastList           = control == calleesList.ToBase<Control>() ? calleesList : callersList;
            const auto selected = GetSelected();
            if (selected && selected->functionStart.has_value()) {
                history.push_back(current);
                ShowFunction(selected->functionStart.value());
            }
            return true;
        }
        if (eventType != Event::ButtonClicked)
            return false;
        switch (ID) {
        case BTN_GO:
        case BTN_CALL_SITE: {
            const auto selected = GetSelected();
            if (!selected)
                return true;
            // an import (or an indirect call) is not in the code: its call site
            resultIsCallSite = ID == BTN_CALL_SITE || !selected->functionStart.has_value();
            result           = resultIsCallSite ? selected->site : selected->functionStart.value();
            Exit(Dialogs::Result::Ok);
            return true;
        }
        case BTN_BACK:
            if (!history.empty()) {
                const uint64 previous = history.back();
                history.pop_back();
                ShowFunction(previous);
            }
            return true;
        case BTN_CLOSE:
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return false;
    }

    std::optional<uint64> GetResult() const
    {
        return result;
    }
    bool IsCallSite() const
    {
        return resultIsCallSite;
    }
};

void Instance::ShowCallTree()
{
    const auto zone = GetCursorOrFirstCodeZone();
    if (!zone || !zone->isInit || !zone->CanReachAsmLines()) {
        Dialogs::MessageBox::ShowNotification("Info", "The calls are found when the disassembly zone is shown!");
        return;
    }
    if (zone->functionStarts.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The functions are found by the deep scan (Config.DeepScanDissasmOnStart)!");
        return;
    }
    // the function of the cursor line (the first function when the cursor is before the functions)
    uint64 functionStart  = zone->functionStarts.front();
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex].get() == zone && zonesFound[0].startingLine >= 2) {
        AsmData withoutKnownFunctions;
        DissasmInsnExtractLineParams params{};
        params.obj        = obj;
        params.zone       = zone;
        params.settings   = settings.get();
        params.asmData    = &withoutKnownFunctions;
        const auto line   = zone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params);
        const auto start  = zone->GetFunctionContaining(line.address);
        if (start.has_value())
            functionStart = start.value();
    }
    auto* settingsData = settings.get();
    CallTreeWindow window(
          zone,
          [settingsData, zone](const X86OperandsInfo& operands) { return FindX86OperandsImport(settingsData, zone, operands); },
          functionStart);
    zone->asmPreCacheData.Clear(); // the decoding position moved: the drawn lines are prepared again
    if (window.Show() != Dialogs::Result::Ok || !window.GetResult().has_value())
        return;
    MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + window.GetResult().value(), !window.IsCallSite());
}

void Instance::AcceptOrDismissAISuggestion(bool accept)
{
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() != 1 || zonesFound[0].startingLine < 2 ||
        settings->parseZones[zonesFound[0].zoneIndex]->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line of a dissasm zone!");
        return;
    }
    const auto zone = static_cast<DissasmCodeZone*>(settings->parseZones[zonesFound[0].zoneIndex].get());
    const uint32 line = zonesFound[0].startingLine - 2u; // the title and the columns header
    if (accept) {
        const auto status = zone->AcceptAISuggestion(line);
        if (!status.ok)
            Dialogs::MessageBox::ShowNotification("Warning", status.message);
    } else if (!zone->DismissAISuggestion(line)) {
        Dialogs::MessageBox::ShowNotification("Warning", "There is no suggestion of the assistant on this line!");
    }
    zone->asmPreCacheData.Clear();
}

void Instance::StartAINaming()
{
    const auto zone = GetCursorOrFirstCodeZone();
    if (!zone || !zone->isInit || !zone->CanReachAsmLines() || zone->functionStarts.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The functions are found by the deep scan of a shown disassembly zone!");
        return;
    }
    if (!queryInterface || !queryInterface->GetSmartAssistantInterface()) {
        Dialogs::MessageBox::ShowNotification("Warning", "There is no digital assistant available!");
        return;
    }
    // the function of the cursor and the functions it calls; only the ones with an automatic name and no suggestion yet
    uint64 functionStart  = zone->functionStarts.front();
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex].get() == zone && zonesFound[0].startingLine >= 2) {
        AsmData withoutKnownFunctions;
        DissasmInsnExtractLineParams params{};
        params.obj      = obj;
        params.zone     = zone;
        params.settings = settings.get();
        params.asmData  = &withoutKnownFunctions;
        const auto start = zone->GetFunctionContaining(zone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params).address);
        if (start.has_value())
            functionStart = start.value();
    }
    auto* settingsData = settings.get();
    std::vector<uint64> candidates{ functionStart };
    for (const auto& callee : zone->GetCallees(
               functionStart, [settingsData, zone](const X86OperandsInfo& operands) { return FindX86OperandsImport(settingsData, zone, operands); }))
        if (callee.functionStart.has_value())
            candidates.push_back(callee.functionStart.value());
    zone->asmPreCacheData.Clear();

    constexpr size_t MAX_FUNCTIONS = 50;
    StopAINaming();
    aiNaming.zone = zone;
    for (const uint64 candidate : candidates) {
        const bool hasAutomaticName = zone->GetLabelNameAt(candidate).starts_with("sub_");
        const bool listed = std::find(aiNaming.functions.begin(), aiNaming.functions.end(), candidate) != aiNaming.functions.end();
        if (hasAutomaticName && !listed && !zone->suggestedNames.contains(candidate) && aiNaming.functions.size() < MAX_FUNCTIONS)
            aiNaming.functions.push_back(candidate);
    }
    aiNaming.total = static_cast<uint32>(aiNaming.functions.size());
    if (aiNaming.functions.empty()) {
        aiNaming = {};
        Dialogs::MessageBox::ShowNotification("Info", "The function and the functions it calls already have names!");
        return;
    }
    // a frontend without frame updates (no FPS mode): every request now
    if (!frameUpdatesSeen)
        while (RunAINamingStep(true)) {
        }
}

void Instance::StopAINaming()
{
    aiNaming.request.Abandon(abandonedAssistantRequests); // an answer that is on its way is dropped; the names received so far stay
    aiNaming = {};
}

// One step of the naming (Ctrl+Shift+K): the answer of the running request is applied once it is ready, then the request of the next
// function is started on a worker thread: the UI stays responsive while the assistant answers. `wait`: the frontend has no frame
// updates, every request is answered at once. False when the naming ended.
bool Instance::RunAINamingStep(bool wait)
{
    const auto zone = aiNaming.zone;
    if (!zone)
        return false;
    if (aiNaming.request.IsRunning()) {
        if (!wait && !aiNaming.request.IsReady())
            return true;
        const auto answer = aiNaming.request.Take();
        const auto name   = answer.success ? ParseAssistantSuggestedName(answer.text) : std::string();
        if (!name.empty())
            zone->suggestedNames[aiNaming.requestFunction] = name;
        aiNaming.answered++;
    }
    const auto assistantInterface = queryInterface ? queryInterface->GetSmartAssistantInterface() : nullptr;
    while (assistantInterface && !aiNaming.functions.empty()) {
        const uint64 functionStart = aiNaming.functions.front();
        aiNaming.functions.pop_front();
        DissasmInsnExtractLineParams params{};
        params.obj      = obj;
        params.zone     = zone;
        params.settings = settings.get();
        params.asmData  = &asmData;
        const std::string code = zone->BuildAssistantFunctionText(functionStart, &params);
        zone->asmPreCacheData.Clear(); // the lines were built for the request
        if (code.empty()) {
            aiNaming.answered++;
            continue;
        }
        std::string prompt = "Suggest one name for this function based on what it does. Write only the name, in CamelCase, without any other text or symbols. " + code;
        std::string displayPrompt = "Give me a name for the function " + zone->GetLabelNameAt(functionStart);
        aiNaming.requestFunction  = functionStart;
        aiNaming.request.Start(assistantInterface, std::move(prompt), std::move(displayPrompt), !wait);
        return true;
    }
    aiNaming = {}; // no request is running
    return false;
}

// The canvas of the graph: scrolled (arrows, Shift+arrows, PageUp / PageDown, the wheel, a drag), a block selected (Tab / Shift+Tab,
// Home: the entry, a click); Enter or a double click jumps to the selected block in the listing
class FunctionGraphCanvas : public AppCUI::Controls::UserControl
{
  public:
    struct Rect {
        int x = 0, y = 0, width = 0, height = 0;
    };

    FunctionGraphCanvas(
          std::vector<Rect> blockRects, size_t selectedBlock, std::function<void()> activate, ColorPair normalColor, ColorPair selectionColor)
        : UserControl(
                "l:0,t:0,r:0,b:0",
                UserControlFlags::ShowVerticalScrollBar | UserControlFlags::ShowHorizontalScrollBar | UserControlFlags::ScrollBarOutsideControl),
          rects(std::move(blockRects)), selected(selectedBlock), onActivate(std::move(activate)), normal(normalColor), selection(selectionColor)
    {
    }

    Graphics::Canvas canvas;

    size_t GetSelectedBlock() const
    {
        return selected;
    }

    void Paint(Graphics::Renderer& renderer) override
    {
        if (revealPending && GetWidth() > 0 && GetHeight() > 0) {
            revealPending = false; // the size of the control is known at the first paint
            Reveal(selected);
        }
        renderer.Clear(' ', normal);
        renderer.DrawCanvas(-scrollX, -scrollY, canvas);
        if (selected < rects.size()) {
            const auto& rect = rects[selected];
            renderer.DrawRect(
                  rect.x - scrollX, rect.y - scrollY, rect.x + rect.width - 1 - scrollX, rect.y + rect.height - 1 - scrollY, selection, LineType::Double);
        }
    }

    void OnUpdateScrollBars() override
    {
        UpdateHScrollBar(static_cast<uint64>(scrollX), static_cast<uint64>(MaxScrollX()));
        UpdateVScrollBar(static_cast<uint64>(scrollY), static_cast<uint64>(MaxScrollY()));
    }

    bool OnKeyEvent(Input::Key keyCode, char16 unicodeChar) override
    {
        switch (keyCode) {
        case Key::Up:
            return ScrollTo(scrollX, scrollY - 1);
        case Key::Down:
            return ScrollTo(scrollX, scrollY + 1);
        case Key::Left:
            return ScrollTo(scrollX - 1, scrollY);
        case Key::Right:
            return ScrollTo(scrollX + 1, scrollY);
        case Key::Shift | Key::Up:
            return ScrollTo(scrollX, scrollY - 10);
        case Key::Shift | Key::Down:
            return ScrollTo(scrollX, scrollY + 10);
        case Key::Shift | Key::Left:
            return ScrollTo(scrollX - 20, scrollY);
        case Key::Shift | Key::Right:
            return ScrollTo(scrollX + 20, scrollY);
        case Key::PageUp:
            return ScrollTo(scrollX, scrollY - std::max(1, static_cast<int>(GetHeight()) - 2));
        case Key::PageDown:
            return ScrollTo(scrollX, scrollY + std::max(1, static_cast<int>(GetHeight()) - 2));
        case Key::Tab:
            return Select((selected + 1) % rects.size());
        case Key::Shift | Key::Tab:
            return Select((selected + rects.size() - 1) % rects.size());
        case Key::Home:
            return Select(0);
        case Key::Enter:
            onActivate();
            return true;
        default:
            break;
        }
        return UserControl::OnKeyEvent(keyCode, unicodeChar);
    }

    bool OnMouseWheel(int, int, Input::MouseWheel direction, Input::Key) override
    {
        switch (direction) {
        case Input::MouseWheel::Up:
            return ScrollTo(scrollX, scrollY - 3);
        case Input::MouseWheel::Down:
            return ScrollTo(scrollX, scrollY + 3);
        case Input::MouseWheel::Left:
            return ScrollTo(scrollX - 6, scrollY);
        case Input::MouseWheel::Right:
            return ScrollTo(scrollX + 6, scrollY);
        default:
            return false;
        }
    }

    void OnMousePressed(int x, int y, Input::MouseButton button, Input::Key) override
    {
        dragging = false;
        if (const auto block = BlockAt(x + scrollX, y + scrollY); block.has_value()) {
            selected = block.value();
            if ((button & Input::MouseButton::DoubleClicked) != Input::MouseButton::None)
                onActivate();
            return;
        }
        // outside the blocks: the graph is dragged
        dragging = true;
        dragX    = scrollX + x;
        dragY    = scrollY + y;
    }

    bool OnMouseDrag(int x, int y, Input::MouseButton, Input::Key) override
    {
        if (!dragging)
            return false;
        return ScrollTo(dragX - x, dragY - y);
    }

    void OnMouseReleased(int x, int y, Input::MouseButton button, Input::Key keyCode) override
    {
        OnMouseDrag(x, y, button, keyCode);
        dragging = false;
    }

    bool OnMouseEnter() override
    {
        return true;
    }

    bool OnMouseLeave() override
    {
        return true;
    }

  private:
    std::vector<Rect> rects;
    size_t selected;
    std::function<void()> onActivate;
    ColorPair normal, selection;
    int scrollX = 0, scrollY = 0;
    int dragX = 0, dragY = 0;
    bool dragging      = false;
    bool revealPending = true;

    int MaxScrollX() const
    {
        return std::max(0, static_cast<int>(canvas.GetWidth()) - static_cast<int>(GetWidth()));
    }
    int MaxScrollY() const
    {
        return std::max(0, static_cast<int>(canvas.GetHeight()) - static_cast<int>(GetHeight()));
    }
    bool ScrollTo(int x, int y)
    {
        scrollX = std::clamp(x, 0, MaxScrollX());
        scrollY = std::clamp(y, 0, MaxScrollY());
        return true;
    }
    std::optional<size_t> BlockAt(int x, int y) const
    {
        for (size_t index = 0; index < rects.size(); index++) {
            const auto& rect = rects[index];
            if (x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height)
                return index;
        }
        return std::nullopt;
    }
    // a block that is not entirely shown is centered (its top is shown when it is taller than the view)
    void Reveal(size_t index)
    {
        if (index >= rects.size())
            return;
        const auto& rect = rects[index];
        const int width = static_cast<int>(GetWidth()), height = static_cast<int>(GetHeight());
        int x = scrollX, y = scrollY;
        if (rect.x < scrollX || rect.x + rect.width > scrollX + width)
            x = rect.width < width ? rect.x + rect.width / 2 - width / 2 : rect.x - 1;
        if (rect.y < scrollY || rect.y + rect.height > scrollY + height)
            y = rect.height < height ? rect.y + rect.height / 2 - height / 2 : rect.y - 1;
        ScrollTo(x, y);
    }
    bool Select(size_t index)
    {
        if (index < rects.size()) {
            selected = index;
            Reveal(index);
        }
        return true;
    }
};

// The graph of a function (Ctrl+B): its basic blocks as boxes in layers (the longest path from the entry), every block under its
// predecessors; the branches are green (taken) / red (not taken), the jumps aqua, the switch cases yellow, the loops go around on the right
class FunctionGraphWindow : public AppCUI::Controls::Window
{
    struct Box {
        int x = 0, y = 0, width = 0, height = 0;
        int layer = 0;
        std::string title;
        std::vector<std::string> lines;
    };

  public:
    FunctionGraphWindow(
          const std::string& title,
          const DissasmFunctionGraph& graph,
          const std::vector<std::string>& titles,
          const std::vector<std::vector<std::string>>& texts,
          std::optional<size_t> currentBlock,
          const DissasmColors& colors)
        : Window(title, "d:c,w:95%,h:90%", WindowFlags::Sizeable)
    {
        constexpr int MIN_BOX_WIDTH = 16, MAX_BOX_WIDTH = 64, GAP_X = 6, GAP_Y = 5, MARGIN = 2;
        const size_t count = graph.blocks.size();
        std::vector<Box> boxes(count);
        for (size_t index = 0; index < count; index++) {
            auto& box   = boxes[index];
            box.title   = titles[index];
            box.lines   = texts[index];
            int longest = static_cast<int>(box.title.size());
            for (const auto& line : box.lines)
                longest = std::max(longest, static_cast<int>(line.size()));
            box.width  = std::clamp(longest + 4, MIN_BOX_WIDTH, MAX_BOX_WIDTH);
            box.height = static_cast<int>(box.lines.size()) + 3; // the borders and the title
        }
        // the layers: the longest path from the entry over the forward edges (the blocks are sorted by address: a forward edge goes to a
        // block of a bigger index)
        int layersCount = 1;
        for (size_t index = 0; index < count; index++)
            for (const auto& edge : graph.blocks[index].successors)
                if (edge.target > index) {
                    boxes[edge.target].layer = std::max(boxes[edge.target].layer, boxes[index].layer + 1);
                    layersCount              = std::max(layersCount, boxes[edge.target].layer + 1);
                }
        std::vector<std::vector<std::pair<double, size_t>>> layers(layersCount);
        std::vector<std::vector<size_t>> forwardPredecessors(count);
        for (size_t index = 0; index < count; index++)
            for (const auto& edge : graph.blocks[index].successors)
                if (edge.target > index)
                    forwardPredecessors[edge.target].push_back(index);
        // the places: a block under the middle of its predecessors, the blocks of a layer never overlap
        std::vector<int> layerTop(layersCount, MARGIN), layerHeight(layersCount, 0);
        for (size_t index = 0; index < count; index++)
            layers[boxes[index].layer].push_back({ 0.0, index });
        int top = MARGIN, width = 0;
        for (int layer = 0; layer < layersCount; layer++) {
            for (auto& [desired, index] : layers[layer]) {
                desired = MARGIN + boxes[index].width / 2.0;
                if (!forwardPredecessors[index].empty()) {
                    double sum = 0;
                    for (const size_t predecessor : forwardPredecessors[index])
                        sum += boxes[predecessor].x + boxes[predecessor].width / 2.0;
                    desired = sum / forwardPredecessors[index].size();
                }
            }
            std::stable_sort(layers[layer].begin(), layers[layer].end());
            int right = MARGIN - GAP_X;
            for (const auto& [desired, index] : layers[layer]) {
                auto& box  = boxes[index];
                box.x      = std::max({ static_cast<int>(desired) - box.width / 2, right + GAP_X, MARGIN });
                box.y      = top;
                right      = box.x + box.width;
                width      = std::max(width, right);
                layerHeight[layer] = std::max(layerHeight[layer], box.height);
            }
            layerTop[layer] = top;
            top += layerHeight[layer] + GAP_Y;
        }
        // the loops (back edges) go up on the right of the graph, one column each
        int backEdges = 0;
        for (size_t index = 0; index < count; index++)
            for (const auto& edge : graph.blocks[index].successors)
                if (edge.target <= index)
                    backEdges++;
        constexpr int MAX_CANVAS_WIDTH = 4000, MAX_CANVAS_HEIGHT = 20000;
        const int canvasWidth  = std::min(width + MARGIN * 2 + backEdges * 2 + 2, MAX_CANVAS_WIDTH);
        const int canvasHeight = std::min(top + MARGIN, MAX_CANVAS_HEIGHT);

        // the block of the cursor is selected, else the entry
        std::vector<FunctionGraphCanvas::Rect> rects;
        for (const auto& box : boxes)
            rects.push_back({ box.x, box.y, box.width, box.height });
        viewer = this->CreateChildControl<FunctionGraphCanvas>(
              std::move(rects), currentBlock.value_or(0), [this]() { Exit(Dialogs::Result::Ok); }, colors.Normal, colors.Selection);
        viewer->canvas.Create(canvasWidth, canvasHeight, ' ', colors.Normal);
        auto canvas = &viewer->canvas;

        const ColorPair taken{ Color::Green, Color::Transparent }, notTaken{ Color::Red, Color::Transparent };
        const ColorPair jump{ Color::Aqua, Color::Transparent }, switchCase{ Color::Yellow, Color::Transparent }, loop{ Color::Blue, Color::Transparent };
        const auto edgeColor = [&](DissasmGraphBlock::EdgeKind kind) {
            switch (kind) {
            case DissasmGraphBlock::EdgeKind::True:
                return taken;
            case DissasmGraphBlock::EdgeKind::False:
                return notTaken;
            case DissasmGraphBlock::EdgeKind::Switch:
                return switchCase;
            default:
                return jump;
            }
        };
        // the edges first: the boxes are drawn over the lines that cross them
        int backColumn = width + MARGIN + 1;
        for (size_t index = 0; index < count; index++) {
            const auto& source     = boxes[index];
            const auto& successors = graph.blocks[index].successors;
            for (size_t edgeIndex = 0; edgeIndex < successors.size(); edgeIndex++) {
                const auto& edge   = successors[edgeIndex];
                const auto& target = boxes[edge.target];
                if (edge.target > index) {
                    // down from the bottom of the source to the gap below its layer, across, then down to the top of the target
                    const int spread  = successors.size() > 1 ? static_cast<int>(edgeIndex * 4) - static_cast<int>((successors.size() - 1) * 2) : 0;
                    const int fromX   = std::clamp(source.x + source.width / 2 + spread, source.x + 1, source.x + source.width - 2);
                    const int fromY   = source.y + source.height;
                    const int channel = layerTop[source.layer] + layerHeight[source.layer] + 1 + static_cast<int>(edgeIndex % 3);
                    const int toX     = target.x + target.width / 2;
                    const int toY     = target.y - 1;
                    const auto color  = edgeColor(edge.kind);
                    canvas->DrawVerticalLine(fromX, fromY, channel, color);
                    canvas->DrawHorizontalLine(std::min(fromX, toX), channel, std::max(fromX, toX), color);
                    canvas->DrawVerticalLine(toX, channel, toY, color);
                    canvas->WriteSpecialCharacter(toX, toY, SpecialChars::TriangleDown, color);
                } else {
                    // a loop: right from the source, up on its own column, left into the target
                    const int fromY = source.y + source.height / 2;
                    const int toY   = target.y + 1;
                    canvas->DrawHorizontalLine(source.x + source.width, fromY, backColumn, loop);
                    canvas->DrawVerticalLine(backColumn, toY, fromY, loop);
                    canvas->DrawHorizontalLine(target.x + target.width, toY, backColumn, loop);
                    canvas->WriteSpecialCharacter(target.x + target.width, toY, SpecialChars::TriangleLeft, loop);
                    backColumn += 2;
                }
            }
        }
        for (size_t index = 0; index < count; index++) {
            const auto& box       = boxes[index];
            const bool isCurrent  = currentBlock == index; // the block of the cursor; the selected one has a double frame
            const ColorPair frame = isCurrent ? colors.AsmJumpInstruction : colors.AsmTitleColumnColor;
            canvas->FillRect(box.x, box.y, box.x + box.width - 1, box.y + box.height - 1, ' ', colors.Normal);
            canvas->DrawRect(box.x, box.y, box.x + box.width - 1, box.y + box.height - 1, frame, LineType::Single);
            const auto clip = [&box](const std::string& text) { return text.size() > static_cast<size_t>(box.width - 4) ? text.substr(0, box.width - 5) + "~" : text; };
            canvas->WriteSingleLineText(box.x + 2, box.y + 1, clip(box.title), colors.AsmFunctionColor);
            for (size_t line = 0; line < box.lines.size(); line++)
                canvas->WriteSingleLineText(box.x + 2, box.y + 2 + static_cast<int>(line), clip(box.lines[line]), colors.Normal);
            if (graph.blocks[index].exits)
                canvas->WriteSingleLineText(box.x + box.width - 7, box.y + box.height - 1, " end ", colors.AsmComment);
        }
        viewer->SetFocus();
    }

    size_t GetSelectedBlock()
    {
        return viewer->GetSelectedBlock();
    }

  private:
    Reference<FunctionGraphCanvas> viewer;
};

void Instance::ShowFunctionGraph()
{
    const auto zone = GetCursorOrFirstCodeZone();
    if (!zone || !zone->isInit || !zone->CanReachAsmLines() || zone->functionStarts.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The functions are found by the deep scan of a shown disassembly zone!");
        return;
    }
    // the function and the address of the cursor line
    AsmData withoutKnownFunctions;
    DissasmInsnExtractLineParams params{};
    params.obj      = obj;
    params.zone     = zone;
    params.settings = settings.get();
    params.asmData  = &withoutKnownFunctions;
    uint64 functionStart = zone->functionStarts.front();
    std::optional<uint64> cursorAddress;
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() == 1 && settings->parseZones[zonesFound[0].zoneIndex].get() == zone && zonesFound[0].startingLine >= 2) {
        cursorAddress    = zone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params).address;
        const auto start = zone->GetFunctionContaining(cursorAddress.value());
        if (start.has_value())
            functionStart = start.value();
    }
    const auto graph = zone->BuildFunctionGraph(functionStart);
    if (graph.blocks.empty()) {
        Dialogs::MessageBox::ShowNotification("Info", "The function has no instructions!");
        return;
    }

    // the text of the blocks: the lines of the listing (labels, imports, the numbers base of the user)
    uint32 firstInstruction = 0;
    if (cs_insn* insn = GetCurrentInstructionByOffset(zone->cachedCodeOffsets[0].offset + functionStart, zone, obj, firstInstruction))
        cs_free(insn, 1);
    std::vector<std::string> titles;
    std::vector<std::vector<std::string>> texts;
    std::optional<size_t> currentBlock;
    std::string comment;
    for (size_t index = 0; index < graph.blocks.size(); index++) {
        const auto& block = graph.blocks[index];
        std::string title = zone->GetLabelNameAt(block.start);
        titles.push_back(title.empty() ? zone->GetLabelName("loc_", block.start) : title);
        auto& lines = texts.emplace_back();
        for (const uint32 ordinal : block.instructions) {
            const uint32 line  = zone->ExpandedToDisplay(zone->InstructionIndexToExpanded(firstInstruction + ordinal));
            const auto asmLine = zone->GetCurrentAsmLine(line, obj, &params);
            std::string text   = asmLine.mnemonic;
            if (asmLine.op_str)
                text.append(" ").append(asmLine.op_str, asmLine.op_str_size);
            else if (asmLine.mapping)
                text.append(" ").append(static_cast<const MemoryMappingEntry*>(asmLine.mapping)->name);
            if (zone->GetComment(asmLine, comment))
                text.append(" ; ").append(comment);
            lines.push_back(std::move(text));
        }
        if (cursorAddress.has_value() && cursorAddress.value() >= block.start && cursorAddress.value() < block.end)
            currentBlock = index;
    }
    zone->asmPreCacheData.Clear(); // the decoding position moved: the drawn lines are prepared again

    LocalString<320> title;
    // the keys in the title: the scroll bars of the canvas use the bottom line
    title.SetFormat("Graph of %s (%zu blocks%s) - arrows / mouse: scroll, Tab / click: a block, Enter / double click: go to it, Esc: close",
                    titles.front().c_str(),
                    graph.blocks.size(),
                    graph.truncated ? ", too big: it stops at the limit" : "");
    FunctionGraphWindow window(title.GetText(), graph, titles, texts, currentBlock, ColorMan.Colors);
    if (window.Show() != Dialogs::Result::Ok)
        return;
    const size_t selected = window.GetSelectedBlock();
    if (selected < graph.blocks.size()) // the label of the block (a jump target) is shown above it
        MoveCursorToZoneFileOffset(zone, zone->cachedCodeOffsets[0].offset + graph.blocks[selected].start, true);
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

// Shown while the assistant answers on a worker thread: the time the request takes; Esc / Cancel stop waiting for it
class AssistantWaitWindow : public AppCUI::Controls::Window
{
    static constexpr int CANCEL_ID = 1;

  public:
    AssistantWaitWindow(const DissasmAssistantRequest& request, std::string_view what)
        : Window("Smart assistant", "d:c,w:64,h:8", WindowFlags::None), request(request), start(std::chrono::steady_clock::now())
    {
        Factory::Label::Create(this, what, "l:1,t:1,r:1,h:1");
        status = Factory::Label::Create(this, "", "l:1,t:2,r:1,h:1");
        Factory::Button::Create(this, "&Cancel", "x:50%,y:100%,a:b,w:14", CANCEL_ID);
        UpdateStatus();
    }

    bool OnFrameUpdate() override
    {
        if (request.IsReady()) {
            Exit(Dialogs::Result::Ok);
            return true;
        }
        return UpdateStatus();
    }

    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        if ((eventType == Event::ButtonClicked && ID == CANCEL_ID) || eventType == Event::WindowClose) {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(control, eventType, ID);
    }

  private:
    const DissasmAssistantRequest& request;
    std::chrono::steady_clock::time_point start;
    Reference<Label> status;
    int64 shownSeconds = -1;

    bool UpdateStatus()
    {
        const int64 seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();
        if (seconds == shownSeconds)
            return false;
        shownSeconds = seconds;
        LocalString<96> text;
        text.SetFormat("Waiting for the answer... %llds (Esc: cancel)", static_cast<long long>(seconds));
        status->SetText(text.GetText());
        return true;
    }
};

std::optional<DissasmAssistantAnswer> Instance::AskAssistantWaiting(
      DissasmAssistantRequest::Assistant* assistant, std::string prompt, std::string displayPrompt)
{
    DissasmAssistantRequest request;
    // a frontend without frame updates could not see the end of the request: it is answered at once
    request.Start(assistant, std::move(prompt), displayPrompt, frameUpdatesSeen);
    if (!request.IsReady()) {
        AssistantWaitWindow window(request, displayPrompt);
        if (window.Show() != Dialogs::Result::Ok) {
            request.Abandon(abandonedAssistantRequests); // it goes on in the background, its answer is dropped
            return std::nullopt;
        }
    }
    return request.Take();
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
                if (isVariable)
                    assemblyLines.emplace_back(currentLine.op_str);
                else
                    assemblyLines.emplace_back(currentLine.GetMnemonicText());
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
    bufferToSendToAssistant.AddFormat("Here is %s assembly code: \n", codeZone->GetArchitectureName());
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

    const auto answer = AskAssistantWaiting(assistantInterface, textData, displayPrompt.GetText());
    if (!answer.has_value())
        return; // cancelled
    bool isSuccess = answer->success;
    auto result    = answer->text;
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
            const auto retry = AskAssistantWaiting(assistantInterface, textData, displayPrompt.GetText());
            if (!retry.has_value())
                return; // cancelled
            result    = retry->text;
            isSuccess = retry->success;
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

                // kept apart from the comments of the user: A accepts it, Shift+A dismisses it
                codeZone->SetAIComment(currentDissasmLine, comment);
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