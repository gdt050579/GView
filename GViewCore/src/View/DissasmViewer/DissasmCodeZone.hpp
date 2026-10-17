#pragma once

#include "DissasmViewer.hpp"

namespace GView::View::DissasmViewer
{
struct DissasmCodeZone : public ParseZone {
    enum class CollapseExpandType : uint8 { Collapse, Expand, NegateCurrentState };
    uint32 lastDrawnLine      = 0; // optimization not to recompute buffer every time
    uint32 lastClosestLine    = 0;
    uint32 offsetCacheMaxLine = 0; // 0 forces the next decoded line to search its closest cached offset
    BufferView lastData;
    uint32 lastReachedLine = UINT32_MAX;

    // fields only for dissasmx86/x64
    const uint8* asmData = nullptr;
    uint64 asmSize = 0, asmAddress = 0;
    uint64 asmWindowEnd = 0; // end (exclusive, relative address) of the bytes that can be decoded from the current cached offset

    uint32 structureIndex = 0;
    std::list<std::reference_wrapper<DissasmCodeInternalType>> types;
    std::list<uint32> levels;
    DissasmCodeInternalType dissasmType{};

    DissasmAsmPreCacheData asmPreCacheData;

    std::vector<AsmOffsetLine> cachedCodeOffsets;
    DisassemblyZone zoneDetails{};
    int internalArchitecture = 0; // used for dissasm libraries
    bool isInit              = false;
    bool changedLevel        = false;
    InternalTypeNewLevelChangeData newLevelChangeData{};

    // x86/x64: decoded instructions count (the zone lines are the instructions plus the annotations of the root type)
    uint32 asmLinesCount = 0;
    // x86/x64: local variables of the frame based functions, filled only by the deep scan
    DissasmLocalVariables localVariables;
    // x86/x64: instruction address (relative, as DissasmAsmPreCacheLine::address) -> bit mask of the operand numbers
    // (FindOperandNumbers order) that are shown as decimal numbers instead of hexadecimal
    std::map<uint64, uint32> decimalOperands;
    // the cache had a record for this zone that could not be applied to the analysis: it is kept aside on save (not overwritten)
    bool cacheRecordRejected = false;
    // x86/x64: the address of the first decoded instruction in the address space of the labels, the VA (offset translation of the plugin)
    // or the file offset when the plugin has no translation. The label of the relative address r is named after labelAddressBase + r.
    uint64 labelAddressBase = 0;

    // the name of the label placed at the relative address `address` (as IDA: sub_140001000, loc_140001020)
    std::string GetLabelName(std::string_view prefix, uint64 address) const;
    // the labels loaded from a cache saved before the labels were named after the VA (sub_0x<file offset> / offset_0x<file offset>) get
    // the names of the analysis; the labels renamed by the user keep their names
    void MigrateLegacyLabelNames();

    DissasmCodeZone() = default;
    // owns the capstone handle
    DissasmCodeZone(const DissasmCodeZone&)            = delete;
    DissasmCodeZone& operator=(const DissasmCodeZone&) = delete;
    ~DissasmCodeZone() override;

    // x86/x64: the capstone handle that decodes the lines, opened once (in the mode of the zone) and closed with the zone; 0 when capstone
    // can not open it
    csh GetDecodeHandle();

    void ResetZoneCaching();
    bool AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd);
    bool CanAddNewZone(uint32 zoneLineStart, uint32 zoneLineEnd) const
    {
        if (zoneLineStart > zoneLineEnd || zoneLineEnd > dissasmType.indexZoneEnd)
            return false;
        return dissasmType.CanAddNewZone(zoneLineStart, zoneLineEnd);
    }
    bool CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference);
    bool RemoveCollapsibleZone(uint32 zoneLine);

    bool InitZone(DissasmCodeZoneInitData& initData);
    // x86/x64 zone initialized successfully: only then the lines can be reached / decoded (the root type is in `types`)
    bool CanReachAsmLines() const
    {
        return isInit && !types.empty() && (zoneDetails.language == DisassemblyLanguage::x86 || zoneDetails.language == DisassemblyLanguage::x64);
    }
    void ReachZoneLine(uint32 line);

    bool ResetTypesReferenceList();
    Utils::GStatus TryRenameLine(
          uint32 line, Reference<GView::Object> obj, std::string_view* newName = nullptr, DissasmInsnExtractLineParams* params = nullptr);

    bool GetComment(uint32 line, std::string& comment);
    bool AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr = true);
    bool RemoveComment(uint32 line, bool showErr = true);
    DissasmAsmPreCacheLine GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);

    // x86/x64 code window: bytes from cachedCodeOffsets[0].offset until the end of the zone
    uint64 GetCodeSize() const;
    // file offset of an address decoded by this zone (the decoded addresses start at 0 on cachedCodeOffsets[0].offset), none when the
    // address is not inside the decoded code (another section, a backward branch that wrapped around, ...)
    std::optional<uint64> GetFileOffsetOfAddress(uint64 address) const;
    // points asmData/asmSize/asmAddress to [relativeStart, relativeEnd), clamped to the zone and to what the data cache returns
    bool FetchCodeWindow(Reference<GView::Object> obj, uint64 relativeStart, uint64 relativeEnd);

    // local variables
    bool Is64BitCode() const
    {
        return zoneDetails.language == DisassemblyLanguage::x64;
    }
    // the variable defined by `line` (variable line) or used by the instruction on `line`
    bool GetLocalVariableFromLine(uint32 line, Reference<GView::Object> obj, uint64& functionStart, int32& frameOffset);
    Utils::GStatus RenameLocalVariable(uint64 functionStart, int32 frameOffset, std::string_view newName);
    // removes the variable and its definition line; the zone loses one line when `lineRemoved` is set
    Utils::GStatus RemoveLocalVariable(uint64 functionStart, int32 frameOffset, bool& lineRemoved);
    // removes text lines of the root type (no collapsible zones) shifting the annotations, comments and the zone end
    void RemoveRootAnnotationLines(const std::vector<uint32>& sortedLines);
    uint32 GetRootZoneLinesCount() const
    {
        return asmLinesCount + static_cast<uint32>(dissasmType.annotations.size());
    }

    // switches the operand number `numberIndex` of the instruction at `address` between hexadecimal and decimal
    void ToggleDecimalOperand(uint64 address, uint32 numberIndex);
    uint32 GetDecimalOperandsMask(uint64 address) const
    {
        const auto it = decimalOperands.find(address);
        return it != decimalOperands.end() ? it->second : 0u;
    }

    bool ToBuffer(std::vector<std::byte>& buffer) const;
    // `zoneLinesChanged` is set when the cache removed lines (deleted local variables), the zone size must be adjusted
    bool TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged);

  private:
    csh decodeHandle = 0;
};

// the lines of the zone as they are shown (without the title), the collapsed zones count as one line
uint32 GetCodeZoneLinesCount(const DissasmCodeZone& zone);
// the listing of an initialized x86/x64 code zone (an .asm file): the lines as they are shown (labels, local variables, jump / call targets
// with their labels, import names) with the comments of the user and the generated comments
bool BuildX86AsmListing(DissasmCodeZone& zone, Reference<GView::Object> obj, SettingsData* settings, AsmData* asmData, std::string& listing);

} // namespace GView::View::DissasmViewer
