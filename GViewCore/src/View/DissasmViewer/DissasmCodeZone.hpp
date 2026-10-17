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

    // fields only for dissasmx86/x64
    const uint8* asmData = nullptr;
    uint64 asmSize = 0, asmAddress = 0;
    uint64 asmWindowEnd = 0; // end (exclusive, relative address) of the bytes that can be decoded from the current cached offset

    // the labels and the local variable lines, keyed by their line in the expanded layout (DissasmCodeInternalType)
    DissasmCodeInternalType dissasmType{};
    // the collapsible zones, sorted by start (and the outer zone first for the same start), in the expanded layout
    std::vector<DissasmCollapsibleZone> collapsibleZones;

    DissasmAsmPreCacheData asmPreCacheData;

    std::vector<AsmOffsetLine> cachedCodeOffsets;
    DisassemblyZone zoneDetails{};
    int internalArchitecture = 0; // used for dissasm libraries
    bool isInit              = false;

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
    // x86/x64: the comments of the user, by anchor (they follow their instruction / label / variable whatever the lines become)
    DissasmUserComments userComments;
    // the names the user gave to labels that the analysis does not find (a cache of another version): saved again, applied when the
    // label comes back. Keyed by the relative address of the label.
    std::map<uint64, std::string> orphanLabelNames;
    // the record that an older version could not apply (kept aside in the cache) was merged into this zone: it is not kept any more
    bool mergedUnappliedRecord = false;
    // the object of the zone (set by InitZone): the line based calls decode their line from it
    Reference<GView::Object> zoneObject;
    // x86/x64 (deep scan): the cross references of the code (address space of the labels) and the function starts (relative, sorted)
    DissasmXrefs xrefs;
    std::vector<uint64> functionStarts;
    std::unordered_map<uint64, std::string> thunkImports; // relative address of an import thunk (jmp [slot]) -> the import

    // the name shown for the label at the relative address (renamed or not); empty when there is no label there
    std::string GetLabelNameAt(uint64 relativeAddress) const;
    // "sub_140001010+0x1A": the function that contains the relative address (its name as shown)
    std::string FormatCodeAddress(uint64 relativeAddress) const;
    // the references to the label at the relative address, shown after the label: "xrefs: sub_140001010+0x84 (call), ... +3"
    std::string FormatXrefsSummary(uint64 relativeAddress) const;

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
    // the zone of the shown lines [zoneLineStart, zoneLineEnd) (a collapsed line counts as its whole zone); false when it would
    // overlap a zone without being nested in it, or the same zone exists
    bool AddCollapsibleZone(uint32 zoneLineStart, uint32 zoneLineEnd);
    // the innermost zone of the shown line `zoneLine` (the zone of a collapsed line); `difference` is the new size of the code zone (its
    // lines and the title); false when there is no zone or it already has the requested state
    bool CollapseOrExtendZone(uint32 zoneLine, CollapseExpandType collapse, int32& difference);
    // removes the innermost expanded zone of the shown line `zoneLine`
    bool RemoveCollapsibleZone(uint32 zoneLine);

    bool InitZone(DissasmCodeZoneInitData& initData);
    // x86/x64 zone initialized successfully: only then the lines can be reached / decoded
    bool CanReachAsmLines() const
    {
        return isInit && linesReady && (zoneDetails.language == DisassemblyLanguage::x86 || zoneDetails.language == DisassemblyLanguage::x64);
    }

    // the line index (the sorted lines of the annotations) after the annotations changed; the decoding starts again from a cached offset
    void RebuildLineIndex();
    // the lines of the expanded layout: the instructions and the annotations
    uint32 GetExpandedLinesCount() const
    {
        return asmLinesCount + static_cast<uint32>(dissasmType.annotations.size());
    }
    // the shown lines: the collapsed zones are one line each
    uint32 GetDisplayLinesCount() const;
    struct LinePlace {
        uint32 expandedLine;
        const DissasmCollapsibleZone* collapsedZone; // the collapsed zone shown on the line (expandedLine is its start)
    };
    // the expanded line of a shown line; none after the last line
    std::optional<LinePlace> DisplayToExpanded(uint32 displayLine) const;
    // the shown line of an expanded line (the line of the collapsed zone that hides it)
    uint32 ExpandedToDisplay(uint32 expandedLine) const;
    // the instruction index of an expanded line that is not an annotation
    uint32 ExpandedToInstructionIndex(uint32 expandedLine) const;
    // the expanded line of the instruction `instructionIndex`
    uint32 InstructionIndexToExpanded(uint32 instructionIndex) const;
    bool IsAnnotationLine(uint32 expandedLine) const;
    // the innermost zone that contains the expanded line / that starts on it
    DissasmCollapsibleZone* FindInnermostZone(uint32 expandedLine);
    const DissasmCollapsibleZone* FindInnermostZoneStartingAt(uint32 expandedLine) const;

    Utils::GStatus TryRenameLine(
          uint32 line, Reference<GView::Object> obj, std::string_view* newName = nullptr, DissasmInsnExtractLineParams* params = nullptr);

    // the comments of the user are attached to the anchor of a line (DissasmCommentAnchor), the line versions find the anchor of the line
    bool GetComment(uint32 line, std::string& comment);
    bool GetComment(const DissasmAsmPreCacheLine& line, std::string& comment) const;
    bool AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr = true);
    bool RemoveComment(uint32 line, bool showErr = true);
    // the instruction, the label or the variable of a line (a collapsed zone: the anchor of its first line)
    static DissasmCommentAnchor GetLineAnchor(const DissasmAsmPreCacheLine& line);
    std::optional<DissasmCommentAnchor> GetAnchorOfLine(uint32 line);
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
    // removes annotation lines (expanded layout) shifting the annotations and the collapsible zones that follow them
    void RemoveRootAnnotationLines(const std::vector<uint32>& sortedLines);
    uint32 GetRootZoneLinesCount() const
    {
        return GetExpandedLinesCount();
    }

    // switches the operand number `numberIndex` of the instruction at `address` between hexadecimal and decimal
    void ToggleDecimalOperand(uint64 address, uint32 numberIndex);
    uint32 GetDecimalOperandsMask(uint64 address) const
    {
        const auto it = decimalOperands.find(address);
        return it != decimalOperands.end() ? it->second : 0u;
    }

    // the record of the zone (cache version 4); not const: the anchors of the collapsible zones are read from their lines
    bool ToBuffer(std::vector<std::byte>& buffer);
    // `zoneLinesChanged` is set when the cache removed lines (deleted local variables), the zone size must be adjusted
    bool TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged);
    // the comments of the line keyed records (cache versions 1 and 2, kept in the root type by line) are moved to their anchors
    void MoveLineCommentsToAnchors();
    // the label names of the user, by the relative address of the label (the renamed labels and orphanLabelNames)
    std::vector<std::pair<uint64, std::string>> GetUserLabelNames() const;
    // gives the name to the label placed at `address`; false when there is no such label (the name is kept in orphanLabelNames) or the
    // name is used by another label
    bool ApplyUserLabelName(uint64 address, const std::string& name);

    // the collapsible zones by the anchors of their first and last lines (saved in the cache): the lines move, the anchors stay
    struct CollapsibleZoneAnchors {
        DissasmCommentAnchor first;
        DissasmCommentAnchor last;
        std::string name;
        bool isCollapsed;
    };
    std::vector<CollapsibleZoneAnchors> GetCollapsibleZoneAnchors();
    // the zones placed on the lines of their anchors (the ones that can not be placed are ignored); true when the shown lines changed
    bool ApplyCollapsibleZoneAnchors(const std::vector<CollapsibleZoneAnchors>& zones);
    // the expanded line of an anchor; none when this analysis has no such line
    std::optional<uint32> GetExpandedLineOfAnchor(const DissasmCommentAnchor& anchor);

  private:
    bool TryLoadCodeZoneRecord(DissasmCache& cache, bool& zoneLinesChanged);
    // true when the merged zones changed the shown lines
    bool MergeUnappliedRecord(DissasmCache& cache);
    // the line of the expanded layout as it is drawn (no collapsed zone)
    DissasmAsmPreCacheLine BuildExpandedLine(uint32 expandedLine, uint32 displayLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);
    bool CanPlaceZone(const DissasmCollapsibleZone& zone) const;
    void InsertZone(DissasmCollapsibleZone zone);

    csh decodeHandle = 0;
    bool linesReady  = false;
    std::vector<uint32> annotationLines;                // the sorted lines of dissasmType.annotations
    std::unordered_map<uint64, uint32> labelLineOfAddress; // relative address of a label -> its line (expanded layout)
};

// the lines of the zone as they are shown (without the title), the collapsed zones count as one line
uint32 GetCodeZoneLinesCount(const DissasmCodeZone& zone);
// the listing of an initialized x86/x64 code zone (an .asm file): the lines as they are shown (labels, local variables, jump / call targets
// with their labels, import names) with the comments of the user and the generated comments
bool BuildX86AsmListing(DissasmCodeZone& zone, Reference<GView::Object> obj, SettingsData* settings, AsmData* asmData, std::string& listing);
// the import (memory mapping, keyed by the RVA of its slot) used by the operands: [rip + 0x...] on x64, the VA of the slot ([0x402010]) on x86
const MemoryMappingEntry* FindX86OperandsImport(SettingsData* settings, const DissasmCodeZone* zone, const X86OperandsInfo& operands);

} // namespace GView::View::DissasmViewer
