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

    bool ToBuffer(std::vector<std::byte>& buffer) const;
    // `zoneLinesChanged` is set when the cache removed lines (deleted local variables), the zone size must be adjusted
    bool TryLoadDataFromCache(DissasmCache& cache, bool& zoneLinesChanged);
};

} // namespace GView::View::DissasmViewer
