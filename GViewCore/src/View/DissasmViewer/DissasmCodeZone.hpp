#pragma once

#include "DissasmViewer.hpp"

namespace GView::View::DissasmViewer
{

struct DissasmCodeZone : public ParseZone {
    enum class CollapseExpandType : uint8 { Collapse, Expand, NegateCurrentState };
    uint32 lastDrawnLine; // optimization not to recompute buffer every time
    uint32 lastClosestLine;
    uint32 offsetCacheMaxLine;
    BufferView lastData;
    uint32 lastReachedLine = UINT32_MAX;

    // fields only for dissasmx86/x64
    const uint8* asmData;
    uint64 asmSize, asmAddress;

    uint32 structureIndex;
    std::list<std::reference_wrapper<DissasmCodeInternalType>> types;
    std::list<uint32> levels;
    DissasmCodeInternalType dissasmType;

    DissasmAsmPreCacheData asmPreCacheData;

    std::vector<AsmOffsetLine> cachedCodeOffsets;
    DisassemblyZone zoneDetails;
    int internalArchitecture; // used for dissasm libraries
    bool isInit;
    bool changedLevel;
    InternalTypeNewLevelChangeData newLevelChangeData;

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
    bool TryRenameLine(uint32 line, std::string_view *newName = nullptr);

    bool GetComment(uint32 line, std::string& comment);
    bool AddOrUpdateComment(uint32 line, const std::string& comment, bool showErr = true);
    bool RemoveComment(uint32 line, bool showErr = true);
    DissasmAsmPreCacheLine GetCurrentAsmLine(uint32 currentLine, Reference<GView::Object> obj, DissasmInsnExtractLineParams* params);

    bool ToBuffer(std::vector<uint8>& buffer) const;
    bool TryLoadDataFromCache(DissasmCache& cache);
};

} // namespace GView::View::DissasmViewer
