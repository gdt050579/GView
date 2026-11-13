#pragma once

#include "DissasmDataTypes.hpp"

#include <optional>

namespace GView::View::DissasmViewer
{
struct DissasmCodeZone;

// What the playback of a replay journal (DissasmReplayController) needs from a view. Apart from DissasmReplayController.hpp: the view
// (Instance, DissasmViewer.hpp) implements it and DissasmViewer.hpp can not include the headers of the zones.
struct DissasmReplayHost {
    virtual ~DissasmReplayHost() = default;
    // the analysed code zone of the file that starts at the file offset (DissasmReplayZone::fileOffset); none when there is no such zone
    virtual DissasmCodeZone* FindZone(uint64 fileOffset) = 0;
    // the cursor on the line of the anchor; false when this analysis has no such line
    virtual bool MoveCursor(DissasmCodeZone& zone, const DissasmCommentAnchor& anchor) = 0;
    // an edit was applied to the zone: its size (a collapsible zone added / removed), its prepared lines, what is drawn from it
    virtual void ZoneLinesChanged(DissasmCodeZone& zone) = 0;
    // an edit of the data / the functions of the user was applied: the zone is analyzed again (keepAddress: relative, the line to show)
    virtual void Reanalyze(DissasmCodeZone& zone, std::optional<uint64> keepAddress) = 0;
};
} // namespace GView::View::DissasmViewer
