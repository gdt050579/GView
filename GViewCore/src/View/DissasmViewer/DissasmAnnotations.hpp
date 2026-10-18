#pragma once

#include "Internal.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
struct DissasmCodeZone;

// The annotations of the user as a plain text file (JSON): the names of the labels, the comments, the names of the local variables, the
// numbers shown in decimal, the collapsible zones, the suggestions of the assistant. Everything is keyed by the address of the listing (the
// VA): the file can be read, reviewed in a diff, merged by hand and shared, and it still applies after a new analysis. A zone is found by
// its file offset; its addressBase rebases the addresses (a rebased image).
constexpr std::string_view DISSASM_ANNOTATIONS_FORMAT  = "gview-disassembly-annotations";
constexpr uint32 DISSASM_ANNOTATIONS_VERSION           = 1;

nlohmann::json ExportZoneAnnotations(DissasmCodeZone& zone);
// the document of the zones: {format, version, file, zones: [...]}
nlohmann::json BuildAnnotationsDocument(const std::vector<DissasmCodeZone*>& zones, std::string_view fileName);

struct DissasmAnnotationsImport {
    uint32 names           = 0;
    uint32 comments        = 0;
    uint32 variables       = 0;
    uint32 decimalOperands = 0;
    uint32 collapsibleZones = 0;
    uint32 aiComments      = 0;
    uint32 suggestedNames  = 0;
    uint32 skipped         = 0; // an address outside the code, a label that does not exist, a name already used, a bad entry
    uint32 zones           = 0; // the zones of the document applied to a zone of the file
    std::vector<DissasmCodeZone*> zonesWithNewLines; // a collapsed zone was placed: the size of the zone changed
};
// Adds the annotations of a zone of the document to the zone: the ones of the document win, the other data of the zone stays (nothing is
// deleted). The history of the edits is cleared (an import is not an edit that can be undone).
void ImportZoneAnnotations(DissasmCodeZone& zone, const nlohmann::json& zoneJson, DissasmAnnotationsImport& result);
// every zone of the document applied to the zone of the same file offset; false (and the reason) when it is not such a document
bool ImportAnnotationsDocument(const nlohmann::json& document, const std::vector<DissasmCodeZone*>& zones, DissasmAnnotationsImport& result, std::string& error);
} // namespace GView::View::DissasmViewer
