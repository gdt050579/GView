#pragma once

#include "Internal.hpp"
#include "DissasmCodeZone.hpp"

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
    uint32 dataRanges      = 0; // the data defined by the user (IDA D / A)
    uint32 functions       = 0; // the functions edited by the user (IDA P, Delete function, noreturn)
    uint32 structures      = 0; // the structures the user gave to the variables (IDA Alt+Q)
    uint32 operandStructures = 0; // the structure offsets of the operands (IDA T)
    uint32 bookmarks         = 0; // the bookmarks of the user (IDA Alt+M)
    uint32 repeatableComments = 0; // the repeatable comments (IDA ;)
    uint32 prototypes         = 0; // the prototypes of the functions (IDA Y)
    std::vector<DissasmCodeZone*> zonesToReanalyze; // their data ranges changed: a new analysis gives their lines
    std::vector<DissasmCodeZone*> zonesWithNewLines; // a collapsed zone was placed: the size of the zone changed
};
// Adds the annotations of a zone of the document to the zone: the ones of the document win, the other data of the zone stays (nothing is
// deleted). The history of the edits is cleared (an import is not an edit that can be undone).
void ImportZoneAnnotations(DissasmCodeZone& zone, const nlohmann::json& zoneJson, DissasmAnnotationsImport& result);
// every zone of the document applied to the zone of the same file offset; false (and the reason) when it is not such a document. The zones
// whose data ranges changed are listed (zonesToReanalyze): their ranges apply at their next analysis
bool ImportAnnotationsDocument(const nlohmann::json& document, const std::vector<DissasmCodeZone*>& zones, DissasmAnnotationsImport& result, std::string& error);
// the same, without the guard against the exceptions of the fields of an unexpected type (ImportAnnotationsDocument catches them)
bool ImportAnnotationsDocumentFields(const nlohmann::json& document, const std::vector<DissasmCodeZone*>& zones, DissasmAnnotationsImport& result, std::string& error);
// the same, and the zones whose data ranges changed are analyzed again by `reanalyze`, then the document is imported into them again (the
// names of the new labels)
bool ImportAnnotationsDocument(
      const nlohmann::json& document,
      const std::vector<DissasmCodeZone*>& zones,
      DissasmAnnotationsImport& result,
      std::string& error,
      const std::function<bool(DissasmCodeZone&)>& reanalyze);

struct DissasmCodeZoneInitData;
// a new analysis of a zone: the annotations of the user and the history of the edits, given back when the analysis ends
struct DissasmReanalysis {
    nlohmann::json annotations;
    DissasmEditHistory history;
};
// the new analysis starts (InitZone with the budgets of initData: the deep scan may continue, IsDeepScanPending); false when the zone can
// not be initialized. FinishCodeZoneReanalysis once the deep scan ended (committed or cancelled): the annotations and the history come back
bool BeginCodeZoneReanalysis(DissasmCodeZone& zone, DissasmCodeZoneInitData& initData, DissasmReanalysis& state);
void FinishCodeZoneReanalysis(DissasmCodeZone& zone, DissasmReanalysis& state, DissasmAnnotationsImport& imported);
// The zone analyzed again (its user data ranges changed: D / A / U): the annotations of the user are exported, the zone is initialized again
// (the line count and the deep scan run at once) and the annotations are imported into the new analysis. False when the zone can not be
// initialized.
bool ReanalyzeCodeZone(DissasmCodeZone& zone, DissasmCodeZoneInitData& initData, DissasmAnnotationsImport& imported);
} // namespace GView::View::DissasmViewer
