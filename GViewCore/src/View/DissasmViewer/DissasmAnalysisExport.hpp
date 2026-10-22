#pragma once

#include "Internal.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace GView::View::DissasmViewer
{
// The analysis of the disassembly zones that a type plugin gives to the viewer, as JSON, without a window (GView analyze): every zone is
// analyzed at once (the deep scan), the data of the user (comments, names) is read from the cache of the file when it has one. The
// functions, their callers and callees, the strings used by the code, the switches, the comments and the names are written.
// Takes the ownership of the data of `settings`.
struct DissasmAnalysisOptions {
    // applied after the cache, in this order (the names of the user first, the signatures name only the sub_ functions); the results are
    // written to the JSON (annotationsImport / signaturesApply, an error there does not stop the analysis)
    const nlohmann::json* annotations = nullptr;
    const nlohmann::json* signatures  = nullptr;
    nlohmann::json* signaturesOutput  = nullptr; // set: receives the signatures of the named functions (BuildSignaturesDocument)
    std::string* listingOutput        = nullptr; // set: receives the listing of every analyzed zone (BuildX86AsmListing), one after the other
};
bool BuildAnalysisJson(Reference<GView::Object> obj, Settings& settings, std::string& json, std::string& error, const DissasmAnalysisOptions& options = {});
} // namespace GView::View::DissasmViewer
