#pragma once

#include "Internal.hpp"

#include <string>

namespace GView::View::DissasmViewer
{
// The analysis of the disassembly zones that a type plugin gives to the viewer, as JSON, without a window (GView analyze): every zone is
// analyzed at once (the deep scan), the data of the user (comments, names) is read from the cache of the file when it has one. The
// functions, their callers and callees, the strings used by the code, the switches, the comments and the names are written.
// Takes the ownership of the data of `settings`.
bool BuildAnalysisJson(Reference<GView::Object> obj, Settings& settings, std::string& json, std::string& error);
} // namespace GView::View::DissasmViewer
