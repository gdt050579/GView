#pragma once

#include "Internal.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
struct DissasmCodeZone;

// Function signatures (FLIRT like): the first bytes of a named function with the bytes that depend on where the code and the data are
// masked (the targets of the calls, the RIP relative displacements, the absolute addresses; ARM: the branches, adrp / adr, the literal
// loads, movw / movt, the addresses built in registers, the literal pools). Written from a file that has the names (a build with symbols,
// a library), applied to a stripped one: a function with an automatic name (sub_) that matches one signature only gets its name.
constexpr std::string_view DISSASM_SIGNATURES_FORMAT = "gview-function-signatures";
constexpr uint32 DISSASM_SIGNATURES_VERSION          = 1;
constexpr uint32 DISSASM_SIGNATURE_MAX_SIZE          = 128; // the bytes of a pattern
constexpr uint32 DISSASM_SIGNATURE_MIN_FIXED_BYTES   = 12;  // a shorter (or mostly masked) function is not specific enough

struct DissasmFunctionPattern {
    std::vector<uint8> bytes;
    std::vector<bool> masked;
    uint64 functionSize = 0; // the bytes of the function (up to the next one)
    // "55 48 89 E5 E8 ?? ?? ?? ??"
    std::string ToText() const;
    uint32 FixedBytes() const;
};

// the pattern of the function at `start` (relative address of a function start of the zone); none when it can not be decoded
std::optional<DissasmFunctionPattern> BuildFunctionPattern(DissasmCodeZone& zone, uint64 start);

// the signatures of the named functions of the zones (not sub_ / loc_ / j_ / EntryPoint): {format, version, architecture, signatures}
nlohmann::json BuildSignaturesDocument(const std::vector<DissasmCodeZone*>& zones);

struct DissasmSignaturesApply {
    uint32 signatures = 0; // read from the document
    uint32 named      = 0; // functions that got a name
    uint32 ambiguous  = 0; // functions matched by signatures of different names, names matched by several functions
};
// the names of the signatures given to the functions with an automatic name; false (and the reason) when it is not such a document or it
// is for another architecture
bool ApplySignaturesDocument(const nlohmann::json& document, const std::vector<DissasmCodeZone*>& zones, DissasmSignaturesApply& result, std::string& error);
} // namespace GView::View::DissasmViewer
