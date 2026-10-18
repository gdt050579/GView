#pragma once

#include "DissasmViewer.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
// A pointer that dyld fixes (Mach-O LC_DYLD_CHAINED_FIXUPS): a rebase points into the image, a bind to an imported symbol
struct ChainedFixup {
    uint64 address = 0; // the VA of the pointer
    bool isBind    = false;
    uint64 target  = 0; // a rebase: the VA it points to
    std::string name;   // a bind: the symbol (as in the file: _malloc)
    int64 addend = 0;   // a bind: the addend of the import and of the pointer
};

// The pointers of LC_DYLD_CHAINED_FIXUPS. `data` is its payload (dyld_chained_fixups_header, the starts of every segment, the imports and
// their names); the chains themselves are in the segments: every pointer holds the distance to the next one, `readPointer` reads the 4 / 8
// bytes at a VA of the image. Formats: DYLD_CHAINED_PTR_64 / 64_OFFSET, ARM64E / ARM64E_USERLAND / ARM64E_USERLAND24 (arm64e, with or
// without authentication), DYLD_CHAINED_PTR_32. False when the header or the pointer format is not known (the fixups found until then
// are kept)
bool DecodeChainedFixups(
      const uint8* data,
      size_t size,
      uint64 imageBase,
      const std::function<std::optional<uint64>(uint64 address, uint8 size)>& readPointer,
      std::vector<ChainedFixup>& fixups);

// the chained fixups given by the plugin (SettingsData::chainedFixups): the rebases become relocated pointers, the binds import slots
// named after their symbols (they are 0 for the view: the loader writes them)
void ApplyChainedFixups(SettingsData& settings, Reference<GView::Object> obj);
} // namespace GView::View::DissasmViewer
