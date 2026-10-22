#include "DissasmChainedFixups.hpp"

#include <cstring>

using namespace GView::View::DissasmViewer;

namespace
{
// the pointer formats of dyld (mach-o/fixup-chains.h)
constexpr uint16 DYLD_CHAINED_PTR_ARM64E            = 1;
constexpr uint16 DYLD_CHAINED_PTR_64                = 2;
constexpr uint16 DYLD_CHAINED_PTR_32                = 3;
constexpr uint16 DYLD_CHAINED_PTR_64_OFFSET         = 6;
constexpr uint16 DYLD_CHAINED_PTR_ARM64E_USERLAND   = 9;
constexpr uint16 DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12;
constexpr uint16 DYLD_CHAINED_PTR_START_NONE        = 0xFFFF; // a page without fixups
constexpr uint16 DYLD_CHAINED_PTR_START_MULTI       = 0x8000; // 32 bit: the page has several chains (an index into the starts)
constexpr uint16 DYLD_CHAINED_PTR_START_LAST        = 0x8000; // 32 bit: the last start of a page
constexpr uint32 MAX_IMPORTS                        = 1u << 20;
constexpr uint32 MAX_CHAIN_POINTERS                 = 1u << 16; // a page of 64 KB with a pointer every 4 bytes: a longer chain loops

template <typename T>
bool ReadAt(const uint8* data, size_t size, uint64 offset, T& value)
{
    if (offset > size || size - offset < sizeof(T))
        return false;
    memcpy(&value, data + offset, sizeof(T));
    return true;
}

uint64 Bits(uint64 value, unsigned shift, unsigned count)
{
    return (value >> shift) & ((1ull << count) - 1);
}

int64 SignedBits(uint64 value, unsigned shift, unsigned count)
{
    const uint64 sign = 1ull << (count - 1);
    return static_cast<int64>((Bits(value, shift, count) ^ sign) - sign);
}

struct ChainedImport {
    std::string name;
    int64 addend = 0;
};

struct ChainedPointer {
    bool isPointer = true; // DYLD_CHAINED_PTR_32: a value above max_valid_pointer is not a pointer
    bool isBind    = false;
    uint64 target  = 0;
    uint32 ordinal = 0; // the index of the import
    int64 addend   = 0;
    uint32 next    = 0; // the distance to the next pointer of the chain, in strides; 0 ends the chain
};

// one pointer of a chain: a rebase (the VA it points to) or a bind (an import)
std::optional<ChainedPointer> DecodePointer(uint16 format, uint64 raw, uint64 imageBase, uint32 maxValidPointer)
{
    ChainedPointer pointer;
    switch (format) {
    case DYLD_CHAINED_PTR_64: // rebase: target:36 high8:8 reserved:7 next:12 bind:1; bind: ordinal:24 addend:8 reserved:19 next:12 bind:1
    case DYLD_CHAINED_PTR_64_OFFSET:
        pointer.next   = static_cast<uint32>(Bits(raw, 51, 12));
        pointer.isBind = Bits(raw, 63, 1) != 0;
        if (pointer.isBind) {
            pointer.ordinal = static_cast<uint32>(Bits(raw, 0, 24));
            pointer.addend  = static_cast<int64>(Bits(raw, 24, 8));
        } else
            pointer.target = Bits(raw, 0, 36) + (format == DYLD_CHAINED_PTR_64_OFFSET ? imageBase : 0); // a VA / an offset in the image
        return pointer;
    case DYLD_CHAINED_PTR_ARM64E: // next:11 at bit 51, bind at 62, auth at 63
    case DYLD_CHAINED_PTR_ARM64E_USERLAND:
    case DYLD_CHAINED_PTR_ARM64E_USERLAND24: {
        pointer.next    = static_cast<uint32>(Bits(raw, 51, 11));
        pointer.isBind  = Bits(raw, 62, 1) != 0;
        const bool auth = Bits(raw, 63, 1) != 0;
        if (pointer.isBind) { // ordinal:16 (24) ...; a bind without authentication has an addend:19 at bit 32
            pointer.ordinal = static_cast<uint32>(Bits(raw, 0, format == DYLD_CHAINED_PTR_ARM64E_USERLAND24 ? 24 : 16));
            if (!auth)
                pointer.addend = SignedBits(raw, 32, 19);
        } else if (auth)
            pointer.target = imageBase + Bits(raw, 0, 32); // an offset in the image
        else
            pointer.target = Bits(raw, 0, 43) + (format == DYLD_CHAINED_PTR_ARM64E ? 0 : imageBase); // ARM64E: a VA, userland: an offset
        return pointer;
    }
    case DYLD_CHAINED_PTR_32: // rebase: target:26 next:5 bind:1; bind: ordinal:20 addend:6 next:5 bind:1
        pointer.next   = static_cast<uint32>(Bits(raw, 26, 5));
        pointer.isBind = Bits(raw, 31, 1) != 0;
        if (pointer.isBind) {
            pointer.ordinal = static_cast<uint32>(Bits(raw, 0, 20));
            pointer.addend  = static_cast<int64>(Bits(raw, 20, 6));
        } else {
            pointer.target    = Bits(raw, 0, 26);
            pointer.isPointer = maxValidPointer == 0 || pointer.target <= maxValidPointer;
        }
        return pointer;
    default:
        return {};
    }
}

bool ReadImports(const uint8* data, size_t size, uint32 importsOffset, uint32 symbolsOffset, uint32 count, uint32 format, std::vector<ChainedImport>& imports)
{
    if (count > MAX_IMPORTS)
        return false;
    const auto nameAt = [data, size, symbolsOffset](uint64 nameOffset) {
        const uint64 offset = static_cast<uint64>(symbolsOffset) + nameOffset;
        if (offset >= size)
            return std::string();
        const auto text = reinterpret_cast<const char*>(data + offset);
        return std::string(text, strnlen(text, size - offset));
    };
    imports.reserve(count);
    for (uint32 index = 0; index < count; index++) {
        ChainedImport import;
        if (format == 1) { // DYLD_CHAINED_IMPORT: lib_ordinal:8 weak_import:1 name_offset:23
            uint32 value = 0;
            if (!ReadAt(data, size, importsOffset + 4ull * index, value))
                return false;
            import.name = nameAt(value >> 9);
        } else if (format == 2) { // DYLD_CHAINED_IMPORT_ADDEND: the same, then an int32 addend
            uint32 value = 0;
            int32 addend = 0;
            if (!ReadAt(data, size, importsOffset + 8ull * index, value) || !ReadAt(data, size, importsOffset + 8ull * index + 4, addend))
                return false;
            import.name   = nameAt(value >> 9);
            import.addend = addend;
        } else if (format == 3) { // DYLD_CHAINED_IMPORT_ADDEND64: lib_ordinal:16 weak_import:1 reserved:15 name_offset:32, an int64 addend
            uint64 value = 0;
            int64 addend = 0;
            if (!ReadAt(data, size, importsOffset + 16ull * index, value) || !ReadAt(data, size, importsOffset + 16ull * index + 8, addend))
                return false;
            import.name   = nameAt(value >> 32);
            import.addend = addend;
        } else
            return false;
        imports.push_back(std::move(import));
    }
    return true;
}
} // namespace

bool GView::View::DissasmViewer::DecodeChainedFixups(
      const uint8* data,
      size_t size,
      uint64 imageBase,
      const std::function<std::optional<uint64>(uint64 address, uint8 size)>& readPointer,
      std::vector<ChainedFixup>& fixups)
{
    // dyld_chained_fixups_header: fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format,
    // symbols_format (0: the names are not compressed)
    uint32 header[7] = {};
    if (!data || !ReadAt(data, size, 0, header) || header[0] != 0 || header[6] != 0)
        return false;
    const uint32 startsOffset = header[1];
    std::vector<ChainedImport> imports;
    if (!ReadImports(data, size, header[2], header[3], header[4], header[5], imports))
        return false;

    // dyld_chained_starts_in_image: seg_count, then the offset of the starts of every segment (0: no fixups), from startsOffset
    uint32 segmentsCount = 0;
    if (!ReadAt(data, size, startsOffset, segmentsCount))
        return false;
    bool known = true;
    for (uint32 segment = 0; segment < segmentsCount; segment++) {
        uint32 segmentInfo = 0;
        if (!ReadAt(data, size, startsOffset + 4ull + 4ull * segment, segmentInfo))
            return false;
        if (segmentInfo == 0)
            continue;
        // dyld_chained_starts_in_segment: size, page_size, pointer_format, segment_offset, max_valid_pointer, page_count, page_start[]
        const uint64 base = static_cast<uint64>(startsOffset) + segmentInfo;
        uint32 infoSize = 0, maxValidPointer = 0;
        uint16 pageSize = 0, format = 0, pageCount = 0;
        uint64 segmentOffset = 0;
        if (!ReadAt(data, size, base, infoSize) || !ReadAt(data, size, base + 4, pageSize) || !ReadAt(data, size, base + 6, format) ||
            !ReadAt(data, size, base + 8, segmentOffset) || !ReadAt(data, size, base + 16, maxValidPointer) || !ReadAt(data, size, base + 20, pageCount))
            return false;
        const bool isArm64e = format == DYLD_CHAINED_PTR_ARM64E || format == DYLD_CHAINED_PTR_ARM64E_USERLAND || format == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
        const bool is64     = format == DYLD_CHAINED_PTR_64 || format == DYLD_CHAINED_PTR_64_OFFSET || isArm64e;
        if (!is64 && format != DYLD_CHAINED_PTR_32) {
            known = false; // the kernel / firmware / shared cache formats
            continue;
        }
        const uint8 pointerSize = is64 ? 8 : 4;
        const uint32 stride     = isArm64e ? 8 : 4;
        const uint64 pageStarts = base + 22;
        const auto pageStartAt  = [&](uint64 index, uint16& value) { return (index + 1) * 2 + 22 <= infoSize && ReadAt(data, size, pageStarts + 2 * index, value); };
        const auto walk         = [&](uint64 page, uint16 start) {
            uint64 offset = segmentOffset + page * pageSize + start;
            for (uint32 count = 0; count < MAX_CHAIN_POINTERS; count++) {
                const uint64 address = imageBase + offset;
                const auto raw       = readPointer(address, pointerSize);
                if (!raw.has_value())
                    return;
                const auto pointer = DecodePointer(format, raw.value(), imageBase, maxValidPointer);
                if (!pointer.has_value())
                    return;
                if (pointer->isBind && pointer->ordinal < imports.size()) {
                    const auto& import = imports[pointer->ordinal];
                    fixups.push_back({ address, true, 0, import.name, import.addend + pointer->addend });
                } else if (!pointer->isBind && pointer->isPointer)
                    fixups.push_back({ address, false, pointer->target, {}, 0 });
                if (pointer->next == 0)
                    return;
                offset += static_cast<uint64>(pointer->next) * stride;
            }
        };
        for (uint64 page = 0; page < pageCount; page++) {
            uint16 start = 0;
            if (!pageStartAt(page, start) || start == DYLD_CHAINED_PTR_START_NONE)
                continue;
            if (format == DYLD_CHAINED_PTR_32 && (start & DYLD_CHAINED_PTR_START_MULTI) != 0) {
                // several chains: page_start[start & 0x7fff] and the next ones, up to the one marked as the last
                for (uint64 index = start & ~DYLD_CHAINED_PTR_START_MULTI; index < 0x8000; index++) {
                    uint16 chain = 0;
                    if (!pageStartAt(index, chain))
                        break;
                    walk(page, chain & ~DYLD_CHAINED_PTR_START_LAST);
                    if ((chain & DYLD_CHAINED_PTR_START_LAST) != 0)
                        break;
                }
                continue;
            }
            walk(page, start);
        }
    }
    return known;
}

bool GView::View::DissasmViewer::DecodeDyldBindOpcodes(
      const uint8* data, size_t size, const std::vector<uint64>& segmentAddresses, uint8 pointerSize, std::vector<DyldBind>& binds)
{
    constexpr uint8 OPCODE_MASK    = 0xF0;
    constexpr uint8 IMMEDIATE_MASK = 0x0F;
    constexpr size_t MAX_BINDS     = 0x400000;
    constexpr uint64 MAX_REPEAT    = 0x100000;
    size_t position                = 0;
    bool malformed                 = false;
    const auto uleb                = [&]() -> uint64 {
        uint64 value = 0;
        uint32 shift = 0;
        while (position < size) {
            const uint8 byte = data[position++];
            if (shift < 64)
                value |= static_cast<uint64>(byte & 0x7F) << shift;
            shift += 7;
            if ((byte & 0x80) == 0)
                return value;
        }
        malformed = true;
        return value;
    };
    const auto sleb = [&]() -> int64 {
        int64 value  = 0;
        uint32 shift = 0;
        uint8 byte   = 0;
        do {
            if (position >= size) {
                malformed = true;
                return value;
            }
            byte = data[position++];
            if (shift < 64)
                value |= static_cast<int64>(byte & 0x7F) << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);
        if (shift < 64 && (byte & 0x40) != 0)
            value |= -(static_cast<int64>(1) << shift);
        return value;
    };
    std::string symbol;
    int64 addend = 0;
    std::optional<uint64> address; // set by SET_SEGMENT_AND_OFFSET
    const auto bind = [&]() {
        if (address.has_value() && !symbol.empty() && binds.size() < MAX_BINDS)
            binds.push_back({ address.value(), symbol, addend });
        if (address.has_value())
            address = address.value() + pointerSize;
    };
    while (position < size && !malformed) {
        const uint8 byte      = data[position++];
        const uint8 immediate = byte & IMMEDIATE_MASK;
        switch (byte & OPCODE_MASK) {
        case 0x00: // DONE
            return true;
        case 0x10: // SET_DYLIB_ORDINAL_IMM
        case 0x30: // SET_DYLIB_SPECIAL_IMM
            break;
        case 0x20: // SET_DYLIB_ORDINAL_ULEB
            uleb();
            break;
        case 0x40: { // SET_SYMBOL_TRAILING_FLAGS_IMM, the name
            const size_t start = position;
            while (position < size && data[position] != 0)
                position++;
            if (position >= size)
                return false;
            symbol.assign(reinterpret_cast<const char*>(data + start), position - start);
            position++;
            break;
        }
        case 0x50: // SET_TYPE_IMM
            break;
        case 0x60: // SET_ADDEND_SLEB
            addend = sleb();
            break;
        case 0x70: { // SET_SEGMENT_AND_OFFSET_ULEB
            const uint64 offset = uleb();
            if (immediate >= segmentAddresses.size())
                return false;
            address = segmentAddresses[immediate] + offset;
            break;
        }
        case 0x80: // ADD_ADDR_ULEB
            if (address.has_value())
                address = address.value() + uleb();
            else
                uleb();
            break;
        case 0x90: // DO_BIND
            bind();
            break;
        case 0xA0: { // DO_BIND_ADD_ADDR_ULEB
            bind();
            const uint64 skip = uleb();
            if (address.has_value())
                address = address.value() + skip;
            break;
        }
        case 0xB0: // DO_BIND_ADD_ADDR_IMM_SCALED
            bind();
            if (address.has_value())
                address = address.value() + static_cast<uint64>(immediate) * pointerSize;
            break;
        case 0xC0: { // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            const uint64 count = uleb();
            const uint64 skip  = uleb();
            if (count > MAX_REPEAT)
                return false;
            for (uint64 index = 0; index < count && !malformed; index++) {
                bind();
                if (address.has_value())
                    address = address.value() + skip;
            }
            break;
        }
        default: // THREADED (arm64e) and the unknown opcodes
            return true;
        }
    }
    return !malformed;
}

void GView::View::DissasmViewer::ApplyChainedFixups(SettingsData& settings, Reference<GView::Object> obj)
{
    if ((settings.chainedFixups.empty() && settings.dyldBindInfos.empty()) || !obj.IsValid() || !settings.offsetTranslateCallback.IsValid())
        return;
    const uint64 fileSize   = obj->GetData().GetSize();
    const auto toFileOffset = [&settings, fileSize](uint64 address) -> std::optional<uint64> {
        const uint64 offset = settings.offsetTranslateCallback->TranslateToFileOffset(address, static_cast<uint32>(DissasmPEConversionType::VA));
        return offset < fileSize ? std::optional<uint64>(offset) : std::nullopt;
    };
    const auto readPointer = [&obj, &toFileOffset](uint64 address, uint8 size) -> std::optional<uint64> {
        const auto offset = toFileOffset(address);
        if (!offset.has_value())
            return {};
        if (size == 8) {
            uint64 value = 0;
            return obj->GetData().Copy<uint64>(offset.value(), value) ? std::optional<uint64>(value) : std::nullopt;
        }
        uint32 value = 0;
        return obj->GetData().Copy<uint32>(offset.value(), value) ? std::optional<uint64>(value) : std::nullopt;
    };
    std::vector<ChainedFixup> fixups;
    if (!settings.chainedFixups.empty())
        DecodeChainedFixups(settings.chainedFixups.data(), settings.chainedFixups.size(), settings.chainedFixupsImageBase, readPointer, fixups);
    // LC_DYLD_INFO: the binds of the opcodes, as the binds of the chains (the rebased pointers of these files already hold their address)
    for (const auto& info : settings.dyldBindInfos) {
        std::vector<DyldBind> binds;
        DecodeDyldBindOpcodes(info.opcodes.data(), info.opcodes.size(), info.segmentAddresses, info.pointerSize, binds);
        for (auto& bind : binds)
            fixups.push_back({ bind.address, true, 0, std::move(bind.name), bind.addend });
    }
    const uint64 imageBase = settings.chainedFixups.empty() && !settings.dyldBindInfos.empty() ? settings.dyldBindInfos.front().imageBase : settings.chainedFixupsImageBase;
    settings.dyldBindInfos.clear();
    for (const auto& fixup : fixups) {
        const auto offset = toFileOffset(fixup.address);
        if (!offset.has_value())
            continue;
        if (!fixup.isBind) {
            settings.relocatedPointers[offset.value()] = fixup.target;
            continue;
        }
        // a bind: an import slot named after its symbol (the indirect symbols of __got may have named it already); its value is not known
        if (!fixup.name.empty() && fixup.address >= imageBase) {
            String demangled;
            const bool isDemangled = GView::Utils::Demangle(fixup.name, demangled);
            const std::string name = isDemangled ? std::string(demangled.GetText(), demangled.Len()) : fixup.name;
#ifndef DISSASM_DISABLE_API_CALLS
            settings.memoryMappings.insert({ fixup.address - imageBase, { name, MemoryMappingType::FunctionMapping } });
#endif
            // the line of the pointer: the symbol and the addend (the vptr of a typeinfo: the vtable of __class_type_info + 0x10)
            std::string bound = name;
            if (fixup.addend != 0) {
                char text[32];
                snprintf(text, sizeof(text), fixup.addend > 0 ? "+0x%llx" : "-0x%llx",
                         static_cast<unsigned long long>(fixup.addend > 0 ? fixup.addend : -fixup.addend));
                bound += text;
            }
            settings.boundSymbols[fixup.address - imageBase] = std::move(bound);
        }
        settings.relocatedPointers.emplace(offset.value(), 0);
    }
    settings.chainedFixups.clear();
    settings.chainedFixups.shrink_to_fit();
}
