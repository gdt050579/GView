#include <GView.hpp>

namespace GView::Utils
{
namespace
{
constexpr size_t MAX_RELOCATIONS = 0x1000000; // 16 M relocations: more is a malformed table

// the numbers of the Android packed relocations: signed LEB128
class Sleb128Reader
{
    const uint8* data;
    size_t size;
    size_t position = 0;

  public:
    bool failed = false;
    Sleb128Reader(const uint8* data, size_t size) : data(data), size(size)
    {
    }
    int64 Next()
    {
        int64 value  = 0;
        uint32 shift = 0;
        uint8 byte   = 0;
        do {
            if (position >= size) {
                failed = true;
                return 0;
            }
            byte = data[position++];
            if (shift < 64)
                value |= static_cast<int64>(byte & 0x7F) << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);
        if (shift < 64 && (byte & 0x40) != 0)
            value |= -(static_cast<int64>(1) << shift);
        return value;
    }
};
} // namespace

bool DecodeElfRelr(BufferView data, bool is64, std::vector<uint64>& addresses)
{
    if (!data.IsValid())
        return false;
    const size_t word      = is64 ? 8 : 4;
    const uint64 slotsBits = word * 8 - 1; // the slots of a bitmap entry: 63 / 31
    std::optional<uint64> next;            // the slot after the last address
    for (size_t position = 0; position + word <= data.GetLength(); position += word) {
        uint64 value = 0;
        memcpy(&value, data.GetData() + position, word);
        if ((value & 1) == 0) {
            // an address: its slot is relocated, a bitmap that follows starts after it
            if (addresses.size() >= MAX_RELOCATIONS)
                return false;
            addresses.push_back(value);
            next = value + word;
            continue;
        }
        // a bitmap: bit n (from 1) relocates the slot n - 1 from `next`; the next bitmap starts 63 / 31 slots later
        if (!next.has_value())
            return false;
        for (uint64 bit = 0; bit < slotsBits; bit++)
            if (((value >> (bit + 1)) & 1) != 0) {
                if (addresses.size() >= MAX_RELOCATIONS)
                    return false;
                addresses.push_back(next.value() + bit * word);
            }
        next = next.value() + slotsBits * word;
    }
    return data.GetLength() % word == 0;
}

bool DecodeAndroidPackedRelocations(BufferView data, bool isRela, std::vector<ElfRelocation>& relocations)
{
    constexpr int64 GROUPED_BY_INFO         = 1;
    constexpr int64 GROUPED_BY_OFFSET_DELTA = 2;
    constexpr int64 GROUPED_BY_ADDEND       = 4;
    constexpr int64 GROUP_HAS_ADDEND        = 8;
    if (!data.IsValid() || data.GetLength() < 4 || memcmp(data.GetData(), "APS2", 4) != 0)
        return false;
    Sleb128Reader reader(data.GetData() + 4, data.GetLength() - 4);
    int64 remaining = reader.Next();
    ElfRelocation relocation{ static_cast<uint64>(reader.Next()), 0, 0 };
    if (reader.failed || remaining < 0 || static_cast<uint64>(remaining) > MAX_RELOCATIONS)
        return false;
    while (remaining > 0) {
        const int64 groupSize  = reader.Next();
        const int64 groupFlags = reader.Next();
        if (reader.failed || groupSize <= 0 || groupSize > remaining)
            return false;
        int64 offsetDelta = 0;
        if ((groupFlags & GROUPED_BY_OFFSET_DELTA) != 0)
            offsetDelta = reader.Next();
        if ((groupFlags & GROUPED_BY_INFO) != 0)
            relocation.info = static_cast<uint64>(reader.Next());
        const bool hasAddend = isRela && (groupFlags & GROUP_HAS_ADDEND) != 0;
        if (hasAddend && (groupFlags & GROUPED_BY_ADDEND) != 0)
            relocation.addend += reader.Next();
        else if (!hasAddend)
            relocation.addend = 0;
        for (int64 index = 0; index < groupSize; index++) {
            relocation.offset += static_cast<uint64>((groupFlags & GROUPED_BY_OFFSET_DELTA) != 0 ? offsetDelta : reader.Next());
            if ((groupFlags & GROUPED_BY_INFO) == 0)
                relocation.info = static_cast<uint64>(reader.Next());
            if (hasAddend && (groupFlags & GROUPED_BY_ADDEND) == 0)
                relocation.addend += reader.Next();
            if (reader.failed)
                return false;
            relocations.push_back(relocation);
        }
        remaining -= groupSize;
    }
    return true;
}
} // namespace GView::Utils
