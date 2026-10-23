// Unit tests for the decoders of the ELF packed relocations in GView::Utils: RELR (-z pack-relative-relocs) and the Android APS2
// format (--pack-dyn-relocs=android).

#include "Internal.hpp"

#include <catch.hpp>

#include <vector>

using namespace GView::Utils;

namespace
{
template <typename T>
void PutWord(std::vector<uint8>& data, T value)
{
    for (size_t index = 0; index < sizeof(T); index++)
        data.push_back(static_cast<uint8>(static_cast<uint64>(value) >> (8 * index)));
}

// signed LEB128, as the packer writes the numbers
void PutSleb(std::vector<uint8>& data, int64 value)
{
    bool more = true;
    while (more) {
        uint8 byte = static_cast<uint8>(value & 0x7F);
        value >>= 7;
        more = !((value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0));
        data.push_back(more ? static_cast<uint8>(byte | 0x80) : byte);
    }
}
} // namespace

TEST_CASE("RELR relocations", "[Utils][ElfRelocations]")
{
    // 64 bit: an address, a bitmap (the slots 0 and 2 after it), an address, a bitmap of the slot 62 then a bitmap of the slot 0 (63 slots later)
    std::vector<uint8> data;
    PutWord<uint64>(data, 0x1000);
    PutWord<uint64>(data, 1 | (1ull << 1) | (1ull << 3));
    PutWord<uint64>(data, 0x2000);
    PutWord<uint64>(data, 1 | (1ull << 63));
    PutWord<uint64>(data, 1 | (1ull << 1));
    std::vector<uint64> addresses;
    REQUIRE(DecodeElfRelr(BufferView(data.data(), data.size()), true, addresses));
    const std::vector<uint64> expected = { 0x1000, 0x1008, 0x1018, 0x2000, 0x2008 + 62 * 8, 0x2008 + 63 * 8 };
    REQUIRE(addresses == expected);

    // 32 bit: 31 slots per bitmap
    data.clear();
    addresses.clear();
    PutWord<uint32>(data, 0x100);
    PutWord<uint32>(data, 1 | (1u << 1) | (1u << 31));
    REQUIRE(DecodeElfRelr(BufferView(data.data(), data.size()), false, addresses));
    REQUIRE(addresses == std::vector<uint64>{ 0x100, 0x104, 0x104 + 30 * 4 });

    // a bitmap before any address, a truncated entry
    data.clear();
    addresses.clear();
    PutWord<uint64>(data, 3);
    REQUIRE_FALSE(DecodeElfRelr(BufferView(data.data(), data.size()), true, addresses));
    data = { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    addresses.clear();
    REQUIRE_FALSE(DecodeElfRelr(BufferView(data.data(), data.size()), true, addresses));
    REQUIRE(addresses == std::vector<uint64>{ 0x1000 });
}

TEST_CASE("Android packed relocations", "[Utils][ElfRelocations]")
{
    constexpr uint64 R_AARCH64_GLOB_DAT = 1025, R_AARCH64_RELATIVE = 1027;
    // "APS2", the count, the first offset; a group of 3 relative relocations (the offset delta and the info grouped, an addend each), a
    // group of 1 (nothing grouped, no addend)
    std::vector<uint8> data = { 'A', 'P', 'S', '2' };
    PutSleb(data, 4);
    PutSleb(data, 0x1000);
    PutSleb(data, 3);
    PutSleb(data, 2 | 1 | 8); // GROUPED_BY_OFFSET_DELTA | GROUPED_BY_INFO | GROUP_HAS_ADDEND
    PutSleb(data, 8);
    PutSleb(data, R_AARCH64_RELATIVE);
    PutSleb(data, 0x500); // the addends: deltas
    PutSleb(data, 0x10);
    PutSleb(data, -0x20);
    PutSleb(data, 1);
    PutSleb(data, 0);
    PutSleb(data, 0x100);
    PutSleb(data, static_cast<int64>((5ull << 32) | R_AARCH64_GLOB_DAT));
    std::vector<ElfRelocation> relocations;
    REQUIRE(DecodeAndroidPackedRelocations(BufferView(data.data(), data.size()), true, relocations));
    REQUIRE(relocations.size() == 4);
    REQUIRE(relocations[0].offset == 0x1008);
    REQUIRE(relocations[0].info == R_AARCH64_RELATIVE);
    REQUIRE(relocations[0].addend == 0x500);
    REQUIRE(relocations[1].offset == 0x1010);
    REQUIRE(relocations[1].addend == 0x510);
    REQUIRE(relocations[2].offset == 0x1018);
    REQUIRE(relocations[2].addend == 0x4F0);
    REQUIRE(relocations[3].offset == 0x1118);
    REQUIRE(relocations[3].info == ((5ull << 32) | R_AARCH64_GLOB_DAT));
    REQUIRE(relocations[3].addend == 0);

    // another magic, a group bigger than the count, a truncated stream
    std::vector<uint8> other = { 'A', 'P', 'S', '1', 0x00 };
    relocations.clear();
    REQUIRE_FALSE(DecodeAndroidPackedRelocations(BufferView(other.data(), other.size()), true, relocations));
    other = { 'A', 'P', 'S', '2' };
    PutSleb(other, 1);
    PutSleb(other, 0);
    PutSleb(other, 2);
    PutSleb(other, 0);
    REQUIRE_FALSE(DecodeAndroidPackedRelocations(BufferView(other.data(), other.size()), true, relocations));
    data.resize(data.size() - 2);
    relocations.clear();
    REQUIRE_FALSE(DecodeAndroidPackedRelocations(BufferView(data.data(), data.size()), true, relocations));
    REQUIRE(relocations.size() == 3); // the group of 3 is kept
}
