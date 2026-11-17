#pragma once

// the mutations of the fuzz tests of the cache records (tests_dissasmviewer.cpp, tests_dissasmreplay.cpp)
#include "AppCUI/include/AppCUI.hpp"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <random>
#include <vector>

using AppCUI::uint32;
using AppCUI::uint64;

// a mutation of a record (the cache file is untrusted: a sample can come with its cache): bit flips, 4 / 8 byte fields at the values that
// break the counts and the sizes, a truncation, inserted bytes, a duplicated chunk
inline std::vector<std::byte> MutateRecord(const std::vector<std::byte>& record, std::mt19937& random)
{
    std::vector<std::byte> data = record;
    const auto pick = [&random](size_t count) { return count == 0 ? size_t(0) : static_cast<size_t>(random() % count); };
    static constexpr uint32 FIELDS[] = { 0, 1, 2, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x10000 };
    switch (random() % 6) {
    case 0:
        for (uint32 count = 1 + random() % 8; count > 0 && !data.empty(); count--)
            data[pick(data.size())] ^= static_cast<std::byte>(1u << (random() % 8));
        break;
    case 1:
        for (uint32 count = 1 + random() % 3; count > 0 && data.size() >= 4; count--) {
            const uint32 value = FIELDS[pick(std::size(FIELDS))];
            memcpy(data.data() + pick(data.size() - 3), &value, sizeof(value));
        }
        break;
    case 2:
        if (data.size() >= 8) {
            const uint64 value = (random() % 2) ? UINT64_MAX : 0x8000000000000000ull;
            memcpy(data.data() + pick(data.size() - 7), &value, sizeof(value));
        }
        break;
    case 3:
        data.resize(pick(data.size()));
        break;
    case 4: {
        const size_t at = pick(data.size() + 1);
        for (uint32 count = 1 + random() % 32; count > 0; count--)
            data.insert(data.begin() + at, static_cast<std::byte>(random() & 0xFF));
        break;
    }
    default:
        if (!data.empty()) {
            const size_t from = pick(data.size()), length = std::min<size_t>(data.size() - from, 1 + random() % 64);
            const std::vector<std::byte> chunk(data.begin() + from, data.begin() + from + length);
            data.insert(data.begin() + pick(data.size() + 1), chunk.begin(), chunk.end());
        }
        break;
    }
    return data;
}
