// Unit tests for the CRC hashes in GView::Hashes: the standard "123456789" check values, and reading the result
// several times / in any order (GetHexValue and Final must not alter the state).

#include "Internal.hpp"

#include <catch.hpp>

#include <string>
#include <string_view>

using namespace GView::Hashes;

namespace
{
constexpr std::string_view CHECK_INPUT = "123456789";

BufferView CheckInput()
{
    return BufferView(CHECK_INPUT);
}
} // namespace

TEST_CASE("CRC16 (CCITT, init 0) check value", "[Hashes][CRC16]")
{
    CRC16 crc{};
    REQUIRE(crc.Init());
    REQUIRE(crc.Update(CheckInput()));

    uint16 value = 0;
    REQUIRE(crc.Final(value));
    REQUIRE(value == 0x31C3);
    REQUIRE(std::string(crc.GetHexValue()) == "31C3");
}

TEST_CASE("CRC64 check values are stable across GetHexValue and Final", "[Hashes][CRC64]")
{
    struct Expected {
        CRC64Type type;
        uint64 value;
        std::string_view hex;
    };
    const Expected expected[] = {
        { CRC64Type::ECMA_182, 0x6C40DF5F0B497347ULL, "6C40DF5F0B497347" },
        { CRC64Type::WE, 0x62EC59E3F1A4F00AULL, "62EC59E3F1A4F00A" },
    };

    for (const auto& e : expected) {
        CRC64 crc{};
        REQUIRE(crc.Init(e.type));
        REQUIRE(crc.Update(CheckInput()));

        // GetHexValue first, then Final, then GetHexValue again: all must report the same value
        REQUIRE(crc.GetHexValue() == e.hex);
        uint64 value = 0;
        REQUIRE(crc.Final(value));
        REQUIRE(value == e.value);
        REQUIRE(crc.GetHexValue() == e.hex);
        REQUIRE(crc.Final(value));
        REQUIRE(value == e.value);
    }
}

TEST_CASE("CRC64 split updates match a single update", "[Hashes][CRC64]")
{
    CRC64 whole{};
    REQUIRE(whole.Init(CRC64Type::WE));
    REQUIRE(whole.Update(CheckInput()));

    CRC64 split{};
    REQUIRE(split.Init(CRC64Type::WE));
    REQUIRE(split.Update(BufferView(CHECK_INPUT.substr(0, 4))));
    REQUIRE(split.GetHexValue().size() == 16); // reading an intermediate value must not disturb the state
    REQUIRE(split.Update(BufferView(CHECK_INPUT.substr(4))));

    REQUIRE(split.GetHexValue() == whole.GetHexValue());
}
