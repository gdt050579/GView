// Unit tests for GView::Decoding::Base64 (RFC 4648 section 4). The decoder consumes attacker-controlled bytes, so the
// alphabet check is exercised with every byte value, including the ones above 0x7F that behave differently on
// targets where `char` is unsigned.

#include <catch.hpp>

#include "Internal.hpp"

#include <string>
#include <vector>

using namespace GView::Decoding;

namespace
{
std::string EncodeToString(BufferView input)
{
    Buffer output;
    Base64::Encode(input, output);
    return std::string(reinterpret_cast<const char*>(output.GetData()), output.GetLength());
}

std::string EncodeToString(std::string_view input)
{
    return EncodeToString(BufferView(input));
}

bool DecodeToBytes(std::string_view input, std::vector<uint8>& bytes, bool* hasWarning = nullptr)
{
    Buffer output;
    bool warning = false;
    String warningMessage;
    const bool ok = Base64::Decode(BufferView(input), output, warning, warningMessage);
    if (hasWarning) {
        *hasWarning = warning;
    }
    bytes.assign(output.GetData(), output.GetData() + output.GetLength());
    return ok;
}

std::string DecodeToString(std::string_view input)
{
    std::vector<uint8> bytes;
    REQUIRE(DecodeToBytes(input, bytes));
    return std::string(bytes.begin(), bytes.end());
}
} // namespace

TEST_CASE("Base64: RFC 4648 test vectors", "[Decoding][Base64]")
{
    const std::pair<std::string_view, std::string_view> vectors[] = {
        { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" }, { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
    };

    for (const auto& [plain, encoded] : vectors) {
        INFO("plain=\"" << plain << "\"");
        REQUIRE(EncodeToString(plain) == encoded);
        REQUIRE(DecodeToString(encoded) == plain);
    }
}

TEST_CASE("Base64: bytes above 0x7F are encoded in every position of the group", "[Decoding][Base64]")
{
    const uint8 first[]  = { 0xFF, 0x00, 0x00 };
    const uint8 second[] = { 0x00, 0xFF, 0x00 };
    const uint8 third[]  = { 0x00, 0x00, 0xFF };
    REQUIRE(EncodeToString(BufferView(first, sizeof(first))) == "/wAA");
    REQUIRE(EncodeToString(BufferView(second, sizeof(second))) == "AP8A");
    REQUIRE(EncodeToString(BufferView(third, sizeof(third))) == "AAD/");

    const uint8 tail[] = { 0x80, 0xFF };
    REQUIRE(EncodeToString(BufferView(tail, sizeof(tail))) == "gP8=");
}

TEST_CASE("Base64: every byte value round-trips", "[Decoding][Base64]")
{
    std::vector<uint8> all(256);
    for (uint32 i = 0; i < all.size(); ++i) {
        all[i] = static_cast<uint8>(i);
    }

    for (size_t length = 0; length <= all.size(); ++length) {
        const std::string encoded = EncodeToString(BufferView(all.data(), length));
        REQUIRE(encoded.size() == ((length + 2) / 3) * 4);

        std::vector<uint8> decoded;
        REQUIRE(DecodeToBytes(encoded, decoded));
        REQUIRE(decoded == std::vector<uint8>(all.begin(), all.begin() + length));
    }
}

TEST_CASE("Base64: decode rejects every byte outside the alphabet", "[Decoding][Base64]")
{
    for (uint32 value = 0; value < 256; ++value) {
        const bool inAlphabet =
              (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '+' || value == '/';
        const bool ignored = value == '\r' || value == '\n';
        const bool padding = value == '=';
        if (inAlphabet || ignored || padding) {
            continue;
        }

        const uint8 input[] = { 'Z', 'm', '9', static_cast<uint8>(value) };
        std::vector<uint8> bytes;
        INFO("byte=" << value);
        REQUIRE_FALSE(DecodeToBytes(std::string_view(reinterpret_cast<const char*>(input), sizeof(input)), bytes));
    }
}

TEST_CASE("Base64: decode skips line breaks, warns on trailing data and rejects excess padding", "[Decoding][Base64]")
{
    REQUIRE(DecodeToString("Zm9v\r\nYmFy\n") == "foobar");

    std::vector<uint8> bytes;
    bool hasWarning = false;
    REQUIRE(DecodeToBytes("Zg==Zg==", bytes, &hasWarning));
    REQUIRE(hasWarning);
    REQUIRE(std::string(bytes.begin(), bytes.end()) == "f");

    REQUIRE_FALSE(DecodeToBytes("Zm9v====", bytes));
}
