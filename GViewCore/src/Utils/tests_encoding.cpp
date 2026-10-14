// Unit tests for the small text helpers in GView::Utils: CharacterSet parsing / string representation,
// EncodedCharacter (UTF-8 encoding of a char16) and the UTF-16 entries of the JSON builder.

#include "Internal.hpp"

#include <catch.hpp>

#include <string>

using namespace GView::Utils;

namespace
{
void RequireSameMask(CharacterSet& a, CharacterSet& b)
{
    bool maskA[256];
    bool maskB[256];
    a.CopySetTo(maskA);
    b.CopySetTo(maskB);
    for (uint32 i = 0; i < 256; i++) {
        INFO("character " << i);
        REQUIRE(maskA[i] == maskB[i]);
    }
}

std::string BytesOf(BufferView bv)
{
    return std::string(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
}
} // namespace

TEST_CASE("CharacterSet parses \\xHH escapes inside ranges", "[Utils][CharacterSet]")
{
    CharacterSet cs;
    cs.ClearAll();
    REQUIRE(cs.Set(std::string_view{ "\\x00-\\x1F" }, true));

    bool mask[256];
    cs.CopySetTo(mask);
    for (uint32 i = 0; i < 256; i++) {
        INFO("character " << i);
        REQUIRE(mask[i] == (i <= 0x1F));
    }

    // an escape followed directly by another character must not swallow it
    cs.ClearAll();
    REQUIRE(cs.Set(std::string_view{ "\\x41B" }, true));
    cs.CopySetTo(mask);
    REQUIRE(mask[0x41]);       // 'A'
    REQUIRE(mask[0x42]);       // 'B'
    REQUIRE_FALSE(mask[0x43]); // 'C'
}

TEST_CASE("CharacterSet string representation round-trips", "[Utils][CharacterSet]")
{
    CharacterSet original;
    original.ClearAll();
    REQUIRE(original.Set(0u, 0x20u, true)); // [0x00, 0x1F] -> written as \x00-\x1F
    original.Set(static_cast<uint8>('A'), true);
    REQUIRE(original.Set(static_cast<uint32>('a'), static_cast<uint32>('z') + 1, true));
    REQUIRE(original.Set(0x80u, 0x100u, true)); // [0x80, 0xFF] -> written as \x80-\xFF

    String repr;
    REQUIRE(original.GetStringRepresentation(repr));

    CharacterSet parsed;
    parsed.ClearAll();
    REQUIRE(parsed.Set(repr.ToStringView(), true));
    RequireSameMask(original, parsed);
}

TEST_CASE("EncodedCharacter produces valid UTF-8", "[Utils][CharacterEncoding]")
{
    using CharacterEncoding::Encoding;
    CharacterEncoding::EncodedCharacter ec;

    REQUIRE(BytesOf(ec.Encode(u'A', Encoding::UTF8)) == "A");
    REQUIRE(BytesOf(ec.Encode(0x7F, Encoding::UTF8)) == "\x7F");
    REQUIRE(BytesOf(ec.Encode(0x80, Encoding::UTF8)) == "\xC2\x80");
    REQUIRE(BytesOf(ec.Encode(0xE9, Encoding::UTF8)) == "\xC3\xA9");
    REQUIRE(BytesOf(ec.Encode(0xFF, Encoding::UTF8)) == "\xC3\xBF");
    REQUIRE(BytesOf(ec.Encode(0x7FF, Encoding::UTF8)) == "\xDF\xBF");
    REQUIRE(BytesOf(ec.Encode(0x20AC, Encoding::UTF8)) == "\xE2\x82\xAC");

    // Latin-1 characters stay single bytes in the Ascii encoding
    REQUIRE(BytesOf(ec.Encode(0xE9, Encoding::Ascii)) == "\xE9");
}

TEST_CASE("JsonBuilder writes UTF-16 values as UTF-8 strings", "[Utils][JsonBuilder]")
{
    auto builder = JsonBuilderInterface::Create();
    // code points instead of raw characters: MSVC reads BOM-less sources with the local code page
    const std::u16string name = std::u16string(u"ab") + static_cast<char16_t>(0x00E9);
    const std::u16string euro(1, static_cast<char16_t>(0x20AC));
    builder->AddU16String("name", name);
    builder->AddU16StringArray("list", { u"x", euro });
    auto arr = builder->StartArray("arr");
    builder->AddU16StringToArray(u"y", arr);
    const auto text = builder->ToString();
    JsonBuilderInterface::Destroy(builder);

    INFO(text);
    REQUIRE(text.find("\"name\": \"ab\xC3\xA9\"") != std::string::npos);
    REQUIRE(text.find("\"x\"") != std::string::npos);
    REQUIRE(text.find("\"\xE2\x82\xAC\"") != std::string::npos);
    REQUIRE(text.find("\"y\"") != std::string::npos);
}
