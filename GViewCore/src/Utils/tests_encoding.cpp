// Unit tests for the small text helpers in GView::Utils: CharacterSet parsing / string representation,
// ExpandedCharacter / ConvertToUnicode16 (decoding, incl. code points above U+FFFF), EncodedCharacter (UTF-8 encoding of
// char16 text, incl. surrogate pairs) and the UTF-16 entries of the JSON builder.

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

// byte string built from numeric values (no non-ASCII characters in the source file)
std::string Bytes(std::initializer_list<uint8> values)
{
    std::string result;
    for (auto v : values)
        result.push_back(static_cast<char>(v));
    return result;
}

std::u16string Units(std::initializer_list<uint16> values)
{
    std::u16string result;
    for (auto v : values)
        result.push_back(static_cast<char16_t>(v));
    return result;
}

// the decoded character as a single char16 (as a number, Catch2 can not print char16_t in C++20)
uint32 CharOf(const CharacterEncoding::ExpandedCharacter& ec)
{
    return static_cast<uint32>(ec.GetChar());
}

std::u16string ToU16(const CharacterEncoding::ExpandedCharacter& ec)
{
    char16 units[2] = { 0, 0 };
    const auto count = ec.ToUTF16(units);
    return std::u16string(units, units + count);
}

// decodes the first character of 'bytes' with the given encoding
bool DecodeFirst(const std::string& bytes, CharacterEncoding::Encoding enc, CharacterEncoding::ExpandedCharacter& ec)
{
    const auto* p = reinterpret_cast<const uint8*>(bytes.data());
    return ec.FromEncoding(enc, p, p + bytes.size());
}

std::u16string ConvertToU16(const std::string& bytes)
{
    auto converted = CharacterEncoding::ConvertToUnicode16(BufferView(bytes.data(), bytes.size()));
    std::u16string result(converted.text, converted.text + converted.size);
    converted.Destroy();
    return result;
}

// encodes every char16 of 'text' (and flushes at the end), like the LexicalViewer "Save As" does
std::string EncodeAll(const std::u16string& text, CharacterEncoding::Encoding enc)
{
    CharacterEncoding::EncodedCharacter encoder;
    std::string result;
    for (auto ch : text)
        result += BytesOf(encoder.Encode(ch, enc));
    result += BytesOf(encoder.Flush());
    return result;
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

TEST_CASE("UTF-8 decoder handles 4-byte sequences (code points above U+FFFF)", "[Utils][CharacterEncoding]")
{
    using CharacterEncoding::Encoding;
    CharacterEncoding::ExpandedCharacter ec;
    const uint32 replacement = CharacterEncoding::UNICODE_REPLACEMENT_CHARACTER;

    // U+1F600 (grinning face) = F0 9F 98 80 -> surrogate pair D83D DE00
    REQUIRE(DecodeFirst(Bytes({ 0xF0, 0x9F, 0x98, 0x80 }), Encoding::UTF8, ec));
    REQUIRE(ec.Length() == 4);
    REQUIRE(ec.GetCodePoint() == 0x1F600);
    REQUIRE(ec.IsSurrogatePair());
    REQUIRE(ToU16(ec) == Units({ 0xD83D, 0xDE00 }));
    // single-cell consumers (TextViewer) get the replacement character, not a truncated value
    REQUIRE(CharOf(ec) == replacement);
    REQUIRE(static_cast<uint32>(static_cast<char16>(ec)) == replacement);

    // first and last 4-byte code points
    REQUIRE(DecodeFirst(Bytes({ 0xF0, 0x90, 0x80, 0x80 }), Encoding::UTF8, ec));
    REQUIRE(ec.GetCodePoint() == 0x10000);
    REQUIRE(ToU16(ec) == Units({ 0xD800, 0xDC00 }));
    REQUIRE(DecodeFirst(Bytes({ 0xF4, 0x8F, 0xBF, 0xBF }), Encoding::UTF8, ec));
    REQUIRE(ec.GetCodePoint() == 0x10FFFF);
    REQUIRE(ToU16(ec) == Units({ 0xDBFF, 0xDFFF }));

    // BMP characters are unchanged
    REQUIRE(DecodeFirst(Bytes({ 0xC3, 0xA9 }), Encoding::UTF8, ec));
    REQUIRE(ec.Length() == 2);
    REQUIRE(CharOf(ec) == 0xE9);
    REQUIRE_FALSE(ec.IsSurrogatePair());
    REQUIRE(ToU16(ec) == Units({ 0xE9 }));
    REQUIRE(DecodeFirst(Bytes({ 0xE2, 0x82, 0xAC }), Encoding::UTF8, ec));
    REQUIRE(ec.Length() == 3);
    REQUIRE(CharOf(ec) == 0x20AC);
    REQUIRE(DecodeFirst(Bytes({ 0xEF, 0xBF, 0xBF }), Encoding::UTF8, ec));
    REQUIRE(CharOf(ec) == 0xFFFF);
}

TEST_CASE("UTF-8 decoder rejects invalid, overlong and out-of-range sequences", "[Utils][CharacterEncoding]")
{
    using CharacterEncoding::Encoding;
    CharacterEncoding::ExpandedCharacter ec;

    // truncated 4-byte sequences
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF0, 0x9F, 0x98 }), Encoding::UTF8, ec));
    REQUIRE_FALSE(ec.IsValid());
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF0 }), Encoding::UTF8, ec));
    // bad continuation bytes
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF0, 0x9F, 0x41, 0x80 }), Encoding::UTF8, ec));
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF0, 0x9F, 0x98, 0x41 }), Encoding::UTF8, ec));
    // above U+10FFFF
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF4, 0x90, 0x80, 0x80 }), Encoding::UTF8, ec));
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF5, 0x80, 0x80, 0x80 }), Encoding::UTF8, ec));
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF7, 0xBF, 0xBF, 0xBF }), Encoding::UTF8, ec));
    // 5-byte lead
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF8, 0x88, 0x80, 0x80, 0x80 }), Encoding::UTF8, ec));
    // overlong forms
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xF0, 0x8F, 0xBF, 0xBF }), Encoding::UTF8, ec)); // U+FFFF in 4 bytes
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xE0, 0x80, 0xAF }), Encoding::UTF8, ec));       // '/' in 3 bytes
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xC0, 0xAF }), Encoding::UTF8, ec));             // '/' in 2 bytes
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xC1, 0xBF }), Encoding::UTF8, ec));
    // UTF-16 surrogates encoded in UTF-8
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xED, 0xA0, 0xBD }), Encoding::UTF8, ec));
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0xED, 0xB8, 0x80 }), Encoding::UTF8, ec));
    // a lone continuation byte
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0x80 }), Encoding::UTF8, ec));
    // last code point before the surrogates is still valid
    REQUIRE(DecodeFirst(Bytes({ 0xED, 0x9F, 0xBF }), Encoding::UTF8, ec));
    REQUIRE(CharOf(ec) == 0xD7FF);
}

TEST_CASE("UTF-16 decoder combines surrogate pairs", "[Utils][CharacterEncoding]")
{
    using CharacterEncoding::Encoding;
    CharacterEncoding::ExpandedCharacter ec;

    REQUIRE(DecodeFirst(Bytes({ 0x3D, 0xD8, 0x00, 0xDE }), Encoding::Unicode16LE, ec));
    REQUIRE(ec.Length() == 4);
    REQUIRE(ec.GetCodePoint() == 0x1F600);
    REQUIRE(CharOf(ec) == 0xFFFD);
    REQUIRE(ToU16(ec) == Units({ 0xD83D, 0xDE00 }));

    REQUIRE(DecodeFirst(Bytes({ 0xD8, 0x3D, 0xDE, 0x00 }), Encoding::Unicode16BE, ec));
    REQUIRE(ec.Length() == 4);
    REQUIRE(ec.GetCodePoint() == 0x1F600);

    // unpaired surrogates stay single units (2 bytes)
    REQUIRE(DecodeFirst(Bytes({ 0x3D, 0xD8, 0x41, 0x00 }), Encoding::Unicode16LE, ec));
    REQUIRE(ec.Length() == 2);
    REQUIRE(CharOf(ec) == 0xD83D);
    REQUIRE(DecodeFirst(Bytes({ 0x3D, 0xD8 }), Encoding::Unicode16LE, ec));
    REQUIRE(ec.Length() == 2);
    REQUIRE(DecodeFirst(Bytes({ 0x00, 0xDE, 0x3D, 0xD8 }), Encoding::Unicode16LE, ec));
    REQUIRE(ec.Length() == 2);
    REQUIRE(CharOf(ec) == 0xDE00);

    // plain BMP character and an incomplete unit
    REQUIRE(DecodeFirst(Bytes({ 0xAC, 0x20 }), Encoding::Unicode16LE, ec));
    REQUIRE(CharOf(ec) == 0x20AC);
    REQUIRE(DecodeFirst(Bytes({ 0x20, 0xAC }), Encoding::Unicode16BE, ec));
    REQUIRE(CharOf(ec) == 0x20AC);
    REQUIRE_FALSE(DecodeFirst(Bytes({ 0x41 }), Encoding::Unicode16LE, ec));
}

TEST_CASE("ConvertToUnicode16 emits surrogate pairs for code points above U+FFFF", "[Utils][CharacterEncoding]")
{
    // UTF-8 BOM forces the UTF-8 decoder
    REQUIRE(ConvertToU16(Bytes({ 0xEF, 0xBB, 0xBF, 'a', 0xF0, 0x9F, 0x98, 0x80, 'b', 0xC3, 0xA9 })) ==
            Units({ 'a', 0xD83D, 0xDE00, 'b', 0xE9 }));
    REQUIRE(ConvertToU16(Bytes({ 0xEF, 0xBB, 0xBF, 0xF4, 0x8F, 0xBF, 0xBF })) == Units({ 0xDBFF, 0xDFFF }));

    // invalid sequences keep the existing handling: every byte of them becomes one (Latin-1) character
    REQUIRE(ConvertToU16(Bytes({ 0xEF, 0xBB, 0xBF, 'a', 0xF0, 0x9F, 0x98, 'b' })) == Units({ 'a', 0xF0, 0x9F, 0x98, 'b' }));
    REQUIRE(ConvertToU16(Bytes({ 0xEF, 0xBB, 0xBF, 0xF4, 0x90, 0x80, 0x80 })) == Units({ 0xF4, 0x90, 0x80, 0x80 }));
    REQUIRE(ConvertToU16(Bytes({ 0xEF, 0xBB, 0xBF, 0xC0, 0xAF })) == Units({ 0xC0, 0xAF }));

    // UTF-16 input: pairs are kept as pairs
    REQUIRE(ConvertToU16(Bytes({ 0xFF, 0xFE, 'x', 0, 0x3D, 0xD8, 0x00, 0xDE, 'y', 0 })) == Units({ 'x', 0xD83D, 0xDE00, 'y' }));
    REQUIRE(ConvertToU16(Bytes({ 0xFE, 0xFF, 0, 'x', 0xD8, 0x3D, 0xDE, 0x00 })) == Units({ 'x', 0xD83D, 0xDE00 }));
}

TEST_CASE("EncodedCharacter writes a surrogate pair as one 4-byte UTF-8 sequence", "[Utils][CharacterEncoding]")
{
    using CharacterEncoding::Encoding;
    const auto replacement = Bytes({ 0xEF, 0xBF, 0xBD });
    const auto emoji       = Bytes({ 0xF0, 0x9F, 0x98, 0x80 });

    {
        CharacterEncoding::EncodedCharacter ec;
        REQUIRE(ec.Encode(0xD83D, Encoding::UTF8).GetLength() == 0); // held back until the low surrogate
        REQUIRE(ec.HasPendingData());
        REQUIRE(BytesOf(ec.Encode(0xDE00, Encoding::UTF8)) == emoji);
        REQUIRE_FALSE(ec.HasPendingData());
        REQUIRE(ec.Flush().GetLength() == 0);
    }

    REQUIRE(EncodeAll(Units({ 'a', 0xD83D, 0xDE00, 'b' }), Encoding::UTF8) == "a" + emoji + "b");
    REQUIRE(EncodeAll(Units({ 0xD800, 0xDC00 }), Encoding::UTF8) == Bytes({ 0xF0, 0x90, 0x80, 0x80 }));
    REQUIRE(EncodeAll(Units({ 0xDBFF, 0xDFFF }), Encoding::UTF8) == Bytes({ 0xF4, 0x8F, 0xBF, 0xBF }));

    // unpaired surrogates become U+FFFD (never a 3-byte encoded surrogate)
    REQUIRE(EncodeAll(Units({ 0xDE00, 'b' }), Encoding::UTF8) == replacement + "b");
    REQUIRE(EncodeAll(Units({ 0xD83D, 'A' }), Encoding::UTF8) == replacement + "A");
    REQUIRE(EncodeAll(Units({ 0xD83D, 0xE9 }), Encoding::UTF8) == replacement + Bytes({ 0xC3, 0xA9 }));
    REQUIRE(EncodeAll(Units({ 0xD83D, 0xD83D, 0xDE00 }), Encoding::UTF8) == replacement + emoji);
    REQUIRE(EncodeAll(Units({ 0xDE00, 0xD83D }), Encoding::UTF8) == replacement + replacement);
    REQUIRE(EncodeAll(Units({ 'a', 0xD83D }), Encoding::UTF8) == "a" + replacement); // flushed at the end

    // UTF-16 output writes the pair unit by unit
    REQUIRE(EncodeAll(Units({ 0xD83D, 0xDE00 }), Encoding::Unicode16LE) == Bytes({ 0x3D, 0xD8, 0x00, 0xDE }));
    REQUIRE(EncodeAll(Units({ 0xD83D, 0xDE00 }), Encoding::Unicode16BE) == Bytes({ 0xD8, 0x3D, 0xDE, 0x00 }));

    // round trip: UTF-8 -> UTF-16 -> UTF-8
    const auto utf8 = Bytes({ 0xEF, 0xBB, 0xBF, 'a', 0xF0, 0x9F, 0x98, 0x80, 0xE2, 0x82, 0xAC, 0xF4, 0x8F, 0xBF, 0xBF });
    REQUIRE(EncodeAll(ConvertToU16(utf8), Encoding::UTF8) == utf8.substr(3));
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
