// Unit tests for GView::Utils::UTF16ToUTF8 / UTF16ToPath. The input is usually attacker-controlled (file paths, e-mail
// headers, document content), so unpaired surrogates must never throw and must always produce valid UTF-8.

#include <catch.hpp>

#include "Internal.hpp"

#include <string>

using GView::Utils::UTF16ToPath;
using GView::Utils::UTF16ToUTF8;

TEST_CASE("UTF16ToUTF8 encodes every UTF-8 sequence length", "[Utils][UTF16]")
{
    REQUIRE(UTF16ToUTF8(u"") == "");
    REQUIRE(UTF16ToUTF8(u"plain ascii") == "plain ascii");
    REQUIRE(UTF16ToUTF8(u"\U000000E9") == "\xC3\xA9");                // 2 bytes
    REQUIRE(UTF16ToUTF8(u"\U00000219") == "\xC8\x99");                // 2 bytes (Romanian s-comma)
    REQUIRE(UTF16ToUTF8(u"\U000020AC") == "\xE2\x82\xAC");            // 3 bytes
    REQUIRE(UTF16ToUTF8(u"\U0000FFFF") == "\xEF\xBF\xBF");            // last BMP code point
    REQUIRE(UTF16ToUTF8(u"\U0001F600") == "\xF0\x9F\x98\x80");    // surrogate pair -> 4 bytes
    REQUIRE(UTF16ToUTF8(u"\U0010FFFF") == "\xF4\x8F\xBF\xBF");    // highest code point
    REQUIRE(UTF16ToUTF8(u"a\U000000E9b\U0001F600c") == "a\xC3\xA9" "b\xF0\x9F\x98\x80" "c");
}

TEST_CASE("UTF16ToUTF8 replaces unpaired surrogates with U+FFFD", "[Utils][UTF16]")
{
    const std::string replacement = "\xEF\xBF\xBD";

    const char16_t loneHigh[]          = { u'a', 0xD83D, 0 };
    const char16_t loneLow[]           = { 0xDE00, u'b', 0 };
    const char16_t highThenAscii[]     = { 0xD83D, u'x', 0 };
    const char16_t twoHighs[]          = { 0xD83D, 0xD83D, 0xDE00, 0 };
    const char16_t reversedPair[]      = { 0xDE00, 0xD83D, 0 };

    REQUIRE(UTF16ToUTF8(loneHigh) == "a" + replacement);
    REQUIRE(UTF16ToUTF8(loneLow) == replacement + "b");
    REQUIRE(UTF16ToUTF8(highThenAscii) == replacement + "x");
    REQUIRE(UTF16ToUTF8(twoHighs) == replacement + "\xF0\x9F\x98\x80");
    REQUIRE(UTF16ToUTF8(reversedPair) == replacement + replacement);
}

TEST_CASE("UTF16ToUTF8 keeps embedded NUL characters", "[Utils][UTF16]")
{
    const std::u16string input(u"a\0b", 3);
    const std::string expected("a\0b", 3);
    REQUIRE(UTF16ToUTF8(input) == expected);
}

TEST_CASE("UTF16ToPath round-trips non-ASCII paths", "[Utils][UTF16]")
{
    const std::u16string input = u"dir/\U00000219\U000000E9\U000020AC\U0001F600.txt";
    REQUIRE(UTF16ToPath(input).u16string() == input);

    const char16_t loneHigh[] = { u'f', 0xD83D, 0 };
    REQUIRE(UTF16ToPath(loneHigh).u16string() == u"f\U0000FFFD");
}
