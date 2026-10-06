#include "Internal.hpp"

constexpr char BASE64_ENCODE_TABLE[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                         'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                         's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

// -1 marks a byte outside the Base64 alphabet. The table is explicitly signed: `char` is unsigned on some targets
// (arm64 Linux among them), where `-1` would not even compile and the "not in alphabet" check would silently break.
constexpr int8 BASE64_DECODE_TABLE[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
                                         54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                                         10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                                         29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

constexpr uint32 BASE64_DECODE_TABLE_SIZE = sizeof(BASE64_DECODE_TABLE) / sizeof(BASE64_DECODE_TABLE[0]);

namespace GView::Decoding::Base64
{
void Encode(BufferView view, Buffer& output)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;

    for (size_t i = 0; i < view.GetLength(); ++i) {
        // zero-extended on purpose: through a (signed) `char`, bytes >= 0x80 would sign-extend over the bytes already packed
        const uint32 byte = view[i];

        sequence |= byte << ((3 - sequenceIndex) * 8);
        sequenceIndex++;

        if (sequenceIndex % 3 == 0) {
            // get 4 encoded components out of this one
            // 0x3f -> 0b00111111
            const char buffer[] = {
                BASE64_ENCODE_TABLE[(sequence >> 26) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 20) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 14) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 8) & 0x3f],
            };

            output.Add(string_view(buffer, 4));

            sequence      = 0;
            sequenceIndex = 0;
        }
    }

    // trailing group of 1 or 2 bytes: 2 or 3 significant characters, padded with '=' up to 4
    if (sequenceIndex > 0) {
        const char buffer[] = {
            BASE64_ENCODE_TABLE[(sequence >> 26) & 0x3f],
            BASE64_ENCODE_TABLE[(sequence >> 20) & 0x3f],
            BASE64_ENCODE_TABLE[(sequence >> 14) & 0x3f],
        };
        output.Add(string_view(buffer, sequenceIndex + 1));
        output.AddMultipleTimes(string_view("=", 1), 3 - sequenceIndex);
    }
}

bool Decode(BufferView view, Buffer& output, bool& hasWarning, String& warningMessage)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;
    uint8 lastEncoded    = 0;
    uint8 paddingCount   = 0;
    hasWarning           = false;
    output.Reserve((view.GetLength() / 4) * 3);

    for (size_t i = 0; i < view.GetLength(); ++i) {
        const uint8 encoded = view[i];

        if (encoded == '\r' || encoded == '\n') {
            continue;
        }

        if (lastEncoded == '=' && sequenceIndex == 0) {
            hasWarning     = true;
            warningMessage = "Ignoring extra bytes after the end of buffer";
            break;
        }

        uint32 decoded;

        if (encoded == '=') {
            // padding
            decoded = 0;
            paddingCount++;
        } else {
            CHECK(encoded < BASE64_DECODE_TABLE_SIZE, false, "");
            const int8 value = BASE64_DECODE_TABLE[encoded];
            CHECK(value >= 0, false, "");
            decoded = static_cast<uint32>(value);
        }

        sequence |= decoded << (2 + (4 - sequenceIndex) * 6);
        sequenceIndex++;

        if (sequenceIndex % 4 == 0) {
            const uint8 bytes[] = { static_cast<uint8>(sequence >> 24), static_cast<uint8>(sequence >> 16), static_cast<uint8>(sequence >> 8) };
            output.Add(BufferView(bytes, sizeof(bytes)));

            sequence      = 0;
            sequenceIndex = 0;
        }

        lastEncoded = encoded;
    }

    // trim the trailing bytes
    CHECK(paddingCount < 3, false, "");
    output.Resize(output.GetLength() - paddingCount);

    return true;
}

bool Decode(BufferView view, Buffer& output)
{
    bool tempHasWarning;
    String tempWarningMessage;

    return Decode(view, output, tempHasWarning, tempWarningMessage);
}

} // namespace GView::Decoding::Base64
