#include "Internal.hpp"

constexpr char BASE64_ENCODE_TABLE[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                         'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                         's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

constexpr char BASE64_DECODE_TABLE[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
                                         54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                                         10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                                         29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

namespace GView::Unpack::Base64
{

void Encode(BufferView view, Buffer& output)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;

    for (uint32 i = 0; i < view.GetLength(); ++i) {
        char decoded = view[i];

        sequence |= decoded << ((3 - sequenceIndex) * 8);
        sequenceIndex++;

        if (sequenceIndex % 3 == 0) {
            // get 4 encoded components out of this one
            // 0x3f -> 0b00111111
            char buffer[] = {
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

    output.AddMultipleTimes(string_view("=", 1), (3 - sequenceIndex) % 3);
}

bool Decode(BufferView view, Buffer& output)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;
    char lastEncoded     = 0;
    uint8 paddingCount   = 0;

    for (uint32 i = 0; i < view.GetLength(); ++i)
    {
        char encoded = view[i];
        CHECK(encoded < sizeof(BASE64_DECODE_TABLE) / sizeof(*BASE64_DECODE_TABLE), false, "");

        if (encoded == '\r' || encoded == '\n') {
            continue;
        }

        if (lastEncoded == '=' && sequenceIndex == 0) {
            AppCUI::Dialogs::MessageBox::ShowError("Warning!", "Ignoring extra bytes after the end of buffer");
            break;
        }

        uint32 decoded;

        if (encoded == '=') {
            // padding
            decoded = 0;
            paddingCount++;
        } else {
            decoded = BASE64_DECODE_TABLE[encoded];
            CHECK(decoded != -1, false, "");
        }

        sequence |= decoded << (2 + (4 - sequenceIndex) * 6);
        sequenceIndex++;

        if (sequenceIndex % 4 == 0) {
            char* buffer = (char*) &sequence;
            output.Add(string_view(buffer + 3, 1));
            output.Add(string_view(buffer + 2, 1));
            output.Add(string_view(buffer + 1, 1));

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
}
