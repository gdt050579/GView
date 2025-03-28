#include "Internal.hpp"

namespace GView::Decoding::HexCharactersToAscii
{

void Encode(BufferView view, Buffer& output)
{
    constexpr char HEX_TABLE[] = "0123456789ABCDEF";

    for (uint32 i = 0; i < view.GetLength(); ++i) {
        const char c         = view[i];
        const char hexPair[] = { HEX_TABLE[(c >> 4) & 0x0F], HEX_TABLE[c & 0x0F] };
        output.Add(string_view(hexPair, 2));
    }
}

// Function to check if a character is a valid hex digit
inline bool IsValidHexChar(char c)
{
    return std::isxdigit(static_cast<unsigned char>(c));
}

// Function to decode Hex to ASCII
bool Decode(BufferView view, Buffer& output)
{
    // if (view.GetLength() % 2 != 0) {
    //     return false; // Hex string must have an even length
    // }

    for (uint32 i = 0; i < view.GetLength(); i += 2) {
        const char high = view[i];
        const char low  = view[i + 1];

        if (!IsValidHexChar(high) || !IsValidHexChar(low)) {
            return false; // Invalid hex character found
        }

        // Convert hex characters to a byte
        char byte = (std::stoi(std::string(1, high), nullptr, 16) << 4) | std::stoi(std::string(1, low), nullptr, 16);

        output.Add(string_view(&byte, 1));
    }

    return output.GetLength() > 0;
}

} // namespace GView::Decoding::HexCharactersToAscii
