#include "Internal.hpp"

//TODO: THIS WAS NOT TESTED!
void GView::Unpack::QuotedPrintable::Encode(BufferView view, Buffer& output)
{
    // Iterate over each character in the input buffer
    for (size_t i = 0; i < view.GetLength(); i++) {
        // Get the current character
        const char character = view[i];

        // Check if the character is printable
        if (character >= 33 && character <= 126) {
            // Write the character to the output buffer
            output.Add(string_view(&character, 1));
        } else {
            // Write the character to the output buffer
            output.Add(string_view("=", 1));

            // Convert the character to its hexadecimal representation
            char hex1 = (character >> 4) & 0xF;
            char hex2 = character & 0xF;

            // Convert the hexadecimal digits to their ASCII representation
            hex1 = (hex1 < 10) ? hex1 + '0' : hex1 - 10 + 'A';
            hex2 = (hex2 < 10) ? hex2 + '0' : hex2 - 10 + 'A';

            // Write the hexadecimal digits to the output buffer
            output.Add(string_view(&hex1, 1));
            output.Add(string_view(&hex2, 1));
        }
    }
}

//TODO: Consider more testing!
bool GView::Unpack::QuotedPrintable::Decode(BufferView view, Buffer& output)
{
    char temp_buffer[2] = {};
    // Iterate over each character in the input buffer
    for (size_t i = 0; i < view.GetLength(); i++) {
        // Check if the character is an encoded character
        if (view[i] == '=') {
            // Check if there are enough characters remaining for an encoded sequence
            if (i + 2 < view.GetLength()) {
                // Get the two hexadecimal digits following the '=' character
                const char hex1 = view[i + 1];
                const char hex2 = view[i + 2];

                if (hex1 == '2' && hex2 == 'E') {
                    temp_buffer[0] = '.';
                    output.Add(string_view(temp_buffer, 1));
                    i += 2;
                    continue;
                }
                if (hex1 == '\r' && hex2 == '\n') {
                    i += 2;
                    continue;
                }

                // Convert the hexadecimal digits to their decimal values
                int value = 0;
                if (hex1 >= '0' && hex1 <= '9') {
                    value += (hex1 - '0') * 16;
                } else if (hex1 >= 'A' && hex1 <= 'F') {
                    value += (hex1 - 'A' + 10) * 16;
                } else if (hex1 >= 'a' && hex1 <= 'f') {
                    value += (hex1 - 'a' + 10) * 16;
                }

                if (hex2 >= '0' && hex2 <= '9') {
                    value += hex2 - '0';
                } else if (hex2 >= 'A' && hex2 <= 'F') {
                    value += hex2 - 'A' + 10;
                } else if (hex2 >= 'a' && hex2 <= 'f') {
                    value += hex2 - 'a' + 10;
                }

                // Write the decoded character to the output buffer
                temp_buffer[0] = static_cast<char>(value);
                output.Add(string_view(temp_buffer, 1));

                // Skip the next two characters in the input buffer
                i += 2;
            } else {
                // If '=' is at the end of the line, it should be treated as a literal '='
                temp_buffer[0] = '=';
                output.Add(string_view(temp_buffer, 1));
            }
        } else {
            // Write the character to the output buffer
            temp_buffer[0] = view[i];
            output.Add(string_view(temp_buffer, 1));
        }
    }

    return true;
}
