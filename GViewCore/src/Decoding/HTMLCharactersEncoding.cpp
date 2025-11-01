#include "Internal.hpp"

namespace GView::Decoding::HTMLCharactersEncoding
{
// HTML entity mappings for encoding
static const std::unordered_map<char, std::string> HTML_ENCODE_MAP = {
    { '&', "&amp;" },  { '<', "&lt;" },    { '>', "&gt;" },
    { '"', "&quot;" }, { '\'', "&apos;" }, { ' ', "&nbsp;" } // Optional: only include if you want to encode spaces
};

// HTML entity mappings for decoding (includes &nbsp; as regular space)
static const std::unordered_map<std::string, char> HTML_DECODE_MAP = {
    { "amp", '&' }, { "lt", '<' }, { "gt", '>' }, { "quot", '"' }, { "apos", '\'' }, { "nbsp", ' ' } // Treat &nbsp; as regular space
};

// Encode function
void Encode(BufferView view, Buffer& output)
{
    for (uint32 i = 0; i < view.GetLength(); ++i) {
        const char c = view[i];
        auto it      = HTML_ENCODE_MAP.find(c);
        if (it != HTML_ENCODE_MAP.end()) {
            output.Add(string_view(it->second));
        } else {
            output.Add(string_view(&c, 1));
        }
    }
}

// Decode function
bool Decode(BufferView view, Buffer& output)
{
    for (uint32 i = 0; i < view.GetLength(); ++i) {
        char c = view[i];

        if (c == '&') {
            size_t semiPos = i + 1;
            while (semiPos < view.GetLength() && view[semiPos] != ';' && semiPos - i <= 10) {
                semiPos++;
            }

            if (semiPos < view.GetLength() && view[semiPos] == ';') {
                std::string entity((char*)view.GetData() + i + 1, semiPos - i - 1);

                auto it = HTML_DECODE_MAP.find(entity);
                if (it != HTML_DECODE_MAP.end()) {
                    output.Add(string_view(&it->second, 1));
                    i = semiPos; // skip past ;
                    continue;
                }
            }
        }

        output.Add(string_view(&c, 1));
    }

    return output.GetLength() > 0;
}
} // namespace GView::Decoding::HTMLCharactersEncoding
