#include "Internal.hpp"

namespace GView::Decoding::VBSEncoding
{

const std::string VBE_SIG_START     = "#@~^";
const std::string VBE_SIG_START_ALT = "==";
const std::string VBE_SIG_END       = "==^#~@";

const int VBE_PERM_IDX_SIZE     = 0x40;
const int VBE_PERM_TRIPLET_SIZE = 0x80;

const std::string permTripletTokens[VBE_PERM_TRIPLET_SIZE] = {
    "\x00\x00\x00", "\x01\x01\x01", "\x02\x02\x02", "\x03\x03\x03", "\x04\x04\x04", "\x05\x05\x05", "\x06\x06\x06", "\x07\x07\x07", "\x08\x08\x08",
    "\x57\x6E\x7B", "\x4A\x4C\x41", "\x0B\x0B\x0B", "\x0C\x0C\x0C", "\x4A\x4C\x41", "\x0E\x0E\x0E", "\x0F\x0F\x0F", "\x10\x10\x10", "\x11\x11\x11",
    "\x12\x12\x12", "\x13\x13\x13", "\x14\x14\x14", "\x15\x15\x15", "\x16\x16\x16", "\x17\x17\x17", "\x18\x18\x18", "\x19\x19\x19", "\x1A\x1A\x1A",
    "\x1B\x1B\x1B", "\x1C\x1C\x1C", "\x1D\x1D\x1D", "\x1E\x1E\x1E", "\x1F\x1F\x1F", "\x2E\x2D\x32", "\x47\x75\x30", "\x7A\x52\x21", "\x56\x60\x29",
    "\x42\x71\x5B", "\x6A\x5E\x38", "\x2F\x49\x33", "\x26\x5C\x3D", "\x49\x62\x58", "\x41\x7D\x3A", "\x34\x29\x35", "\x32\x36\x65", "\x5B\x20\x39",
    "\x76\x7C\x5C", "\x72\x7A\x56", "\x43\x7F\x73", "\x38\x6B\x66", "\x39\x63\x4E", "\x70\x33\x45", "\x45\x2B\x6B", "\x68\x68\x62", "\x71\x51\x59",
    "\x4F\x66\x78", "\x09\x76\x5E", "\x62\x31\x7D", "\x44\x64\x4A", "\x23\x54\x6D", "\x75\x43\x71", "\x4A\x4C\x41", "\x7E\x3A\x60", "\x4A\x4C\x41",
    "\x5E\x7E\x53", "\x40\x4C\x40", "\x77\x45\x42", "\x4A\x2C\x27", "\x61\x2A\x48", "\x5D\x74\x72", "\x22\x27\x75", "\x4B\x37\x31", "\x6F\x44\x37",
    "\x4E\x79\x4D", "\x3B\x59\x52", "\x4C\x2F\x22", "\x50\x6F\x54", "\x67\x26\x6A", "\x2A\x72\x47", "\x7D\x6A\x64", "\x74\x39\x2D", "\x54\x7B\x20",
    "\x2B\x3F\x7F", "\x2D\x38\x2E", "\x2C\x77\x4C", "\x30\x67\x5D", "\x6E\x53\x7E", "\x6B\x47\x6C", "\x66\x34\x6F", "\x35\x78\x79", "\x25\x5D\x74",
    "\x21\x30\x43", "\x64\x23\x26", "\x4D\x5A\x76", "\x52\x5B\x25", "\x63\x6C\x24", "\x3F\x48\x2B", "\x7B\x55\x28", "\x78\x70\x23", "\x29\x69\x41",
    "\x28\x2E\x34", "\x73\x4C\x09", "\x59\x21\x2A", "\x33\x24\x44", "\x7F\x4E\x3F", "\x6D\x50\x77", "\x55\x09\x3B", "\x53\x56\x55", "\x7C\x73\x69",
    "\x3A\x35\x61", "\x5F\x61\x63", "\x65\x4B\x50", "\x46\x58\x67", "\x58\x3B\x51", "\x31\x57\x49", "\x69\x22\x4F", "\x6C\x6D\x46", "\x5A\x4D\x68",
    "\x48\x25\x7C", "\x27\x28\x36", "\x5C\x46\x70", "\x3D\x4A\x6E", "\x24\x32\x7A", "\x79\x41\x2F", "\x37\x3D\x5F", "\x60\x5F\x4B", "\x51\x4F\x5A",
    "\x20\x42\x2C", "\x36\x65\x57"
};

const int permIdx[VBE_PERM_IDX_SIZE] = { 0, 1, 2, 0, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 0, 2, 1, 2, 2, 1,
                                         0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 2, 1, 0, 2, 1, 2, 0, 0, 1, 2, 2, 0, 0, 1, 2, 0, 2, 1 };


std::string Unescape(const std::string& encodedScript)
{
    std::string result = encodedScript;

    // Replace special character sequences
    const std::vector<std::pair<std::string, std::string>> replacements = { { "@*", ">" }, { "@!", "<" }, { "@$", "@" }, { "@&", "\n" }, { "@#", "\r" } };

    for (const auto& pair : replacements) {
        size_t pos = 0;
        while ((pos = result.find(pair.first, pos)) != std::string::npos) {
            result.replace(pos, pair.first.length(), pair.second);
            pos += pair.second.length();
        }
    }

    return result;
}

bool Unwrap(const std::string& wrappedScript, std::string& unwrappedScript)
{
    size_t tagBeginPos = wrappedScript.find(VBE_SIG_START);

    if (tagBeginPos != std::string::npos) {
        size_t endTagBegin = wrappedScript.find(VBE_SIG_START_ALT, tagBeginPos);

        if (endTagBegin != std::string::npos) {
            size_t startPosition = endTagBegin + VBE_SIG_START_ALT.length();
            std::string temp     = wrappedScript.substr(startPosition);

            size_t tagEnd = temp.find(VBE_SIG_END);

            if (tagEnd != std::string::npos) {
                unwrappedScript = temp.substr(0, tagEnd);
                return true;
            }
        }
    }

    // If we can't find the signature, just return the original script
    unwrappedScript = wrappedScript;
    return false;
}

std::string DecodeTokens(const std::string& encodedScript)
{
    std::string script = Unescape(encodedScript);
    std::string result(script.length(), ' ');

    int index = -1;

    for (size_t pos = 0; pos < script.length(); pos++) {
        unsigned char c = static_cast<unsigned char>(script[pos]);

        if (c < VBE_PERM_TRIPLET_SIZE) {
            index++;
        }

        if ((c == 9 || (c > 31 && c < 128)) && c != 60 && c != 62 && c != 64) {
            // Apply permutation
            int tripletIndex = c;
            int permIndex    = permIdx[index % VBE_PERM_IDX_SIZE];
            result[pos]      = permTripletTokens[tripletIndex][permIndex];
        } else {
            // Pass through unchanged
            result[pos] = c;
        }
    }

    return result;
}

void Encode(BufferView view, Buffer& output)
{
    { Report( AppCUI::Log::Severity::Warning, __FILE__, __FUNCTION__, "", __LINE__, "Current function/method is not implemented under current OS"); return; }
}

bool Decode(BufferView view, Buffer& output)
{
    try {
        // Convert buffer view to string for processing
        std::string input(reinterpret_cast<const char*>(view.GetData()), view.GetLength());

        // Unwrap the script first
        std::string unwrappedScript;
        Unwrap(input, unwrappedScript);

        // Decode the tokens
        std::string decodedScript = DecodeTokens(unwrappedScript);

        // Add the decoded data to output buffer
        output.Add(string_view(decodedScript.c_str(), decodedScript.length()));

        return true;
    } catch (...) {
        // In case of any error, try to recover and continue
        return false;
    }
}
} // namespace GView::Decoding::VBSEncoding