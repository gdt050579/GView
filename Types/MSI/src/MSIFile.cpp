// MSIFile.cpp
// Compact implementations for CFBHelper and MSIFile (minimal heuristics)

#include "msi.hpp"
#include <cstring>
#include <codecvt>
#include <locale>

using namespace GView::Type::MSI;

//
// --- CFBHelper (very small heuristic implementation) ---
//

CFBHelper::CFBHelper(const uint8_t* data, size_t size) : data_(data), size_(size)
{
}

bool CFBHelper::HasCFBSignature(const uint8_t* data, size_t size)
{
    if (size < 8 || data == nullptr)
        return false;
    const uint8_t sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    return (std::memcmp(data, sig, 8) == 0);
}

std::vector<std::string> CFBHelper::FindLikelyStreamNames() const
{
    std::vector<std::string> out;
    if (!data_ || size_ == 0)
        return out;

    // check for SummaryInformation (0x05 + ASCII) and Property (ASCII)
    std::string sum;
    sum.push_back(char(0x05));
    sum += "SummaryInformation";

    if (ContainsNameASCII("Property"))
        out.push_back("Property");
    if (ContainsNameASCII(sum))
        out.push_back(sum);
    // naive: add any ASCII occurrences of "SummaryInformation" or "Property"
    return out;
}

bool CFBHelper::ContainsNameASCII(const std::string& name) const
{
    if (name.empty() || !data_)
        return false;
    const char* raw = reinterpret_cast<const char*>(data_);
    size_t n        = size_;
    for (size_t i = 0; i + name.size() <= n; ++i) {
        if (std::memcmp(raw + i, name.data(), name.size()) == 0)
            return true;
    }
    return false;
}

bool CFBHelper::ContainsNameUTF16(const std::string& name) const
{
    if (name.empty() || !data_)
        return false;
    // build UTF-16LE bytes of name (no BOM)
    std::u16string u16;
    {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
        try {
            u16 = conv.from_bytes(name);
        } catch (...) {
            return false;
        }
    }
    std::vector<uint8_t> pattern;
    pattern.reserve(u16.size() * 2);
    for (char16_t c : u16) {
        pattern.push_back(static_cast<uint8_t>(c & 0xFF));
        pattern.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    // search pattern
    if (pattern.empty())
        return false;
    const uint8_t* raw = data_;
    for (size_t i = 0; i + pattern.size() <= size_; ++i) {
        if (std::memcmp(raw + i, pattern.data(), pattern.size()) == 0)
            return true;
    }
    return false;
}

//
// --- MSIFile implementation (minimal) ---
//

MSIFile::MSIFile() : valid_(false)
{
}

MSIFile::~MSIFile()
{
}

bool MSIFile::UpdateFromBuffer(const AppCUI::Utils::BufferView& buf)
{
    streams_.clear();
    metadata_.clear();
    valid_ = false;

    size_t len = buf.GetLength();
    if (len < 512)
        return false;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());

    // quick CFB check
    if (!CFBHelper::HasCFBSignature(data, len))
        return false;

    CFBHelper helper(data, len);

    // list likely streams (heuristic)
    streams_ = helper.FindLikelyStreamNames();

    // small heuristic metadata: look for Property names and simple ASCII values in buffer
    const std::vector<std::string> interesting = { "ProductName", "ProductVersion", "Manufacturer" };
    for (auto& k : interesting) {
        // ASCII search
        if (helper.ContainsNameASCII(k)) {
            // naive extraction: find occurrence and read following ASCII readable characters
            const char* raw = reinterpret_cast<const char*>(data);
            size_t n        = len;
            for (size_t i = 0; i + k.size() <= n; ++i) {
                if (std::memcmp(raw + i, k.c_str(), k.size()) == 0) {
                    size_t after = i + k.size();
                    while (after < n && (raw[after] == 0 || raw[after] == 1 || raw[after] == 0x1F))
                        after++;
                    std::string val;
                    size_t q = after;
                    while (q < n && raw[q] >= 0x20 && raw[q] < 0x7F && (q - after) < 200) {
                        val.push_back(raw[q]);
                        q++;
                    }
                    if (!val.empty()) {
                        metadata_[k] = val;
                        break;
                    }
                }
            }
        } else if (helper.ContainsNameUTF16(k)) {
            // best-effort: extract following UTF-16LE sequence
            const uint8_t* raw = data;
            size_t n           = len;
            // construct UTF-16 pattern
            std::u16string u16;
            {
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
                try {
                    u16 = conv.from_bytes(k);
                } catch (...) {
                    u16.clear();
                }
            }
            if (u16.empty())
                continue;
            std::vector<uint8_t> pat;
            for (char16_t c : u16) {
                pat.push_back(static_cast<uint8_t>(c & 0xFF));
                pat.push_back(static_cast<uint8_t>(c >> 8));
            }
            for (size_t i = 0; i + pat.size() <= n; ++i) {
                if (std::memcmp(raw + i, pat.data(), pat.size()) == 0) {
                    size_t after = i + pat.size();
                    // extract UTF-16LE string
                    std::u16string got;
                    size_t r = after;
                    while (r + 1 < n) {
                        uint16_t ch = raw[r] | (raw[r + 1] << 8);
                        if (ch == 0)
                            break;
                        if (ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D)
                            break;
                        got.push_back((char16_t) ch);
                        r += 2;
                        if (got.size() > 256)
                            break;
                    }
                    if (!got.empty()) {
                        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
                        try {
                            metadata_[k] = conv.to_bytes(got);
                        } catch (...) {
                            metadata_[k] = std::string();
                        }
                        break;
                    }
                }
            }
        }
    }

    // minimal success
    valid_ = true;
    return true;
}

bool MSIFile::IsValid() const
{
    return valid_;
}
const std::vector<std::string>& MSIFile::GetStreams() const
{
    return streams_;
}
const std::map<std::string, std::string>& MSIFile::GetMetadata() const
{
    return metadata_;
}

std::string_view MSIFile::GetTypeName()
{
    return "MSI";
}
void MSIFile::RunCommand(std::string_view)
{
}
bool MSIFile::UpdateKeys(KeyboardControlsInterface* /*interface*/)
{
    return true;
}

uint32 MSIFile::GetSelectionZonesCount()
{
    CHECK(selectionZoneInterface.IsValid(), 0, "");
    return selectionZoneInterface->GetSelectionZonesCount();
}

//TypeInterface::SelectionZone MSIFile::GetSelectionZone(uint32 index)
//{
//    static auto d = TypeInterface::SelectionZone{ 0, 0 };
//    CHECK(selectionZoneInterface.IsValid(), d, "");
//    CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");
//    return selectionZoneInterface->GetSelectionZone(index);
//}

GView::Utils::JsonBuilderInterface* MSIFile::GetSmartAssistantContext(const std::string_view&, std::string_view)
{
    return nullptr;
}
