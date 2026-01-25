// msi.cpp
// GView plugin wrapper for MSI (CFB) using portable parser in msi.hpp
// Implements Validate, CreateInstance, PopulateWindow, UpdateSettings
//
// Assumes msi.hpp provides a portable parser namespace MSI { CFBReader, MSIFile }.

#include "msi.hpp"   // portable parser produced earlier
#include "GView.hpp" // existing GView headers (as used in ico.cpp)

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

namespace GView
{
namespace Type
{
    namespace MSI
    {
        // wrapper type to be used by GView (TypeInterface)
        class MSIFile : public TypeInterface
        {
          public:
            bool isMsi{ false };

            // parsed results (kept in memory for panels)
            std::vector<std::string> streams;
            std::map<std::string, std::string> metadata;

            // selection zone interface for buffer viewer
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

            MSIFile() = default;
            virtual ~MSIFile()
            {
            }

            // Populate internal parsed data from the buffer (called from PopulateWindow)
            bool UpdateFromBuffer(const AppCUI::Utils::BufferView& buf)
            {
                streams.clear();
                metadata.clear();
                isMsi = false;

                const auto len = buf.GetLength();
                if (len < 512)
                    return false;

                const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());
                MSI::CFBReader reader(data, len);
                if (!reader.Parse())
                    return false;

                // list stream names
                streams = reader.ListStreamNames();

                // parse SummaryInformation stream if present
                std::string sumName;
                sumName.push_back(char(0x05));
                sumName += "SummaryInformation";
                auto sstream = reader.GetStream(sumName);
                if (sstream) {
                    MSI::MSIFile tmp(sstream->data.data(), sstream->data.size());
                    // We do not have a direct MSIFile::GetMetadata on the portable parser, but the
                    // helper ParseSummaryInformation exists in that implementation.
                    // To keep separation, we'll call a tiny local parser here using portable helper:
                    // We'll reuse a tiny instance: call MSI::MSIFile::GetMetadata if exists,
                    // otherwise directly parse property set using ParseSummaryInformation from the parser.
                    // For compatibility with the previously supplied parser, instantiate portable MSI::MSIFile:
                    // (the portable MSIFile earlier provided GetMetadata when constructed with whole file,
                    // but here we only have a summary stream; we'll call the portable parser's ParseSummaryInformation
                    // function if available — otherwise we treat the blob heuristically.)
                    // For safety, attempt to populate metadata using the portable parsing helper by constructing
                    // a full MSI::MSIFile from the whole buffer (if that exists).
                }

                // Try to use the full-file portable MSI::MSIFile to get metadata (portable MSI class expects whole file bytes)
                MSI::MSIFile portableFull(data, len);
                if (portableFull.IsValid()) {
                    auto map = portableFull.GetMetadata();
                    for (auto& kv : map)
                        metadata[kv.first] = kv.second;
                } else {
                    // fallback: if portableFull isn't valid, attempt direct SummaryInformation if available
                    auto sum = reader.GetStream(sumName);
                    if (sum) {
                        // the portable header provided ParseSummaryInformation in the MSIFile implementation
                        // but it's private there; instead we will construct a temporary portable MSI::MSIFile and call GetMetadata if possible.
                        MSI::MSIFile tmpFull(sum->data.data(), sum->data.size());
                        // tmpFull is likely invalid as a full MSI, but its GetMetadata may produce nothing.
                        // We'll instead perform a heuristic: call portable parser's CFB-based functions where appropriate.
                        // Simpler fallback: attempt heuristic property stream scanning
                    }
                }

                // As additional heuristic, try Property stream
                auto prop = reader.GetStream("Property");
                if (prop) {
                    // portableFull.GetMetadata should already include Property info; if not, attempt a lightweight heuristic:
                    // For simplicity, search for common property names and store values (same approach as earlier portable code)
                    // We'll implement a tiny inline heuristic here.
                    const std::vector<std::string> interesting = { "ProductName", "ProductVersion", "Manufacturer", "ProductCode", "PackageCode" };
                    const uint8_t* raw                         = prop->data.data();
                    size_t n                                   = prop->data.size();
                    for (auto& k : interesting) {
                        // search for ASCII occurrence
                        for (size_t i = 0; i + k.size() < n; ++i) {
                            if (memcmp(raw + i, k.c_str(), k.size()) == 0) {
                                // try simple ASCII extraction after the key
                                size_t after = i + k.size();
                                while (after < n && (raw[after] == 0 || raw[after] == 1 || raw[after] == 0x1F))
                                    after++;
                                std::string val;
                                size_t q = after;
                                while (q < n && raw[q] >= 0x20 && raw[q] < 0x7F && (q - after) < 200) {
                                    val.push_back(static_cast<char>(raw[q]));
                                    q++;
                                }
                                if (!val.empty()) {
                                    metadata[k] = val;
                                    break;
                                }
                                // try UTF-16LE
                                if (after + 2 < n) {
                                    std::u16string u;
                                    size_t r = after;
                                    while (r + 1 < n) {
                                        uint16_t ch = (uint16_t) raw[r] | (uint16_t(raw[r + 1]) << 8);
                                        if (ch == 0 || ch < 0x20 || ch > 0xD7FF)
                                            break;
                                        u.push_back((char16_t) ch);
                                        r += 2;
                                        if (u.size() > 200)
                                            break;
                                    }
                                    if (!u.empty()) {
                                        std::wstring_convert<std::codecvt_utf8utf16<char16_t>, char16_t> conv;
                                        try {
                                            metadata[k] = conv.to_bytes(u);
                                        } catch (...) {
                                            std::string tmp;
                                            for (char16_t c : u)
                                                tmp.push_back((char) (c & 0xFF));
                                            metadata[k] = tmp;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // finalize
                isMsi = true;
                return true;
            }

            // minimal stubs for TypeInterface
            std::string_view GetTypeName() override
            {
                return "MSI";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

            uint32 GetSelectionZonesCount() override
            {
                CHECK(selectionZoneInterface.IsValid(), 0, "");
                return selectionZoneInterface->GetSelectionZonesCount();
            }

            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

                return selectionZoneInterface->GetSelectionZone(index);
            }

            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override
            {
                return nullptr;
            }
        }; // class MSIFile

        // Helper to create a buffer view for MSI (header + content)
        void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MSIFile> msi)
        {
            BufferViewer::Settings settings;
            // header zone (first 512 bytes)
            settings.AddZone(0, 512, ColorPair{ Color::Magenta, Color::DarkBlue }, "CFB Header");

            // set selection zones interface
            msi->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
        }

        // Helper to create a simple Streams ListView viewer (no binary image viewer)
        void CreateStreamsPanel(Reference<GView::View::WindowInterface> win, Reference<MSIFile> msi)
        {
            // not used here; the Streams panel will be created in PopulateWindow below
            (void) win;
            (void) msi;
        }

    } // namespace MSI
} // namespace Type
} // namespace GView

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    // Basic validation:
    //  - at least header size
    //  - CFB signature present
    //  - parseable by portable CFB parser and contains at least one named stream commonly used by MSI (SummaryInformation or Property)

    if (buf.GetLength() < 512)
        return false;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.GetData());
    // CFB signature
    const uint8_t sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    if (memcmp(p, sig, 8) != 0)
        return false;

    // Try parsing CFB quickly
    MSI::CFBReader reader(p, buf.GetLength());
    if (!reader.Parse())
        return false;

    // look for typical MSI streams
    std::string sinfo;
    sinfo.push_back(char(0x05));
    sinfo += "SummaryInformation";
    bool hasSummary  = (reader.GetStream(sinfo).has_value());
    bool hasProperty = (reader.GetStream("Property").has_value());

    // Accept if at least one known stream present, or extension explicitly .msi
    if (hasSummary || hasProperty)
        return true;

    // fallback: accept based on extension hint
    if (!extension.empty()) {
        std::string ext(extension);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".msi")
            return true;
    }

    return false;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new MSI::MSIFile();
}

void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<GView::Type::MSI::MSIFile> msi)
{
    // Reuse the helper defined above
    GView::Type::MSI::CreateBufferView(win, msi);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto msi = win->GetObject()->GetContentType<GView::Type::MSI::MSIFile>();
    // parse buffer into wrapper object
    if (!msi->UpdateFromBuffer(win->GetObject()->GetBufferView())) {
        // nothing to show
        return false;
    }

    // add viewer
    CreateBufferView(win, msi);

    // add panels
    win->AddPanel(Pointer<TabPage>(new GView::Type::MSI::Panels::Information(msi)), true);
    win->AddPanel(Pointer<TabPage>(new GView::Type::MSI::Panels::Streams(msi, win)), true);

    // populate panels
    // GView will call Update on panels as necessary, but we can call them now for immediate content
    // find panels and call Update (optional)
    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"] = {
        "magic:D0 CF 11 E0 A1 B1 1A E1",
    };
    sect["Priority"]    = 1;
    sect["Description"] = "MSI Installer Package (*.msi) - Compound File Binary (CFB/OLE)";
}
} // extern "C"

int main()
{
    return 0;
}
