#include "JT.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        CHECK(buf.GetLength() > sizeof(JT::FileHeader), false, "");

        auto fileHeader = buf.GetObject<JT::FileHeader>(0);
        CHECK(fileHeader.IsValid(), false, "");

        CHECK(memcmp(fileHeader->version, "Version", 7) == 0, false, "");
        CHECK(memcmp(fileHeader->version + 75, " \n\r\n ", 5) == 0, false, "");
        CHECK(fileHeader->byteOrder == 0 || fileHeader->byteOrder == 1, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new JT::JTFile();
    }

    static constexpr auto MagentaDarkBlue = ColorPair{ Color::Magenta, Color::DarkBlue };
    static constexpr auto DarkGreenBlue   = ColorPair{ Color::DarkGreen, Color::DarkBlue };

    static constexpr auto AquaBlue = ColorPair{ Color::Aqua, Color::DarkBlue };
    static constexpr auto TealBlue = ColorPair{ Color::Yellow, Color::DarkBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<JT::JTFile> jt)
    {
        BufferViewer::Settings settings;

        auto offset = 0ULL;
        settings.AddZone(offset, sizeof(jt->fh), MagentaDarkBlue, "FileHeader");
        offset += jt->fh.tocOffset;

        settings.AddZone(offset, sizeof(jt->tc.entryCount) + jt->tc.entries.size() * sizeof(JT::TOCEntry), DarkGreenBlue, "TOC");
        offset += sizeof(jt->tc) + jt->tc.entries.size() * sizeof(JT::TOCEntry);

        LocalString<1024> ls;
        auto i            = 0U;
        const auto colors = { AquaBlue, TealBlue };

        // ofc this is not fast
        auto entriesCopy = jt->tc.entries;
        std::sort(
              entriesCopy.begin(),
              entriesCopy.end(),
              [](const JT::TOCEntry& e1, const JT::TOCEntry& e2) { return e1.segmentOffset < e2.segmentOffset; });

        for (const auto& e : entriesCopy)
        {
            const auto iFound = std::abs(std::distance(std::find(jt->tc.entries.begin(), jt->tc.entries.end(), e), jt->tc.entries.begin()));
            settings.AddZone(e.segmentOffset, e.segmentLength, *(colors.begin() + (i % 2)), ls.Format("(#%u) Data Entry", iFound));
            i++;
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto lnk = win->GetObject()->GetContentType<JT::JTFile>();
        lnk->Update();

        // add views
        CreateBufferView(win, lnk);

        // add panels
        win->AddPanel(Pointer<TabPage>(new JT::Panels::Information(win->GetObject(), lnk)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        // sect["Pattern"]   = "hex:'4C 00 00 00'";
        sect["Extension"] = "jlwf";
        sect["Priority"]  = 1;
    }
}
