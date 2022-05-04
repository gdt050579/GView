#include "JOB.hpp"

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
        CHECK(buf.GetLength() > sizeof(JOB::FIXDLEN_DATA), false, "");

        auto fixedLengthData = buf.GetObject<JOB::FIXDLEN_DATA>(0);
        CHECK(fixedLengthData.IsValid(), false, "");

        CHECK(fixedLengthData->productVersion == JOB::ProductVersion::WindowsNT4Point0 ||
                    fixedLengthData->productVersion == JOB::ProductVersion::Windows2000 ||
                    fixedLengthData->productVersion == JOB::ProductVersion::WindowsXP ||
                    fixedLengthData->productVersion == JOB::ProductVersion::WindowsVista ||
                    fixedLengthData->productVersion == JOB::ProductVersion::Windows7 ||
                    fixedLengthData->productVersion == JOB::ProductVersion::Windows8 ||
                    fixedLengthData->productVersion == JOB::ProductVersion::Windows8Point1 ||
                    fixedLengthData->productVersion == JOB::ProductVersion::Windows10,
              false,
              "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new JOB::JOBFile();
    }

    static constexpr auto MagentaDarkBlue = ColorPair{ Color::Magenta, Color::DarkBlue };
    static constexpr auto DarkGreenBlue   = ColorPair{ Color::DarkGreen, Color::DarkBlue };
    static constexpr auto DarkRedBlue     = ColorPair{ Color::DarkRed, Color::DarkBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<JOB::JOBFile> job)
    {
        BufferViewer::Settings settings;

        auto offset = 0ULL;
        settings.AddZone(offset, sizeof(job->fixedLengthData), ColorPair{ Color::DarkGreen, Color::DarkBlue }, "FIXDLEN_DATA");
        offset += sizeof(job->fixedLengthData);

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto lnk = win->GetObject()->GetContentType<JOB::JOBFile>();
        lnk->Update();

        // add views
        CreateBufferView(win, lnk);

        // add panels
        win->AddPanel(Pointer<TabPage>(new JOB::Panels::Information(win->GetObject(), lnk)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        // sect["Pattern"]   = "hex:'4C 00 00 00'";
        sect["Extension"] = "job";
        sect["Priority"]  = 1;
    }
}
