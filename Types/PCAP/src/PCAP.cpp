#include "PCAP.hpp"

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
        // CHECK(buf.GetLength() > sizeof(JOB::FIXDLEN_DATA), false, "");
        //
        // auto fixedLengthData = buf.GetObject<JOB::FIXDLEN_DATA>(0);
        // CHECK(fixedLengthData.IsValid(), false, "");
        //
        // CHECK(fixedLengthData->productVersion == JOB::ProductVersion::WindowsNT4Point0 ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::Windows2000 ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::WindowsXP ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::WindowsVista ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::Windows7 ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::Windows8 ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::Windows8Point1 ||
        //             fixedLengthData->productVersion == JOB::ProductVersion::Windows10,
        //       false,
        //       "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new PCAP::PCAPFile();
    }

    static constexpr auto MagentaDarkBlue = ColorPair{ Color::Magenta, Color::DarkBlue };
    static constexpr auto DarkGreenBlue   = ColorPair{ Color::DarkGreen, Color::DarkBlue };
    static constexpr auto DarkRedBlue     = ColorPair{ Color::DarkRed, Color::DarkBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PCAP::PCAPFile> pcap)
    {
        BufferViewer::Settings settings;

        auto offset = 0ULL;
        settings.AddZone(offset, sizeof(pcap->header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        offset += sizeof(pcap->header);

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pcap = win->GetObject()->GetContentType<PCAP::PCAPFile>();
        pcap->Update();

        // add views
        CreateBufferView(win, pcap);

        // add panels
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Information(win->GetObject(), pcap)), true);
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Packets(pcap, win)), false);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        // NG -> static const std::initializer_list<std::string> patterns{ "hex:'A1 B2 C3 D4'", "hex:'A1 B2 3C 4D'" };
        // NG -> sect["Pattern"]   = patterns;

        sect["Extension"] = "pcap"; // NG -> pcapng
        sect["Priority"]  = 1;
    }
}
