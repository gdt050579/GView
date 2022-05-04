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
        settings.AddZone(offset, sizeof(job->fixedLengthData), ColorPair{ Color::Magenta, Color::DarkBlue }, "FIXDLEN_DATA");
        offset += sizeof(job->fixedLengthData);

        settings.AddZone(offset, sizeof(uint16), ColorPair{ Color::Green, Color::DarkBlue }, "Running Instance Count");
        offset += sizeof(uint16);

        auto size = job->applicationNameSize * sizeof(char16) + sizeof(job->applicationNameSize);
        settings.AddZone(offset, size, ColorPair{ Color::Aqua, Color::DarkBlue }, "Application Name");
        offset += size;

        size = job->parametersSize * sizeof(char16) + sizeof(job->parametersSize);
        settings.AddZone(offset, size, ColorPair{ Color::Red, Color::DarkBlue }, "Parameters");
        offset += size;

        size = job->workingDirectorySize * sizeof(char16) + sizeof(job->workingDirectorySize);
        settings.AddZone(offset, size, ColorPair{ Color::Magenta, Color::DarkBlue }, "Working Directory Size");
        offset += size;

        size = job->authorSize * sizeof(char16) + sizeof(job->authorSize);
        settings.AddZone(offset, size, ColorPair{ Color::Olive, Color::DarkBlue }, "Author");
        offset += size;

        size = job->commentSize * sizeof(char16) + sizeof(job->commentSize);
        settings.AddZone(offset, size, ColorPair{ Color::Silver, Color::DarkBlue }, "Comment");
        offset += size;

        settings.AddZone(
              offset,
              job->variableSizeDataSection.userData.GetLength() + sizeof(uint16),
              ColorPair{ Color::Green, Color::DarkBlue },
              "User Data");
        offset += job->variableSizeDataSection.userData.GetLength() + sizeof(uint16);

        settings.AddZone(
              offset,
              job->variableSizeDataSection.reservedData.size + sizeof(uint16),
              ColorPair{ Color::Aqua, Color::DarkBlue },
              "Reserved Data");
        offset += job->variableSizeDataSection.reservedData.size + sizeof(uint16);

        settings.AddZone(
              offset,
              job->variableSizeDataSection.triggers.count * sizeof(JOB::Trigger) + sizeof(job->variableSizeDataSection.triggers.count),
              ColorPair{ Color::Pink, Color::DarkBlue },
              "Triggers");
        offset += job->variableSizeDataSection.triggers.count * sizeof(JOB::Trigger) + sizeof(job->variableSizeDataSection.triggers.count);

        if (job->variableSizeDataSection.jobSignature.has_value())
        {
            settings.AddZone(offset, sizeof(JOB::JobSignature), ColorPair{ Color::Blue, Color::DarkBlue }, "Job Signature");
            offset += sizeof(JOB::JobSignature);
        }

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
