#include "pyextractor.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr string_view IPYEXTRACTOR_ICON = "................"  // 1
                                          "................"  // 2
                                          "................"  // 3
                                          "................"  // 4
                                          "WWWWWW..WW....WW"  // 5
                                          "WW..WW...WW..WW."  // 6
                                          "WW..WW....WWWW.."  // 7
                                          "WW.WWW.....WW..."  // 8
                                          "WW.........WW..."  // 9
                                          "WW.........WW..."  // 10
                                          "WW.........WW..."  // 11
                                          "................"  // 12
                                          "................"  // 13
                                          "................"  // 14
                                          "................"  // 15
                                          "................"; // 16

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        CHECK(buf.GetLength() > sizeof(uint16), false, "");
        auto magic = static_cast<PYEXTRACTOR::Magic>(*reinterpret_cast<uint16*>(const_cast<uint8*>(buf.GetData())));
        CHECK(magic == PYEXTRACTOR::Magic::NoCompression || magic == PYEXTRACTOR::Magic::DefaultCompression ||
                    magic == PYEXTRACTOR::Magic::BestCompression,
              false,
              "");
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new PYEXTRACTOR::PYEXTRACTORFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PYEXTRACTOR::PYEXTRACTORFile> py)
    {
        BufferViewer::Settings settings;
        win->CreateViewer("BufferView", settings);
    }

    void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<PYEXTRACTOR::PYEXTRACTORFile> py)
    {
        ContainerViewer::Settings settings;

        settings.SetIcon(IPYEXTRACTOR_ICON);
        settings.SetColumns({
              "n:&Name,a:l,w:80",
              "n:&Size,a:r,w:20",
              "n:&Created,a:r,w:25",
              "n:&OffsetInFile,a:r,w:20",
              "n:&Flags,a:r,w:25",
        });

        settings.SetEnumerateCallback(
              win->GetObject()->GetContentType<PYEXTRACTOR::PYEXTRACTORFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
        settings.SetOpenItemCallback(
              win->GetObject()->GetContentType<PYEXTRACTOR::PYEXTRACTORFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

        win->CreateViewer("ContainerView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto py = win->GetObject()->GetContentType<PYEXTRACTOR::PYEXTRACTORFile>();
        py->Update();

        CreateBufferView(win, py);
        CreateContainerView(win, py);

        if (py->HasPanel(PYEXTRACTOR::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new PYEXTRACTOR::Panels::Information(win->GetObject(), py)), true);
        }

        if (py->HasPanel(PYEXTRACTOR::Panels::IDs::TOCEntries))
        {
            win->AddPanel(Pointer<TabPage>(new PYEXTRACTOR::Panels::TOCEntries(py, win)), false);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> list{ "hex:'78 01'", "hex:'78 9C'", "hex:'78 DA'" };
        sect["Pattern"]  = list;
        sect["Priority"] = 1;
    }
}
