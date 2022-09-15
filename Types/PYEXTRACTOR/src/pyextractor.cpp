#include "pyextractor.hpp"

using namespace AppCUI;
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

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto py = win->GetObject()->GetContentType<PYEXTRACTOR::PYEXTRACTORFile>();
        py->Update();

        CreateBufferView(win, py);

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
