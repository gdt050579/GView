#include "ico.hpp"

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
        if (buf.GetLength() < sizeof(ICO::Header) + sizeof(ICO::IconDirectoryEntry))
            return false;
        auto ic = buf.GetObject<ICO::Header>();
        if ((ic->magic != ICO::MAGIC_FORMAT_ICO) && (ic->magic != ICO::MAGIC_FORMAT_CUR))
            return false;
        if (ic->count == 0)
            return false; // at least one component needs to be present
        // all good
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new ICO::ICOFile();
    }
    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<ICO::ICOFile> ico)
    {
        BufferViewer::Settings settings;
        LocalString<128> tempStr;

        settings.AddZone(0, sizeof(ICO::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        settings.AddZone(
              sizeof(ICO::Header),
              sizeof(ICO::DirectoryEntry) * ico->dirs.size(),
              ColorPair{ Color::Olive, Color::DarkBlue },
              "Image entries");

        uint8 idx = 1;
        for (auto& e : ico->dirs)
        {
            settings.AddZone(e.cursor.offset, e.cursor.size, ColorPair{ Color::Silver, Color::DarkBlue }, tempStr.Format("Img #%d", idx));
            if (idx < 10)
                settings.AddBookmark(idx, e.cursor.offset);
            idx++;
        }

        ico->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }
    void CreateImageView(Reference<GView::View::WindowInterface> win, Reference<ICO::ICOFile> ico)
    {
        GView::View::ImageViewer::Settings settings;
        settings.SetLoadImageCallback(ico.ToBase<View::ImageViewer::LoadImageInterface>());

        for (uint32 idx = 0; idx < ico->dirs.size(); idx++)
        {
            settings.AddImage(ico->dirs[idx].ico.offset, ico->dirs[idx].ico.size);
        }

        win->CreateViewer(settings);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto ico = win->GetObject()->GetContentType<ICO::ICOFile>();
        ico->Update();

        // add viewer
        CreateImageView(win, ico);
        CreateBufferView(win, ico);

        // add panels
        win->AddPanel(Pointer<TabPage>(new ICO::Panels::Information(ico)), true);
        win->AddPanel(Pointer<TabPage>(new ICO::Panels::Directories(ico, win)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"] = {
            "magic:00 00 01 00",
            "magic:00 00 02 00",
        };
        sect["Priority"]    = 1;
        sect["Description"] = "Icon/Cursor image file (*.ico, *.cur)";
    }
}

int main()
{
    return 0;
}
