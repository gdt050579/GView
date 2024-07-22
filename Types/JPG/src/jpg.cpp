#include "jpg.hpp"

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
    if (buf.GetLength() < sizeof(JPG::Header) + sizeof(JPG::App0MarkerSegment))
        return false;
    auto header = buf.GetObject<JPG::Header>();
    if (header->soi != JPG::JPG_SOI_MARKER || header->app0 != JPG::JPG_APP0_MARKER)
        return false;
    auto app0MarkerSegment = buf.GetObject<JPG::App0MarkerSegment>(sizeof(JPG::Header));
    if (memcmp(app0MarkerSegment->identifier, "JFIF", 5) != 0)
        return false;
    // all good
    return true;
}

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new JPG::JPGFile;
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<JPG::JPGFile> jpg)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(JPG::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        settings.AddZone(sizeof(JPG::Header), sizeof(JPG::App0MarkerSegment), ColorPair{ Color::Olive, Color::DarkBlue }, "APP0 Marker Segment");

        jpg->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    void CreateImageView(Reference<GView::View::WindowInterface> win, Reference<JPG::JPGFile> jpg)
    {
        GView::View::ImageViewer::Settings settings;
        settings.SetLoadImageCallback(jpg.ToBase<View::ImageViewer::LoadImageInterface>());
        settings.AddImage(0, jpg->obj->GetData().GetSize());
        win->CreateViewer(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto jpg = win->GetObject()->GetContentType<JPG::JPGFile>();
        jpg->Update();

        // add viewer
        CreateImageView(win, jpg);
        CreateBufferView(win, jpg);

        // add panels
        win->AddPanel(Pointer<TabPage>(new JPG::Panels::Information(jpg)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]     = "magic:FF D8";
        sect["Priority"]    = 1;
        sect["Description"] = "JPEG image file (*.jpg, *.jpeg)";
    }
}

int main()
{
    return 0;
}