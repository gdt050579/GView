#include "bmp.hpp"

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
        if (buf.GetLength() < sizeof(BMP::Header) + sizeof(BMP::InfoHeader))
            return false;
        auto header = buf.GetObject<BMP::Header>();
        if ((header->magic != BMP::BITMAP_WINDOWS_MAGIC))
            return false;
        // all good
        return true;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::DataCache> file)
    {
        return new BMP::BMPFile(file);
    }
    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<BMP::BMPFile> bmp)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(BMP::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        settings.AddZone(sizeof(BMP::Header), sizeof(BMP::InfoHeader), ColorPair{ Color::Olive, Color::DarkBlue }, "Image entries");

        win->CreateViewer("BufferView", settings);
    }
    void CreateImageView(Reference<GView::View::WindowInterface> win, Reference<BMP::BMPFile> bmp)
    {
        GView::View::ImageViewer::Settings settings;
        settings.SetLoadImageCallback(bmp.ToBase<View::ImageViewer::LoadImageInterface>());
        settings.AddImage(0, bmp->file->GetSize());
        win->CreateViewer("ImageView", settings);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto bmp = win->GetObject()->GetContentType<BMP::BMPFile>();
        bmp->Update();

        // add viewer
        CreateImageView(win, bmp);
        CreateBufferView(win, bmp);

        // add panels
        win->AddPanel(Pointer<TabPage>(new BMP::Panels::Information(bmp)), true);

        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]  = "BM";
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}
