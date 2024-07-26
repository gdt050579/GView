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

        const std::vector<ColorPair> colors = { ColorPair{ Color::Teal, Color::DarkBlue }, ColorPair{ Color::Yellow, Color::DarkBlue } };

        auto& data            = jpg->obj->GetData();
        const uint64 dataSize = data.GetSize();
        uint64 offset         = 0;
        uint32 colorIndex     = 0;
        uint32 segmentCount   = 1;

        settings.AddZone(0, sizeof(JPG::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "SOI Segment");
        offset += sizeof(JPG::Header);

        settings.AddZone(offset, sizeof(JPG::App0MarkerSegment), ColorPair{ Color::Olive, Color::DarkBlue }, "APP0 Segment");
        offset += sizeof(JPG::App0MarkerSegment);

        while (offset < dataSize - 2) {
            uint8 marker_prefix;
            uint8 marker_type;

            if (!data.Copy<uint8>(offset, marker_prefix) || marker_prefix != 0xFF) {
                break;
            }

            if (!data.Copy<uint8>(offset + 1, marker_type) || marker_type == 0x00 || marker_type == 0xFF) {
                offset++;
                continue;
            }

            if (marker_type == 0xD9) {
                settings.AddZone(offset, 2, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOI Segment");
                break;
            }

            uint16 length;
            if (!data.Copy<uint16>(offset + 2, length)) {
                offset++;
                continue;
            }

            length = Endian::BigToNative(length);
            uint16 segmentLength = length + 2;

            if (offset + segmentLength > data.GetSize()) {
                offset++;
                continue;
            }

            std::string label = "Marker " + std::to_string(segmentCount);
            settings.AddZone(offset, segmentLength, colors[colorIndex], label.c_str());
            offset += segmentLength;
            colorIndex = (colorIndex + 1) % colors.size();
            segmentCount++;

            if (marker_type == 0xDA) {
                if (offset + segmentLength < dataSize - 2) {
                    settings.AddZone(offset, dataSize - 2 - offset, ColorPair{ Color::Red, Color::DarkBlue }, "Compressed Data");
                    offset = dataSize - 2;
                }
                break;
            }
        }

        if (offset < dataSize - 2) {
            settings.AddZone(offset, dataSize - 2 - offset, ColorPair{ Color::Red, Color::DarkBlue }, "Compressed Data");
            offset = dataSize - 2;
        }

        if (offset < dataSize) {
            uint8 byte1, byte2;
            if (data.Copy<uint8>(offset, byte1) && data.Copy<uint8>(offset + 1, byte2)) {
                if ((byte2 << 8 | byte1) == 0xD9FF) {
                    settings.AddZone(offset, 2, ColorPair{ Color::Magenta, Color::DarkBlue }, "EOI Segment");
                }
            }
        }

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