#include "LNK.hpp"

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
        auto header = buf.GetObject<LNK::Header>(0);
        CHECK(header.IsValid(), false, "");
        CHECK(header->headerSize == LNK::SIGNATURE, false, "");
        CHECK(memcmp(header->classIdentifier, LNK::CLASS_IDENTIFIER, 16) == 0, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new LNK::LNKFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<LNK::LNKFile> lnk)
    {
        BufferViewer::Settings settings;

        auto offset = 0;
        settings.AddZone(offset, sizeof(LNK::Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        offset += sizeof(LNK::Header);

        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
        {
            settings.AddZone(
                  offset,
                  sizeof(lnk->linkTargetIDList.IDListSize) + lnk->linkTargetIDList.IDListSize,
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "LinkTargetIDList");
            offset += sizeof(lnk->linkTargetIDList.IDListSize) + lnk->linkTargetIDList.IDListSize;
        }

        const auto liStartOffset = offset;
        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
        {
            settings.AddZone(offset, lnk->locationInformation.size, ColorPair{ Color::DarkRed, Color::DarkBlue }, "LocationInformation");
            offset += lnk->locationInformation.size;
        }

        if (lnk->volumeInformation != nullptr)
        {
            settings.AddZone(
                  liStartOffset + lnk->locationInformation.volumeInformationOffset,
                  lnk->volumeInformation->size,
                  ColorPair{ Color::DarkGreen, Color::DarkBlue },
                  "Volume Information");
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto lnk = win->GetObject()->GetContentType<LNK::LNKFile>();
        lnk->Update();

        // add views
        CreateBufferView(win, lnk);

        // add panels
        win->AddPanel(Pointer<TabPage>(new LNK::Panels::Information(win->GetObject(), lnk)), true);
        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
        {
            win->AddPanel(Pointer<TabPage>(new LNK::Panels::LinkTargetIDList(win->GetObject(), lnk)), true);
        }

        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
        {
            win->AddPanel(Pointer<TabPage>(new LNK::Panels::LocationInformation(win->GetObject(), lnk)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]   = "hex:'4C 00 00 00'";
        sect["Extension"] = "lnk";
        sect["Priority"]  = 1;
    }
}
