#include "LNK.hpp"

#include <array>

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
        CHECK(memcmp(&header->classIdentifier, LNK::CLASS_IDENTIFIER, sizeof(LNK::MyGUID)) == 0, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new LNK::LNKFile();
    }

    static constexpr auto MagentaDarkBlue = ColorPair{ Color::Magenta, Color::DarkBlue };
    static constexpr auto DarkGreenBlue   = ColorPair{ Color::DarkGreen, Color::DarkBlue };
    static constexpr auto DarkRedBlue     = ColorPair{ Color::DarkRed, Color::DarkBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<LNK::LNKFile> lnk)
    {
        BufferViewer::Settings settings;

        auto offset = 0ULL;
        settings.AddZone(offset, sizeof(LNK::Header), MagentaDarkBlue, "Header");
        offset += sizeof(LNK::Header);

        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasTargetIDList)
        {
            settings.AddZone(
                  offset, sizeof(lnk->linkTargetIDList.IDListSize) + lnk->linkTargetIDList.IDListSize, DarkGreenBlue, "LinkTargetIDList");
            offset += sizeof(lnk->linkTargetIDList.IDListSize) + lnk->linkTargetIDList.IDListSize;
        }

        const auto liStartOffset = offset;
        if (lnk->header.linkFlags & (uint32) LNK::LinkFlags::HasLinkInfo)
        {
            settings.AddZone(offset, lnk->locationInformation.size + 1ULL, DarkRedBlue, "LocationInformation");
            offset += lnk->locationInformation.size;
        }

        if (lnk->volumeInformation != nullptr)
        {
            settings.AddZone(
                  (uint64) liStartOffset + lnk->locationInformation.volumeInformationOffset,
                  lnk->volumeInformation->size,
                  DarkGreenBlue,
                  "Volume Information");
        }

        const bool isUnicode         = (lnk->header.linkFlags & (uint32) LNK::LinkFlags::IsUnicode);
        offset                       = lnk->dataStringsOffset;
        auto count                   = 0;
        constexpr static auto colors = std::array<ColorPair, 2>{ DarkGreenBlue, DarkRedBlue };
        for (const auto& [type, data] : lnk->dataStrings)
        {
            auto size = 0ULL;
            if (isUnicode)
            {
                std::u16string_view sv{ std::get<std::u16string_view>(data) };
                size = sv.size() * sizeof(char16);
            }
            else
            {
                std::string_view sv{ std::get<std::string_view>(data) };
                size = sv.size();
            }
            size += 2ULL;

            const auto& typeName = LNK::DataStringTypesNames.at(type);
            const auto& c        = *(colors.begin() + (count % 2));
            settings.AddZone(offset, size, c, typeName.data());
            offset += size;
            count++;
        }

        for (const auto& extraData : lnk->extraDataBases)
        {
            const auto& name = LNK::ExtraDataSignaturesNames.at(extraData->signature);
            const auto& c    = *(colors.begin() + (count % 2));
            settings.AddZone(offset, extraData->size, c, name.data());
            count++;
            offset += extraData->size;
        }

        if (lnk->obj->GetData().GetSize() == offset + 4) // terminal block
        {
            const auto& c = *(colors.begin() + (count % 2));
            settings.AddZone(offset, sizeof(uint32), c, "Terminal");
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

        if (lnk->extraDataBases.size() > 0)
        {
            win->AddPanel(Pointer<TabPage>(new LNK::Panels::ExtraData(win->GetObject(), lnk)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]     = "hex:'4C 00 00 00'";
        sect["Extension"]   = "lnk";
        sect["Priority"]    = 1;
        sect["Description"] = "Link / binary format file shortcuat for Windows OS (*.lnk)";
    }
}
