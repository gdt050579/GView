#include "Internal.hpp"

namespace GView::App
{
using namespace AppCUI::Controls;

class PluginsThatMatches
{
    uint8 bitmapExtension[256];
    uint8 bitmapContent[ARRAY_LEN(bitmapExtension)];
    uint32 countExtensionMatches;
    uint32 countContentMatches;
    uint32 countTypePlugins;

  public:
    PluginsThatMatches(
          std::vector<GView::Type::Plugin>& typePlugins,
          AppCUI::Utils::BufferView buf,
          GView::Type::Matcher::TextParser& textParser,
          uint64 extensionHash)
    {
        ASSERT(typePlugins.size() <= sizeof(bitmapExtension) * 8, "Too many plugins (increase the internal buffer)");

        for (auto idx = 0U; idx < ARRAY_LEN(bitmapExtension); idx++)
        {
            bitmapExtension[idx] = 0;
            bitmapContent[idx]   = 0;
        }
        countExtensionMatches = 0;
        countContentMatches   = 0;
        countTypePlugins      = static_cast<uint32>(typePlugins.size());
        auto idx              = 0U;

        // check extension
        if (extensionHash != 0)
        {
            for (auto& pType : typePlugins)
            {
                if (pType.MatchExtension(extensionHash))
                {
                    if (pType.IsOfType(buf, textParser))
                    {
                        bitmapExtension[idx / 8] |= static_cast<uint8>(1 << (idx & 7));
                        countExtensionMatches++;
                    }
                }
                idx++;
            }
        }
        // check the content
        idx = 0;
        for (auto& pType : typePlugins)
        {
            if (pType.MatchContent(buf, textParser))
            {
                if (pType.IsOfType(buf, textParser))
                {
                    bitmapContent[idx / 8U] |= static_cast<uint8>(1U << (idx & 7U));
                    countExtensionMatches++;
                }
            }
            idx++;
        }
    }

    inline bool HasExtesionMatches() const
    {
        return countExtensionMatches > 0;
    }
    inline bool HasContentMatches() const
    {
        return countContentMatches > 0;
    }
    inline bool HasNoMatches() const
    {
        return (countExtensionMatches + countContentMatches) < countTypePlugins;
    }
    inline bool IsMatchByExtension(uint32 index) const
    {
        return (bitmapExtension[index / 8] & (1<<(index & 7U))) != 0;
    }
    inline bool IsMatchByContent(uint32 index) const
    {
        return (bitmapContent[index / 8] & (1<<(index & 7U))) != 0;
    }
    inline uint32 GetTypePluginsCount() const
    {
        return countTypePlugins;
    }
};

SelectTypeDialog::SelectTypeDialog(
      std::vector<GView::Type::Plugin>& typePlugins,
      AppCUI::Utils::BufferView buf,
      GView::Type::Matcher::TextParser& textParser,
      uint64 extensionHash)
    : Window("Select type", "d:c,w:80,h:24", WindowFlags::ProcessReturn)
{
    PluginsThatMatches pm(typePlugins, buf, textParser, extensionHash);
    auto lstView = Factory::ListView::Create(this, "x:1,y:1,w:40,h:18", { "n:Name,w:7,a:l", "n:Description,w:100,a:l" },ListViewFlags::SearchMode|ListViewFlags::HideColumns);
    if (pm.HasExtesionMatches())
    {
        lstView->AddItem("Matched by extension").SetType(ListViewItem::Type::Category);
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByExtension(idx))
            {
                auto& plg = typePlugins[idx];
                auto item = lstView->AddItem(plg.GetName());
                item.SetText(1, plg.GetDescription());
                item.SetType(ListViewItem::Type::Highlighted);
                item.SetData(static_cast<uint64>(idx));
            }
        }
    }
    if (pm.HasContentMatches())
    {
        lstView->AddItem("Matched by content").SetType(ListViewItem::Type::Category);
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByContent(idx))
            {
                auto& plg = typePlugins[idx];
                auto item = lstView->AddItem(plg.GetName());
                item.SetText(1, plg.GetDescription());
                item.SetType(ListViewItem::Type::Emphasized_1);
                item.SetData(static_cast<uint64>(idx));
            }
        }
    }
    if (pm.HasNoMatches())
    {
        lstView->AddItem("Not matched").SetType(ListViewItem::Type::Category);
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if ((pm.IsMatchByContent(idx) == false) && (pm.IsMatchByExtension(idx) == false))
            {
                auto& plg = typePlugins[idx];
                auto item = lstView->AddItem(plg.GetName());
                item.SetText(1, plg.GetDescription());
                item.SetType(ListViewItem::Type::GrayedOut);
                item.SetData(static_cast<uint64>(idx));
            }
        }
    }
    lstView->SetCurrentItem(lstView->GetItem(1));
}
bool SelectTypeDialog::OnEvent(Reference<Control> ctrl, Event eventType, int id)
{
    return Window::OnEvent(ctrl, eventType, id);
}
} // namespace GView::App