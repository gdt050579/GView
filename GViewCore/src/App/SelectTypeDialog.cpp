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
                        bitmapExtension[idx / 8] |= static_cast<uint8>(1 << (idx & 7U));
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
                    countContentMatches++;
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
        return (bitmapExtension[index / 8] & (1 << (index & 7U))) != 0;
    }
    inline bool IsMatchByContent(uint32 index) const
    {
        return (bitmapContent[index / 8] & (1 << (index & 7U))) != 0;
    }
    inline uint32 GetTypePluginsCount() const
    {
        return countTypePlugins;
    }
};
std::string_view BuildTypeName(String& output, GView::Type::Plugin& plg)
{
    output.Set(plg.GetName());
    output.AddChars(' ', 12);
    output.Truncate(12);
    output.Add(": ");
    output.Add(plg.GetDescription());
    return output.ToStringView();
}
SelectTypeDialog::SelectTypeDialog(
      std::vector<GView::Type::Plugin>& typePlugins,
      AppCUI::Utils::BufferView _buf,
      GView::Type::Matcher::TextParser& _textParser,
      uint64 extensionHash)
    : Window("Select type", "d:c,w:80,h:28", WindowFlags::ProcessReturn), buf(_buf), textParser(_textParser)
{
    PluginsThatMatches pm(typePlugins, buf, textParser, extensionHash);

    auto lbType = Factory::Label::Create(this, "&Type", "x:1,y:1,w:10");
    auto lbName = Factory::Label::Create(this, "&Name", "x:1,y:3,w:10");
    auto lbPath = Factory::Label::Create(this, "&Path", "x:1,y:5,w:10");
    auto lbView = Factory::Label::Create(this, "Pre&view", "x:1,y:7,w:10");
    auto cbType = Factory::ComboBox::Create(this, "l:12,t:1,r:1");
    auto txName = Factory::TextField::Create(this, "", "l:12,t:3,r:1", TextFieldFlags::Readonly);
    auto cbView = Factory::ComboBox::Create(this, "l:12,t:7,r:1", "Buffer,Hex");

    if (textParser.GetTextLength() > 0)
    {
        cbView->AddItem("Text");
        cbView->AddItem("Text with word wrap");
    }
    // auto rbHexView    = Factory::RadioBox::Create(this, "&Hex", "x:1,y:7,w:10", 123);
    // auto rbBufferView = Factory::RadioBox::Create(this, "&Buffer", "x:1,y:8,w:10", 123);
    // auto rbTextView   = Factory::RadioBox::Create(this, "&Text", "x:1,y:9,w:10", 123);

    canvas = Factory::CanvasViewer::Create(this, "l:1,t:8,r:1,b:3", 100, 100, ViewerFlags::Border);

    PaintBuffer();

    LocalString<128> tmp;

    if (pm.HasExtesionMatches())
    {
        cbType->AddSeparator("Matched by extension");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByExtension(idx))
            {
                auto item = cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]));
            }
        }
    }
    if (pm.HasContentMatches())
    {
        cbType->AddSeparator("Matched by content");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByContent(idx))
            {
                auto item = cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]));
            }
        }
    }
    if (pm.HasNoMatches())
    {
        cbType->AddSeparator("Not matched");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if ((pm.IsMatchByContent(idx) == false) && (pm.IsMatchByExtension(idx) == false))
            {
                auto item = cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]));
            }
        }
    }

    // auto sp      = Factory::Splitter::Create(this, "l:0,t:7,r:0,b:3", SplitterFlags::Vertical);
    // auto lstView = Factory::ListView::Create(
    //       sp, "d:c", { "n:Name,w:7,a:l", "n:Description,w:100,a:l" }, ListViewFlags::SearchMode | ListViewFlags::HideColumns);
    // auto tab = Factory::Tab::Create(sp, "d:c");
    // auto pgHex = Factory::TabPage::Create(tab, "&Hex view");
    // sp->SetFirstPanelSize(40);
    // if (pm.HasExtesionMatches())
    //{
    //     lstView->AddItem("Matched by extension").SetType(ListViewItem::Type::Category);
    //     for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
    //     {
    //         if (pm.IsMatchByExtension(idx))
    //         {
    //             auto& plg = typePlugins[idx];
    //             auto item = lstView->AddItem(plg.GetName());
    //             item.SetText(1, plg.GetDescription());
    //             item.SetType(ListViewItem::Type::Highlighted);
    //             item.SetData(static_cast<uint64>(idx));
    //         }
    //     }
    // }
    // if (pm.HasContentMatches())
    //{
    //     lstView->AddItem("Matched by content").SetType(ListViewItem::Type::Category);
    //     for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
    //     {
    //         if (pm.IsMatchByContent(idx))
    //         {
    //             auto& plg = typePlugins[idx];
    //             auto item = lstView->AddItem(plg.GetName());
    //             item.SetText(1, plg.GetDescription());
    //             item.SetType(ListViewItem::Type::Emphasized_1);
    //             item.SetData(static_cast<uint64>(idx));
    //         }
    //     }
    // }
    // if (pm.HasNoMatches())
    //{
    //     lstView->AddItem("Not matched").SetType(ListViewItem::Type::Category);
    //     for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
    //     {
    //         if ((pm.IsMatchByContent(idx) == false) && (pm.IsMatchByExtension(idx) == false))
    //         {
    //             auto& plg = typePlugins[idx];
    //             auto item = lstView->AddItem(plg.GetName());
    //             item.SetText(1, plg.GetDescription());
    //             item.SetType(ListViewItem::Type::GrayedOut);
    //             item.SetData(static_cast<uint64>(idx));
    //         }
    //     }
    // }
    // lstView->SetCurrentItem(lstView->GetItem(1));
}
void SelectTypeDialog::PaintHex()
{
    auto c   = canvas->GetCanvas();
    auto s   = buf.begin();
    auto e   = buf.end();
    auto x   = 0;
    auto y   = 0;
    auto cfg = this->GetConfig();

    LocalString<128> tmp;
    AppCUI::Graphics::CodePage cp(AppCUI::Graphics::CodePageID::DOS_437);
    c->Resize(74, std::max<>(18u, static_cast<uint32>((buf.GetLength() >> 4))), ' ', cfg->Text.Normal);
    c->Clear(' ', cfg->Text.Normal);
    while (s < e)
    {
        if (x == 0)
        {
            c->WriteSingleLineText(0, y, tmp.Format("%04X", y * 16), cfg->Text.Emphasized1);
        }
        c->WriteSingleLineText(x * 3 + 7, y, tmp.Format("%02X", *s), NoColorPair);
        c->WriteCharacter(x + 48 + 9, y, cp[*s], cfg->Text.Highlighted);
        x++;
        if (x == 16)
        {
            x = 0;
            y++;
        }
        s++;
    }
    c->DrawVerticalLine(4 * 3 + 6, 0, y, cfg->Text.Inactive, true);
    c->DrawVerticalLine(8 * 3 + 6, 0, y, cfg->Text.Inactive, true);
    c->DrawVerticalLine(12 * 3 + 6, 0, y, cfg->Text.Inactive, true);
}
void SelectTypeDialog::PaintBuffer()
{
    auto c   = canvas->GetCanvas();
    auto s   = buf.begin();
    auto e   = buf.end();
    auto x   = 0;
    auto y   = 0;
    auto cfg = this->GetConfig();

    LocalString<128> tmp;
    AppCUI::Graphics::CodePage cp(AppCUI::Graphics::CodePageID::DOS_437);
    // c->Clear(' ', cfg->Text.Normal);
    c->Resize(74, std::max<>(18u, static_cast<uint32>((1 + buf.GetLength() / 74))), ' ', cfg->Text.Normal);
    c->Clear(' ', cfg->Text.Normal);
    while (s < e)
    {
        auto ch = cp[*s];
        c->WriteCharacter(x, y, ch, cfg->Text.Normal);
        x++;
        if (x == 74)
        {
            x = 0;
            y++;
        }
        s++;
    }
}
void SelectTypeDialog::PaintText()
{
    auto c   = canvas->GetCanvas();
    auto s   = textParser.GetText();
    auto e   = s + textParser.GetTextLength();
    auto x   = 0;
    auto y   = 0;
    auto cfg = this->GetConfig();

    c->Resize(160, 200, ' ', cfg->Text.Normal);
    c->Clear(' ', cfg->Text.Normal);
    while (s < e)
    {
        switch (*s)
        {
        case '\n':
            x = 0;
            y++;
            s++;
            if ((s < e) && ((*s) == '\r'))
                s++;
            break;
        case '\r':
            x = 0;
            y++;
            s++;
            if ((s < e) && ((*s) == '\n'))
                s++;
            break;
        case '\t':
            x = ((x + 4) >> 2) << 2;
            s++;
            break;
        default:
            c->WriteCharacter(x, y, *s, cfg->Text.Normal);
            s++;
            x++;
            break;
        }
    }
}
bool SelectTypeDialog::OnEvent(Reference<Control> ctrl, Event eventType, int id)
{
    return Window::OnEvent(ctrl, eventType, id);
}
} // namespace GView::App