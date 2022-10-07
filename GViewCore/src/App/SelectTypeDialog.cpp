#include "Internal.hpp"

namespace GView::App
{
using namespace AppCUI::Controls;
constexpr int BTN_COMMAND_OK          = 12345;
constexpr int BTN_COMMAND_CANCEL      = 12346;
constexpr uint32 INVALID_TYPE_INDEX   = 0xFFFFFFFF;
constexpr uint32 DEFAULT_PLUGIN_INDEX = 0xFFFFFF;
namespace PreviewMode
{
    constexpr uint64 Buffer      = 100;
    constexpr uint64 Hex         = 101;
    constexpr uint64 Text        = 102;
    constexpr uint64 TextWrapped = 103;
} // namespace PreviewMode

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
    output.AddChars(' ', 8);
    output.Truncate(8);
    output.Add(": ");
    output.Add(plg.GetDescription());
    return output.ToStringView();
}

SelectTypeDialog::SelectTypeDialog(
      const AppCUI::Utils::ConstString& name,
      const AppCUI::Utils::ConstString& path,
      uint64 dataSize,
      std::vector<GView::Type::Plugin>& _typePlugins,
      AppCUI::Utils::BufferView _buf,
      GView::Type::Matcher::TextParser& _textParser,
      uint64 extensionHash)
    : Window("Select type", "d:c,w:80,h:28", WindowFlags::ProcessReturn), typePlugins(_typePlugins), buf(_buf), textParser(_textParser),
      result(nullptr), shouldUseDefaultPlugin(false)
{
    NumericFormatter num;
    NumericFormat numFormat(NumericFormatFlags::None, 10, 3, ',');
    auto lbType    = Factory::Label::Create(this, "&Type", "x:1,y:1,w:10");
    auto lbName    = Factory::Label::Create(this, "&Name", "x:1,y:3,w:10");
    auto lbSize    = Factory::Label::Create(this, "&Size", "x:50,y:3,w:10");
    auto lbPath    = Factory::Label::Create(this, "&Path", "x:1,y:5,w:10");
    auto lbView    = Factory::Label::Create(this, "Pre&view", "x:1,y:7,w:10");
    cbType         = Factory::ComboBox::Create(this, "l:12,t:1,r:1");
    auto txName    = Factory::TextField::Create(this, name, "x:12,y:3,w:33", TextFieldFlags::Readonly);
    auto txSize    = Factory::TextField::Create(this, num.ToString(dataSize, numFormat), "l:56,t:3,r:1", TextFieldFlags::Readonly);
    auto txPath    = Factory::TextField::Create(this, path, "l:12,t:5,r:1", TextFieldFlags::Readonly);
    cbView         = Factory::ComboBox::Create(this, "l:12,t:7,r:1");
    canvas         = Factory::CanvasViewer::Create(this, "l:1,t:8,r:1,b:3", 100, 100, ViewerFlags::Border);
    auto btnOK     = Factory::Button::Create(this, "&Ok", "b:0,l:22,w:15", BTN_COMMAND_OK);
    auto btnCancel = Factory::Button::Create(this, "&Cancel", "b:0,l:41,w:15", BTN_COMMAND_CANCEL);
    // hot keys
    cbView->SetHotKey('V');
    cbType->SetHotKey('T');
    txPath->SetHotKey('P');
    txSize->SetHotKey('S');
    txName->SetHotKey('N');

    PopulateViewModes();
    PopulateTypes(typePlugins, buf, textParser, extensionHash);

    btnOK->SetFocus();
}
void SelectTypeDialog::PopulateTypes(
      std::vector<GView::Type::Plugin>& typePlugins,
      AppCUI::Utils::BufferView buf,
      GView::Type::Matcher::TextParser& textParser,
      uint64 extensionHash)
{
    PluginsThatMatches pm(typePlugins, buf, textParser, extensionHash);
    LocalString<128> tmp;

    if (pm.HasExtesionMatches())
    {
        cbType->AddSeparator("Matched by extension");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByExtension(idx))
                cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]), idx);
        }
    }
    if (pm.HasContentMatches())
    {
        cbType->AddSeparator("Matched by content");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if (pm.IsMatchByContent(idx))
                cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]), idx);
        }
    }
    {
        cbType->AddSeparator("Defaults");
        cbType->AddItem("Unknown type (Buffer or Text)", DEFAULT_PLUGIN_INDEX);
    }
    if (pm.HasNoMatches())
    {
        cbType->AddSeparator("Not matched");
        for (auto idx = 0U; idx < pm.GetTypePluginsCount(); idx++)
        {
            if ((pm.IsMatchByContent(idx) == false) && (pm.IsMatchByExtension(idx) == false))
                cbType->AddItem(BuildTypeName(tmp, typePlugins[idx]), idx);
        }
    }
}
void SelectTypeDialog::PopulateViewModes()
{
    auto defaultViewMode = PreviewMode::Buffer;
    if (textParser.GetTextLength() > 0)
    {
        cbView->AddSeparator("Binary view");
        cbView->AddItem("Buffer view", PreviewMode::Buffer);
        cbView->AddItem("Hex vew", PreviewMode::Hex);
        cbView->AddSeparator("Text view");
        cbView->AddItem("Text view", PreviewMode::Text);
        cbView->AddItem("Text view (with line wrapping)", PreviewMode::TextWrapped);

        // check if the text requires wrap or not
        auto* p         = textParser.GetText();
        auto* e         = p + textParser.GetTextLength();
        auto nrLines    = 0U;
        auto lineLength = 0U;
        auto largeLines = 0U;
        while (p < e)
        {
            if (((*p) == '\n') || ((*p) == '\r'))
            {
                if (lineLength > 100)
                    largeLines++;
                nrLines++;
                if ((p + 1 < e) && (((p[1]) == '\n') || ((p[1]) == '\r')) && (p[0] != p[1]))
                    p++;
                p++;
                lineLength = 0;
                continue;
            }
            lineLength++;
            p++;
        }
        defaultViewMode = largeLines > 5 ? PreviewMode::TextWrapped : PreviewMode::Text;
    }
    else
    {
        cbView->AddItem("Buffer view", PreviewMode::Buffer);
        cbView->AddItem("Hex vew", PreviewMode::Hex);
    }
    // search for the appropiate view mode
    auto cnt = cbView->GetItemsCount();
    for (auto idx = 0U; idx < cnt; idx++)
    {
        if (cbView->GetItemUserData(idx, 0) == defaultViewMode)
        {
            cbView->SetCurentItemIndex(idx);
            UpdateView(defaultViewMode);
            return;
        }
    }
}
void SelectTypeDialog::UpdateView(uint64 mode)
{
    switch (mode)
    {
    case PreviewMode::Buffer:
        PaintBuffer();
        break;
    case PreviewMode::Hex:
        PaintHex();
        break;
    case PreviewMode::Text:
        PaintText(false);
        break;
    case PreviewMode::TextWrapped:
        PaintText(true);
        break;
    }
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
void SelectTypeDialog::PaintText(bool wrap)
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
            if ((x > 74) && (wrap))
            {
                x = 0;
                y++;
            }
            break;
        }
    }
}
void SelectTypeDialog::Validate()
{
    auto idx               = cbType->GetCurrentItemUserData(INVALID_TYPE_INDEX);
    result                 = nullptr;
    shouldUseDefaultPlugin = false;

    if (idx == INVALID_TYPE_INDEX)
        return;
    if (idx == DEFAULT_PLUGIN_INDEX)
    {
        shouldUseDefaultPlugin = true;
        Exit(Dialogs::Result::Ok);
        return;
    }
    auto* plg = &typePlugins[idx];
    if (plg->IsOfType(buf, textParser) == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Selected plugin can not process/match current buffer/text !");
        return;
    }
    result = plg;
    Exit(Dialogs::Result::Ok);
}
bool SelectTypeDialog::OnEvent(Reference<Control> ctrl, Event eventType, int id)
{
    switch (eventType)
    {
    case Event::ComboBoxSelectedItemChanged:
        if (ctrl == cbView)
            UpdateView(cbView->GetCurrentItemUserData(0));
        return true;
    case Event::ButtonClicked:
        if (id == BTN_COMMAND_OK)
        {
            Validate();
            return true;
        }
        if (id == BTN_COMMAND_CANCEL)
        {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return true;
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }
    return false;
}
} // namespace GView::App