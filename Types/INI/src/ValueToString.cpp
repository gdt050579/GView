#include "ini.hpp"

namespace GView::Type::INI::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;

constexpr int BUTTON_OK_ID     = 123;
constexpr int BUTTON_CANCEL_ID = 124;

class SelectValuesToConvertDialog : public Window
{
    Reference<CheckBox> cbText, cbNumbers, cbBools;

  public:
    SelectValuesToConvertDialog() : Window("Value to String", "d:c,w:70,h:10", WindowFlags::ProcessReturn)
    {
        cbText    = Factory::CheckBox::Create(this, "Convert &text values (name = john) into (name = \"john\")", "x:1,y:1,w:66");
        cbNumbers = Factory::CheckBox::Create(this, "Convert &numeric values (age = 20) into (age = \"29\")", "x:1,y:2,w:66");
        cbBools   = Factory::CheckBox::Create(this, "Convert &boolean values (valid = true) into (valid = \"true\")", "x:1,y:3,w:66");
        cbText->SetChecked(true);
        Factory::Button::Create(this, "&Run", "l:21,b:0,w:13", BUTTON_OK_ID);
        Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BUTTON_CANCEL_ID);
    }
    bool OnEvent(Reference<Controls::Control> control, Controls::Event eventType, int controlID) override
    {
        if ((eventType == Event::WindowAccept) || ((eventType == Event::ButtonClicked) && (controlID == BUTTON_OK_ID)))
        {
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
        if ((eventType == Event::WindowClose) || ((eventType == Event::ButtonClicked) && (controlID == BUTTON_CANCEL_ID)))
        {
            this->Exit(Dialogs::Result::Cancel);
            return true;
        }
        return false;
    }
    bool ShouldConvertTexts()
    {
        return cbText->IsChecked();
    }
    bool ShouldConvertNumbers()
    {
        return cbNumbers->IsChecked();
    }
    bool ShouldConvertBools()
    {
        return cbBools->IsChecked();
    }
};

std::string_view ValueToString::GetName()
{
    return "Values to string";
}
std::string_view ValueToString::GetDescription()
{
    return "Convert values to string format (e.g. name = John is converted in name = \"John\")";
}
bool ValueToString::CanBeAppliedOn(const PluginData& data)
{
    return true;
}
void ValueToString::ConvertToString(Token& tok, GView::View::LexicalViewer::PluginData& data)
{
    LocalUnicodeStringBuilder<256> temp;
    auto text             = tok.GetText();
    auto countSingleQuote = 0;
    auto countDoubleQuote = 0;
    for (auto ch : text)
    {
        if (ch == '"')
            countDoubleQuote++;
        if (ch == '\'')
            countSingleQuote++;
    }
    if (countDoubleQuote == 0)
    {
        temp.Set("\"");
        temp.Add(text);
        temp.Add("\"");
    }
    else
    {
        if (countSingleQuote == 0)
        {
            temp.Set("'");
            temp.Add(text);
            temp.Add("'");
        }
        else
        {
            temp.Set("\"\"\"");
            temp.Add(text);
            temp.Add("\"\"\"");
        }
    }
    auto start = tok.GetTokenStartOffset();
    auto end   = tok.GetTokenEndOffset();
    if ((start.has_value()) && (end.has_value()))
        data.editor.Replace(start.value(), end.value() - start.value(), temp);
}

PluginAfterActionRequest ValueToString::Execute(PluginData& data)
{
    SelectValuesToConvertDialog dlg;
    if (dlg.Show() != Dialogs::Result::Ok)
        return PluginAfterActionRequest::None;
    bool convertText    = dlg.ShouldConvertTexts();
    bool convertNumbers = dlg.ShouldConvertNumbers();
    bool convertBools   = dlg.ShouldConvertBools();

    if ((!convertText) && (!convertNumbers) && (!convertBools))
        return PluginAfterActionRequest::None;

    auto len = static_cast<int>(data.tokens.Len()) - 1;
    for (auto index = len; index >= 0; index--)
    {
        auto tok = data.tokens[index];
        if (tok.GetTypeID(TokenType::Invalid) != TokenType::Value)
            continue;
        auto dt = tok.GetDataType();
        if (((dt == TokenDataType::Boolean) && (convertBools)) || ((dt == TokenDataType::Number) && (convertNumbers)) ||
            ((dt == TokenDataType::None) && (convertText)))
            ConvertToString(tok, data);
    }
    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::INI::Plugins