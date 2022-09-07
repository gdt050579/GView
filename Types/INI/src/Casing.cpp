#include "ini.hpp"

namespace GView::Type::INI::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;

constexpr int BUTTON_OK_ID     = 123;
constexpr int BUTTON_CANCEL_ID = 124;

inline bool IsChar(char16 ch)
{
    if ((ch >= 'A') && (ch <= 'Z'))
        return true;
    if ((ch >= 'a') && (ch <= 'z'))
        return true;
    if ((ch >= '0') && (ch <= '9'))
        return true;
    if ((ch == '_') || (ch > 128))
        return true;
    return false;
}

class SelectCaseDialog : public Window
{
    Reference<ComboBox> comboSections, comboKeys;

  public:
    SelectCaseDialog() : Window("Case-ing", "d:c,w:70,h:10", WindowFlags::ProcessReturn)
    {
        Factory::Label::Create(this, "&Sections", "x:1,y:1,w:10");
        Factory::Label::Create(this, "&Keys", "x:1,y:3,w:10");
        comboSections = Factory::ComboBox::Create(
              this, "x:15,y:1,w:52", "Do nothing,Upper case (ABC.ABC),Lower case (abc.abc), Sentence case (Abc.abc), Title case (Abc.Abc)");
        comboSections->SetCurentItemIndex(0);
        comboSections->SetHotKey('S');
        comboKeys = Factory::ComboBox::Create(
              this, "x:15,y:3,w:52", "Do nothing,Upper case (ABC.ABC),Lower case (abc.abc), Sentence case (Abc.abc), Title case (Abc.Abc)");
        comboKeys->SetCurentItemIndex(0);
        comboKeys->SetHotKey('K');
        Factory::Button::Create(this, "&Run", "l:21,b:0,w:13", BUTTON_OK_ID);
        Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BUTTON_CANCEL_ID);
        comboSections->SetFocus();
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
    CaseFormat GetCaseFormatForSections()
    {
        return static_cast<CaseFormat>(comboSections->GetCurrentItemIndex());
    }
    CaseFormat GetCaseFormatForKeys()
    {
        return static_cast<CaseFormat>(comboKeys->GetCurrentItemIndex());
    }
};

std::string_view Casing::GetName()
{
    return "Change case-ing";
}
std::string_view Casing::GetDescription()
{
    return "Change case-ing for keys and sections (upper, lower, sentence, title)";
}
bool Casing::CanBeAppliedOn(const PluginData& data)
{
    return true;
}
void Casing::ChangeCaseForToken(Token& tok, CaseFormat format, bool isSection)
{
    LocalUnicodeStringBuilder<256> temp;
    auto text  = tok.GetText();
    auto index = 0U;
    auto sz    = static_cast<uint32>(text.length());
    bool first = true;

    for (; index < sz; index++)
    {
        auto ch = text[index];
        switch (format)
        {
        case CaseFormat::LowerCase:
            if ((ch >= 'A') && (ch <= 'Z'))
                ch |= 0x20;
            break;
        case CaseFormat::UpperCase:
            if ((ch >= 'a') && (ch <= 'z'))
                ch -= 0x20;
            break;
        case CaseFormat::SentenceCase:
            if (IsChar(ch))
            {
                if ((first) && (ch >= 'a') && (ch <= 'z'))
                    ch -= 0x20;
                else if ((!first) && (ch >= 'A') && (ch <= 'Z'))
                    ch |= 0x20;
                first = false;
            }
            break;
        case CaseFormat::TitleCase:
            if (IsChar(ch))
            {
                if ((first) && (ch >= 'a') && (ch <= 'z'))
                    ch -= 0x20;
                else if ((!first) && (ch >= 'A') && (ch <= 'Z'))
                    ch |= 0x20;
                first = false;
            }
            if ((ch == ':') || (ch == '/') || (ch == '\\') || (ch == '.'))
                first = true;
            break;
        }
        temp.AddChar(ch);
    }
    tok.SetText(temp);
}

PluginAfterActionRequest Casing::Execute(PluginData& data)
{
    SelectCaseDialog dlg;
    if (dlg.Show() != (int) Dialogs::Result::Ok)
        return PluginAfterActionRequest::None;
    auto sectionAction = dlg.GetCaseFormatForSections();
    auto keysAction    = dlg.GetCaseFormatForKeys();
    if ((sectionAction == CaseFormat::None) && (keysAction == CaseFormat::None))
        return PluginAfterActionRequest::None;

    auto len = data.tokens.Len();
    for (auto index = 0U; index < len; index++)
    {
        auto tok  = data.tokens[index];
        auto type = tok.GetTypeID(TokenType::Invalid);
        if ((type == TokenType::Section) && (sectionAction != CaseFormat::None))
            ChangeCaseForToken(tok, sectionAction, true);
        if ((type == TokenType::Key) && (keysAction != CaseFormat::None))
            ChangeCaseForToken(tok, keysAction, false);
    }
    return PluginAfterActionRequest::Refresh;
}
} // namespace GView::Type::INI::Plugins