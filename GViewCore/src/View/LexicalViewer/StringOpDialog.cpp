#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BNT_ID_OPEN   = 2;
constexpr int32 BTN_ID_CANCEL = 3;

StringOpDialog::StringOpDialog(TokenObject& _tok, const char16* _text, Reference<ParseInterface> _parser)
    : Window("String Operations", "d:c,w:80,h:16", WindowFlags::ProcessReturn), tok(_tok), parser(_parser), text(_text)
{
    Factory::Label::Create(this, "&Value", "x:1,y:1,w:30");
    this->txValue = Factory::TextArea::Create(this, "", "x:1,y:2,w:65,h:9", TextAreaFlags::ShowLineNumbers);
    this->txValue->SetHotKey('V');

    // button
    Factory::Button::Create(this, "&Apply", "l:10,b:0,w:15", BTN_ID_OK);
    Factory::Button::Create(this, "&Open content", "l:26,b:0,w:15", BNT_ID_OPEN);
    Factory::Button::Create(this, "&Cancel", "l:42,b:0,w:15", BTN_ID_CANCEL);

    this->txValue->SetFocus();
    UpdateValue(false);
}
void StringOpDialog::UpdateValue(bool original)
{
    LocalUnicodeStringBuilder<512> tmp;
    auto val = original ? tok.GetOriginalText(text) : tok.GetText(text);
    if (parser->StringToContent(val, tmp) == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError(
              "Error", "Fail to extract string content from string (is `StringToContent` virtual method implemented ?");
        this->txValue->SetText(val);
    }
    else
    {
        this->txValue->SetText(tmp);
    }
}
void StringOpDialog::UpdateTokenValue()
{
    LocalUnicodeStringBuilder<512> content;
    LocalUnicodeStringBuilder<512> output;
    if (content.Set(this->txValue->GetText()) == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Fail to get content from text area object !");
        txValue->SetFocus();
        return;
    }
    if (parser->ContentToString(content.ToStringView(), output) == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError(
              "Error", "Fail to convert content to string (is `ContentToString` virtual method implemented ?");
        txValue->SetFocus();
        return;
    }
    // all good --> set value to token
    tok.value.Set(output);
    tok.error.Clear();
    Exit(Dialogs::Result::Ok);
}
bool StringOpDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    switch (eventType)
    {
    case Event::ButtonClicked:
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            UpdateTokenValue();
            return true;
        }
        break;

    case Event::WindowAccept:
        UpdateTokenValue();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}