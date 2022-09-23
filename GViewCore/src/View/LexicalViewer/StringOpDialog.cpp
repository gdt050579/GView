#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BNT_ID_OPEN   = 2;
constexpr int32 BTN_ID_CANCEL = 3;

constexpr uint32 CMD_ID_RELOAD_ORIGINAL = 0;
constexpr uint32 CMD_ID_RELOAD          = 1;
constexpr uint32 CMD_ID_REVERSE         = 2;
constexpr uint32 INVALID_CMD_ID         = 0xFFFFFFFF;

StringOpDialog::StringOpDialog(TokenObject& _tok, const char16* _text, Reference<ParseInterface> _parser)
    : Window("String Operations", "d:c,w:80,h:20", WindowFlags::ProcessReturn), tok(_tok), parser(_parser), editor(nullptr, 0), text(_text),
      openInANewWindow(false)
{
    auto panel = Factory::Panel::Create(this, "Value", "l:1,t:1,r:1,b:3");
    auto spl   = Factory::Splitter::Create(panel, "d:c", SplitterFlags::Vertical);
    auto lst   = Factory::ListView::Create(
          spl,
          "d:c",
          { "w:100,a:l,n:Operations" },
          ListViewFlags::HideBorder | ListViewFlags::HideCurrentItemWhenNotFocused | ListViewFlags::PopupSearchBar);
    this->txValue = Factory::TextArea::Create(spl, "", "x:15,y:2,w:60,h:9", TextAreaFlags::ShowLineNumbers);

    // list commands
    lst->AddItem("Original value").SetData(CMD_ID_RELOAD_ORIGINAL);
    lst->AddItem("Reload value").SetData(CMD_ID_RELOAD);
    lst->AddItem("").SetType(ListViewItem::Type::Category);
    lst->AddItem("Reverse").SetData(CMD_ID_REVERSE);

    spl->SetFirstPanelSize(20);
    // button
    Factory::Button::Create(this, "&Apply", "l:15,b:0,w:15", BTN_ID_OK);
    Factory::Button::Create(this, "&Open content", "l:31,b:0,w:15", BNT_ID_OPEN);
    Factory::Button::Create(this, "&Cancel", "l:47,b:0,w:15", BTN_ID_CANCEL);

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

void StringOpDialog::ReverseValue()
{
    if (editor.Len() == 0)
        return;
    auto e = editor.Len() - 1;
    auto s = 0U;
    while (s < e)
    {
        std::swap(editor[s], editor[e]);
        s++;
        e--;
    }
}
void StringOpDialog::RunStringOperation(AppCUI::Controls::ListViewItem item)
{
    // check if valid or separator
    if (item.GetText(0).Len() == 0)
        return;
    uint32 id = static_cast<uint32>(item.GetData(INVALID_CMD_ID));
    switch (id)
    {
    case CMD_ID_RELOAD_ORIGINAL:
        UpdateValue(true);
        return;
    case CMD_ID_RELOAD:
        UpdateValue(false);
        return;
    }
    // otherwise, we are dealing with some changes to be done directly over the text
    editor.Set(this->txValue->GetText());
    switch (id)
    {
    case CMD_ID_REVERSE:
        ReverseValue();
        break;
    }
    this->txValue->SetText((std::u16string_view) editor);
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
        case BNT_ID_OPEN:
            openInANewWindow = true;
            Exit(Dialogs::Result::Ok);
            return true;
        }
        break;
    case Event::ListViewItemPressed:
        RunStringOperation(control.ToObjectRef<ListView>()->GetCurrentItem());
        control->SetFocus();
        return true;
    case Event::WindowAccept:
        UpdateTokenValue();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}