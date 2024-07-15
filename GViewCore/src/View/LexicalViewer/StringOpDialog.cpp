#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BNT_ID_OPEN   = 2;
constexpr int32 BTN_ID_CANCEL = 3;

constexpr int32 CMD_ID_RELOAD_ORIGINAL   = 10001;
constexpr int32 CMD_ID_RELOAD            = 10002;
constexpr int32 CMD_ID_SHOW_LINE_NUMBERS = 10003;
constexpr int32 INVALID_CMD_ID           = -1;

struct
{
    std::string_view name;
    void (*run)(TextEditor& editor, uint32 start, uint32 end);
} plugins[]{ { "&Reverse", StringOperationsPlugins::Reverse },
             { "&UpperCase", StringOperationsPlugins::UpperCase },
             { "&LowerCase", StringOperationsPlugins::LowerCase },
             { "Remove extra &white spaces", StringOperationsPlugins::RemoveUnnecesaryWhiteSpaces },
             { "Un&escape characters", StringOperationsPlugins::UnescapedCharacters },
             { "Esc&ape non-ASCII Characters", StringOperationsPlugins::EscapeNonAsciiCharacters } };

StringOpDialog::StringOpDialog(TokenObject& _tok, const char16* _text, Reference<ParseInterface> _parser)
    : Window("String Operations", "d:c,w:80,h:20", WindowFlags::ProcessReturn | WindowFlags::Menu), tok(_tok), parser(_parser),
      editor(nullptr, 0), text(_text), openInANewWindow(false)
{
    auto tokMnu = this->AddMenu("&Token");
    tokMnu->AddCommandItem("Restore &original value", CMD_ID_RELOAD_ORIGINAL);
    tokMnu->AddCommandItem("Restore &current value", CMD_ID_RELOAD);
    auto mnuView = this->AddMenu("&View");
    mnuView->AddCheckItem("Show &line numbers", 1, true);
    mnuView->AddCheckItem("&Word wrap", 1, false);
    auto mnuPlugins = this->AddMenu("&Plugins");
    for (auto index = 0; index < ARRAY_LEN(plugins); index++)
    {
        mnuPlugins->AddCommandItem(plugins[index].name, index);
    }

    this->txValue =
          Factory::TextArea::Create(this, "", "l:0,r:0,t:0,b:3", TextAreaFlags::ShowLineNumbers | TextAreaFlags::DisableAutoSelectOnFocus);

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

void StringOpDialog::RunStringOperation(uint32 id)
{
    if (id < ARRAY_LEN(plugins))
    {
        editor.Set(this->txValue->GetText());
        uint32 start, size;
        if (this->txValue->GetSelection(start, size) == false)
        {
            start = 0;
            size  = editor.Len();
        }

        plugins[id].run(editor, start, start + size);
        this->txValue->SetText((std::u16string_view) editor);
    }
    else
    {
        // special cases
        switch (id)
        {
        case CMD_ID_RELOAD_ORIGINAL:
            UpdateValue(true);
            return;
        case CMD_ID_RELOAD:
            UpdateValue(false);
            return;
        case CMD_ID_SHOW_LINE_NUMBERS:         
            return;
        }
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
        case BNT_ID_OPEN:
            openInANewWindow = true;
            Exit(Dialogs::Result::Ok);
            return true;
        }
        break;
    case Event::Command:
        RunStringOperation(ID);
        txValue->SetFocus();
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