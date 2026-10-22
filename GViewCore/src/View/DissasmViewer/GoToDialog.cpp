#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

void GoToDialog::Validate()
{
    LocalString<256> text;
    if (!text.Set(textField->GetText()) || text.Len() == 0) {
        Dialogs::MessageBox::ShowError("Error", "Please write an address or a name!");
        textField->SetFocus();
        return;
    }
    std::string error;
    if (!resolver(text.ToStringView(), error)) {
        Dialogs::MessageBox::ShowError("Error", error);
        textField->SetFocus();
        return;
    }
    resultText = text.GetText();
    Exit(Dialogs::Result::Ok);
}

GoToDialog::GoToDialog(std::string_view shownAddressType, Resolver resolver)
    : Window("GoTo", "d:c,w:70,h:10", WindowFlags::ProcessReturn), resolver(std::move(resolver))
{
    Factory::Label::Create(this, "&Address or name:", "x:1,y:1,w:18");
    textField = Factory::TextField::Create(this, "", "x:20,y:1,w:46");
    textField->SetHotKey('A');

    LocalString<128> help;
    help.SetFormat("An address is hexadecimal (%.*s, as the address column)", static_cast<int>(shownAddressType.size()), shownAddressType.data());
    Factory::Label::Create(this, help, "x:1,y:3,w:66");
    Factory::Label::Create(this, "Prefixes: va:  rva:  off:  line: (decimal)", "x:1,y:4,w:66");

    Factory::Button::Create(this, "&OK", "l:21,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);

    textField->SetFocus();
}

bool GoToDialog::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked) {
        switch (ID) {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
    }

    switch (eventType) {
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
