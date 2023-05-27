#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

void GoToDialog::Validate()
{
    LocalString<128> tmp;
    LocalString<256> error;
    NumberParseFlags flags = NumberParseFlags::BaseAuto;

    if (tmp.Set(lineTextField->GetText()) == false)
    {
        Dialogs::MessageBox::ShowError("Error", "Invalid line number (expecting ascii characters) for line number!");
        lineTextField->SetFocus();
        return;
    }
    const auto lineParser = Number::ToUInt32(tmp, flags);
    if (!lineParser.has_value())
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Line number `%s` is not a valid UInt32 number!", tmp.GetText()));
        lineTextField->SetFocus();
        return;
    }

    const auto newLine = lineParser.value();
    if (newLine >= totalAvailableLines)
    {
        Dialogs::MessageBox::ShowError("Error", error.Format("Expected a line number `%s` lower than %lu!", tmp.GetText(), totalAvailableLines));
        lineTextField->SetFocus();
        return;
    }
    resultLine = newLine;
    Exit(Dialogs::Result::Ok);
}

GoToDialog::GoToDialog(uint32 currentLine, uint32 totalAvailableLines)
    : Window("GoTo", "d:c,w:60,h:7", WindowFlags::ProcessReturn), resultLine(currentLine), totalAvailableLines(totalAvailableLines)
{
    Factory::Label::Create(this, "&Line:", "x:1,y:1,w:8");
    lineTextField = Factory::TextField::Create(this, "", "x:10,y:1,w:46");
    lineTextField->SetHotKey('L');

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

    lineTextField->SetFocus();
}

bool GoToDialog::OnEvent(Reference<Control> reference, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked)
    {
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
    }

    switch (eventType)
    {
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}