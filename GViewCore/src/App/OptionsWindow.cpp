#include "Internal.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

class ChangeThemeWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<Button> closeButton;

  public:
    ChangeThemeWindow() : Window("Change Theme", "t:10,l:10,w:74,h:13", WindowFlags::Sizeable)
    {
        Factory::Label::Create(
              this,
              "You can chane the theme by changing the field 'Theme'","t:2,l:5,w:60");
        Factory::Label::Create(this, "    inside the category [AppCUI] from gview.ini", "t:3,l:5,w:64");


        Factory::Label::Create(
              this,
              "Available options are: 'Default', 'Dark' and 'Light'","t:4,l:5,w:64");
        Factory::Label::Create(this, "If you do see the field, run 'gview reset'", "t:5,l:5,w:64");

        Factory::Label::Create(this, "It will generate a new configuration - 'gview.ini'", "t:6,l:5,w:64");

        Factory::Label::Create(this, "License: MIT", "t:8,l:25,w:64");
        Factory::Label::Create(this, "Version: " GVIEW_VERSION, "t:9,l:25,w:64");

        closeButton                              = Factory::Button::Create(this, "Close", "t:11,l:26,w:13", 100, ButtonFlags::Flat);
        closeButton->Handlers()->OnButtonPressed = this;
    }

    void OnButtonPressed(Reference<Controls::Button> r) override
    {
        Exit();
    }
};

void Instance::ShowChangeThemeWindow()
{
    ChangeThemeWindow window{};
    window.Show();
}