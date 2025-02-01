#include "Internal.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

class AboutWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<Button> closeButton;
  public:
    AboutWindow() : Window("About", "t:10,l:10,w:74,h:13", WindowFlags::Sizeable)
    {
        Factory::Label::Create(this, "GView is a cross-platform framework for reverse-engineering. Users can leverage the diverse range of available visualization options to effectively analyze and interpret the information.", "t:2,l:5,w:60");
        Factory::Label::Create(this, "Users can leverage the diverse range of available visualization options to effectively analyze and interpret the information.", "t:3,l:5,w:64");
        Factory::Label::Create(this, "options to effectively analyze and interpret the information.", "t:4,l:5,w:64");

        Factory::Label::Create(this, "Read more on https://github.com/gdt050579/GView", "t:6,l:8,w:64");

        Factory::Label::Create(this, "License: MIT", "t:8,l:25,w:64");
        Factory::Label::Create(this, "Version: " GVIEW_VERSION, "t:9,l:25,w:64");

        closeButton = Factory::Button::Create(this, "Close", "t:11,l:26,w:13", 100, ButtonFlags::Flat);
        closeButton->Handlers()->OnButtonPressed = this;
    }

    void OnButtonPressed(Reference<Controls::Button> r) override
    {
        Exit();
    }
};

void Instance::ShowAboutWindow()
{
    AboutWindow aboutWindow{};
    aboutWindow.Show();
}