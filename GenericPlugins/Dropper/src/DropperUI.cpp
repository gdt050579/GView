#pragma once

#include "DropperUI.hpp"

constexpr std::string_view BINARY_PAGE_NAME  = "Binary";
constexpr std::string_view OBJECTS_PAGE_NAME = "Objects";
constexpr std::string_view STRINGS_PAGE_NAME = "Strings";

constexpr int32 BUTTON_ID_CANCEL = 1;
constexpr int32 BUTTON_ID_RUN    = 2;

using namespace AppCUI::Controls;

namespace GView::GenericPlugins::Droppper
{
DropperUI::DropperUI(Reference<GView::Object> object) : Window("Dropper", "d:c,w:100,h:30", WindowFlags::None)
{
    this->object = object;

    this->tab = Factory::Tab::Create(this, "l:1,t:1,r:1,b:3", TabFlags::LeftTabs | TabFlags::TabsBar);
    Factory::TabPage::Create(this->tab, BINARY_PAGE_NAME);
    Factory::TabPage::Create(this->tab, OBJECTS_PAGE_NAME);
    Factory::TabPage::Create(this->tab, STRINGS_PAGE_NAME);

    Factory::Button::Create(this, "&Cancel", "x:40%,y:28,a:b,w:12", BUTTON_ID_CANCEL);
    Factory::Button::Create(this, "&Run", "x:60%,y:28,a:b,w:12", BUTTON_ID_RUN);
}

bool DropperUI::OnEvent(Reference<Control> control, Event eventType, int32 ID)
{
    if (Window::OnEvent(control, eventType, ID)) {
        return true;
    }

    if (eventType == Event::ButtonClicked) {
        if (ID == BUTTON_ID_CANCEL) {
            this->Exit(Dialogs::Result::Cancel);
            return true;
        }
        if (ID == BUTTON_ID_RUN) {
            if (instance.Process(object)) {
                Dialogs::MessageBox::ShowNotification("Dropper", "Objects extracted.");
            } else {
                Dialogs::MessageBox::ShowError("Dropper", "Failed extracting objects!");
            }

            return true;
        }
    } else if (eventType == Event::WindowClose) {
        this->Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::GenericPlugins::Droppper
