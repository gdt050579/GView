#pragma once

#include "DropperUI.hpp"

constexpr std::string_view BINARY_PAGE_NAME             = "Binary";
constexpr std::string_view OBJECTS_PAGE_NAME            = "Objects";
constexpr std::string_view STRINGS_PAGE_NAME            = "Strings";
constexpr std::string_view FORMAT_INFORMATION_PAGE_NAME = "Format Info";

constexpr int32 TAB_ID_BINARY             = 1;
constexpr int32 TAB_ID_OBJECTS            = 2;
constexpr int32 TAB_ID_STRINGS            = 3;
constexpr int32 TAB_ID_FORMAT_INFORMATION = 4;

constexpr int32 BUTTON_ID_CANCEL = 1;
constexpr int32 BUTTON_ID_RUN    = 2;

constexpr int32 RADIO_GROUP_COMPUTATION = 1;
constexpr int32 RADIO_ID_FILE           = 1;
constexpr int32 RADIO_ID_SELECTION      = 2;

constexpr int32 CHECKBOX_ID_OPEN_DROPPED_FILE = 1;

constexpr int32 RADIO_GROUP_BINARY_DATA_FILE = 2;
constexpr int32 RADIO_ID_OVERWRITE_FILE      = 1;
constexpr int32 RADIO_ID_APPEND_TO_FILE      = 2;

constexpr int32 CMD_BINARY_DATA_DROP = 1;

using namespace AppCUI::Controls;

namespace GView::GenericPlugins::Droppper
{
DropperUI::DropperUI(Reference<GView::Object> object) : Window("Dropper", "d:c,w:100,h:30", WindowFlags::None)
{
    auto desktop         = AppCUI::Application::GetDesktop();
    auto focusedChild    = desktop->GetFocusedChild();
    const auto windowsNo = desktop->GetChildrenCount();
    for (uint32 i = 0; i < windowsNo; i++) {
        auto window = desktop->GetChild(i);

        if (window == focusedChild || (focusedChild.IsValid() && focusedChild->HasDistantParent(window))) {
            this->parentWindow = window.ToObjectRef<Window>();
            break;
        }
    }

    this->object = object;
    if (!this->instance.Init(object)) {
        Dialogs::MessageBox::ShowError("Dropper", "Failed to initialize dropper!");
        this->Exit(Dialogs::Result::Cancel);
    }

    this->tab = Factory::Tab::Create(this, "l:1,t:1,r:1,b:6", TabFlags::TopTabs | TabFlags::TabsBar);
    auto tpb  = Factory::TabPage::Create(this->tab, BINARY_PAGE_NAME, TAB_ID_BINARY);
    auto tpo  = Factory::TabPage::Create(this->tab, OBJECTS_PAGE_NAME, TAB_ID_OBJECTS);
    auto tps  = Factory::TabPage::Create(this->tab, STRINGS_PAGE_NAME, TAB_ID_STRINGS);
    auto tpf  = Factory::TabPage::Create(this->tab, FORMAT_INFORMATION_PAGE_NAME, TAB_ID_FORMAT_INFORMATION);

    LocalUnicodeStringBuilder<1024> lusb;

    /* init binary tab page area */

    lusb.Set(object->GetName());
    lusb.Add(".drop");

    Factory::Label::Create(tpb, "Description: drop selection(s) to a file (overwrite or append)", "x:2%,y:1,w:97%");

    Factory::Label::Create(tpb, "Filename", "x:2%,y:3,w:13%");
    this->binaryFilename = Factory::TextField::Create(tpb, lusb, "x:15%,y:3,w:84%");

    Factory::Label::Create(tpb, "CharSet to include (a-z,\\x01-\\x05)", "x:2%,y:5,w:97%");
    this->includedCharset = Factory::TextField::Create(tpb, DEFAULT_INCLUDE_CHARSET, "x:2%,y:6,w:97%");

    Factory::Label::Create(tpb, "CharSet to exclude (a-z,\\x01-\\x05)", "x:2%,y:8,w:97%");
    this->excludedCharset = Factory::TextField::Create(tpb, DEFAULT_EXCLUDE_CHARSET, "x:2%,y:9,w:97%");

    this->checkboxOpenDroppedFile = Factory::CheckBox::Create(tpb, "Open &dropped file", "x:2%,y:11,w:96%", CHECKBOX_ID_OPEN_DROPPED_FILE);
    this->overwriteFile = Factory::RadioBox::Create(tpb, "Over&write file", "x:2%,y:13,w:96%", RADIO_GROUP_BINARY_DATA_FILE, RADIO_ID_OVERWRITE_FILE, true);
    this->appendToFile  = Factory::RadioBox::Create(tpb, "&Append to file", "x:2%,y:15,w:96%", RADIO_GROUP_BINARY_DATA_FILE, RADIO_ID_APPEND_TO_FILE);

    /* end binary tab page area */

    computeForFile      = Factory::RadioBox::Create(this, "Compute for the &entire file", "x:1,y:23,w:31", RADIO_GROUP_COMPUTATION, RADIO_ID_FILE);
    computeForSelection = Factory::RadioBox::Create(this, "Compute for the &selection", "x:1,y:24,w:31", RADIO_GROUP_COMPUTATION, RADIO_ID_SELECTION);

    if (this->instance.IsComputingFile()) {
        computeForFile->SetChecked(true);
        computeForSelection->SetEnabled(false);
    } else {
        computeForSelection->SetChecked(true);
    }

    Factory::Button::Create(this, "&Cancel", "x:40%,y:28,a:b,w:12", BUTTON_ID_CANCEL);
    Factory::Button::Create(this, "&Run", "x:60%,y:28,a:b,w:12", BUTTON_ID_RUN);
}

bool DropperUI::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(AppCUI::Input::Key::F3, "Drop binary data", CMD_BINARY_DATA_DROP);
    return false;
}

bool DropperUI::DropBinary()
{
    auto include = static_cast<std::string>(this->includedCharset->GetText());
    include.erase(remove_if(include.begin(), include.end(), isspace), include.end());

    auto exclude = static_cast<std::string>(this->excludedCharset->GetText());
    exclude.erase(remove_if(exclude.begin(), exclude.end(), isspace), exclude.end());

    if (instance.DropBinaryData(
              (static_cast<std::string>(this->binaryFilename->GetText())).c_str(),
              this->overwriteFile->IsChecked(),
              this->checkboxOpenDroppedFile->IsChecked(),
              include,
              exclude,
              this->parentWindow)) {
        Dialogs::MessageBox::ShowNotification("Dropper", "Dumped binary data.");

        if (this->checkboxOpenDroppedFile->IsChecked()) {
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
    } else {
        Dialogs::MessageBox::ShowError("Dropper", "Failed dumping binary data!");
    }

    return true;
}

bool DropperUI::OnEvent(Reference<Control> control, Event eventType, int32 ID)
{
    if (Window::OnEvent(control, eventType, ID)) {
        return true;
    }

    if (eventType == Event::Command) {
        if (ID == CMD_BINARY_DATA_DROP) {
            CHECK(DropBinary(), false, "");
            return true;
        }
    }

    switch (eventType) {
    case AppCUI::Controls::Event::WindowClose:
        this->Exit(Dialogs::Result::Cancel);
        return true;
    case AppCUI::Controls::Event::ButtonClicked:
        if (ID == BUTTON_ID_CANCEL) {
            this->Exit(Dialogs::Result::Cancel);
            return true;
        }
        if (ID == BUTTON_ID_RUN) {
            switch (this->tab->GetCurrentTab()->GetControlID()) {
            case TAB_ID_BINARY:
                CHECK(DropBinary(), false, "");
                break;
            case TAB_ID_OBJECTS:
                if (instance.Process()) {
                    Dialogs::MessageBox::ShowNotification("Dropper", "Objects extracted.");
                } else {
                    Dialogs::MessageBox::ShowError("Dropper", "Failed extracting objects!");
                }
                break;
            case TAB_ID_STRINGS:
                break;
            case TAB_ID_FORMAT_INFORMATION:
                break;
            default:
                break;
            }

            return true;
        }
        break;
    case AppCUI::Controls::Event::CheckedStatusChanged:
        if (control->GetGroup() == RADIO_GROUP_COMPUTATION) {
            if (ID == RADIO_ID_FILE) {
                this->instance.SetComputingFile(true);
                return true;
            }
            if (ID == RADIO_ID_SELECTION) {
                this->instance.SetComputingFile(false);
                return true;
            }
        } else if (control->GetGroup() == RADIO_GROUP_BINARY_DATA_FILE) {
            // nothing
        }
        break;
    default:
        break;
    }

    return false;
}
} // namespace GView::GenericPlugins::Droppper
