#pragma once

#include "DropperUI.hpp"
#include "Artefacts.hpp"

constexpr std::string_view BINARY_PAGE_NAME             = "Binary";
constexpr std::string_view OBJECTS_PAGE_NAME            = "Objects";
constexpr std::string_view STRINGS_PAGE_NAME            = "Strings";
constexpr std::string_view FORMAT_INFORMATION_PAGE_NAME = "Format Info";

constexpr int32 TAB_ID_BINARY             = 1;
constexpr int32 TAB_ID_OBJECTS            = 2;
constexpr int32 TAB_ID_STRINGS            = 3;
constexpr int32 TAB_ID_FORMAT_INFORMATION = 4;

constexpr int32 BUTTON_ID_CANCEL               = 1;
constexpr int32 BUTTON_ID_RUN                  = 2;
constexpr int32 BUTTON_ID_SELECT_ALL_OBJECTS   = 3;
constexpr int32 BUTTON_ID_DESELECT_ALL_OBJECTS = 4;

constexpr int32 RADIO_GROUP_COMPUTATION = 1;
constexpr int32 RADIO_ID_FILE           = 1;
constexpr int32 RADIO_ID_SELECTION      = 2;

constexpr int32 CHECKBOX_ID_OPEN_DROPPED_FILE          = 1;
constexpr int32 CHECKBOX_ID_RECURSIVE_OBJECTS          = 2;
constexpr int32 CHECKBOX_ID_WRITE_LOG_OBJECTS          = 3;
constexpr int32 CHECKBOX_ID_OPEN_LOG_OBJECTS           = 4;
constexpr int32 CHECKBOX_ID_OPEN_DROPPED_OBJECTS       = 5;
constexpr int32 CHECKBOX_ID_HIGHLIGHT_DROPPED_OBJECTS  = 6;
constexpr int32 CHECKBOX_ID_DROP_ASCII_STRINGS         = 7;
constexpr int32 CHECKBOX_ID_DROP_UNICODE_STRINGS       = 8;
constexpr int32 CHECKBOX_ID_OPEN_STRINGS_LOG_FILE      = 9;
constexpr int32 CHECKBOX_ID_IDENTIFY_STRINGS_ARTEFACTS = 10;

constexpr int32 RADIO_GROUP_BINARY_DATA_FILE = 2;
constexpr int32 RADIO_ID_OVERWRITE_FILE      = 1;
constexpr int32 RADIO_ID_APPEND_TO_FILE      = 2;

constexpr int32 RADIO_GROUP_STRING_DUMP_FORMAT = 3;
constexpr int32 RADIO_ID_STRING_DUMP_SIMPLE    = 1;
constexpr int32 RADIO_ID_STRING_DUMP_TABULAR   = 2;

constexpr int32 CMD_BINARY_DATA_DROP                    = 1;
constexpr int32 CMD_BINARY_OBJECTS_DROP                 = 2;
constexpr int32 CMD_BINARY_OBJECTS_HIGHLIGHTING         = 3;
constexpr int32 CMD_BINARY_OBJECTS_HIGHLIGHTING_ENABLE  = 4;
constexpr int32 CMD_BINARY_OBJECTS_HIGHLIGHTING_DISABLE = 5;

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

    /* init binary tab page area */

    droppedFilename = object->GetPath();
    {
        std::u16string f = droppedFilename.filename().u16string().append(u".drop");
        droppedFilename  = droppedFilename.parent_path() / f;
    }

    Factory::Label::Create(tpb, "Description: drop selection(s) to a file (overwrite or append)", "x:2%,y:1,w:97%");

    Factory::Label::Create(tpb, "Filename", "x:2%,y:3,w:13%");
    this->binaryFilename = Factory::TextField::Create(tpb, droppedFilename.filename().u16string(), "x:15%,y:3,w:84%");

    Factory::Label::Create(tpb, "CharSet to include (a-z,\\x01-\\x05)", "x:2%,y:5,w:97%");
    this->binaryIncludedCharset = Factory::TextField::Create(tpb, DEFAULT_BINARY_INCLUDE_CHARSET, "x:2%,y:6,w:97%");

    Factory::Label::Create(tpb, "CharSet to exclude (a-z,\\x01-\\x05)", "x:2%,y:8,w:97%");
    this->binaryExcludedCharset = Factory::TextField::Create(tpb, DEFAULT_BINARY_EXCLUDE_CHARSET, "x:2%,y:9,w:97%");

    this->checkboxOpenDroppedFile = Factory::CheckBox::Create(tpb, "Open dro&pped file", "x:2%,y:11,w:96%", CHECKBOX_ID_OPEN_DROPPED_FILE);
    this->overwriteFile = Factory::RadioBox::Create(tpb, "Over&write file", "x:2%,y:13,w:96%", RADIO_GROUP_BINARY_DATA_FILE, RADIO_ID_OVERWRITE_FILE, true);
    this->appendToFile  = Factory::RadioBox::Create(tpb, "&Append to file", "x:2%,y:14,w:96%", RADIO_GROUP_BINARY_DATA_FILE, RADIO_ID_APPEND_TO_FILE);

    /* end binary tab page area */

    /* init objects tab page area*/

    this->objectsMetadata.reserve(1000); // these will be used for list view item data

    Factory::Label::Create(tpo, "Description: drop objects found in file or selection (recursive or not)", "x:2%,y:1,w:97%");

    this->objectsPlugins = Factory::ListView::Create(
          tpo, "x:2%,y:3,w:38%,h:16", { "" }, AppCUI::Controls::ListViewFlags::CheckBoxes | AppCUI::Controls::ListViewFlags::HideColumns);
    this->objectsPlugins->GetColumn(0).SetWidth(100.0);

    this->currentObjectDescription = Factory::Label::Create(tpo, "Object description", "x:42%,y:4,w:56%,h:4");
    Factory::Label::Create(tpo, "Objects name prefix", "x:42%,y:9,w:20%");
    this->objectsFilename = Factory::TextField::Create(tpo, droppedFilename.filename().u16string(), "x:64%,y:9,w:30%");

    logFilename = object->GetPath();
    {
        std::u16string f = logFilename.filename().u16string().append(u".dropper.log");
        logFilename      = logFilename.parent_path() / f;
    }
    Factory::Label::Create(tpo, "Log filename", "x:42%,y:10,w:20%");
    this->objectsLogFilename = Factory::TextField::Create(tpo, logFilename.filename().u16string(), "x:64%,y:10,w:30%");

    this->checkRecursiveInObjects = Factory::CheckBox::Create(tpo, "Check recursive&ly in objects", "x:42%,y:12,w:56%", CHECKBOX_ID_RECURSIVE_OBJECTS);
    this->writeObjectsLog         = Factory::CheckBox::Create(tpo, "Write objec&ts log", "x:42%,y:13,w:56%", CHECKBOX_ID_WRITE_LOG_OBJECTS);
    this->openLogInView           = Factory::CheckBox::Create(tpo, "Open lo&g file", "x:42%,y:14,w:56%", CHECKBOX_ID_WRITE_LOG_OBJECTS);
    this->openDroppedObjects      = Factory::CheckBox::Create(tpo, "Open dropped ob&jects", "x:42%,y:15,w:56%", CHECKBOX_ID_OPEN_DROPPED_OBJECTS);
    this->highlightObjects        = Factory::CheckBox::Create(tpo, "&Highlight dropped objects", "x:42%,y:16,w:56%", CHECKBOX_ID_HIGHLIGHT_DROPPED_OBJECTS);

    this->checkRecursiveInObjects->SetChecked(true);
    this->writeObjectsLog->SetChecked(true);

    Factory::Button::Create(tpo, "&Select all objects", "x:42%,y:18,w:25%", BUTTON_ID_SELECT_ALL_OBJECTS);
    Factory::Button::Create(tpo, "&Deselect all objects", "x:69%,y:18,w:25%", BUTTON_ID_DESELECT_ALL_OBJECTS);

    const auto AddSubItem = [this](ListViewItem parent, Category category, Subcategory subcategory, const Metadata& md) {
        LocalUnicodeStringBuilder<1024> lusb;
        lusb.Set("  ");
        lusb.Add(md.name);

        auto i = this->objectsPlugins->AddItem(lusb);
        i.SetCheck(md.availability);
        if (!md.availability) {
            i.SetType(ListViewItem::Type::GrayedOut);
        }

        auto& metadata = this->objectsMetadata.emplace_back(ItemMetadata{ .parent = parent, .category = category, .subcategory = subcategory });
        i.SetData<ItemMetadata>(&metadata);

        return i;
    };

    for (const auto& [k, v] : OBJECT_CATEGORY_MAP) {
        auto item = this->objectsPlugins->AddItem(v);
        item.SetCheck(true);

        auto& metadata = this->objectsMetadata.emplace_back(ItemMetadata{ .parent = std::nullopt, .category = k, .subcategory = Subcategory::None });
        item.SetData<ItemMetadata>(&metadata);

        auto& subcategories = CATEGORY_TO_SUBCATEGORY_MAP.at(k);
        for (const auto& sc : subcategories) {
            const auto& md = TYPES_MAP.at(sc);
            metadata.children.emplace_back(AddSubItem(item, k, sc, md));
        }

        bool parentActive{ false };
        for (const auto& c : metadata.children) {
            if (c.IsChecked()) {
                parentActive = true;
                break;
            }
        }
        item.SetCheck(parentActive);
    }

    // we always assume that we have at least one item and it's from a main cateogry
    this->objectsPlugins->SetCurrentItem(this->objectsPlugins->GetItem(0));
    const auto& description = OBJECT_DECRIPTION_MAP.at(this->objectsPlugins->GetCurrentItem().GetData<ItemMetadata>()->category);
    this->currentObjectDescription->SetText(description);

    /* end objects tab page area*/

    /* init strings tab page area*/

    stringsFilename = object->GetPath();
    {
        std::u16string f = stringsFilename.filename().u16string().append(u".strings");
        stringsFilename  = stringsFilename.parent_path() / f;
    }

    Factory::Label::Create(tps, "Description: identify various string(s) and dump them to a file", "x:2%,y:1,w:97%");

    Factory::Label::Create(tps, "Filename", "x:2%,y:3,w:13%");
    this->stringsLogFilename = Factory::TextField::Create(tps, stringsFilename.filename().u16string(), "x:15%,y:3,w:84%");

    this->dropAsciiStrings   = Factory::CheckBox::Create(tps, "Dr&op ascii strings", "x:2%,y:5,w:28%", CHECKBOX_ID_DROP_ASCII_STRINGS);
    this->dropUnicodeStrings = Factory::CheckBox::Create(tps, "Drop unicode str&ings", "x:2%,y:6,w:28%", CHECKBOX_ID_DROP_UNICODE_STRINGS);
    this->dropAsciiStrings->SetChecked(true);
    this->dropUnicodeStrings->SetChecked(true);

    this->logDumpSimple = Factory::RadioBox::Create(tps, "Dump &simple format", "x:32%,y:5,w:28%", RADIO_GROUP_STRING_DUMP_FORMAT, RADIO_ID_STRING_DUMP_SIMPLE);
    this->logDumpTabular =
          Factory::RadioBox::Create(tps, "Dump &tabular format", "x:32%,y:6,w:28%", RADIO_GROUP_STRING_DUMP_FORMAT, RADIO_ID_STRING_DUMP_TABULAR, true);

    Factory::Label::Create(tps, "Min. string size", "x:62%,y:5,w:20%");
    Factory::Label::Create(tps, "Max. string size", "x:62%,y:6,w:20%");

    Factory::Label::Create(tps, "M&in. string size", "x:62%,y:5,w:20%");
    Factory::Label::Create(tps, "M&ax. string size", "x:62%,y:6,w:20%");
    this->minimumStringSize = Factory::TextField::Create(tps, "8", "x:82%,y:5,w:10%");
    this->maximumStringSize = Factory::TextField::Create(tps, "", "x:82%,y:6,w:10%");

    Factory::Label::Create(tps, "CharSet to use (a-z,\\x01-\\x05)", "x:2%,y:8,w:38%");
    this->stringsCharset = Factory::TextField::Create(tps, DEFAULT_STRINGS_CHARSET, "x:42%,y:8,w:57%");

    this->openStringsLogFile = Factory::CheckBox::Create(tps, "Open log fi&le", "x:2%,y:10,w:28%", CHECKBOX_ID_OPEN_STRINGS_LOG_FILE);

    this->identifyStringsArtefacts =
          Factory::CheckBox::Create(tps, "Identify suspicious art&efacts", "x:2%,y:12,w:38%", CHECKBOX_ID_IDENTIFY_STRINGS_ARTEFACTS);

    /* end strings tab page area */

    /* init type info tab page area */

    // TODO: (optional?) callbacks in type plugins
    Factory::Label::Create(tpf, "Description: dump information about a particular file format (text, JSON, etc)", "x:2%,y:1,w:97%");
    Factory::Label::Create(tpf, "Not available at the moment (WIP)!", "x:2%,y:2,w:97%");

    /* end type info tab page area */

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
    commandBar.SetCommand(AppCUI::Input::Key::F10, "Drop objects", CMD_BINARY_OBJECTS_DROP);
    commandBar.SetCommand(AppCUI::Input::Key::F4, "Enable highlight objects", CMD_BINARY_OBJECTS_HIGHLIGHTING_ENABLE);
    commandBar.SetCommand(AppCUI::Input::Key::F5, "Disable highlight objects", CMD_BINARY_OBJECTS_HIGHLIGHTING_DISABLE);
    commandBar.SetCommand(AppCUI::Input::Key::F11, "Highlight objects", CMD_BINARY_OBJECTS_HIGHLIGHTING);

    return false;
}

const std::vector<PluginClassification> DropperUI::GetActivePlugins()
{
    std::vector<PluginClassification> plugins;

    const auto count = objectsPlugins->GetItemsCount();
    plugins.reserve(count);

    for (uint32 i = 0; i < count; i++) {
        auto item = objectsPlugins->GetItem(i);
        auto data = item.GetData<ItemMetadata>();

        if (data->parent.has_value()) { // not a main category
            if (item.IsChecked()) {
                plugins.emplace_back(PluginClassification{ data->category, data->subcategory });
            }
        }
    }

    return plugins;
}

bool DropperUI::DropBinary()
{
    auto include = static_cast<std::string>(this->binaryIncludedCharset->GetText());
    include.erase(remove_if(include.begin(), include.end(), isspace), include.end());

    auto exclude = static_cast<std::string>(this->binaryExcludedCharset->GetText());
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

    switch (eventType) {
    case AppCUI::Controls::Event::Command:
        if (ID == CMD_BINARY_DATA_DROP) {
            CHECK(DropBinary(), false, "");
            return true;
        }
        if (ID == CMD_BINARY_OBJECTS_DROP) {
            CHECK(instance.DropObjects(this->GetActivePlugins(), this->droppedFilename, this->logFilename, true, true, false), false, "");
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
        if (ID == CMD_BINARY_OBJECTS_HIGHLIGHTING) {
            CHECK(instance.DropObjects(this->GetActivePlugins(), this->droppedFilename, this->logFilename, true, false, true), false, "");
            this->Exit(Dialogs::Result::Ok);
            return true;
        }
        if (ID == CMD_BINARY_OBJECTS_HIGHLIGHTING_ENABLE) {
            this->Exit(Dialogs::Result::Ok);
            CHECK(instance.SetHighlighting(true, true), false, "");
            return true;
        }
        if (ID == CMD_BINARY_OBJECTS_HIGHLIGHTING_DISABLE) {
            this->Exit(Dialogs::Result::Ok);
            CHECK(instance.SetHighlighting(false, true), false, "");
            return true;
        }
        break;

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
            case TAB_ID_OBJECTS: {
                if (instance.DropObjects(
                          this->GetActivePlugins(),
                          this->droppedFilename,
                          this->logFilename,
                          this->checkRecursiveInObjects->IsChecked(),
                          this->writeObjectsLog->IsChecked(),
                          this->highlightObjects->IsChecked())) {
                    if (this->openDroppedObjects->IsChecked()) {
                        const auto& paths = instance.GetObjectsPaths();
                        for (const auto& p : paths) {
                            GView::App::OpenFile(p, GView::App::OpenMethod::BestMatch, "", parentWindow);
                        }
                    }

                    if (this->openLogInView->IsChecked()) {
                        GView::App::OpenFile(this->logFilename, GView::App::OpenMethod::BestMatch, "", parentWindow);
                    }

                    if (this->openLogInView->IsChecked() || this->openDroppedObjects->IsChecked()) {
                        this->Exit(Dialogs::Result::Ok);
                    } else {
                        Dialogs::MessageBox::ShowNotification("Dropper", "Objects extracted.");
                    }
                } else {
                    Dialogs::MessageBox::ShowError("Dropper", "Failed extracting objects!");
                }
            } break;
            case TAB_ID_STRINGS: {
                const auto min               = std::stoi(this->minimumStringSize->GetText());
                const auto max               = this->maximumStringSize->GetText().IsEmpty() ? (uint32) (-1) : std::stoi(this->maximumStringSize->GetText());
                const auto charSet           = static_cast<std::string>(this->stringsCharset->GetText());
                const auto ascii             = this->dropAsciiStrings->IsChecked();
                const auto unicode           = this->dropUnicodeStrings->IsChecked();
                const auto simpleLogFormat   = this->logDumpSimple->IsChecked();
                const auto identifyArtefacts = this->identifyStringsArtefacts->IsChecked();
                if (instance.DropStrings(ascii, unicode, this->stringsFilename, simpleLogFormat, min, max, charSet, identifyArtefacts)) {
                    bool showDialog{ true };

                    if (this->openStringsLogFile->IsChecked()) {
                        this->Exit(Dialogs::Result::Ok);
                        GView::App::OpenFile(this->stringsFilename, GView::App::OpenMethod::BestMatch, "", parentWindow);
                        showDialog = false;
                    }

                    if (identifyArtefacts) {
                        showDialog = false;
                        this->Exit(Dialogs::Result::Ok);
                        ArtefactsUI(this->object->GetData(), this->instance.GetFindings()).Show();
                    }

                    if (showDialog) {
                        Dialogs::MessageBox::ShowNotification("Dropper", "Strings extracted.");
                    }
                } else {
                    Dialogs::MessageBox::ShowError("Dropper", "Failed extracting strings!");
                }
            } break;
            case TAB_ID_FORMAT_INFORMATION:
                break;
            default:
                break;
            }

            return true;
        }
        if (ID == BUTTON_ID_SELECT_ALL_OBJECTS) {
            const auto count = this->objectsPlugins->GetItemsCount();
            for (uint32 i = 0; i < count; i++) {
                this->objectsPlugins->GetItem(i).SetCheck(true);
            }
            return true;
        }
        if (ID == BUTTON_ID_DESELECT_ALL_OBJECTS) {
            const auto count = this->objectsPlugins->GetItemsCount();
            for (uint32 i = 0; i < count; i++) {
                this->objectsPlugins->GetItem(i).SetCheck(false);
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

    case AppCUI::Controls::Event::TabChanged:
        switch (this->tab->GetCurrentTab()->GetControlID()) {
        case TAB_ID_BINARY:
            break;
        case TAB_ID_OBJECTS:
            this->objectsPlugins->SetFocus();
            break;
        case TAB_ID_STRINGS:
            break;
        case TAB_ID_FORMAT_INFORMATION:
            break;
        default:
            break;
        }
        break;

    case AppCUI::Controls::Event::ListViewItemChecked:
    case AppCUI::Controls::Event::ListViewCurrentItemChanged: {
        auto item = this->objectsPlugins->GetCurrentItem();
        auto data = item.GetData<ItemMetadata>();

        if (eventType == Event::ListViewItemChecked) {
            if (data->parent.has_value()) {
                data->parent->SetCheck(false);
                for (auto& c : data->parent->GetData<ItemMetadata>()->children) {
                    if (c.IsChecked()) {
                        data->parent->SetCheck(true);
                        break;
                    }
                }
            } else {
                for (auto& c : data->children) {
                    c.SetCheck(item.IsChecked());
                }
            }

            return true;
        }

        if (eventType == Event::ListViewCurrentItemChanged) {
            const auto& description = data->parent.has_value()
                                            ? TYPES_MAP.at(data->subcategory).description
                                            : OBJECT_DECRIPTION_MAP.at(this->objectsPlugins->GetCurrentItem().GetData<ItemMetadata>()->category);
            this->currentObjectDescription->SetText(description);
            return true;
        }
    } break;

    default:
        break;
    }

    return false;
}
} // namespace GView::GenericPlugins::Droppper
