#include "Yara.hpp"

namespace GView::GenericPlugins::Yara
{

constexpr int32 CMD_BUTTON_ADD    = 1;
constexpr int32 CMD_BUTTON_REMOVE = 2;
constexpr int32 CMD_BUTTON_SCAN   = 3;
constexpr int32 CMD_BUTTON_CLOSE  = 4;

YaraDialog::YaraDialog(Reference<GView::Object> object) : Window("Yara Scanner", "d:c,w:80,h:25", WindowFlags::ProcessReturn)
{
    this->object = object;

    Factory::Label::Create(this, "Yara plugin", "x:1,y:2,w:58");

    rulesList = Factory::ListView::Create(this, "l:1,t:3,r:1,b:5", { "n:Rule Files,w:100" });

    addButton                              = Factory::Button::Create(this, "&Add Rule File", "x:1,y:18,w:18", CMD_BUTTON_ADD);
    addButton->Handlers()->OnButtonPressed = this;

    removeButton                              = Factory::Button::Create(this, "&Remove Selected", "x:21,y:18,w:18", CMD_BUTTON_REMOVE);
    removeButton->Handlers()->OnButtonPressed = this;

    scanButton                              = Factory::Button::Create(this, "&Scan", "x:40%,y:23,a:b,w:12", CMD_BUTTON_SCAN);
    scanButton->Handlers()->OnButtonPressed = this;

    closeButton                              = Factory::Button::Create(this, "&Close", "x:60%,y:23,a:b,w:12", CMD_BUTTON_CLOSE);
    closeButton->Handlers()->OnButtonPressed = this;

    addButton->SetFocus();
}

void YaraDialog::OnButtonPressed(Reference<Button> b)
{
    switch (b->GetControlID()) {
    case CMD_BUTTON_ADD:
        AddRuleFile();
        break;
    case CMD_BUTTON_REMOVE:
        RemoveRuleFile();
        break;
    case CMD_BUTTON_SCAN:
        ScanWithYara();
        break;
    case CMD_BUTTON_CLOSE:
        Exit();
        break;
    }
}

bool YaraDialog::OnEvent(Reference<Control> control, Event eventType, int id)
{
    if (Window::OnEvent(control, eventType, id)) {
        return true;
    }

    if (eventType == Event::WindowAccept) {
        OnButtonPressed(addButton);
        return true;
    }

    return false;
}

void YaraDialog::AddRuleFile()
{
    std::filesystem::path initialPath;
    if (!ruleFiles.empty()) {
        initialPath = ruleFiles.back().parent_path();
    } else if (object.IsValid()) {
        initialPath = std::filesystem::path(object->GetPath()).parent_path();
    }

    auto res = Dialogs::FileDialog::ShowOpenFileWindow("", "YARA Rules:yar,yara|All Files:*", initialPath);
    if (res.has_value()) {
        bool alreadyExists = false;
        for (const auto& existingPath : ruleFiles) {
            if (existingPath == res.value()) {
                alreadyExists = true;
                break;
            }
        }

        if (!alreadyExists) {
            ruleFiles.push_back(res.value());
            UpdateRulesList();
        } else {
            Dialogs::MessageBox::ShowWarning("Yara", "This rule file is already in the list!");
        }
    }
}

void YaraDialog::RemoveRuleFile()
{
    auto currentItem = rulesList->GetCurrentItem();
    if (!currentItem.IsValid()) {
        Dialogs::MessageBox::ShowWarning("Yara", "Please select a rule file to remove!");
        return;
    }

    uint32 index     = 0;
    bool found       = false;
    const auto count = rulesList->GetItemsCount();
    for (uint32 i = 0; i < count; i++) {
        if (rulesList->GetItem(i).IsCurrent()) {
            index = i;
            found = true;
            break;
        }
    }

    if (found && index < ruleFiles.size()) {
        ruleFiles.erase(ruleFiles.begin() + index);
        UpdateRulesList();
    }
}

void YaraDialog::ScanWithYara()
{
    Dialogs::MessageBox::ShowNotification("Yara", "Coming soon!");
}

void YaraDialog::UpdateRulesList()
{
    rulesList->DeleteAllItems();
    for (const auto& ruleFile : ruleFiles) {
        rulesList->AddItem({ ruleFile.filename().u16string() });
    }

    if (ruleFiles.empty()) {
        rulesList->AddItem({ "(No rule files added)" });
    }
}

} // namespace GView::GenericPlugins::Yara

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Yara") {
        GView::GenericPlugins::Yara::YaraDialog dlg(object);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.Yara"] = Input::Key::F11;
}
}