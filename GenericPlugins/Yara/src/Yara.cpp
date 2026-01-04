#include "Yara.hpp"
#include "yara.h"
#undef MessageBox

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

    Factory::Label::Create(this, "Output File:", "x:1,y:16,w:12");
    outputFilename = Factory::TextField::Create(this, "yara_scan_results.txt", "x:14,y:16,w:65");

    addButton                              = Factory::Button::Create(this, "&Add Rule File", "x:1,y:19,w:18", CMD_BUTTON_ADD);
    addButton->Handlers()->OnButtonPressed = this;

    removeButton                              = Factory::Button::Create(this, "&Remove Selected", "x:21,y:19,w:18", CMD_BUTTON_REMOVE);
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
            AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "This rule file is already in the list!");
        }
    }
}

void YaraDialog::RemoveRuleFile()
{
    auto currentItem = rulesList->GetCurrentItem();
    if (!currentItem.IsValid()) {
        AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "Please select a rule file to remove!");
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

struct ScanCallbackData
{
    Buffer* buffer;
    bool* scanFinished;
};

int ScanCallback(void* context, int message, void* message_data, void* user_data)
{
    ScanCallbackData* callbackData = static_cast<ScanCallbackData*>(user_data);
    if (!callbackData)
        return CALLBACK_CONTINUE;

    YR_SCAN_CONTEXT* scanContext = static_cast<YR_SCAN_CONTEXT*>(context);
    
    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING: {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        callbackData->buffer->Add("Rule matching: ");
        callbackData->buffer->Add(rule->identifier);

        YR_STRING* string;

        yr_rule_strings_foreach(rule, string)
        {
            YR_MATCH* match;
            yr_string_matches_foreach(scanContext, string, match)
            {
                std::string_view sv((const char*) string->string, string->length);
                callbackData->buffer->Add("\n  String matched: ");
                callbackData->buffer->Add(sv);
            }
        }
        callbackData->buffer->Add("\n");

        break;
    }
    case CALLBACK_MSG_TOO_MANY_MATCHES: {
        break;
    }
    case CALLBACK_MSG_SCAN_FINISHED: {
        if (callbackData->scanFinished) {
            *callbackData->scanFinished = true;
        }
        break;
    }
    default:
        break;
    }

    return CALLBACK_CONTINUE;
}

void YaraDialog::ScanWithYara()
{
    if (ruleFiles.empty()) {
        AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "Please add at least one rule file!");
        return;
    }

    auto outputFile = outputFilename->GetText();
    if (outputFile.IsEmpty()) {
        AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "Please specify an output filename!");
        return;
    }

    GView::Yara::YaraManager& yaraManager = GView::Yara::YaraManager::GetInstance();
    if (!yaraManager.Initialize()) {
        AppCUI::Dialogs::MessageBox::ShowError("Yara", "Failed to initialize Yara engine!");
        return;
    }

    auto yaraCompiler = yaraManager.GetNewCompiler();

    for (const auto& ruleFile : ruleFiles) {
        if (!yaraCompiler->AddRules(ruleFile)) {
            AppCUI::Dialogs::MessageBox::ShowError("Yara", "Failed to add rules from file: " + ruleFile.string());
            return;
        }
    }

    auto yaraRules = yaraCompiler->GetRules();

    Buffer scanResults;
    bool scanFinished = false;
    ScanCallbackData callbackData{ &scanResults, &scanFinished };
    std::string outputFileString(outputFile);

    {
        GView::Yara::YaraScanner yaraScanner(yaraRules, ScanCallback, &callbackData);
        yaraScanner.ScanBuffer(object->GetData().GetEntireFile());
    }

    if (scanResults.GetLength() > 0) {
        auto file = std::make_unique<AppCUI::OS::File>();
        file->Create(outputFileString, false);
        if (file->OpenWrite(outputFileString)) {
            file->Write(scanResults.GetData(), scanResults.GetLength());
            file->Close();
        }
    }

    AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "Scan completed! Results saved to: " + outputFileString);
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