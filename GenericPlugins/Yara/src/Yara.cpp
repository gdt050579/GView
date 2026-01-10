#include "Yara.hpp"
#include "yara.h"
#undef MessageBox

namespace GView::GenericPlugins::Yara
{

// === YaraDialog Command IDs ===
constexpr int32 CMD_BUTTON_ADD_FILE   = 1;
constexpr int32 CMD_BUTTON_ADD_FOLDER = 2;
constexpr int32 CMD_BUTTON_ADD_RECENT = 3;
constexpr int32 CMD_BUTTON_REMOVE     = 4;
constexpr int32 CMD_BUTTON_SCAN       = 5;
constexpr int32 CMD_BUTTON_CLOSE      = 6;

// === RecentRulesDialog Command IDs ===
constexpr int32 CMD_RECENT_CONFIRM = 100;
constexpr int32 CMD_RECENT_CANCEL  = 101;

// ============================================================================
// RecentRulesDialog Implementation
// ============================================================================

static std::string FormatTimeAgo(time_t lastUsed)
{
    auto diff = (time(nullptr) - lastUsed) / 3600;
    if (diff < 1)
        return "just now";
    if (diff < 24)
        return std::to_string(diff) + "h ago";

    auto days = diff / 24;
    if (days == 1)
        return "1 day ago";
    if (days < 7)
        return std::to_string(days) + " days ago";
    if (days < 14)
        return "1 week ago";
    if (days < 30)
        return std::to_string(days / 7) + " weeks ago";
    if (days < 60)
        return "1 month ago";

    return std::to_string(days / 30) + " months ago";
}

RecentRulesDialog::RecentRulesDialog(const std::vector<RecentEntry>& list)
    : Window("Recently Used Rules", "d:c,w:75,h:18", WindowFlags::ProcessReturn), recentList(list)
{
    recentListView = Factory::ListView::Create(this, "l:1,t:1,r:1,b:5", { "n:Name,w:36", "n:Type,w:8", "n:Last Used,w:15" }, ListViewFlags::CheckBoxes);

    for (const auto& entry : recentList) {
        recentListView->AddItem({ entry.path.filename().string(), entry.isFolder ? "Folder" : "File", FormatTimeAgo(entry.lastUsed) });
    }

    Factory::Label::Create(this, "Path:", "x:1,y:13,w:5");
    fullPathField = Factory::TextField::Create(this, "(select an item)", "x:7,y:13,w:65", TextFieldFlags::Readonly);

    confirmButton                              = Factory::Button::Create(this, "Confirm", "x:25,y:15,w:12", CMD_RECENT_CONFIRM);
    confirmButton->Handlers()->OnButtonPressed = this;
    cancelButton                               = Factory::Button::Create(this, "Cancel", "x:40,y:15,w:12", CMD_RECENT_CANCEL);
    cancelButton->Handlers()->OnButtonPressed  = this;

    if (recentListView->GetItemsCount() > 0) {
        recentListView->SetFocus();
        UpdateFullPathField();
    }
}

void RecentRulesDialog::OnButtonPressed(Reference<Button> b)
{
    switch (b->GetControlID()) {
    case CMD_RECENT_CONFIRM:
        OnConfirmSelected();
        break;
    case CMD_RECENT_CANCEL:
        Exit(Dialogs::Result::Cancel);
        break;
    }
}

bool RecentRulesDialog::OnEvent(Reference<Control> control, Event eventType, int id)
{
    if (Window::OnEvent(control, eventType, id)) {
        return true;
    }

    switch (eventType) {
    case Event::ListViewCurrentItemChanged:
        UpdateFullPathField();
        return true;

    case Event::ListViewItemPressed:
        OnConfirmSelected();
        return true;

    case Event::WindowAccept:
        OnConfirmSelected();
        return true;

    default:
        break;
    }

    return false;
}

void RecentRulesDialog::UpdateFullPathField()
{
    auto currentItem = recentListView->GetCurrentItem();
    if (!currentItem.IsValid()) {
        fullPathField->SetText("(select an item)");
        return;
    }

    uint32 index = 0;
    for (uint32 i = 0; i < recentListView->GetItemsCount(); i++) {
        if (recentListView->GetItem(i).IsCurrent()) {
            index = i;
            break;
        }
    }

    if (index < recentList.size()) {
        fullPathField->SetText(recentList[index].path.u16string());
    }
}

void RecentRulesDialog::OnConfirmSelected()
{
    selectedEntries.clear();

    // Collect checked items
    for (uint32 i = 0; i < recentListView->GetItemsCount(); i++) {
        auto item = recentListView->GetItem(i);
        if (item.IsChecked() && i < recentList.size()) {
            selectedEntries.push_back(recentList[i]);
        }
    }

    // If nothing checked, use current item (for double-click)
    if (selectedEntries.empty()) {
        for (uint32 i = 0; i < recentListView->GetItemsCount(); i++) {
            if (recentListView->GetItem(i).IsCurrent() && i < recentList.size()) {
                selectedEntries.push_back(recentList[i]);
                break;
            }
        }
    }

    Exit(Dialogs::Result::Ok);
}

// ============================================================================
// YaraDialog Implementation
// ============================================================================

YaraDialog::YaraDialog(Reference<GView::Object> object, ScanContext ctx, const std::filesystem::path& target)
    : Window("Yara Scanner", "d:c,w:80,h:24", WindowFlags::ProcessReturn), context(ctx), scanTarget(target)
{
    this->object = object;

    RestoreRecentlyUsed();

    if (context == ScanContext::SingleFile) {
        Factory::Label::Create(this, "Scanning file:", "x:1,y:1,w:14");
        Factory::TextField::Create(this, scanTarget.u16string(), "x:16,y:1,w:62", TextFieldFlags::Readonly);
    } else {
        Factory::Label::Create(this, "Scanning folder:", "x:1,y:1,w:16");
        Factory::TextField::Create(this, scanTarget.u16string(), "x:18,y:1,w:60", TextFieldFlags::Readonly);
    }

    Factory::Label::Create(this, "Add Rules:", "x:1,y:3,w:10");
    addFileButton                                = Factory::Button::Create(this, "Add File", "x:12,y:3,w:12", CMD_BUTTON_ADD_FILE);
    addFileButton->Handlers()->OnButtonPressed   = this;
    addFolderButton                              = Factory::Button::Create(this, "Add Folder", "x:25,y:3,w:14", CMD_BUTTON_ADD_FOLDER);
    addFolderButton->Handlers()->OnButtonPressed = this;
    addRecentButton                              = Factory::Button::Create(this, "Add Recent", "x:41,y:3,w:16", CMD_BUTTON_ADD_RECENT);
    addRecentButton->Handlers()->OnButtonPressed = this;

    Factory::Label::Create(this, "Rules to apply:", "x:1,y:5,w:15");
    rulesListView = Factory::ListView::Create(this, "l:1,t:6,r:1,b:6", { "n:Rule Files,w:100" });

    removeButton                              = Factory::Button::Create(this, "Remove Selected", "x:1,y:18,w:18", CMD_BUTTON_REMOVE);
    removeButton->Handlers()->OnButtonPressed = this;

    scanButton                              = Factory::Button::Create(this, "Scan", "x:35%,y:21,w:12", CMD_BUTTON_SCAN);
    scanButton->Handlers()->OnButtonPressed = this;

    closeButton                              = Factory::Button::Create(this, "Close", "x:55%,y:21,w:12", CMD_BUTTON_CLOSE);
    closeButton->Handlers()->OnButtonPressed = this;

    addFileButton->SetFocus();
}

void YaraDialog::OnButtonPressed(Reference<Button> b)
{
    switch (b->GetControlID()) {
    case CMD_BUTTON_ADD_FILE:
        AddRuleFile();
        break;
    case CMD_BUTTON_ADD_FOLDER:
        AddRuleFolder();
        break;
    case CMD_BUTTON_ADD_RECENT:
        AddRecentRules();
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
        OnButtonPressed(addFileButton);
        return true;
    }

    return false;
}

// === Rule Management ===

void YaraDialog::AddRuleFile()
{
    std::filesystem::path initialPath;
    if (!ruleFiles.empty()) {
        initialPath = ruleFiles.back().parent_path();
    } else if (object.IsValid()) {
        initialPath = std::filesystem::path(object->GetPath()).parent_path();
    }

    auto res = Dialogs::FileDialog::ShowOpenFileWindow("", "Yara Rules:yar,yara|All Files:*", initialPath);
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
            UpdateRulesListView();
        } else {
            AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "This rule file is already in the list!");
        }
    }
}

void YaraDialog::AddRuleFolder()
{
    // TODO: Implement folder selection and recursive .yar files discovery
    // - Open a folder picker dialog (similar to file dialog but for directories)
    // - Recursively find all .yar/.yara files in the selected folder
    // - Add discovered files to ruleFiles list (skip duplicates)
    // - Update the rules list display
    AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "Add Rule Folder - Not yet implemented");
}

void YaraDialog::AddRecentRules()
{
    if (recentlyUsedList.empty()) {
        AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "No recently used rules found.");
        return;
    }

    RecentRulesDialog dlg(recentlyUsedList);
    if (dlg.Show() != Dialogs::Result::Ok) {
        return; // User cancelled or closed the dialog
    }

    const auto& selectedList = dlg.GetSelectedEntries();
    for (const auto& entry : selectedList) {
        bool alreadyExists = false;
        for (const auto& existingPath : ruleFiles) {
            if (existingPath == entry.path) {
                alreadyExists = true;
                break;
            }
        }

        if (alreadyExists) {
            continue;
        }

        if (entry.isFolder) {
            // TODO: Recursively iterate folder, find all .yar files, add each to ruleFiles. I expect the implementation to be very simillar to AddRuleFolder function.
            AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "Loading rules from folder - Not yet implemented");
        } else {
            ruleFiles.push_back(entry.path);
        }
    }

    UpdateRulesListView();
}

void YaraDialog::RemoveRuleFile()
{
    auto currentItem = rulesListView->GetCurrentItem();
    if (!currentItem.IsValid()) {
        AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "Please select a rule file to remove!");
        return;
    }

    uint32 index     = 0;
    bool found       = false;
    const auto count = rulesListView->GetItemsCount();
    for (uint32 i = 0; i < count; i++) {
        if (rulesListView->GetItem(i).IsCurrent()) {
            index = i;
            found = true;
            break;
        }
    }

    if (found && index < ruleFiles.size()) {
        ruleFiles.erase(ruleFiles.begin() + index);
        UpdateRulesListView();
    }
}

void YaraDialog::UpdateRulesListView()
{
    rulesListView->DeleteAllItems();
    for (const auto& ruleFile : ruleFiles) {
        rulesListView->AddItem({ ruleFile.filename().string() });
    }

    if (ruleFiles.empty()) {
        rulesListView->AddItem({ "(No rule files added)" });
    }
}

// === Recently Used Persistence ===

void YaraDialog::RestoreRecentlyUsed()
{
    // TODO: Currently mocked. Design a persistence mechanism where:
    // - Recently used rule files/folders are saved to a config file (e.g., JSON)
    // - Compiled rules could be cached in a GView app folder for faster loading
    // - Track metadata: path, isFolder, lastUsed timestamp, maybe hash for change detection
    // - Load on dialog open, save after successful scan

    recentlyUsedList.clear();

    // MOCK DATA for demonstration. Please remove this once you have a proper persistence mechanism.
    time_t now = time(nullptr);
    recentlyUsedList.push_back({
          "C:\\Users\\demo\\yara-rules\\malware_signatures.yar",
          false,
          now - 2 * 3600 // 2 hours ago
    });
    recentlyUsedList.push_back({
          "C:\\Users\\demo\\yara-rules\\crypto_rules",
          true,
          now - 48 * 3600 // 48 hours ago
    });
    recentlyUsedList.push_back({
          "C:\\Users\\demo\\yara-rules\\packer_detection.yar",
          false,
          now - 168 * 3600 // 1 week ago
    });
}

void YaraDialog::PersistRecentlyUsed(const std::filesystem::path& path, bool isFolder)
{
    // TODO: Persist to config file (e.g., JSON in GView config directory)
    // Currently in-memory only - lost on dialog close

    // Remove if already exists (will re-add at front)
    auto it = std::remove_if(recentlyUsedList.begin(), recentlyUsedList.end(), [&path](const RecentEntry& entry) { return entry.path == path; });
    recentlyUsedList.erase(it, recentlyUsedList.end());

    // Add at front (most recent) with current timestamp
    recentlyUsedList.insert(recentlyUsedList.begin(), RecentEntry{ path, isFolder, time(nullptr) });

    if (recentlyUsedList.size() > MAX_RECENT_ENTRIES) {
        recentlyUsedList.resize(MAX_RECENT_ENTRIES);
    }
}

// ============================================================================
// Scanning
// ============================================================================

static constexpr size_t MAX_MATCH_DISPLAY_LENGTH = 32;

struct ScanMatch {
    std::string ruleName;
    std::string stringId;
    std::string matchValue;
    uint64_t offset;
    uint64_t length;
};

struct ScanCallbackData {
    std::string fileName;
    std::vector<ScanMatch> matches;
};

static std::string EscapeCsvField(const std::string& field)
{
    bool needsQuotes = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needsQuotes = true;
            break;
        }
    }

    if (!needsQuotes) {
        return field;
    }

    std::string escaped = "\"";
    for (char c : field) {
        if (c == '"')
            escaped += "\"\"";
        else
            escaped += c;
    }

    escaped += "\"";
    return escaped;
}

static std::string FormatResultsAsCsv(const ScanCallbackData& data)
{
    std::string csv = "File,Rule,StringID,MatchValue,Offset,Length\n";

    for (const auto& match : data.matches) {
        csv += EscapeCsvField(data.fileName) + ",";
        csv += EscapeCsvField(match.ruleName) + ",";
        csv += EscapeCsvField(match.stringId) + ",";
        csv += EscapeCsvField(match.matchValue) + ",";

        char offsetBuf[32];
        snprintf(offsetBuf, sizeof(offsetBuf), "0x%llX", (unsigned long long) match.offset);
        csv += offsetBuf;
        csv += ",";

        csv += std::to_string(match.length) + "\n";
    }

    return csv;
}

static int ScanCallback(void* context, int message, void* message_data, void* user_data)
{
    ScanCallbackData* callbackData = static_cast<ScanCallbackData*>(user_data);
    if (!callbackData) {
        return CALLBACK_CONTINUE;
    }

    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }

    YR_SCAN_CONTEXT* scanContext = static_cast<YR_SCAN_CONTEXT*>(context);
    YR_RULE* rule                = static_cast<YR_RULE*>(message_data);

    YR_STRING* string;
    yr_rule_strings_foreach(rule, string)
    {
        YR_MATCH* match;
        yr_string_matches_foreach(scanContext, string, match)
        {
            ScanMatch scanMatch;
            scanMatch.ruleName = rule->identifier;
            scanMatch.stringId = string->identifier;
            scanMatch.offset   = match->offset;
            scanMatch.length   = match->data_length;

            const uint8_t* data = match->data;
            size_t dataLen      = static_cast<size_t>(match->data_length);
            size_t truncatedLen = dataLen < MAX_MATCH_DISPLAY_LENGTH ? dataLen : MAX_MATCH_DISPLAY_LENGTH;

            for (size_t i = 0; i < truncatedLen; i++) {
                char c = static_cast<char>(data[i]);
                scanMatch.matchValue += (c >= 32 && c < 127) ? c : '.';
            }

            if (dataLen > MAX_MATCH_DISPLAY_LENGTH) {
                scanMatch.matchValue += "...";
            }

            callbackData->matches.push_back(scanMatch);
        }
    }

    return CALLBACK_CONTINUE;
}

void YaraDialog::ScanWithYara()
{
    if (ruleFiles.empty()) {
        AppCUI::Dialogs::MessageBox::ShowWarning("Yara", "Please add at least one rule file!");
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

    ScanCallbackData callbackData;
    callbackData.fileName = scanTarget.filename().string();

    if (context == ScanContext::SingleFile) {
        GView::Yara::YaraScanner yaraScanner(yaraRules, ScanCallback, &callbackData);
        yaraScanner.ScanBuffer(object->GetData().GetEntireFile());
    } else {
        // TODO: Scan folder recursively - iterate files, scan each, collect results
        AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "Folder scanning - Not yet implemented");
        return;
    }

    // Save all used rules to recently used only after successful scan
    for (const auto& ruleFile : ruleFiles) {
        PersistRecentlyUsed(ruleFile, false);
    }

    if (callbackData.matches.empty()) {
        AppCUI::Dialogs::MessageBox::ShowNotification("Yara", "Scan completed! No matches found.");
        return;
    }

    std::string csv = FormatResultsAsCsv(callbackData);
    BufferView resultView(csv.data(), static_cast<uint32>(csv.size()));
    GView::App::OpenBuffer(resultView, "Yara Scan Results", "yara_results.csv", GView::App::OpenMethod::FirstMatch, "csv");

    Exit();
}

} // namespace GView::GenericPlugins::Yara

// ============================================================================
// Plugin Registration
// ============================================================================

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Yara") {
        std::filesystem::path target = object->GetPath();
        bool isFolder                = object->GetObjectType() == GView::Object::Type::Folder;
        auto ctx                     = isFolder ? GView::GenericPlugins::Yara::ScanContext::Folder : GView::GenericPlugins::Yara::ScanContext::SingleFile;

        GView::GenericPlugins::Yara::YaraDialog dlg(object, ctx, target);
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
