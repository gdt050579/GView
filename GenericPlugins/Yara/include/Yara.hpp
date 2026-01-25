#pragma once

#include "GView.hpp"
#include <vector>
#include <filesystem>
#include <ctime>
#include <algorithm>

namespace GView::GenericPlugins::Yara
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;

struct RecentEntry {
    std::filesystem::path path;
    bool isFolder;
    time_t lastUsed;
};

enum class ScanContext { SingleFile, Folder };

/**
 * Selection dialog for recently used YARA rules.
 *
 * Presents a list of previously used rule files/folders for quick reuse.
 * Supports both multi-selection (checkboxes) and single-click actions.
 */
class RecentRulesDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    const std::vector<RecentEntry>& recentList;
    Reference<ListView> recentListView;
    Reference<TextField> fullPathField;
    Reference<Button> confirmButton;
    Reference<Button> cancelButton;
    std::vector<RecentEntry> selectedEntries;

  public:
    RecentRulesDialog(const std::vector<RecentEntry>& recentList);
    void OnButtonPressed(Reference<Button> b) override;
    bool OnEvent(Reference<Control> control, Event eventType, int id) override;
    const std::vector<RecentEntry>& GetSelectedEntries() const
    {
        return selectedEntries;
    }

  private:
    void UpdateFullPathField();
    void OnConfirmSelected();
};

/**
 * Provides a context-aware dialog to configure and execute YARA scans.
 * Adapts to scanning either a single file or an entire directory based on input.
 *
 * Key Features:
 * - Add rules from files, folders, or recent history
 * - Adapts to scanning either a single file or an entire directory
 * - Generates CSV results and opens them in Table Viewer
 */
class YaraDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;

    // === Context-aware scan target (determined at construction) ===
    ScanContext context;
    std::filesystem::path scanTarget;

    // === Rule controls ===
    Reference<ListView> rulesListView;
    Reference<Button> addFileButton;
    Reference<Button> addFolderButton;
    Reference<Button> addRecentButton;
    Reference<Button> removeButton;

    // === Action controls ===
    Reference<Button> scanButton;
    Reference<Button> closeButton;

    // === Rule tracking ===
    std::vector<std::filesystem::path> ruleFiles;
    std::vector<RecentEntry> recentlyUsedList;
    static constexpr size_t MAX_RECENT_ENTRIES = 10;

  public:
    YaraDialog(Reference<GView::Object> object, ScanContext ctx, const std::filesystem::path& target);
    void OnButtonPressed(Reference<Button> b) override;
    bool OnEvent(Reference<Control> control, Event eventType, int id) override;

  private:
    // === Rule Management ===
    void AddRuleFile();
    void AddRuleFolder();
    void AddRecentRules();
    void RemoveRuleFile();
    void UpdateRulesListView();
    void LoadRulesFromFolder(const std::filesystem::path& folderPath, std::vector<std::string>& errors);

    // === Recently used persistence ===
    void RestoreRecentlyUsed();
    void PersistRecentlyUsed(const std::filesystem::path& path, bool isFolder);

    // === Scanning ===
    void ScanWithYara();
};

} // namespace GView::GenericPlugins::Yara
