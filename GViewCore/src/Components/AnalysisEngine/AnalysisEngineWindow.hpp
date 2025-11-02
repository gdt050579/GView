#pragma once
#include "AnalysisEngine.hpp"

namespace GView::Components::AnalysisEngine
{

struct TreeWindowData
{
    uint64 parent;
    TreeViewItem parent_handle;
    TreeViewItem handle;
};

struct LineData
{
    std::string subject;
    std::string confidence;
    std::string action;
    std::string message;

    bool was_suggestion;
    SuggestionId suggestion_id;
    ActId action_id;
};

struct WindowData
{
    std::vector<LineData> data;
};

struct Owner {
    enum class Type : uint8 {
        Subject = 0,
        Action  = 1,
    };
    Type type;
};

struct ActionData
{
    ActId id;
    LineData data;
};

struct SubjectData
{
    Subject subject;
    std::string name;
};
using ActionSubjectVariant = std::variant<SubjectData, ActionData>;
struct EntryLineData;
struct EntryContainerData {
    ActionSubjectVariant type;
    std::shared_ptr<EntryLineData> data;

    std::shared_ptr<EntryLineData> owner;
    std::map<ActId, std::shared_ptr<EntryLineData>> actions;

    void ResetOwnerToSelf()
    {
        owner = data;
    }
};

using EntryLineDataEntry = std::variant<std::shared_ptr<LineData>, std::shared_ptr<EntryContainerData>>;
struct EntryLineData
{
    std::vector<EntryLineDataEntry> children;
};


class AnalysisEngineWindow : public Controls::Window, public Handlers::OnTreeViewCurrentItemChangedInterface, public Handlers::OnTreeViewItemPressedInterface
{
  public:
    AnalysisEngineWindow(Reference<RuleEngine> engine);
    bool OnEvent(AppCUI::Utils::Reference<Control>, AppCUI::Controls::Event eventType, int ID) override;
    bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
    //void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;
    //void OnListViewCurrentItemChanged(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;
    void OnTreeViewCurrentItemChanged(Reference<Controls::TreeView> tree, TreeViewItem& item) override;
    void OnTreeViewItemPressed(Reference<Controls::TreeView> tree, TreeViewItem& item) override;
    void BeforeOpen();
    void AddAnalysisNotes(const Subject& currentWindow, std::string data);
    void RegisterSubjectWithParent(const Subject& currentWindow, Reference<Subject> parentWindow);
    uint64 FindMainParent(uint64 current_subject);

  private:
    void GetHint();
    void DrawSuggestions();
    void DrawPredicatesForCurrentIndex(uint32 index);
    void RebuildTreeData();

    Reference<TreeView> detailsTree;
    bool tree_data_needs_rebuild;


    Reference<RuleEngine> engine;
    //Reference<ListView> listView;
    Reference<Label> statusLabel;
    Reference<Label> predicatesLabel;

    std::unordered_map<SubjectId, SubjectParentInfo> subjects_hierarchy;
    std::unordered_map<SubjectId, Subject> windows;
    std::unordered_map<SubjectId, WindowData> window_data;
    std::map<SubjectId, TreeWindowData> tree_data;

    std::map<SubjectId, std::shared_ptr<EntryContainerData>> new_subject_data;

};
}