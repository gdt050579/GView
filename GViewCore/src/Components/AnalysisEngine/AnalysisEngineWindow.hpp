#pragma once
#include "AnalysisEngine.hpp"

namespace GView::Components::AnalysisEngine
{

struct TreeWindowData
{
    uint64 parent;
    TreeViewItem parent_handle, handle;
};

struct LineData
{
    std::string subject;
    std::string confidence;
    std::string action;
    std::string message;

    bool was_suggestion;
    SuggestionId suggestion_id;
};

struct WindowData
{
    std::vector<LineData> data;
};

class AnalysisEngineWindow : public Controls::Window, Handlers::OnTreeViewCurrentItemChangedInterface, Handlers::OnTreeViewItemPressedInterface
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

    std::unordered_map<uint64, SubjectParentInfo> subjects_hierarchy;
    std::unordered_map<uint64, Subject> windows;
    std::unordered_map<uint64, WindowData> window_data;
    std::map<uint64, TreeWindowData> tree_data;

};
}