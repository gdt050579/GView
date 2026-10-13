#pragma once

// The HDF window (Alt+F12): four analyst views driven only by the read-only views of the current disclosure session.
//   Subject - the subject tree (ExtractedFrom), each subject with its assertions (den, expl) and its selectable actions
//   Actions - the disclosure trace, one row per transition
//   Summary - the LLM selection assistant over Selectable(Gamma_i) (never executes by itself)
//   Report  - the explanation E of I(Gamma_i, tau) and the derivation tree of the selected assertion

#include "Engine.hpp"
#include "SummaryAssistant.hpp"

namespace GView::HDF
{
class HDFWindow : public AppCUI::Controls::Window,
                  public AppCUI::Controls::Handlers::OnTreeViewCurrentItemChangedInterface,
                  public AppCUI::Controls::Handlers::OnTreeViewItemPressedInterface
{
    enum class ItemKind : uint8 { None = 0, Subject = 1, Assertion = 2, Action = 3 };

    Engine& engine;
    DisclosureSession* session{ nullptr };
    Reference<AppCUI::Controls::Tab> tabs;
    Reference<AppCUI::Controls::TreeView> subjectTree;
    Reference<AppCUI::Controls::ListView> actionsList;
    Reference<AppCUI::Controls::TextArea> summaryText;
    Reference<AppCUI::Controls::TextArea> reportText;
    Reference<AppCUI::Controls::Label> statusLabel;
    Reference<AppCUI::Controls::Label> detailsLabel;
    Reference<AppCUI::Controls::CheckBox> closeOnNewSubject;
    std::vector<GroundActionId> recommended;
    uint64 selectedKey{ 0 };
    Reference<AppCUI::Controls::Window> focusAfterClose;

    static inline uint64 Key(ItemKind kind, uint32 id)
    {
        return (static_cast<uint64>(kind) << 32) | id;
    }
    static inline ItemKind KindOf(uint64 key)
    {
        return static_cast<ItemKind>(key >> 32);
    }
    static inline uint32 IdOf(uint64 key)
    {
        return static_cast<uint32>(key & 0xFFFFFFFFu);
    }

    void RebuildAll();
    void RebuildSubjectTree();
    void RebuildActions();
    void RebuildReport();
    void RefreshStatus();
    void RefreshSummary();
    void ExecuteAction(GroundActionId beta);
    void ExecuteRecommended();
    void FinishSession();

  public:
    explicit HDFWindow(Engine& engine);
    // selects the disclosure session of subject (or the most recent one), rebuilds the views and shows the window (modal)
    void Open(Subject current);

    bool OnEvent(Reference<Control> control, AppCUI::Controls::Event eventType, int ID) override;
    bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
    void OnTreeViewCurrentItemChanged(Reference<AppCUI::Controls::TreeView> tree, AppCUI::Controls::TreeViewItem& item) override;
    void OnTreeViewItemPressed(Reference<AppCUI::Controls::TreeView> tree, AppCUI::Controls::TreeViewItem& item) override;
};

} // namespace GView::HDF
