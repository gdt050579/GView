#include "HDFWindow.hpp"
#include "Explanation.hpp"

#include <unordered_map>
#include <unordered_set>

using namespace AppCUI::Controls;
using namespace AppCUI::Input;

namespace GView::HDF
{
namespace
{
    constexpr int32 COMMAND_CLOSE             = 1;
    constexpr int32 COMMAND_REFRESH_SUMMARY   = 2;
    constexpr int32 COMMAND_FINISH            = 3;
    constexpr int32 COMMAND_REBUILD           = 4;
    constexpr int32 COMMAND_RUN_RECOMMENDED   = 5;
    constexpr uint32 MAX_DISCLOSED_TEXT       = 2000;
    constexpr uint32 MAX_TREE_ASSERTIONS      = 5000; // per subject (the tree stays usable on huge sessions)
    constexpr std::string_view NO_SESSION_MSG = "No disclosure session: open a file first.";
} // namespace

HDFWindow::HDFWindow(Engine& hdf) : Window("HDF - Hybrid Disclosure Framework", "t:1,l:1,r:1,b:1", WindowFlags::Sizeable), engine(hdf)
{
    tabs             = Factory::Tab::Create(this, "l:0,t:0,r:0,b:5");
    auto subjectPage = Factory::TabPage::Create(tabs, "&Subject");
    auto actionsPage = Factory::TabPage::Create(tabs, "&Actions");
    auto summaryPage = Factory::TabPage::Create(tabs, "S&ummary");
    auto reportPage  = Factory::TabPage::Create(tabs, "&Report");

    subjectTree = Factory::TreeView::Create(
          subjectPage, "l:0,t:0,r:0,b:0", { "n:Subject / assertion / action,w:60", "n:Symbol,w:24", "n:Source,w:fill" }, TreeViewFlags::Searchable);
    subjectTree->Handlers()->OnCurrentItemChanged = this;
    subjectTree->Handlers()->OnItemPressed        = this;

    actionsList = Factory::ListView::Create(
          actionsPage,
          "l:0,t:0,r:0,b:0",
          { "n:Step,w:6", "n:Transition,w:40", "n:Status,w:10", "n:Disclosed,w:10", "n:Derived,w:8", "n:|Gamma|,w:8", "n:Assertions,w:fill" },
          ListViewFlags::PopupSearchBar);

    summaryText = Factory::TextArea::Create(
          summaryPage,
          "Press Ctrl+R to ask the smart assistant which selectable action to execute next.",
          "l:0,t:0,r:0,b:0",
          TextAreaFlags::Readonly | TextAreaFlags::ScrollBars);
    reportText = Factory::TextArea::Create(reportPage, "", "l:0,t:0,r:0,b:0", TextAreaFlags::Readonly | TextAreaFlags::ScrollBars);

    statusLabel       = Factory::Label::Create(this, "", "l:1,b:3,r:1,h:1");
    detailsLabel      = Factory::Label::Create(this, "", "l:1,b:2,r:1,h:1");
    closeOnNewSubject = Factory::CheckBox::Create(this, "Close this window when an action opens a new subject", "l:1,b:1,w:70");
    closeOnNewSubject->SetChecked(true);
}

void HDFWindow::Open(Subject current)
{
    session = engine.SessionOf(current);
    if (!session && engine.SessionsCount() > 0)
        session = &engine.SessionAt(engine.SessionsCount() - 1);
    recommended.clear();
    focusAfterClose.Reset();
    RebuildAll();
    Show();
    if (focusAfterClose.IsValid())
        focusAfterClose->SetFocus();
}

void HDFWindow::RebuildAll()
{
    RebuildSubjectTree();
    RebuildActions();
    RebuildReport();
    RefreshStatus();
}

void HDFWindow::RefreshStatus()
{
    if (!session) {
        statusLabel->SetText(NO_SESSION_MSG);
        return;
    }
    // the decision the session computed after its last transition (the one the stopping policy saw)
    std::string text = "Interpretation: " + ExplanationFormatter::DecisionSummary(session->LastDecision(), engine.Spec().interpretation, session->Registry());
    text += " | |Gamma| = " + std::to_string(session->Gamma().Size()) + " | Selectable = " + std::to_string(session->Selectable().size()) +
            " | steps = " + std::to_string(session->Trace().ActionCount());
    if (session->IsFinished())
        text += " | finished: " + std::string(StopReasonName(session->GetStopReason()));
    if (engine.LoadDiagnostics().HasErrors())
        text += " | HDF.json has " + std::to_string(engine.LoadDiagnostics().ErrorCount()) + " error(s)";
    statusLabel->SetText(text);
}

void HDFWindow::RebuildSubjectTree()
{
    // keep the expanded items and the current item across rebuilds (keys are stable: subject / assertion / action ids)
    std::unordered_set<uint64> expanded, seen;
    for (uint32 i = 0; i < subjectTree->GetItemsCount(); i++) {
        auto item = subjectTree->GetItemByIndex(i);
        seen.insert(item.GetData(0));
        if (item.IsExpandable() && !item.IsFolded())
            expanded.insert(item.GetData(0));
    }
    subjectTree->ClearItems();
    if (!session) {
        subjectTree->AddItem(NO_SESSION_MSG);
        return;
    }
    const auto& gamma    = session->Gamma();
    const auto& registry = session->Registry();
    const auto& sig      = session->GetSignature();

    // assertions and selectable actions grouped by their first (Subject) argument
    std::unordered_map<SubjectId, std::vector<AssertionId>> bySubject;
    for (AssertionId a = 0; a < gamma.Size(); a++) {
        const auto p = gamma.Predicate(a);
        if (p == sig.hasName || p == sig.extractedFrom || gamma.Arity(a) == 0)
            continue; // shown by the tree itself
        const auto first = gamma.Args(a)[0];
        if (session->Pool().Kind(first) == SortKind::Subject)
            bySubject[session->Pool().AsSubject(first)].push_back(a);
    }
    std::unordered_map<SubjectId, std::vector<GroundActionId>> actionsBySubject;
    for (const auto beta : session->Selectable()) {
        const auto args = session->Enabled().Args(beta);
        if (!args.empty() && session->Pool().Kind(args[0]) == SortKind::Subject)
            actionsBySubject[session->Pool().AsSubject(args[0])].push_back(beta);
    }

    TreeViewItem current;
    struct Pending {
        SubjectId subject;
        TreeViewItem parent;
    };
    std::vector<Pending> stack{ { session->Root(), TreeViewItem() } };
    while (!stack.empty()) {
        auto [s, parent] = stack.back();
        stack.pop_back();
        if (!registry.IsValid(s))
            continue;
        const auto& entry = registry.Get(s);
        auto node         = parent.IsValid() ? parent.AddChild(entry.name, true) : subjectTree->AddItem(entry.name, true);
        node.SetType(TreeViewItem::Type::Category);
        node.SetData(Key(ItemKind::Subject, s));
        node.SetText(1, "Subject");
        node.SetText(2, entry.window.IsValid() ? "window open" : "");
        if (Key(ItemKind::Subject, s) == selectedKey)
            current = node;
        const auto& assertions = bySubject[s];
        for (size_t i = 0; i < assertions.size() && i < MAX_TREE_ASSERTIONS; i++) {
            const auto a = assertions[i];
            auto child   = node.AddChild(Denotation::Assertion(*session, a));
            child.SetData(Key(ItemKind::Assertion, a));
            child.SetText(1, sig.predicates.Get(gamma.Predicate(a)).name);
            const auto expl = session->Pool().Strings().Get(gamma.Explanation(a));
            child.SetText(2, expl.empty() ? Denotation::Source(*session, a) : std::string(expl));
            if (session->Derivations().Get(a).kind == DerivationKind::Rule)
                child.SetType(sig.predicates.Get(gamma.Predicate(a)).isVerdict ? TreeViewItem::Type::ErrorInformation : TreeViewItem::Type::Highlighted);
            if (Key(ItemKind::Assertion, a) == selectedKey)
                current = child;
        }
        for (const auto beta : actionsBySubject[s]) {
            auto child = node.AddChild(Denotation::Action(*session, beta));
            child.SetData(Key(ItemKind::Action, beta));
            child.SetText(1, "<" + sig.actions.Get(session->Enabled().Get(beta).action).name + ">");
            const bool executable    = engine.HasExecutor(*session, beta);
            const bool isRecommended = std::find(recommended.begin(), recommended.end(), beta) != recommended.end();
            child.SetText(2, !executable ? "no tool can execute it" : (isRecommended ? "recommended (Enter to execute)" : "Enter to execute"));
            child.SetType(executable ? TreeViewItem::Type::Emphasized_2 : TreeViewItem::Type::GrayedOut);
            if (Key(ItemKind::Action, beta) == selectedKey)
                current = child;
        }
        // children in creation order
        for (auto it = entry.children.rbegin(); it != entry.children.rend(); ++it)
            if (session->OwnsSubject(*it))
                stack.push_back({ *it, node });
    }
    // restore folding; subjects that were not in the tree before are expanded
    for (uint32 i = 0; i < subjectTree->GetItemsCount(); i++) {
        auto item = subjectTree->GetItemByIndex(i);
        if (item.IsExpandable())
            item.SetFolding(!seen.contains(item.GetData(0)) || expanded.contains(item.GetData(0)));
    }
    if (current.IsValid())
        current.SetCurrent();
}

void HDFWindow::RebuildActions()
{
    actionsList->DeleteAllItems();
    if (!session)
        return;
    const auto& trace = session->Trace();
    const auto& gamma = session->Gamma();
    for (uint32 t = 0; t < trace.Size(); t++) {
        const auto& tr = trace.transitions[t];
        std::string step, what, status = "success";
        switch (tr.kind) {
        case TransitionKind::InitialExtraction:
            step = "init";
            what = "Init_T(" + (session->Registry().IsValid(tr.subject) ? session->Registry().Get(tr.subject).name : std::string("?")) + ")";
            break;
        case TransitionKind::Observation:
            step = "obs";
            what = "observation: " + std::string(session->Pool().Strings().Get(tr.label));
            break;
        case TransitionKind::Action:
            step = std::to_string(trace.StepIndex(t));
            what = Denotation::Action(*session, tr.action);
            break;
        }
        if (tr.status == ActionStatus::Failed)
            status = "failed";
        else if (tr.status == ActionStatus::Cancelled)
            status = "cancelled";
        const uint32 completion = tr.completionAssertion != INVALID_ASSERTION_ID ? 1 : 0;
        const uint32 disclosed  = tr.disclosedEnd - tr.disclosedBegin + completion;
        const uint32 derived    = tr.toCount - tr.disclosedEnd - completion;
        std::string assertions;
        for (AssertionId a = tr.disclosedBegin; a < tr.toCount && a < gamma.Size() && assertions.size() < MAX_DISCLOSED_TEXT; a++) {
            if (gamma.Predicate(a) == session->GetSignature().hasName)
                continue;
            if (!assertions.empty())
                assertions += "; ";
            assertions += Denotation::Assertion(*session, a);
        }
        if (tr.closureIncomplete)
            status += " (closure capped)";
        actionsList->AddItem({ step, what, status, std::to_string(disclosed), std::to_string(derived), std::to_string(tr.toCount), assertions });
    }
}

void HDFWindow::RebuildReport()
{
    if (!session) {
        reportText->SetText(NO_SESSION_MSG);
        return;
    }
    const auto& interpretation = engine.Spec().interpretation;
    auto text                  = ExplanationFormatter::ToMarkdown(Explanation::Build(*session, interpretation, session->Root()), interpretation);
    if (KindOf(selectedKey) == ItemKind::Assertion && IdOf(selectedKey) < session->Gamma().Size()) {
        const auto a = IdOf(selectedKey);
        text += "\n## Derivation tree of the selected assertion\n" + Denotation::Atom(*session, a) + "\n" +
                ExplanationFormatter::DerivationTreeText(*session, DerivationTree::Build(session->Derivations(), a));
    }
    reportText->SetText(text);
}

void HDFWindow::RefreshSummary()
{
    if (!session) {
        summaryText->SetText(NO_SESSION_MSG);
        return;
    }
    // the smart assistants of the window of the subject (or of any open window of the session)
    GView::CommonInterfaces::SmartAssistants::SmartAssistantPromptInterface* assistant = nullptr;
    std::vector<SubjectId> subjects;
    session->Registry().Descendants(session->Root(), subjects);
    for (const auto s : subjects) {
        auto win = engine.WindowOf(s);
        if (!win.IsValid())
            continue;
        auto wi = win.ToObjectRef<GView::View::WindowInterface>();
        if (!wi.IsValid())
            continue;
        auto query = wi->GetQueryInterface();
        if (query.IsValid() && (assistant = query->GetSmartAssistantInterface()) != nullptr)
            break;
    }
    const auto selectable = std::vector<GroundActionId>(session->Selectable().begin(), session->Selectable().end());
    const auto result     = SummaryAssistant::Request(*session, selectable, assistant);
    if (!result.success) {
        summaryText->SetText("The summary request failed (no smart assistant is configured, or LLM hints are disabled by the course policy).");
        return;
    }
    recommended      = result.recommended;
    std::string text = result.narrative;
    if (!recommended.empty()) {
        text += "\n\nRecommended (Ctrl+E executes the first one that is still selectable, or press Enter on it in the Subject tab):\n";
        for (const auto beta : recommended)
            text += "  - " + Denotation::Action(*session, beta) + "\n";
    }
    summaryText->SetText(text);
    RebuildSubjectTree();
}

void HDFWindow::ExecuteAction(GroundActionId beta)
{
    if (!session || beta >= session->Enabled().Size())
        return;
    if (session->Enabled().Get(beta).action == session->GetSignature().reanalyzeSelection) {
        AppCUI::Dialogs::MessageBox::ShowNotification(
              "HDF", "ReanalyzeSelection needs a selected range: select it in a viewer of the subject and press Enter (open selection).");
        return;
    }
    if (!engine.HasExecutor(*session, beta)) {
        AppCUI::Dialogs::MessageBox::ShowError("HDF", "No tool can execute this action (no plugin registered an executor for it).");
        return;
    }
    const auto subjectsBefore = session->Registry().Count();
    const auto r              = engine.Step(*session, beta);
    if (r.status != StepStatus::Executed) {
        AppCUI::Dialogs::MessageBox::ShowError("HDF", StepStatusName(r.status));
        return;
    }
    std::erase(recommended, beta);
    // a new subject with a window: show it (the analyst continues there)
    Reference<AppCUI::Controls::Window> opened;
    for (SubjectId s = subjectsBefore; s < session->Registry().Count(); s++)
        if (session->Registry().Get(s).window.IsValid())
            opened = session->Registry().Get(s).window;
    if (r.actionStatus != ActionStatus::Success)
        AppCUI::Dialogs::MessageBox::ShowWarning(
              "HDF",
              r.actionStatus == ActionStatus::Failed ? "The action failed (recorded in the trace, no completion assertion)."
                                                     : "The action was cancelled (recorded in the trace).");
    RebuildAll();
    if (opened.IsValid() && closeOnNewSubject->IsChecked()) {
        focusAfterClose = opened;
        Exit(Dialogs::Result::Ok);
    }
}

void HDFWindow::ExecuteRecommended()
{
    if (!session)
        return;
    for (const auto beta : recommended)
        if (!session->IsCompleted(beta)) {
            ExecuteAction(beta);
            return;
        }
    AppCUI::Dialogs::MessageBox::ShowNotification("HDF", "No recommended action is selectable (press Ctrl+R in the Summary tab first).");
}

void HDFWindow::FinishSession()
{
    if (!session || session->IsFinished())
        return;
    if (AppCUI::Dialogs::MessageBox::ShowOkCancel("HDF", "Finish the disclosure process of this subject (manual stop)? The session is frozen.") !=
        Dialogs::Result::Ok)
        return;
    session->Finish(StopReason::ManualStop);
    RebuildAll();
    tabs->SetCurrentTabPageByIndex(3);
}

bool HDFWindow::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command) {
        switch (ID) {
        case COMMAND_CLOSE:
            Exit(Dialogs::Result::Cancel);
            return true;
        case COMMAND_REFRESH_SUMMARY:
            RefreshSummary();
            return true;
        case COMMAND_FINISH:
            FinishSession();
            return true;
        case COMMAND_REBUILD:
            RebuildAll();
            return true;
        case COMMAND_RUN_RECOMMENDED:
            ExecuteRecommended();
            return true;
        default:
            break;
        }
    }
    if (eventType == Event::WindowClose || eventType == Event::WindowAccept) {
        Exit(Dialogs::Result::Cancel);
        return true;
    }
    return Window::OnEvent(control, eventType, ID);
}

bool HDFWindow::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Escape, "Close", COMMAND_CLOSE);
    commandBar.SetCommand(Key::F5, "Rebuild", COMMAND_REBUILD);
    commandBar.SetCommand(Key::Ctrl | Key::R, "Summary", COMMAND_REFRESH_SUMMARY);
    commandBar.SetCommand(Key::Ctrl | Key::E, "RunRecommended", COMMAND_RUN_RECOMMENDED);
    commandBar.SetCommand(Key::Ctrl | Key::F, "Finish", COMMAND_FINISH);
    return true;
}

void HDFWindow::OnTreeViewCurrentItemChanged(Reference<TreeView> tree, TreeViewItem& item)
{
    // TreeViewItem::IsValid only checks the control: ClearItems reports an item with an invalid handle (empty tree)
    if (!item.IsValid() || !session || tree->GetItemsCount() == 0)
        return;
    selectedKey   = item.GetData(0);
    const auto id = IdOf(selectedKey);
    std::string details;
    switch (KindOf(selectedKey)) {
    case ItemKind::Assertion:
        if (id < session->Gamma().Size())
            details = Denotation::Atom(*session, id) + "  [" + Denotation::Source(*session, id) + "]";
        break;
    case ItemKind::Action:
        if (id < session->Enabled().Size()) {
            const auto& ga = session->Enabled().Get(id);
            details        = Denotation::ActionAtom(*session, id);
            if (ga.rule < session->GetSpecification().actionRules.size()) {
                const auto& rule = session->GetSpecification().actionRules[ga.rule];
                details += "  enabled by " + rule.name + ": " + session->GetSpecification().FormatRule(rule, session->GetSignature(), session->Pool());
            }
        }
        break;
    case ItemKind::Subject:
        if (session->Registry().IsValid(id)) {
            const auto path = session->Registry().ProvenancePath(id, session->Root());
            for (size_t i = path.size(); i-- > 0;)
                details += session->Registry().Get(path[i]).name + (i > 0 ? " -> " : "");
        }
        break;
    default:
        break;
    }
    detailsLabel->SetText(details);
    RebuildReport();
}

void HDFWindow::OnTreeViewItemPressed(Reference<TreeView> tree, TreeViewItem& item)
{
    if (!item.IsValid() || !session || tree->GetItemsCount() == 0)
        return;
    const auto key = item.GetData(0);
    if (KindOf(key) == ItemKind::Action)
        ExecuteAction(IdOf(key));
}

} // namespace GView::HDF
