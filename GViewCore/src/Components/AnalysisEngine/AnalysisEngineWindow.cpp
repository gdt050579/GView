#include "AnalysisEngineWindow.hpp"

using namespace GView::Components::AnalysisEngine;

constexpr int32 COMMAND_CLOSE    = 0;
constexpr int32 COMMAND_GET_HINT = 1;

AnalysisEngineWindow::AnalysisEngineWindow(Reference<RuleEngine> engine)
    : Window("Analysis Engine", "t:1,l:1,r:1,b:1", Controls::WindowFlags::Sizeable), engine(engine)
{
    tree_data_needs_rebuild = true;
    detailsTree =
          Factory::TreeView::Create(this, "l:0,t:0,r:0,b:5", { "n:Subj.,w:8", "n:Conf.,w:6", "n:Action,w:25", "n:Message,w:fill" }, TreeViewFlags::Searchable);
    detailsTree->Handlers()->OnCurrentItemChanged = this;
    detailsTree->Handlers()->OnItemPressed        = this;
    // windowTree->Handlers()->OnCurrentItemChanged = this;

    // listView = Factory::ListView::Create(
    //       this, "x:1,y:1,w:99%,h:70%", { "n:RuleID,w:10%", "n:Confidence,w:10%", "n:Action,w:20%", "n:Message,w:59%" }, ListViewFlags::PopupSearchBar);

    auto y = detailsTree->GetHeight() + 1;
    LocalString<128> ls;
    ls.Format("x:1,y:%d, w:99", y);
    statusLabel = Factory::Label::Create(this, "Press F12 to get hints", ls.GetText());

    y += 1;
    ls.Format("x:1,y:%d, w:99", y);
    predicatesLabel = Factory::Label::Create(this, "Predicates: ", ls.GetText());

    // listView->Handlers()->OnItemPressed        = this;
    // listView->Handlers()->OnCurrentItemChanged = this;

    // listView->DeleteAllItems();

    DrawSuggestions();
}

bool AnalysisEngineWindow::OnEvent(AppCUI::Utils::Reference<Control> reference, AppCUI::Controls::Event eventType, int ID)
{
    switch (eventType) {
    case Event::Command: {
        switch (ID) {
        case COMMAND_CLOSE:
            Exit(Dialogs::Result::Cancel);
            return true;
        case COMMAND_GET_HINT:
            GetHint();
            return true;
        default:
            break;
        }
        break;
    }
    case Event::ButtonClicked:
    case Event::WindowAccept:
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;

    default:
        return false;
    }
    return false;
}

bool AnalysisEngineWindow::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Input::Key::Escape, "Close", COMMAND_CLOSE);
    commandBar.SetCommand(Input::Key::F12, "GetHint", COMMAND_GET_HINT);
    return true;
}

void AnalysisEngineWindow::OnTreeViewCurrentItemChanged(Reference<Controls::TreeView> tree, TreeViewItem& item)
{
    if (!item.IsValid())
        return;
    const auto data = item.GetData<LineData>();
    if (!data.IsValid())
        return;
    //DrawPredicatesForCurrentIndex(static_cast<uint32>(index));
}

void AnalysisEngineWindow::OnTreeViewItemPressed(Reference<Controls::TreeView> tree, TreeViewItem& item)
{
    if (!item.IsValid())
        return;
    auto data = item.GetData<LineData>();
    if (!data.IsValid())
        return;
    bool shouldCloseAnalysisWindow = false;
    if (!engine->TryExecuteSuggestionBySuggestionId(data->suggestion_id, shouldCloseAnalysisWindow)) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Found error");
        return;
    }

    predicatesLabel->SetText("Predicates: ");
    DrawSuggestions();
    data->subject       = "";
    data->suggestion_id = 0;
    data->confidence    = "";
    data->action        = "";
    item.SetData<LineData>(nullptr);

    if (shouldCloseAnalysisWindow) {
        tree_data_needs_rebuild = true;
        Exit(Dialogs::Result::Ok);
    }
    RebuildTreeData();
}

//void AnalysisEngineWindow::OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item)
//{
//    if (!item.IsValid())
//        return;
//    const auto index = item.GetData(UINT64_MAX);
//    if (index == UINT64_MAX)
//        return;
//    bool shouldCloseAnalysisWindow = false;
//    if (!engine->TryExecuteSuggestionByArrayIndex(static_cast<uint32>(index), shouldCloseAnalysisWindow)) {
//        Dialogs::MessageBox::ShowNotification("Suggestion error", "Found error");
//        return;
//    }
//    predicatesLabel->SetText("Predicates: ");
//    DrawSuggestions();
//    if (shouldCloseAnalysisWindow) {
//        Exit(Dialogs::Result::Ok);
//    }
//}

//void AnalysisEngineWindow::OnListViewCurrentItemChanged(Reference<Controls::ListView> lv, Controls::ListViewItem item)
//{
//    if (!item.IsValid())
//        return;
//    const auto index = item.GetData(UINT64_MAX);
//    if (index == UINT64_MAX)
//        return;
//    DrawPredicatesForCurrentIndex(static_cast<uint32>(index));
//}

void AnalysisEngineWindow::BeforeOpen()
{
    if (!tree_data_needs_rebuild)
        return;
    tree_data_needs_rebuild = true;
    RebuildTreeData();

    // DrawSuggestions();
}

void AnalysisEngineWindow::RegisterSubjectWithParent(const Subject& currentWindow, Reference<Subject> parentWindow)
{
    const bool already_inside = subjects_hierarchy.contains(currentWindow.value);
    assert(!already_inside); // Should not re-register existing subject

    SubjectParentInfo info;
    info.direct_parent                      = parentWindow ? parentWindow->value : 1;
    info.main_parent                        = parentWindow ? FindMainParent(parentWindow->value) : 1;
    subjects_hierarchy[currentWindow.value] = info;
    windows[currentWindow.value]            = currentWindow;

    window_data[currentWindow.value] = WindowData();
}

uint64 AnalysisEngineWindow::FindMainParent(uint64 current_subject)
{
    uint64 subject = current_subject;
    while (true) {
        auto it = subjects_hierarchy.find(subject);
        if (it == subjects_hierarchy.end())
            break;
        if (it->first == 1)
            break;
        subject = it->first;
    }
    return subject;
}

void AnalysisEngineWindow::GetHint()
{
    if (!engine.IsValid()) {
        Dialogs::MessageBox::ShowError("Invalid state", "Invalid rule engine!");
        return;
    }
    auto w           = Application::GetCurrentWindow();
    auto w_interface = w.ToObjectRef<View::WindowInterface>();

    auto subject = w_interface->GetCurrentWindowSubject();

    auto suggestions = engine->evaluate(subject);

    if (suggestions.empty()) {
        statusLabel->SetText("Received no new suggestions!");
    } else {
        LocalString<128> ls;
        ls.Format("Received %u new suggestions", (uint32) suggestions.size());
        statusLabel->SetText(ls.GetText());

        auto& window_data_entry = window_data[subject->value];
        for (const auto& suggestion : suggestions) {

            LineData line_data;
            line_data.confidence = std::to_string(suggestion.confidence);

            const auto &first_result = suggestion.results[0];
            std::string first_result_name;
            if (first_result.type == PredOrAction::PredOrActionType::Action) {
                first_result_name = engine->GetActName(first_result.data.action_id);
            } else {
                first_result_name = "NoAction";
            }
            line_data.action = first_result_name;
            line_data.message = suggestion.message;
            line_data.suggestion_id = suggestion.id;
            window_data_entry.data.push_back(std::move(line_data));
        }
        RebuildTreeData();
        DrawSuggestions();
    }
}

void AnalysisEngineWindow::DrawSuggestions()
{
    /*listView->DeleteAllItems();
    auto available_suggestions = engine->GetAllAvailableSuggestions();
    if (available_suggestions.empty())
        return;
    for (uint32 i = 0; i < available_suggestions.size(); i++) {
        const auto& s                = available_suggestions[i];
        std::string_view action_name = "NoAction!!";
        for (const auto& result : s.results) {
            if (result.type == PredOrAction::PredOrActionType::Action) {
                action_name = engine->GetActName(result.data.action_id);
                break;
            }
        }
        std::string rule_id                            = std::to_string(s.rule_id);
        const auto confidence                          = std::to_string(s.confidence);
        const std::initializer_list<ConstString> items = { rule_id, confidence, action_name, s.message };
        auto new_item                                  = listView->AddItem(items);
        new_item.SetData(i);
    }
    DrawPredicatesForCurrentIndex(0);*/
}

void AnalysisEngineWindow::DrawPredicatesForCurrentIndex(uint32 index)
{
    LocalString<512> ls;
    const auto& suggestions = engine->GetAllAvailableSuggestions();
    if (index >= suggestions.size()) {
        ls.Format("Invalid index: %u", index);
        predicatesLabel->SetText(ls.GetText());
        return;
    }
    const auto& s         = engine->GetAllAvailableSuggestions()[index];
    auto predicate_string = engine->GetRulePredicates(s.rule_id);

    ls.Format("Predicates: %s", predicate_string.c_str());
    predicatesLabel->SetText(ls.GetText());
}

void AnalysisEngineWindow::RebuildTreeData()
{
    detailsTree->ClearItems();
    tree_data.clear();

    for (auto& window : window_data) {
        auto& subject_data              = windows[window.first];
        std::string initial_val         = std::to_string(subject_data.value);
        TreeWindowData tree_window_data = {};
        tree_window_data.parent         = subjects_hierarchy[window.first].direct_parent;
        if (tree_window_data.parent != 1) {
            tree_window_data.parent_handle = tree_data[tree_window_data.parent].handle;
            tree_window_data.handle        = tree_window_data.parent_handle.AddChild(initial_val);
        } else {
            tree_window_data.handle = detailsTree->AddItem(initial_val);
        }

        tree_window_data.handle.SetData<LineData>(nullptr);

        for (auto& data : window.second.data) {
            std::string default_name = "-";
            if (!data.subject.empty())
                default_name = data.subject;

            const bool expandable = data.suggestion_id != 0;
            auto entry            = tree_window_data.handle.AddChild(default_name);
            if (!data.confidence.empty())
                entry.SetText(1,data.confidence);
            if (!data.action.empty())
                entry.SetText(2, data.action);
            if (!data.message.empty())
                entry.SetText(3, data.message);

            if (expandable)
                entry.SetData<LineData>(&data);
            else
                entry.SetData<LineData>(nullptr);

        }
        tree_data[window.first] = std::move(tree_window_data);
    }
}