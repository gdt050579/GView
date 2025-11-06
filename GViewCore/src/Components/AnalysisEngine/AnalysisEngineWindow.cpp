#include "AnalysisEngineWindow.hpp"

using namespace GView::Components::AnalysisEngine;

constexpr int32 COMMAND_CLOSE    = 0;
constexpr int32 COMMAND_GET_HINT = 1;

constexpr uint32 SUBJECT_COLUMN_INDEX = 0;
constexpr uint32 ACTION_COLUMN_INDEX  = 1;
constexpr uint32 MESSAGE_COLUMN_INDEX = 2;

AnalysisEngineWindow::AnalysisEngineWindow(Reference<RuleEngine> engine)
    : Window("Analysis Engine", "t:1,l:1,r:1,b:1", Controls::WindowFlags::Sizeable), engine(engine)
{
    tree_data_needs_rebuild = true;
    detailsTree = Factory::TreeView::Create(this, "l:0,t:0,r:0,b:5", { "n:Subject,w:30", "n:Action,w:25", "n:Assertions,w:fill" }, TreeViewFlags::Searchable);
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
    // DrawPredicatesForCurrentIndex(static_cast<uint32>(index));
}

void SearchForTopEntrySubject(std::shared_ptr<EntryContainerData>& current_entry)
{
}

void AnalysisEngineWindow::OnTreeViewItemPressed(Reference<Controls::TreeView> tree, TreeViewItem& item)
{
    if (!item.IsValid())
        return;
    auto data = item.GetData<LineData>();//EntryContainerData
    if (!data.IsValid())
        return;
    ActId action_id                = data->action_id;
    bool shouldCloseAnalysisWindow = false;
    SuggestionId suggestion_id     = data->suggestion_id;

    data->subject        = "";
    data->suggestion_id  = 0;
    data->confidence     = "";
    data->action         = "";
    data->was_suggestion = true;
    item.SetType(TreeViewItem::Type::WarningInformation);
    item.SetData<LineData>(nullptr);

    auto suggestion = engine->GetSuggestionById(suggestion_id);
    if (!suggestion.IsValid()) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Failed to get suggestion by id");
        return;
    }
    auto parent_subject = new_subject_data[suggestion->subject.value];
    if (!parent_subject) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Failed to get subject data for suggestion!");
        return;
    }

    assert(parent_subject->type.index() == 0); // SubjectData
    auto parent_window = subjects_hierarchy[std::get<SubjectData>(parent_subject->type).subject.value].current_window;
    if (parent_window.IsValid()) {
        parent_window->SetFocus();
    }

    auto action_owner = parent_subject->actions.find(action_id);
    if (action_owner == parent_subject->actions.end()) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Failed to get action data for suggestion!");
        return;
    }
    parent_subject->owner = action_owner->second;

    if (!engine->TryExecuteSuggestionBySuggestionId(suggestion_id, shouldCloseAnalysisWindow)) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Failed to execute suggestion!");
        parent_subject->ResetOwnerToSelf();
        return;
    }

    //parent_subject->ResetOwnerToSelf();
    predicatesLabel->SetText("Predicates: ");
    DrawSuggestions();

    if (shouldCloseAnalysisWindow) {
        tree_data_needs_rebuild = true;
        Exit(Dialogs::Result::Ok);
    }
    RebuildTreeData();
}

// void AnalysisEngineWindow::OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item)
//{
//     if (!item.IsValid())
//         return;
//     const auto index = item.GetData(UINT64_MAX);
//     if (index == UINT64_MAX)
//         return;
//     bool shouldCloseAnalysisWindow = false;
//     if (!engine->TryExecuteSuggestionByArrayIndex(static_cast<uint32>(index), shouldCloseAnalysisWindow)) {
//         Dialogs::MessageBox::ShowNotification("Suggestion error", "Found error");
//         return;
//     }
//     predicatesLabel->SetText("Predicates: ");
//     DrawSuggestions();
//     if (shouldCloseAnalysisWindow) {
//         Exit(Dialogs::Result::Ok);
//     }
// }

// void AnalysisEngineWindow::OnListViewCurrentItemChanged(Reference<Controls::ListView> lv, Controls::ListViewItem item)
//{
//     if (!item.IsValid())
//         return;
//     const auto index = item.GetData(UINT64_MAX);
//     if (index == UINT64_MAX)
//         return;
//     DrawPredicatesForCurrentIndex(static_cast<uint32>(index));
// }

void AnalysisEngineWindow::BeforeOpen()
{
    if (!tree_data_needs_rebuild)
        return;
    tree_data_needs_rebuild = false;
    RebuildTreeData();

    // DrawSuggestions();
}

void AnalysisEngineWindow::AddAnalysisNotes(const Subject& currentWindow, std::string data)
{
    if (data.empty())
        return;

    auto& subject_data_entry = new_subject_data[currentWindow.value];

    auto& window_data_entry = window_data[currentWindow.value];
    LineData line_data      = {};
    line_data.message       = data;
    window_data_entry.data.push_back(line_data);
    tree_data_needs_rebuild = true;

    constexpr const char* opening_string = "Opening ";
    auto name_it                         = data.find(opening_string);
    if (name_it != std::string::npos) {
        auto filename = data.substr(name_it + strlen(opening_string));
        assert(subject_data_entry->type.index() == 0); // SubjectData
        std::get<SubjectData>(subject_data_entry->type).name = filename;
        return;
    }

    auto line_data_ptr = std::make_shared<LineData>(line_data);
    subject_data_entry->owner->children.emplace_back(line_data_ptr);
}

void AnalysisEngineWindow::RegisterSubjectWithParent(const Subject& currentWindowSubject, Reference<Window> currentWindow, Reference<Subject> parentWindow)
{
    const bool already_inside = subjects_hierarchy.contains(currentWindowSubject.value);
    assert(!already_inside); // Should not re-register existing subject

    SubjectParentInfo info;
    info.direct_parent                             = parentWindow ? parentWindow->value : 0;
    info.main_parent                               = parentWindow ? FindMainParent(parentWindow->value) : 0;
    info.current_window                            = currentWindow;
    subjects_hierarchy[currentWindowSubject.value] = info;

    windows[currentWindowSubject.value] = currentWindowSubject;

    if (!window_data.contains(currentWindowSubject.value))
        window_data[currentWindowSubject.value] = WindowData();

    auto subject_data_entry    = SubjectData{};
    subject_data_entry.subject = currentWindowSubject;

    auto container_data_entry   = std::make_shared<EntryContainerData>();
    container_data_entry->type  = std::move(subject_data_entry);
    container_data_entry->data  = std::make_shared<EntryLineData>();
    container_data_entry->owner = container_data_entry->data;
    new_subject_data.insert({ currentWindowSubject.value, container_data_entry });

    if (parentWindow) {
        auto& parent_subject_data = new_subject_data[parentWindow->value];
        parent_subject_data->owner->children.emplace_back(container_data_entry);
    }
}

uint64 AnalysisEngineWindow::FindMainParent(uint64 current_subject)
{
    uint64 subject = current_subject;
    while (true) {
        auto it = subjects_hierarchy.find(subject);
        if (it == subjects_hierarchy.end())
            break;
        if (it->second.main_parent <= 1) // First ID
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
            LineData line_data   = {};
            line_data.confidence = std::to_string(suggestion.confidence);

            const auto& first_result = suggestion.results[0];
            std::string first_result_name;
            if (first_result.type == PredOrAction::PredOrActionType::Action) {
                first_result_name = engine->GetActName(first_result.data.action_id);
            } else {
                first_result_name = "NoAction";
            }
            line_data.action        = first_result_name;
            line_data.message       = suggestion.message;
            line_data.suggestion_id = suggestion.id;

            window_data_entry.data.push_back(line_data);

            auto parent_subject_data = new_subject_data[subject->value];
            if (first_result.type == PredOrAction::PredOrActionType::Action) {
                ActionData action_data            = {};
                action_data.id                    = first_result.data.action_id;
                line_data.action_id               = first_result.data.action_id;
                action_data.data                  = std::move(line_data);
                ActionSubjectVariant variant_data = std::move(action_data);
                auto action_data_ptr              = std::make_shared<EntryContainerData>();
                action_data_ptr->type             = std::move(variant_data);
                action_data_ptr->data             = std::make_shared<EntryLineData>();
                action_data_ptr->owner            = action_data_ptr->data;
                parent_subject_data->owner->children.emplace_back(action_data_ptr);
                parent_subject_data->actions[first_result.data.action_id] = action_data_ptr->data;
            } else {
                auto line_data_ptr = std::make_shared<LineData>(std::move(line_data));
                parent_subject_data->owner->children.emplace_back(line_data_ptr);
            }
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

void PopulateTreeDataFromLineData(TreeViewItem handle, LineData* data)
{
    if (!data->subject.empty())
        handle.SetText(SUBJECT_COLUMN_INDEX, data->subject);
    if (!data->action.empty())
        handle.SetText(ACTION_COLUMN_INDEX, data->action);
    if (!data->message.empty())
        handle.SetText(MESSAGE_COLUMN_INDEX, data->message);

    if (data->suggestion_id != 0) {
        handle.SetType(TreeViewItem::Type::Emphasized_2);
        handle.SetData<LineData>(data);
    } else if (data->was_suggestion) {
        handle.SetType(TreeViewItem::Type::WarningInformation);
    } else if (!data->subject.empty()) {
        handle.SetType(TreeViewItem::Type::Category);
    }
}

void AnalysisEngineWindow::RebuildTreeData()
{

    std::map<std::string, bool> extended_items = {};

    auto selectedItem            = detailsTree->GetCurrentItem();
    const bool validSelectedItem = selectedItem.IsValid();
    uint32 selectedIndex         = UINT32_MAX;

    auto children_count = detailsTree->GetItemsCount();
    for (uint32 i = 0; i < children_count; i++) {
        auto item = detailsTree->GetItemByIndex(i);
        if (item.IsExpandable() && !item.IsFolded())
            extended_items[item.GetText()] = true;
        if (validSelectedItem && item == selectedItem) {
            selectedIndex = i;
        }
    }

    // RebuildOldTreeData();

    detailsTree->ClearItems();
    tree_data.clear();

    if (new_subject_data.empty())
        return;

    std::unordered_map<SubjectId, bool> visited = {};
    std::vector<std::shared_ptr<EntryContainerData>> entries;
    std::vector<uint32> depths;
    std::vector<TreeWindowData> tree_window;

    entries.reserve(8);
    depths.reserve(8);
    tree_window.reserve(8);

    entries.emplace_back(new_subject_data.begin()->second);
    depths.emplace_back(0);

    uint32 current_index = 0;
    while (!entries.empty()) {
        auto current_depth        = depths.back();
        const auto& current_entry = entries.back();

        if (current_depth == 0) {
            LineData local_data = {};
            LineData* line_ptr = &local_data;
            std::visit(
                  [&line_ptr](auto&& arg){
                      using T = std::decay_t<decltype(arg)>;
                      if constexpr (std::is_same_v<T, SubjectData>) {
                          line_ptr->subject  = arg.name;
                          line_ptr->message  = "Opening " + arg.name;
                          return;
                      } else if constexpr (std::is_same_v<T, ActionData>) {
                          line_ptr = &arg.data;
                          return;
                      }
                      assert(false); // Should not happen
                  },
                  current_entry->type);
            TreeWindowData data = {};
            if (tree_window.empty()) {
                data.handle = detailsTree->AddItem(line_ptr->subject);
            } else {
                data.handle = tree_window.back().handle.AddChild(line_ptr->subject);
            }

            PopulateTreeDataFromLineData(data.handle, line_ptr);
            if (selectedIndex == current_index++) {
                data.handle.SetCurrent();
            }
            if (extended_items.contains(line_ptr->subject)) {
                data.handle.SetFolding(true);
            }
            tree_window.push_back(std::move(data));
        }

        if (current_depth >= current_entry->data->children.size()) {
            entries.pop_back();
            depths.pop_back();
            tree_window.pop_back();
            continue;
        }

        auto& current_child = current_entry->data->children[current_depth];
        depths.back()++;
        std::visit(
              [&](auto&& arg) {
                  using T = std::decay_t<decltype(arg)>;
                  if constexpr (std::is_same_v<T, std::shared_ptr<LineData>>) {
                      TreeWindowData data = {};
                      data.handle         = tree_window.back().handle.AddChild("");
                      PopulateTreeDataFromLineData(data.handle, arg.get());

                      if (selectedIndex == current_index++) {
                          data.handle.SetCurrent();
                      }
                      if (extended_items.contains(arg->subject)) {
                          data.handle.SetFolding(true);
                      }
                  } else if constexpr (std::is_same_v<T, std::shared_ptr<EntryContainerData>>) {
                      entries.push_back(arg);
                      depths.push_back(0);
                  }
              },
              current_child);
    }
}