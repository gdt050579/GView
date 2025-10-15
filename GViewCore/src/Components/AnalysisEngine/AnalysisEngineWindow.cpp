#include "AnalysisEngineWindow.hpp"

using namespace GView::Components::AnalysisEngine::Window;

constexpr int32 COMMAND_CLOSE    = 0;
constexpr int32 COMMAND_GET_HINT = 1;

AnalysisEngineWindow::AnalysisEngineWindow(Reference<RuleEngine> engine)
    : Window("Analysis Engine", "t:1,l:1,r:1,b:1", Controls::WindowFlags::Sizeable), engine(engine)
{
    listView = Factory::ListView::Create(
          this, "x:1,y:1,w:99%,h:70%", { "n:RuleID,w:10%", "n:Confidence,w:10%", "n:Action,w:20%", "n:Message,w:59%" }, ListViewFlags::PopupSearchBar);

    const auto y = listView->GetHeight() + 2;
    LocalString<128> ls;
    ls.Format("x:1,y:%d, w:99", y);
    statusLabel = Factory::Label::Create(this, "Press F12 to get hints", ls.GetText());

    listView->Handlers()->OnItemPressed = this;

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

void AnalysisEngineWindow::OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item)
{
    if (!item.IsValid())
        return;
    const auto index = item.GetData((uint64) (-1));
    if (index == (uint64) (-1))
        return;
    if (!engine->TryExecuteSuggestion((uint32) index)) {
        Dialogs::MessageBox::ShowNotification("Suggestion error", "Found error");
        return;
    }
    DrawSuggestions();
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

    auto suggestions = engine->evaluate(std::move(subject));

    if (suggestions.empty()) {
        statusLabel->SetText("Received no new suggestions!");
    } else {
        LocalString<128> ls;
        ls.Format("Received %u new suggestions", (uint32) suggestions.size());
        statusLabel->SetText(ls.GetText());
        DrawSuggestions();
    }
}

void AnalysisEngineWindow::DrawSuggestions()
{
    listView->DeleteAllItems();
    auto available_suggestions = engine->GetAllAvailableSuggestions();
    if (available_suggestions.empty())
        return;
    for (uint32 i = 0; i < available_suggestions.size(); i++) {
        const auto& s = available_suggestions[i];

        const auto action_name                         = engine->GetActName(s.action.key);
        const auto confidence                          = std::to_string(s.confidence);
        const std::initializer_list<ConstString> items = { s.rule_id, confidence, action_name, s.message };
        auto new_item                                  = listView->AddItem(items);
        new_item.SetData(i);
    }
}