#pragma once
#include "AnalysisEngine.hpp"

namespace GView::Components::AnalysisEngine::Window
{
class AnalysisEngineWindow : public Controls::Window, public Handlers::OnListViewItemPressedInterface
{
  public:
    AnalysisEngineWindow(Reference<RuleEngine> engine);
    bool OnEvent(AppCUI::Utils::Reference<Control>, AppCUI::Controls::Event eventType, int ID) override;
    bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
    void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;

private:
    void GetHint();
    void DrawSuggestions();

    Reference<RuleEngine> engine;
    Reference<ListView> listView;
    Reference<Label> statusLabel;

};
}