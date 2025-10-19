#pragma once
#include "AnalysisEngine.hpp"

namespace GView::Components::AnalysisEngine
{
class AnalysisEngineWindow : public Controls::Window,
                             public Handlers::OnListViewItemPressedInterface,
                             public Handlers::OnListViewCurrentItemChangedInterface
{
  public:
    AnalysisEngineWindow(Reference<RuleEngine> engine);
    bool OnEvent(AppCUI::Utils::Reference<Control>, AppCUI::Controls::Event eventType, int ID) override;
    bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
    void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;
    void OnListViewCurrentItemChanged(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;
    void BeforeOpen();

  private:
    void GetHint();
    void DrawSuggestions();
    void DrawPredicatesForCurrentIndex(uint32 index);

private:
    Reference<RuleEngine> engine;
    Reference<ListView> listView;
    Reference<Label> statusLabel;
    Reference<Label> predicatesLabel;

};
}