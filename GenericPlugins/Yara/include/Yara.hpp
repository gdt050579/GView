#pragma once

#include "GView.hpp"
#include <vector>
#include <filesystem>

namespace GView::GenericPlugins::Yara
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;

class YaraDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;
    Reference<ListView> rulesList;
    Reference<Button> addButton;
    Reference<Button> removeButton;
    Reference<Button> scanButton;
    Reference<Button> closeButton;
    std::vector<std::filesystem::path> ruleFiles;

  public:
    YaraDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
    bool OnEvent(Reference<Control> control, Event eventType, int id) override;

  private:
    void AddRuleFile();
    void RemoveRuleFile();
    void ScanWithYara();
    void UpdateRulesList();
};

} // namespace GView::GenericPlugins::Yara
