#include <format>
#include "ui/OnlineAnalyticsResultsUI.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

constexpr int32 TAB_ID_GENERAL      = 0;
constexpr int32 TAB_ID_HASHES       = 1;
constexpr int32 TAB_ID_CAPABILITIES = 2;
constexpr int32 TAB_ID_ANALYSIS     = 3;

constexpr std::string SEVERITY_LABELS[] = {
    std::string("None"), std::string("Low"), std::string("Medium"), std::string("High"), std::string("Critical"),
};

OnlineAnalyticsResultsUI::OnlineAnalyticsResultsUI(Reference<GView::Object> object, Reference<Utils::Report> report)
    : Window("Online analytics: results", "d:c,w:80,h:24", WindowFlags::None)
{
    this->object  = object;
    this->report  = report;
    this->didInit = false;

    this->tabs                                       = Factory::Tab::Create(this, "l:0,t:0,r:0,b:0", TabFlags::TopTabs | TabFlags::TabsBar);
    Reference<Controls::TabPage> generalTabPage      = Factory::TabPage::Create(this->tabs, "General", TAB_ID_GENERAL);
    Reference<Controls::TabPage> hashesTabPage       = Factory::TabPage::Create(this->tabs, "Hashes", TAB_ID_HASHES);
    Reference<Controls::TabPage> capabilitiesTabPage = Factory::TabPage::Create(this->tabs, "Capabilities", TAB_ID_CAPABILITIES);
    Reference<Controls::TabPage> analysisTabPage     = Factory::TabPage::Create(this->tabs, "Analysis", TAB_ID_ANALYSIS);

    Reference<Controls::Label> nameLabel = Factory::Label::Create(generalTabPage, std::format("File name: {}", this->report->fileName), "a:t,l:1,r:1,y:1,h:1");
    Reference<Controls::Label> sizeLabel =
          Factory::Label::Create(generalTabPage, std::format("File size: {} B", this->report->fileSize), "a:t,l:1,r:1,y:2,h:1");
    Reference<Controls::Label> severityLabel =
          Factory::Label::Create(generalTabPage, std::format("Severity from provider: {}", SEVERITY_LABELS[this->report->severity]), "a:t,l:1,r:1,y:4,h:1");
};

bool OnlineAnalyticsResultsUI::Init()
{
    CHECK(this->didInit == false, false, "Already called init on Results UI");

    this->didInit = true;
    return true;
}

AppCUI::Dialogs::Result OnlineAnalyticsResultsUI::Show()
{
    CHECK(this->didInit == true, AppCUI::Dialogs::Result::Cancel, "Did not call init on Results UI");
    return Window::Show();
}

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI