#include <format>
#include "utils/Visit.hpp"
#include "ui/OnlineAnalyticsResultsUI.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::UI
{
using namespace AppCUI::Controls;

constexpr int32 TAB_ID_GENERAL      = 0;
constexpr int32 TAB_ID_HASHES       = 1;
constexpr int32 TAB_ID_CAPABILITIES = 2;
constexpr int32 TAB_ID_ANALYSIS     = 3;
constexpr int32 TAB_ID_TAGS         = 4;

constexpr int32 BUTTON_VISIT_URL = 5;

constexpr std::string SEVERITY_LABELS[] = {
    std::string("None"), std::string("Low"), std::string("Medium"), std::string("High"), std::string("Critical"),
};

OnlineAnalyticsResultsUI::OnlineAnalyticsResultsUI(Reference<Utils::Report> report)
    : Window("Online analytics: results", "d:c,w:96,h:24", WindowFlags::None)
{
    this->report  = report;
    this->didInit = false;

    Reference<Controls::Tab> tabs                    = Factory::Tab::Create(this, "l:0,t:0,r:0,b:0", TabFlags::TopTabs | TabFlags::TabsBar);
    Reference<Controls::TabPage> generalTabPage      = Factory::TabPage::Create(tabs, "General", TAB_ID_GENERAL);
    Reference<Controls::TabPage> hashesTabPage       = Factory::TabPage::Create(tabs, "Hashes", TAB_ID_HASHES);
    Reference<Controls::TabPage> capabilitiesTabPage = Factory::TabPage::Create(tabs, "Capabilities", TAB_ID_CAPABILITIES);
    Reference<Controls::TabPage> analysisTabPage     = Factory::TabPage::Create(tabs, "Analysis", TAB_ID_ANALYSIS);
    Reference<Controls::TabPage> tagsTabPage         = Factory::TabPage::Create(tabs, "Tags", TAB_ID_TAGS);

    Reference<Controls::Label> nameLabel = Factory::Label::Create(generalTabPage, std::format("File name: {}", this->report->fileName), "a:t,l:1,r:1,y:1,h:1");
    Reference<Controls::Label> sizeLabel =
          Factory::Label::Create(generalTabPage, std::format("File size: {} B", this->report->fileSize), "a:t,l:1,r:1,y:2,h:1");
    Reference<Controls::Label> severityLabel =
          Factory::Label::Create(generalTabPage, std::format("Severity from provider: {}", SEVERITY_LABELS[this->report->severity]), "a:t,l:1,r:1,y:4,h:1");
    Reference<Controls::Label> urlLabel = Factory::Label::Create(generalTabPage, std::format("URL for report: {}", this->report->url), "a:t,l:1,r:1,y:6,h:1");
    Reference<Controls::Button> visitButton  = Factory::Button::Create(generalTabPage, "&View report", "x:1,y:8,w:24,h:1", BUTTON_VISIT_URL);
    visitButton->Handlers()->OnButtonPressed = this;
    visitButton->SetFocus();

    Reference<Controls::Label> md5Label  = Factory::Label::Create(hashesTabPage, std::format("MD5 hash: {}", this->report->md5), "a:t,l:1,r:1,y:1,h:1");
    Reference<Controls::Label> sha1Label = Factory::Label::Create(hashesTabPage, std::format("SHA-1 hash: {}", this->report->sha1), "a:t,l:1,r:1,y:2,h:1");
    Reference<Controls::Label> sha256Label =
          Factory::Label::Create(hashesTabPage, std::format("SHA-256 hash: {}", this->report->sha256), "a:t,l:1,r:1,y:3,h:1");

    Reference<Controls::ListView> capabilitiesListView = Factory::ListView::Create(capabilitiesTabPage, "l:1,r:1,t:1,b:1", { "n:&Capability,w:100%" });

    for (std::string& capability : report->capabilities) {
        capabilitiesListView->AddItem(capability.c_str());
    };

    Reference<Controls::ListView> analysisListView =
          Factory::ListView::Create(analysisTabPage, "l:1,r:1,t:1,b:1", { "n:&Analysis,w:33%", "n:&Version,w:33%", "n:&Result,w:34%" });

    for (Utils::Analysis& analysis : report->analysis) {
        analysisListView->AddItem(
              { analysis.engine.c_str(), analysis.version.c_str(), analysis.result == Utils::AnalysisResult::Malicious ? "Malicious" : "Undetected" });
    }

    Reference<Controls::ListView> tagsListView = Factory::ListView::Create(tagsTabPage, "l:1,r:1,t:1,b:1", { "n:&Tags,w:100%" });

    for (std::string& tag : report->tags) {
        tagsListView->AddItem(tag);
    }
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

void OnlineAnalyticsResultsUI::OnButtonPressed(Reference<Controls::Button> button)
{
    switch (button->GetControlID()) {
    case BUTTON_VISIT_URL:
        this->OnVisitButtonPressed();
        break;
    }
}

void OnlineAnalyticsResultsUI::OnVisitButtonPressed()
{
    Utils::VisitUrl(this->report->url);
}

}; // namespace GView::GenericPlugins::OnlineAnalytics::UI