#include "YaraViewer.hpp"

using namespace GView::View::YaraViewer;
using namespace AppCUI::Input;

#define DATA ((SettingsData*) data)

SettingsData::SettingsData()
{
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetAnalysisLevel(int analysisLevelParam)
{
    DATA->analysisLevel = analysisLevelParam;
}