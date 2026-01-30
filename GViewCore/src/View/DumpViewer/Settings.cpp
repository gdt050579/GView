#include "DumpViewer.hpp"

using namespace GView::View::DumpViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{

}
Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetLeftColumnName(String lName)
{
    ((SettingsData*) data)->leftColumnName = lName;
}
void Settings::SetRightColumnName(String rName)
{
    ((SettingsData*) data)->rightColumnName = rName;
}
void Settings::AddLeftColumnInfo(std::vector<String> lColumn)
{
    ((SettingsData*) data)->leftColumn = lColumn;
}
void Settings::AddRightColumnInfo(std::vector<String> rColumn)
{
    ((SettingsData*) data)->rightColumn = rColumn;
}
void Settings::AddHighlightedInfoLeft(std::vector<String> hlColumn)
{
  
    ((SettingsData*) data)->highlitedInfoLeft = hlColumn;
}

void Settings::AddHighlightedInfoRight(std::vector<String> hrColumn)
{
    ((SettingsData*) data)->highlitedInfoRight = hrColumn;
}
