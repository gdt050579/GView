#include "Internal.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    for (unsigned int tr = 0; tr < 10; tr++)
        this->bookmarks[tr] = GView::Utils::INVALID_OFFSET;
    this->translationMethodsCount = 0;
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::AddZone(unsigned long long start, unsigned long long size, ColorPair col, std::string_view name)
{
    auto* Members = (SettingsData*) (this->data);
    if (size > 0)
        Members->zList.Add(start, start + size - 1, col, name);
}
void Settings::AddBookmark(unsigned char bookmarkID, unsigned long long fileOffset)
{
    auto* Members = (SettingsData*) (this->data);
    if (bookmarkID < 10)
        Members->bookmarks[bookmarkID] = fileOffset;
}
void Settings::SetOffsetTranslationList(std::initializer_list<std::string_view> list, Reference<OffsetTranslateInterface> cbk)
{
    // only valid if at list one translation method is provided and the callback si correct 
    if ((!cbk.IsValid()) || (list.size() == 0))
        return;
    auto* Members                       = (SettingsData*) (this->data);
    Members->translationMethods[0].name = "FileOffset";
    Members->translationMethodsCount    = 1;
    Members->offsetTranslateCallback    = cbk;
    for (auto &i: list)
    {
        Members->translationMethods[Members->translationMethodsCount++].name = i;
        if (Members->translationMethodsCount >= sizeof(Members->translationMethods) / sizeof(OffsetTranslationMethod))
            break;
    }
}
void Settings::SetPositionToColorCallback(Reference<PositionToColorInterface> cbk)
{
    ((SettingsData*) (this->data))->positionToColorCallback = cbk;
}
