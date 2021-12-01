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
void Settings::AddOffsetTranslationMethod(std::string_view _name, MethodID _methodID)
{
    auto* Members = (SettingsData*) (this->data);
    for (unsigned int tr = 0; tr < Members->translationMethodsCount; tr++)
        if (Members->translationMethods[tr].methodID == _methodID)
            return;
    if (Members->translationMethodsCount >= sizeof(Members->translationMethods) / sizeof(OffsetTranslationMethod))
        return;
    auto m      = &Members->translationMethods[Members->translationMethodsCount];
    m->methodID = _methodID;
    m->name     = _name;
    Members->translationMethodsCount++;
}
void Settings::SetOffsetTranslationCallback(Reference<OffsetTranslateInterface> cbk)
{
    ((SettingsData*) (this->data))->offsetTranslateCallback = cbk;
}