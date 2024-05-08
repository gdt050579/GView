#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    for (uint32 tr = 0; tr < 10; tr++)
        this->bookmarks[tr] = GView::Utils::INVALID_OFFSET;
    this->translationMethodsCount = 0;
    this->entryPointOffset        = GView::Utils::INVALID_OFFSET;
}

Settings::Settings()
{
    this->data = new SettingsData();
}

Settings::~Settings()
{
    if (this->data) {
        delete reinterpret_cast<SettingsData*>(this->data);
        this->data = nullptr;
    }
}

void Settings::AddZone(uint64 start, uint64 size, ColorPair col, std::string_view name)
{
    auto* Members = (SettingsData*) (this->data);
    if (size > 0)
        Members->zList.Add(start, start + size - 1, col, name);
}

void Settings::SetZonesListForObjectHighlighting(const GView::Utils::ZonesList& zones)
{
    auto data = reinterpret_cast<SettingsData*>(this->data);
    CHECKRET(data, "");
    data->zListObjects = zones;
}

void Settings::AddBookmark(uint8 bookmarkID, uint64 fileOffset)
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
    for (auto& i : list) {
        Members->translationMethods[Members->translationMethodsCount++].name = i;
        if (Members->translationMethodsCount >= sizeof(Members->translationMethods) / sizeof(OffsetTranslationMethod))
            break;
    }
}

void Settings::SetPositionToColorCallback(Reference<PositionToColorInterface> cbk)
{
    ((SettingsData*) (this->data))->positionToColorCallback = cbk;
}

void Settings::SetEntryPointOffset(uint64 offset)
{
    ((SettingsData*) (this->data))->entryPointOffset = offset;
}

void Settings::SetArchitecture(GView::Dissasembly::Architecture architecture)
{
    ((SettingsData*) (this->data))->architecture = architecture;
}

void Settings::SetDesign(GView::Dissasembly::Design design)
{
    ((SettingsData*) (this->data))->design = design;
}

void Settings::SetEndianess(GView::Dissasembly::Endianess endianess)
{
    ((SettingsData*) (this->data))->endianess = endianess;
}

bool Settings::SetName(std::string_view name)
{
    return ((SettingsData*) (this->data))->name.Set(name);
}