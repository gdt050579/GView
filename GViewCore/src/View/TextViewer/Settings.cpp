#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->imgList.reserve(8);
    this->loadImageCallback.Reset();
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetLoadImageCallback(Reference<LoadImageInterface> cbk)
{
    if (cbk != nullptr)
        ((SettingsData*) (this->data))->loadImageCallback = cbk;
}
void Settings::AddImage(uint64 offset, uint64 size)
{
    if ((size > 0) && (offset != GView::Utils::INVALID_OFFSET))
    {
        auto& elem = ((SettingsData*) (this->data))->imgList.emplace_back();
        elem.start = offset;
        elem.end   = offset + size;
    }
}
