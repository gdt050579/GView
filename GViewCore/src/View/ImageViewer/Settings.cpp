#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->imagesCount = 0;
    this->loadImageCallback.Reset();
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetLoadImageCallback(Reference<LoadImageInterface> cbk, uint32 imagesCount)
{
    if ((cbk != nullptr) && (imagesCount >= 1))
    {
        ((SettingsData*) (this->data))->loadImageCallback = cbk;
        ((SettingsData*) (this->data))->imagesCount       = imagesCount;
    }
}

