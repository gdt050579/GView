#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

Config Instance::config;

Instance::Instance(const std::string_view& _name, Reference<GView::Object> _obj, Settings* _settings) : settings(nullptr)
{
    imgView = Factory::ImageViewer::Create(this, "d:c", ViewerFlags::None);

    this->obj               = _obj;
    this->name              = _name;
    this->currentImageIndex = 0;
    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        // default setup
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();

    // load first image
    LoadImage();
}

void Instance::LoadImage()
{
    if (this->settings->loadImageCallback->LoadImageToObject(this->img, this->currentImageIndex))
    {
        this->imgView->SetImage(this->img, ImageRenderingMethod::PixelTo16ColorsSmallBlock, ImageScaleMethod::NoScale);
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType != Event::Command)
        return false;
    switch (ID)
    {
    default:
        break;
    }
    return false;
}
bool Instance::GoTo(uint64 offset)
{
    for (uint32 idx = 0; idx < settings->imgList.size(); idx++)
    {
        if ((offset >= settings->imgList[idx].start) && (offset < settings->imgList[idx].end))
        {
            if (this->currentImageIndex != idx)
            {
                this->currentImageIndex = idx;
                LoadImage();
            }
            return true;
        }
    }
    return false; 
}
bool Instance::Select(uint64 offset, uint64 size)
{
    return false; // no selection is possible in this mode
}
std::string_view Instance::GetName()
{
    return this->name;
}

//======================================================================[Cursor information]==================

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display

};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    default:
        break;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
    default:
        break;
    }
    error.SetFormat("Unknown internat ID: %u", id);
    return false;
}
void Instance::SetCustomPropetyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    switch (static_cast<PropertyID>(propertyID))
    {
    default:
        break;
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        // Display
        //{ BT(PropertyID::Columns), "Display", "Columns", PropertyType::List, "8 columns=8,16 columns=16,32 columns=32,FullScreen=0" },

    };
}
#undef BT