#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

Config Instance::config;

Instance::Instance(const std::string_view& _name, Reference<GView::Object> _obj, Settings* _settings) : settings(nullptr)
{
    imgView = Factory::ImageView::Create(this, "d:c", ViewerFlags::None);

    this->obj               = _obj;
    this->name              = _name;
    this->currentImageIndex = 0;
    this->scale             = ImageScaleMethod::NoScale;
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
ImageScaleMethod Instance::NextPreviousScale(bool next)
{
    switch (scale)
    {
    case AppCUI::Graphics::ImageScaleMethod::NoScale:
        return next ? ImageScaleMethod::NoScale : ImageScaleMethod::Scale50;
    case AppCUI::Graphics::ImageScaleMethod::Scale50:
        return next ? ImageScaleMethod::NoScale : ImageScaleMethod::Scale33;
    case AppCUI::Graphics::ImageScaleMethod::Scale33:
        return next ? ImageScaleMethod::Scale50 : ImageScaleMethod::Scale25;
    case AppCUI::Graphics::ImageScaleMethod::Scale25:
        return next ? ImageScaleMethod::Scale33 : ImageScaleMethod::Scale20;
    case AppCUI::Graphics::ImageScaleMethod::Scale20:
        return next ? ImageScaleMethod::Scale25 : ImageScaleMethod::Scale10;
    case AppCUI::Graphics::ImageScaleMethod::Scale10:
        return next ? ImageScaleMethod::Scale20 : ImageScaleMethod::Scale5;
    case AppCUI::Graphics::ImageScaleMethod::Scale5:
        return next ? ImageScaleMethod::Scale10 : ImageScaleMethod::Scale5;
    default:
        return ImageScaleMethod::NoScale;
    }
}
void Instance::RedrawImage()
{
    this->imgView->SetImage(this->img, ImageRenderingMethod::PixelTo16ColorsSmallBlock, scale);
}
void Instance::LoadImage()
{
    if (this->settings->loadImageCallback->LoadImageToObject(this->img, this->currentImageIndex))
    {
        RedrawImage();
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    switch (keyCode)
    {
    case Key::PageUp:
        if (this->currentImageIndex > 0)
        {
            this->currentImageIndex--;
            LoadImage();
        }
        return true;
    case Key::PageDown:
        if ((size_t) this->currentImageIndex + 1 < this->settings->imgList.size())
        {
            this->currentImageIndex++;
            LoadImage();
        }
        return true;
    }

    switch (characterCode)
    {
    case '+':
    case '=':
        this->scale = NextPreviousScale(true);
        this->RedrawImage();
        return true;
    case '-':
    case '_':
        this->scale = NextPreviousScale(false);
        this->RedrawImage();
        return true;
    }

    return false;
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
    LocalString<128> tmp;
    r.WriteSingleLineText(0, 0, "Size:", config.Colors.Highlighted);
    r.WriteSingleLineText(6, 0, tmp.Format("%u x %u", img.GetWidth(), img.GetHeight()), config.Colors.Normal);
    r.DrawVerticalLine(16, 0, height, config.Colors.Line, true);

    r.WriteSingleLineText(18, 0, "Image:", config.Colors.Highlighted);
    r.WriteSingleLineText(
          25, 0, tmp.Format("%u/%u", this->currentImageIndex + 1, (uint32) this->settings->imgList.size()), config.Colors.Normal);
    r.DrawVerticalLine(32, 0, height, config.Colors.Line, true);

    r.WriteSingleLineText(34, 0, "Zoom:", config.Colors.Highlighted);
    r.WriteSingleLineText(39, 0, tmp.Format("%3u%%", 100U / (uint32) scale), config.Colors.Normal);
    r.DrawVerticalLine(44, 0, height, config.Colors.Line, true);
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