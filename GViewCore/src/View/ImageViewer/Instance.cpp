#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_ZOOMIN     = 0xBF00;
constexpr int32 CMD_ID_ZOOMOUT    = 0xBF01;
constexpr int32 CMD_ID_NEXT_IMAGE = 0xBF02;
constexpr int32 CMD_ID_PREV_IMAGE = 0xBF03;

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
    commandBar.SetCommand(config.Keys.ZoomIn, "ZoomIN", CMD_ID_ZOOMIN);
    commandBar.SetCommand(config.Keys.ZoomOut, "ZoomOUT", CMD_ID_ZOOMOUT);
    if (this->settings->imgList.size()>1)
    {
        commandBar.SetCommand(Key::PageUp, "PrevImage", CMD_ID_PREV_IMAGE);
        commandBar.SetCommand(Key::PageDown, "NextImage", CMD_ID_NEXT_IMAGE);
    }
    return false;
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
    case CMD_ID_ZOOMIN:
        this->scale = NextPreviousScale(true);
        this->RedrawImage();
        return true;
    case CMD_ID_ZOOMOUT:
        this->scale = NextPreviousScale(false);
        this->RedrawImage();
        return true;
    case CMD_ID_PREV_IMAGE:
        if (this->currentImageIndex > 0)
        {
            this->currentImageIndex--;
            LoadImage();
        }
        return true;
    case CMD_ID_NEXT_IMAGE:
        if ((size_t) this->currentImageIndex + 1 < this->settings->imgList.size())
        {
            this->currentImageIndex++;
            LoadImage();
        }
        return true;
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
bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
{
    NOT_IMPLEMENTED(false);
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
    ImagesCount,
    Scale,
    CurrentImageIndex,
    CurrentImageSize,
    ZoomIn,
    ZoomOut
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::ImagesCount:
        value = (uint32) settings->imgList.size();
        return true;
    case PropertyID::Scale:
        value = static_cast<uint32>(this->scale);
        return true;
    case PropertyID::CurrentImageIndex:
        value = this->currentImageIndex;
        return true;
    case PropertyID::CurrentImageSize:
        value = Size{ img.GetWidth(), img.GetHeight() };
        return true;
    case PropertyID::ZoomIn:
        value = config.Keys.ZoomIn;
        return true;
    case PropertyID::ZoomOut:
        value = config.Keys.ZoomOut;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::Scale:
        this->scale = static_cast<ImageScaleMethod>(std::get<uint64>(value));
        this->RedrawImage();
        return true;
    case PropertyID::CurrentImageIndex:
        if ((std::get<uint32>(value))>=this->settings->imgList.size())
        {
            error.SetFormat("Invalid image index (should be between 0 and %d)", (int) (this->settings->imgList.size() - 1));
            return false;
        }
        this->currentImageIndex = std::get<uint32>(value);
        LoadImage();
        return true;
    case PropertyID::ZoomIn:
        config.Keys.ZoomIn = std::get<Key>(value);
        return true;
    case PropertyID::ZoomOut:
        config.Keys.ZoomOut = std::get<Key>(value);
        return true;
    }
    error.SetFormat("Unknown internat ID: %u", id);
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    switch (static_cast<PropertyID>(propertyID))
    {
    case PropertyID::ImagesCount:
    case PropertyID::CurrentImageSize:
        return true;
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { BT(PropertyID::ImagesCount), "General", "Images count", PropertyType::UInt32 },
        { BT(PropertyID::Scale), "General", "Scale", PropertyType::List, "100%=1,50%=2,33%=3,25%=4,20%=5,10%=10,5%=20" },
        { BT(PropertyID::CurrentImageIndex), "Current Image", "Index", PropertyType::UInt32 },
        { BT(PropertyID::CurrentImageSize), "Current Image", "Size", PropertyType::Size },
        { BT(PropertyID::ZoomIn), "Shortcuts", "Key for ZoomIn", PropertyType::Key },
        { BT(PropertyID::ZoomOut), "Shortcuts", "Key for ZoomOut", PropertyType::Key },

    };
}
#undef BT