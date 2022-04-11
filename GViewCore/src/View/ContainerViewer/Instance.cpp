#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_ZOOMIN     = 0xBF00;
constexpr int32 CMD_ID_ZOOMOUT    = 0xBF01;
constexpr int32 CMD_ID_NEXT_IMAGE = 0xBF02;
constexpr int32 CMD_ID_PREV_IMAGE = 0xBF03;

Instance::Instance(const std::string_view& _name, Reference<GView::Object> _obj, Settings* _settings) : settings(nullptr)
{
    this->obj  = _obj;
    this->name = _name;

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

    // create some object
    imgView = Factory::ImageView::Create(this, "x:0,y:0,w:16,h:8", ViewerFlags::HideScrollBar);
    if ((this->settings->icon.GetWidth() == 16) && (this->settings->icon.GetHeight() == 16))
        imgView->SetImage(this->settings->icon, ImageRenderingMethod::PixelTo16ColorsSmallBlock, ImageScaleMethod::NoScale);
    this->propList = Factory::ListView::Create(
          this,
          "l:17,t:0,r:0,h:8",
          { { "Field", TextAlignament::Left, 20 }, { "Value", TextAlignament::Left, 200 } },
          ListViewFlags::HideColumns);

    this->items = Factory::TreeView::Create(this, "l:0,t:10,r:0,b:0", {});
    for (uint32 idx = 0; idx < settings->columnsCount; idx++)
    {
        const auto& col = settings->columns[idx];
        this->items->AddColumn(col.Name, col.Align, col.Width);
    }
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    return false;
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType != Event::Command)
        return false;
    switch (ID)
    {
    }
    return false;
}
bool Instance::GoTo(uint64 offset)
{
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
    this->WriteCursorInfo(r, 0, 0, 16, "temp", "temp");
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    None
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
    }
    error.SetFormat("Unknown internat ID: %u", id);
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {

    };
}
#undef BT