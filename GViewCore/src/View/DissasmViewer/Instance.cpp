#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr uint32 PROP_ID_ADD_NEW_TYPE     = 1;
constexpr uint32 PROP_ID_DISSASM_LANGUAGE = 2;

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* _settings)
    : name(name), obj(obj), settings(nullptr)
{
    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();
}

bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        value = config.Keys.AddNewType;
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        value = (uint64) (settings->defaultLanguage);
        return true;
    }
    return false;
}

bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        config.Keys.AddNewType = std::get<Key>(value);
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        settings->defaultLanguage = static_cast<DissamblyLanguage>(std::get<uint64>(value));
        return true;
    }
    return false;
}

void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}

bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
    // return propertyID == PROP_ID_DISSASM_LANGUAGE;
}

const vector<Property> Instance::GetPropertiesList()
{
    return {
        { PROP_ID_ADD_NEW_TYPE, "Shortcuts", "Key addind new data type", PropertyType::Key },
        { PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, "x86=1,x64=2,JavaByteCode=3,IL=4" },
    };
}

bool Instance::GoTo(uint64 offset)
{
    return true;
}

bool Instance::Select(uint64 offset, uint64 size)
{
    return true;
}

bool Instance::ShowGoToDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowCopyDialog()
{
    NOT_IMPLEMENTED(false);
}

std::string_view Instance::GetName()
{
    return "DissasmView";
}

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    renderer.WriteSingleLineText(0, 0, "Cursor data", DefaultColorPair);
}

void Instance::Paint(AppCUI::Graphics::Renderer& renderer)
{
    renderer.WriteSingleLineText(0, 0, "ASM ASM", DefaultColorPair);
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(config.Keys.AddNewType, "AddNewType", 12345);

    return false;
}

bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        if (ID==12345)
        {
            Dialogs::MessageBox::ShowNotification("Info", "OK!");
            return true;
        }
    }

    return false;
}