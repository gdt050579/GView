#include "GridViewer.hpp"

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

constexpr uint32 PROP_ID_TOGGLE_HEADER = 0;

constexpr uint32 COMMAND_ID_TOGGLE_HEADER = 0x1000;

Config Instance::config;

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* _settings) : settings(nullptr)
{
    this->obj  = obj;
    this->name = name;

    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        // default setup
        settings.reset(new SettingsData());
    }

    if (settings)
    {
        grid = AppCUI::Controls::Factory::Grid::Create(
              this, "d:c,w:100%,h:100%", settings->cols, settings->rows, AppCUI::Controls::GridFlags::TransparentBackground);

        grid->SetSeparator(settings->separator);
        PopulateGrid();
    }

    if (config.Loaded == false)
        config.Initialize();
}

std::string_view Instance::GetName()
{
    return name;
}

bool Instance::GoTo(unsigned long long offset)
{
    return true;
}

bool Instance::Select(unsigned long long offset, unsigned long long size)
{
    return true;
}

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height)
{
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(config.Keys.ToggleHeader, "ToggleHeader", COMMAND_ID_TOGGLE_HEADER);
    return true;
}

bool Instance::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        if (ID == COMMAND_ID_TOGGLE_HEADER)
        {
            settings->showHeader = !settings->showHeader;
            bool isHeaderShown   = grid->IsHeaderVisible();
            if (settings->showHeader == isHeaderShown)
            {
                return false;
            }
            PopulateGrid();

            return true;
        }
    }

    return false;
}

void Instance::PopulateGrid()
{
    grid->ShowHeader(settings->showHeader);

    auto i              = 0U;
    const auto& content = settings->content;
    if (settings->showHeader)
    {
        const auto& header = content[0];
        std::vector<AppCUI::Utils::ConstString> headerCS;
        for (const auto& value : header)
        {
            headerCS.push_back(value);
        }

        grid->UpdateHeaderValues(headerCS);
        i++;
    }

    for (; i < content.size(); i++)
    {
        const auto& row = content[i];
        for (auto j = 0U; j < row.size(); j++)
        {
            grid->UpdateCell(j, i - settings->showHeader, AppCUI::Controls::Grid::CellType::String, row[j]);
        }
    }
}

enum class PropertyID : uint32
{
    None
};

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (id)
    {
    case PROP_ID_TOGGLE_HEADER:
        value = config.Keys.ToggleHeader;
        return true;
    default:
        break;
    }
    return false;
}

bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (id)
    {
    case PROP_ID_TOGGLE_HEADER:
        config.Keys.ToggleHeader = std::get<Key>(value);
        return true;
    default:
        break;
    }
    return false;
}

void Instance::SetCustomPropetyValue(uint32 propertyID)
{
}

bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
}

const vector<Property> Instance::GetPropertiesList()
{
    return {
        { PROP_ID_TOGGLE_HEADER, "General", "Toggle header existence", PropertyType::Key },
    };
}
