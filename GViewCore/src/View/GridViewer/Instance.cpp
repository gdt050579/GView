#include "GridViewer.hpp"

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

Config Instance::config;

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings) : settings(nullptr)
{
    this->obj  = obj;
    this->name = name;

    // settings
    if ((settings) && (settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) settings->data);
        settings->data = nullptr;
    }
    else
    {
        // default setup
        this->settings.reset(new SettingsData());
    }

    if ((this->settings) && (this->settings->content))
    {
        grid = AppCUI::Controls::Factory::Grid::Create(
              this,
              "d:c,w:100%,h:100%",
              this->settings->cols,
              this->settings->rows,
              AppCUI::Controls::GridFlags::TransparentBackground | AppCUI::Controls::GridFlags::HideHeader);

        const auto content = reinterpret_cast<std::vector<std::vector<std::string>>*>(this->settings->content);
        for (auto i = 0U; i < content->size(); i++)
        {
            const auto& row = (*content)[i];
            for (auto j = 0U; j < row.size(); j++)
            {
                grid->UpdateCell(j, i, AppCUI::Controls::Grid::CellType::String, row[j]);
            }
        }
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

enum class PropertyID : uint32
{
    None
};

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    return false;
}

bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
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
    return {};
}
