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

    if (config.loaded == false)
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
    if (height == 1)
    {
        const uint32 x1 = 1;
        const uint32 x2 = x1 + config.cursorInformationCellSpace + 1;
        const uint32 x3 = x2 + config.cursorInformationCellSpace + 1;
        const uint32 x4 = x3 + config.cursorInformationCellSpace + 1;
        const uint32 x5 = x4 + config.cursorInformationCellSpace + 1;
        const uint32 x6 = x5 + config.cursorInformationCellSpace + 1;
        const uint32 y  = 0;

        PaintCursorInformationWidth(renderer, x1, y);
        PaintCursorInformationSeparator(renderer, x2 - 1, y);
        PaintCursorInformationHeight(renderer, x2, y);
        PaintCursorInformationSeparator(renderer, x3 - 1, y);
        PaintCursorInformationCells(renderer, x3, y);
        PaintCursorInformationSeparator(renderer, x4 - 1, y);
        PaintCursorInformationCurrentLocation(renderer, x4, y);
        PaintCursorInformationSeparator(renderer, x5 - 1, y);
        PaintCursorInformationSelection(renderer, x5, y);
    }
    else if (height > 1)
    {
        const uint32 x1 = 1;
        const uint32 x2 = 1;
        const uint32 x3 = x1 + config.cursorInformationCellSpace + 1;
        const uint32 x4 = x2 + config.cursorInformationCellSpace + 1;
        const uint32 x5 = x3 + config.cursorInformationCellSpace + 1;
        const uint32 x6 = x4 + config.cursorInformationCellSpace + 1;
        const uint32 y1 = 0;
        const uint32 y2 = 1;

        PaintCursorInformationWidth(renderer, x1, y1);
        PaintCursorInformationHeight(renderer, x2, y2);
        PaintCursorInformationSeparator(renderer, x2 - 1, y1);
        PaintCursorInformationCells(renderer, x3, y1);
        PaintCursorInformationCurrentLocation(renderer, x4, y2);
        PaintCursorInformationSeparator(renderer, x4 - 1, y1);
        PaintCursorInformationSelection(renderer, x5, y1);
    }
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(config.keys.toggleHeader, "ToggleHeader", COMMAND_ID_TOGGLE_HEADER);
    return true;
}

bool Instance::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        if (ID == COMMAND_ID_TOGGLE_HEADER)
        {
            settings->firstRowAsHeader = !settings->firstRowAsHeader;
            PopulateGrid();

            return true;
        }
    }

    return false;
}

void Instance::PopulateGrid()
{
    auto i              = 0U;
    const auto& content = settings->content;
    if (settings->firstRowAsHeader)
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
    else
    {
        grid->ResetHeaderValues();
    }

    for (; i < content.size(); i++)
    {
        const auto& row = content[i];
        for (auto j = 0U; j < row.size(); j++)
        {
            grid->UpdateCell(j, i - settings->firstRowAsHeader, AppCUI::Controls::Grid::CellType::String, row[j]);
        }
    }
}

void GView::View::GridViewer::Instance::PaintCursorInformationWidth(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    WriteTextParams params{ WriteTextFlags::SingleLine };
    params.Color = config.color.cursorInformation.name;
    params.X     = x;
    params.Y     = y;
    params.Width = config.cursorInformationCellSpace;
    params.Align = TextAlignament::Left;

    LocalString<256> ls;

    const auto width = grid->GetWidth();
    renderer.WriteText("Width:", params);
    params.Color = config.color.cursorInformation.value;
    params.X += 6;
    ls.Format("%d", width);
    renderer.WriteText(ls, params);
}

void GView::View::GridViewer::Instance::PaintCursorInformationHeight(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    WriteTextParams params{ WriteTextFlags::SingleLine };
    params.Color = config.color.cursorInformation.name;
    params.X     = x;
    params.Y     = y;
    params.Width = config.cursorInformationCellSpace;
    params.Align = TextAlignament::Left;

    LocalString<256> ls;

    const auto height = grid->GetHeight();
    renderer.WriteText("Height:", params);
    params.Color = config.color.cursorInformation.value;
    params.X += 7;
    ls.Format("%d", height);
    renderer.WriteText(ls, params);
}

void GView::View::GridViewer::Instance::PaintCursorInformationCells(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    WriteTextParams params{ WriteTextFlags::SingleLine };
    params.Color = config.color.cursorInformation.name;
    params.X     = x;
    params.Y     = y;
    params.Width = config.cursorInformationCellSpace;
    params.Align = TextAlignament::Left;

    LocalString<256> ls;

    const auto cells = grid->GetCellsCount();
    renderer.WriteText("Cells:", params);
    params.Color = config.color.cursorInformation.value;
    params.X += 6;
    ls.Format("%d", cells);
    renderer.WriteText(ls, params);
}

void GView::View::GridViewer::Instance::PaintCursorInformationCurrentLocation(
      AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    WriteTextParams params{ WriteTextFlags::SingleLine };
    params.Color = config.color.cursorInformation.name;
    params.X     = x;
    params.Y     = y;
    params.Width = config.cursorInformationCellSpace;
    params.Align = TextAlignament::Left;

    LocalString<256> ls;

    const auto location = grid->GetHoveredLocation();
    renderer.WriteText("Hovered:", params);
    params.Color = config.color.cursorInformation.value;
    params.X += 9;
    if (location == Point{ -1, -1 })
    {
        ls.Format("- | -");
    }
    else
    {
        ls.Format("%d | %d", location.X, location.Y);
    }
    renderer.WriteText(ls, params);
}

void GView::View::GridViewer::Instance::PaintCursorInformationSelection(
      AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    WriteTextParams params{ WriteTextFlags::SingleLine };
    params.Color = config.color.cursorInformation.name;
    params.X     = x;
    params.Y     = y;
    params.Width = config.cursorInformationCellSpace;
    params.Align = TextAlignament::Left;

    LocalString<256> ls;

    const auto start = grid->GetSelectionLocationsStart();
    const auto end   = grid->GetSelectionLocationsEnd();
    renderer.WriteText("Selection:", params);
    params.Color = config.color.cursorInformation.value;
    params.X += 10;
    if (start == Point{ -1, -1 } || end == Point{ -1, -1 })
    {
        ls.Format("- & - -> - & -");
    }
    else
    {
        ls.Format("%d & %d -> %d & %d", start.X, start.Y, end.X, end.Y);
    }
    renderer.WriteText(ls, params);
}

void GView::View::GridViewer::Instance::PaintCursorInformationSeparator(
      AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
{
    renderer.DrawVerticalLine(x, y, y + 4, config.color.cursorInformation.value);
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
        value = config.keys.toggleHeader;
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
        config.keys.toggleHeader = std::get<Key>(value);
        return true;
    default:
        break;
    }
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
        { PROP_ID_TOGGLE_HEADER, "General", "Toggle header existence", PropertyType::Key },
    };
}
