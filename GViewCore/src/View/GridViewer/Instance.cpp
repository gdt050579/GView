#include "GridViewer.hpp"
#include <fstream>
#include <filesystem>

 //#include <windows.h>

using namespace GView::View::GridViewer;
using namespace AppCUI::Input;

constexpr uint32 PROP_ID_REPLACE_HEADER_WITH_1ST_ROW = 0;
constexpr uint32 PROP_ID_TOGGLE_HORIZONTAL_LINES     = 1;
constexpr uint32 PROP_ID_TOGGLE_VERTICAL_LINES       = 2;

constexpr uint32 COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW = 0x1000;
constexpr uint32 COMMAND_ID_TOGGLE_HORIZONTAL_LINES     = 0x1001;
constexpr uint32 COMMAND_ID_TOGGLE_VERTICAL_LINES       = 0x1002;
constexpr uint32 COMMAND_ID_VIEW_CELL_CONTENT           = 0x1003; 
constexpr uint32 COMMAND_ID_EXPORT_CELL_CONTENT         = 0x1004; 
constexpr uint32 COMMAND_ID_EXPORT_COLUMN_CONTENT       = 0x1005;

Config Instance::config;

Instance::Instance(Reference<GView::Object> obj, Settings* _settings) : settings(nullptr), ViewControl("Grid View")
{
    this->obj = obj;
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
              this,
              "d:c,w:100%,h:100%",
              static_cast<uint32>(settings->cols),
              static_cast<uint32>(settings->rows),
              AppCUI::Controls::GridFlags::Sort | AppCUI::Controls::GridFlags::Filter | GridFlags::DisableDuplicates);

        grid->SetSeparator(settings->separator);
    }

    if (config.loaded == false)
        config.Initialize();
    const auto count = GView::App::GetObjectsCount();
    if (count == 0)
    {
        return;
    }
    auto path                   = GView::App::GetObject(0)->GetPath();
    auto lastSlash              = path.rfind(u".");
    std::u16string exportedPath = std::u16string(path.substr(0, lastSlash));
    exportedPath.append(u"_exported");
    this->exportedPathUTF8 = { exportedPath.begin(), exportedPath.end() };
    auto lastP = path.rfind(u"\\");
    std::u16string exportedPathSlash = std::u16string(path.substr(0, lastP));
    exportedPathSlash.append(u"\\");

    this->exportedFolderPath = { exportedPathSlash.begin(), exportedPathSlash.end() };
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
    CHECK(findDialog.Show() == Dialogs::Result::Ok, true, "");

    auto filterValue = findDialog.GetFilterValue();
    grid->SetFilterOnCurrentColumn(filterValue);
    grid->Filter();

    return true;
}

bool Instance::ShowCopyDialog()
{
    grid->OnKeyEvent(Key::Ctrl | Key::C, 0);
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
        const uint32 x5 = x4 + config.cursorInformationCellSpace + 1 ;
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
    commandBar.SetCommand(config.keys.replaceHeaderWith1stRow, "ReplaceHeader", COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW);
    commandBar.SetCommand(config.keys.toggleHorizontalLines, "ToggleHorizontalLines", COMMAND_ID_TOGGLE_HORIZONTAL_LINES);
    commandBar.SetCommand(config.keys.toggleVerticalLines, "ToggleVerticalLines", COMMAND_ID_TOGGLE_VERTICAL_LINES);
    commandBar.SetCommand(config.keys.viewCellContent, "ViewCellContent", COMMAND_ID_VIEW_CELL_CONTENT);
    commandBar.SetCommand(config.keys.exportCellContent, "ExportCellContent", COMMAND_ID_EXPORT_CELL_CONTENT);
    commandBar.SetCommand(config.keys.exportColumnContent, "ExportColumnContent", COMMAND_ID_EXPORT_COLUMN_CONTENT);
    return false;
}

vector<uint8_t> Instance::getHexCellContent(const std::string& content) {

    vector<uint8_t> hexData;
    for (auto chunkIndex = 0; chunkIndex < content.size() / 8; chunkIndex++)
    {
        uint8_t value = 0;
        for (auto valueIndex = chunkIndex * 8; valueIndex < (chunkIndex + 1) * 8; valueIndex++)
        {
            value = value * 2 + content[valueIndex] - '0';
        }
        hexData.push_back(value);
    }
    return hexData;
}

bool Instance::OnEvent(Reference<Control> control, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        if (ID == COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW)
        {
            settings->firstRowAsHeader = !settings->firstRowAsHeader;
            PopulateGrid();
            return true;
        }
        else if (ID == COMMAND_ID_TOGGLE_HORIZONTAL_LINES)
        {
            grid->ToggleHorizontalLines();
            return true;
        }
        else if (ID == COMMAND_ID_TOGGLE_VERTICAL_LINES)
        {
            grid->ToggleVerticalLines();
            return true;
        }
        else if (ID == COMMAND_ID_VIEW_CELL_CONTENT)
        {
            auto cellContent = grid->GetSelectedCellContent();
            auto content = getHexCellContent(cellContent.value());
            BufferView buffer(content.data(), content.size());
            GView::App::OpenBuffer(buffer, "Cell Content", "", GView::App::OpenMethod::Select, "");
        }
        else if (ID == COMMAND_ID_EXPORT_CELL_CONTENT)
        {
            auto cellContent = grid->GetSelectedCellContent();
            auto content     = getHexCellContent(cellContent.value());
            
            std::time_t t = std::time(0);
            auto timestampPath = this->exportedPathUTF8 + "_" + std::to_string(t);

            std::ofstream file(timestampPath.c_str(), std::ios::binary); // Open the file in binary mode
            file.write(reinterpret_cast<const char*>(content.data()), content.size());
            file.close();
            

            AppCUI::Dialogs::MessageBox::ShowNotification("File Export Result", std::string("File exported successfully at: ") + timestampPath);
        }
        else if (ID == COMMAND_ID_EXPORT_COLUMN_CONTENT)
        {
            auto data = grid->GetSelectedColumnContent();
            auto index = 0;

            auto folderPath = this->exportedFolderPath + data.value().first + "_";
            std::time_t t   = std::time(0);
            folderPath += std::to_string(t);

            if (!std::filesystem::exists(folderPath)) {
                std::filesystem::create_directory(folderPath);
            }


            for (auto& content : data.value().second)
            {
                auto hexContent = getHexCellContent(content);
                std::string newName = folderPath + "\\row_" + std::to_string(index);
                std::ofstream file(newName.c_str(), std::ios::binary); // Open the file in binary mode

                file.write(reinterpret_cast<const char*>(hexContent.data()), hexContent.size());
                file.close();
                
                index++;
            }

            folderPath.pop_back();
            folderPath.pop_back();
            AppCUI::Dialogs::MessageBox::ShowNotification("Files Export Result", std::string("Files exported successfully at folder: ") + folderPath);

        }
    }

    return false;
}

void Instance::OnStart()
{
    ProcessContent();
    grid->SetGridDimensions({ static_cast<uint32>(settings->cols), static_cast<uint32>(settings->rows) });
    PopulateGrid();
}

void Instance::PopulateGrid()
{
    const auto& content = settings->tokens;
    auto it             = content.begin();

    if (settings->firstRowAsHeader)
    {
        const auto& header = it->second;
        std::vector<AppCUI::Utils::ConstString> headerCS;
        for (const auto& [start, end] : header)
        {
            const auto token = obj->GetData().Get(start, static_cast<uint32>(end - start), false);
            headerCS.push_back(token);
        }
        std::advance(it, 1);
        grid->UpdateHeaderValues(headerCS);
    }
    else
    {
        grid->SetDefaultHeaderValues();
    }

    const auto dimensions = grid->GetGridDimensions();
    if (static_cast<uint32>(settings->rows - settings->firstRowAsHeader) != dimensions.Height)
    {
        grid->SetGridDimensions({ static_cast<uint32>(settings->cols), static_cast<uint32>(settings->rows - settings->firstRowAsHeader) });
    }

    while (it != content.end())
    {
        const auto i    = it->first;
        const auto& row = it->second;
        for (auto itRow = row.begin(); itRow != row.end(); itRow++)
        {
            const auto j     = row.size() - std::abs(std::distance(row.end(), itRow));
            const auto token = obj->GetData().Get(itRow->first, static_cast<uint32>(itRow->second - itRow->first), false);
            const ConstString value{ token };
            grid->UpdateCell(static_cast<uint32>(j), static_cast<uint32>(i - settings->firstRowAsHeader), value);
        }
        std::advance(it, 1);
    }

    grid->Sort();
}

void GView::View::GridViewer::Instance::ProcessContent()
{
    std::map<uint64, std::pair<uint64, uint64>> lines;
    std::map<uint64, std::vector<std::pair<uint64, uint64>>> tokens;

    const auto oSize = obj->GetData().GetSize();
    const auto cSize = obj->GetData().GetCacheSize();
    auto lines1 = settings->lines;
    auto oSizeProcessed = 0ULL;
    auto lineStart      = 0ULL;
    auto currentLine    = 0ULL;

    do
    {
        const auto buf = obj->GetData().Get(oSizeProcessed, static_cast<uint32>(cSize), false);
        const std::string_view data{ reinterpret_cast<const char*>(buf.GetData()), buf.GetLength() };

        auto nPos       = data.find_first_of('\n', 0);
        const auto rPos = data.find_first_of('\r', 0);

        const auto oldOSizeProcessed = oSizeProcessed;

        if (nPos < rPos)
        {
            if (nPos + 1 < data.size() && data[nPos + 1] == '\r')
            {
                oSizeProcessed += nPos + 2;
            }
            else
            {
                oSizeProcessed += nPos + 1;
            }
        }
        else if (nPos > rPos)
        {
            if (rPos + 1 < data.size() && data[rPos + 1] == '\n')
            {
                oSizeProcessed += rPos + 2;
            }
            else
            {
                oSizeProcessed += rPos + 1;
            }
        }
        else
        {
            nPos = oSize - oldOSizeProcessed;
            oSizeProcessed += nPos;
        }

        lines.insert({ currentLine, { lineStart + oldOSizeProcessed, nPos + oldOSizeProcessed } });
        const std::string_view line{ reinterpret_cast<const char*>(buf.GetData() + lineStart), nPos };

        std::vector<uint64> separators;
        {
            size_t pos = line.find(settings->separator[0]);
            while (pos < line.size())
            {
                separators.push_back(pos + oldOSizeProcessed);
               /* auto value = line.size() > pos + 1;

                auto distance = (int) (line.end() - line.begin() + pos - 1);
                auto offset   = std::min<>(distance, 100);
               */
                auto new_pos = std::search(
                      line.begin() + pos + 1, line.end(),
                      settings->separator,
                      settings->separator + 1,
                      [](char a, char b) { return a == b ; });

                pos          = new_pos - line.begin(); 
                //pos        = line.find(settings->separator[0], pos + 1);
            }
            separators.push_back(line.size() + oldOSizeProcessed);
        }

        std::vector<std::pair<uint64, uint64>> lTokens;
        if (separators.size() == 0)
        {
            lTokens.push_back({ lineStart + oldOSizeProcessed, nPos + oldOSizeProcessed });
        }

        {
            auto tStart = oldOSizeProcessed;
            auto tEnd   = oldOSizeProcessed;
            for (const auto& i : separators)
            {
                tEnd = i;
                lTokens.push_back({ tStart, tEnd });
                tStart = tEnd + 1;
            }
        }

        tokens.insert({ currentLine, std::move(lTokens) });

        currentLine++;

    } while (oSizeProcessed < oSize);

    settings->rows   = lines.size();
    settings->cols   = tokens.size() > 0 ? tokens.begin()->second.size() : 0;
    settings->lines  = std::move(lines);
    settings->tokens = std::move(tokens);
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

void GView::View::GridViewer::Instance::PaintCursorInformationCurrentLocation(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
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

void GView::View::GridViewer::Instance::PaintCursorInformationSelection(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
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

void GView::View::GridViewer::Instance::PaintCursorInformationSeparator(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y)
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
    case PROP_ID_REPLACE_HEADER_WITH_1ST_ROW:
        value = config.keys.replaceHeaderWith1stRow;
        return true;
    case PROP_ID_TOGGLE_HORIZONTAL_LINES:
        value = config.keys.toggleHorizontalLines;
        return true;
    case PROP_ID_TOGGLE_VERTICAL_LINES:
        value = config.keys.toggleVerticalLines;
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
    case PROP_ID_REPLACE_HEADER_WITH_1ST_ROW:
        config.keys.replaceHeaderWith1stRow = std::get<Key>(value);
        return true;
    case PROP_ID_TOGGLE_HORIZONTAL_LINES:
        config.keys.toggleHorizontalLines = std::get<Key>(value);
        return true;
    case PROP_ID_TOGGLE_VERTICAL_LINES:
        config.keys.toggleVerticalLines = std::get<Key>(value);
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
        { PROP_ID_REPLACE_HEADER_WITH_1ST_ROW, "Content", "Replace header with first row", PropertyType::Key },
        { PROP_ID_TOGGLE_HORIZONTAL_LINES, "Look", "Hide/Show horizontal lines", PropertyType::Key },
        { PROP_ID_TOGGLE_VERTICAL_LINES, "Look", "Hide/Show vertical lines", PropertyType::Key },
    };
}
