#include "DumpViewer.hpp"
#include <algorithm>

using namespace GView::View::DumpViewer;
using namespace AppCUI;
using namespace AppCUI::Input;
using namespace AppCUI::Graphics;

Config Instance::config;

Instance::Instance(Reference<GView::Object> _obj, Settings* _settings)
    : ViewControl("Dump View", UserControlFlags::ShowVerticalScrollBar | UserControlFlags::ScrollBarOutsideControl), settings(new SettingsData()),
      leftFirstLine(0), leftCursorLine(0), rightFirstLine(0), rightCursorLine(0), leftActive(true), splitX(0)
{
    this->obj = _obj;

    if ((_settings) && (_settings->data)) {
        settings        = Pointer<SettingsData>((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }

    if (!config.Loaded)
        config.Initialize();
}


bool Instance::Update()
{
    return true;
}

bool Instance::GetPropertyValue(uint32, PropertyValue&)
{
    return false;
}

bool Instance::SetPropertyValue(uint32, const PropertyValue&, String&)
{
    return false;
}

void Instance::SetCustomPropertyValue(uint32)
{
}

bool Instance::IsPropertyValueReadOnly(uint32)
{
    return true;
}

const vector<Property> Instance::GetPropertiesList()
{
    return {};
}

std::string_view Instance::GetCategoryNameForSerialization() const
{
    return {};
}

bool Instance::AddCategoryBeforePropertyNameWhenSerializing() const
{
    return false;
}



bool Instance::GoTo(uint64)
{
    return false;
}

bool Instance::Select(uint64, uint64)
{
    return false;
}

bool Instance::ShowGoToDialog()
{
    return false;
}

bool Instance::ShowFindDialog()
{
    return false;
}

bool Instance::ShowCopyDialog()
{
    return false;
}



void Instance::PaintCursorInformation(Renderer& renderer, uint32 width, uint32)
{
    String info;

    int32 activeLine = leftActive ? leftCursorLine : rightCursorLine;

    info.Format(
          "Modules: %zu | Active: %s | Line: %d",
          leftActive ? settings->leftColumn.size() : settings->rightColumn.size(),
          leftActive ? "Left" : "Right",
          activeLine + 1);

    renderer.WriteSingleLineText(0, 0, info, ColorPair{ Color::Black, Color::Red });
}


bool Instance::OnKeyEvent(Key keyCode, char16)
{   
    int32 totalLines;
    if (leftActive) {
        totalLines = static_cast<int32>(settings->leftColumn.size());
    } else {
        totalLines = static_cast<int32>(settings->rightColumn.size());
    }
    if (totalLines <= 0)
        return false;

  
    const int32 viewHeight = std::max(1, this->GetHeight() - 3);

    int32& cursorLine = leftActive ? leftCursorLine : rightCursorLine;
    int32& firstLine  = leftActive ? leftFirstLine : rightFirstLine;

    switch (keyCode) {
    case Key::Tab:
        leftActive = !leftActive;
        this->Update();
        return true;

    case Key::Up:
        if (cursorLine > 0) {
            cursorLine--;
            if (cursorLine < firstLine)
                firstLine = cursorLine;
            this->Update();
        }
        return true;

    case Key::Down:
        if (cursorLine + 1 < totalLines) {
            cursorLine++;
            if (cursorLine >= firstLine + viewHeight)
                firstLine = cursorLine - viewHeight + 1;
            this->Update();
        }
        return true;

    case Key::PageUp:
        cursorLine = std::max(0, cursorLine - viewHeight);
        firstLine  = cursorLine;
        this->Update();
        return true;

    case Key::PageDown:
        cursorLine = std::min(totalLines - 1, cursorLine + viewHeight);
        firstLine  = std::max(0, cursorLine - viewHeight + 1);
        this->Update();
        return true;

    case Key::Home:
        cursorLine = 0;
        firstLine  = 0;
        this->Update();
        return true;

    case Key::End:
        cursorLine = totalLines - 1;
        firstLine  = std::max(0, totalLines - viewHeight);
        this->Update();
        return true;
    }

    return ViewControl::OnKeyEvent(keyCode, 0);
}


void Instance::PaintColumn(Renderer& renderer, vector<String> data, vector<String> highlitedText, int32 firstLine, int32 cursorLine, int x, int width, bool active, const char* columnName)
{


    const ColorPair normalColor = Cfg.Text.Normal;// ColorPair(Color::Black, Color::DarkBlue);
    const ColorPair selectedColor  = Cfg.Text.Focused; // ColorPair(Color::Yellow, Color::Blue);
    const ColorPair headerColor    = Cfg.Text.Emphasized1; // ColorPair(Color::White, Color::DarkGreen);
    const ColorPair separatorColor = Cfg.Text.Normal;      // ColorPair(Color::Gray, Color::Transparent);
    const ColorPair highlitedColor = Cfg.Text.Emphasized2; // ColorPair(Color::Magenta, Color::Green);
    const int height = this->GetHeight();

    
    renderer.FillHorizontalLine(x, 1, width, ' ', headerColor);
    renderer.WriteSingleLineText(x, 1, columnName, headerColor);
    renderer.FillHorizontalLine(x, 2, width, '-', separatorColor);


    int y = 3;

    for (int i = firstLine; i < (int) data.size() && y < height; i++) {
        bool isCursor = (i == cursorLine);
        bool isHighlighted = false;
        for (const auto& hText : highlitedText) {
            if (data[i] == hText) {
                isHighlighted = true;
                break;
            }
        }
        ColorPair clr = normalColor;
        if (isHighlighted) {
            clr = highlitedColor;
        }
   
        std::string text = data[i].GetText();

        size_t pos = 0;
        while (pos < text.length() && y < height) {
            
            size_t newlinePos = text.find('\n', pos);
            if (newlinePos == std::string::npos) {
                newlinePos = text.length();
            }

            
            std::string segment = text.substr(pos, newlinePos - pos);

            
            segment.erase(std::remove(segment.begin(), segment.end(), '\r'), segment.end());

            
            size_t segPos = 0;
            while (segPos < segment.length() && y < height) {
                size_t chunkSize  = std::min((size_t) width, segment.length() - segPos);
                std::string chunk = segment.substr(segPos, chunkSize);

               
                renderer.FillHorizontalLine(x, y, width, ' ', clr);
                renderer.WriteSingleLineText(x, y, chunk.c_str(), clr);

                segPos += chunkSize;
                y++;
            }

            pos = newlinePos + 1; 
        }
    }

    
    for (; y < height; y++) {
        renderer.FillHorizontalLine(x, y, width, ' ', normalColor);
    }
}


void Instance::Paint(Renderer& renderer)
{
    const int width  = this->GetWidth();
    const int height = this->GetHeight();

    if (width < 4 || height < 2)
        return;

   
    if (leftActive) {
        splitX = (width * 80) / 100;
    } else {
        splitX = (width * 20) / 100;
    }

   
    if (leftActive) {
        splitX = std::min(splitX, width - 10); 
    } else {
        splitX = std::max(splitX, 10); 
    }


    PaintColumn(renderer, settings->leftColumn, settings->highlitedInfoLeft, leftFirstLine, leftCursorLine, 0, splitX - 1, leftActive, settings->leftColumnName);
    PaintColumn(renderer, settings->rightColumn, settings->highlitedInfoRight, rightFirstLine, rightCursorLine, splitX + 1, width - splitX - 1, !leftActive, settings->rightColumnName);

    for (int y = 1; y < height; y++) {
        renderer.WriteCharacter(splitX, y, '|', ColorPair{ Color::Gray, Color::Transparent });
    }
}