#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
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

    this->lineNumberWidth = 0;
    this->tabSize         = 4;
}
void Instance::RecomputeLineIndexes()
{
    // first --> simple estimation
    auto buf        = this->obj->GetData().Get(0, 4096, false);
    auto sz         = this->obj->GetData().GetSize();
    auto csz        = this->obj->GetData().GetCacheSize();
    auto crlf_count = (uint64) 1;

    for (auto ch : buf)
        if ((ch == '\n') || (ch == '\r'))
            crlf_count++;

    auto estimated_count = ((crlf_count * sz) / buf.GetLength()) + 16;

    this->lineIndex.Clear();
    if (this->lineIndex.Reserve((uint32) estimated_count) == false)
        return;

    uint64 offset = 0;
    uint64 start  = 0;
    uint8 last    = 0;
    while (offset < sz)
    {
        buf = this->obj->GetData().Get(offset, csz, false);
        if (buf.Empty())
            return;
        // process the buffer
        auto* p = buf.begin();
        for (; p < buf.end(); p++)
        {
            if (((*p) == '\n') || ((*p) == '\r'))
            {
                if (((last == '\n') || (last == '\r')) && (last != (*p)))
                {
                    // either \n\r or \r\n
                    start++; // skip current character
                    last = 0;
                    continue;
                }
                this->lineIndex.Push((uint32) start);
                start = offset + (p - buf.begin()) + 1; // next pos
                last  = *p;
            }
            else
            {
                last = 0;
            }
        }
        offset += buf.GetLength();
    }
    if (start < sz)
        this->lineIndex.Push((uint32) start);
    auto linesCount = this->lineIndex.Len() + 1;
    if (linesCount < 10)
        this->lineNumberWidth = 2;
    else if (linesCount < 100)
        this->lineNumberWidth = 3;
    else if (linesCount < 1000)
        this->lineNumberWidth = 4;
    else if (linesCount < 10000)
        this->lineNumberWidth = 5;
    else if (linesCount < 100000)
        this->lineNumberWidth = 6;
    else if (linesCount < 1000000)
        this->lineNumberWidth = 7;
    else
        this->lineNumberWidth = 8;
}
bool Instance::GetLineInfo(uint32 lineNo, uint64& offset, uint32& size)
{
    uint32 ofs, next;
    if (this->lineIndex.Get(lineNo, ofs) == false)
        return false;
    offset = ofs;
    if (lineNo + 1 == this->lineIndex.Len())
    {
        size = (uint32) (this->obj->GetData().GetSize() - offset);
    }
    else
    {
        if (this->lineIndex.Get(lineNo + 1, next) == false)
            return false;
        size = next - ofs;
    }
    return true;
}
void Instance::DrawLine(uint32 xScroll, int32 y, uint32 lineNo, uint32 width, Graphics::Renderer& renderer)
{
    uint64 ofs;
    uint32 sz;
    BufferView buf;
    NumericFormatter n;
    

    if (GetLineInfo(lineNo, ofs, sz))
        buf = this->obj->GetData().Get(ofs, sz, false);
    renderer.WriteSingleLineText(0, y, this->lineNumberWidth, n.ToDec(lineNo + 1), DefaultColorPair, TextAlignament::Right);
    renderer.WriteSpecialCharacter(this->lineNumberWidth, y, SpecialChars::BoxVerticalSingleLine, DefaultColorPair);

    // parse buf until the first visible character
    uint32 xPoz = 0;
    auto p      = buf.begin();
    auto e      = buf.end();

    // compute relative position
    for (; (xPoz < xScroll) && (p < e); p++)
    {
        if ((*p) == '\t')
        {
            xPoz += this->tabSize - (xPoz % this->tabSize);
        }
        else
        {
            xPoz++;
        }
    }
    xPoz -= xScroll;

    // write chars over the chars buffer
    auto c     = this->chars;
    auto c_end = c + MAX_CHARACTERS_PER_LINE;
    auto x     = 0U;
    while ((x < width) && (c < c_end) && (p < e))
    {
        if (((*p) == '\n') || ((*p) == '\r'))
            break;

        if ((*p) == '\t')
        {
            auto dif = this->tabSize - (x % this->tabSize);
            x += dif;
            for (; (dif > 0) && (c < c_end); dif--,c++)
            {
                c->Code = ' ';                
            }
        }
        else
        {
            c->Code = *p;
            c++;
            x++;
        }
        p++;
    }

    renderer.WriteSingleLineText(this->lineNumberWidth + 1, y, CharacterView(chars, (size_t) (c - chars)), Cfg.Text.Normal);
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    auto h   = this->GetHeight();
    uint32 w = this->GetWidth();
    if (w <= (this->lineNumberWidth + 2))
        w = 0;
    else
        w = w - (this->lineNumberWidth + 2);
    for (auto y = 0; y < h; y++)
    {
        DrawLine(0, y, (uint32) y, w, renderer);
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(config.Keys.ZoomIn, "ZoomIN", CMD_ID_ZOOMIN);
    commandBar.SetCommand(config.Keys.ZoomOut, "ZoomOUT", CMD_ID_ZOOMOUT);
    if (this->settings->imgList.size() > 1)
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
        return true;
    case Key::PageDown:
        return true;
    }

    return false;
}
void Instance::OnStart()
{
    RecomputeLineIndexes();
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
bool Instance::ExtractTo(Reference<AppCUI::OS::DataObject> output, ExtractItem item, uint64 size)
{
    NOT_IMPLEMENTED(false);
}
//======================================================================[Cursor information]==================

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    WordWrap,
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::WordWrap:
        value = false;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::WordWrap:
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
    case PropertyID::WordWrap:
        return true;
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { BT(PropertyID::WordWrap), "General", "Word Wrap", PropertyType::Boolean },
    };
}
#undef BT