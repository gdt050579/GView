#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_WORD_WRAP    = 0xBF00;

class CharacterStream
{
    char16 ch;
    const uint8* pos;
    const uint8* end;
    uint32 xPos, nextPos;
    uint32 charRelativeOffset, nextCharRelativeOffset;
    Reference<SettingsData> settings;

  public:
    CharacterStream(BufferView buf, Reference<SettingsData> _settings)
    {
        this->pos                    = buf.begin();
        this->end                    = buf.end();
        this->xPos                   = 0;
        this->nextPos                = 0;
        this->charRelativeOffset     = 0;
        this->nextCharRelativeOffset = 0;
        this->settings               = _settings;
    }
    bool Next()
    {
        if (this->pos >= this->end)
            return false;
        switch (this->settings->encoding)
        {
        case Encoding::Ascii:
            this->ch = *this->pos;
            this->pos++;
            break;
        default:
            return false;
        }
        this->xPos               = this->nextPos;
        this->charRelativeOffset = this->nextCharRelativeOffset++;
        if (this->ch == '\t')
        {
            this->ch      = ' '; // tab will be showd as a space
            this->nextPos = this->settings->tabSize - (this->nextPos % this->settings->tabSize);
        }
        else
            this->nextPos++;
        if ((this->ch == '\n') || (this->ch == '\r'))
        {
            this->pos = this->end; // advance to end of line
            return false;
        }

        return true;
    }
    inline uint32 GetXOffset() const
    {
        return this->xPos;
    }
    inline uint32 GetNextXOffset() const
    {
        return this->nextPos;
    }
    inline uint32 GetRelativeOffset() const
    {
        return this->charRelativeOffset;
    }
    inline void ResetXOffset(uint32 value = 0)
    {
        this->xPos = this->nextPos = value;
    }
    inline char16 GetCharacter() const
    {
        return this->ch;
    }
};

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
    this->subLineIndex.Create(256); // alocate 256 entries
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
bool Instance::ComputeSubLineIndexes(uint32 lineNo, BufferView& buf)
{
    uint64 offset;
    uint32 size;
    uint32 w = this->GetWidth();

    this->subLineIndex.Clear();
    CHECK(GetLineInfo(lineNo, offset, size), false, "");
    CHECK(this->subLineIndex.Push(0), false, "");

    if ((this->lineNumberWidth + 1) >= w)
        w = 1;
    else
        w -= (this->lineNumberWidth + 1);
    buf = this->obj->GetData().Get(offset, size, false);
    CharacterStream cs(buf, this->settings.ToReference());
    // process
    if (this->settings->wordWrap)
    {
        while (cs.Next())
        {
            if (cs.GetXOffset() >= w)
            {
                // move to next line
                this->subLineIndex.Push(cs.GetRelativeOffset());
                cs.ResetXOffset();
            }
        }
    }
    return true;
}
int Instance::DrawLine(uint32 xScroll, int32 y, uint32 lineNo, uint32 width, Graphics::Renderer& renderer)
{
    BufferView buf;
    NumericFormatter n;
    bool firstLine = true;

    ComputeSubLineIndexes(lineNo, buf);

    // write text
    auto idx    = this->subLineIndex.GetUInt32Array();
    auto idxEnd = idx + this->subLineIndex.Len();
    auto cBuf   = buf.begin();

    // draw each sub-line
    while (idx < idxEnd)
    {
        auto start = *idx;
        auto end   = (idx + 1) < idxEnd ? idx[1] : (uint32) buf.GetLength();
        CharacterStream cs(BufferView(cBuf + start, end - start), this->settings.ToReference());
        auto c     = this->chars;
        auto lastC = this->chars + 1;
        auto c_end = c + MAX_CHARACTERS_PER_LINE;
        // skip left part
        if (xScroll > 0)
        {
            while ((cs.Next()) && (cs.GetNextXOffset() < xScroll))
            {
            }
        }
        while ((cs.Next()) && (lastC < c_end))
        {
            auto c = this->chars + cs.GetXOffset();
            // fill in the spaces
            while (lastC < c)
            {
                lastC->Code  = ' ';
                lastC->Color = Cfg.Text.Normal;
                lastC++;
            }
            c->Code  = cs.GetCharacter();
            c->Color = Cfg.Text.Normal;
            lastC    = c + 1;
        }
        if (firstLine)
        {
            renderer.WriteSingleLineText(0, y, this->lineNumberWidth, n.ToDec(lineNo + 1), DefaultColorPair, TextAlignament::Right);
            firstLine = false;
        }
        else
            renderer.FillHorizontalLine(0, y, this->lineNumberWidth, ' ', DefaultColorPair);
        renderer.WriteSpecialCharacter(this->lineNumberWidth, y, SpecialChars::BoxVerticalSingleLine, DefaultColorPair);
        renderer.WriteSingleLineText(this->lineNumberWidth + 1, y, CharacterView(chars, (size_t) (lastC - chars)), Cfg.Text.Normal);
        y++;
        idx++;
    }
    return y;
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    auto h   = this->GetHeight();
    uint32 w = this->GetWidth();
    if (w <= (this->lineNumberWidth + 2))
        w = 0;
    else
        w = w - (this->lineNumberWidth + 2);
    auto y      = 0;
    auto lineNo = 0U;
    while (y < h)
    {
        y = DrawLine(0, y, lineNo, w, renderer);
        lineNo++;
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    if (this->settings->wordWrap)
        commandBar.SetCommand(config.Keys.WordWrap, "WordWrap:ON", CMD_ID_WORD_WRAP);
    else
        commandBar.SetCommand(config.Keys.WordWrap, "WordWrap:OF", CMD_ID_WORD_WRAP);

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
    case CMD_ID_WORD_WRAP:
        this->settings->wordWrap = !this->settings->wordWrap;
        return true;
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