#include "TextViewer.hpp"
#include <algorithm>

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_WORD_WRAP = 0xBF00;

class CharacterStream
{
    char16 ch;
    const uint8* start;
    const uint8* pos;
    const uint8* end;
    uint32 xPos, nextPos;
    uint32 charIndex, nextCharIndex;
    Reference<SettingsData> settings;
    CharacterEncoding::ExpandedCharacter ec;

  public:
    CharacterStream(BufferView buf, uint32 characterIndex, Reference<SettingsData> _settings)
    {
        this->pos           = buf.begin();
        this->start         = this->pos;
        this->end           = buf.end();
        this->xPos          = 0;
        this->nextPos       = 0;
        this->charIndex     = characterIndex;
        this->nextCharIndex = characterIndex;
        this->settings      = _settings;
    }
    bool Next()
    {
        if (this->pos >= this->end)
            return false; // stop getting the next character
        if (this->ec.FromEncoding(this->settings->encoding, this->pos, this->end))
        {
            this->ch = this->ec.GetChar();
            this->pos += this->ec.Length();
            this->xPos               = this->nextPos;
            this->charIndex          = this->nextCharIndex++;
            if (this->ch == '\t')
            {
                this->ch      = ' '; // tab will be showd as a space
                this->nextPos = this->settings->tabSize - (this->nextPos % this->settings->tabSize);
            }
            else
                this->nextPos++;
        }
        else
        {
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
    inline uint32 GetCharIndex() const
    {
        return this->charIndex;
    }
    inline void ResetXOffset(uint32 value = 0)
    {
        this->xPos = this->nextPos = value;
    }
    inline char16 GetCharacter() const
    {
        return this->ch;
    }
    inline uint32 GetCurrentBufferPos() const
    {
        return (uint32) (this->pos - this->start);
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

    this->lineNumberWidth  = 0;
    this->ViewDataCount    = 0;
    this->Cursor.lineNo    = 0;
    this->Cursor.charIndex = 0;
    this->subLineIndex.Create(256); // alocate 256 entries

    this->settings->encoding = CharacterEncoding::AnalyzeBufferForEncoding(this->obj->GetData().Get(0, 4096, false), true, this->sizeOfBOM);
    this->UpdateViewBounderies();
}

void Instance::RecomputeLineIndexes()
{
    // first --> simple estimation
    auto buf        = this->obj->GetData().Get(0, 4096, false);
    auto sz         = this->obj->GetData().GetSize();
    auto csz        = this->obj->GetData().GetCacheSize() & 0xFFFFFFF0; // make sure that csz is odd
    auto crlf_count = (uint64) 1;

    for (auto ch : buf)
        if ((ch == '\n') || (ch == '\r'))
            crlf_count++;

    auto estimated_count = ((crlf_count * sz) / buf.GetLength()) + 16;

    this->lines.clear();
    this->lines.reserve(estimated_count);

    uint64 offset    = this->sizeOfBOM;
    uint64 start     = this->sizeOfBOM;
    uint32 charCount = 0;
    char16 lastChar  = 0;

    CharacterEncoding::ExpandedCharacter ch;

    while (offset < sz)
    {
        buf = this->obj->GetData().Get(offset, csz, false);
        if (buf.Empty())
            return;
        // process the buffer
        auto* p       = buf.begin();
        auto* e       = buf.end();
        auto* loopEnd = buf.end();
        if (((offset + buf.GetLength()) < sz) && (buf.GetLength() > 16))
        {
            // if this is a partial part of the file and it has more then 16 bytes, deduct 8 bytes to make sure that any possible conversion
            // will be made
            loopEnd -= 8;
        }
        while (p < loopEnd)
        {
            if (ch.FromEncoding(this->settings->encoding, p, e))
            {
                p += ch.Length();
                auto chr = ch.GetChar();
                if (((chr == '\n') && (lastChar != '\r')) || ((chr == '\r') && (lastChar != '\n')))
                {
                    // end of the current line
                    lines.emplace_back(start, charCount, (uint32) (offset - start));
                    offset += ch.Length();
                    start     = offset;
                    charCount = 0;
                    lastChar  = chr;
                    continue;
                }

                // combined CRLF or LFCR
                if (((chr == '\n') && (lastChar == '\r')) || ((chr == '\r') && (lastChar == '\n')))
                {
                    // just advanced one extra char (no new line found)
                    offset += ch.Length();
                    start     = offset;
                    charCount = 0;
                    lastChar  = 0; // important as the CRLF or LFCR has ended
                    continue;
                }

                // other character
                lastChar = 0; // don't care
                charCount++;
                offset += ch.Length();
                if (charCount > 2000)
                {
                    // limit line to 2000 characters
                    lines.emplace_back(start, charCount, (uint32) (offset - start));
                    start     = offset;
                    charCount = 0;
                }
            }
            else
            {
                // need to treat conversion error
                // consider one character (binary format)
                charCount++;
                offset++;
                p++;
                if (charCount > 2000)
                {
                    // limit line to 2000 characters
                    lines.emplace_back(start, charCount, (uint32) (offset - start));
                    start     = offset;
                    charCount = 0;
                }
            }
        }
        if (charCount > 0)
        {
            // last line
            lines.emplace_back(start, charCount, (uint32) (offset - start));
        }
    }

    auto linesCount = this->lines.size() + 1;
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
bool Instance::GetLineInfo(uint32 lineNo, LineInfo& li)
{
    if (lineNo >= this->lines.size())
        return false;
    li = this->lines[lineNo];
    return true;
}
LineInfo Instance::GetLineInfo(uint32 lineNo)
{
    const auto sz = this->lines.size();
    if (lineNo < sz)
        return this->lines[lineNo];
    // if its outside --> always return the last line
    if (sz > 0)
        return this->lines[sz - 1];
    // otherwise return an empty line
    return LineInfo(0, 0, 0);
}
bool Instance::ComputeSubLineIndexes(uint32 lineNo, BufferView& buf, uint64& startOffset)
{
    LineInfo li;
    uint32 w    = this->GetWidth();
    startOffset = 0;

    this->subLineIndex.Clear();
    CHECK(GetLineInfo(lineNo, li), false, "");
    startOffset = li.offset;
    CHECK(this->subLineIndex.Push(0), false, "");

    if ((this->lineNumberWidth + 1) >= w)
        w = 1;
    else
        w -= (this->lineNumberWidth + 1);
    buf = this->obj->GetData().Get(li.offset, li.size, false);
    CharacterStream cs(buf, 0, this->settings.ToReference());
    // process
    if (this->settings->wordWrap)
    {
        while (cs.Next())
        {
            if (cs.GetXOffset() >= w)
            {
                // move to next line
                this->subLineIndex.Push(cs.GetCharIndex());
                cs.ResetXOffset();
            }
        }
    }
    return true;
}
void Instance::MoveTo(uint32 lineNo, uint32 charIndex, bool select)
{
    // sanity checks
    if (lineNo > this->lines.size())
        lineNo = this->lines.size() - 1;
    LineInfo li = GetLineInfo(lineNo);
    if (charIndex >= li.charsCount)
    {
        charIndex = li.charsCount == 0 ? 0 : li.charsCount - 1;
    }
    // all good -> valid values for lineNo and charIndex

    this->Cursor.lineNo    = lineNo;
    this->Cursor.charIndex = charIndex;
}
void Instance::MoveToStartOfLine(uint32 lineNo, bool select)
{
    if (lineNo >= this->lines.size())
        MoveToEndOfLine(this->lines.size() - 1, select); // last position
    else
        MoveTo(lineNo, 0, select);
}
void Instance::MoveToEndOfLine(uint32 lineNo, bool select)
{
    LineInfo li = GetLineInfo(lineNo);
    if (li.charsCount > 0)
        MoveTo(lineNo, li.charsCount - 1, select);
    else
        MoveTo(lineNo, 0, select);
}
void Instance::MoveLeft(bool select)
{
    if (this->Cursor.charIndex > 0)
    {
        MoveTo(this->Cursor.lineNo, this->Cursor.charIndex - 1, select);
    }
    else
    {
        if (this->Cursor.lineNo == 0)
            MoveTo(0, 0, select);
        else
            MoveToEndOfLine(this->Cursor.lineNo - 1, select);
    }
}
void Instance::MoveRight(bool select)
{
    LineInfo li = GetLineInfo(this->Cursor.lineNo);
    if (this->Cursor.charIndex + 1 < li.charsCount)
        MoveTo(this->Cursor.lineNo, this->Cursor.charIndex + 1, select);
    else
        MoveToStartOfLine(this->Cursor.lineNo + 1, select);
}
void Instance::UpdateViewBounderies()
{
    BufferView buf;
    auto h   = this->GetHeight();
    uint32 w = this->GetWidth();
    if (w <= (this->lineNumberWidth + 2))
        w = 0;
    else
        w = w - (this->lineNumberWidth + 2);
    uint64 lineStartOffset = 0;
    auto y                 = 0;
    auto lineNo            = 0U;
    auto vd                = this->ViewData;
    this->ViewDataCount    = 0;
    auto xScroll           = 0U; // temporary -> should be a class data member
    auto xMaxPos           = xScroll + w;
    auto nrLines           = lines.size();

    while ((y < h) && (lineNo < nrLines))
    {
        ComputeSubLineIndexes(lineNo, buf, lineStartOffset);

        // write text
        auto idx    = this->subLineIndex.GetUInt32Array();
        auto idxEnd = idx + this->subLineIndex.Len();
        auto cBuf   = buf.begin();

        // parse each sub-line
        while ((idx < idxEnd) && (y < h))
        {
            auto start = *idx;
            auto end   = (idx + 1) < idxEnd ? idx[1] : (uint32) buf.GetLength();
            CharacterStream cs(BufferView(cBuf + start, end - start), start, this->settings.ToReference());

            // skip left part
            if (xScroll > 0)
            {
                while ((cs.Next()) && (cs.GetNextXOffset() < xScroll))
                {
                }
            }
            auto cptr  = cs.GetCurrentBufferPos();
            vd->lineNo = lineNo;
            vd->pos    = lineStartOffset + start + cptr;
            vd->xStart = cs.GetNextXOffset() - xScroll;
            while ((cs.Next()) && (cs.GetXOffset() < xMaxPos))
            {
            }
            vd->bufferSize = (uint32) (cs.GetCurrentBufferPos() - cptr);

            y++;
            idx++;
            vd++;
            this->ViewDataCount++;
        }
        lineNo++;
    }
}
void Instance::DrawLine(uint32 y, Graphics::Renderer& renderer, ControlState state, bool showLineNumber)
{
    BufferView buf;
    NumericFormatter n;
    ColorPair textColor;

    auto lineNoColor  = Cfg.LineMarker.GetColor(state);
    auto lineSepColor = Cfg.Lines.GetColor(state);
    bool focused      = state == ControlState::Focused;

    switch (state)
    {
    case ControlState::Focused:
        textColor = Cfg.Text.Normal;
        break;
    default:
        textColor = Cfg.Text.Inactive;
        break;
    }
    const auto vd = this->ViewData + y;
    CharacterStream cs(this->obj->GetData().Get(vd->pos, vd->bufferSize, false), vd->pos, this->settings.ToReference());
    auto c     = this->chars;
    auto lastC = this->chars + 1;
    auto c_end = c + MAX_CHARACTERS_PER_LINE;
    while ((cs.Next()) && (lastC < c_end))
    {
        auto c = this->chars + cs.GetXOffset();
        // fill in the spaces
        while (lastC < c)
        {
            lastC->Code  = ' ';
            lastC->Color = textColor;
            lastC++;
        }
        c->Code  = cs.GetCharacter();
        c->Color = textColor;
        if ((focused) && (vd->lineNo == Cursor.lineNo) && (cs.GetCharIndex() == Cursor.charIndex))
            c->Color = Cfg.Cursor.Normal;
        lastC = c + 1;
    }
    renderer.FillHorizontalLine(0, y, this->lineNumberWidth - 1, ' ', lineNoColor);
    if (showLineNumber)
        renderer.WriteSingleLineText(0, y, this->lineNumberWidth, n.ToDec(vd->lineNo + 1), lineNoColor, TextAlignament::Right);
    renderer.WriteSpecialCharacter(this->lineNumberWidth, y, SpecialChars::BoxVerticalSingleLine, lineSepColor);
    renderer.WriteSingleLineCharacterBuffer(this->lineNumberWidth + 1, y, CharacterView(chars, (size_t) (lastC - chars)), false);
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    auto idx         = 0;
    auto lineNo      = 0xFFFFFFFFU;
    const auto focus = this->HasFocus();

    if (this->ViewDataCount == 0)
        UpdateViewBounderies();

    while (idx < this->ViewDataCount)
    {
        auto state         = focus ? ControlState::Focused : ControlState::Normal;
        const auto cLineNo = this->ViewData[idx].lineNo;
        DrawLine(idx, renderer, state, cLineNo != lineNo);
        lineNo = cLineNo;
        idx++;
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    if (this->settings->wordWrap)
        commandBar.SetCommand(config.Keys.WordWrap, "WordWrap:ON", CMD_ID_WORD_WRAP);
    else
        commandBar.SetCommand(config.Keys.WordWrap, "WordWrap:OFF", CMD_ID_WORD_WRAP);

    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    switch (keyCode)
    {
    case Key::Left:
        MoveLeft(false);
        return true;
    case Key::Left | Key::Shift:
        MoveLeft(true);
        return true;
    case Key::Right:
        MoveRight(false);
        return true;
    case Key::Right | Key::Shift:
        MoveRight(true);
        return true;
    case Key::Home:
        MoveToStartOfLine(this->Cursor.lineNo, false);
        return true;
    case Key::Home | Key::Shift:
        MoveToStartOfLine(this->Cursor.lineNo, true);
        return true;
    case Key::End:
        MoveToEndOfLine(this->Cursor.lineNo, false);
        return true;
    case Key::End | Key::Shift:
        MoveToEndOfLine(this->Cursor.lineNo, true);
        return true;
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
        UpdateViewBounderies();
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