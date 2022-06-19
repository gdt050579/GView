#include "TextViewer.hpp"
#include <algorithm>

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_WORD_WRAP     = 0xBF00;
constexpr uint32 INVALID_LINE_NUMBER = 0xFFFFFFFF;

enum class BulletParserState : uint8
{
    FirstPadding,
    Bullet,
    NextPadding
};

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
    bool decodingError;
    bool charIsTab;

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
            this->decodingError = false;
            this->ch            = this->ec.GetChar();
            this->charIsTab     = ch == '\t';
            this->pos += this->ec.Length();
            this->xPos      = this->nextPos;
            this->charIndex = this->nextCharIndex++;
            if (this->charIsTab)
            {
                this->ch = settings->showTabCharacter ? 0x2192 : ' '; // tab will be showd as a space
                this->nextPos += this->settings->tabSize - (this->xPos % this->settings->tabSize);
            }
            else
                this->nextPos++;
        }
        else
        {
            // conversion error
            this->decodingError = true;
            this->ch            = *this->pos; // binary character
            this->charIsTab     = false;
            this->pos++;
            this->xPos      = this->nextPos++;
            this->charIndex = this->nextCharIndex++;
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
    inline uint32 GetNextCharIndex() const
    {
        return this->nextCharIndex;
    }
    inline void ResetXOffset(uint32 value = 0)
    {
        this->xPos = this->nextPos = value;
    }
    inline char16 GetCharacter() const
    {
        return this->ch;
    }
    inline bool IsTabCharacter() const
    {
        return this->charIsTab;
    }
    inline uint32 GetCurrentBufferPos() const
    {
        return (uint32) (this->pos - this->start);
    }
    inline bool HasDecodingErrors() const
    {
        return this->decodingError;
    }
};

Instance::Instance(const std::string_view& _name, Reference<GView::Object> _obj, Settings* _settings)
    : settings(nullptr), ViewControl(UserControlFlags::ShowVerticalScrollBar | UserControlFlags::ScrollBarOutsideControl)
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
    this->SubLines.entries.reserve(256); // reserve 256 sub-lines
    this->SubLines.lineNo  = INVALID_LINE_NUMBER;
    this->ViewPort.scrollX = 0;
    this->ViewPort.Reset();

    this->settings->encoding = CharacterEncoding::AnalyzeBufferForEncoding(this->obj->GetData().Get(0, 4096, false), true, this->sizeOfBOM);
    this->MoveTo(0, 0, false);
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
void Instance::ComputeSubLineIndexes(uint32 lineNo, BufferView& buf, uint64& startOffset)
{
    if (lineNo == this->SubLines.lineNo)
        return; // we've already computed this --> no need to computed again

    LineInfo li            = GetLineInfo(lineNo);
    uint32 w               = this->GetWidth();
    uint32 bufPos          = 0;
    uint32 charIndex       = 0;
    bool computeAlignament = true;
    auto bp                = BulletParserState::FirstPadding;
    uint32 bpBulletWidth   = 0;
    startOffset            = li.offset;

    //---------------------------------------------------
    //|  We will always have at least ONE sub-line      |
    //---------------------------------------------------
    this->SubLines.entries.clear();
    this->SubLines.lineNo         = lineNo;
    this->SubLines.leftAlignament = 0;

    if ((this->lineNumberWidth + 2) >= w)
        w = 1;
    else
        w -= (this->lineNumberWidth + 2);
    buf = this->obj->GetData().Get(li.offset, li.size, false);
    CharacterStream cs(buf, 0, this->settings.ToReference());
    // process

    if (this->settings->wrapMethod != WrapMethod::None)
    {
        // parse first sub-line
        while (cs.Next())
        {
            if (cs.GetNextXOffset() > w)
            {
                // move to next line
                this->SubLines.entries.emplace_back(
                      bufPos, cs.GetCurrentBufferPos() - bufPos, charIndex, cs.GetNextCharIndex() - charIndex);
                bufPos            = cs.GetCurrentBufferPos();
                charIndex         = cs.GetNextCharIndex();
                computeAlignament = false;
                cs.ResetXOffset(this->SubLines.leftAlignament);
            }
            if (computeAlignament)
            {
                switch (this->settings->wrapMethod)
                {
                case WrapMethod::LeftMargin:
                    computeAlignament             = false;
                    this->SubLines.leftAlignament = 0;
                    break;
                case WrapMethod::Padding:
                    if ((cs.GetCharacter() == ' ') || (cs.IsTabCharacter()))
                        this->SubLines.leftAlignament = cs.GetNextXOffset();
                    else
                        computeAlignament = false;
                    break;
                case WrapMethod::Bullets:
                    // its important for the parser to check this states in this order (next padding, first padding and bullet)
                    if (bp == BulletParserState::NextPadding)
                    {
                        if ((cs.GetCharacter() == ' ') || (cs.IsTabCharacter()))
                            this->SubLines.leftAlignament = cs.GetNextXOffset();
                        else
                            computeAlignament = false;
                    }
                    if (bp == BulletParserState::FirstPadding)
                    {
                        if ((cs.GetCharacter() == ' ') || (cs.IsTabCharacter()))
                            this->SubLines.leftAlignament = cs.GetNextXOffset();
                        else
                        {
                            bp            = BulletParserState::Bullet;
                            bpBulletWidth = 0;
                        }
                    }
                    if (bp == BulletParserState::Bullet)
                    {
                        this->SubLines.leftAlignament = cs.GetNextXOffset();
                        bpBulletWidth++;
                        if ((cs.GetCharacter() == '-') || (cs.GetCharacter() == '*') || (cs.GetCharacter() == '.') ||
                            (cs.GetCharacter() == ')'))
                            bp = BulletParserState::NextPadding;
                        else if (bpBulletWidth > 4)
                        {
                            // no special bullet detected --> align normally to the left margin
                            computeAlignament             = false;
                            this->SubLines.leftAlignament = 0;
                        }
                    }
                    break;
                default:
                    computeAlignament = false;
                    break;
                }
            }
        }
        if (cs.GetCurrentBufferPos() > bufPos)
            this->SubLines.entries.emplace_back(bufPos, cs.GetCurrentBufferPos() - bufPos, charIndex, cs.GetCharIndex() - charIndex);
        // there should always be at least one sub-line
        if (this->SubLines.entries.empty())
        {
            this->SubLines.entries.emplace_back(0, 0, 0, 0);
            this->SubLines.lineNo = INVALID_LINE_NUMBER; // need to recompute
        }
    }
    else
    {
        this->SubLines.entries.emplace_back(0, li.size, 0, li.charsCount);
        if ((li.size == 0) || (li.charsCount == 0))
        {
            this->SubLines.lineNo = INVALID_LINE_NUMBER; // need to recompute
        }
    }
}
void Instance::ComputeSubLineIndexes(uint32 lineNo)
{
    if (lineNo == this->SubLines.lineNo)
        return; // we've already computed this --> no need to computed again
    uint64 startOffset;
    BufferView buf;
    ComputeSubLineIndexes(lineNo, buf, startOffset);
}
uint32 Instance::CharacterIndexToSubLineNo(uint32 charIndex)
{
    // binary search
    auto start  = 0U;
    auto end    = static_cast<uint32>(this->SubLines.entries.size() - 1); // always at least one
    auto middle = (start + end) >> 1;

    if (end == 0)
        return 0;                       // only one-subline
    auto lastValidStartIndex = end - 1; // end is bigger than 0
    // boundery check
    if (charIndex < this->SubLines.entries[0].relativeCharIndex)
        return 0;
    const auto& last = this->SubLines.entries[end];
    if (charIndex > last.relativeCharIndex + last.charsCount)
        return end;

    while (true)
    {
        const auto& sl   = this->SubLines.entries[middle];
        const auto& next = this->SubLines.entries[middle + 1];
        if ((charIndex >= sl.relativeCharIndex) && (charIndex < next.relativeCharIndex))
            return middle;

        if (charIndex < sl.relativeCharIndex)
        {
            end = middle - 1;
            if (middle == 0)
                return 0; // sanity check --> in reality this case can not happen
        }
        else
        {
            start = middle + 1;
            if (start > lastValidStartIndex)
                return static_cast<uint32>(this->SubLines.entries.size() - 1);
        }
        middle = (start + end) >> 1;
    }
}
void Instance::CommputeViewPort_NoWrap(uint32 lineNo, Direction dir)
{
    auto h       = (std::min<>(static_cast<uint32>(std::max<>(this->GetHeight(), 1)), MAX_LINES_TO_VIEW)) - 1U;
    uint32 start = lineNo;
    auto* l      = ViewPort.Lines;

    if (dir == Direction::BottomToTop)
    {
        start = lineNo > h ? lineNo - h : 0;
    }

    ViewPort.Reset();
    if (this->lines.empty())
        return;

    uint32 lastLineNo = static_cast<uint32>(this->lines.size() - 1); // lines.size() will alway be bigger than 1

    // sets the view port
    ViewPort.Start.lineNo    = start;
    ViewPort.Start.subLineNo = 0;
    ViewPort.End.lineNo      = ((start + h) > lastLineNo) ? lastLineNo : (start + h);
    ViewPort.End.subLineNo   = 0;

    // populate the lines
    ViewPort.linesCount = (ViewPort.End.lineNo + 1) - ViewPort.Start.lineNo;
    auto* l_end         = l + ViewPort.linesCount;
    while (l < l_end)
    {
        auto lineInfo    = GetLineInfo(start);
        l->lineNo        = start;
        l->size          = lineInfo.size;
        l->offset        = lineInfo.offset;
        l->xStart        = 0;
        l->lineCharIndex = 0;
        start++;
        l++;
    }
}
void Instance::CommputeViewPort_Wrap(uint32 lineNo, uint32 subLineNo, Direction dir)
{
    auto h = (std::min<>(static_cast<uint32>(std::max<>(this->GetHeight(), 1)), MAX_LINES_TO_VIEW));

    ViewPort.Reset();
    if (this->lines.empty())
        return;
    if (dir == Direction::TopToBottom)
    {
        ViewPort.Start.lineNo    = lineNo;
        ViewPort.Start.subLineNo = subLineNo;
        ViewPort.End.lineNo      = lineNo;
        ViewPort.End.subLineNo   = subLineNo;
        auto start               = lineNo;
        auto startSL             = subLineNo;
        auto* l                  = ViewPort.Lines;
        const auto* l_max        = l + h;

        while ((l < l_max) && (start < this->lines.size()))
        {
            auto lineInfo = GetLineInfo(start);
            ComputeSubLineIndexes(start);
            ViewPort.End.lineNo    = start;
            ViewPort.End.subLineNo = 0; // default value
            while ((l < l_max) && (startSL < this->SubLines.entries.size()))
            {
                const auto& sl   = this->SubLines.entries[startSL];
                l->lineNo        = start;
                l->offset        = sl.relativeOffset + lineInfo.offset;
                l->xStart        = startSL == 0 ? 0 : this->SubLines.leftAlignament;
                l->size          = sl.size;
                l->lineCharIndex = sl.relativeCharIndex;
                l++;
                ViewPort.End.subLineNo = startSL;
                startSL++;
            }
            startSL = 0; // reset sub-line index
            start++;
        }

        ViewPort.linesCount = (uint32) (l - ViewPort.Lines);
    }
    else
    {
        ViewPort.Start.lineNo    = lineNo;
        ViewPort.Start.subLineNo = subLineNo;
        ViewPort.End.lineNo      = lineNo;
        ViewPort.End.subLineNo   = subLineNo;
        auto* l                  = ViewPort.Lines + MAX_LINES_TO_VIEW - 1;
        const auto* l_min        = l - h;
        auto start               = (int32) lineNo;
        auto startSL             = (int32) subLineNo;
        bool resetSL             = false;
        while ((l > l_min) && (start >= 0))
        {
            auto lineInfo = GetLineInfo(start);
            ComputeSubLineIndexes(start);
            ViewPort.Start.lineNo = start;
            if (resetSL)
                startSL = static_cast<uint32>(this->SubLines.entries.size() - 1); // default value
            ViewPort.Start.subLineNo = startSL;
            while ((l > l_min) && (startSL >= 0))
            {
                const auto& sl   = this->SubLines.entries[startSL];
                l->lineNo        = start;
                l->offset        = sl.relativeOffset + lineInfo.offset;
                l->xStart        = startSL == 0 ? 0 : this->SubLines.leftAlignament;
                l->size          = sl.size;
                l->lineCharIndex = sl.relativeCharIndex;
                l--;
                ViewPort.Start.subLineNo = startSL;
                startSL--;
            }
            resetSL = true;
            start--;
        }
        l++; // last added line
        ViewPort.linesCount = (uint32) ((ViewPort.Lines + MAX_LINES_TO_VIEW) - l);
        // we need to move the lines to the first position
        if (l != ViewPort.Lines)
        {
            memmove(ViewPort.Lines, l, ViewPort.linesCount * sizeof(ViewPort.Lines[0]));
        }
    }
}
void Instance::ComputeViewPort(uint32 lineNo, uint32 subLineNo, Direction dir)
{
    if (this->HasWordWrap())
        CommputeViewPort_Wrap(lineNo, subLineNo, dir);
    else
        CommputeViewPort_NoWrap(lineNo, dir);
}
void Instance::MoveTo(uint32 lineNo, uint32 charIndex, bool select)
{
    auto sidx = -1;
    if (select)
        sidx = this->selection.BeginSelection(this->Cursor.pos);
    // sanity checks
    if (this->lines.size() == 0)
    {
        lineNo = 0;
    }
    else
    {
        if (lineNo >= static_cast<uint32>(this->lines.size()))
            lineNo = static_cast<uint32>(this->lines.size() - 1);
    }
    LineInfo li = GetLineInfo(lineNo);
    if (charIndex >= li.charsCount)
    {
        charIndex = li.charsCount == 0 ? 0 : li.charsCount - 1;
    }
    // all good -> valid values for lineNo and charIndex

    this->Cursor.lineNo    = lineNo;
    this->Cursor.charIndex = charIndex;
    if (this->HasWordWrap())
    {
        // find the new subline for the cursor
        ComputeSubLineIndexes(lineNo);
        this->Cursor.sublineNo = CharacterIndexToSubLineNo(charIndex);
    }
    else
    {
        // no sublines
        this->Cursor.sublineNo = 0;
    }
    this->UpdateViewPort();
    if ((select) && (sidx >= 0))
    {
        this->selection.UpdateSelection(sidx, this->Cursor.pos);
    }
}
void Instance::MoveToStartOfLine(uint32 lineNo, bool select)
{
    if (lineNo >= this->lines.size())
        MoveToEndOfLine(static_cast<uint32>(this->lines.size() - 1), select); // last position
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
void Instance::MoveToEndOfFile(bool select)
{
    if (this->lines.empty())
        return;
    MoveTo(static_cast<uint32>(this->lines.size() - 1), 0xFFFFFFFF, select);
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
void Instance::MoveDown(uint32 noOfTimes, bool select)
{
    if (this->lines.size() == 0)
        return; // safety check
    uint32 lastLine = static_cast<uint32>(this->lines.size() - 1);
    if (HasWordWrap())
    {
        auto lineNo = this->Cursor.lineNo;
        ComputeSubLineIndexes(lineNo);
        auto slIndex              = CharacterIndexToSubLineNo(this->Cursor.charIndex);
        const auto initialSubLine = slIndex;
        const auto charIndexDif   = this->Cursor.charIndex > this->SubLines.entries[slIndex].relativeCharIndex
                                          ? this->Cursor.charIndex - this->SubLines.entries[slIndex].relativeCharIndex
                                          : 0U;
        while (true)
        {
            ComputeSubLineIndexes(lineNo);
            const auto slCount = static_cast<uint32>(this->SubLines.entries.size());
            const auto dif     = std::min<>(noOfTimes, slCount - slIndex);
            noOfTimes -= dif;
            slIndex += dif;
            if (noOfTimes > 0)
            {
                lineNo++;
                slIndex = 0;
                if (lineNo > lastLine)
                {
                    lineNo    = lastLine;
                    noOfTimes = 0;
                    slIndex   = slCount - 1; // last subline
                }
            }
            else
            {
                if (slIndex >= slCount)
                {
                    if (lineNo < lastLine)
                    {
                        // move to next line
                        lineNo++;
                        slIndex = 0;
                    }
                    else
                    {
                        // we are already at the last line
                        if (initialSubLine + 1 == slCount)
                        {
                            MoveToEndOfLine(lastLine, select);
                            return;
                        }
                        else
                        {
                            slIndex = slCount - 1;
                        }
                    }
                }
                break;
            }
        }
        const auto& currentSL = this->SubLines.entries[slIndex];
        if (currentSL.charsCount == 0)
            MoveTo(lineNo, currentSL.relativeCharIndex, select);
        else
            MoveTo(lineNo, currentSL.relativeCharIndex + std::min<>(currentSL.charsCount - 1, charIndexDif), select);
    }
    else
    {
        if (Cursor.lineNo == lastLine)
            MoveToEndOfLine(lastLine, select);
        else
            MoveTo(std::min<>(lastLine, this->Cursor.lineNo + noOfTimes), this->Cursor.charIndex, select);
    }
}
void Instance::MoveUp(uint32 noOfTimes, bool select)
{
    if (HasWordWrap())
    {
        auto lineNo = this->Cursor.lineNo;
        ComputeSubLineIndexes(lineNo);
        auto slIndex              = CharacterIndexToSubLineNo(this->Cursor.charIndex);
        const auto initialSubLine = slIndex;
        const auto charIndexDif   = this->Cursor.charIndex > this->SubLines.entries[slIndex].relativeCharIndex
                                          ? this->Cursor.charIndex - this->SubLines.entries[slIndex].relativeCharIndex
                                          : 0U;
        while (true)
        {
            ComputeSubLineIndexes(lineNo);
            const auto dif = std::min<>(noOfTimes, slIndex);
            noOfTimes -= dif;
            slIndex -= dif;
            if (noOfTimes > 0)
            {
                // slIndex is definetelly 0 (as dif is the smallest from noOfTimes and slIndex)
                // we've reached the first sub-line
                if (lineNo > 0)
                {
                    // move one line up
                    lineNo--;
                    ComputeSubLineIndexes(lineNo);
                    slIndex = static_cast<uint32>(this->SubLines.entries.size()) - 1;
                    noOfTimes--;
                    if (noOfTimes == 0)
                        break;
                }
                else
                {
                    MoveToStartOfLine(0, select);
                    return;
                }
            }
            else
            {
                // noOfTimes is 0
                break;
            }
        }
        const auto& currentSL = this->SubLines.entries[slIndex];
        if (currentSL.charsCount == 0)
            MoveTo(lineNo, currentSL.relativeCharIndex, select);
        else
            MoveTo(lineNo, currentSL.relativeCharIndex + std::min<>(currentSL.charsCount - 1, charIndexDif), select);
    }
    else
    {
        if (Cursor.lineNo == 0)
            MoveToStartOfLine(0, select);
        else
        {
            if (Cursor.lineNo > noOfTimes)
                MoveTo(Cursor.lineNo - noOfTimes, this->Cursor.charIndex, select);
            else
                MoveTo(0, this->Cursor.charIndex, select);
        }
    }
}
void Instance::UpdateCursor_NoWrap()
{
    auto li = GetLineInfo(Cursor.lineNo);
    // simple checkes
    if (Cursor.charIndex == 0)
    {
        this->ViewPort.scrollX = 0;
        this->Cursor.pos       = li.offset;
        return; // obvious --> first char is first in the line
    }

    uint32 w = this->GetWidth();
    w        = (w <= (this->lineNumberWidth + 1)) ? 1 : w - (this->lineNumberWidth + 1);
    auto idx = 0U;

    CharacterStream cs(this->obj->GetData().Get(li.offset, li.size, false), 0, this->settings.ToReference());
    // while ((cs.Next()) && (idx < Cursor.charIndex))
    while ((idx < Cursor.charIndex) && (cs.Next()))
    {
        idx++;
    }
    uint32 newXPos;
    if (idx == Cursor.charIndex)
    {
        newXPos    = cs.GetNextXOffset();
        Cursor.pos = static_cast<uint64>(cs.GetCurrentBufferPos()) + li.offset;
    }
    else
    {
        newXPos    = 0;
        Cursor.pos = 0; // de vazut daca e ok
    }
    if ((newXPos >= this->ViewPort.scrollX) && (newXPos < (this->ViewPort.scrollX + w)))
        return; // already visible
    if (newXPos <= this->ViewPort.scrollX)
    {
        this->ViewPort.scrollX = newXPos;
    }
    else
    {
        this->ViewPort.scrollX = newXPos >= w ? newXPos + 1 - w : 0;
    }
}
void Instance::UpdateCursor_Wrap()
{
    // only file pos need to be computed
    auto li = GetLineInfo(Cursor.lineNo);
    ComputeSubLineIndexes(Cursor.lineNo);
    Cursor.sublineNo = CharacterIndexToSubLineNo(Cursor.charIndex);
    const auto& sl   = this->SubLines.entries[Cursor.sublineNo];
    auto idx         = sl.relativeCharIndex;
    CharacterStream cs(this->obj->GetData().Get(sl.relativeOffset + li.offset, sl.size, false), 0, this->settings.ToReference());
    // while ((cs.Next()) && (idx < Cursor.charIndex))
    while ((idx < Cursor.charIndex) && (cs.Next()))
    {
        idx++;
    }
    if (idx == Cursor.charIndex)
    {
        Cursor.pos = static_cast<uint64>(cs.GetCurrentBufferPos()) + li.offset + sl.relativeOffset;
    }
    else
    {
        Cursor.pos = 0; // de vazut daca e ok
    }
}
void Instance::UpdateViewPort()
{
    if (ViewPort.linesCount == 0)
    {
        ComputeViewPort(0, 0, Direction::TopToBottom);
        if (!HasWordWrap())
            UpdateCursor_NoWrap();
        else
            UpdateCursor_Wrap();
    }
    if ((Cursor.lineNo < ViewPort.Start.lineNo) ||
        ((Cursor.lineNo == ViewPort.Start.lineNo) && (Cursor.sublineNo < ViewPort.Start.subLineNo)))
    {
        // cursor is before current ViewPort
        ComputeViewPort(Cursor.lineNo, Cursor.sublineNo, Direction::TopToBottom);
        if (!HasWordWrap())
            UpdateCursor_NoWrap();
        else
            UpdateCursor_Wrap();
        return;
    }
    if ((Cursor.lineNo > ViewPort.End.lineNo) || ((Cursor.lineNo == ViewPort.End.lineNo) && (Cursor.sublineNo > ViewPort.End.subLineNo)))
    {
        // cursor is after
        ComputeViewPort(Cursor.lineNo, Cursor.sublineNo, Direction::BottomToTop);
        if (!HasWordWrap())
            UpdateCursor_NoWrap();
        else
            UpdateCursor_Wrap();
        return;
    }
    // else the viewport is ok --> xOffset has to be computed
    if (!HasWordWrap())
        UpdateCursor_NoWrap();
    else
        UpdateCursor_Wrap();
}
void Instance::DrawLine(uint32 y, Graphics::Renderer& renderer, ControlState state, bool showLineNumber)
{
    BufferView buf;
    NumericFormatter n;
    ColorPair textColor;

    auto lineNoColor  = Cfg.LineMarker.GetColor(state);
    auto lineSepColor = Cfg.Lines.GetColor(state);
    bool focused      = state == ControlState::Focused;
    const auto vd     = this->ViewPort.Lines + y;

    switch (state)
    {
    case ControlState::Focused:
        if ((vd->lineNo == this->Cursor.lineNo) && (this->settings->highlightCurrentLine))
        {
            textColor   = Cfg.Editor.Focused;
            lineNoColor = Cfg.Selection.Editor;
            renderer.FillHorizontalLine(this->lineNumberWidth + 1, y, this->GetWidth(), ' ', Cfg.Editor.Focused);
        }
        else
        {
            textColor = Cfg.Text.Focused;
        }
        break;
    default:
        textColor = Cfg.Text.Inactive;
        break;
    }

    // fill in the line and the line number

    renderer.FillHorizontalLine(0, y, this->lineNumberWidth - 1, ' ', lineNoColor);
    if (showLineNumber)
        renderer.WriteSingleLineText(0, y, this->lineNumberWidth, n.ToDec(vd->lineNo + 1), lineNoColor, TextAlignament::Right);
    renderer.WriteSpecialCharacter(this->lineNumberWidth, y, SpecialChars::BoxVerticalSingleLine, lineSepColor);

    if (vd->size > 0)
    {
        CharacterStream cs(this->obj->GetData().Get(vd->offset, vd->size, false), 0, this->settings.ToReference());
        auto c       = this->chars;
        auto lastC   = this->chars;
        auto c_end   = c + MAX_CHARACTERS_PER_LINE;
        auto xScroll = 0U;

        if (ViewPort.scrollX > 0)
        {
            while (cs.Next())
            {
                if (cs.GetNextXOffset() >= ViewPort.scrollX)
                {
                    xScroll = ViewPort.scrollX;
                    break;
                }
            }
        }
        auto bufPos = cs.GetCurrentBufferPos();
        while ((cs.Next()) && (lastC < c_end))
        {
            auto c = this->chars + (cs.GetXOffset() + vd->xStart - xScroll);
            if (c >= c_end) // safety check
                break;
            // fill in the spaces

            while (lastC < c)
            {
                lastC->Code  = ' ';
                lastC->Color = textColor;
                lastC++;
            }

            c->Code  = cs.GetCharacter();
            c->Color = textColor;
            if (focused)
            {
                if (this->selection.Contains(vd->offset + bufPos))
                {
                    if ((vd->lineNo == Cursor.lineNo) && (cs.GetCharIndex() + vd->lineCharIndex == Cursor.charIndex))
                        c->Color = Cfg.Cursor.OverSelection;
                    else
                        c->Color = Cfg.Selection.Editor;
                }
                else
                {
                    if ((vd->lineNo == Cursor.lineNo) && (cs.GetCharIndex() + vd->lineCharIndex == Cursor.charIndex))
                        c->Color = Cfg.Cursor.Normal;
                    else if (cs.HasDecodingErrors())
                        c->Color = Cfg.Text.Error;
                    else if (cs.IsTabCharacter())
                        c->Color = Cfg.Text.Inactive;
                }
            }
            lastC  = c + 1;
            bufPos = cs.GetCurrentBufferPos();
        }
        renderer.WriteSingleLineCharacterBuffer(this->lineNumberWidth + 1, y, CharacterView(chars, (size_t) (lastC - chars)), false);
    }
    else
    {
        // empty line
        if ((focused) && (this->Cursor.lineNo == vd->lineNo))
            renderer.WriteCharacter(this->lineNumberWidth + 1, y, ' ', Cfg.Cursor.Normal);
    }
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    auto idx         = 0U;
    auto lineNo      = INVALID_LINE_NUMBER;
    const auto focus = this->HasFocus();

    if (this->ViewPort.linesCount == 0)
    {
        this->ComputeViewPort(0, 0, Direction::TopToBottom);
        this->UpdateViewPort();
    }

    while (idx < this->ViewPort.linesCount)
    {
        auto state         = focus ? ControlState::Focused : ControlState::Normal;
        const auto cLineNo = this->ViewPort.Lines[idx].lineNo;
        DrawLine(idx, renderer, state, cLineNo != lineNo);
        lineNo = cLineNo;
        idx++;
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    switch (this->settings->wrapMethod)
    {
    case WrapMethod::None:
        commandBar.SetCommand(config.Keys.WordWrap, "Wrap:OFF", CMD_ID_WORD_WRAP);
        break;
    case WrapMethod::LeftMargin:
        commandBar.SetCommand(config.Keys.WordWrap, "Wrap:LeftMargin", CMD_ID_WORD_WRAP);
        break;
    case WrapMethod::Padding:
        commandBar.SetCommand(config.Keys.WordWrap, "Wrap:Padding", CMD_ID_WORD_WRAP);
        break;
    case WrapMethod::Bullets:
        commandBar.SetCommand(config.Keys.WordWrap, "Wrap:Bullets", CMD_ID_WORD_WRAP);
        break;
    }
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
    case Key::Up:
        MoveUp(1, false);
        return true;
    case Key::Up | Key::Shift:
        MoveUp(1, true);
        return true;
    case Key::Down:
        MoveDown(1, false);
        return true;
    case Key::Down | Key::Shift:
        MoveDown(1, true);
        return true;
    case Key::PageUp:
        MoveUp(std::max<>(1, this->GetHeight()), false);
        return true;
    case Key::PageUp | Key::Shift:
        MoveUp(std::max<>(1, this->GetHeight()), true);
        return true;
    case Key::PageDown:
        MoveDown(std::max<>(1, this->GetHeight()), false);
        return true;
    case Key::PageDown | Key::Shift:
        MoveDown(std::max<>(1, this->GetHeight()), true);
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
    case Key::Home | Key::Ctrl:
        MoveTo(0, 0, false);
        return true;
    case Key::Home | Key::Ctrl | Key::Shift:
        MoveTo(0, 0, true);
        return true;
    case Key::End | Key::Ctrl:
        MoveToEndOfFile(false);
        return true;
    case Key::End | Key::Ctrl | Key::Shift:
        MoveToEndOfFile(true);
        return true;
    }

    return false;
}
void Instance::OnStart()
{
    this->RecomputeLineIndexes();
    this->ViewPort.Reset();
    this->UpdateViewPort();
}
void Instance::OnAfterResize(int newWidth, int newHeight)
{
    this->ComputeViewPort(this->ViewPort.Start.lineNo, this->ViewPort.Start.subLineNo, Direction::TopToBottom);
    this->UpdateViewPort();
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType != Event::Command)
        return false;
    switch (ID)
    {
    case CMD_ID_WORD_WRAP:
        switch (this->settings->wrapMethod)
        {
        case WrapMethod::None:
            SetWrapMethod(WrapMethod::LeftMargin);
            break;
        case WrapMethod::LeftMargin:
            SetWrapMethod(WrapMethod::Padding);
            break;
        case WrapMethod::Padding:
            SetWrapMethod(WrapMethod::Bullets);
            break;
        case WrapMethod::Bullets:
            SetWrapMethod(WrapMethod::None);
            break;
        default:
            SetWrapMethod(WrapMethod::None);
            break;
        }
        return true;
    }
    return false;
}
void Instance::OnUpdateScrollBars()
{
    if (this->lines.size()>0)
    {
        const auto& fistLine = this->lines[0];
        const auto& lastLine = this->lines[this->lines.size() - 1];
        const auto maxOfs    = lastLine.offset + lastLine.size;
        auto pos             = std::max<>(this->Cursor.pos, fistLine.offset);        
        this->UpdateVScrollBar(std::min<>(pos, maxOfs), maxOfs);
    }
    else
    {
        this->UpdateVScrollBar(0, 0);
    }
}
void Instance::SetWrapMethod(WrapMethod method)
{
    this->settings->wrapMethod = method;
    this->ViewPort.scrollX     = 0;
    this->SubLines.lineNo      = INVALID_LINE_NUMBER;
    this->ViewPort.Reset();
    this->ComputeViewPort(this->ViewPort.Start.lineNo, this->ViewPort.Start.subLineNo, Direction::TopToBottom);
    this->UpdateViewPort();
}
bool Instance::GoTo(uint64 offset)
{
    auto lineNo = 0U;
    for (lineNo = 0U; lineNo < this->lines.size(); lineNo++)
    {
        if (offset < this->lines[lineNo].offset)
            break;
    }
    if (lineNo > 0)
        lineNo--;
    auto li     = GetLineInfo(lineNo);
    auto cIndex = 0U;
    CharacterStream cs(this->obj->GetData().Get(li.offset, li.size, false), 0, this->settings.ToReference());
    while (cs.Next())
    {
        cIndex = cs.GetCharIndex();
        if ((cs.GetCurrentBufferPos() + li.offset) > offset)
            break;
    }
    MoveTo(lineNo, cIndex, false);
    return true;
}
bool Instance::Select(uint64 offset, uint64 size)
{
    return false; // no selection is possible in this mode
}
bool Instance::ShowGoToDialog()
{
    GoToDialog dlg(this->Cursor.pos, this->obj->GetData().GetSize(), this->Cursor.lineNo + 1U, static_cast<uint32>(this->lines.size()));
    if (dlg.Show() == (int) Dialogs::Result::Ok)
    {
        if (dlg.ShouldGoToLine())
        {
            MoveTo(dlg.GetLine(), 0, false);
        }
        else
        {
            GoTo(dlg.GetFileOffset());
        }
    }
    return true;
}
std::string_view Instance::GetName()
{
    return this->name;
}
//======================================================================[Cursor information]==================
int Instance::PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r)
{
    uint64 start, end;
    bool show = (selectionID == 0) || (this->selection.IsMultiSelectionEnabled());
    if (show)
    {
        if (this->selection.GetSelection(selectionID, start, end))
        {
            LocalString<32> tmp;
            tmp.Format("%X,%X", start, (end - start) + 1);
            r.WriteSingleLineText(x, y, width, tmp.GetText(), this->Cfg.Text.Normal);
        }
        else
        {
            r.WriteSingleLineText(x, y, width, "NO Selection", Cfg.Text.Inactive, TextAlignament::Center);
        }
    }
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->Cfg.Lines.Normal);
    return x + width + 1;
}
void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    LocalString<128> tmp;
    auto xPoz = 0;
    if (height == 1)
    {
        xPoz = PrintSelectionInfo(0, 0, 0, 16, r);
        if (this->selection.IsMultiSelectionEnabled())
        {
            xPoz = PrintSelectionInfo(1, xPoz, 0, 16, r);
            xPoz = PrintSelectionInfo(2, xPoz, 0, 16, r);
            xPoz = PrintSelectionInfo(3, xPoz, 0, 16, r);
        }
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 10, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    }
    else
    {
        PrintSelectionInfo(0, 0, 0, 16, r);
        xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
        PrintSelectionInfo(1, xPoz, 0, 16, r);
        xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
        this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
        xPoz = this->WriteCursorInfo(r, xPoz, 1, 20, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    }
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    WordWrap,
    Encoding,
    HasBOM,
    HighlightCurrentLine,
    TabSize,
    ShowTabCharacter,
    WrapMethodKey,
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::WordWrap:
        value = static_cast<uint64>(this->settings->wrapMethod);
        return true;
    case PropertyID::Encoding:
        value = static_cast<uint32>(this->settings->encoding);
        return true;
    case PropertyID::HasBOM:
        value = this->sizeOfBOM > 0;
        return true;
    case PropertyID::HighlightCurrentLine:
        value = this->settings->highlightCurrentLine;
        return true;
    case PropertyID::TabSize:
        value = this->settings->tabSize;
        return true;
    case PropertyID::ShowTabCharacter:
        value = this->settings->showTabCharacter;
        return true;
    case PropertyID::WrapMethodKey:
        value = this->config.Keys.WordWrap;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    uint32 uint32Temp = 0;
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::WordWrap:
        SetWrapMethod(static_cast<WrapMethod>(std::get<uint64>(value)));
        return true;
    case PropertyID::HighlightCurrentLine:
        this->settings->highlightCurrentLine = std::get<bool>(value);
        return true;
    case PropertyID::TabSize:
        uint32Temp = std::get<uint32>(value);
        if (uint32Temp < 1)
        {
            error.Set("Tab size should not be smaller than 1 character !");
            return false;
        }
        if (uint32Temp > 32)
        {
            error.Set("Tab size should not be bigger than 32 characters");
            return false;
        }
        this->settings->tabSize = uint32Temp;
        this->UpdateViewPort();
        return true;
    case PropertyID::ShowTabCharacter:
        this->settings->showTabCharacter = std::get<bool>(value);
        return true;
    case PropertyID::WrapMethodKey:
        config.Keys.WordWrap = std::get<AppCUI::Input::Key>(value);
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
    case PropertyID::Encoding:
    case PropertyID::HasBOM:
        return true;
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { BT(PropertyID::WordWrap), "General", "Wrap method", PropertyType::List, "None=0,LeftMargin=1,Padding=2,Bullets=3" },
        { BT(PropertyID::HighlightCurrentLine), "General", "Highlight Current line", PropertyType::Boolean },
        { BT(PropertyID::TabSize), "Tabs", "Size", PropertyType::UInt32 },
        { BT(PropertyID::ShowTabCharacter), "Tabs", "Show tab character", PropertyType::Boolean },
        { BT(PropertyID::Encoding), "Encoding", "Format", PropertyType::List, "Binary=0,Ascii=1,UTF-8=2,UTF-16(LE)=3,UTF-16(BE)=4" },
        { BT(PropertyID::HasBOM), "Encoding", "HasBom", PropertyType::Boolean },
        // shortcuts
        { BT(PropertyID::WrapMethodKey), "Shortcuts", "Change wrap method", PropertyType::Key },
    };
}
#undef BT