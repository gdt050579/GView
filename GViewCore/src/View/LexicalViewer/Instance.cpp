#include "LexicalViewer.hpp"
#include <algorithm>

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_SHOW_METADATA = 0xBF00;
constexpr int32 CMD_ID_PRETTY_FORMAT = 0xBF01;
constexpr uint32 INVALID_LINE_NUMBER = 0xFFFFFFFF;

inline int32 ComputeXDist(int32 x1, int32 x2)
{
    return x1 > x2 ? x1 - x2 : x2 - x1;
}

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

    // load the entire data into a file
    auto buf                = obj->GetData().GetEntireFile();
    size_t sz               = 0;
    this->text              = GView::Utils::CharacterEncoding::ConvertToUnicode16(buf, sz);
    textLength              = (uint32) sz;
    this->Scroll.x          = 0;
    this->Scroll.y          = 0;
    this->currentTokenIndex = 0;
    this->lineNrWidth       = 0;
    this->lastLineNumber    = 0;
    this->noItemsVisible    = true;
    this->prettyFormat      = true;

    if (this->settings->parser)
    {
        TokensListBuilder tokensList(this);
        this->settings->parser->AnalyzeText(TextParser(this->text, this->textLength), tokensList);
        ComputeMultiLineTokens();
        RecomputeTokenPositions();
        MoveToClosestVisibleToken(0, false);
    }
}

void Instance::RecomputeTokenPositions()
{
    this->noItemsVisible = true;
    UpdateVisibilityStatus(0, (uint32) this->tokens.size(), true);
    if (this->prettyFormat)
        PrettyFormat();
    else
        ComputeOriginalPositions();
    EnsureCurrentItemIsVisible();
    this->lineNrWidth    = 0;
    this->lastLineNumber = 0;
    if (this->noItemsVisible == false)
    {
        // find the last visible
        auto idx = (uint32) (this->tokens.size() - 1);
        while ((idx > 0) && (this->tokens[idx].IsVisible() == false))
            idx--;
        // worst case, the fist item should be visible (if none is tham noItemsVisible can not be false)
        this->lastLineNumber = tokens[idx].y + tokens[idx].height;
        if (lastLineNumber < 100)
            this->lineNrWidth = 4;
        else if (lastLineNumber < 1000)
            this->lineNrWidth = 5;
        else if (lastLineNumber < 10000)
            this->lineNrWidth = 6;
        else if (lastLineNumber < 100000)
            this->lineNrWidth = 7;
        else
            this->lineNrWidth = 8;
    }
}
void Instance::ComputeMultiLineTokens()
{
    for (auto& tok : this->tokens)
    {
        const char16* p = this->text + tok.start;
        const char16* e = this->text + tok.end;
        auto nrLines    = 1U;
        while (p < e)
        {
            if (((*p) == '\n') || ((*p) == '\r'))
            {
                nrLines++;
                auto c = *p;
                p++;
                if ((p < e) && (((*p) == '\n') || ((*p) == '\r')) && ((*p) != c))
                    p++; // auto detect \n\r or \r\n
            }
            p++;
        }
        tok.height = nrLines;
    }
}
void Instance::MoveToClosestVisibleToken(uint32 startIndex, bool selected)
{
    if (startIndex >= this->tokens.size())
        return;
    if (this->tokens[startIndex].IsVisible())
        MoveToToken(startIndex, false);
    else
    {
        auto beforeIndex = Token::INVALID_INDEX;
        auto afterIndex  = Token::INVALID_INDEX;
        // find closest from top
        if (startIndex > 0)
        {
            auto idx = startIndex - 1;
            while ((idx > 0) && (!this->tokens[idx].IsVisible()))
                idx--;
            if (this->tokens[idx].IsVisible())
                beforeIndex = idx;
        }
        // find the coloset from the end
        if (startIndex + 1 < this->tokens.size())
        {
            auto idx = startIndex + 1;
            while ((idx < this->tokens.size()) && (!this->tokens[idx].IsVisible()))
                idx++;
            if (idx < this->tokens.size())
                afterIndex = idx;
        }
        // find the closest
        uint32 difBefore = beforeIndex == Token::INVALID_INDEX ? 0xFFFFFFFF : startIndex - beforeIndex;
        uint32 difAfter  = afterIndex == Token::INVALID_INDEX ? 0xFFFFFFFF : afterIndex - startIndex;
        if (difAfter < difBefore)
            MoveToToken(afterIndex, false);
        else if (difBefore < difAfter)
            MoveToToken(beforeIndex, false);
        else if (difBefore != 0xFFFFFFFF)
            MoveToToken(beforeIndex, false);
    }
}
void Instance::ComputeOriginalPositions()
{
    int32 x         = 0;
    int32 y         = 0;
    const char16* p = this->text;
    const char16* e = this->text + this->textLength;
    uint32 pos      = 0;
    uint32 idx      = 0;
    uint32 tknCount = (uint32) this->tokens.size();

    // skip to the first visible
    while ((idx < tknCount) && (!this->tokens[idx].IsVisible()))
        idx++;
    uint32 tknOffs = tknCount > 0 ? this->tokens[idx].start : 0xFFFFFFFF;
    while (p < e)
    {
        if ((*p) == '\t')
            x = ((x / 4) + 1) * 4;
        // asign position
        if (pos == tknOffs)
        {
            if (!this->tokens[idx].IsVisible())
            {
                this->tokens[idx].x = 0;
                this->tokens[idx].y = 0;
                p += (this->tokens[idx].end - this->tokens[idx].start);
                pos += (this->tokens[idx].end - this->tokens[idx].start);
                if (p >= e)
                    break;
            }
            else
            {
                this->tokens[idx].x = x;
                this->tokens[idx].y = y;
            }

            idx++;
            if (idx >= tknCount)
                break;
            tknOffs = this->tokens[idx].start;
        }
        if (((*p) == '\n') || ((*p) == '\r'))
        {
            x = 0;
            y++;
            if (((p + 1) < e) && ((p[1] == '\n') || (p[1] == '\r')) && (p[1] != (*p)))
            {
                p += 2;
                pos += 2;
            }
            else
            {
                p++;
                pos++;
            }
        }
        else
        {
            x++;
            p++;
            pos++;
        }
    }
}
void Instance::PrettyFormatForBlock(uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin)
{
    auto x   = leftMargin;
    auto y   = topMargin;
    auto idx = idxStart;
    // skip to the first visible
    for (; idx < idxEnd; idx++)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
            continue;
        if (((tok.align & TokenAlignament::NewLineBefore) != TokenAlignament::None) && (y > topMargin))
        {
            x = leftMargin;
            y++;
        }
        if (((tok.align & TokenAlignament::StartsOnNewLine) != TokenAlignament::None) && (x > leftMargin))
        {
            x = leftMargin;
            y++;
        }
        if (((tok.align & TokenAlignament::SpaceOnLeft) != TokenAlignament::None) && (x > leftMargin))
            x++;
        tok.x = x;
        tok.y = y;
        x += tok.width;
        y += tok.height - 1;
        if ((tok.align & TokenAlignament::SpaceOnRight) != TokenAlignament::None)
            x++;
        if ((tok.align & TokenAlignament::NewLineAfter) != TokenAlignament::None)
        {
            x = leftMargin;
            y++;
        }
    }
}
void Instance::PrettyFormat()
{
    PrettyFormatForBlock(0, (uint32) this->tokens.size(), 0, 0);
}
void Instance::UpdateVisibilityStatus(uint32 start, uint32 end, bool visible)
{
    auto pos = start;
    while (pos < end)
    {
        auto& tok       = this->tokens[pos];
        bool showStatus = visible;
        if ((tok.dataType == TokenDataType::MetaInformation) && (this->showMetaData == false))
            showStatus = false;

        tok.SetVisible(showStatus);
        this->noItemsVisible &= (!showStatus);

        // check block status
        if (tok.IsBlockStarter())
        {
            if (tok.IsFolded())
                showStatus = false;
            auto& block = this->blocks[tok.blockID];
            UpdateVisibilityStatus(block.tokenStart + 1, block.tokenEnd, showStatus);
            pos = block.tokenEnd;
        }
        else
        {
            pos++;
        }
    }
}

void Instance::EnsureCurrentItemIsVisible()
{
    if (this->noItemsVisible)
        return;

    const auto& tok    = this->tokens[this->currentTokenIndex];
    auto tk_right      = tok.x + (int32) tok.width - 1;
    auto tk_bottom     = tok.y + (int32) tok.height - 1;
    auto scroll_right  = Scroll.x + this->GetWidth() - 1;
    auto scroll_bottom = Scroll.y + this->GetHeight() - 1;

    // if already in current view -> return;
    if ((tok.x >= Scroll.x) && (tok.y >= Scroll.y) && (tk_right <= scroll_right) && (tk_bottom <= scroll_bottom))
        return;
    if (tk_right > scroll_right)
        Scroll.x += (tk_right - scroll_right);
    if (tk_bottom > scroll_bottom)
        Scroll.y += (tk_bottom - scroll_bottom);
    if (tok.x < Scroll.x)
        Scroll.x = tok.x;
    if (tok.y < Scroll.y)
        Scroll.y = tok.y;
}

void Instance::FillBlockSpace(Graphics::Renderer& renderer, const TokenObject& tok)
{
    const auto& block    = this->blocks[tok.blockID];
    const auto& tknEnd   = this->tokens[block.tokenEnd];
    const auto rightPos  = tknEnd.x + tknEnd.width - 1;
    const auto bottomPos = tknEnd.y + tknEnd.height - 1;
    const auto col       = Cfg.Editor.Focused;
    if (tok.IsFolded() == false)
    {
        if (bottomPos > tok.y)
        {
            // multi-line block
            bool fillEntireRect =
                  ((size_t) block.tokenEnd + (size_t) 1 < tokens.size()) ? (tokens[block.tokenEnd + 1].y != tknEnd.y) : true;
            if (this->prettyFormat)
            {
                // in pretty format mode --> all blocks are left-alligend
                if (fillEntireRect)
                {
                    renderer.FillRect(lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, this->GetWidth(), bottomPos - Scroll.y, ' ', col);
                }
                else
                {
                    // partial rect (the last line of the block contains some elements that are not part of the block
                    renderer.FillRect(
                          lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, this->GetWidth(), bottomPos - 1 - Scroll.y, ' ', col);
                    renderer.FillHorizontalLine(
                          lineNrWidth + tok.x - Scroll.x, bottomPos - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
                }
            }
            else
            {
                // blocks are not left alligend
                // first draw the first line
                renderer.FillHorizontalLine(lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, this->GetWidth(), ' ', col);
                // second draw the rest of the bloc
                if (fillEntireRect)
                {
                    renderer.FillRect(lineNrWidth, tok.y + 1 - Scroll.y, this->GetWidth(), bottomPos - Scroll.y, ' ', col);
                }
                else
                {
                    renderer.FillRect(lineNrWidth, tok.y + 1 - Scroll.y, this->GetWidth(), bottomPos - 1 - Scroll.y, ' ', col);
                    renderer.FillHorizontalLine(lineNrWidth, bottomPos - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
                }
            }
        }
        else
        {
            renderer.FillHorizontalLine(lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
        }
    }
}
void Instance::PaintLineNumbers(Graphics::Renderer& renderer)
{
    auto state           = this->HasFocus() ? ControlState::Focused : ControlState::Normal;
    auto lineSepColor    = Cfg.Lines.GetColor(state);
    auto lineMarkerColor = Cfg.LineMarker.GetColor(state);

    renderer.FillRect(0, 0, this->lineNrWidth - 2, this->GetHeight(), ' ', lineMarkerColor);
    renderer.DrawVerticalLine(this->lineNrWidth - 1, 0, this->GetHeight(), lineSepColor);
    NumericFormatter num;
    WriteTextParams params(WriteTextFlags::FitTextToWidth | WriteTextFlags::SingleLine);
    params.Width = lineNrWidth - 2;
    params.Color = lineMarkerColor;
    params.X     = params.Width;
    params.Align = TextAlignament::Right;
    auto height  = this->GetHeight();

    for (auto i = 0, value = Scroll.y + 1; (i < height) && (value<=this->lastLineNumber); i++,value++)
    {
        params.Y = i;
        renderer.WriteText(num.ToDec(value), params);
    }
}
void Instance::PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, bool onCursor)
{
    u16string_view txt = { this->text + tok.start, (size_t) (tok.end - tok.start) };
    ColorPair col;
    if (onCursor)
    {
        col = Cfg.Cursor.Normal;
    }
    else
    {
        switch (tok.color)
        {
        case TokenColor::Comment:
            col = Cfg.Text.Inactive;
            break;
        case TokenColor::Operator:
            col = Cfg.Text.Normal;
            break;
        case TokenColor::Word:
            col = Cfg.Text.Highlighted;
            break;
        case TokenColor::Keyword:
            col = Cfg.Text.Focused;
            break;
        case TokenColor::String:
            col = Cfg.Text.Emphasized1;
            break;
        default:
            col = Cfg.Text.Normal;
            break;
        }
    }
    if (tok.IsBlockStarter() && onCursor)
        FillBlockSpace(renderer, tok);
    if (tok.height > 1)
    {
        WriteTextParams params(WriteTextFlags::MultipleLines, TextAlignament::Left);
        params.X     = lineNrWidth + tok.x - Scroll.x;
        params.Y     = tok.y - Scroll.y;
        params.Color = col;
        renderer.WriteText(txt, params);
    }
    else
    {
        renderer.WriteSingleLineText(lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, txt, col);
    }
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    if (noItemsVisible)
        return;
    const int32 scroll_right  = Scroll.x + (int32) this->GetWidth() - 1;
    const int32 scroll_bottom = Scroll.y + (int32) this->GetHeight() - 1;
    uint32 idx                = 0;
    for (auto& t : this->tokens)
    {
        if (!t.IsVisible())
        {
            idx++;
            continue;
        }
        const auto onCursor  = idx == currentTokenIndex;
        const auto tk_right  = t.x + (int32) t.width - 1;
        const auto tk_bottom = t.y + (int32) t.height - 1;
        idx++;
        // if token not in visible screen => skip it
        if ((t.x > scroll_right) || (t.y > scroll_bottom) || (tk_right < Scroll.x) || (tk_bottom < Scroll.y))
            continue;
        PaintToken(renderer, t, onCursor);
    }
    PaintLineNumbers(renderer);
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    if (this->showMetaData)
        commandBar.SetCommand(config.Keys.showMetaData, "ShowMetaData:ON", CMD_ID_SHOW_METADATA);
    else
        commandBar.SetCommand(config.Keys.showMetaData, "ShowMetaData:OFF", CMD_ID_SHOW_METADATA);

    if (this->prettyFormat)
        commandBar.SetCommand(config.Keys.prettyFormat, "Format:Pretty", CMD_ID_PRETTY_FORMAT);
    else
        commandBar.SetCommand(config.Keys.prettyFormat, "Format:Original", CMD_ID_PRETTY_FORMAT);
    return false;
}
void Instance::MoveToToken(uint32 index, bool selected)
{
    if ((noItemsVisible) || (index == this->currentTokenIndex))
        return;
    index                   = std::min(index, (uint32) (this->tokens.size() - 1));
    this->currentTokenIndex = index;
    EnsureCurrentItemIsVisible();
}
void Instance::MoveLeft(bool selected, bool stopAfterFirst)
{
    if ((this->currentTokenIndex == 0) || (noItemsVisible))
        return;

    auto idx          = this->currentTokenIndex - 1;
    auto yPos         = this->tokens[currentTokenIndex].y;
    auto lastValidIdx = this->currentTokenIndex;
    while (idx > 0)
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx--;
            continue;
        }
        if (this->tokens[idx].y != yPos)
            break;
        lastValidIdx = idx;
        if (stopAfterFirst)
            break;
        else
            idx--;
    }
    if ((idx == 0) && (this->tokens[0].IsVisible()) && (this->tokens[0].y == yPos))
        lastValidIdx = 0;
    MoveToToken(lastValidIdx, selected);
}
void Instance::MoveRight(bool selected, bool stopAfterFirst)
{
    if (noItemsVisible)
        return;
    auto idx          = this->currentTokenIndex + 1;
    auto yPos         = this->tokens[currentTokenIndex].y;
    auto lastValidIdx = this->currentTokenIndex;
    auto count        = this->tokens.size();
    while (idx < count)
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (this->tokens[idx].y != yPos)
            break;
        lastValidIdx = idx;
        if (stopAfterFirst)
            break;
        else
            idx++;
    }
    MoveToToken(lastValidIdx, selected);
}
void Instance::MoveUp(uint32 times, bool selected)
{
    if ((noItemsVisible) || (times == 0))
        return;
    if (this->currentTokenIndex == 0)
        return;
    uint32 idx = this->currentTokenIndex - 1;
    auto lastY = this->tokens[this->currentTokenIndex].y;
    auto posX  = this->tokens[this->currentTokenIndex].x;
    while (times > 0)
    {
        while ((idx > 0) && (this->tokens[idx].y == lastY))
            idx--;

        while ((idx > 0) && ((!this->tokens[idx].IsVisible()) || (this->tokens[idx].y == lastY)))
            idx--;

        if (idx == 0)
        {
            if (this->tokens[0].IsVisible())
            {
                if (this->tokens[idx].y == lastY)
                {
                    // already on the first line --> move to first token
                    MoveToToken(0, selected);
                    return;
                }
                // otherwise do nothing --> just decrease the times count
            }
            else
            {
                // move to first visible item
                MoveToClosestVisibleToken(0, selected);
                return;
            }
        }
        lastY = this->tokens[idx].y;
        times--;
    }
    // found the line that I am interested in --> now search the closest token in terms of position
    auto found     = idx;
    auto best_dist = ComputeXDist(this->tokens[found].x, posX);
    while ((idx > 0) && (best_dist > 0))
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx--;
            continue;
        }
        if (this->tokens[idx].y != lastY)
            break;
        auto dist = ComputeXDist(this->tokens[idx].x, posX);
        if (dist < best_dist)
        {
            found     = idx;
            best_dist = dist;
        }
        idx--;
    }
    if ((idx == 0) && (this->tokens[idx].IsVisible()))
    {
        // it is possible that the first token is the closest --> so test this
        auto dist = ComputeXDist(this->tokens[idx].x, posX);
        if (dist < best_dist)
        {
            found     = idx;
            best_dist = dist;
        }
    }
    MoveToToken(found, selected);
}
void Instance::MoveDown(uint32 times, bool selected)
{
    if ((noItemsVisible) || (times == 0))
        return;
    uint32 cnt = (uint32) this->tokens.size();
    uint32 idx = this->currentTokenIndex + 1;
    auto lastY = this->tokens[this->currentTokenIndex].y;
    auto posX  = this->tokens[this->currentTokenIndex].x;
    if (idx >= cnt)
        return;
    while (times > 0)
    {
        while ((idx < cnt) && ((!this->tokens[idx].IsVisible()) || (this->tokens[idx].y == lastY)))
            idx++;
        if (idx >= cnt)
        {
            // already on the last line --> move to last token
            MoveToClosestVisibleToken(cnt - 1, selected);
            return;
        }
        lastY = this->tokens[idx].y;
        times--;
    }
    // found the line that I am interested in --> now search the closest token in terms of position
    auto found     = idx;
    auto best_dist = ComputeXDist(this->tokens[found].x, posX);
    while ((idx < cnt) && (best_dist > 0))
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (this->tokens[idx].y != lastY)
            break;
        auto dist = ComputeXDist(this->tokens[idx].x, posX);
        if (dist < best_dist)
        {
            found     = idx;
            best_dist = dist;
        }
        idx++;
    }
    MoveToToken(found, selected);
}
void Instance::SetFoldStatus(uint32 index, FoldStatus foldStatus, bool recursive)
{
    if (this->noItemsVisible)
        return;
    if ((size_t) this->currentTokenIndex >= this->tokens.size())
        return;
    auto& tok = this->tokens[this->currentTokenIndex];
    if (!tok.IsBlockStarter())
        return;
    bool foldValue = foldStatus == FoldStatus::Folded ? true : (foldStatus == FoldStatus::Expanded ? false : (!tok.IsFolded()));
    tok.SetFolded(foldValue);
    RecomputeTokenPositions();
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    switch (keyCode)
    {
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
    case Key::Left:
        MoveLeft(false, true);
        return true;
    case Key::Left | Key::Shift:
        MoveLeft(true, true);
        return true;
    case Key::Right:
        MoveRight(false, true);
        return true;
    case Key::Right | Key::Shift:
        MoveRight(true, true);
        return true;
    case Key::Home:
        MoveLeft(false, false);
        return true;
    case Key::Home | Key::Shift:
        MoveLeft(true, false);
        return true;
    case Key::End:
        MoveRight(false, false);
        return true;
    case Key::End | Key::Shift:
        MoveRight(true, false);
        return true;

    // view-port scroll
    case Key::Left | Key::Ctrl:
        if (Scroll.x > 0)
            Scroll.x--;
        return true;
    case Key::Right | Key::Ctrl:
        Scroll.x++;
        return true;
    case Key::Up | Key::Ctrl:
        if (Scroll.y > 0)
            Scroll.y--;
        return true;
    case Key::Down | Key::Ctrl:
        Scroll.y++;
        return true;

    // fold -> unfold
    case Key::Space:
        SetFoldStatus(this->currentTokenIndex, FoldStatus::Reverse, false);
        return true;
    }

    return false;
}
void Instance::OnStart()
{
}
void Instance::OnAfterResize(int newWidth, int newHeight)
{
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType != Event::Command)
        return false;
    switch (ID)
    {
    case CMD_ID_SHOW_METADATA:
        this->showMetaData = !this->showMetaData;
        this->RecomputeTokenPositions();
        return true;
    case CMD_ID_PRETTY_FORMAT:
        this->prettyFormat = !this->prettyFormat;
        this->RecomputeTokenPositions();
        return true;
    }
    return false;
}
void Instance::OnUpdateScrollBars()
{
}
bool Instance::GoTo(uint64 offset)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::Select(uint64 offset, uint64 size)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowGoToDialog()
{
    NOT_IMPLEMENTED(false);
    // GoToDialog dlg(this->Cursor.pos, this->obj->GetData().GetSize(), this->Cursor.lineNo + 1U, static_cast<uint32>(this->lines.size()));
    // if (dlg.Show() == (int) Dialogs::Result::Ok)
    //{

    //}
    // return true;
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
std::string_view Instance::GetName()
{
    return this->name;
}
//======================================================================[Mouse coords]==================
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{
}
void Instance::OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button)
{
}
bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button)
{
    NOT_IMPLEMENTED(false);
}
bool Instance::OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction)
{
    switch (direction)
    {
    case MouseWheel::Up:
        return OnKeyEvent(Key::Up | Key::Ctrl, false);
    case MouseWheel::Down:
        return OnKeyEvent(Key::Down | Key::Ctrl, false);
    }

    return false;
}
//======================================================================[Cursor information]==================
// int Instance::PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r)
//{
//    //uint64 start, end;
//    //bool show = (selectionID == 0) || (this->selection.IsMultiSelectionEnabled());
//    //if (show)
//    //{
//    //    if (this->selection.GetSelection(selectionID, start, end))
//    //    {
//    //        LocalString<32> tmp;
//    //        tmp.Format("%X,%X", start, (end - start) + 1);
//    //        r.WriteSingleLineText(x, y, width, tmp.GetText(), this->Cfg.Text.Normal);
//    //    }
//    //    else
//    //    {
//    //        r.WriteSingleLineText(x, y, width, "NO Selection", Cfg.Text.Inactive, TextAlignament::Center);
//    //    }
//    //}
//    //r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->Cfg.Lines.Normal);
//    return x + width + 1;
//}
void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    // LocalString<128> tmp;
    // auto xPoz = 0;
    // if (height == 1)
    //{
    //     xPoz = PrintSelectionInfo(0, 0, 0, 16, r);
    //     if (this->selection.IsMultiSelectionEnabled())
    //     {
    //         xPoz = PrintSelectionInfo(1, xPoz, 0, 16, r);
    //         xPoz = PrintSelectionInfo(2, xPoz, 0, 16, r);
    //         xPoz = PrintSelectionInfo(3, xPoz, 0, 16, r);
    //     }
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 10, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    // }
    // else
    //{
    //     PrintSelectionInfo(0, 0, 0, 16, r);
    //     xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
    //     PrintSelectionInfo(1, xPoz, 0, 16, r);
    //     xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
    //     this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 1, 20, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    // }
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
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
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        //{ BT(PropertyID::WordWrap), "General", "Wrap method", PropertyType::List, "None=0,LeftMargin=1,Padding=2,Bullets=3" },
        //{ BT(PropertyID::HighlightCurrentLine), "General", "Highlight Current line", PropertyType::Boolean },
        //{ BT(PropertyID::TabSize), "Tabs", "Size", PropertyType::UInt32 },
        //{ BT(PropertyID::ShowTabCharacter), "Tabs", "Show tab character", PropertyType::Boolean },
        //{ BT(PropertyID::Encoding), "Encoding", "Format", PropertyType::List, "Binary=0,Ascii=1,UTF-8=2,UTF-16(LE)=3,UTF-16(BE)=4" },
        //{ BT(PropertyID::HasBOM), "Encoding", "HasBom", PropertyType::Boolean },
        //// shortcuts
        //{ BT(PropertyID::WrapMethodKey), "Shortcuts", "Change wrap method", PropertyType::Key },
    };
}
#undef BT