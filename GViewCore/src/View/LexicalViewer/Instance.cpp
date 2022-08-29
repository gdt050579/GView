#include "LexicalViewer.hpp"
#include <algorithm>

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_SHOW_METADATA    = 0xBF00;
constexpr int32 CMD_ID_PRETTY_FORMAT    = 0xBF01;
constexpr int32 CMD_ID_DELETE           = 0xBF02;
constexpr int32 CMD_ID_CHANGE_SELECTION = 0xBF03;
constexpr int32 CMD_ID_FOLD_ALL         = 0xBF04;
constexpr int32 CMD_ID_EXPAND_ALL       = 0xBF05;
constexpr int32 CMD_ID_SHOW_PLUGINS     = 0xBF06;
constexpr uint32 INVALID_LINE_NUMBER    = 0xFFFFFFFF;

/*
void TestTextEditor()
{
    TextEditorBuilder ted(nullptr, 0);
    ted.Set(u"123456789");
    ted.Add("x");
    ted.InsertChar(0, '-');
    ted.InsertChar(4, '-');
    ted.Insert(0, u"XXX");
    ted.Insert(8, "xxxxx");
    ted.Insert(ted.Len(), "<END>");
    ted.DeleteChar(5);
    ted.Delete(3, 2);
    ted.Delete(5, 100000);
    ted.Add(u"ABCDEFG");
    ted.Add("123");
    ted.Set("0123456789                                                                                  ");
    ted.Replace(3, 2, "xx");
    ted.Set("0123456789");
    ted.Replace(3, 2, "x");
    ted.Set("0123456789");
    ted.Replace(3, 2, u"xxxxxx");
    ted.Set("                                     ");
    ted.Set("0123456789");
    ted.Replace(8, 100, u"ABC");
    ted.Set("                                     ");
    ted.Set("0123456789");
    ted.Replace(12, 100, u"ABC");
    ted.Set("                                     ");
    ted.Set("0123456789");
    ted.Replace(9, 1, u"ABC");

    ted.Set("                                     ");
    ted.Set("0123456789");
    ted.ReplaceAll("89", "abc");
}
//*/

inline int32 ComputeXDist(int32 x1, int32 x2)
{
    return x1 > x2 ? x1 - x2 : x2 - x1;
}
inline std::string_view TokenDataTypeToString(TokenDataType dataType)
{
    switch (dataType)
    {
    case TokenDataType::Boolean:
        return "Boolean";
    case TokenDataType::String:
        return "String";
    case TokenDataType::MetaInformation:
        return "Meta information";
    case TokenDataType::Number:
        return "Numeric value";
    case TokenDataType::None:
        return "N/A";
    default:
        return "???";
    }
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
    auto buf           = obj->GetData().GetEntireFile();
    this->text         = GView::Utils::CharacterEncoding::ConvertToUnicode16(buf);
    this->prettyFormat = true;

    this->Parse();

    // TestTextEditor();
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
void Instance::UpdateTokensInformation()
{
    /*
    Computes:
    - height
    - hashing
    */
    for (auto& tok : this->tokens)
    {
        tok.UpdateSizes(this->text.text);
        tok.UpdateHash(this->text.text, this->settings->ignoreCase);
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
    const char16* p = this->text.text;
    const char16* e = this->text.text + this->text.size;
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
void Instance::PrettyFormatIncreaseUntilNewLineXWithValue(uint32 idxStart, uint32 idxEnd, int32 currentLineYOffset, int32 diff)
{
    auto idx                 = idxStart;
    bool foundSameColumnFlag = false;
    for (; idx < idxEnd; idx++)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
            continue;
        if (tok.y != currentLineYOffset)
            break;
        tok.x += diff;
        if ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None)
            foundSameColumnFlag = true;
    }
    if ((idx >= idxEnd) || (foundSameColumnFlag == false))
        return;
    // we did found another token aligned to the same column, we need to align the rest of the block

    auto diffToAdd = 0;
    for (; idx < idxEnd; idx++)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
            continue;
        if (tok.y != currentLineYOffset)
        {
            currentLineYOffset = tok.y;
            diffToAdd          = 0;
        }
        if ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None)
            diffToAdd = diff;
        tok.x += diffToAdd;
    }
}
void Instance::PrettyFormatIncreaseAllXWithValue(uint32 idxStart, uint32 idxEnd, int32 dif)
{
    for (auto idx = idxStart; idx < idxEnd; idx++)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
            continue;
        tok.x += dif;
    }
}
void Instance::PrettyFormatAlignToSameColumn(uint32 idxStart, uint32 idxEnd, int32 columnXOffset)
{
    auto idx                     = idxStart;
    auto dif                     = 0;
    auto lastLine                = -1;
    auto firstWithSameColumnFlag = true;

    while (idx < idxEnd)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (lastLine != tok.y)
        {
            lastLine                = tok.y;
            dif                     = 0;
            firstWithSameColumnFlag = true;
        }
        if ((firstWithSameColumnFlag) && ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None))
        {
            dif                     = columnXOffset - tok.x;
            firstWithSameColumnFlag = false;
        }
        tok.x += dif;
        if (tok.IsBlockStarter())
        {
            const auto& block = this->blocks[tok.blockID];
            auto endToken     = block.HasEndMarker() ? block.tokenEnd : block.tokenEnd + 1;
            if (tok.IsFolded())
            {
                // nothing to do
                idx = endToken;
                continue;
            }
            // if not folded a different logic
            if (dif == 0)
            {
                idx = endToken;
                continue;
            }
            switch (block.align)
            {
            case BlockAlignament::AsCurrentBlock:
            case BlockAlignament::ToRightOfCurrentBlock:
                // align until current line ends --> if a sameColumn flag is found , align the rest of the block as well
                PrettyFormatIncreaseUntilNewLineXWithValue(idx + 1, endToken, tok.y, dif);
                break;
            case BlockAlignament::AsBlockStartToken:
                // all visible tokens must be increaset with diff
                PrettyFormatIncreaseAllXWithValue(idx + 1, endToken, dif);
                break;
            default:
                // do nothing --> leave the block as it is
                break;
            }
            idx = endToken;
        }
        else
        {
            idx++;
        }
    }
}
AppCUI::Graphics::Point Instance::PrettyFormatForBlock(uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin)
{
    auto x                       = leftMargin;
    auto y                       = topMargin;
    auto lastY                   = topMargin;
    auto idx                     = idxStart;
    auto spaceAdded              = true;
    auto partOfFoldedBlock       = false;
    auto indent                  = 0U;
    auto firstOnNewLine          = true;
    auto sameColumnCount         = 0;
    auto maxXOffsetForSameColumn = 0;
    auto sameColumnDifferences   = false;
    auto lastSameColumnLine      = 0;

    while (idx < idxEnd)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (!partOfFoldedBlock)
        {
            // indent flags (before)
            if ((tok.align & TokenAlignament::IncrementIndentBeforePaint) != TokenAlignament::None)
                indent++;
            if (((tok.align & TokenAlignament::DecrementIndentBeforePaint) != TokenAlignament::None) && (indent > 0))
                indent--;
            if ((tok.align & TokenAlignament::ClearIndentBeforePaint) != TokenAlignament::None)
                indent = 0;

            // new line flags
            if (((tok.align & TokenAlignament::NewLineBefore) != TokenAlignament::None) && (y > topMargin))
            {
                x              = leftMargin + indent * settings->indentWidth;
                spaceAdded     = true;
                firstOnNewLine = true;
                if (y == lastY)
                    y += 2;
                else
                    y++;
            }
            if (((tok.align & TokenAlignament::StartsOnNewLine) != TokenAlignament::None) && (!firstOnNewLine))
            {
                x              = leftMargin + indent * settings->indentWidth;
                spaceAdded     = true;
                firstOnNewLine = true;
                y++;
            }
            if ((tok.align & TokenAlignament::AfterPreviousToken) != TokenAlignament::None)
            {
                if (y == lastY)
                {
                    if ((spaceAdded) && (x > leftMargin))
                        x--;
                }
                else
                {
                    if (idx > idxStart)
                    {
                        auto& previous = tokens[idx - 1];
                        y              = previous.y + previous.height - 1;
                        x              = previous.x + previous.width;
                    }
                }
                spaceAdded = false;
            }
            if (((tok.align & TokenAlignament::AddSpaceBefore) != TokenAlignament::None) && (!spaceAdded))
                x++;
        }

        // assign position to curent token
        tok.x                   = x;
        tok.y                   = y;
        lastY                   = y;
        firstOnNewLine          = false;
        const auto blockStarter = tok.IsBlockStarter();
        const auto folded       = tok.IsFolded();
        if ((blockStarter) && (folded))
        {
            const auto& block = this->blocks[tok.blockID];
            if (block.foldMessage.empty())
                x += tok.width + 3; // for ...
            else
                x += tok.width + (int32) block.foldMessage.size();
            partOfFoldedBlock = block.HasEndMarker(); // only limit the alignament for end marker
        }
        else
        {
            x += tok.width;
            y += tok.height - 1;
            partOfFoldedBlock = false;
        }
        spaceAdded = false;
        if (!partOfFoldedBlock)
        {
            // Same column logic
            if ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None)
            {
                sameColumnCount++;
                if (sameColumnCount == 1)
                {
                    // first one
                    maxXOffsetForSameColumn = tok.x;
                    lastSameColumnLine      = tok.y;
                }
                else
                {
                    if ((tok.x > maxXOffsetForSameColumn) && (tok.y != lastSameColumnLine))
                    {
                        maxXOffsetForSameColumn = tok.x;
                        sameColumnDifferences   = true;
                    }
                    lastSameColumnLine = tok.y;
                }
            }
            // indent
            if ((tok.align & TokenAlignament::IncrementIndentAfterPaint) != TokenAlignament::None)
                indent++;
            if (((tok.align & TokenAlignament::DecrementIndentAfterPaint) != TokenAlignament::None) && (indent > 0))
                indent--;
            if ((tok.align & TokenAlignament::ClearIndentAfterPaint) != TokenAlignament::None)
                indent = 0;

            if ((tok.align & TokenAlignament::AddSpaceAfter) != TokenAlignament::None)
            {
                x++;
                spaceAdded = true;
            }
            if ((tok.align & TokenAlignament::NewLineAfter) != TokenAlignament::None)
            {
                x              = leftMargin + indent * settings->indentWidth;
                spaceAdded     = true;
                firstOnNewLine = true;
                y++;
            }
        }
        if (tok.IsBlockStarter())
        {
            auto& block           = this->blocks[tok.blockID];
            auto endToken         = block.HasEndMarker() ? block.tokenEnd : block.tokenEnd + 1;
            int32 blockMarginTop  = 0;
            int32 blockMarginLeft = 0;
            switch (block.align)
            {
            case BlockAlignament::AsCurrentBlock:
                blockMarginTop            = y;
                blockMarginLeft           = leftMargin;
                block.leftHighlightMargin = leftMargin;
                break;
            case BlockAlignament::ToRightOfCurrentBlock:
                blockMarginTop            = y;
                blockMarginLeft           = leftMargin + (indent + 1) * settings->indentWidth;
                block.leftHighlightMargin = leftMargin + indent * settings->indentWidth;
                break;
            case BlockAlignament::AsBlockStartToken:
                blockMarginTop            = y;
                blockMarginLeft           = x;
                block.leftHighlightMargin = x;
                break;
            default:
                blockMarginTop            = y;
                blockMarginLeft           = x;
                block.leftHighlightMargin = 0;
                break;
            }
            if (((idx + 1) < endToken) && (tok.IsFolded() == false))
            {
                // not an empty block and not folded
                auto p = PrettyFormatForBlock(idx + 1, endToken, blockMarginLeft, blockMarginTop);
                x      = p.X == blockMarginLeft ? leftMargin + indent * settings->indentWidth : p.X;
                y      = p.Y;
            }
            idx = endToken;
        }
        else
        {
            idx++; // next token
        }
    }
    // recompute same column only if differences were found
    if (sameColumnDifferences)
    {
        PrettyFormatAlignToSameColumn(idxStart, idxEnd, maxXOffsetForSameColumn);
    }
    return { x, y };
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
        if (tok.IsMarkForDeletion())
            showStatus = false;

        tok.SetVisible(showStatus);
        this->noItemsVisible &= (!showStatus);

        // check block status
        if (tok.IsBlockStarter())
        {
            if (tok.IsFolded())
                showStatus = false;
            const auto& block = this->blocks[tok.blockID];
            auto endToken     = block.HasEndMarker() ? block.tokenEnd : block.tokenEnd + 1;
            UpdateVisibilityStatus(block.tokenStart + 1, endToken, showStatus);
            pos = endToken;
        }
        else
        {
            pos++;
        }
    }
}
uint32 Instance::TokenToBlock(uint32 tokenIndex)
{
    if ((size_t) tokenIndex >= tokens.size())
        return BlockObject::INVALID_ID;
    const auto blocksCount = static_cast<uint32>(blocks.size());
    auto pos               = tokenIndex;
    while (pos > 0)
    {
        const auto& tok = this->tokens[pos];
        if ((tok.IsBlockStarter()) && (tok.blockID < blocksCount))
        {
            const auto& block = this->blocks[tok.blockID];
            if (tokenIndex < block.GetEndIndex())
                return tok.blockID;
        }
        pos--;
    }
    const auto& tok = this->tokens[0];
    if ((tok.IsBlockStarter()) && (tok.blockID < blocksCount))
    {
        const auto& block = this->blocks[tok.blockID];
        if (tokenIndex < block.GetEndIndex())
            return tok.blockID;
    }
    // finally --> check the first position
    return BlockObject::INVALID_ID;
}
uint32 Instance::CountSimilarTokens(uint32 start, uint32 end, uint64 hash)
{
    if ((size_t) end > this->tokens.size())
        return 0;
    uint32 count = 0;
    for (; start < end; start++)
    {
        if (tokens[start].hash == hash)
            count++;
    }
    return count;
}

void Instance::EnsureCurrentItemIsVisible()
{
    if (this->noItemsVisible)
        return;

    const auto& tok    = this->tokens[this->currentTokenIndex];
    auto tk_right      = tok.x + (int32) tok.width - 1;
    auto tk_bottom     = tok.y + (int32) tok.height - 1;
    auto scroll_right  = Scroll.x + this->GetWidth() - 1 - this->lineNrWidth;
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
void Instance::Parse()
{
    this->Scroll.x          = 0;
    this->Scroll.y          = 0;
    this->currentTokenIndex = 0;
    this->lineNrWidth       = 0;
    this->lastLineNumber    = 0;
    this->currentHash       = 0;
    this->noItemsVisible    = true;

    this->tokens.clear();
    this->blocks.clear();
    this->selection.Clear();

    if (this->settings->parser)
    {
        // step 1 (run the preprocessor)
        TextEditorBuilder ted(this->text);
        this->settings->parser->PreprocessText(ted);
        this->text = ted.Release();

        // step 2 (run the analyzer)
        TokensListBuilder tokensList(this);
        BlocksListBuilder blockList(this);
        TextParser textParser(this->text.text, this->text.size);
        SyntaxManager syntax(textParser, tokensList, blockList);
        this->settings->parser->AnalyzeText(syntax);
        UpdateTokensInformation();
        RecomputeTokenPositions();
        MoveToClosestVisibleToken(0, false);
    }
}
void Instance::Reparse(bool openInNewWindow)
{
    if (openInNewWindow)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Open in a new window is not implemented yet !");
    }
    else
    {
        TextEditorBuilder ted(this->text);
        auto res   = RebuildTextFromTokens(ted);
        this->text = ted.Release();
        if (!res)
        {
            this->noItemsVisible = true; // hide all text
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Fail to reparse current text !");
        }
        this->Parse();
    }
}
bool Instance::RebuildTextFromTokens(TextEditor& editor)
{
    auto it  = this->tokens.crbegin();
    auto end = this->tokens.crend();
    for (; it != end; it++)
    {
        if (it->IsMarkForDeletion())
        {
            editor.Delete(it->start, it->end - it->start);
            continue;
        }
        if (it->value.Len() > 0)
        {
            if (!editor.Replace(it->start, it->end - it->start, it->value.ToStringView()))
                return false;
            continue;
        }
    }
    return true;
}

void Instance::FillBlockSpace(Graphics::Renderer& renderer, const BlockObject& block)
{
    const auto& tok      = this->tokens[block.tokenStart];
    const auto& tknEnd   = this->tokens[block.tokenEnd];
    const auto rightPos  = tknEnd.x + tknEnd.width - 1;
    const auto bottomPos = tknEnd.y + tknEnd.height - 1;
    const auto col       = Cfg.Editor.Focused;
    if (tok.IsFolded() == false)
    {
        if (bottomPos > tok.y)
        {
            // multi-line block
            bool fillLastLine = ((size_t) block.tokenEnd + (size_t) 1 < tokens.size()) ? (tokens[block.tokenEnd + 1].y != tknEnd.y) : true;
            auto leftPos      = this->prettyFormat ? lineNrWidth + block.leftHighlightMargin - Scroll.x : 0;
            // first draw the first line
            renderer.FillHorizontalLine(lineNrWidth + tok.x - Scroll.x, tok.y - Scroll.y, this->GetWidth(), ' ', col);
            // draw the middle part
            if (fillLastLine)
            {
                renderer.FillRect(leftPos, tok.y + 1 - Scroll.y, this->GetWidth(), bottomPos - Scroll.y, ' ', col);
            }
            else
            {
                // partial rect (the last line of the block contains some elements that are not part of the block
                renderer.FillRect(leftPos, tok.y + 1 - Scroll.y, this->GetWidth(), bottomPos - 1 - Scroll.y, ' ', col);
                renderer.FillHorizontalLine(leftPos, bottomPos - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
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
    auto lineMarkerColor = Cfg.LineMarker.GetColor(state);

    renderer.FillRect(0, 0, this->lineNrWidth - 2, this->GetHeight(), ' ', lineMarkerColor);
    NumericFormatter num;
    WriteTextParams params(WriteTextFlags::FitTextToWidth | WriteTextFlags::SingleLine);
    params.Width = lineNrWidth - 2;
    params.Color = lineMarkerColor;
    params.X     = params.Width;
    params.Align = TextAlignament::Right;
    auto height  = this->GetHeight();

    for (auto i = 0, value = Scroll.y + 1; (i < height) && (value <= this->lastLineNumber); i++, value++)
    {
        params.Y = i;
        renderer.WriteText(num.ToDec(value), params);
    }
}
void Instance::PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, uint32 index)
{
    u16string_view txt = tok.GetText(this->text.text);
    ColorPair col;
    bool onCursor    = index == this->currentTokenIndex;
    bool onSelection = this->selection.Contains(index);
    if (onCursor)
    {
        col = Cfg.Cursor.Normal;
        if (onSelection)
            col = Cfg.Cursor.OverSelection;
    }
    else
    {
        switch (tok.color)
        {
        case TokenColor::Comment:
            col = ColorPair{ Color::DarkGreen, Color::Transparent };
            break;
        case TokenColor::Operator:
            col = ColorPair{ Color::Gray, Color::Transparent };
            break;
        case TokenColor::Word:
            col = ColorPair{ Color::Silver, Color::Transparent };
            break;
        case TokenColor::Keyword:
            col = ColorPair{ Color::Yellow, Color::Transparent };
            break;
        case TokenColor::Keyword2:
            col = ColorPair{ Color::Aqua, Color::Transparent };
            break;
        case TokenColor::String:
            col = ColorPair{ Color::Red, Color::Transparent };
            break;
        case TokenColor::Datatype:
            col = ColorPair{ Color::Green, Color::Transparent };
            break;
        case TokenColor::Constant:
            col = ColorPair{ Color::Pink, Color::Transparent };
            break;
        case TokenColor::Number:
            col = ColorPair{ Color::Teal, Color::Transparent };
            break;
        case TokenColor::Preprocesor:
            col = ColorPair{ Color::Olive, Color::Transparent };
            break;
        default:
            col = Cfg.Text.Normal;
            break;
        }
        if ((this->currentHash != 0) && (tok.hash == this->currentHash))
            col = Cfg.Selection.SimilarText;
        if (onSelection)
            col = Cfg.Selection.Editor;
    }
    const auto blockStarter = tok.IsBlockStarter();
    if ((onCursor) && (tok.HasBlock()))
        FillBlockSpace(renderer, this->blocks[tok.blockID]);
    if ((blockStarter) && (this->blocks[tok.blockID].CanOnlyBeFoldedManually() == false))
    {
        foldColumn.SetBlock(tok.y - Scroll.y, tok.blockID);
    }
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
    if (blockStarter && tok.IsFolded())
    {
        auto x            = lineNrWidth + tok.x + tok.width - Scroll.x;
        auto y            = tok.y + tok.height - 1 - Scroll.y;
        const auto& block = this->blocks[tok.blockID];
        if (block.foldMessage.empty())
            renderer.WriteSingleLineText(x, y, "...", ColorPair{ Color::Gray, Color::Black });
        else
            renderer.WriteSingleLineText(x, y, block.foldMessage, ColorPair{ Color::Gray, Color::Black });
    }
    // check for selection precedence
    if ((index > 0) && (onSelection) && (selection.Contains(index - 1)))
    {
        const auto& precTok = this->tokens[index - 1];
        if ((tok.y == precTok.y) && (tok.height == 1))
        {
            // fill in the space between them
            renderer.FillHorizontalLine(
                  lineNrWidth + precTok.x + precTok.width - Scroll.x,
                  precTok.y - Scroll.y,
                  lineNrWidth + tok.x - 1 - Scroll.x,
                  -1,
                  Cfg.Selection.Editor);
        }
    }
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    if (noItemsVisible)
        return;
    foldColumn.Clear(this->GetHeight());
    // paint token on cursor first (and show block highlight if needed)
    if (this->currentTokenIndex < this->tokens.size())
    {
        auto& currentTok = this->tokens[this->currentTokenIndex];
        if (currentTok.IsVisible())
        {
            this->currentHash = currentTok.hash;
            PaintToken(renderer, currentTok, this->currentTokenIndex);
        }
    }
    else
    {
        this->currentHash = 0;
    }

    const int32 scroll_right  = Scroll.x + (int32) this->GetWidth() - 1;
    const int32 scroll_bottom = Scroll.y + (int32) this->GetHeight() - 1;
    uint32 idx                = 0;
    for (auto& t : this->tokens)
    {
        // skip hidden and current token
        if ((!t.IsVisible()) || (idx == this->currentTokenIndex))
        {
            idx++;
            continue;
        }
        const auto tk_right  = t.x + (int32) t.width - 1;
        const auto tk_bottom = t.y + (int32) t.height - 1;

        // if token not in visible screen => skip it
        if ((t.x > scroll_right) || (t.y > scroll_bottom) || (tk_right < Scroll.x) || (tk_bottom < Scroll.y))
        {
            idx++;
            continue;
        }
        PaintToken(renderer, t, idx);
        idx++;
    }
    PaintLineNumbers(renderer);
    foldColumn.Paint(renderer, this->lineNrWidth - 1, this);
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

    if (this->noItemsVisible == false)
        commandBar.SetCommand(Key::Delete, "Delete", CMD_ID_DELETE);

    if (this->selection.IsSingleSelectionEnabled())
        commandBar.SetCommand(config.Keys.changeSelectionType, "Select:Single", CMD_ID_CHANGE_SELECTION);
    else
        commandBar.SetCommand(config.Keys.changeSelectionType, "Select:Multiple", CMD_ID_CHANGE_SELECTION);

    commandBar.SetCommand(config.Keys.foldAll, "Fold all", CMD_ID_FOLD_ALL);
    commandBar.SetCommand(config.Keys.expandAll, "Expand all", CMD_ID_EXPAND_ALL);
    commandBar.SetCommand(config.Keys.showPlugins, "Plugins", CMD_ID_SHOW_PLUGINS);

    return false;
}
void Instance::MoveToToken(uint32 index, bool selected)
{
    if ((noItemsVisible) || (index == this->currentTokenIndex))
        return;
    auto sidx = -1;
    if (selected)
        sidx = this->selection.BeginSelection(this->currentTokenIndex);
    index                   = std::min(index, (uint32) (this->tokens.size() - 1));
    this->currentTokenIndex = index;
    EnsureCurrentItemIsVisible();
    if ((selected) && (sidx >= 0))
    {
        this->selection.UpdateSelection(sidx, this->currentTokenIndex);
    }
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
    if ((size_t) index >= this->tokens.size())
        return;
    auto& tok = this->tokens[index];
    if (tok.IsBlockStarter())
    {
        bool foldValue = foldStatus == FoldStatus::Folded ? true : (foldStatus == FoldStatus::Expanded ? false : (!tok.IsFolded()));
        tok.SetFolded(foldValue);
        if (recursive)
        {
            const auto& block = this->blocks[tok.blockID];
            for (auto idx = block.tokenStart; idx < block.tokenEnd; idx++)
            {
                auto& currentTok = this->tokens[idx];
                if (currentTok.IsBlockStarter())
                {
                    const auto& currentBlock = this->blocks[currentTok.blockID];
                    // skip block that can only be folded manually
                    if ((foldValue) && (currentBlock.CanOnlyBeFoldedManually()))
                        continue;
                    currentTok.SetFolded(foldValue);
                }
            }
        }
        RecomputeTokenPositions();
    }
    else
    {
        // if current token is not the block starter, but reference a block, fold that block
        if (tok.HasBlock())
            SetFoldStatus(this->blocks[tok.blockID].tokenStart, foldStatus, recursive);
        else
        {
            auto blockIDX = TokenToBlock(index);
            if (blockIDX != BlockObject::INVALID_ID)
            {
                const auto& block = this->blocks[blockIDX];
                // collapse the entire block
                MoveToToken(block.tokenStart, false);
                MoveToClosestVisibleToken(block.tokenStart, false);
                SetFoldStatus(block.tokenStart, FoldStatus::Folded, recursive);
            }
        }
    }
}
void Instance::ExpandAll()
{
    for (const auto& block : this->blocks)
    {
        this->tokens[block.tokenStart].SetFolded(false);
    }
    RecomputeTokenPositions();
}
void Instance::FoldAll()
{
    for (const auto& block : this->blocks)
    {
        if (block.CanOnlyBeFoldedManually() == false)
            this->tokens[block.tokenStart].SetFolded(true);
    }
    RecomputeTokenPositions();
    MoveToClosestVisibleToken(this->currentTokenIndex, false);
}
void Instance::EditCurrentToken()
{
    // sanity checks
    if (this->noItemsVisible)
        return;
    if ((size_t) this->currentTokenIndex >= this->tokens.size())
        return;
    auto& tok = this->tokens[this->currentTokenIndex];
    if (!tok.IsVisible())
        return;
    if (tok.CanChangeValue() == false)
    {
        AppCUI::Dialogs::MessageBox::ShowNotification("Rename", "This type of token can not be modified/renamed !");
        return;
    }

    // all good -> edit the token
    auto containerBlock = TokenToBlock(this->currentTokenIndex);
    NameRefactorDialog dlg(tok, this->text.text, selection.HasSelection(0), containerBlock != BlockObject::INVALID_ID);
    if (dlg.Show() == (int) Dialogs::Result::Ok)
    {
        auto method = dlg.GetApplyMethod();
        auto start  = 0U;
        auto end    = 0U;
        switch (method)
        {
        case ApplyMethod::CurrentToken:
            start = this->currentTokenIndex;
            end   = start + 1;
            break;
        case ApplyMethod::Block:
            start = blocks[containerBlock].GetStartIndex();
            end   = blocks[containerBlock].GetEndIndex();
            break;
        case ApplyMethod::Selection:
            start = static_cast<uint32>(selection.GetSelectionStart(0));
            end   = static_cast<uint32>(selection.GetSelectionEnd(0)) + 1;
            break;
        case ApplyMethod::EntireProgram:
            start = 0;
            end   = static_cast<uint32>(tokens.size());
            break;
        default:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Unknwon implementation for apply method !");
            return;
        }
        auto count = CountSimilarTokens(start, end, tok.hash);
        if (count > 1)
        {
            LocalString<64> tmp;
            if (AppCUI::Dialogs::MessageBox::ShowOkCancel("Rename", tmp.Format("Rename %u tokens ?", count)) != AppCUI::Dialogs::Result::Ok)
                return;
        }
        for (auto idx = start; idx < end; idx++)
        {
            if (tokens[idx].hash == tok.hash)
                tokens[idx].value = dlg.GetNewValue();
        }
        // Update the original as well
        tok.value = dlg.GetNewValue();
        if (dlg.ShouldReparse())
        {
            this->Reparse(false);
        }
        else
        {
            UpdateTokensInformation();
            RecomputeTokenPositions();
        }
    }
}
void Instance::DeleteTokens()
{
    // sanity checks
    if (this->noItemsVisible)
        return;
    if ((size_t) this->currentTokenIndex >= this->tokens.size())
        return;
    auto& tok = this->tokens[this->currentTokenIndex];

    // all good -> edit the token
    auto containerBlock = TokenToBlock(this->currentTokenIndex);
    DeleteDialog dlg(tok, this->text.text, selection.HasSelection(0), containerBlock != BlockObject::INVALID_ID);
    if (dlg.Show() == (int) Dialogs::Result::Ok)
    {
        auto method = dlg.GetApplyMethod();
        auto start  = 0U;
        auto end    = 0U;
        switch (method)
        {
        case ApplyMethod::CurrentToken:
            start = this->currentTokenIndex;
            end   = start + 1;
            break;
        case ApplyMethod::Block:
            start = blocks[containerBlock].GetStartIndex();
            end   = blocks[containerBlock].GetEndIndex();
            break;
        case ApplyMethod::Selection:
            start = static_cast<uint32>(selection.GetSelectionStart(0));
            end   = static_cast<uint32>(selection.GetSelectionEnd(0)) + 1;
            break;
        default:
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Unknwon implementation for apply method in delete dialog !");
            return;
        }
        for (; start < end; start++)
            this->tokens[start].SetShouldDeleteFlag();
        this->Reparse(false);
    }
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
    case Key::PageUp:
        MoveUp(this->GetHeight(), false);
        return true;
    case Key::PageUp | Key::Shift:
        MoveUp(this->GetHeight(), true);
        return true;
    case Key::Down:
        MoveDown(1, false);
        return true;
    case Key::Down | Key::Shift:
        MoveDown(1, true);
        return true;
    case Key::PageDown:
        MoveDown(this->GetHeight(), false);
        return true;
    case Key::PageDown | Key::Shift:
        MoveDown(this->GetHeight(), true);
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
    case Key::Space | Key::Ctrl:
        SetFoldStatus(this->currentTokenIndex, FoldStatus::Reverse, true);
        return true;

    case Key::Enter:
        EditCurrentToken();
        return true;

    case Key::E:
        ExpandAll();
        return true;
    case Key::F:
        FoldAll();
        return true;

    // copy & selection
    case Key::A | Key::Ctrl:
        if ((!this->tokens.empty()) && (this->noItemsVisible == false))
        {
            this->selection.Clear();
            this->selection.SetSelection(0, 0, this->tokens.size() - 1);
        }
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
    case CMD_ID_DELETE:
        this->DeleteTokens();
        return true;
    case CMD_ID_CHANGE_SELECTION:
        this->selection.InvertMultiSelectionMode();
        return true;
    case CMD_ID_FOLD_ALL:
        this->FoldAll();
        return true;
    case CMD_ID_EXPAND_ALL:
        this->ExpandAll();
        return true;
    case CMD_ID_SHOW_PLUGINS:
        this->ShowPlugins();
        return true;
    }
    return false;
}
void Instance::OnUpdateScrollBars()
{
    if (this->noItemsVisible)
        this->UpdateVScrollBar(0, 0);
    else
        this->UpdateVScrollBar(this->currentTokenIndex, this->tokens.size());
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
void Instance::ShowPlugins()
{
    if (settings->plugins.empty())
    {
        AppCUI::Dialogs::MessageBox::ShowNotification("Plugins", "No plugins defined for this type of file !");
        return;
    }
}
std::string_view Instance::GetName()
{
    return this->name;
}
//======================================================================[Mouse coords]========================
uint32 Instance::MousePositionToTokenID(int x, int y)
{
    auto idx = 0U;
    for (const auto& tok : this->tokens)
    {
        if (tok.IsVisible() == false)
        {
            idx++;
            continue;
        }
        auto tokLeft   = tok.x + lineNrWidth - Scroll.x;
        auto tokTop    = tok.y - Scroll.y;
        auto tokRight  = tokLeft + tok.width;
        auto tokBottom = tokTop + tok.height;
        if ((x >= tokLeft) && (x < tokRight) && (y >= tokTop) && (y < tokBottom))
            return idx;
        idx++;
    }
    return Token::INVALID_INDEX;
}
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{
    if (x == (this->lineNrWidth - 1))
    {
        auto blockID = foldColumn.MouseToBlockIndex(y);
        if (blockID != BlockObject::INVALID_ID)
        {
            auto currentScroll = this->Scroll;
            SetFoldStatus(this->blocks[blockID].tokenStart, FoldStatus::Reverse, false);
            this->Scroll = currentScroll; // make sure that we preserve the same view
        }
        return;
    }
    if (x >= this->lineNrWidth)
    {
        auto tokIDX = MousePositionToTokenID(x, y);
        if (tokIDX != Token::INVALID_INDEX)
        {
            MoveToToken(tokIDX, false);
        }
    }
}
void Instance::OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button)
{
}
bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button)
{
    if (x >= this->lineNrWidth)
    {
        auto tokIDX = MousePositionToTokenID(x, y);
        if (tokIDX != Token::INVALID_INDEX)
        {
            MoveToToken(tokIDX, true);
            return true;
        }
    }
    return false;
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
bool Instance::OnMouseOver(int x, int y)
{
    if (x == (this->lineNrWidth - 1))
        return foldColumn.UpdateMouseHoverIndex(y);
    else
        return foldColumn.ClearMouseHoverIndex();
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
            auto ofsStart = tokens[static_cast<uint32>(start)].start;
            auto ofsEnd   = tokens[static_cast<uint32>(end)].end;
            tmp.Format("%X,%X", ofsStart, (ofsEnd - ofsStart) + 1);
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
int Instance::PrintTokenTypeInfo(uint32 tokenTypeID, int x, int y, uint32 width, Renderer& r)
{
    if (this->settings->parser)
    {
        LocalString<64> tmp;
        tmp.Clear();
        this->settings->parser->GetTokenIDStringRepresentation(tokenTypeID, tmp);
        this->WriteCursorInfo(r, x, y, width, "Token Type: ", tmp.ToStringView());
    }
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->Cfg.Lines.Normal);
    return x + width + 1;
}
int Instance::PrintDataTypeInfo(TokenDataType dataType, int x, int y, uint32 width, Renderer& r)
{
    this->WriteCursorInfo(r, x, y, width, "Data Type : ", TokenDataTypeToString(dataType));
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->Cfg.Lines.Normal);
    return x + width + 1;
}

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    if (this->noItemsVisible)
    {
        r.WriteSingleLineText(0, 0, "No information available", Cfg.Text.Inactive);
        return;
    }
    const auto& tok = this->tokens[this->currentTokenIndex];
    LocalString<128> tmp;
    auto xPoz = 0;
    switch (height)
    {
    case 1:
        xPoz = PrintSelectionInfo(0, 0, 0, 16, r);
        if (this->selection.IsMultiSelectionEnabled())
        {
            xPoz = PrintSelectionInfo(1, xPoz, 0, 16, r);
            xPoz = PrintSelectionInfo(2, xPoz, 0, 16, r);
            xPoz = PrintSelectionInfo(3, xPoz, 0, 16, r);
        }
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 16, "Line:", tmp.Format("%d/%d", tok.y + 1, this->lastLineNumber + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 9, "Col:", tmp.Format("%d", tok.x + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 18, "Char ofs:", tmp.Format("%u", tok.start));
        xPoz = this->PrintTokenTypeInfo(tok.type, xPoz, 0, 30, r);
        break;
    case 2:
        PrintSelectionInfo(0, 0, 0, 16, r);
        xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
        PrintSelectionInfo(1, xPoz, 0, 16, r);
        xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
        this->WriteCursorInfo(r, xPoz, 0, 16, "Line: ", tmp.Format("%d/%d", tok.y + 1, this->lastLineNumber + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 1, 16, "Col : ", tmp.Format("%d", tok.x + 1));
        this->WriteCursorInfo(r, xPoz, 0, 18, "Char ofs: ", tmp.Format("%u", tok.start));
        xPoz = this->WriteCursorInfo(r, xPoz, 1, 18, "Tokens  : ", tmp.Format("%u", (size_t) tokens.size()));
        this->WriteCursorInfo(r, xPoz, 0, 35, "Token     : ", tok.GetText(this->text.text));
        xPoz = this->PrintTokenTypeInfo(tok.type, xPoz, 1, 35, r);
        break;
    case 3:
        PrintSelectionInfo(0, 0, 0, 16, r);
        PrintSelectionInfo(1, 0, 1, 16, r);
        xPoz = PrintSelectionInfo(2, 0, 2, 16, r);
        PrintSelectionInfo(3, xPoz, 0, 16, r);
        this->WriteCursorInfo(r, xPoz, 1, 16, "Line: ", tmp.Format("%d/%d", tok.y + 1, this->lastLineNumber + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 2, 16, "Col : ", tmp.Format("%d", tok.x + 1));
        this->WriteCursorInfo(r, xPoz, 0, 35, "Token     : ", tok.GetText(this->text.text));
        this->PrintTokenTypeInfo(tok.type, xPoz, 1, 35, r);
        xPoz = this->PrintDataTypeInfo(tok.dataType, xPoz, 2, 35, r);
        break;
    default:
        PrintSelectionInfo(0, 0, 0, 16, r);
        PrintSelectionInfo(1, 0, 1, 16, r);
        PrintSelectionInfo(2, 0, 2, 16, r);
        xPoz = PrintSelectionInfo(3, 0, 3, 16, r);

        // second colum
        this->WriteCursorInfo(r, xPoz, 0, 20, "Line    : ", tmp.Format("%d/%d", tok.y + 1, this->lastLineNumber + 1));
        this->WriteCursorInfo(r, xPoz, 1, 20, "Col     : ", tmp.Format("%d", tok.x + 1));
        this->WriteCursorInfo(r, xPoz, 2, 20, "Char ofs: ", tmp.Format("%u", tok.start));
        xPoz = this->WriteCursorInfo(r, xPoz, 3, 20, "Tokens  : ", tmp.Format("%u", (size_t) tokens.size()));

        // Third column
        this->WriteCursorInfo(r, xPoz, 0, 40, "Token     : ", tok.GetText(this->text.text));
        this->WriteCursorInfo(r, xPoz, 1, 40, "Original  : ", tok.GetOriginalText(this->text.text));
        this->PrintTokenTypeInfo(tok.type, xPoz, 2, 40, r);
        xPoz = this->PrintDataTypeInfo(tok.dataType, xPoz, 3, 40, r);

        break;
    }
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