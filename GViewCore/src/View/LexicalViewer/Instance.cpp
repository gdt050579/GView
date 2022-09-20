#include "LexicalViewer.hpp"
#include <algorithm>

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_SHOW_METADATA    = 0xBF00;
constexpr int32 CMD_ID_SAVE_AS          = 0xBF01;
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
                this->tokens[idx].pos.x = 0;
                this->tokens[idx].pos.y = 0;
                p += (this->tokens[idx].end - this->tokens[idx].start);
                pos += (this->tokens[idx].end - this->tokens[idx].start);
                if (p >= e)
                    break;
            }
            else
            {
                this->tokens[idx].pos.x = x;
                this->tokens[idx].pos.y = y;
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
        if (tok.pos.y != currentLineYOffset)
            break;
        tok.pos.x += diff;
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
        if (tok.pos.y != currentLineYOffset)
        {
            currentLineYOffset = tok.pos.y;
            diffToAdd          = 0;
        }
        if ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None)
            diffToAdd = diff;
        tok.pos.x += diffToAdd;
    }
}
void Instance::PrettyFormatIncreaseAllXWithValue(uint32 idxStart, uint32 idxEnd, int32 dif)
{
    for (auto idx = idxStart; idx < idxEnd; idx++)
    {
        auto& tok = this->tokens[idx];
        if (tok.IsVisible() == false)
            continue;
        tok.pos.x += dif;
    }
    if (idxEnd > 0)
    {
        // move all tokens after the end of the block with the same diff
        auto lastLineY = this->tokens[idxEnd - 1].pos.y;
        auto len       = static_cast<uint32>(this->tokens.size());
        for (auto idx = idxEnd; idx < len; idx++)
        {
            auto& tok = this->tokens[idx];
            if (tok.IsVisible() == false)
                continue;
            if (tok.pos.y != lastLineY)
                break;
            tok.pos.x += dif;
        }
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
        if (lastLine != tok.pos.y)
        {
            lastLine                = tok.pos.y;
            dif                     = 0;
            firstWithSameColumnFlag = true;
        }
        if ((firstWithSameColumnFlag) && ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None))
        {
            dif                     = columnXOffset - tok.pos.x;
            firstWithSameColumnFlag = false;
        }
        tok.pos.x += dif;
        if (tok.IsBlockStarter())
        {
            auto& block   = this->blocks[tok.blockID];
            auto endToken = block.HasEndMarker() ? block.tokenEnd : block.tokenEnd + 1;
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
            case BlockAlignament::ParentBlock:
            case BlockAlignament::ParentBlockWithIndent:
                // align until current line ends --> if a sameColumn flag is found , align the rest of the block as well
                PrettyFormatIncreaseUntilNewLineXWithValue(idx + 1, endToken, tok.pos.y, dif);
                break;
            case BlockAlignament::CurrentToken:
            case BlockAlignament::CurrentTokenWithIndent:
                // all visible tokens must be increaset with diff
                PrettyFormatIncreaseAllXWithValue(idx + 1, endToken, dif);
                lastLine = -1; // required so that we don't add diff twice
                block.leftHighlightMargin += dif;
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
void Instance::PrettyFormatForBlock(uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin, PrettyFormatLayoutManager& manager)
{
    auto idx                     = idxStart;
    auto partOfFoldedBlock       = false;
    auto indent                  = 0U;
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
            if (((tok.align & TokenAlignament::NewLineBefore) != TokenAlignament::None) && (manager.y > topMargin))
            {
                manager.x              = leftMargin + indent * settings->indentWidth;
                manager.spaceAdded     = true;
                manager.firstOnNewLine = true;
                if (manager.y == manager.lastY)
                    manager.y += 2;
                else
                    manager.y++;
            }
            if (((tok.align & TokenAlignament::StartsOnNewLine) != TokenAlignament::None) && (!manager.firstOnNewLine))
            {
                manager.x              = leftMargin + indent * settings->indentWidth;
                manager.spaceAdded     = true;
                manager.firstOnNewLine = true;
                manager.y++;
            }
            if ((tok.align & TokenAlignament::AfterPreviousToken) != TokenAlignament::None)
            {
                if (manager.y == manager.lastY)
                {
                    if ((manager.spaceAdded) && (manager.x > leftMargin))
                        manager.x--;
                }
                else
                {
                    if (idx > idxStart)
                    {
                        auto& previous = tokens[idx - 1];
                        manager.y      = previous.pos.y + previous.pos.height - 1;
                        manager.x      = previous.pos.x + previous.pos.width;
                    }
                }
                manager.spaceAdded = false;
            }
            if (((tok.align & TokenAlignament::AddSpaceBefore) != TokenAlignament::None) && (!manager.spaceAdded))
                manager.x++;
        }

        // assign position to curent token
        tok.pos.x               = manager.x;
        tok.pos.y               = manager.y;
        manager.firstOnNewLine  = false;
        const auto blockStarter = tok.IsBlockStarter();
        const auto folded       = tok.IsFolded();
        if ((blockStarter) && (folded))
        {
            const auto& block = this->blocks[tok.blockID];
            if (block.foldMessage.empty())
                manager.x += tok.pos.width + 3; // for ...
            else
                manager.x += tok.pos.width + (int32) block.foldMessage.size();
            partOfFoldedBlock = block.HasEndMarker(); // only limit the alignament for end marker
        }
        else
        {
            manager.x += tok.pos.width;
            manager.y += tok.pos.height - 1;
            partOfFoldedBlock = false;
        }
        manager.lastY      = manager.y;
        manager.spaceAdded = false;
        if (!partOfFoldedBlock)
        {
            // Same column logic
            if ((tok.align & TokenAlignament::SameColumn) != TokenAlignament::None)
            {
                sameColumnCount++;
                if (sameColumnCount == 1)
                {
                    // first one
                    maxXOffsetForSameColumn = tok.pos.x;
                    lastSameColumnLine      = tok.pos.y;
                }
                else
                {
                    if (tok.pos.y != lastSameColumnLine)
                    {
                        // a new item on a differnt line
                        maxXOffsetForSameColumn = std::max<>(maxXOffsetForSameColumn, tok.pos.x);
                        sameColumnDifferences   = true;      // set the marker
                        lastSameColumnLine      = tok.pos.y; // update last line
                    }
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
                manager.x++;
                manager.spaceAdded = true;
            }
            if ((tok.align & TokenAlignament::NewLineAfter) != TokenAlignament::None)
            {
                manager.x              = leftMargin + indent * settings->indentWidth;
                manager.spaceAdded     = true;
                manager.firstOnNewLine = true;
                manager.y++;
            }
            if (((tok.align & TokenAlignament::WrapToNextLine) != TokenAlignament::None) && (manager.x > (int) this->settings->maxWidth))
            {
                manager.x              = leftMargin + indent * settings->indentWidth;
                manager.spaceAdded     = true;
                manager.firstOnNewLine = true;
                manager.y++;
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
            case BlockAlignament::ParentBlock:
                blockMarginTop            = manager.y;
                blockMarginLeft           = leftMargin;
                block.leftHighlightMargin = leftMargin;
                break;
            case BlockAlignament::ParentBlockWithIndent:
                blockMarginTop            = manager.y;
                blockMarginLeft           = leftMargin + (indent + 1) * settings->indentWidth;
                block.leftHighlightMargin = leftMargin + indent * settings->indentWidth;
                break;
            case BlockAlignament::CurrentToken:
                blockMarginTop            = manager.y;
                blockMarginLeft           = manager.x;
                block.leftHighlightMargin = manager.x;
                break;
            case BlockAlignament::CurrentTokenWithIndent:
                blockMarginTop            = manager.y;
                blockMarginLeft           = manager.x + settings->indentWidth;
                block.leftHighlightMargin = manager.x;
                break;
            default:
                blockMarginTop            = manager.y;
                blockMarginLeft           = manager.x;
                block.leftHighlightMargin = 0;
                break;
            }
            if (((idx + 1) < endToken) && (tok.IsFolded() == false))
            {
                // not an empty block and not folded
                if (manager.firstOnNewLine)
                {
                    // of the new token has already been moved to the next like, make sure that the "x" offset is alligned to the new block
                    // position
                    manager.x = blockMarginLeft;
                }
                manager.y = blockMarginTop;
                PrettyFormatForBlock(idx + 1, endToken, blockMarginLeft, blockMarginTop, manager);
                if (manager.x == blockMarginLeft)
                    manager.x = leftMargin + indent * settings->indentWidth;
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
}
void Instance::PrettyFormat()
{
    PrettyFormatLayoutManager manager;
    manager.x              = 0;
    manager.y              = 0;
    manager.lastY          = 0;
    manager.firstOnNewLine = true;
    manager.spaceAdded     = true;
    PrettyFormatForBlock(0, (uint32) this->tokens.size(), 0, 0, manager);
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

void Instance::MakeTokenVisible(uint32 index)
{
    if (static_cast<size_t>(index) >= this->tokens.size())
        return;
    auto& tok    = this->tokens[index];
    auto blockID = BlockObject::INVALID_ID;
    if (tok.IsBlockStarter())
    {
        tok.SetFolded(false);
        tok.SetVisible(true);
        if (index == 0)
            return;
        // find the block that contains the current block (start with the precedent token)
        blockID = TokenToBlock(index - 1);
    }
    else
    {
        tok.SetVisible(true);
        // find the block that contains the current bloc
        blockID = TokenToBlock(index);
    }
    if (blockID == BlockObject::INVALID_ID)
        return;
    MakeTokenVisible(this->blocks[blockID].tokenStart);
}

void Instance::EnsureCurrentItemIsVisible()
{
    if (this->noItemsVisible)
        return;

    const auto& tok    = this->tokens[this->currentTokenIndex];
    auto tk_right      = tok.pos.x + (int32) tok.pos.width - 1;
    auto tk_bottom     = tok.pos.y + (int32) tok.pos.height - 1;
    auto scroll_right  = Scroll.x + this->GetWidth() - 1 - this->lineNrWidth;
    auto scroll_bottom = Scroll.y + this->GetHeight() - 1;

    // if already in current view -> return;
    if ((tok.pos.x >= Scroll.x) && (tok.pos.y >= Scroll.y) && (tk_right <= scroll_right) && (tk_bottom <= scroll_bottom))
        return;
    if (tk_right > scroll_right)
        Scroll.x += (tk_right - scroll_right);
    if (tk_bottom > scroll_bottom)
        Scroll.y += (tk_bottom - scroll_bottom);
    if (tok.pos.x < Scroll.x)
        Scroll.x = tok.pos.x;
    if (tok.pos.y < Scroll.y)
        Scroll.y = tok.pos.y;
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
    this->showMetaData      = true; // has to be true at this point to proper compute line numbers

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

        // step 3 (recompute line numbers)
        // the list of tokens and blocks has been cleared so we know for sure that everything is expanded
        auto lastY  = -1;
        auto lineNo = 0;
        for (auto& tok : this->tokens)
        {
            if (tok.pos.y != lastY)
            {
                lineNo++;
                lastY = tok.pos.y;
            }
            tok.lineNo = lineNo;
        }
        // at the end --> lineNo is the highest line number
        this->lineNrWidth    = 0;
        this->lastLineNumber = lineNo;

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
void Instance::BakupTokensPositions()
{
    // make a copy of all tokens positions
    backupedTokenPositionList.reserve(this->tokens.size());
    backupedTokenPositionList.clear();
    for (const auto& tok : this->tokens)
    {
        backupedTokenPositionList.push_back({ 0, 0, 1, 1, TokenStatus::None });
    }
}
void Instance::RestoreTokensPositionsFromBackup()
{
    ASSERT(this->tokens.size() == this->backupedTokenPositionList.size(), "Expecting backup list to be of the same size as tokens list");
    auto sz    = this->tokens.size();
    auto index = static_cast<size_t>(0);
    for (auto& tok : this->tokens)
    {
        const auto& bakPos = this->backupedTokenPositionList[index];
        // copy from bakPos to tok
        index++;
    }
    backupedTokenPositionList.clear();
}

void Instance::FillBlockSpace(Graphics::Renderer& renderer, const BlockObject& block)
{
    const auto& tok      = this->tokens[block.tokenStart];
    const auto& tknEnd   = this->tokens[block.tokenEnd];
    const auto rightPos  = tknEnd.pos.x + static_cast<int32>(tknEnd.pos.width) - 1;
    const auto bottomPos = tknEnd.pos.y + static_cast<int32>(tknEnd.pos.height) - 1;
    const auto col       = Cfg.Editor.Focused;
    if (tok.IsFolded() == false)
    {
        if (bottomPos > tok.pos.y)
        {
            // multi-line block
            bool fillLastLine =
                  ((size_t) block.tokenEnd + (size_t) 1 < tokens.size()) ? (tokens[block.tokenEnd + 1].pos.y != tknEnd.pos.y) : true;
            auto leftPos = this->prettyFormat ? lineNrWidth + block.leftHighlightMargin - Scroll.x : 0;
            // first draw the first line
            renderer.FillHorizontalLine(lineNrWidth + tok.pos.x - Scroll.x, tok.pos.y - Scroll.y, this->GetWidth(), ' ', col);
            // draw the middle part
            if (fillLastLine)
            {
                renderer.FillRect(leftPos, tok.pos.y + 1 - Scroll.y, this->GetWidth(), bottomPos - Scroll.y, ' ', col);
            }
            else
            {
                // partial rect (the last line of the block contains some elements that are not part of the block
                renderer.FillRect(leftPos, tok.pos.y + 1 - Scroll.y, this->GetWidth(), bottomPos - 1 - Scroll.y, ' ', col);
                renderer.FillHorizontalLine(leftPos, bottomPos - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
            }
        }
        else
        {
            renderer.FillHorizontalLine(
                  lineNrWidth + tok.pos.x - Scroll.x, tok.pos.y - Scroll.y, lineNrWidth + rightPos - Scroll.x, ' ', col);
        }
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
        case TokenColor::Error:
            col = ColorPair{ Color::Black, Color::Red };
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
        foldColumn.SetBlock(tok.pos.y - Scroll.y, tok.blockID);
    }
    if (tok.pos.height > 1)
    {
        WriteTextParams params(WriteTextFlags::MultipleLines, TextAlignament::Left);
        params.X     = lineNrWidth + tok.pos.x - Scroll.x;
        params.Y     = tok.pos.y - Scroll.y;
        params.Color = col;
        renderer.WriteText(txt, params);
    }
    else
    {
        renderer.WriteSingleLineText(lineNrWidth + tok.pos.x - Scroll.x, tok.pos.y - Scroll.y, txt, col);
    }
    if (blockStarter && tok.IsFolded())
    {
        auto x            = lineNrWidth + tok.pos.x + tok.pos.width - Scroll.x;
        auto y            = tok.pos.y + tok.pos.height - 1 - Scroll.y;
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
        if ((tok.pos.y == precTok.pos.y) && (tok.pos.height == 1))
        {
            // fill in the space between them
            renderer.FillHorizontalLine(
                  lineNrWidth + precTok.pos.x + precTok.pos.width - Scroll.x,
                  precTok.pos.y - Scroll.y,
                  lineNrWidth + tok.pos.x - 1 - Scroll.x,
                  -1,
                  Cfg.Selection.Editor);
        }
    }
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    auto state           = this->HasFocus() ? ControlState::Focused : ControlState::Normal;
    auto lineMarkerColor = Cfg.LineMarker.GetColor(state);
    // draw line number bar
    renderer.FillRect(0, 0, this->lineNrWidth - 2, this->GetHeight(), ' ', lineMarkerColor);

    // check if there are items to be shown
    if (noItemsVisible)
        return;
    foldColumn.Clear(this->GetHeight());

    NumericFormatter num;
    WriteTextParams params(WriteTextFlags::FitTextToWidth | WriteTextFlags::SingleLine);

    params.Width = lineNrWidth - 2;
    params.Color = lineMarkerColor;
    params.X     = params.Width;
    params.Align = TextAlignament::Right;

    // paint token on cursor first (and show block highlight if needed)
    if (this->currentTokenIndex < this->tokens.size())
    {
        auto& currentTok = this->tokens[this->currentTokenIndex];
        if (currentTok.IsVisible())
        {
            this->currentHash = currentTok.hash;
            PaintToken(renderer, currentTok, this->currentTokenIndex);
            params.Y = std::max<>(0, currentTok.pos.y - Scroll.y);
            renderer.WriteText(num.ToDec(currentTok.lineNo), params);
        }
    }
    else
    {
        this->currentHash = 0;
    }

    const int32 scroll_right  = Scroll.x + (int32) this->GetWidth() - 1;
    const int32 scroll_bottom = Scroll.y + (int32) this->GetHeight() - 1;
    uint32 idx                = 0;
    int32 lastY               = -1;

    for (auto& t : this->tokens)
    {
        // skip hidden and current token
        if ((!t.IsVisible()) || (idx == this->currentTokenIndex))
        {
            idx++;
            continue;
        }
        const auto tk_right  = t.pos.x + (int32) t.pos.width - 1;
        const auto tk_bottom = t.pos.y + (int32) t.pos.height - 1;

        // if token not in visible screen => skip it
        if ((t.pos.x > scroll_right) || (t.pos.y > scroll_bottom) || (tk_right < Scroll.x) || (tk_bottom < Scroll.y))
        {
            idx++;
            continue;
        }
        PaintToken(renderer, t, idx);
        if (t.pos.y != lastY)
        {
            params.Y = std::max<>(0, t.pos.y - Scroll.y);
            renderer.WriteText(num.ToDec(t.lineNo), params);
            lastY = t.pos.y;
        }
        idx++;
    }
    foldColumn.Paint(renderer, this->lineNrWidth - 1, this);
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    if (this->showMetaData)
        commandBar.SetCommand(config.Keys.showMetaData, "ShowMetaData:ON", CMD_ID_SHOW_METADATA);
    else
        commandBar.SetCommand(config.Keys.showMetaData, "ShowMetaData:OFF", CMD_ID_SHOW_METADATA);

    if (this->noItemsVisible == false)
        commandBar.SetCommand(Key::Delete, "Delete", CMD_ID_DELETE);

    if (this->selection.IsSingleSelectionEnabled())
        commandBar.SetCommand(config.Keys.changeSelectionType, "Select:Single", CMD_ID_CHANGE_SELECTION);
    else
        commandBar.SetCommand(config.Keys.changeSelectionType, "Select:Multiple", CMD_ID_CHANGE_SELECTION);

    commandBar.SetCommand(config.Keys.foldAll, "Fold all", CMD_ID_FOLD_ALL);
    commandBar.SetCommand(config.Keys.expandAll, "Expand all", CMD_ID_EXPAND_ALL);
    commandBar.SetCommand(config.Keys.showPlugins, "Plugins", CMD_ID_SHOW_PLUGINS);
    commandBar.SetCommand(config.Keys.saveAs, "Save As", CMD_ID_SAVE_AS);

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
    auto yPos         = this->tokens[currentTokenIndex].pos.y;
    auto lastValidIdx = this->currentTokenIndex;
    while (idx > 0)
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx--;
            continue;
        }
        if (this->tokens[idx].pos.y != yPos)
            break;
        lastValidIdx = idx;
        if (stopAfterFirst)
            break;
        else
            idx--;
    }
    if ((idx == 0) && (this->tokens[0].IsVisible()) && (this->tokens[0].pos.y == yPos))
        lastValidIdx = 0;
    MoveToToken(lastValidIdx, selected);
}
void Instance::MoveRight(bool selected, bool stopAfterFirst)
{
    if (noItemsVisible)
        return;
    auto idx          = this->currentTokenIndex + 1;
    auto yPos         = this->tokens[currentTokenIndex].pos.y;
    auto lastValidIdx = this->currentTokenIndex;
    auto count        = this->tokens.size();
    while (idx < count)
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (this->tokens[idx].pos.y != yPos)
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
    auto lastY = this->tokens[this->currentTokenIndex].pos.y;
    auto posX  = this->tokens[this->currentTokenIndex].pos.x;
    while (times > 0)
    {
        while ((idx > 0) && (this->tokens[idx].pos.y == lastY))
            idx--;

        while ((idx > 0) && ((!this->tokens[idx].IsVisible()) || (this->tokens[idx].pos.y == lastY)))
            idx--;

        if (idx == 0)
        {
            if (this->tokens[0].IsVisible())
            {
                if (this->tokens[idx].pos.y == lastY)
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
        lastY = this->tokens[idx].pos.y;
        times--;
    }
    // found the line that I am interested in --> now search the closest token in terms of position
    auto found     = idx;
    auto best_dist = ComputeXDist(this->tokens[found].pos.x, posX);
    while ((idx > 0) && (best_dist > 0))
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx--;
            continue;
        }
        if (this->tokens[idx].pos.y != lastY)
            break;
        auto dist = ComputeXDist(this->tokens[idx].pos.x, posX);
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
        auto dist = ComputeXDist(this->tokens[idx].pos.x, posX);
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
    auto lastY = this->tokens[this->currentTokenIndex].pos.y;
    auto posX  = this->tokens[this->currentTokenIndex].pos.x;
    if (idx >= cnt)
        return;
    while (times > 0)
    {
        while ((idx < cnt) && ((!this->tokens[idx].IsVisible()) || (this->tokens[idx].pos.y == lastY)))
            idx++;
        if (idx >= cnt)
        {
            // already on the last line --> move to last token
            MoveToClosestVisibleToken(cnt - 1, selected);
            return;
        }
        lastY = this->tokens[idx].pos.y;
        times--;
    }
    // found the line that I am interested in --> now search the closest token in terms of position
    auto found     = idx;
    auto best_dist = ComputeXDist(this->tokens[found].pos.x, posX);
    while ((idx < cnt) && (best_dist > 0))
    {
        if (this->tokens[idx].IsVisible() == false)
        {
            idx++;
            continue;
        }
        if (this->tokens[idx].pos.y != lastY)
            break;
        auto dist = ComputeXDist(this->tokens[idx].pos.x, posX);
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
    if (tok.error.Len() > 0)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", tok.error);
    }
    if (tok.CanChangeValue() == false)
    {
        AppCUI::Dialogs::MessageBox::ShowNotification("Rename", "This type of token can not be modified/renamed !");
        return;
    }

    // all good -> edit the token
    auto containerBlock = TokenToBlock(this->currentTokenIndex);
    NameRefactorDialog dlg(tok, this->text.text, selection.HasSelection(0), containerBlock != BlockObject::INVALID_ID);
    if (dlg.Show() == Dialogs::Result::Ok)
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
    if (dlg.Show() == Dialogs::Result::Ok)
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
    // case CMD_ID_PRETTY_FORMAT:
    //     this->prettyFormat = !this->prettyFormat;
    //     this->RecomputeTokenPositions();
    //     return true;
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
    case CMD_ID_SAVE_AS:
        this->ShowSaveAsDialog();
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
    if (this->tokens.empty())
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "No tokens to go to !");
        return true;
    }
    auto curentLineNumber = 1U;
    if (this->currentTokenIndex < this->tokens.size())
        curentLineNumber = this->tokens[this->currentTokenIndex].lineNo;

    GoToDialog dlg(curentLineNumber, lastLineNumber);
    if (dlg.Show() == Dialogs::Result::Ok)
    {
        auto gotoLine = dlg.GetSelectedLineNo();
        auto idx      = 0U;
        for (const auto& tok : this->tokens)
        {
            if (tok.lineNo == gotoLine)
            {
                MakeTokenVisible(idx);
                RecomputeTokenPositions();
                MoveToToken(idx, false);
                break;
            }
            idx++;
        }
    }
    return true;
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowCopyDialog()
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
    // we need to clone the existing text as we don't want to modify the text while showing it
    auto textClone = text.Clone();
    TextEditorBuilder ted(textClone);
    TokensListBuilder tokensList(this);
    BlocksListBuilder blockList(this);
    PluginData pd(ted, tokensList, blockList);
    pd.currentTokenIndex = this->currentTokenIndex;

    // selection and block infos
    uint32 selectionStart = 0, selectionEnd = 0, blockStart = 0, blockEnd = 0;
    auto tokensCount = static_cast<uint32>(this->tokens.size());
    if (this->selection.HasSelection(0))
    {
        selectionStart = static_cast<uint32>(this->selection.GetSelectionStart(0));
        selectionEnd   = static_cast<uint32>(this->selection.GetSelectionEnd(0) + 1);
        // some sanity checks
        if ((selectionStart >= selectionEnd) || (selectionEnd > tokensCount))
        {
            selectionStart = 0;
            selectionEnd   = 0;
        }
    }
    auto blockIndex = TokenToBlock(this->currentTokenIndex);
    if (blockIndex != BlockObject::INVALID_ID)
    {
        blockStart = this->blocks[blockIndex].GetStartIndex();
        blockEnd   = this->blocks[blockIndex].GetEndIndex();
        // some sanity checks
        if ((blockStart >= blockEnd) || (blockEnd > tokensCount))
        {
            blockStart = 0;
            blockEnd   = 0;
        }
    }

    PluginDialog dlg(pd, this->settings.ToReference(), selectionStart, selectionEnd, blockStart, blockEnd);
    auto result = static_cast<AppCUI::Dialogs::Result>(dlg.Show());
    textClone   = ted.Release();
    if (result == Dialogs::Result::Cancel)
    {
        textClone.Destroy();
        return;
    }
    switch (dlg.GetAfterActionRequest())
    {
    case PluginAfterActionRequest::None:
        textClone.Destroy();
        return; // do nothing
    case PluginAfterActionRequest::Refresh:
        textClone.Destroy();
        UpdateTokensInformation();
        RecomputeTokenPositions();
        break;
    case PluginAfterActionRequest::Rescan:
        this->text.Destroy();
        this->text = textClone;
        this->Parse();
        break;
    default:
        textClone.Destroy();
        return;
    }
}
void Instance::ShowSaveAsDialog()
{
    SaveAsDialog dlg(this->obj);
    if (dlg.Show() != Dialogs::Result::Ok)
        return;
    LocalUnicodeStringBuilder<256> tmpPath;
    tmpPath.Set(dlg.GetFilePath());

    if ((dlg.ShouldBackupOriginalFile()) && (std::filesystem::exists(tmpPath)))
    {
        LocalUnicodeStringBuilder<256> tmpBakPath;
        tmpBakPath.Set(tmpPath);
        tmpBakPath.Add(".bak");
        try
        {
            std::filesystem::rename(tmpPath, tmpBakPath);
        }
        catch (...)
        {
            if (Dialogs::MessageBox::ShowOkCancel(
                      "Backup", "Unable to backup the original file. Do you want to continue and overwrite it ?") != Dialogs::Result::Ok)
                return;
        }
    }

    // open the file
    AppCUI::OS::File f;
    if (f.Create(tmpPath, true) == false)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Fail to create file !");
        return;
    }

    // actual save
    // step 1 --> make sure that we save all tokens , not just the visible ones
    BakupTokensPositions();
    auto originalShowMetaDataValue = this->showMetaData;
    this->showMetaData             = true;
    ExpandAll();

    // Step 2 --> create a buffer for the entire text
    Buffer b;
    CharacterEncoding::EncodedCharacter encChar;
    b.Reserve(100000);
    auto y       = 0;
    auto x       = 0;
    auto newLine = dlg.GetNewLineFormat();
    auto enc     = dlg.GetTextEncoding();
    auto bom     = dlg.HasBOM() ? CharacterEncoding::GetBOMForEncoding(enc) : BufferView();

    b.Add(bom);
    for (const auto& tok : this->tokens)
    {
        if (tok.IsVisible() == false)
            continue;
        if (y < tok.pos.y)
        {
            b.AddMultipleTimes(newLine, tok.pos.y - y);
            x = 0;
            y = tok.pos.y;
        }
        if (x < tok.pos.x)
        {
            b.AddMultipleTimes(" ", tok.pos.x - x);
            x = tok.pos.x;
        }
        auto txt    = tok.GetText(this->text.text);
        auto lastCH = static_cast<char16>(0);
        for (auto ch : txt)
        {
            if ((ch == '\n') || (ch == '\r'))
            {
                if (((lastCH == '\n') || (lastCH == '\r')) && (lastCH != ch))
                {
                    // CRLF or LFCR cases => do nothing, just reset the last char
                    lastCH = 0;
                }
                else
                {
                    b.Add(newLine);
                    b.AddMultipleTimes(" ", tok.pos.x);
                    x = tok.pos.x;
                    y++;
                    lastCH = ch;
                }
            }
            else
            {
                b.Add(encChar.Encode(ch, enc));
                x++;
                lastCH = 0;
            }
        }
        if (b.GetLength() > 0x10000)
        {
            if (f.Write(static_cast<const void*>(b.GetData()), static_cast<uint32>(b.GetLength())) == false)
            {
                AppCUI::Dialogs::MessageBox::ShowError("Error", "Writing to file failed !");
                f.Close();
                return;
            }
            b.Resize(0);
        }
    }
    // Stept 3 --> restore the original tokens positions
    RestoreTokensPositionsFromBackup();
    this->showMetaData = originalShowMetaDataValue;

    // Step 4 --> save
    if (b.GetLength() > 0)
    {
        if (f.Write(static_cast<const void*>(b.GetData()), static_cast<uint32>(b.GetLength())) == false)
        {
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Writing to file failed !");
            f.Close();
            return;
        }
    }
    f.Close();
    AppCUI::Dialogs::MessageBox::ShowNotification("Save As", "Save succesifull !");
    if (dlg.ShouldOpenANewWindow())
    {
        GView::App::OpenFile(tmpPath);
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
        auto tokLeft   = tok.pos.x + lineNrWidth - Scroll.x;
        auto tokTop    = tok.pos.y - Scroll.y;
        auto tokRight  = tokLeft + static_cast<int32>(tok.pos.width);
        auto tokBottom = tokTop + static_cast<int32>(tok.pos.height);
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
int Instance::PrintError(std::u16string_view error, int x, int y, uint32 width, Renderer& r)
{
    auto col = this->HasFocus() ? Cfg.Text.Error : Cfg.Text.Inactive;
    r.WriteSingleLineText(x, y, width, error, col, TextAlignament::Left);
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
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 16, "Line:", tmp.Format("%d/%d", tok.lineNo, this->lastLineNumber));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 9, "Col:", tmp.Format("%d", tok.pos.x + 1));
        xPoz = this->WriteCursorInfo(r, xPoz, 0, 18, "Char ofs:", tmp.Format("%u", tok.start));
        if (tok.error.Len() > 0)
            xPoz = PrintError(tok.error, xPoz, 0, 50, r);
        else
            xPoz = this->PrintTokenTypeInfo(tok.type, xPoz, 0, 30, r);
        break;
    case 2:
        PrintSelectionInfo(0, 0, 0, 16, r);
        xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
        PrintSelectionInfo(1, xPoz, 0, 16, r);
        xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
        this->WriteCursorInfo(r, xPoz, 0, 16, "Line: ", tmp.Format("%d/%d", tok.lineNo, this->lastLineNumber));
        xPoz = this->WriteCursorInfo(r, xPoz, 1, 16, "Col : ", tmp.Format("%d", tok.pos.x + 1));
        this->WriteCursorInfo(r, xPoz, 0, 18, "Char ofs: ", tmp.Format("%u", tok.start));
        xPoz = this->WriteCursorInfo(r, xPoz, 1, 18, "Tokens  : ", tmp.Format("%u", (size_t) tokens.size()));
        this->WriteCursorInfo(r, xPoz, 0, 35, "Token     : ", tok.GetText(this->text.text));
        if (tok.error.Len() > 0)
            xPoz = PrintError(tok.error, xPoz, 1, 35, r);
        else
            xPoz = this->PrintTokenTypeInfo(tok.type, xPoz, 1, 35, r);
        break;
    case 3:
        PrintSelectionInfo(0, 0, 0, 16, r);
        PrintSelectionInfo(1, 0, 1, 16, r);
        xPoz = PrintSelectionInfo(2, 0, 2, 16, r);
        PrintSelectionInfo(3, xPoz, 0, 16, r);
        this->WriteCursorInfo(r, xPoz, 1, 16, "Line: ", tmp.Format("%d/%d", tok.lineNo, this->lastLineNumber));
        xPoz = this->WriteCursorInfo(r, xPoz, 2, 16, "Col : ", tmp.Format("%d", tok.pos.x + 1));
        this->WriteCursorInfo(r, xPoz, 0, 35, "Token     : ", tok.GetText(this->text.text));
        this->PrintTokenTypeInfo(tok.type, xPoz, 1, 35, r);
        if (tok.error.Len() > 0)
            xPoz = PrintError(tok.error, xPoz, 2, 35, r);
        else
            xPoz = this->PrintDataTypeInfo(tok.dataType, xPoz, 2, 35, r);
        break;
    default:
        PrintSelectionInfo(0, 0, 0, 16, r);
        PrintSelectionInfo(1, 0, 1, 16, r);
        PrintSelectionInfo(2, 0, 2, 16, r);
        xPoz = PrintSelectionInfo(3, 0, 3, 16, r);

        // second colum
        this->WriteCursorInfo(r, xPoz, 0, 20, "Line    : ", tmp.Format("%d/%d", tok.lineNo, this->lastLineNumber));
        this->WriteCursorInfo(r, xPoz, 1, 20, "Col     : ", tmp.Format("%d", tok.pos.x + 1));
        this->WriteCursorInfo(r, xPoz, 2, 20, "Char ofs: ", tmp.Format("%u", tok.start));
        xPoz = this->WriteCursorInfo(r, xPoz, 3, 20, "Tokens  : ", tmp.Format("%u", (size_t) tokens.size()));

        // Third column
        this->WriteCursorInfo(r, xPoz, 0, 40, "Token     : ", tok.GetText(this->text.text));
        this->WriteCursorInfo(r, xPoz, 1, 40, "Original  : ", tok.GetOriginalText(this->text.text));
        this->PrintTokenTypeInfo(tok.type, xPoz, 2, 40, r);
        if (tok.error.Len() > 0)
            xPoz = PrintError(tok.error, xPoz, 3, 40, r);
        else
            xPoz = this->PrintDataTypeInfo(tok.dataType, xPoz, 3, 40, r);

        break;
    }
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    IndentWidth,
    ViewWidth,
    // shortcuts
    ShowPluginListKey,
    SaveAsKey,
    ShowMetaDataKey,
    ChangeSelectionTypeKey,
    FoldAllKey,
    ExpandAllKey,
    // General
    NoOfTokens,
    NoOfBlocks,
    NoOfLines,
    // View
    Pretty,
    ShowMetaData
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::IndentWidth:
        value = this->settings->indentWidth;
        return true;
    case PropertyID::ViewWidth:
        value = this->settings->maxWidth;
        return true;
    case PropertyID::ShowPluginListKey:
        value = this->config.Keys.showPlugins;
        return true;
    case PropertyID::SaveAsKey:
        value = this->config.Keys.saveAs;
        return true;
    case PropertyID::ShowMetaDataKey:
        value = this->config.Keys.showMetaData;
        return true;
    case PropertyID::ChangeSelectionTypeKey:
        value = this->config.Keys.changeSelectionType;
        return true;
    case PropertyID::FoldAllKey:
        value = this->config.Keys.foldAll;
        return true;
    case PropertyID::ExpandAllKey:
        value = this->config.Keys.expandAll;
        return true;
    case PropertyID::NoOfTokens:
        value = static_cast<uint32>(this->tokens.size());
        return true;
    case PropertyID::NoOfBlocks:
        value = static_cast<uint32>(this->blocks.size());
        return true;
    case PropertyID::NoOfLines:
        value = static_cast<uint32>(this->lastLineNumber + 1);
        return true;
    case PropertyID::Pretty:
        value = this->prettyFormat;
        return true;
    case PropertyID::ShowMetaData:
        value = this->showMetaData;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::IndentWidth:
        this->settings->indentWidth = std::min<uint8>(30, std::max<uint8>(2, std::get<uint8>(value)));
        RecomputeTokenPositions();
        return true;
    case PropertyID::ViewWidth:
        this->settings->maxWidth = std::min<>(2000U, std::max<>(8U, std::get<uint32>(value)));
        Parse();
        return true;
    case PropertyID::ShowPluginListKey:
        this->config.Keys.showPlugins = std::get<Input::Key>(value);
        return true;
    case PropertyID::SaveAsKey:
        this->config.Keys.saveAs = std::get<Input::Key>(value);
        return true;
    case PropertyID::ShowMetaDataKey:
        this->config.Keys.showMetaData = std::get<Input::Key>(value);
        return true;
    case PropertyID::ChangeSelectionTypeKey:
        this->config.Keys.changeSelectionType = std::get<Input::Key>(value);
        return true;
    case PropertyID::FoldAllKey:
        this->config.Keys.foldAll = std::get<Input::Key>(value);
        return true;
    case PropertyID::ExpandAllKey:
        this->config.Keys.expandAll = std::get<Input::Key>(value);
        return true;
    case PropertyID::Pretty:
        this->prettyFormat = std::get<bool>(value);
        Parse();
        return true;
    case PropertyID::ShowMetaData:
        this->showMetaData = std::get<bool>(value);
        RecomputeTokenPositions();
        return true;
    }
    error.SetFormat("Unknown internal ID: %u", id);
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    switch (static_cast<PropertyID>(propertyID))
    {
    case PropertyID::NoOfTokens:
    case PropertyID::NoOfLines:
    case PropertyID::NoOfBlocks:
        return true;
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { BT(PropertyID::IndentWidth), "Sizes", "Indent with", PropertyType::UInt8 },
        { BT(PropertyID::ViewWidth), "Sizes", "View width", PropertyType::UInt32 },
        // shortcuts
        { BT(PropertyID::ShowPluginListKey), "Shortcuts", "Show plugin list", PropertyType::Key },
        { BT(PropertyID::SaveAsKey), "Shortcuts", "SaveAs", PropertyType::Key },
        { BT(PropertyID::ShowMetaDataKey), "Shortcuts", "Show/Hide metadata", PropertyType::Key },
        { BT(PropertyID::ChangeSelectionTypeKey), "Shortcuts", "Change selection", PropertyType::Key },
        { BT(PropertyID::FoldAllKey), "Shortcuts", "Fold all", PropertyType::Key },
        { BT(PropertyID::ExpandAllKey), "Shortcuts", "ExpandAll", PropertyType::Key },
        // General
        { BT(PropertyID::NoOfTokens), "General", "Tokens count", PropertyType::UInt32 },
        { BT(PropertyID::NoOfBlocks), "General", "Blocks count", PropertyType::UInt32 },
        { BT(PropertyID::NoOfLines), "General", "Lines count", PropertyType::UInt32 },
        // View
        { BT(PropertyID::Pretty), "View", "Auto format text", PropertyType::Boolean },
        { BT(PropertyID::ShowMetaData), "View", "Show/Hide metadate", PropertyType::Boolean },
    };
}
#undef BT
