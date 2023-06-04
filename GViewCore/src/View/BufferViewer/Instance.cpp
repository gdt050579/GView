#include "BufferViewer.hpp"

#include <algorithm>

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

const char hexCharsList[]              = "0123456789ABCDEF";
const uint32 characterFormatModeSize[] = { 2 /*Hex*/, 3 /*Oct*/, 4 /*signed 8*/, 3 /*unsigned 8*/ };
const std::string_view hex_header      = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F ";
const std::string_view oct_header =
      "000 001 002 003 004 005 006 007 010 011 012 013 014 015 016 017 020 021 022 023 024 025 026 027 030 031 032 033 034 035 036 037 ";
const std::string_view signed_dec_header = "  +0   +1   +2   +3   +4   +5   +6   +7   +8   +9  +10  +11  +12  +13  +14  +15  +16  +17  +18 "
                                           " +19  +20  +21  +22  +23  +24  +25  +26  +27  +28  +29  +30  +31  ";
const std::string_view unsigned_dec_header =
      " +0  +1  +2  +3  +4  +5  +6  +7  +8  +9 +10 +11 +12 +13 +14 +15 +16 +17 +18 +19 +20 +21 +22 +23 +24 +25 +26 +27 +28 +29 +30 +31 ";

bool DefaultAsciiMask[256] = {
    false, false, false, false, false, false, false, false, false, true,  false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  false, true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false
};

constexpr int BUFFERVIEW_CMD_CHANGECOL         = 0xBF00;
constexpr int BUFFERVIEW_CMD_CHANGEBASE        = 0xBF01;
constexpr int BUFFERVIEW_CMD_CHANGEADDRESSMODE = 0xBF02;
constexpr int BUFFERVIEW_CMD_GOTOEP            = 0xBF03;
constexpr int BUFFERVIEW_CMD_CHANGECODEPAGE    = 0xBF04;
constexpr int BUFFERVIEW_CMD_CHANGESELECTION   = 0xBF05;
constexpr int BUFFERVIEW_CMD_HIDESTRINGS       = 0xBF06;
constexpr int BUFFERVIEW_CMD_FINDNEXT          = 0xBF07;
constexpr int BUFFERVIEW_CMD_FINDPREVIOUS      = 0xBF08;
constexpr int BUFFERVIEW_CMD_DISSASM_DIALOG    = 0xBF09;
/*
    constexpr int32 VIEW_COMMAND_ACTIVATE_COMPARE{ 0xBF10 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_COMPARE{ 0xBF11 };
    constexpr int32 VIEW_COMMAND_ACTIVATE_SYNC{ 0xBF12 };
    constexpr int32 VIEW_COMMAND_DEACTIVATE_SYNC{ 0xBF13 };
*/

Config Instance::config;

Instance::Instance(Reference<GView::Object> _obj, Settings* _settings)
    : obj(_obj), settings(nullptr), ViewControl("Buffer View", UserControlFlags::ShowVerticalScrollBar | UserControlFlags::ScrollBarOutsideControl)
{
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::Transparent });

    memcpy(this->StringInfo.AsciiMask, DefaultAsciiMask, 256);

    this->bufColor.Reset();
    this->ResetStringInfo();

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
}

bool Instance::SetOnStartViewMoveCallback(Reference<OnStartViewMoveInterface> cbk)
{
    this->settings->onStartViewMoveCallback = cbk;
    return true;
}

bool Instance::SetBufferColorProcessorCallback(Reference<BufferColorInterface> cbk)
{
    this->settings->bufferColorCallback = cbk;
    return true;
}

bool Instance::GetViewData(ViewData& vd, uint64 offset)
{
    vd.viewStartOffset   = cursor.GetStartView();
    vd.viewSize          = static_cast<uint64>(Layout.charactersPerLine) * Layout.visibleRows;
    vd.cursorStartOffset = cursor.GetCurrentPosition();

    if (offset != GView::Utils::INVALID_OFFSET)
    {
        const auto b = this->GetObject()->GetData().Get(offset, 1, true);
        CHECK(b.IsValid(), false, "");
        vd.byte = b.GetData()[0];
    }
    else
    {
        vd.byte = 0;
    }

    return true;
}

bool Instance::AdvanceStartView(int64 offset)
{
    if (offset < 0)
    {
        if (static_cast<uint64>(abs(offset)) > cursor.GetStartView())
        {
            offset = -1ll * cursor.GetStartView();
        }
    }

    const auto newStartView = std::clamp<uint64>(cursor.GetStartView() + offset, 0ull, this->GetObject()->GetData().GetSize() - 1ull);
    cursor.SetCurrentPosition(newStartView);
    cursor.SetStartView(newStartView);

    return true;
}

void Instance::OpenCurrentSelection()
{
    uint64 start, end;
    auto res = this->selection.OffsetToSelection(this->cursor.GetCurrentPosition(), start, end);
    if (res >= 0)
    {
        LocalString<128> temp;
        temp.Format("Buffer_%llx_%llx", start, end);
        auto buf = this->obj->GetData().CopyToBuffer(start, (uint32) (end - start + 1));
        if (buf.IsValid() == false)
        {
            Dialogs::MessageBox::ShowError("Error", "Fail to read content to buffer");
            return;
        }

        LocalUnicodeStringBuilder<2048> fullPath;
        fullPath.Add(this->obj->GetPath());
        fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
        fullPath.Add(temp);

        GView::App::OpenBuffer(buf, temp, fullPath, GView::App::OpenMethod::Select);
    }
}
void Instance::UpdateCurrentSelection()
{
    this->CurrentSelection.size  = 0;
    this->CurrentSelection.start = GView::Utils::INVALID_OFFSET;
    this->CurrentSelection.end   = GView::Utils::INVALID_OFFSET;

    if (this->selection.IsSingleSelectionEnabled())
    {
        uint64 start, end;
        if ((this->selection.GetSelection(0, start, end)))
        {
            if ((end - start) < 254)
            {
                this->CurrentSelection.size = ((uint32) (end - start)) + 1;
                auto b                      = obj->GetData().Get(start, this->CurrentSelection.size, true);
                if (b.IsValid())
                {
                    memcpy(this->CurrentSelection.buffer, b.begin(), b.GetLength());
                }
                else
                {
                    this->CurrentSelection.size = 0;
                }
            }
        }
    }
}
void Instance::MoveTo(uint64 offset, bool select)
{
    if (obj->GetData().GetSize() == 0)
        return;

    if (offset > (obj->GetData().GetSize() - 1))
        offset = obj->GetData().GetSize() - 1;

    if (offset == cursor.GetCurrentPosition())
    {
        cursor.SetStartView(offset);
        return;
    }

    auto sidx     = (!select) ? (-1) : selection.BeginSelection(cursor.GetCurrentPosition());
    const auto sz = Layout.charactersPerLine * Layout.visibleRows;
    if ((offset >= cursor.GetStartView()) && (offset < cursor.GetStartView() + sz))
    {
        cursor.SetCurrentPosition(offset);
        if (select && sidx >= 0)
        {
            selection.UpdateSelection(sidx, offset);
            UpdateCurrentSelection();
            return; // nothing to do ... already in visual space
        }
    }

    const auto& startView = cursor.GetStartView();
    if (offset < startView)
    {
        cursor.SetStartView(offset);
    }
    else
    {
        const auto delta = cursor.GetCurrentPosition() - startView;
        if (offset >= delta)
        {
            if (offset - delta != startView)
            {
                cursor.SetStartView(offset - delta);
            }
        }
        else
        {
            cursor.SetStartView(0);
        }
    }

    cursor.SetCurrentPosition(offset);
    if (select && sidx >= 0)
    {
        selection.UpdateSelection(sidx, offset);
        UpdateCurrentSelection();
    }

    if (moveInSync && settings && settings->onStartViewMoveCallback)
    {
        if (cursor.GetDeltaStartView() != 0)
        {
            settings->onStartViewMoveCallback->GenerateActionOnMove(
                  this,
                  cursor.GetDeltaStartView(),
                  ViewData{ .viewStartOffset   = cursor.GetStartView(),
                            .viewSize          = static_cast<uint64>(Layout.charactersPerLine) * Layout.visibleRows,
                            .cursorStartOffset = cursor.GetCurrentPosition(),
                            .byte              = 0 });
        }
    }

    cursor.SetStartView(cursor.GetStartView()); // invalidate delta
}
void Instance::MoveScrollTo(uint64 offset)
{
    if (obj->GetData().GetSize() == 0)
        return;

    if (offset > (obj->GetData().GetSize() - 1))
        offset = obj->GetData().GetSize() - 1;

    const auto previous = cursor.GetStartView();
    cursor.SetStartView(offset);
    if (cursor.GetStartView() > previous)
    {
        MoveTo(cursor.GetCurrentPosition() + (cursor.GetStartView() - previous), false);
    }
    else
    {
        auto delta = previous - cursor.GetStartView();
        if (delta <= cursor.GetCurrentPosition() && delta != 0)
        {
            MoveTo(cursor.GetCurrentPosition() - delta, false);
        }
        else
        {
            MoveTo(0, false);
        }
    }
}
void Instance::MoveToSelection(uint32 selIndex)
{
    uint64 start, end;

    if (this->selection.GetSelection(selIndex, start, end))
    {
        if (this->cursor.GetCurrentPosition() != start)
            MoveTo(start, false);
        else
            MoveTo(end, false);
    }
}
void Instance::SkipCurentCaracter(bool selected)
{
    uint64 tr, fileSize;
    uint32 gr;

    auto buf = this->obj->GetData().Get(this->cursor.GetCurrentPosition(), 1, true);

    if (!buf.IsValid())
        return;
    auto toSkip = *buf.GetData();

    fileSize = this->obj->GetData().GetSize();
    for (tr = this->cursor.GetCurrentPosition(); tr < fileSize;)
    {
        auto buf = this->obj->GetData().Get(tr, 256, false);
        if (!buf.IsValid())
            break;
        for (gr = 0; gr < buf.GetLength(); gr++, tr++)
            if (buf[gr] != toSkip)
                break;
        if (gr < buf.GetLength())
            break;
    }
    MoveTo(tr, selected);
}
void Instance::MoveTillNextBlock(bool select, int dir)
{
    // GView::Objects::FileZones* zone;
    // switch (File->ColorMode)
    //{
    // case GView::Constants::COLORMODE_OBJECTS:
    //    zone = &File->Zones.Objects;
    //    break;
    // case GView::Constants::COLORMODE_TYPE:
    //    zone = &InitData->TypeZones;
    //    break;
    // default:
    //    return;
    //};
    // uint32 count = zone->GetCount();
    // const GView::Objects::FileZone* z;
    // if (dir == 1)
    //{
    //    for (uint32 tr = 0; tr < count; tr++)
    //    {
    //        z = zone->Get(tr);
    //        if (z->Start > this->Cursor.currentPos)
    //        {
    //            MoveTo(z->Start, select);
    //            return;
    //        }
    //    }
    //}
    // else
    //{
    //    for (int tr = ((int) count) - 1; tr >= 0; tr--)
    //    {
    //        z = zone->Get(tr);
    //        if (z->End < this->Cursor.currentPos)
    //        {
    //            MoveTo(z->Start, select);
    //            return;
    //        }
    //    }
    //}
}
void Instance::MoveTillEndBlock(bool selected)
{
    uint64 tr, fileSize;
    uint32 lastValue = 0xFFFFFFFF;
    uint32 count     = 0;

    fileSize = this->obj->GetData().GetSize();

    for (tr = this->cursor.GetCurrentPosition(); tr < fileSize;)
    {
        auto buf = this->obj->GetData().Get(tr, 4096, false);
        if (!buf.IsValid())
            break;
        auto* s = buf.begin();
        auto* e = buf.end();
        while (s < e)
        {
            if ((*s) == lastValue)
            {
                count++;
                if (count == 16)
                    break;
            }
            else
            {
                count     = 1;
                lastValue = *s;
            }
            s++;
        }
        tr += (s - buf.begin());
        if (count == 16)
        {
            tr -= 16;
            break;
        }
    }
    MoveTo(tr, selected);
}
void Instance::MoveToZone(bool startOfZone, bool select)
{
    if (auto z = settings->zList.OffsetToZone(this->cursor.GetCurrentPosition()))
    {
        MoveTo(startOfZone ? z->interval.low : z->interval.high, select);
    }
}

bool Instance::ShowGoToDialog()
{
    GoToDialog dlg(settings.get(), this->cursor.GetCurrentPosition(), this->obj->GetData().GetSize());
    if (dlg.Show() == Dialogs::Result::Ok)
    {
        MoveTo(dlg.GetResultedPos(), false);
    }
    return true;
}
bool Instance::ShowFindDialog()
{
    findDialog.UpdateData(this->cursor.GetCurrentPosition(), this->obj);
    CHECK(findDialog.Show() == Dialogs::Result::Ok, true, "");

    const auto [start, length] = findDialog.GetNextMatch(this->cursor.GetCurrentPosition());
    if (start != GView::Utils::INVALID_OFFSET && length != GView::Utils::INVALID_OFFSET)
    {
        if (findDialog.AlignToUpperRightCorner())
        {
            MoveScrollTo(start);
        }
        else
        {
            MoveTo(start, false);
        }

        if (findDialog.SelectMatch())
        {
            this->selection.Clear();
            this->selection.BeginSelection(start);
            this->selection.UpdateSelection(0, start + length - 1);
            UpdateCurrentSelection();
        }
    }
    else
    {
        Dialogs::MessageBox::ShowError("Error!", "Pattern not found!");
    }

    return true;
}
bool Instance::ShowCopyDialog()
{
    CopyDialog dlg(this);
    CHECK(dlg.Show() == Dialogs::Result::Ok, true, "");

    return true;
}

bool Instance::ShowDissasmDialog()
{
    DissasmDialog dlg(this);
    CHECK(dlg.Show() == Dialogs::Result::Ok, false, "");
    return true;
}

void Instance::ResetStringInfo()
{
    StringInfo.start  = GView::Utils::INVALID_OFFSET;
    StringInfo.end    = GView::Utils::INVALID_OFFSET;
    StringInfo.middle = GView::Utils::INVALID_OFFSET;
    StringInfo.type   = StringType::None;
}
void Instance::UpdateStringInfo(uint64 offset)
{
    auto buf = this->obj->GetData().Get(offset, 1024, false);
    if (!buf.IsValid())
    {
        ResetStringInfo();
        return;
    }

    // check for ascii
    if (this->StringInfo.showAscii)
    {
        auto* s = buf.GetData();
        auto* e = s + buf.GetLength();

        if (StringInfo.AsciiMask[*s])
        {
            while ((s < e) && (StringInfo.AsciiMask[*s]))
                s++;
            if (s - buf.GetData() >= StringInfo.minCount)
            {
                // ascii string found
                StringInfo.start = offset;
                StringInfo.end   = offset + (s - buf.GetData());
                StringInfo.type  = StringType::Ascii;
                return;
            }
        }
    }

    // check for unicode
    if (this->StringInfo.showUnicode)
    {
        auto* s = (char16*) buf.GetData();
        auto* e = s + buf.GetLength() / 2;
        if ((s < e) && ((*s) < 256) && (StringInfo.AsciiMask[*s]))
        {
            while ((s < e) && ((*s) < 256) && (StringInfo.AsciiMask[*s]))
                s++;
            if (s - (char16*) buf.GetData() >= StringInfo.minCount)
            {
                // ascii string found
                StringInfo.start  = offset;
                StringInfo.end    = offset + ((const uint8*) s - buf.GetData());
                StringInfo.middle = offset + (s - (char16*) buf.GetData());
                StringInfo.type   = StringType::Unicode;
                return;
            }
        }
    }

    // compute the size of non-string data
    StringInfo.start  = offset;
    StringInfo.middle = GView::Utils::INVALID_OFFSET;
    StringInfo.type   = StringType::None;

    {
        auto* s = buf.GetData();
        auto* e = s + buf.GetLength();

        while (s < e)
        {
            while ((s < e) && (!StringInfo.AsciiMask[*s]))
                s++;
            if (s == e)
                break;
            // reached a possible string --> check for minim size
            auto* s_s = s;
            auto* s_e = s + StringInfo.minCount;
            if (s_e <= e)
            {
                while ((s_s < s_e) && (StringInfo.AsciiMask[*s_s]))
                    s_s++;
                if (s_s == s_e)
                {
                    // found a possible string at 's' position --> stop before 's'
                    StringInfo.end = offset + (s - buf.GetData());
                    return;
                }
            }
            // check if not an unicode string
            auto* u_s = (char16_t*) s;
            auto* u_e = u_s + StringInfo.minCount;
            if ((((const uint8*) u_e) + 1) <= e)
            {
                while ((u_s < u_e) && (*u_s < 256) && (StringInfo.AsciiMask[*u_s]))
                    u_s++;
                if (u_s == u_e)
                {
                    // found a possible unicode at 's' position --> stop before 's'
                    StringInfo.end = offset + (s - buf.GetData());
                    return;
                }
            }
            // no possible string found --> advance to next non_ascii character
            if (s_s > s)
                s = s_s;
            else
                s++; // move to next
        }
    }
    // all buffer was process and nothing was found
    StringInfo.end = offset + buf.GetLength();
}
std::string_view Instance::GetAsciiMaskStringRepresentation()
{
    GView::Utils::CharacterSet cSet(this->StringInfo.AsciiMask);
    this->StringInfo.asciiMaskRepr.Clear();
    if (cSet.GetStringRepresentation(this->StringInfo.asciiMaskRepr))
        return this->StringInfo.asciiMaskRepr.ToStringView();
    return "";
}
bool Instance::SetStringAsciiMask(string_view stringRepresentation)
{
    GView::Utils::CharacterSet cSet;
    cSet.ClearAll();
    if (cSet.Set(stringRepresentation, true))
    {
        cSet.CopySetTo(this->StringInfo.AsciiMask);
        return true;
    }
    return false;
}

ColorPair Instance::OffsetToColorZone(uint64 offset)
{
    if (auto z = this->settings->zList.OffsetToZone(offset))
        return z->color;

    return Cfg.Text.Inactive;
}
ColorPair Instance::OffsetToColor(uint64 offset)
{
    // current selection
    if ((this->CurrentSelection.size) && (this->CurrentSelection.highlight))
    {
        if ((offset >= this->CurrentSelection.start) && (offset < this->CurrentSelection.end))
            return Cfg.Selection.SimilarText;

        auto b = this->obj->GetData().Get(offset, this->CurrentSelection.size, true);
        if (b.IsValid())
        {
            if (b[0] == this->CurrentSelection.buffer[0])
            {
                if (memcmp(b.begin(), this->CurrentSelection.buffer, this->CurrentSelection.size) == 0)
                {
                    this->CurrentSelection.start = offset;
                    this->CurrentSelection.end   = offset + this->CurrentSelection.size;
                    return Cfg.Selection.SimilarText;
                }
            }
        }
    }

    // color
    if (settings)
    {
        if (showSyncCompare && settings->bufferColorCallback)
        {
            if ((offset >= bufColor.start) && (offset <= bufColor.end))
                return bufColor.color;

            if (cursor.GetStartView() <= offset)
            {
                auto b = this->obj->GetData().Get(offset, 1, true);
                if (b.IsValid())
                {
                    if (settings->bufferColorCallback->GetColorForByteAt(
                              offset,
                              ViewData{ .viewStartOffset   = cursor.GetStartView(),
                                        .viewSize          = static_cast<uint64>(Layout.charactersPerLine) * Layout.visibleRows,
                                        .cursorStartOffset = cursor.GetCurrentPosition(),
                                        .byte              = b.GetData()[0] },
                              bufColor.color))
                    {
                        bufColor.start = offset;
                        bufColor.end   = offset;
                        return bufColor.color;
                    }
                }
            }
            // no color provided for the specific buffer --> check show types
        }

        if (showTypeObjects && settings->positionToColorCallback)
        {
            if ((offset >= bufColor.start) && (offset <= bufColor.end))
                return bufColor.color;
            if (settings->positionToColorCallback->GetColorForBuffer(offset, this->obj->GetData().Get(offset, 16, false), bufColor))
                return bufColor.color;

            // no color provided for the specific buffer --> check strings and zones
        }
    }

    // check strings
    if (this->StringInfo.showAscii || this->StringInfo.showUnicode)
    {
        if ((offset >= StringInfo.start) && (offset < StringInfo.end))
        {
            switch (StringInfo.type)
            {
            case StringType::Ascii:
                return config.Colors.Ascii;
            case StringType::Unicode:
                return config.Colors.Unicode;
            }
        }
        else
        {
            UpdateStringInfo(offset);
            if ((offset >= StringInfo.start) && (offset < StringInfo.end))
            {
                switch (StringInfo.type)
                {
                case StringType::Ascii:
                    return config.Colors.Ascii;
                case StringType::Unicode:
                    return config.Colors.Unicode;
                }
            }
        }
    }

    // not a string --> check the zone
    return OffsetToColorZone(offset);
}

void Instance::UpdateViewSizes()
{
    // need to recompute all offsets lineAddressSize
    auto sz            = this->Layout.lineNameSize;
    this->Layout.xName = 0;

    if (this->Layout.lineAddressSize > 0)
    {
        this->Layout.xAddress = sz;
        if (sz > 0)
        {
            sz += this->Layout.lineAddressSize + 1; // one extra space
            this->Layout.xAddress++;
        }
        else
            sz += this->Layout.lineAddressSize;
    }

    if (sz > 0)
        sz += 3; // 3 extra spaces between offset (address) and characters
    this->Layout.xNumbers = sz;
    if (this->Layout.nrCols == 0)
    {
        this->Layout.xText = sz;
        // full screen --> ascii only
        auto width = (uint32) this->GetWidth();
        if (sz + 1 < width)
            this->Layout.charactersPerLine = width - (1 + sz);
        else
            this->Layout.charactersPerLine = 1;
    }
    else
    {
        this->Layout.xText             = sz + this->Layout.nrCols * (characterFormatModeSize[(uint32) this->Layout.charFormatMode] + 1) + 3;
        this->Layout.charactersPerLine = this->Layout.nrCols;
    }
    // compute visible rows
    this->Layout.visibleRows = this->GetHeight();
    if (this->Layout.visibleRows > 0)
        this->Layout.visibleRows--;
    if (this->Layout.visibleRows == 0)
        this->Layout.visibleRows = 1;
}
void Instance::PrepareDrawLineInfo(DrawLineInfo& dli)
{
    if (dli.recomputeOffsets)
    {
        // need to recompute all offsets
        dli.offsetAndNameSize = this->Layout.lineAddressSize;
        if (this->Layout.lineNameSize > 0)
        {
            if (dli.offsetAndNameSize > 0)
                dli.offsetAndNameSize += this->Layout.lineNameSize + 1; // one extra space
            else
                dli.offsetAndNameSize += this->Layout.lineNameSize;
        }
        if (dli.offsetAndNameSize > 0)
            dli.offsetAndNameSize += 3; // 3 extra spaces between offset (address) and characters
        if (this->Layout.nrCols == 0)
        {
            // full screen --> ascii only
            auto width      = (uint32) this->GetWidth();
            dli.numbersSize = 0;
            if (dli.offsetAndNameSize + 1 < width)
                dli.textSize = width - (1 + dli.offsetAndNameSize);
            else
                dli.textSize = 0;
        }
        else
        {
            auto sz         = characterFormatModeSize[(uint32) this->Layout.charFormatMode];
            dli.numbersSize = this->Layout.nrCols * (sz + 1) + 3; // one extra space between chrars + 3 spaces at the end
            dli.textSize    = this->Layout.nrCols;
        }
        // make sure that we have enough buffer
        this->chars.Resize(dli.offsetAndNameSize + dli.textSize + dli.numbersSize);
        dli.recomputeOffsets = false;
    }
    auto buf          = this->obj->GetData().Get(dli.offset, dli.textSize, false);
    dli.start         = buf.GetData();
    dli.end           = buf.GetData() + buf.GetLength();
    dli.chNameAndSize = this->chars.GetBuffer();
    dli.chText        = dli.chNameAndSize + (dli.offsetAndNameSize + dli.numbersSize);
    dli.chNumbers     = dli.chNameAndSize + dli.offsetAndNameSize;
}
void Instance::WriteHeaders(Renderer& renderer)
{
    WriteTextParams params(WriteTextFlags::OverwriteColors | WriteTextFlags::SingleLine | WriteTextFlags::ClipToWidth);
    params.Align = TextAlignament::Left;
    params.Y     = 0;
    params.Color = this->HasFocus() ? Cfg.Header.Text.Focused : Cfg.Header.Text.Normal;

    renderer.FillHorizontalLine(0, 0, this->GetWidth(), ' ', params.Color);

    if (this->Layout.lineNameSize > 0)
    {
        params.X     = this->Layout.xName;
        params.Width = this->Layout.lineNameSize;
        renderer.WriteText("Name", params);
    }
    if (this->Layout.lineAddressSize > 0)
    {
        params.X     = this->Layout.xAddress;
        params.Width = this->Layout.lineAddressSize;
        if (this->settings->translationMethodsCount == 0)
            renderer.WriteText("Address", params);
        else
            renderer.WriteText(this->settings->translationMethods[this->currentAdrressMode].name.GetText(), params);
    }
    if (this->Layout.nrCols != 0)
    {
        params.X     = this->Layout.xNumbers;
        params.Width = this->Layout.xText - (this->Layout.xNumbers + 3);
        switch (this->Layout.charFormatMode)
        {
        case CharacterFormatMode::Hex:
            renderer.WriteText(hex_header, params);
            break;
        case CharacterFormatMode::Octal:
            renderer.WriteText(oct_header, params);
            break;
        case CharacterFormatMode::SignedDecimal:
            renderer.WriteText(signed_dec_header, params);
            break;
        case CharacterFormatMode::UnsignedDecimal:
            renderer.WriteText(unsigned_dec_header, params);
            break;
        }
    }
    params.X     = this->Layout.xText;
    params.Width = this->Layout.charactersPerLine;
    renderer.WriteText("Text", params);
}
void Instance::WriteLineAddress(DrawLineInfo& dli)
{
    uint64 ofs = dli.offset;
    auto c     = Cfg.Text.Inactive;
    auto n     = dli.chNameAndSize;

    if (HasFocus())
    {
        c = OffsetToColorZone(dli.offset);
    }

    if (this->Layout.lineNameSize > 0)
    {
        auto e             = n + this->Layout.lineNameSize;
        const char* nm     = nullptr;
        const char* nm_end = nullptr;

        if (auto z = this->settings->zList.OffsetToZone(dli.offset))
        {
            nm     = z->name.GetText();
            nm_end = nm + z->name.Len();
        }
        else
        {
            nm     = "--------------------------------------------------------------------------------------------------------------";
            nm_end = nm + 100;
        }

        while (n < e)
        {
            if (nm < nm_end)
                n->Code = *nm;
            else
                n->Code = ' ';
            n->Color = c;
            n++;
            nm++;
        }
        n->Code  = ' ';
        n->Color = c;
        n++;
    }

    if (this->Layout.lineAddressSize > 0)
    {
        auto prev_n = n;
        auto s      = n + this->Layout.lineAddressSize - 1;
        n           = s + 1;

        if ((settings) && (settings->translationMethodsCount > 0) && (this->currentAdrressMode > 0))
        {
            ofs = settings->offsetTranslateCallback->TranslateFromFileOffset(ofs, this->currentAdrressMode);
        }

        if (ofs == GView::Utils::INVALID_OFFSET)
        {
            while (s >= prev_n)
            {
                s->Code  = '-';
                s->Color = Cfg.Text.Inactive;
                s--;
            }
        }
        else
        {
            // hex
            while (s >= prev_n)
            {
                s->Code  = hexCharsList[ofs & 0xF];
                s->Color = c;
                ofs >>= 4;
                s--;
            }
            if ((ofs > 0) && (this->Layout.lineAddressSize >= 3))
            {
                // value is to large --> add some points
                s        = prev_n;
                s->Code  = '.';
                s->Color = c;
                s++;
                s->Code  = '.';
                s->Color = c;
            }
        }
    }

    // clear space
    while (n < dli.chNumbers)
    {
        n->Code  = ' ';
        n->Color = c;
        n++;
    }
}
void Instance::WriteLineTextToChars(DrawLineInfo& dli)
{
    auto cp    = Cfg.Text.Inactive;
    bool activ = this->HasFocus();

    if (activ)
    {
        const auto startCh  = dli.chText;
        const auto ofsStart = dli.offset;
        while (dli.start < dli.end)
        {
            cp = OffsetToColor(dli.offset);
            if (selection.Contains(dli.offset))
                cp = Cfg.Selection.Editor;
            if (StringInfo.type == StringType::Unicode)
            {
                if (dli.offset > StringInfo.middle)
                    dli.chText->Code = ' ';
                else
                    dli.chText->Code = codePage[obj->GetData().GetFromCache(((dli.offset - StringInfo.start) << 1) + StringInfo.start)];
            }
            else
            {
                dli.chText->Code = codePage[*dli.start];
            }
            dli.chText->Color = cp;
            dli.chText++;
            dli.start++;
            dli.offset++;
        }
        if ((this->cursor.GetCurrentPosition() >= ofsStart) && (this->cursor.GetCurrentPosition() < dli.offset))
        {
            (startCh + (this->cursor.GetCurrentPosition() - ofsStart))->Color = Cfg.Cursor.Normal;
        }
    }
    else
    {
        while (dli.start < dli.end)
        {
            dli.chText->Code  = codePage[*dli.start];
            dli.chText->Color = Cfg.Text.Inactive;
            dli.chText++;
            dli.start++;
        }
    }
    this->chars.Resize((uint32) (dli.chText - this->chars.GetBuffer()));
}
void Instance::WriteLineNumbersToChars(DrawLineInfo& dli)
{
    auto c     = dli.chNumbers;
    auto cp    = Cfg.Text.Inactive;
    bool activ = this->HasFocus();
    auto ut    = (uint8) 0;
    auto sps   = dli.chText;
    auto start = dli.offset;
    auto end   = start + (dli.end - dli.start);

    while (dli.start < dli.end)
    {
        if (activ)
        {
            cp = OffsetToColor(dli.offset);

            if (selection.Contains(dli.offset))
            {
                cp = Cfg.Selection.Editor;
                if (c > this->chars.GetBuffer())
                    (c - 1)->Color = cp;
            }
        }
        switch (this->Layout.charFormatMode)
        {
        case CharacterFormatMode::Hex:
            c->Code  = hexCharsList[(*dli.start) >> 4];
            c->Color = cp;
            c++;
            c->Code  = hexCharsList[(*dli.start) & 0x0F];
            c->Color = cp;
            c++;
            break;
        case CharacterFormatMode::Octal:
            c->Code  = '0' + ((*dli.start) >> 6);
            c->Color = cp;
            c++;
            c->Code  = '0' + (((*dli.start) >> 3) & 0x7);
            c->Color = cp;
            c++;
            c->Code  = '0' + ((*dli.start) & 0x7);
            c->Color = cp;
            c++;
            break;
        case CharacterFormatMode::UnsignedDecimal:
            if ((*dli.start) < 10)
            {
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = '0' + *dli.start;
                c->Color = cp;
                c++;
            }
            else if ((*dli.start) < 100)
            {
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = '0' + ((*dli.start) / 10);
                c->Color = cp;
                c++;
                c->Code  = '0' + ((*dli.start) % 10);
                c->Color = cp;
                c++;
            }
            else
            {
                ut       = *dli.start;
                c->Code  = '0' + (ut / 100);
                c->Color = cp;
                c++;
                ut       = ut % 100;
                c->Code  = '0' + (ut / 10);
                c->Color = cp;
                c++;
                ut       = ut % 10;
                c->Code  = '0' + ut;
                c->Color = cp;
                c++;
            }
            break;
        case CharacterFormatMode::SignedDecimal:
            int tmp   = *(const char*) dli.start;
            char sign = '+';
            if (tmp < 0)
            {
                sign = '-';
                tmp  = -tmp;
            }
            if (tmp == 0)
                sign = ' ';
            if (tmp < 10)
            {
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = sign;
                c->Color = cp;
                c++;
                c->Code  = '0' + tmp;
                c->Color = cp;
                c++;
            }
            else if (tmp < 100)
            {
                c->Code  = ' ';
                c->Color = cp;
                c++;
                c->Code  = sign;
                c->Color = cp;
                c++;
                c->Code  = '0' + (tmp / 10);
                c->Color = cp;
                c++;
                c->Code  = '0' + (tmp % 10);
                c->Color = cp;
                c++;
            }
            else
            {
                c->Code  = sign;
                c->Color = cp;
                c++;
                c->Code  = '0' + (tmp / 100);
                c->Color = cp;
                c++;
                tmp      = tmp % 100;
                c->Code  = '0' + (tmp / 10);
                c->Color = cp;
                c++;
                tmp      = tmp % 10;
                c->Code  = '0' + tmp;
                c->Color = cp;
                c++;
            }
            break;
        }
        // number columns separators
        c->Code  = ' ';
        c->Color = cp;
        c++;

        if (activ)
        {
            if (StringInfo.type == StringType::Unicode)
            {
                if (dli.offset > StringInfo.middle)
                    dli.chText->Code = ' ';
                else
                    dli.chText->Code = codePage[obj->GetData().GetFromCache(((dli.offset - StringInfo.start) << 1) + StringInfo.start)];
            }
            else
            {
                dli.chText->Code = codePage[*dli.start];
            }
        }
        else
        {
            dli.chText->Code = codePage[*dli.start];
        }

        dli.chText->Color = cp;
        dli.chText++;
        dli.start++;
        dli.offset++;
    }
    // clear space until text column
    while (c < sps)
    {
        c->Code  = ' ';
        c->Color = Cfg.Text.Inactive;
        c++;
    }
    if ((activ) && (this->cursor.GetCurrentPosition() >= start) && (this->cursor.GetCurrentPosition() < end))
    {
        const auto reprsz = characterFormatModeSize[static_cast<uint32>(this->Layout.charFormatMode)] + 1;
        c                 = dli.chNumbers + (this->cursor.GetCurrentPosition() - start) * reprsz;
        const auto st     = this->chars.GetBuffer();
        const auto c_e    = std::min<>(c + reprsz, sps);
        c                 = std::max<>(c - 1, st);
        while (c < c_e)
        {
            c->Color = Cfg.Cursor.Normal;
            c++;
        }
        c = sps + (this->cursor.GetCurrentPosition() - start);
        if ((c >= st) && (c < dli.chText))
            c->Color = Cfg.Cursor.Normal;
    }
    this->chars.Resize((uint32) (dli.chText - this->chars.GetBuffer()));
}
void Instance::Paint(Renderer& renderer)
{
    renderer.Clear();
    WriteHeaders(renderer);

    const auto& startView = cursor.GetStartView();
    settings->zList.SetCache({ startView, ((uint64) Layout.charactersPerLine) * (Layout.visibleRows - 1ull) + startView });

    DrawLineInfo dli;
    for (uint32 tr = 0; tr < Layout.visibleRows; tr++)
    {
        dli.offset = ((uint64) Layout.charactersPerLine) * tr + startView;
        if (dli.offset >= obj->GetData().GetSize())
            break;
        PrepareDrawLineInfo(dli);
        WriteLineAddress(dli);
        if (Layout.nrCols == 0)
            WriteLineTextToChars(dli);
        else
            WriteLineNumbersToChars(dli);
        renderer.WriteSingleLineCharacterBuffer(0, tr + 1, chars, false);
    }
}
void Instance::OnAfterResize(int width, int height)
{
    this->UpdateViewSizes();
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    // columns
    switch (this->Layout.nrCols)
    {
    case 0:
        commandBar.SetCommand(config.Keys.ChangeColumnsNumber, "Cols:FullScr", BUFFERVIEW_CMD_CHANGECOL);
        break;
    case 8:
        commandBar.SetCommand(config.Keys.ChangeColumnsNumber, "Cols:8", BUFFERVIEW_CMD_CHANGECOL);
        break;
    case 16:
        commandBar.SetCommand(config.Keys.ChangeColumnsNumber, "Cols:16", BUFFERVIEW_CMD_CHANGECOL);
        break;
    case 32:
        commandBar.SetCommand(config.Keys.ChangeColumnsNumber, "Cols:32", BUFFERVIEW_CMD_CHANGECOL);
        break;
    default:
        commandBar.SetCommand(config.Keys.ChangeColumnsNumber, "Change Cols", BUFFERVIEW_CMD_CHANGECOL);
        break;
    }

    // Value format & codepage
    if (this->Layout.nrCols == 0)
    {
        LocalString<64> tmp;
        commandBar.SetCommand(
              config.Keys.ChangeValueFormatOrCP, tmp.Format("CP:%s", CodePage::GetCodePageName(this->codePage).data()), BUFFERVIEW_CMD_CHANGECODEPAGE);
    }
    else
    {
        switch (this->Layout.charFormatMode)
        {
        case CharacterFormatMode::Hex:
            commandBar.SetCommand(config.Keys.ChangeValueFormatOrCP, "Hex", BUFFERVIEW_CMD_CHANGEBASE);
            break;
        case CharacterFormatMode::Octal:
            commandBar.SetCommand(config.Keys.ChangeValueFormatOrCP, "Oct", BUFFERVIEW_CMD_CHANGEBASE);
            break;
        case CharacterFormatMode::SignedDecimal:
            commandBar.SetCommand(config.Keys.ChangeValueFormatOrCP, "Sign", BUFFERVIEW_CMD_CHANGEBASE);
            break;
        case CharacterFormatMode::UnsignedDecimal:
            commandBar.SetCommand(config.Keys.ChangeValueFormatOrCP, "Dec", BUFFERVIEW_CMD_CHANGEBASE);
            break;
        }
    }

    // address mode
    if ((this->settings) && (this->settings->translationMethodsCount > 0))
    {
        commandBar.SetCommand(
              config.Keys.ChangeAddressMode, this->settings->translationMethods[this->currentAdrressMode].name, BUFFERVIEW_CMD_CHANGEADDRESSMODE);
    }

    // Entry point
    commandBar.SetCommand(config.Keys.GoToEntryPoint, "EntryPoint", BUFFERVIEW_CMD_GOTOEP);

    // Selection
    if (this->selection.IsSingleSelectionEnabled())
        commandBar.SetCommand(config.Keys.ChangeSelectionType, "Select:Single", BUFFERVIEW_CMD_CHANGESELECTION);
    else
        commandBar.SetCommand(config.Keys.ChangeSelectionType, "Select:Multiple", BUFFERVIEW_CMD_CHANGESELECTION);

    // Strings
    if (this->StringInfo.showAscii)
    {
        if (this->StringInfo.showUnicode)
            commandBar.SetCommand(config.Keys.ShowHideStrings, "Strings:ON", BUFFERVIEW_CMD_HIDESTRINGS);
        else
            commandBar.SetCommand(config.Keys.ShowHideStrings, "Strings:Ascii", BUFFERVIEW_CMD_HIDESTRINGS);
    }
    else
    {
        if (this->StringInfo.showUnicode)
            commandBar.SetCommand(config.Keys.ShowHideStrings, "Strings:Unicode", BUFFERVIEW_CMD_HIDESTRINGS);
        else
            commandBar.SetCommand(config.Keys.ShowHideStrings, "Strings:OFF", BUFFERVIEW_CMD_HIDESTRINGS);
    }

    if (findDialog.HasResults())
    {
        commandBar.SetCommand(config.Keys.FindNext, "FindNext", BUFFERVIEW_CMD_FINDNEXT);
        commandBar.SetCommand(config.Keys.FindPrevious, "FindPrevious", BUFFERVIEW_CMD_FINDPREVIOUS);
    }

    commandBar.SetCommand(config.Keys.DissasmDialog, "Dissasm", BUFFERVIEW_CMD_DISSASM_DIALOG);

    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    bool select = ((keyCode & Key::Shift) != Key::None);
    if (select)
        keyCode = static_cast<Key>((uint32) keyCode - (uint32) Key::Shift);

    // tratare cazuri editare
    // if (this->EditMode)
    //{
    //    if ((KeyCode == Key::Tab) || (KeyCode == (Key::Tab | Key::Ctrl)))
    //    {
    //        if (IsNormalRow())
    //        {
    //            editNumbers    = !editNumbers;
    //            editNumbersOfs = 0;
    //        }
    //        return true;
    //    }
    //    if (KeyCode == Key::Backspace)
    //    {
    //        if (editNumbersOfs > 0)
    //            editNumbersOfs--;
    //        return true;
    //    }
    //    if (charCode >= 32)
    //    {
    //        AddChar(charCode);
    //        return true;
    //    }
    //}

    switch (keyCode)
    {
    case Key::Down:
        MoveTo(this->cursor.GetCurrentPosition() + this->Layout.charactersPerLine, select);
        return true;
    case Key::Up:
        if (this->cursor.GetCurrentPosition() > this->Layout.charactersPerLine)
            MoveTo(this->cursor.GetCurrentPosition() - this->Layout.charactersPerLine, select);
        else
            MoveTo(0, select);
        return true;
    case Key::Left:
        if (this->cursor.GetCurrentPosition() > 0)
            MoveTo(this->cursor.GetCurrentPosition() - 1, select);
        return true;
    case Key::Right:
        MoveTo(this->cursor.GetCurrentPosition() + 1, select);
        return true;
    case Key::PageDown:
        MoveTo(this->cursor.GetCurrentPosition() + (uint64) this->Layout.charactersPerLine * this->Layout.visibleRows, select);
        return true;
    case Key::PageUp:
        if (this->cursor.GetCurrentPosition() > (uint64) this->Layout.charactersPerLine * this->Layout.visibleRows)
            MoveTo(this->cursor.GetCurrentPosition() - ((uint64) this->Layout.charactersPerLine * this->Layout.visibleRows), select);
        else
            MoveTo(0, select);
        return true;
    case Key::Home:
        MoveTo(this->cursor.GetCurrentPosition() - (this->cursor.GetCurrentPosition() - this->cursor.GetStartView()) % this->Layout.charactersPerLine, select);
        return true;
    case Key::End:
        MoveTo(
              this->cursor.GetCurrentPosition() - (this->cursor.GetCurrentPosition() - this->cursor.GetStartView()) % this->Layout.charactersPerLine +
                    this->Layout.charactersPerLine - 1,
              select);
        return true;

    case Key::Ctrl | Key::Up:
        if (this->cursor.GetStartView() > this->Layout.charactersPerLine)
            MoveScrollTo(this->cursor.GetStartView() - this->Layout.charactersPerLine);
        else
            MoveScrollTo(0);
        return true;
    case Key::Ctrl | Key::Down:
        MoveScrollTo(this->cursor.GetStartView() + this->Layout.charactersPerLine);
        return true;
    case Key::Ctrl | Key::Left:
        if (this->cursor.GetStartView() >= 1)
            MoveScrollTo(this->cursor.GetStartView() - 1);
        return true;
    case Key::Ctrl | Key::Right:
        MoveScrollTo(this->cursor.GetStartView() + 1);
        return true;

    case Key::Ctrl | Key::Home:
        MoveTo(0, select);
        return true;
    case Key::Ctrl | Key::End:
        MoveTo(this->obj->GetData().GetSize(), select);
        return true;
    case Key::Ctrl | Key::PageUp:
        MoveToZone(true, select);
        return true;
    case Key::Ctrl | Key::PageDown:
        MoveToZone(false, select);
        return true;

    case Key::Ctrl | Key::Alt | Key::PageUp:
        MoveTillNextBlock(select, -1);
        return true;
    case Key::Ctrl | Key::Alt | Key::PageDown:
        MoveTillNextBlock(select, 1);
        return true;

    case Key::Alt | Key::N1:
        MoveToSelection(0);
        return true;
    case Key::Alt | Key::N2:
        MoveToSelection(1);
        return true;
    case Key::Alt | Key::N3:
        MoveToSelection(2);
        return true;
    case Key::Alt | Key::N4:
        MoveToSelection(3);
        return true;
    case Key::Alt | Key::N0:
        MoveToSelection(4);
        return true;

    case Key::E:
        MoveTillEndBlock(select);
        return true;
    case Key::S:
        SkipCurentCaracter(select);
        return true;

    case Key::Enter:
        OpenCurrentSelection();
        return true;
    };

    if ((charCode >= '0') && (charCode <= '9'))
    {
        auto addr = this->settings->bookmarks[charCode - '0'];
        if (addr != GView::Utils::INVALID_OFFSET)
            MoveTo(addr, select);
        return true;
    }

    switch (charCode)
    {
    case '[':
        if (this->Layout.lineAddressSize > 0)
            Layout.lineAddressSize--;
        this->UpdateViewSizes();
        return true;
    case ']':
        if (this->Layout.lineAddressSize < 32)
            this->Layout.lineAddressSize++;
        this->UpdateViewSizes();
        return true;
    case '{':
        if (this->Layout.lineNameSize > 0)
            this->Layout.lineNameSize--;
        this->UpdateViewSizes();
        return true;
    case '}':
        if (this->Layout.lineNameSize < 32)
            this->Layout.lineNameSize++;
        this->UpdateViewSizes();
        return true;
    }

    return ViewControl::OnKeyEvent(select ? (keyCode | Key::Shift) : keyCode, charCode);
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    CHECK(eventType == Event::Command, false, "");

    switch (ID)
    {
    case BUFFERVIEW_CMD_CHANGECOL:
        if (this->Layout.nrCols == 0)
            this->Layout.nrCols = 8;
        else
            this->Layout.nrCols <<= 1;
        if (this->Layout.nrCols >= 64)
            this->Layout.nrCols = 0;
        UpdateViewSizes();
        return true;
    case BUFFERVIEW_CMD_CHANGEBASE:
        if (this->Layout.nrCols == 0)
        {
            // not implemented yet
        }
        else
        {
            this->Layout.charFormatMode = static_cast<CharacterFormatMode>((((uint8) this->Layout.charFormatMode) + 1) % ((uint8) CharacterFormatMode::Count));
            UpdateViewSizes();
        }
        return true;
    case BUFFERVIEW_CMD_CHANGECODEPAGE:
        codePage = static_cast<CodePageID>((((uint32) ((CodePageID) codePage)) + 1) % CodePage::GetSupportedCodePagesCount());
        return true;
    case BUFFERVIEW_CMD_CHANGEADDRESSMODE:
        if ((this->settings) && (this->settings->translationMethodsCount > 0))
        {
            this->currentAdrressMode = (this->currentAdrressMode + 1) % this->settings->translationMethodsCount;
            return true;
        }
        return false;
    case BUFFERVIEW_CMD_GOTOEP:
        if ((this->settings) && (this->settings->entryPointOffset != GView::Utils::INVALID_OFFSET))
        {
            MoveTo(this->settings->entryPointOffset, false);
            return true;
        }
        return false;
    case BUFFERVIEW_CMD_CHANGESELECTION:
        if (this->selection.IsMultiSelectionEnabled())
        {
            this->CurrentSelection.Clear();
        }
        this->selection.InvertMultiSelectionMode();
        return true;
    case BUFFERVIEW_CMD_HIDESTRINGS:
        if (this->StringInfo.showAscii && this->StringInfo.showUnicode)
        {
            this->StringInfo.showAscii = this->StringInfo.showUnicode = false;
        }
        else
        {
            this->StringInfo.showAscii = this->StringInfo.showUnicode = true;
        }
        return true;
    case BUFFERVIEW_CMD_FINDNEXT:
    {
        selection.Clear();
        CurrentSelection.Clear();
        const auto [start, length] = findDialog.GetNextMatch(this->cursor.GetCurrentPosition() + 1);
        if (start != GView::Utils::INVALID_OFFSET && length > 0)
        {
            bool samePosition = this->cursor.GetCurrentPosition() == start;

            if (findDialog.AlignToUpperRightCorner())
            {
                MoveScrollTo(start);
            }
            else
            {
                MoveTo(start, false);
            }

            if (findDialog.SelectMatch())
            {
                this->selection.Clear();
                this->selection.BeginSelection(start);
                this->selection.UpdateSelection(0, start + length - 1);
                UpdateCurrentSelection();
            }

            if (samePosition)
            {
                Dialogs::MessageBox::ShowError("Error!", "No next match found!");
            }
        }
        else
        {
            Dialogs::MessageBox::ShowError("Error!", "No next match found!");
        }

        return true;
    }
    case BUFFERVIEW_CMD_FINDPREVIOUS:
    {
        if (this->cursor.GetCurrentPosition() == 0)
        {
            Dialogs::MessageBox::ShowError("Error!", "No previous match found!");
            return true;
        }

        selection.Clear();
        CurrentSelection.Clear();
        const auto [start, length] = findDialog.GetPreviousMatch(this->cursor.GetCurrentPosition() - 1);
        if (start != GView::Utils::INVALID_OFFSET && length > 0)
        {
            bool samePosition = this->cursor.GetCurrentPosition() == start;

            if (findDialog.AlignToUpperRightCorner())
            {
                MoveScrollTo(start);
            }
            else
            {
                MoveTo(start, false);
            }

            if (findDialog.SelectMatch())
            {
                this->selection.Clear();
                this->selection.BeginSelection(start);
                this->selection.UpdateSelection(0, start + length - 1);
                UpdateCurrentSelection();
            }

            if (samePosition)
            {
                Dialogs::MessageBox::ShowError("Error!", "No previous match found!");
            }
        }
        else
        {
            Dialogs::MessageBox::ShowError("Error!", "No previous match found!");
        }

        return true;
    }
    case BUFFERVIEW_CMD_DISSASM_DIALOG:
        this->ShowDissasmDialog();
        return true;

    case VIEW_COMMAND_ACTIVATE_COMPARE:
        showSyncCompare = true;
        return true;
    case VIEW_COMMAND_DEACTIVATE_COMPARE:
        showSyncCompare = false;
        return true;

    case VIEW_COMMAND_ACTIVATE_SYNC:
        moveInSync = true;
        return true;
    case VIEW_COMMAND_DEACTIVATE_SYNC:
        moveInSync = false;
        return true;
    }
    return false;
}
void Instance::OnFocus()
{
    cursor.SetStartView(cursor.GetStartView()); // invalidate delta;
}
void Instance::OnLoseFocus()
{
    cursor.SetStartView(cursor.GetStartView()); // invalidate delta;
}
bool Instance::GoTo(uint64 offset)
{
    this->MoveTo(offset, false);
    return true;
}
bool Instance::Select(uint64 offset, uint64 size)
{
    if (offset >= this->obj->GetData().GetSize())
        return false;
    auto end = offset + size - 1;
    if ((end < offset) || (end + 1 < size))
        return false;
    if (end > this->obj->GetData().GetSize())
        return false;
    this->selection.SetSelection(0, offset, end);
    return true;
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
            r.WriteSingleLineText(x, y, width, tmp.GetText(), this->CursorColors.Normal);
        }
        else
        {
            r.WriteSingleLineText(x, y, width, "NO Selection", Cfg.Text.Inactive, TextAlignament::Center);
        }
    }
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    return x + width + 1;
}
int Instance::PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Pos:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(x + 4, y, width - 4, n.ToBase(this->cursor.GetCurrentPosition(), this->cursor.GetBase()), this->CursorColors.Normal);
    x += width;
    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    // percentage

    if (this->obj->GetData().GetSize() > 0)
    {
        LocalString<32> tmp;
        tmp.Format("%3u%%", (this->cursor.GetCurrentPosition() + 1) * 100ULL / this->obj->GetData().GetSize());
        r.WriteSingleLineText(x, y, tmp.GetText(), this->CursorColors.Normal);
    }
    else
    {
        r.WriteSingleLineText(x, y, "----", this->CursorColors.Line);
    }
    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    return x + 5;
}
int Instance::PrintCursorZone(int x, int y, uint32 width, Renderer& r)
{
    if (auto z = this->settings->zList.OffsetToZone(this->cursor.GetCurrentPosition()))
    {
        r.WriteSingleLineText(x, y, width, z->name, this->CursorColors.Highlighted);
    }
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    return x + width + 1;
}
int Instance::Print8bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r)
{
    if (buffer.GetLength() == 0)
        return x;
    const uint8 v_u8 = buffer[0];
    NumericFormatter n;
    NumericFormat fmt = { NumericFormatFlags::None, 16, 0, 0, 2 };
    switch (height)
    {
    case 0:
        break;
    case 1:
        r.WriteSingleLineText(x, 0, "Asc:  I8:     Hex:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, this->codePage[v_u8], this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 0, n.ToDec(*(const char*) (&v_u8)), this->CursorColors.Normal, TextAlignament::Right);
        r.WriteSingleLineText(x + 18, 0, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 20, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 21;
    case 2:
        r.WriteSingleLineText(x, 0, "Asc:    I8:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:    U8:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, this->codePage[v_u8], this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 0, n.ToDec(*(const char*) (&v_u8)), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 1, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 1, n.ToDec(v_u8), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 15, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        r.WriteSpecialCharacter(x + 15, 1, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 16;
    default:
        // 3 , 4 or more lines
        r.WriteSingleLineText(x, 0, "Asc:    I8:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:    U8:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 2, "Bin:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, this->codePage[v_u8], this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 0, n.ToDec(*(const char*) (&v_u8)), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 1, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 1, n.ToDec(v_u8), this->CursorColors.Normal);
        fmt.Base        = 2;
        fmt.DigitsCount = 8;
        r.WriteSingleLineText(x + 4, 2, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        if (height > 3)
        {
            r.WriteSingleLineText(x, 3, "Oct:", this->CursorColors.Highlighted);
            fmt.Base        = 8;
            fmt.DigitsCount = 3;
            r.WriteSingleLineText(x + 4, 3, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        }
        r.DrawVerticalLine(x + 15, 0, 3, this->CursorColors.Line);
        return x + 16;
    }
    return x;
}

int Instance::Print16bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r)
{
    if (buffer.GetLength() < 2)
        return x;
    const uint16 v_u16 = *(uint16*) buffer.GetData();
    NumericFormatter n;
    NumericFormat fmt = { NumericFormatFlags::None, 16, 0, 0, 4 };
    switch (height)
    {
    case 0:
        break;
    case 1:
        r.WriteSingleLineText(x, 0, "Unc:  I16:       Hex:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, v_u16, this->CursorColors.Normal);
        r.WriteSingleLineText(x + 15, 0, n.ToDec(*(const int16*) (&v_u16)), this->CursorColors.Normal, TextAlignament::Right);
        r.WriteSingleLineText(x + 21, 0, n.ToString(v_u16, fmt), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 25, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 26;
    case 2:
        r.WriteSingleLineText(x, 0, "Unc:      I16:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:      U16:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, v_u16, this->CursorColors.Normal);
        r.WriteSingleLineText(x + 14, 0, n.ToDec(*(const int16*) (&v_u16)), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 1, n.ToString(v_u16, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 14, 1, n.ToDec(v_u16), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 20, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        r.WriteSpecialCharacter(x + 20, 1, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 21;
    default:
        // 3 , 4 or more lines
        r.WriteSingleLineText(x, 0, "Unc:      I16:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:      U16:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 2, "Bin:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, v_u16, this->CursorColors.Normal);
        r.WriteSingleLineText(x + 14, 0, n.ToDec(*(const int16*) (&v_u16)), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 1, n.ToString(v_u16, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 14, 1, n.ToDec(v_u16), this->CursorColors.Normal);
        fmt.Base        = 2;
        fmt.DigitsCount = 16;
        r.WriteSingleLineText(x + 4, 2, n.ToString(v_u16, fmt), this->CursorColors.Normal);
        if (height > 3)
        {
            r.WriteSingleLineText(x, 3, "Oct:", this->CursorColors.Highlighted);
            fmt.Base        = 8;
            fmt.DigitsCount = 6;
            r.WriteSingleLineText(x + 4, 3, n.ToString(v_u16, fmt), this->CursorColors.Normal);
        }
        r.DrawVerticalLine(x + 20, 0, 3, this->CursorColors.Line);
        return x + 21;
    }
    return x;
}
int Instance::Print32bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r)
{
    if (buffer.GetLength() < 4)
        return x;
    const uint32 v_u32 = *(uint32*) buffer.GetData();
    NumericFormatter n;
    NumericFormat fmt    = { NumericFormatFlags::HexSuffix, 16, 0, 0, 8 };
    NumericFormat fmtDec = { NumericFormatFlags::None, 10, 3, ',' };
    switch (height)
    {
    case 0:
        break;
    case 1:
        r.WriteSingleLineText(x, 0, "DW:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x + 3, 0, n.ToString(v_u32, fmt), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 12, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 14;
    default:
        // 2,3, 4 or more lines
        r.WriteSingleLineText(x, 0, "Hex:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "I32:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x + 4, 0, n.ToString(v_u32, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 1, n.ToString(*(const int*) (&v_u32), fmtDec), this->CursorColors.Normal);
        if (height >= 3)
        {
            r.WriteSingleLineText(x, 2, "U32:", this->CursorColors.Highlighted);
            r.WriteSingleLineText(x + 4, 2, n.ToString(v_u32, fmtDec), this->CursorColors.Normal);
        }
        if (height >= 4)
        {
            r.WriteSingleLineText(x, 3, "Flt:", this->CursorColors.Highlighted);
            LocalString<32> tmp;
            tmp.SetFormat("%f", *(const float*) (&v_u32));
            if (tmp.Len() > 16)
                tmp.Truncate(16);
            r.WriteSingleLineText(x + 4, 3, tmp, this->CursorColors.Normal);
        }
        r.DrawVerticalLine(x + 20, 0, 3, this->CursorColors.Line);
        return x + 21;
    }
    return x;
}
int Instance::Print32bitBEValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r)
{
    if (buffer.GetLength() < 4)
        return x;
    const uint32 v_u32 = (((uint32_t) buffer[0]) << 24) | (((uint32_t) buffer[1]) << 16) | (((uint32_t) buffer[2]) << 8) | (((uint32_t) buffer[3]));
    NumericFormatter n;
    NumericFormat fmt    = { NumericFormatFlags::HexSuffix, 16, 0, 0, 8 };
    NumericFormat fmtDec = { NumericFormatFlags::None, 10, 3, ',' };
    switch (height)
    {
    case 0:
    case 1:
    case 2:
        break;
    case 3:
        r.WriteSingleLineText(x, 0, "Hex (BE):", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "I32 (BE):", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 2, "U32 (BE):", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x + 9, 0, n.ToString(v_u32, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 9, 1, n.ToString(*(const int*) (&v_u32), fmtDec), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 9, 2, n.ToString(v_u32, fmtDec), this->CursorColors.Normal);
        r.DrawVerticalLine(x + 27, 0, 2, this->CursorColors.Line);
        return x + 28;
    default:
        // 4 or more lines
        r.WriteSingleLineText(x, 0, "    Big Endian    ", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 2, "I32:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 3, "U32:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x + 4, 1, n.ToString(v_u32, fmt), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 2, n.ToString(*(const int*) (&v_u32), fmtDec), this->CursorColors.Normal);
        r.WriteSingleLineText(x + 4, 3, n.ToString(v_u32, fmtDec), this->CursorColors.Normal);
        r.DrawVerticalLine(x + 20, 0, 3, this->CursorColors.Line);
        return x + 23;
    }
    return x;
}
void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    int x = 0;
    // set up the cursor colors

    if (this->HasFocus())
    {
        this->CursorColors.Normal      = Cfg.Text.Normal;
        this->CursorColors.Line        = Cfg.Lines.Normal;
        this->CursorColors.Highlighted = Cfg.Text.Highlighted;
    }
    else
    {
        this->CursorColors.Normal      = Cfg.Text.Inactive;
        this->CursorColors.Line        = Cfg.Lines.Inactive;
        this->CursorColors.Highlighted = Cfg.Text.Inactive;
    }
    r.Clear();
    auto buf = this->obj->GetData().Get(this->cursor.GetCurrentPosition(), 8, false);
    switch (height)
    {
    case 0:
        break;
    case 1:
        x = PrintSelectionInfo(0, 0, 0, 16, r);
        if (this->selection.IsMultiSelectionEnabled())
        {
            x = PrintSelectionInfo(1, x, 0, 16, r);
            x = PrintSelectionInfo(2, x, 0, 16, r);
            x = PrintSelectionInfo(3, x, 0, 16, r);
        }
        x = PrintCursorPosInfo(x, 0, 16, true, r);
        x = PrintCursorZone(x, 0, 16, r);
        x = Print8bitValue(x, height, buf, r);
        x = Print16bitValue(x, height, buf, r);
        x = Print32bitValue(x, height, buf, r);
        break;
    case 2:
        PrintSelectionInfo(0, 0, 0, 16, r);
        x = PrintSelectionInfo(2, 0, 1, 16, r);
        PrintSelectionInfo(1, x, 0, 16, r);
        x = PrintSelectionInfo(3, x, 1, 16, r);
        PrintCursorZone(x, 1, 21, r);
        x = PrintCursorPosInfo(x, 0, 17, false, r);
        x = Print8bitValue(x, height, buf, r);
        x = Print16bitValue(x, height, buf, r);
        x = Print32bitValue(x, height, buf, r);
        break;
    case 3:
        PrintSelectionInfo(0, 0, 0, 18, r);
        PrintSelectionInfo(1, 0, 1, 18, r);
        x = PrintSelectionInfo(2, 0, 2, 18, r);
        PrintSelectionInfo(3, x, 0, 18, r);
        PrintCursorPosInfo(x, 1, 14, false, r);
        x = PrintCursorZone(x, 2, 18, r);
        x = Print8bitValue(x, height, buf, r);
        x = Print16bitValue(x, height, buf, r);
        x = Print32bitValue(x, height, buf, r);
        x = Print32bitBEValue(x, height, buf, r);
        break;
    default:
        // 4 or more
        PrintSelectionInfo(0, 0, 0, 18, r);
        PrintSelectionInfo(1, 0, 1, 18, r);
        PrintSelectionInfo(2, 0, 2, 18, r);
        x = PrintSelectionInfo(3, 0, 3, 18, r);
        PrintCursorPosInfo(x, 0, 14, false, r);
        PrintCursorZone(x, 1, 18, r);
        r.DrawVerticalLine(x + 18, 0, 3, this->CursorColors.Line);
        x += 19;
        x = Print8bitValue(x, height, buf, r);
        x = Print16bitValue(x, height, buf, r);
        x = Print32bitValue(x, height, buf, r);
        x = Print32bitBEValue(x, height, buf, r);
        break;
    }
}

//======================================================================[Mouse events]========================
void Instance::AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo)
{
    mpInfo.location = MouseLocation::Outside;
    if (y < 0)
    {
        mpInfo.location = MouseLocation::Outside;
        return;
    }
    if (y == 0)
    {
        mpInfo.location = MouseLocation::OnHeader;
        return;
    }
    // y>=1 --> check if in buffer
    auto yPoz = y - 1;
    if (x < 0)
    {
        mpInfo.location = MouseLocation::Outside;
        return;
    }
    auto xPoz = (uint32) x;
    if ((xPoz >= Layout.xText) && (xPoz < Layout.xText + Layout.charactersPerLine))
    {
        mpInfo.location     = MouseLocation::OnView;
        mpInfo.bufferOffset = yPoz * Layout.charactersPerLine + xPoz - Layout.xText;
    }
    else
    {
        if ((Layout.nrCols > 0) && (xPoz >= Layout.xNumbers))
        {
            auto sz_char = characterFormatModeSize[(uint32) this->Layout.charFormatMode] + 1;
            if (xPoz < Layout.nrCols * sz_char + Layout.xNumbers)
            {
                mpInfo.location     = MouseLocation::OnView;
                mpInfo.bufferOffset = yPoz * Layout.charactersPerLine + ((xPoz - Layout.xNumbers) / sz_char);
            }
        }
    }
    if (mpInfo.location == MouseLocation::OnView)
    {
        mpInfo.bufferOffset += cursor.GetStartView();
        if (mpInfo.bufferOffset >= this->obj->GetData().GetSize())
            mpInfo.location = MouseLocation::Outside;
    }
}
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if ((mpInfo.location == MouseLocation::OnView) && (mpInfo.bufferOffset != cursor.GetCurrentPosition()))
    {
        MoveTo(mpInfo.bufferOffset, false);
    }
}
void Instance::OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button)
{
}
bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if ((mpInfo.location == MouseLocation::OnView) && (mpInfo.bufferOffset != cursor.GetCurrentPosition()))
    {
        MoveTo(mpInfo.bufferOffset, true);
        return true;
    }
    return false;
}
bool Instance::OnMouseEnter()
{
    return false;
}
bool Instance::OnMouseOver(int x, int y)
{
    return false;
}
bool Instance::OnMouseLeave()
{
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
    case MouseWheel::Left:
        return OnKeyEvent(Key::PageUp, false);
    case MouseWheel::Right:
        return OnKeyEvent(Key::PageDown, false);
    }

    return false;
}

// =====================================================================[SCROLLBAR]===========================
void Instance::OnUpdateScrollBars()
{
    this->UpdateVScrollBar(this->cursor.GetCurrentPosition() + 1, this->obj->GetData().GetSize());
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    Columns = 0,
    CursorOffset,
    DataFormat,
    ShowAddress,
    ShowZoneName,
    ShowTypeObject,
    ShowSyncCompare,
    AddressBarWidth,
    ZoneNameWidth,
    CodePage,
    AddressType,
    // selection
    HighlightSelection,
    SelectionType,
    Selection_1,
    Selection_2,
    Selection_3,
    Selection_4,
    // strings
    ShowAscii,
    ShowUnicode,
    StringCharacterSet,
    MinimCharsInString,
    // shortcuts
    ChangeColumnsView,
    ChangeValueFormatOrCP,
    ChangeAddressMode,
    GoToEntryPoint,
    ChangeSelectionType,
    ShowHideStrings,
    Dissasm,
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::Columns:
        value = this->Layout.nrCols;
        return true;
    case PropertyID::CursorOffset:
        value = this->cursor.GetBase() == 16;
        return true;
    case PropertyID::DataFormat:
        value = (uint64) this->Layout.charFormatMode;
        return true;
    case PropertyID::ShowAscii:
        value = this->StringInfo.showAscii;
        return true;
    case PropertyID::ShowUnicode:
        value = this->StringInfo.showUnicode;
        return true;
    case PropertyID::MinimCharsInString:
        value = this->StringInfo.minCount;
        return true;
    case PropertyID::ShowAddress:
        value = this->Layout.lineAddressSize > 0;
        return true;
    case PropertyID::AddressBarWidth:
        value = this->Layout.lineAddressSize;
        return true;
    case PropertyID::ShowZoneName:
        value = this->Layout.lineNameSize > 0;
        return true;
    case PropertyID::ZoneNameWidth:
        value = this->Layout.lineNameSize;
        return true;
    case PropertyID::StringCharacterSet:
        value = this->GetAsciiMaskStringRepresentation();
        return true;
    case PropertyID::ShowTypeObject:
        value = this->showTypeObjects;
        return true;
    case PropertyID::ShowSyncCompare:
        value = this->showSyncCompare;
        return true;
    case PropertyID::HighlightSelection:
        value = this->CurrentSelection.highlight;
        return true;
    case PropertyID::CodePage:
        value = (uint64) ((CodePageID) this->codePage);
        return true;
    case PropertyID::SelectionType:
        value = this->selection.IsSingleSelectionEnabled() ? (uint64) 0 : (uint64) 1;
        return true;
    case PropertyID::Selection_1:
        value = this->selection.GetStringRepresentation(0);
        return true;
    case PropertyID::Selection_2:
        value = this->selection.GetStringRepresentation(1);
        return true;
    case PropertyID::Selection_3:
        value = this->selection.GetStringRepresentation(2);
        return true;
    case PropertyID::Selection_4:
        value = this->selection.GetStringRepresentation(3);
        return true;
    case PropertyID::ChangeAddressMode:
        value = config.Keys.ChangeAddressMode;
        return true;
    case PropertyID::ChangeValueFormatOrCP:
        value = config.Keys.ChangeValueFormatOrCP;
        return true;
    case PropertyID::ChangeColumnsView:
        value = config.Keys.ChangeColumnsNumber;
        return true;
    case PropertyID::GoToEntryPoint:
        value = config.Keys.GoToEntryPoint;
        return true;
    case PropertyID::ChangeSelectionType:
        value = config.Keys.ChangeSelectionType;
        return true;
    case PropertyID::ShowHideStrings:
        value = config.Keys.ShowHideStrings;
        return true;
    case PropertyID::AddressType:
        value = this->currentAdrressMode;
        return true;
    case PropertyID::Dissasm:
        value = config.Keys.DissasmDialog;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    uint32 tmpValue;
    switch (static_cast<PropertyID>(id))
    {
    case PropertyID::Columns:
        this->Layout.nrCols = (uint32) std::get<uint64>(value);
        UpdateViewSizes();
        return true;
    case PropertyID::CursorOffset:
        this->cursor.SetBase(std::get<bool>(value) ? 16 : 10);
        return true;
    case PropertyID::DataFormat:
        this->Layout.charFormatMode = static_cast<CharacterFormatMode>(std::get<uint64>(value));
        UpdateViewSizes();
        return true;
    case PropertyID::ShowAscii:
        this->StringInfo.showAscii = std::get<bool>(value);
        this->ResetStringInfo();
        return true;
    case PropertyID::ShowUnicode:
        this->StringInfo.showUnicode = std::get<bool>(value);
        this->ResetStringInfo();
        return true;
    case PropertyID::MinimCharsInString:
        tmpValue = std::get<uint32>(value);
        if ((tmpValue < 3) || (tmpValue > 20))
        {
            error = "The minim size of a string must be a value between 3 and 20 !";
            return false;
        }
        this->StringInfo.minCount = tmpValue;
        this->ResetStringInfo();
        return true;
    case PropertyID::ShowAddress:
        this->Layout.lineAddressSize = std::get<bool>(value) ? 8 : 0;
        return true;
    case PropertyID::ShowZoneName:
        this->Layout.lineNameSize = std::get<bool>(value) ? 8 : 0;
        return true;
    case PropertyID::AddressBarWidth:
        tmpValue = std::get<uint32>(value);
        if (tmpValue > 20)
        {
            error = "Address bar size must not exceed 20 characters !";
            return false;
        }
        this->Layout.lineAddressSize = tmpValue;
        UpdateViewSizes();
        return true;
    case PropertyID::ZoneNameWidth:
        tmpValue = std::get<uint32>(value);
        if (tmpValue > 20)
        {
            error = "Zone name bar size must not exceed 20 characters !";
            return false;
        }
        this->Layout.lineNameSize = tmpValue;
        UpdateViewSizes();
        return true;
    case PropertyID::StringCharacterSet:
        if (this->SetStringAsciiMask(std::get<string_view>(value)))
            return true;
        error = "Invalid format (use \\x<hex> values, ascii characters or '-' sign for intervals (ex: A-Z)";
        return false;
    case PropertyID::ShowTypeObject:
        this->showTypeObjects = std::get<bool>(value);
        return true;
    case PropertyID::ShowSyncCompare:
        this->showSyncCompare = std::get<bool>(value);
        return true;
    case PropertyID::HighlightSelection:
        this->CurrentSelection.highlight = std::get<bool>(value);
        return true;
    case PropertyID::CodePage:
        codePage = static_cast<CodePageID>(std::get<uint64>(value));
        return true;
    case PropertyID::SelectionType:
        this->selection.EnableMultiSelection(std::get<uint64>(value) == 1);
        return true;
    case PropertyID::ChangeAddressMode:
        config.Keys.ChangeAddressMode = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::ChangeValueFormatOrCP:
        config.Keys.ChangeValueFormatOrCP = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::ChangeColumnsView:
        config.Keys.ChangeColumnsNumber = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::GoToEntryPoint:
        config.Keys.GoToEntryPoint = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::ChangeSelectionType:
        config.Keys.ChangeSelectionType = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::ShowHideStrings:
        config.Keys.ShowHideStrings = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::Dissasm:
        config.Keys.DissasmDialog = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::AddressType:
        this->currentAdrressMode = (uint32) std::get<uint64>(value);
        return true;
    }
    error.SetFormat("Unknown internat ID: %u", id);
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
    auto propID = static_cast<PropertyID>(propertyID);
    if ((propID == PropertyID::Selection_1) || (propID == PropertyID::Selection_2) || (propID == PropertyID::Selection_3) ||
        (propID == PropertyID::Selection_4))
    {
        const auto idx = propertyID - (uint32) (PropertyID::Selection_1);
        SelectionEditor dlg(&this->selection, idx, this->settings.get(), this->obj->GetData().GetSize());
        dlg.Show();
    }
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    switch (static_cast<PropertyID>(propertyID))
    {
    case PropertyID::DataFormat:
        return (this->Layout.nrCols == 0); // if full screen display --> dataformat is not available
    case PropertyID::Selection_2:
    case PropertyID::Selection_3:
    case PropertyID::Selection_4:
        return this->selection.IsSingleSelectionEnabled();
    }

    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    addressModesList.Clear();
    if (this->settings->translationMethodsCount == 0)
    {
        addressModesList.Set("FileOffset=0");
    }
    else
    {
        for (uint32 tr = 0; tr < settings->translationMethodsCount; tr++)
        {
            if (tr > 0)
                addressModesList.AddChar(',');
            addressModesList.AddFormat("%s=%u", settings->translationMethods[tr].name.GetText(), tr);
        }
    }

    return {
        // Display
        { BT(PropertyID::Columns), "Display", "Columns", PropertyType::List, "8 columns=8,16 columns=16,32 columns=32,FullScreen=0" },
        { BT(PropertyID::CursorOffset), "Display", "Cursor offset", PropertyType::Boolean, "Dec,Hex" },
        { BT(PropertyID::DataFormat), "Display", "Data format", PropertyType::List, "Hex=0,Oct=1,Signed decimal=2,Unsigned decimal=3" },
        { BT(PropertyID::ShowTypeObject), "Display", "Show Type specific patterns", PropertyType::Boolean },
        { BT(PropertyID::CodePage), "Display", "CodePage", PropertyType::List, CodePage::GetPropertyListValues() },

        // Address
        { BT(PropertyID::AddressType), "Address", "Type", PropertyType::List, addressModesList.ToStringView() },
        { BT(PropertyID::ShowAddress), "Address", "Show Address", PropertyType::Boolean },
        { BT(PropertyID::ShowZoneName), "Address", "Show Zone Name", PropertyType::Boolean },
        { BT(PropertyID::AddressBarWidth), "Address", "Address Bar Width", PropertyType::UInt32 },
        { BT(PropertyID::ZoneNameWidth), "Address", "Zone name Width", PropertyType::UInt32 },

        // Selection
        { BT(PropertyID::HighlightSelection), "Selection", "Highlight current selection", PropertyType::Boolean },
        { BT(PropertyID::SelectionType), "Selection", "Type", PropertyType::List, "Single=0,Multiple=1" },
        { BT(PropertyID::Selection_1), "Selection", "Selection 1", PropertyType::Custom },
        { BT(PropertyID::Selection_2), "Selection", "Selection 2", PropertyType::Custom },
        { BT(PropertyID::Selection_3), "Selection", "Selection 3", PropertyType::Custom },
        { BT(PropertyID::Selection_4), "Selection", "Selection 4", PropertyType::Custom },

        // String
        { BT(PropertyID::ShowAscii), "Strings", "Ascii", PropertyType::Boolean },
        { BT(PropertyID::ShowUnicode), "Strings", "Unicode", PropertyType::Boolean },
        { BT(PropertyID::StringCharacterSet), "Strings", "Character set", PropertyType::Ascii },
        { BT(PropertyID::MinimCharsInString), "Strings", "Minim consecutives chars", PropertyType::UInt32 },

        // shortcuts
        { BT(PropertyID::ChangeAddressMode), "Shortcuts", "Change address mode/type", PropertyType::Key },
        { BT(PropertyID::ChangeValueFormatOrCP), "Shortcuts", "Change value format/code page", PropertyType::Key },
        { BT(PropertyID::ChangeColumnsView), "Shortcuts", "Change nr. of columns", PropertyType::Key },
        { BT(PropertyID::GoToEntryPoint), "Shortcuts", "Go To Entry Point", PropertyType::Key },
        { BT(PropertyID::ChangeSelectionType), "Shortcuts", "Change selection type", PropertyType::Key },
        { BT(PropertyID::ShowHideStrings), "Shortcuts", "Show/Hide strings", PropertyType::Key },

        // dissasm
        { BT(PropertyID::Dissasm), "Shortcuts", "Dissasm", PropertyType::Key },
    };
}
#undef BT
