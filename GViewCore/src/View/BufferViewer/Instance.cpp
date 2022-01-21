#include "BufferViewer.hpp"

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

const char16 CodePage_437[] = {
    0x0020, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25D8, 0x25CB, 0x25D9, 0x2642, 0x2640, 0x266A, 0x266B, 0x263C,
    0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8, 0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC,
    0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x2302,
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x0020
};
const char16 CodePage_Latin1[] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,
    26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,
    78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
};
const char16 CodePage_PrintableAscii[] = {
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,
    78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
    32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
};
CodePageInfo CodePages[(uint32) CodePageID::Count] = {
    { CodePage_437, "OEM-437" },
    { CodePage_Latin1, "Latin-1" },
    { CodePage_PrintableAscii, "Printable Ascii" },
};
bool DefaultAsciiMask[256] = {
    false, false, false, false, false, false, false, false, false, true,  false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, true,  true,  true,  true,  true,  true,
    false, true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  false, false, true,  false, false, true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  false, true,  false, false,
    true,  false, true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,  true,
    true,  true,  true,  true,  true,  true,  true,  true,  true,  false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false
};

constexpr int BUFFERVIEW_CMD_CHANGECOL         = 0xBF00;
constexpr int BUFFERVIEW_CMD_CHANGEBASE        = 0xBF01;
constexpr int BUFFERVIEW_CMD_CHANGEADDRESSMODE = 0xBF02;
constexpr int BUFFERVIEW_CMD_GOTOEP            = 0xBF03;
constexpr int BUFFERVIEW_CMD_CHANGECODEPAGE    = 0xBF04;
constexpr int BUFFERVIEW_CMD_GOTO              = 0xBF05;
constexpr int BUFFERVIEW_CMD_CHANGESELECTION   = 0xBF06;
constexpr int BUFFERVIEW_CMD_HIDESTRINGS       = 0xBF07;

Config Instance::config;

Instance::Instance(const std::string_view& _name, Reference<GView::Object> _obj, Settings* _settings) : settings(nullptr)
{
    this->obj  = _obj;
    this->name = _name;
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::Transparent });
    this->showTypeObjects            = true;
    this->Layout.nrCols              = 0;
    this->Layout.charFormatMode      = CharacterFormatMode::Hex;
    this->Layout.lineAddressSize     = 8;
    this->Layout.lineNameSize        = 8;
    this->Layout.charactersPerLine   = 1;
    this->Layout.visibleRows         = 1;
    this->Layout.xName               = 0;
    this->Layout.xNumbers            = 0;
    this->Layout.xAddress            = 0;
    this->Layout.xText               = 0;
    this->Cursor.currentPos          = 0;
    this->Cursor.startView           = 0;
    this->StringInfo.minCount        = 4;
    this->StringInfo.showAscii       = true;
    this->StringInfo.showUnicode     = true;
    this->Cursor.base                = 16;
    this->currentAdrressMode         = 0;
    this->CurrentSelection.size      = 0;
    this->CurrentSelection.start     = GView::Utils::INVALID_OFFSET;
    this->CurrentSelection.end       = GView::Utils::INVALID_OFFSET;
    this->CurrentSelection.highlight = true;
    this->Cfg                        = this->GetConfig();

    memcpy(this->StringInfo.AsciiMask, DefaultAsciiMask, 256);

    this->SetCodePage(CodePageID::DOS_437);
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

void Instance::SetCodePage(CodePageID id)
{
    this->CodePage.id      = id;
    this->CodePage.mapping = CodePages[(uint32) this->CodePage.id].mapping;
}

void Instance::OpenCurrentSelection()
{
    uint64 start, end;
    auto res = this->selection.OffsetToSelection(this->Cursor.currentPos, start, end);
    if (res >= 0)
    {
        LocalString<128> temp;
        temp.Format("Buffer_%llx_%llx", start, end);
        GView::App::OpenItem((ExtractItem) (res), this, (end - start) + 1, temp);
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
                auto b                      = obj->cache.Get(start, this->CurrentSelection.size, true);
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
    if (this->obj->cache.GetSize() == 0)
        return;
    if (offset > (obj->cache.GetSize() - 1))
        offset = obj->cache.GetSize() - 1;

    if (offset == this->Cursor.currentPos)
    {
        this->Cursor.startView = offset;
        return;
    }

    auto h    = this->Layout.visibleRows;
    auto sz   = this->Layout.charactersPerLine * h;
    auto sidx = -1;
    if (select)
        sidx = this->selection.BeginSelection(this->Cursor.currentPos);
    if ((offset >= this->Cursor.startView) && (offset < this->Cursor.startView + sz))
    {
        this->Cursor.currentPos = offset;
        if ((select) && (sidx >= 0))
        {
            this->selection.UpdateSelection(sidx, offset);
            UpdateCurrentSelection();
            return; // nothing to do ... already in visual space
        }
    }

    if (offset < this->Cursor.startView)
        this->Cursor.startView = offset;
    else
    {
        auto dif = this->Cursor.currentPos - this->Cursor.startView;
        if (offset >= dif)
            this->Cursor.startView = offset - dif;
        else
            this->Cursor.startView = 0;
    }
    this->Cursor.currentPos = offset;
    if ((select) && (sidx >= 0))
    {
        this->selection.UpdateSelection(sidx, offset);
        UpdateCurrentSelection();
    }
}
void Instance::MoveScrollTo(uint64 offset)
{
    if (this->obj->cache.GetSize() == 0)
        return;
    if (offset > (obj->cache.GetSize() - 1))
        offset = obj->cache.GetSize() - 1;
    auto old               = this->Cursor.startView;
    this->Cursor.startView = offset;
    if (this->Cursor.startView > old)
        MoveTo(this->Cursor.currentPos + (this->Cursor.startView - old), false);
    else
    {
        auto dif = old - Cursor.startView;
        if (dif <= this->Cursor.currentPos)
            MoveTo(this->Cursor.currentPos - dif, false);
        else
            MoveTo(0, false);
    }
}
void Instance::MoveToSelection(uint32 selIndex)
{
    uint64 start, end;

    if (this->selection.GetSelection(selIndex, start, end))
    {
        if (this->Cursor.currentPos != start)
            MoveTo(start, false);
        else
            MoveTo(end, false);
    }
}
void Instance::SkipCurentCaracter(bool selected)
{
    uint64 tr, fileSize;
    uint32 gr;

    auto buf = this->obj->cache.Get(this->Cursor.currentPos, 1, true);

    if (!buf.IsValid())
        return;
    auto toSkip = *buf.GetData();

    fileSize = this->obj->cache.GetSize();
    for (tr = this->Cursor.currentPos; tr < fileSize;)
    {
        auto buf = this->obj->cache.Get(tr, 256, false);
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

    fileSize = this->obj->cache.GetSize();

    for (tr = this->Cursor.currentPos; tr < fileSize;)
    {
        auto buf = this->obj->cache.Get(tr, 4096, false);
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
    const auto* z = settings->zList.OffsetToZone(this->Cursor.currentPos);
    if (z)
    {
        if (startOfZone)
            MoveTo(z->start, select);
        else
            MoveTo(z->end, select);
    }
}

void Instance::ShowGoToDialog()
{
    GoToDialog dlg(settings.get(), this->Cursor.currentPos, this->obj->cache.GetSize());
    if (dlg.Show() == (int) Dialogs::Result::Ok)
    {
        MoveTo(dlg.GetResultedPos(), false);
    }
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
    auto buf = this->obj->cache.Get(offset, 1024, false);
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
        auto* s = (char16_t*) buf.GetData();
        auto* e = s + buf.GetLength() / 2;
        if ((s < e) && ((*s) < 256) && (StringInfo.AsciiMask[*s]))
        {
            while ((s < e) && ((*s) < 256) && (StringInfo.AsciiMask[*s]))
                s++;
            if (s - (char16_t*) buf.GetData() >= StringInfo.minCount)
            {
                // ascii string found
                StringInfo.start  = offset;
                StringInfo.end    = offset + ((const uint8*) s - buf.GetData());
                StringInfo.middle = offset + (s - (char16_t*) buf.GetData());
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
    auto* z = this->settings->zList.OffsetToZone(offset);
    if (z == nullptr)
        return Cfg->Text.Inactive;
    else
        return z->color;
}
ColorPair Instance::OffsetToColor(uint64 offset)
{
    // current selection
    if ((this->CurrentSelection.size) && (this->CurrentSelection.highlight))
    {
        if ((offset >= this->CurrentSelection.start) && (offset < this->CurrentSelection.end))
            return config.Colors.SameSelection;

        auto b = this->obj->cache.Get(offset, this->CurrentSelection.size, true);
        if (b.IsValid())
        {
            if (b[0] == this->CurrentSelection.buffer[0])
            {
                if (memcmp(b.begin(), this->CurrentSelection.buffer, this->CurrentSelection.size) == 0)
                {
                    this->CurrentSelection.start = offset;
                    this->CurrentSelection.end   = offset + this->CurrentSelection.size;
                    return config.Colors.SameSelection;
                }
            }
        }
    }
    // color
    if ((showTypeObjects) && (settings) && (settings->positionToColorCallback))
    {
        if ((offset >= bufColor.start) && (offset <= bufColor.end))
            return bufColor.color;
        if (settings->positionToColorCallback->GetColorForBuffer(offset, this->obj->cache.Get(offset, 16, false), bufColor))
            return bufColor.color;
        // no color provided for the specific buffer --> check strings and zones
    }
    // check strings
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
        if (this->StringInfo.showAscii || this->StringInfo.showUnicode)
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
    auto buf          = this->obj->cache.Get(dli.offset, dli.textSize, false);
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
    params.Color = this->HasFocus() ? Cfg->Header.Text.Focused : Cfg->Header.Text.Normal;

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
    uint64 ofs                  = dli.offset;
    auto c                      = Cfg->Text.Inactive;
    auto n                      = dli.chNameAndSize;
    const GView::Utils::Zone* z = nullptr;

    if (HasFocus())
    {
        c = OffsetToColorZone(dli.offset);
    }
    z = this->settings->zList.OffsetToZone(dli.offset);

    if (this->Layout.lineNameSize > 0)
    {
        auto e             = n + this->Layout.lineNameSize;
        const char* nm     = nullptr;
        const char* nm_end = nullptr;

        if (z)
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
                s->Color = Cfg->Text.Inactive;
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
    auto cp    = Cfg->Text.Inactive;
    bool activ = this->HasFocus();

    if (activ)
    {
        while (dli.start < dli.end)
        {
            cp = OffsetToColor(dli.offset);
            if (selection.Contains(dli.offset))
                cp = Cfg->Selection.Editor;
            if (dli.offset == this->Cursor.currentPos)
                cp = Cfg->Cursor.Normal;
            if (StringInfo.type == StringType::Unicode)
            {
                if (dli.offset > StringInfo.middle)
                    dli.chText->Code = ' ';
                else
                    dli.chText->Code = CodePage.mapping[obj->cache.GetFromCache(((dli.offset - StringInfo.start) << 1) + StringInfo.start)];
            }
            else
            {
                dli.chText->Code = CodePage.mapping[*dli.start];
            }
            dli.chText->Color = cp;
            dli.chText++;
            dli.start++;
            dli.offset++;
        }
    }
    else
    {
        while (dli.start < dli.end)
        {
            dli.chText->Code  = CodePage.mapping[*dli.start];
            dli.chText->Color = Cfg->Text.Inactive;
            dli.chText++;
            dli.start++;
        }
    }
    this->chars.Resize((uint32) (dli.chText - this->chars.GetBuffer()));
}
void Instance::WriteLineNumbersToChars(DrawLineInfo& dli)
{
    auto c     = dli.chNumbers;
    auto cp    = Cfg->Text.Inactive;
    bool activ = this->HasFocus();
    auto ut    = (uint8) 0;
    auto sps   = dli.chText;

    while (dli.start < dli.end)
    {
        if (activ)
        {
            cp = OffsetToColor(dli.offset);

            if (selection.Contains(dli.offset))
            {
                cp = Cfg->Selection.Editor;
                if (c > this->chars.GetBuffer())
                    (c - 1)->Color = cp;
            }

            if (dli.offset == this->Cursor.currentPos)
            {
                cp = Cfg->Cursor.Normal;
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
                    dli.chText->Code = CodePage.mapping[obj->cache.GetFromCache(((dli.offset - StringInfo.start) << 1) + StringInfo.start)];
            }
            else
            {
                dli.chText->Code = CodePage.mapping[*dli.start];
            }
        }
        else
        {
            dli.chText->Code = CodePage.mapping[*dli.start];
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
        c->Color = Cfg->Text.Inactive;
        c++;
    }
    this->chars.Resize((uint32) (dli.chText - this->chars.GetBuffer()));
}
void Instance::Paint(Renderer& renderer)
{
    renderer.Clear();
    DrawLineInfo dli;
    WriteHeaders(renderer);
    for (uint32 tr = 0; tr < this->Layout.visibleRows; tr++)
    {
        dli.offset = ((uint64) this->Layout.charactersPerLine) * tr + this->Cursor.startView;
        if (dli.offset >= this->obj->cache.GetSize())
            break;
        PrepareDrawLineInfo(dli);
        WriteLineAddress(dli);
        if (this->Layout.nrCols == 0)
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
              config.Keys.ChangeValueFormatOrCP,
              tmp.Format("CP:%s", CodePages[(uint32) CodePage.id].name.data()),
              BUFFERVIEW_CMD_CHANGECODEPAGE);
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
              config.Keys.ChangeAddressMode,
              this->settings->translationMethods[this->currentAdrressMode].name,
              BUFFERVIEW_CMD_CHANGEADDRESSMODE);
    }

    // Entry point
    commandBar.SetCommand(config.Keys.GoToEntryPoint, "EntryPoint", BUFFERVIEW_CMD_GOTOEP);

    // Generic goto
    commandBar.SetCommand(config.Keys.GoToAddress, "GoTo", BUFFERVIEW_CMD_GOTO);

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
        MoveTo(this->Cursor.currentPos + this->Layout.charactersPerLine, select);
        return true;
    case Key::Up:
        if (this->Cursor.currentPos > this->Layout.charactersPerLine)
            MoveTo(this->Cursor.currentPos - this->Layout.charactersPerLine, select);
        else
            MoveTo(0, select);
        return true;
    case Key::Left:
        if (this->Cursor.currentPos > 0)
            MoveTo(this->Cursor.currentPos - 1, select);
        return true;
    case Key::Right:
        MoveTo(this->Cursor.currentPos + 1, select);
        return true;
    case Key::PageDown:
        MoveTo(this->Cursor.currentPos + this->Layout.charactersPerLine * this->Layout.visibleRows, select);
        return true;
    case Key::PageUp:
        if (this->Cursor.currentPos > this->Layout.charactersPerLine * this->Layout.visibleRows)
            MoveTo(this->Cursor.currentPos - (this->Layout.charactersPerLine * this->Layout.visibleRows), select);
        else
            MoveTo(0, select);
        return true;
    case Key::Home:
        MoveTo(this->Cursor.currentPos - (this->Cursor.currentPos - this->Cursor.startView) % this->Layout.charactersPerLine, select);
        return true;
    case Key::End:
        MoveTo(
              this->Cursor.currentPos - (this->Cursor.currentPos - this->Cursor.startView) % this->Layout.charactersPerLine +
                    this->Layout.charactersPerLine - 1,
              select);
        return true;

    case Key::Ctrl | Key::Up:
        if (this->Cursor.startView > this->Layout.charactersPerLine)
            MoveScrollTo(this->Cursor.startView - this->Layout.charactersPerLine);
        else
            MoveScrollTo(0);
        return true;
    case Key::Ctrl | Key::Down:
        MoveScrollTo(this->Cursor.startView + this->Layout.charactersPerLine);
        return true;
    case Key::Ctrl | Key::Left:
        if (this->Cursor.startView >= 1)
            MoveScrollTo(this->Cursor.startView - 1);
        return true;
    case Key::Ctrl | Key::Right:
        MoveScrollTo(this->Cursor.startView + 1);
        return true;

    case Key::Ctrl | Key::Home:
        MoveTo(0, select);
        return true;
    case Key::Ctrl | Key::End:
        MoveTo(this->obj->cache.GetSize(), select);
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

    return false;
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType != Event::Command)
        return false;
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
            this->Layout.charFormatMode =
                  static_cast<CharacterFormatMode>((((uint8) this->Layout.charFormatMode) + 1) % ((uint8) CharacterFormatMode::Count));
            UpdateViewSizes();
        }
        return true;
    case BUFFERVIEW_CMD_CHANGECODEPAGE:
        this->SetCodePage(static_cast<CodePageID>((((uint32) CodePage.id) + 1) % (uint32) CodePageID::Count));
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
    case BUFFERVIEW_CMD_GOTO:
        ShowGoToDialog();
        return true;
    }
    return false;
}
bool Instance::GoTo(uint64 offset)
{
    this->MoveTo(offset, false);
    return true;
}
bool Instance::Select(uint64 offset, uint64 size)
{
    if (offset >= this->obj->cache.GetSize())
        return false;
    auto end = offset + size;
    if ((end < offset) || (end < size))
        return false;
    if (end >= this->obj->cache.GetSize())
        return false;
    this->selection.SetSelection(0, offset, end);
    return true;
}
std::string_view Instance::GetName()
{
    return this->name;
}
bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
{
    uint32 idx = reinterpret_cast<uint32>(item);
    uint64 start, end;
    CHECK(this->selection.GetSelection(idx, start, end), false, "");
    CHECK(this->obj->cache.WriteTo(output, start, (end - start) + 1), false, "");
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
            r.WriteSingleLineText(x, y, width, "NO Selection", Cfg->Text.Inactive, TextAlignament::Center);
        }
    }
    r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    return x + width + 1;
}
int Instance::PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Pos:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(x + 4, y, width - 4, n.ToBase(this->Cursor.currentPos, this->Cursor.base), this->CursorColors.Normal);
    x += width;
    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
    // percentage

    if (this->obj->cache.GetSize() > 0)
    {
        LocalString<32> tmp;
        tmp.Format("%3u%%", (this->Cursor.currentPos + 1) * 100ULL / this->obj->cache.GetSize());
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
    auto zone = this->settings->zList.OffsetToZone(this->Cursor.currentPos);
    if (zone)
    {
        r.WriteSingleLineText(x, y, width, zone->name, this->CursorColors.Highlighted);
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
        r.WriteCharacter(x + 4, 0, this->CodePage.mapping[v_u8], this->CursorColors.Normal);
        r.WriteSingleLineText(x + 11, 0, n.ToDec(*(const char*) (&v_u8)), this->CursorColors.Normal, TextAlignament::Right);
        r.WriteSingleLineText(x + 18, 0, n.ToString(v_u8, fmt), this->CursorColors.Normal);
        r.WriteSpecialCharacter(x + 20, 0, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);
        return x + 21;
    case 2:
        r.WriteSingleLineText(x, 0, "Asc:    I8:", this->CursorColors.Highlighted);
        r.WriteSingleLineText(x, 1, "Hex:    U8:", this->CursorColors.Highlighted);
        r.WriteCharacter(x + 4, 0, this->CodePage.mapping[v_u8], this->CursorColors.Normal);
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
        r.WriteCharacter(x + 4, 0, this->CodePage.mapping[v_u8], this->CursorColors.Normal);
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
    const uint32 v_u32 =
          (((uint32_t) buffer[0]) << 24) | (((uint32_t) buffer[1]) << 16) | (((uint32_t) buffer[2]) << 8) | (((uint32_t) buffer[3]));
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
        this->CursorColors.Normal      = Cfg->Text.Normal;
        this->CursorColors.Line        = Cfg->Lines.Normal;
        this->CursorColors.Highlighted = Cfg->Text.Highlighted;
    } else
    {
        this->CursorColors.Normal      = Cfg->Text.Inactive;
        this->CursorColors.Line        = Cfg->Lines.Inactive;
        this->CursorColors.Highlighted = Cfg->Text.Inactive;
    } 
    r.Clear();
    auto buf = this->obj->cache.Get(this->Cursor.currentPos, 8, false);
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
        mpInfo.bufferOffset += Cursor.startView;
        if (mpInfo.bufferOffset >= this->obj->cache.GetSize())
            mpInfo.location = MouseLocation::Outside;
    }
}
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if ((mpInfo.location == MouseLocation::OnView) && (mpInfo.bufferOffset != Cursor.currentPos))
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
    if ((mpInfo.location == MouseLocation::OnView) && (mpInfo.bufferOffset != Cursor.currentPos))
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
    GoToAddress

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
        value = this->Cursor.base == 16;
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
    case PropertyID::HighlightSelection:
        value = this->CurrentSelection.highlight;
        return true;
    case PropertyID::CodePage:
        value = (uint64) this->CodePage.id;
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
    case PropertyID::GoToAddress:
        value = config.Keys.GoToAddress;
        return true;
    case PropertyID::AddressType:
        value = this->currentAdrressMode;
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
        this->Cursor.base = std::get<bool>(value) ? 16 : 10;
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
    case PropertyID::HighlightSelection:
        this->CurrentSelection.highlight = std::get<bool>(value);
        return true;
    case PropertyID::CodePage:
        this->SetCodePage(static_cast<CodePageID>(std::get<uint64>(value)));
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
    case PropertyID::GoToAddress:
        config.Keys.GoToAddress = std::get<AppCUI::Input::Key>(value);
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
        SelectionEditor dlg(&this->selection, idx, this->settings.get(), this->obj->cache.GetSize());
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
    CodePage.stringList.Clear();
    for (uint32 idx = 0; idx < (uint32) CodePageID::Count; idx++)
    {
        if (idx > 0)
            CodePage.stringList.AddChar(',');
        CodePage.stringList.Add(CodePages[idx].name.data(), (uint32) CodePages[idx].name.size());
        CodePage.stringList.AddChar('=');
        CodePage.stringList.AddFormat("%u", idx);
    }

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
        { BT(PropertyID::CodePage), "Display", "CodePage", PropertyType::List, CodePage.stringList.ToStringView() },

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
        { BT(PropertyID::GoToAddress), "Shortcuts", "Go To Address", PropertyType::Key },

    };
}
#undef BT