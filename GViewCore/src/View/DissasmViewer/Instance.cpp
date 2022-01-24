#include "DissasmViewer.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <cassert>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr uint32 PROP_ID_ADD_NEW_TYPE     = 1;
constexpr uint32 PROP_ID_DISSASM_LANGUAGE = 2;

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

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* _settings)
    : name(name), obj(obj), settings(nullptr)
{
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::DarkBlue });
    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();

    this->Cursor.currentPos = 0;
    this->Cursor.startView  = 0;
    this->Cursor.base       = 10;

    this->CursorColors.Normal      = config.Colors.Normal;
    this->CursorColors.Highlighted = config.Colors.Highlight;
    this->CursorColors.Line        = config.Colors.Line;

    this->Layout.visibleRows                     = 1;
    this->Layout.charactersPerLine               = 1;
    this->Layout.startingTextLineOffset          = 5;
    this->Layout.structuresInitialCollapsedState = false;

    RecomputeDissasmLayout();
}

bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        value = config.Keys.AddNewType;
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        value = (uint64) (settings->defaultLanguage);
        return true;
    }
    return false;
}

bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        config.Keys.AddNewType = std::get<Key>(value);
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        settings->defaultLanguage = static_cast<DissamblyLanguage>(std::get<uint64>(value));
        return true;
    }
    return false;
}

void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}

bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
    // return propertyID == PROP_ID_DISSASM_LANGUAGE;
}

const vector<Property> Instance::GetPropertiesList()
{
    return {
        { PROP_ID_ADD_NEW_TYPE, "Shortcuts", "Key addind new data type", PropertyType::Key },
        { PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, "x86=1,x64=2,JavaByteCode=3,IL=4" },
    };
}

bool Instance::GoTo(uint64 offset)
{
    return true;
}

bool Instance::Select(uint64 offset, uint64 size)
{
    return true;
}

std::string_view Instance::GetName()
{
    return "DissasmView";
}

bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
{
    NOT_IMPLEMENTED(false);
}

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    this->CursorColors.Normal      = config.Colors.Normal;
    this->CursorColors.Line        = config.Colors.Line;
    this->CursorColors.Highlighted = config.Colors.Highlight;
    if (!this->HasFocus())
    {
        this->CursorColors.Normal      = config.Colors.Inactive;
        this->CursorColors.Highlighted = config.Colors.Inactive;
    }
    renderer.Clear(' ', this->CursorColors.Normal);
    int x = 0;
    x     = PrintCursorPosInfo(x, 0, 16, false, renderer);
}

int Instance::PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Pos:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(x + 4, y, width - 4, n.ToBase(this->Cursor.currentPos, this->Cursor.base), this->CursorColors.Normal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

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

bool Instance::PrepareDrawLineInfo(DrawLineInfo& dli)
{
    if (dli.recomputeOffsets)
    {
        dli.lineOffset = Layout.startingTextLineOffset;
        auto width     = (uint32) this->GetWidth();
        dli.textSize   = width - (1 + dli.lineOffset);

        this->chars.Resize((uint32) dli.textFileOffset + dli.textSize);
        dli.recomputeOffsets      = false;
        dli.currentLineFromOffset = this->Cursor.startView / this->Layout.charactersPerLine;
    }

    // TODO: send multiple lines to be drawn with each other instead of searching line by line
    //          for example: search how many line from the text needs to be written -> write all of thems

    uint32 currentLineIndex = dli.currentLineFromOffset + dli.lineToDraw;
    if (!settings->parseZones.empty())
    {
        auto& zones       = settings->parseZones;
        uint32 zonesCount = settings->parseZones.size();
        // TODO: optimization -> instead of search every time keep the last zone index inside memmory and search from there
        for (uint32 i = 0; i < zonesCount; i++)
        {
            if ((currentLineIndex >= zones[i].startLineIndex && currentLineIndex < zones[i].endingLineIndex))
            {
                // struct
                dli.actualLineToDraw     = currentLineIndex - zones[i].startLineIndex;
                dli.lastZoneIndexToReset = i;
                return PrepareStructureViewToDraw(dli, zones[i]);
            }
            else
            {
                dli.actualLineToDraw = currentLineIndex + zones[i].textLinesOffset - zones[i].endingLineIndex;
                if (i + 1 >= zonesCount)
                {
                    return WriteTextLineToChars(dli);
                    break;
                }
                if (currentLineIndex < zones[i + 1].startLineIndex)
                {
                    currentLineIndex = currentLineIndex;
                    return WriteTextLineToChars(dli);
                }
            }
        }
    }
    else
    {
        dli.actualLineToDraw = currentLineIndex;
        return WriteTextLineToChars(dli);
    }

    return true;
}

bool Instance::PrepareStructureViewToDraw(DrawLineInfo& dli, ParseZone& zone)
{
    if (zone.structureIndex == zone.extendedSize)
    {
        while (zone.levels.size() > 1)
        {
            zone.types.pop_back();
            zone.levels.pop_back();
        }
        zone.levels.pop_back();
        zone.levels.push_back(0);
        zone.structureIndex = 0;
        zone.textFileOffset = zone.initalTextFileOffset;
    }

    uint32 levelToReach    = dli.actualLineToDraw;
    int16& levelNow        = zone.structureIndex;
    dli.wasInsideStructure = true;

    //levelNow     = 0;
    //levelToReach = 47;

    while (levelNow < levelToReach)
    {
        const DissasmType& currentType = zone.types.back();
        int currentLevel               = zone.levels.back();

        switch (currentType.primaryType)
        {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel < currentType.internalTypes.size())
            {
                zone.types.push_back(currentType.internalTypes[currentLevel]);
                zone.levels.push_back(0);
            }
            else
            {
                zone.types.pop_back();
                zone.levels.pop_back();
                currentLevel = zone.levels.back() + 1;
                zone.levels.pop_back();
                zone.levels.push_back(currentLevel);
                continue;
            }
            break;
        default:
            // for basic types remove them and go back
            zone.types.pop_back();
            zone.levels.pop_back();
            currentLevel = zone.levels.back() + 1;
            zone.levels.pop_back();
            zone.levels.push_back(currentLevel);
            continue;
            break;
        }

        levelNow++;
    }

    //levelNow     = 47;
    //levelToReach = 0;

    bool isFromBreak = true;

    while (levelNow > levelToReach)
    {
        int c                          = zone.types.size();
        const DissasmType& currentType = zone.types.back();
        int currentLevel               = zone.levels.back();

        switch (currentType.primaryType)
        {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel > 0)
            {
                zone.levels.pop_back();
                currentLevel--;
                zone.levels.push_back(currentLevel);
                zone.types.push_back(currentType.internalTypes[currentLevel]);
                int32 anteiorLevel = currentType.internalTypes[currentLevel].internalTypes.size();
                if (anteiorLevel > 0)
                    anteiorLevel--;
                zone.levels.push_back(anteiorLevel);
                isFromBreak = false;
            }
            else
            {
                if (isFromBreak)
                {
                    isFromBreak = false;
                    break;
                }
                zone.types.pop_back();
                zone.levels.pop_back();
                continue;
            }
            break;
        default:
            // for basic types remove them and go back
            zone.types.pop_back();
            zone.levels.pop_back();
            isFromBreak = true;
            continue;
            break;
        }

        levelNow--;
    }

    //assert(zone.levels.size() == 1);
    //assert(zone.levels.back() == 0);


    WriteStructureToScreen(dli, zone.types.back(), (zone.levels.size() - 1) * 4, zone);
    return true;
}

bool Instance::WriteStructureToScreen(DrawLineInfo& dli, const DissasmType& currentType, int spaces, ParseZone& zone)
{
    ColorPair normalColor = config.Colors.Normal;

    dli.chNameAndSize = this->chars.GetBuffer();
    dli.chText        = dli.chNameAndSize + dli.lineOffset;

    if (spaces > 0)
    {
        for (int i = 0; i < spaces; i++)
        {
            dli.chText->Code  = CodePage_437[' '];
            dli.chText->Color = normalColor;
            dli.chText++;
        }
    }

    uint32 typeSize    = 0;
    bool isSignedValue = false;

    switch (currentType.primaryType)
    {
    case GView::View::DissasmViewer::InternalDissasmType::UInt8:
        typeSize      = 1;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt16:
        typeSize      = 2;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt32:
        typeSize      = 4;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt64:
        typeSize      = 8;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int8:
        typeSize      = 1;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int16:
        typeSize      = 2;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int32:
        typeSize      = 4;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int64:
        typeSize      = 8;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::AsciiZ:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Utf16Z:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Utf32Z:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UnidimnsionalArray:
        AddStringToChars(dli, config.Colors.StructureColor, "Array[%u] ", currentType.width);
        AddStringToChars(dli, config.Colors.Normal, "%s", currentType.name.data());
        break;
    case GView::View::DissasmViewer::InternalDissasmType::BidimensionalArray:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UserDefined:
        AddStringToChars(dli, config.Colors.StructureColor, "Structure ");
        AddStringToChars(dli, config.Colors.Normal, "%s", currentType.name.data());
        RegisterStructureCollapseButton(dli, SpecialChars::TriangleRight, zone);
        break;
    default:
        return false;
    }

    if (typeSize > 0)
    {
        // TODO
        auto buf = this->obj->cache.Get(zone.textFileOffset, typeSize, false);
        zone.textFileOffset += typeSize;

        char buffer[9];
        memset(buffer, '\0', 9);
        for (uint32 i = 0; i < typeSize; i++)
            buffer[i] = buf[i];

        if (isSignedValue)
        {
            int64 value = *(int64*) buffer;
            AddStringToChars(dli, normalColor, "%s: %lli", currentType.name.data(), value);
        }
        else
        {
            uint64 value = *(uint64*) buffer;
            AddStringToChars(dli, normalColor, "%s: %llu", currentType.name.data(), value);
        }
    }

    this->chars.Resize((uint32) (dli.chText - dli.chNameAndSize));
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.lineToDraw + 1, chars, false);
    // WriteTextLineToChars(dli, false);
    return true;
}

void Instance::RegisterStructureCollapseButton(DrawLineInfo& dli, SpecialChars c, ParseZone& zone)
{
    ButtonsData bData = { 3, dli.lineToDraw + 1, c, config.Colors.DataTypeColor, 3, zone };
    MyLine.buttons.push_back(bData);
}

void Instance::AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd)
{
    size_t length = stringToAdd.size();
    for (uint32 i = 0; i < length; i++)
    {
        dli.chText->Code  = CodePage_437[stringToAdd[i]];
        dli.chText->Color = pair;
        dli.chText++;
    }
}

void Instance::AddStringToChars(DrawLineInfo& dli, ColorPair pair, const char* fmt, ...)
{
    char buffer[256];
    buffer[0] = '\0';
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, 255, fmt, args);
    va_end(args);

    size_t length = strlen(buffer);
    for (uint32 i = 0; i < length; i++)
    {
        dli.chText->Code  = CodePage_437[buffer[i]];
        dli.chText->Color = pair;
        dli.chText++;
    }
}

void Instance::FillRestWithSpaces(DrawLineInfo& dli)
{
    size_t toFillSize = dli.chText - this->chars.GetBuffer();
    if (toFillSize < dli.textSize)
    {
        toFillSize = dli.textSize - toFillSize;
        for (uint32 i = 0; i < toFillSize; i++)
        {
            dli.chText->Code  = CodePage_437[' '];
            dli.chText->Color = this->config.Colors.Normal;
            dli.chText++;
        }
    }
}

bool Instance::WriteTextLineToChars(DrawLineInfo& dli)
{
    dli.textFileOffset = ((uint64) this->Layout.charactersPerLine) * dli.actualLineToDraw;

    if (dli.textFileOffset >= this->obj->cache.GetSize())
        return false;

    auto buf          = this->obj->cache.Get(dli.textFileOffset, dli.textSize, false);
    dli.start         = buf.GetData();
    dli.end           = buf.GetData() + buf.GetLength();
    dli.chNameAndSize = this->chars.GetBuffer() + dli.lineOffset;
    dli.chText        = dli.chNameAndSize;

    auto cp    = config.Colors.Inactive;
    bool activ = this->HasFocus();

    if (activ)
    {
        while (dli.start < dli.end)
        {
            cp = config.Colors.Normal; // OutsideZone;
            // cp = OffsetToColor(dli.offset);
            // if (selection.Contains(dli.textFileOffset))
            //    cp = config.Colors.Selection;
            if (dli.textFileOffset == this->Cursor.currentPos)
                cp = config.Colors.Cursor;
            dli.chText->Code  = CodePage_437[*dli.start];
            dli.chText->Color = cp;
            dli.chText++;
            dli.start++;
            dli.textFileOffset++;
        }
    }
    else
    {
        while (dli.start < dli.end)
        {
            dli.chText->Code  = CodePage_437[*dli.start];
            dli.chText->Color = config.Colors.Inactive;
            dli.chText++;
            dli.start++;
        }
    }

    this->chars.Resize((uint32) (dli.textSize));
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.lineToDraw + 1, chars, false);
    return true;
}

void Instance::Paint(AppCUI::Graphics::Renderer& renderer)
{
    if (!MyLine.buttons.empty())
        MyLine.buttons.clear();
    if (HasFocus())
        renderer.Clear(' ', config.Colors.Normal);
    else
        renderer.Clear(' ', config.Colors.Inactive);

    DrawLineInfo dli(renderer);
    for (uint32 tr = 0; tr < this->Layout.visibleRows; tr++)
    {
        dli.lineToDraw = tr;
        if (!PrepareDrawLineInfo(dli))
            break;

        // uint64 val2 = ((uint64) tr - 1) * Layout.charactersPerLine;
        // if (dli.viewOffset <= Cursor.currentPos && Cursor.currentPos < nextOffset)
        //{
        //    uint64 val                   = this->Cursor.currentPos % dli.textSize + dli.lineOffset;
        //    chars.GetBuffer()[val].Color = config.Colors.Cursor;
        //}
        // auto asdasdasd = CharacterView{ chars.GetBuffer(), 10 };
        // srenderer.WriteSingleLineText(0, tr + 1, asdasdasd, DefaultColorPair);

        // chars.Resize(10);
        // renderer.WriteSingleLineCharacterBuffer(0, tr + 1, chars, false);
    }

    if (!MyLine.buttons.empty())
    {
        for (const auto& btn : MyLine.buttons)
            renderer.WriteSpecialCharacter(btn.x, btn.y, btn.c, btn.color);
    }
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(config.Keys.AddNewType, "AddNewType", 12345);

    return false;
}

bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        if (ID == 12345)
        {
            Dialogs::MessageBox::ShowNotification("Info", "OK!");
            return true;
        }
    }

    return false;
}

void Instance::OnAfterResize(int newWidth, int newHeight)
{
    this->RecomputeDissasmLayout();
}

void Instance::OnStart()
{
    this->RecomputeDissasmLayout();

    // from dli, may need to be recomputed
    uint32 lineOffset = Layout.startingTextLineOffset;
    uint32 width      = (uint32) this->GetWidth();
    uint32 textSize   = width - (1 + lineOffset);

    uint32 lastEndMinusLastOffset = 0;
    uint16 currentIndex           = 0;

    for (const auto& mapping : this->settings->dissasmTypeMapped)
    {
        ParseZone parseZone;
        parseZone.startLineIndex  = mapping.first / (uint64) textSize;
        parseZone.endingLineIndex = parseZone.startLineIndex + 1;
        parseZone.isCollapsed     = Layout.structuresInitialCollapsedState;
        parseZone.extendedSize    = mapping.second.GetExpandedSize() - 1;
        parseZone.textLinesOffset = parseZone.startLineIndex - lastEndMinusLastOffset;
        parseZone.dissasmType     = mapping.second;
        parseZone.levels.push_back(0);
        parseZone.types.push_back(mapping.second);
        parseZone.structureIndex       = 0;
        parseZone.textFileOffset       = mapping.first;
        parseZone.initalTextFileOffset = mapping.first;
        parseZone.structureID          = currentIndex++;

        if (!parseZone.isCollapsed)
            parseZone.endingLineIndex += parseZone.extendedSize;

        lastEndMinusLastOffset = parseZone.endingLineIndex + parseZone.textLinesOffset;
        settings->parseZones.push_back(parseZone);
    }
}

void GView::View::DissasmViewer::Instance::RecomputeDissasmLayout()
{
    this->Layout.visibleRows       = this->GetHeight() - 1;
    this->Layout.charactersPerLine = this->GetWidth() - 1 - this->Layout.startingTextLineOffset;
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
    if ((xPoz >= Layout.startingTextLineOffset) && (xPoz < Layout.startingTextLineOffset + Layout.charactersPerLine))
    {
        mpInfo.location     = MouseLocation::OnView;
        mpInfo.bufferOffset = yPoz * Layout.charactersPerLine + xPoz - Layout.startingTextLineOffset;
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
    else if (mpInfo.location == MouseLocation::Outside && !MyLine.buttons.empty())
    {
        for (const auto& btn : MyLine.buttons)
            if (btn.x == x && btn.y == y)
            {
                ChangeZoneCollapseState(btn.zone);
                break;
            }
    }
}

void Instance::ChangeZoneCollapseState(ParseZone& zoneToChange)
{
    int16 sizeToAdjust;
    sizeToAdjust = zoneToChange.extendedSize;
    if (!zoneToChange.isCollapsed)
        sizeToAdjust *= -1;
    zoneToChange.isCollapsed = !zoneToChange.isCollapsed;
    zoneToChange.endingLineIndex += sizeToAdjust;

    bool foundZone = false;
    for (auto& zone : settings->parseZones)
    {
        if (foundZone)
        {
            zone.startLineIndex += sizeToAdjust;
            zone.endingLineIndex += sizeToAdjust;
        }
        if (zoneToChange.structureID == zone.structureID)
            foundZone = true;
    }

    // TODO: search for following zones and update their size
}

bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    bool select = ((keyCode & Key::Shift) != Key::None);
    if (select)
        keyCode = static_cast<Key>((uint32) keyCode - (uint32) Key::Shift);

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
    };
    return false;
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
    /*if (select)
        sidx = this->selection.BeginSelection(this->Cursor.currentPos);*/
    if ((offset >= this->Cursor.startView) && (offset < this->Cursor.startView + sz))
    {
        this->Cursor.currentPos = offset;
        // if ((select) && (sidx >= 0))
        //{
        //    this->selection.UpdateSelection(sidx, offset);
        //    UpdateCurrentSelection();
        //    return; // nothing to do ... already in visual space
        //}
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
    /* if ((select) && (sidx >= 0))
     {
         this->selection.UpdateSelection(sidx, offset);
         UpdateCurrentSelection();
     }*/
}