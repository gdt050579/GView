#include "DissasmViewer.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <cassert>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Config Instance::config;

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* _settings)
    : name(name), obj(obj), settings(nullptr)
{
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::DarkBlue });
    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        //_settings->data = nullptr; //TODO: is this ok?
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
    this->Layout.textSize                        = 1;
    this->Layout.totalCharactersPerLine          = 1;
    this->Layout.startingTextLineOffset          = 5;
    this->Layout.structuresInitialCollapsedState = true;

    this->codePage = CodePageID::DOS_437;
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

// bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
//{
//     NOT_IMPLEMENTED(false);
// }

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    this->CursorColors.Normal      = config.Colors.Normal;
    this->CursorColors.Highlighted = config.Colors.Highlight;
    if (!this->HasFocus())
    {
        this->CursorColors.Normal      = config.Colors.Inactive;
        this->CursorColors.Highlighted = config.Colors.Inactive;
    }

    renderer.Clear(' ', this->CursorColors.Normal);

    int x = 0;
    switch (height)
    {
    case 0:
        break;
    case 1:
        x = PrintCursorPosInfo(x, 0, 16, false, renderer);
        x = PrintCursorLineInfo(x, 0, 16, false, renderer);
        break;
    default:
        PrintCursorPosInfo(x, 0, 16, false, renderer);
        PrintCursorLineInfo(x, 1, 16, false, renderer);
        break;
    }
}

int Instance::PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Pos:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(
          x + 4, y, width - 4, n.ToBase(this->Cursor.currentPos % Layout.textSize, this->Cursor.base), this->CursorColors.Normal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    if (this->obj->GetData().GetSize() > 0)
    {
        LocalString<32> tmp;
        tmp.Format("%3u%%", (this->Cursor.currentPos + 1) * 100ULL / this->obj->GetData().GetSize());
        r.WriteSingleLineText(x, y, tmp.GetText(), this->CursorColors.Normal);
    }
    else
    {
        r.WriteSingleLineText(x, y, "----", this->CursorColors.Line);
    }
    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    return x + 5;
}

int Instance::PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Line:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(
          x + 5, y, width - 4, n.ToString(this->Cursor.currentPos / Layout.textSize, NumericFormatFlags::None), this->CursorColors.Normal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    return x + 5;
}

bool Instance::PrepareDrawLineInfo(DrawLineInfo& dli)
{
    if (dli.recomputeOffsets)
    {
        this->chars.Resize(Layout.totalCharactersPerLine);
        dli.recomputeOffsets      = false;
        dli.currentLineFromOffset = (uint32) (this->Cursor.startView / this->Layout.textSize);
    }

    // TODO: send multiple lines to be drawn with each other instead of searching line by line
    //          for example: search how many line from the text needs to be written -> write all of thems

    uint32 currentLineIndex = dli.currentLineFromOffset + dli.lineToDraw;
    if (!settings->parseZones.empty())
    {
        auto& zones       = settings->parseZones;
        uint32 zonesCount = (uint32) settings->parseZones.size();
        // TODO: optimization -> instead of search every time keep the last zone index inside memmory and search from there
        for (uint32 i = 0; i < zonesCount; i++)
        {
            if ((currentLineIndex >= zones[i]->startLineIndex && currentLineIndex < zones[i]->endingLineIndex))
            {
                // struct
                dli.actualLineToDraw     = currentLineIndex - zones[i]->startLineIndex;
                dli.lastZoneIndexToReset = i;
                switch (zones[i]->zoneType)
                {
                case DissasmParseZoneType::StructureParseZone:
                    return DrawStructureZone(dli, (DissasmParseStructureZone*) zones[i].get());

                // TODO:
                case DissasmParseZoneType::DissasmCodeParseZone:
                    return DrawStructureZone(dli, (DissasmParseStructureZone*) zones[i].get());
                default:
                    return false;
                }
            }
            else
            {
                dli.actualLineToDraw = currentLineIndex + zones[i]->textLinesOffset - zones[i]->endingLineIndex;
                if (i + 1 >= zonesCount)
                {
                    return WriteTextLineToChars(dli);
                    break;
                }
                if (currentLineIndex < zones[i + 1]->startLineIndex)
                {
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

inline void GView::View::DissasmViewer::Instance::UpdateCurrentZoneIndex(
      const DissasmType& cType, DissasmParseStructureZone* zone, bool increaseOffset)
{
    if (cType.primaryType >= InternalDissasmType::UInt8 && cType.primaryType <= InternalDissasmType::Int64)
    {
        // Uint8 - index 0 -> 1 byte, Int8 -> index 4 -> 1 byte
        uint32 val = ((uint8) cType.primaryType + 1u) % 4;
        if (increaseOffset)
            zone->textFileOffset += val;
        else
            zone->textFileOffset -= val;
        // zone.textFileOffset += (increaseOffset ? 1 : -1) * (((int) cType.primaryType + 1u) % 4);
    }
}

bool Instance::DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone)
{
    if (structureZone->structureIndex == structureZone->extendedSize)
    {
        while (structureZone->levels.size() > 1)
        {
            structureZone->types.pop_back();
            structureZone->levels.pop_back();
        }
        structureZone->levels.pop_back();
        structureZone->levels.push_back(0);
        structureZone->structureIndex = 0;
        structureZone->textFileOffset = structureZone->initalTextFileOffset;
    }

    uint32 levelToReach    = dli.actualLineToDraw;
    int16& levelNow        = structureZone->structureIndex;
    dli.wasInsideStructure = true;
    // TODO: consider if this value can be biffer than int16
    bool increaseOffset = levelNow < (int16) levelToReach;

    // levelNow     = 0;
    // levelToReach = 47;

    // TODO: consider optimization if the levelToReach > levelNow and levelToReach should reach close to 0 then it all should be reset to 0
    while (levelNow < (int16) levelToReach)
    {
        const DissasmType& currentType = structureZone->types.back();
        int currentLevel               = structureZone->levels.back();

        switch (currentType.primaryType)
        {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel < currentType.internalTypes.size())
            {
                UpdateCurrentZoneIndex(currentType.internalTypes[currentLevel], structureZone, true);
                structureZone->types.push_back(currentType.internalTypes[currentLevel]);
                structureZone->levels.push_back(0);
            }
            else
            {
                structureZone->types.pop_back();
                structureZone->levels.pop_back();
                currentLevel = structureZone->levels.back() + 1;
                structureZone->levels.pop_back();
                structureZone->levels.push_back(currentLevel);
                continue;
            }
            break;
        default:
            // for basic types remove them and go back
            structureZone->types.pop_back();
            structureZone->levels.pop_back();
            currentLevel = structureZone->levels.back() + 1;
            structureZone->levels.pop_back();
            structureZone->levels.push_back(currentLevel);
            continue;
            break;
        }

        levelNow++;
    }

    // levelNow     = 47;
    // levelToReach = 0;

    bool isFromBreak = false;

    while (levelNow > (int16) levelToReach)
    {
        const DissasmType& currentType = structureZone->types.back();
        int currentLevel               = structureZone->levels.back();

        switch (currentType.primaryType)
        {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel > 0)
            {
                structureZone->levels.pop_back();
                currentLevel--;
                structureZone->levels.push_back(currentLevel);
                structureZone->types.push_back(currentType.internalTypes[currentLevel]);
                int32 anteiorLevel = (int32) currentType.internalTypes[currentLevel].internalTypes.size();
                if (anteiorLevel > 0)
                    anteiorLevel--;
                structureZone->levels.push_back(anteiorLevel);
                isFromBreak = false;
            }
            else
            {
                if (isFromBreak)
                {
                    isFromBreak = false;
                    break;
                }
                UpdateCurrentZoneIndex(structureZone->types.back(), structureZone, false);
                structureZone->types.pop_back();
                structureZone->levels.pop_back();
                continue;
            }
            break;
        default:
            // for basic types remove them and go back
            UpdateCurrentZoneIndex(structureZone->types.back(), structureZone, false);
            structureZone->types.pop_back();
            structureZone->levels.pop_back();
            isFromBreak = true;
            continue;
            break;
        }

        levelNow--;
    }

    WriteStructureToScreen(dli, structureZone->types.back(), (uint32) (structureZone->levels.size() - 1) * 4, structureZone);
    // if (increaseOffset)
    //    UpdateCurrentZoneIndex(structureZone->types.back(), zone, true);

    // assert(structureZone->levels.size() == 1);
    // assert(structureZone->levels.back() == 0);
    // assert(structureZone->textFileOffset == structureZone->initalTextFileOffset);

    return true;
}

bool Instance::WriteStructureToScreen(
      DrawLineInfo& dli, const DissasmType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone)
{
    ColorPair normalColor = config.Colors.Normal;

    dli.chNameAndSize = this->chars.GetBuffer();
    dli.chText        = dli.chNameAndSize + Layout.startingTextLineOffset;

    if (spaces > 0)
    {
        for (uint32 i = 0; i < spaces; i++)
        {
            dli.chText->Code  = codePage[' '];
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
        RegisterStructureCollapseButton(
              dli, structureZone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, structureZone);
        break;
    default:
        return false;
    }

    if (typeSize > 0)
    {
        // TODO: check textFileOffset!!
        auto buf = this->obj->GetData().Get(structureZone->textFileOffset - typeSize, typeSize, false);

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

    size_t buffer_size = dli.chText - dli.chNameAndSize;
    auto bufferToDraw  = CharacterView{ chars.GetBuffer(), buffer_size };

    // this->chars.Resize((uint32) (dli.chText - dli.chNameAndSize));
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.lineToDraw + 1, bufferToDraw, false);
    return true;
}

void Instance::RegisterStructureCollapseButton(DrawLineInfo& dli, SpecialChars c, ParseZone* zone)
{
    ButtonsData bData = { 3, (int) (dli.lineToDraw + 1), c, config.Colors.DataTypeColor, 3, zone };
    MyLine.buttons.push_back(bData);
}

void Instance::AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd)
{
    size_t length = stringToAdd.size();
    for (uint32 i = 0; i < length; i++)
    {
        dli.chText->Code  = codePage[stringToAdd[i]];
        dli.chText->Color = pair;
        dli.chText++;
    }
}

void Instance::AddStringToChars(DrawLineInfo& dli, ColorPair pair, const char* fmt, ...)
{
    // TODO: increase and use more size
    char buffer[256];
    buffer[0] = '\0';
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, 255, fmt, args);
    va_end(args);

    size_t length = strlen(buffer);
    for (uint32 i = 0; i < length; i++)
    {
        dli.chText->Code  = codePage[buffer[i]];
        dli.chText->Color = pair;
        dli.chText++;
    }
}

bool Instance::WriteTextLineToChars(DrawLineInfo& dli)
{
    uint64 textFileOffset = ((uint64) this->Layout.textSize) * dli.actualLineToDraw;

    if (textFileOffset >= this->obj->GetData().GetSize())
        return false;

    auto buf          = this->obj->GetData().Get(textFileOffset, Layout.textSize, false);
    dli.start         = buf.GetData();
    dli.end           = buf.GetData() + buf.GetLength();
    dli.chNameAndSize = this->chars.GetBuffer() + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    bool activ     = this->HasFocus();
    auto textColor = activ ? config.Colors.Normal : config.Colors.Inactive;

    while (dli.start < dli.end)
    {
        dli.chText->Code  = codePage[*dli.start];
        dli.chText->Color = textColor;
        dli.chText++;
        dli.start++;
    }

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.lineToDraw + 1, chars, true);
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

bool Instance::ShowGoToDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowCopyDialog()
{
    NOT_IMPLEMENTED(false);
}

void Instance::OnAfterResize(int newWidth, int newHeight)
{
    this->RecomputeDissasmLayout();
}

void Instance::OnStart()
{
    this->RecomputeDissasmLayout();

    // from dli, may need to be recomputed
    const uint32 textSize = Layout.textSize;

    uint32 lastEndMinusLastOffset = 0;
    uint32 lastZoneEndingIndex    = 0;
    uint16 currentIndex           = 0;

    for (const auto& mapping : this->settings->dissasmTypeMapped)
    {
        std::unique_ptr<DissasmParseStructureZone> parseZone = std::make_unique<DissasmParseStructureZone>();
        parseZone->startLineIndex                            = (uint32) (mapping.first / textSize);
        if (parseZone->startLineIndex < lastZoneEndingIndex)
            parseZone->startLineIndex = lastZoneEndingIndex;
        parseZone->endingLineIndex = parseZone->startLineIndex + 1;
        parseZone->isCollapsed     = Layout.structuresInitialCollapsedState;
        parseZone->extendedSize    = mapping.second.GetExpandedSize() - 1;
        parseZone->textLinesOffset = parseZone->startLineIndex - lastEndMinusLastOffset;
        parseZone->dissasmType     = mapping.second;
        parseZone->levels.push_back(0);
        parseZone->types.push_back(mapping.second);
        parseZone->structureIndex       = 0;
        parseZone->textFileOffset       = mapping.first;
        parseZone->initalTextFileOffset = mapping.first;
        parseZone->zoneID               = currentIndex++;
        parseZone->zoneType             = DissasmParseZoneType::StructureParseZone;

        if (!parseZone->isCollapsed)
            parseZone->endingLineIndex += parseZone->extendedSize;

        lastEndMinusLastOffset = parseZone->endingLineIndex + parseZone->textLinesOffset;
        lastZoneEndingIndex    = parseZone->endingLineIndex;
        settings->parseZones.push_back(std::move(parseZone));
    }

    // TODO: rethink
    if (settings->defaultLanguage == DissasemblyLanguage::Default)
        settings->defaultLanguage = DissasemblyLanguage::x86;

    // TODO: fix dissasemblyZones to be where they belong not really after structuress

    for (const auto& dissasmZone : settings->dissasemblyZones)
    {
        std::unique_ptr<DissasmCodeZone> codeZone = std::make_unique<DissasmCodeZone>();
        codeZone->zoneDetails                     = dissasmZone.second;
        codeZone->startLineIndex                  = (uint32) (dissasmZone.first / textSize);
        if (codeZone->startLineIndex < lastZoneEndingIndex)
            codeZone->startLineIndex = lastZoneEndingIndex;
        codeZone->endingLineIndex = codeZone->startLineIndex + 1;
        codeZone->textLinesOffset = codeZone->startLineIndex - lastEndMinusLastOffset;
        codeZone->zoneID          = currentIndex++;
        codeZone->zoneType        = DissasmParseZoneType::DissasmCodeParseZone;
    }
}

void GView::View::DissasmViewer::Instance::RecomputeDissasmLayout()
{
    this->Layout.visibleRows            = this->GetHeight() - 1;
    this->Layout.totalCharactersPerLine = this->GetWidth() - 1;
    this->Layout.textSize               = this->Layout.totalCharactersPerLine - this->Layout.startingTextLineOffset;
}

void Instance::ChangeZoneCollapseState(ParseZone* zoneToChange)
{
    int16 sizeToAdjust;
    sizeToAdjust = zoneToChange->extendedSize;
    if (!zoneToChange->isCollapsed)
        sizeToAdjust *= -1;
    zoneToChange->isCollapsed = !zoneToChange->isCollapsed;
    zoneToChange->endingLineIndex += sizeToAdjust;

    bool foundZone = false;
    for (auto& zone : settings->parseZones)
    {
        if (foundZone)
        {
            zone->startLineIndex += sizeToAdjust;
            zone->endingLineIndex += sizeToAdjust;
        }
        if (zoneToChange->zoneID == zone->zoneID)
            foundZone = true;
    }

    // TODO: search for following zones and update their size
}

Instance::~Instance()
{
    while (!settings->buffersToDelete.empty())
    {
        char* bufferToDelete = settings->buffersToDelete.back();
        settings->buffersToDelete.pop_back();
        delete bufferToDelete;
    }
}