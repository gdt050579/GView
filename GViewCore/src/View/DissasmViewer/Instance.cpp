#include <array>

#include "DissasmViewer.hpp"
#include "DissasmKeys.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <cassert>
#include <unordered_map>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr size_t DISSASM_MAX_STORED_JUMPS = 5;

const std::array<AsmFunctionDetails, 4> KNOWN_FUNCTIONS = {
    { { "WriteFile",
        { { "hFile", "HANDLE" },
          { "lpBuffer", "LPCVOID" },
          { "nNumberOfBytesToWrite", "DWORD" },
          { "lpNumberOfBytesWritten", "LPDWORD" },
          { "lpOverlapped", "LPOVERLAPPED" } } },
      { "CloseHandle", { { "hObject", "HANDLE" } } },
      { "CreateFileW",
        { { "lpFileName", "LPCWSTR" },
          { "dwDesiredAccess", "DWORD" },
          { "dwShareMode", "DWORD" },
          { "lpSecurityAttributes", "LPSECURITY_ATTRIBUTES" },
          { "dwCreationDisposition", "DWORD" },
          { "dwFlagsAndAttributes", "DWORD" },
          { "hTemplateFile", "HANDLE" } } },
      { "MessageBoxA", { { "hWnd", "HWND" }, { "lpText", "LPCTSTR" }, { "lpCaption", "LPCTSTR" }, { "uType", "UINT" } } } }
};

struct {
    int commandID;
    string_view text;
    // Input::Key shortcutKey = Input::Key::None;
    ItemHandle handle = InvalidItemHandle;
} RIGHT_CLICK_MENU_COMMANDS[] = { /*{ RIGHT_CLICK_MENU_CMD_NEW, "New structure" },
                                  { RIGHT_CLICK_MENU_CMD_EDIT, "Edit zone" },
                                  { RIGHT_CLICK_MENU_CMD_DELETE, "Delete zone" },
                                  { RIGHT_CLICK_MENU_CMD_COLLAPSE, "Collapse zone" },*/
                                  { RIGHT_CLICK_ADD_COMMENT, "Add comment" },
                                  { RIGHT_CLICK_REMOVE_COMMENT, "Remove comment" },
                                  { RIGHT_CLICK_DISSASM_ADD_ZONE, "Collapse dissasm zone" },
                                  { RIGHT_CLICK_DISSASM_REMOVE_ZONE, "Remove dissasm zone" }
};

Instance::Instance(Reference<GView::Object> obj, Settings* _settings)
    : ViewControl("Dissasm View"), obj(obj), settings(nullptr), jumps_holder(DISSASM_MAX_STORED_JUMPS)
{
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::DarkBlue });
    // settings
    if ((_settings) && (_settings->data)) {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        //_settings->data = nullptr; //TODO: is this ok?
    } else {
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();

    // this->selection.EnableMultiSelection(true);

    this->Cursor.lineInView    = 0;
    this->Cursor.startViewLine = 0;
    this->Cursor.offset        = 0;

    this->CursorColors.Normal      = config.Colors.Normal;
    this->CursorColors.Highlighted = config.Colors.Highlight;
    this->CursorColors.Line        = config.Colors.Line;

    this->Layout.visibleRows                     = 1;
    this->Layout.textSize                        = 1;
    this->Layout.totalCharactersPerLine          = 1;
    this->Layout.startingTextLineOffset          = 5;
    this->Layout.structuresInitialCollapsedState = true;
    this->Layout.totalLinesSize                  = 0;

    this->CurrentSelection = {};

    this->codePage = CodePageID::DOS_437;

    for (auto& menu_command : RIGHT_CLICK_MENU_COMMANDS) {
        menu_command.handle = rightClickMenu.AddCommandItem(menu_command.text, menu_command.commandID);
    }
    // rightClickOffset = 0;

    // TODO: to be moved inside plugin for some sort of API for token<->color
    asmData.instructionToColor = {
        { *((uint32*) "int3"), config.Colors.AsmIrrelevantInstructionColor },
        { *((uint32*) "ret"), config.Colors.AsmFunctionColor },
        { *((uint32*) "call"), config.Colors.AsmFunctionColor },
        { *((uint32*) "cmp"), config.Colors.AsmCompareInstructionColor },
        { *((uint32*) "test"), config.Colors.AsmCompareInstructionColor },
        { *((uint32*) "word"), config.Colors.AsmLocationInstruction },
        { *((uint32*) "dwor"), config.Colors.AsmLocationInstruction },
        { *((uint32*) "qwor"), config.Colors.AsmLocationInstruction },
        { *((uint32*) "ptr"), config.Colors.AsmLocationInstruction },
    };
}

inline uint64 LinePositionToOffset(LinePosition&& linePosition, uint32 textSize)
{
    return static_cast<uint64>(linePosition.line) * textSize + linePosition.offset;
}

bool Instance::GoTo(uint64 offset)
{
    return true;
}

bool Instance::Select(uint64 offset, uint64 size)
{
    return true;
}

// bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
//{
//     NOT_IMPLEMENTED(false);
// }

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    this->CursorColors.Normal      = config.Colors.Normal;
    this->CursorColors.Highlighted = config.Colors.Highlight;
    if (!this->HasFocus()) {
        this->CursorColors.Normal      = config.Colors.Inactive;
        this->CursorColors.Highlighted = config.Colors.Inactive;
    }

    renderer.Clear(' ', this->CursorColors.Normal);

    if (Layout.textSize == 0)
        return;

    int x = 0;
    switch (height) {
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
    r.WriteSingleLineText(x + 4, y, width - 4, n.ToBase(this->Cursor.offset, 10), this->CursorColors.Normal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    if (Layout.totalLinesSize > 0) {
        LocalString<32> tmp;
        tmp.Format("%3u%%", (static_cast<uint64>(Cursor.startViewLine) + Cursor.lineInView) * 100ULL / Layout.totalLinesSize);
        r.WriteSingleLineText(x, y, tmp.GetText(), this->CursorColors.Normal);
    } else {
        r.WriteSingleLineText(x, y, "  0%", this->CursorColors.Line);
    }
    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    return x + 5;
}

int Instance::PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Line:", this->CursorColors.Highlighted);
    r.WriteSingleLineText(x + 5, y, width - 4, n.ToString(Cursor.lineInView + Cursor.startViewLine, NumericFormatFlags::None), this->CursorColors.Normal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->CursorColors.Line);

    return x + 5;
}

void Instance::OpenCurrentSelection()
{
    UnicodeStringBuilder usb{};
    if (!ProcessSelectedDataToPrintable(usb))
        return;
    std::string out;
    usb.ToString(out);

    LocalUnicodeStringBuilder<2048> fullPath;
    fullPath.Add(this->obj->GetPath());
    fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
    fullPath.Add("temp_dissasm");

    BufferView buffer = { out.data(), out.size() };
    GView::App::OpenBuffer(buffer, "temp_dissasm", fullPath, GView::App::OpenMethod::Select);
}

void Instance::AddNewCollapsibleZone()
{
    Dialogs::MessageBox::ShowNotification("Error", "Reenable this!");
    // TODO: reenable this!!
    // if (!selection.HasAnySelection())
    //{
    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection first!");
    //     return;
    // }

    // const uint64 offsetStart = selection.GetSelectionStart(0);
    // const uint64 offsetEnd   = selection.GetSelectionEnd(0);

    // const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
    // if (zonesFound.empty() || zonesFound.size() != 1)
    //{
    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a single text zone!");
    //     return;
    // }

    // const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    // if (zone->zoneType != DissasmParseZoneType::CollapsibleAndTextZone)
    //{
    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a text zone!");
    //     return;
    // }

    // auto data = static_cast<CollapsibleAndTextZone*>(zone.get());
    // if (data->data.canBeCollapsed)
    //{
    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a text zone that cannot be collapsed!");
    //     return;
    // }

    //// TODO:
    // settings->collapsibleAndTextZones[offsetStart] = { offsetStart, offsetEnd - offsetStart + 1, true };
    // RecomputeDissasmZones();
}

void Instance::AddComment()
{
    const uint64 offsetStart = Cursor.GetOffset(Layout.textSize);
    const uint64 offsetEnd   = offsetStart + 1;

    const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    uint32 startingLine = zonesFound[0].startingLine;
    if (startingLine == 0 || startingLine == 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please add comment inside the region, not on the title!");
        return;
    }
    startingLine--;

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());

    std::string foundComment;
    // TODO: refactor function HasComment to return the comment or empty string for avoiding double initialization
    convertedZone->comments.HasComment(startingLine, foundComment);

    selection.Clear();
    CommentDataWindow dlg(foundComment);
    if (dlg.Show() == Dialogs::Result::Ok) {
        convertedZone->comments.AddOrUpdateComment(startingLine, dlg.GetResult());
    }
}

void Instance::RemoveComment()
{
    // TODO: duplicate code -> maybe extract this?
    const uint64 offsetStart = Cursor.GetOffset(Layout.textSize);
    const uint64 offsetEnd   = offsetStart + 1;

    const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    uint32 startingLine = zonesFound[0].startingLine;
    if (startingLine == 0 || startingLine == 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please remove comment inside the region, not on the title!");
        return;
    }
    startingLine--;

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    convertedZone->comments.RemoveComment(startingLine);
}

bool Instance::PrepareDrawLineInfo(DrawLineInfo& dli)
{
    if (dli.recomputeOffsets) {
        this->chars.Resize(Layout.totalCharactersPerLine);
        dli.recomputeOffsets      = false;
        dli.currentLineFromOffset = this->Cursor.startViewLine;
    }

    // TODO: send multiple lines to be drawn with each other instead of searching line by line
    //          for example: search how many line from the text needs to be written -> write all of them

    // TODO: current algorithm is build with ordered index values, could be improved later with a binary search

    const uint32 currentLineIndex = dli.currentLineFromOffset + dli.screenLineToDraw;
    if (!settings->parseZones.empty()) {
        auto& zones       = settings->parseZones;
        uint32 zonesCount = (uint32) settings->parseZones.size();
        // TODO: optimization -> instead of search every time keep the last zone index inside memory and search from there
        for (uint32 i = 0; i < zonesCount; i++) {
            if ((currentLineIndex >= zones[i]->startLineIndex && currentLineIndex < zones[i]->endingLineIndex)) {
                // struct
                dli.textLineToDraw = currentLineIndex - zones[i]->startLineIndex;
                switch (zones[i]->zoneType) {
                case DissasmParseZoneType::StructureParseZone:
                    return DrawStructureZone(dli, (DissasmParseStructureZone*) zones[i].get());

                // TODO:
                case DissasmParseZoneType::DissasmCodeParseZone:
                    return DrawDissasmZone(dli, (DissasmCodeZone*) zones[i].get());
                case DissasmParseZoneType::CollapsibleAndTextZone:
                    return DrawCollapsibleAndTextZone(dli, (CollapsibleAndTextZone*) zones[i].get());
                default:
                    return false;
                }
            }
        }
        // return true;
        if (!zonesCount) {
            assert(false);
        }
    } else {
        if (!config.ShowFileContent) {
            dli.renderer.WriteSingleLineText(
                  Layout.startingTextLineOffset, 1, "No structures found an File content is hidden. No content to show.", config.Colors.Normal);
            return true;
        }

        dli.textLineToDraw = currentLineIndex;
        return WriteTextLineToChars(dli);
    }

    return true;
}

inline void GView::View::DissasmViewer::Instance::UpdateCurrentZoneIndex(
      const DissasmStructureType& cType, DissasmParseStructureZone* zone, bool increaseOffset)
{
    if (cType.primaryType >= InternalDissasmType::UInt8 && cType.primaryType <= InternalDissasmType::Int64) {
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
    if (structureZone->structureIndex == structureZone->extendedSize) {
        while (structureZone->levels.size() > 1) {
            structureZone->types.pop_back();
            structureZone->levels.pop_back();
        }
        structureZone->levels.pop_back();
        structureZone->levels.push_back(0);
        structureZone->structureIndex = 0;
        structureZone->textFileOffset = structureZone->initialTextFileOffset;
    }

    uint32 levelToReach = dli.textLineToDraw;
    int16& levelNow     = structureZone->structureIndex;

    // TODO: consider if this value can be biffer than int16
    // bool increaseOffset = levelNow < (int16) levelToReach;

    // levelNow     = 0;
    // levelToReach = 47;

    // TODO: consider optimization if the levelToReach > levelNow and levelToReach should reach close to 0 then it all should be reset to 0
    while (levelNow < (int16) levelToReach) {
        const DissasmStructureType& currentType = structureZone->types.back();
        int currentLevel                        = structureZone->levels.back();

        switch (currentType.primaryType) {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel < currentType.internalTypes.size()) {
                UpdateCurrentZoneIndex(currentType.internalTypes[currentLevel], structureZone, true);
                structureZone->types.push_back(currentType.internalTypes[currentLevel]);
                structureZone->levels.push_back(0);
            } else {
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

    while (levelNow > (int16) levelToReach) {
        const DissasmStructureType& currentType = structureZone->types.back();
        int currentLevel                        = structureZone->levels.back();

        switch (currentType.primaryType) {
        case InternalDissasmType::UnidimnsionalArray:
        case InternalDissasmType::UserDefined:
            if (currentLevel > 0) {
                structureZone->levels.pop_back();
                currentLevel--;
                structureZone->levels.push_back(currentLevel);
                structureZone->types.push_back(currentType.internalTypes[currentLevel]);
                int32 anteiorLevel = (int32) currentType.internalTypes[currentLevel].internalTypes.size();
                if (anteiorLevel > 0)
                    anteiorLevel--;
                structureZone->levels.push_back(anteiorLevel);
                isFromBreak = false;
            } else {
                if (isFromBreak) {
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
    // assert(structureZone->textFileOffset == structureZone->initialTextFileOffset);

    return true;
}

bool Instance::WriteStructureToScreen(DrawLineInfo& dli, const DissasmStructureType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone)
{
    ColorPair normalColor = config.Colors.Normal;

    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;

    auto clearChar = this->chars.GetBuffer();
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = config.Colors.Normal;
        clearChar++;
    }

    dli.chText = dli.chNameAndSize;

    if (spaces > 0) {
        for (uint32 i = 0; i < spaces; i++) {
            dli.chText->Code  = codePage[' '];
            dli.chText->Color = normalColor;
            dli.chText++;
        }
    }

    uint32 typeSize    = 0;
    bool isSignedValue = false;

    switch (currentType.primaryType) {
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
        RegisterStructureCollapseButton(dli, structureZone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, structureZone);
        break;
    default:
        return false;
    }

    if (typeSize > 0) {
        // TODO: check textFileOffset!!
        auto buf = this->obj->GetData().Get(structureZone->textFileOffset - typeSize, typeSize, false);

        char buffer[9];
        memset(buffer, '\0', 9);
        for (uint32 i = 0; i < typeSize; i++)
            buffer[i] = buf[i];

        if (isSignedValue) {
            int64 value = *(int64*) buffer;
            AddStringToChars(dli, normalColor, "%s: %lli", currentType.name.data(), value);
        } else {
            uint64 value = *(uint64*) buffer;
            AddStringToChars(dli, normalColor, "%s: %llu", currentType.name.data(), value);
        }
    }

    const size_t buffer_size = dli.chText - this->chars.GetBuffer();

    // const uint32 cursorLine = Cursor.lineInView;
    // if (cursorLine == dli.screenLineToDraw)
    //{
    //     uint32 index = this->Cursor.offset;
    //     if (index < buffer_size - Layout.startingTextLineOffset)
    //         dli.chNameAndSize[index].Color = config.Colors.Selection;
    //     else
    //         dli.renderer.WriteCharacter(Layout.startingTextLineOffset + index, cursorLine + 1, codePage[' '], config.Colors.Selection);
    // }

    HighlightSelectionAndDrawCursorText(dli, buffer_size - Layout.startingTextLineOffset, buffer_size);

    const auto bufferToDraw = CharacterView{ chars.GetBuffer(), buffer_size };

    // this->chars.Resize((uint32) (dli.chText - dli.chNameAndSize));
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    return true;
}

bool Instance::DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone)
{
    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;

    auto clearChar = dli.chLineStart;
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = config.Colors.Normal;
        clearChar++;
    }
    dli.chText = dli.chNameAndSize;

    if (zone->data.canBeCollapsed && dli.textLineToDraw == 0) {
        AddStringToChars(dli, config.Colors.StructureColor, "Collapsible zone [%llu] ", zone->data.size);
        RegisterStructureCollapseButton(dli, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);
    } else {
        if (!zone->isCollapsed) {
            // TODO: hack-ish, maybe find another alternative or reset it down
            if (!zone->data.canBeCollapsed)
                dli.textLineToDraw++;

            uint64 dataNeeded = std::min<uint64>(zone->data.size, Layout.textSize);
            if (zone->data.size / Layout.textSize + 1 == dli.textLineToDraw) {
                dataNeeded = std::min<uint64>(zone->data.size % Layout.textSize, Layout.textSize);
            }
            const uint64 startingOffset = zone->data.startingOffset + (static_cast<uint64>(dli.textLineToDraw) - 1ull) * Layout.textSize;

            if (startingOffset + dataNeeded <= this->obj->GetData().GetSize()) {
                const auto buf = this->obj->GetData().Get(startingOffset, static_cast<uint32>(dataNeeded), false);
                if (!buf.IsValid()) {
                    AddStringToChars(dli, config.Colors.StructureColor, "\tInvalid buff at position: %llu", zone->data.startingOffset + zone->data.size);

                    const size_t buffer_size = dli.chText - this->chars.GetBuffer();
                    const auto bufferToDraw  = CharacterView{ chars.GetBuffer(), buffer_size };

                    // this->chars.Resize((uint32) (dli.chText - dli.chNameAndSize));
                    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
                    return true;
                }

                dli.start         = buf.GetData();
                dli.end           = buf.GetData() + buf.GetLength();
                dli.chLineStart   = this->chars.GetBuffer();
                dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
                dli.chText        = dli.chNameAndSize;

                const bool activeColor = this->HasFocus();
                auto textColor         = activeColor ? config.Colors.Line : config.Colors.Inactive;
                if (!zone->data.canBeCollapsed)
                    textColor = config.Colors.Normal;

                while (dli.start < dli.end) {
                    dli.chText->Code  = codePage[*dli.start];
                    dli.chText->Color = textColor;
                    dli.chText++;
                    dli.start++;
                }

                HighlightSelectionAndDrawCursorText(dli, buf.GetLength(), buf.GetLength() + Layout.startingTextLineOffset);

                // const uint32 cursorLine = Cursor.lineInView;
                // if (cursorLine == dli.screenLineToDraw)
                //{
                //     const uint32 index             = this->Cursor.offset;
                //     dli.chNameAndSize[index].Color = config.Colors.Selection;
                // }
            } else {
                AddStringToChars(dli, config.Colors.StructureColor, "\tNot enough data for offset: %llu", zone->data.startingOffset + zone->data.size);
            }
        }
    }
    const size_t buffer_size = dli.chText - this->chars.GetBuffer();
    const auto bufferToDraw  = CharacterView{ chars.GetBuffer(), buffer_size };

    // this->chars.Resize((uint32) (dli.chText - dli.chNameAndSize));
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, bufferToDraw, false);
    return true;
}

bool Instance::DrawDissasmZone(DrawLineInfo& dli, DissasmCodeZone* zone)
{
    if (zone->zoneDetails.language != DisassemblyLanguage::x86 && zone->zoneDetails.language != DisassemblyLanguage::x64) {
        dli.WriteErrorToScreen("Not yet supported language!");
        AdjustZoneExtendedSize(zone, 1);
        return true;
    }

    return DrawDissasmX86AndX64CodeZone(dli, zone);
}

void Instance::RegisterStructureCollapseButton(DrawLineInfo& dli, SpecialChars c, ParseZone* zone)
{
    ButtonsData bData = { 3, (int) (dli.screenLineToDraw + 1), c, config.Colors.DataTypeColor, 3, zone };
    MyLine.buttons.push_back(bData);
}

void Instance::AddStringToChars(DrawLineInfo& dli, ColorPair pair, string_view stringToAdd)
{
    size_t length = stringToAdd.size();
    for (uint32 i = 0; i < length; i++) {
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
    for (uint32 i = 0; i < length; i++) {
        dli.chText->Code  = codePage[buffer[i]];
        dli.chText->Color = pair;
        dli.chText++;
    }
}

void Instance::HighlightSelectionAndDrawCursorText(DrawLineInfo& dli, uint32 maxLineLength, uint32 availableCharacters)
{
    for (uint32 i = 0; i < selection.GetCount(); i++) {
        if (selection.HasSelection(i)) {
            const auto selectionStart = selection.GetSelectionStart(i);
            const auto selectionEnd   = selection.GetSelectionEnd(i);
            auto selectionStorage     = selection.GetStorage(i);
            bool isAltPressed         = selection.IsAltPressed(i);

            const uint32 selectStartLine  = selectionStart.line;
            const uint32 selectionEndLine = selectionEnd.line;
            const uint32 lineToDrawTo     = dli.screenLineToDraw + Cursor.startViewLine;

            if (selectStartLine <= lineToDrawTo && lineToDrawTo <= selectionEndLine) {
                uint32 startingIndex = selectionStart.offset; // % Layout.textSize;
                uint32 endIndex      = selectionEnd.offset % Layout.textSize + 1;
                if (!isAltPressed) {
                    if (selectStartLine < lineToDrawTo)
                        startingIndex = 0;
                    if (lineToDrawTo < selectionEndLine)
                        endIndex = static_cast<uint32>(maxLineLength);
                }
                // uint32 endIndex      = (uint32) std::min(selectionEnd - selectionStart + startingIndex + 1, buf.GetLength());
                // TODO: variables can be skipped, use startingPointer < EndPointer
                const auto savedChText = dli.chText;
                dli.chText             = dli.chNameAndSize + startingIndex;
                while (startingIndex < endIndex) {
                    dli.chText->Color = Cfg.Selection.Editor;
                    selectionStorage->push_back(dli.chText->Code);
                    dli.chText++;
                    startingIndex++;
                    // TODO: improve this!
                }
                dli.chText = savedChText;
                selectionStorage->push_back('\n');
            }
        }
    }

    if (Cursor.lineInView == dli.screenLineToDraw) {
        uint32 index = this->Cursor.offset;
        if (index < availableCharacters - Layout.startingTextLineOffset)
            dli.chNameAndSize[index].Color = config.Colors.Selection;
        else
            dli.renderer.WriteCharacter(Layout.startingTextLineOffset + index, Cursor.lineInView + 1, codePage[' '], config.Colors.Selection);

        auto ch   = dli.chLineStart;
        ch->Code  = codePage['-'];
        ch->Color = config.Colors.Highlight;
        ch++;
        ch->Code  = codePage['-'];
        ch->Color = config.Colors.Highlight;
        ch++;
        ch->Code  = codePage['>'];
        ch->Color = config.Colors.Highlight;
    }
}

struct MappingZonesData {
    void* data;
    DissasmParseZoneType zoneType;
};

void Instance::RecomputeDissasmZones()
{
    std::map<uint32, std::vector<MappingZonesData>> mappingData;
    for (auto& mapping : this->settings->dissasmTypeMapped) {
        mappingData[OffsetToLinePosition(mapping.first).line].push_back({ &mapping.second, DissasmParseZoneType::StructureParseZone });
    }
    for (auto& dissasmZone : settings->disassemblyZones) {
        mappingData[OffsetToLinePosition(dissasmZone.first).line].push_back({ &dissasmZone.second, DissasmParseZoneType::DissasmCodeParseZone });
    }
    for (auto& zone : settings->collapsibleAndTextZones) {
        mappingData[OffsetToLinePosition(zone.first).line].push_back({ &zone.second, DissasmParseZoneType::CollapsibleAndTextZone });
    }

    uint32 lastZoneEndingIndex = 0;
    uint16 currentIndex        = 0;
    uint32 textLinesOffset     = 0;
    settings->parseZones.clear();

    for (const auto& mapping : mappingData) {
        for (const auto& entry : mapping.second) {
            uint32 zoneStartingLine = mapping.first;
            if (zoneStartingLine < lastZoneEndingIndex || !config.ShowFileContent)
                zoneStartingLine = lastZoneEndingIndex;
            if (zoneStartingLine > lastZoneEndingIndex) {
                const uint64 startingTextOffset = LinePositionToOffset({ textLinesOffset }, Layout.textSize);
                textLinesOffset += zoneStartingLine - lastZoneEndingIndex;
                const uint64 endTextOffset = LinePositionToOffset({ textLinesOffset }, Layout.textSize);

                auto collapsibleZone = std::make_unique<CollapsibleAndTextZone>();

                collapsibleZone->data            = { startingTextOffset, endTextOffset - startingTextOffset, false };
                collapsibleZone->startLineIndex  = lastZoneEndingIndex;
                collapsibleZone->isCollapsed     = false;
                collapsibleZone->endingLineIndex = collapsibleZone->startLineIndex;
                // collapsibleZone->textLinesOffset = textLinesOffset;
                collapsibleZone->zoneID       = currentIndex++;
                collapsibleZone->zoneType     = DissasmParseZoneType::CollapsibleAndTextZone;
                collapsibleZone->extendedSize = static_cast<uint32>(collapsibleZone->data.size / Layout.textSize);

                if (!collapsibleZone->isCollapsed)
                    collapsibleZone->endingLineIndex += collapsibleZone->extendedSize;

                // lastEndMinusLastOffset = collapsibleZone->endingLineIndex + collapsibleZone->textLinesOffset;
                lastZoneEndingIndex = collapsibleZone->endingLineIndex;
                settings->parseZones.push_back(std::move(collapsibleZone));
            }

            switch (entry.zoneType) {
            case DissasmParseZoneType::StructureParseZone: {
                const auto convertedData   = static_cast<DissasmStructureType*>(entry.data);
                auto parseZone             = std::make_unique<DissasmParseStructureZone>();
                parseZone->startLineIndex  = zoneStartingLine;
                parseZone->endingLineIndex = parseZone->startLineIndex + 1;
                parseZone->isCollapsed     = Layout.structuresInitialCollapsedState;
                parseZone->extendedSize    = convertedData->GetExpandedSize() - 1;
                // parseZone->textLinesOffset = textLinesOffset;
                parseZone->dissasmType = *convertedData;
                parseZone->levels.push_back(0);
                parseZone->types.emplace_back(parseZone->dissasmType);
                parseZone->structureIndex        = 0;
                parseZone->textFileOffset        = mapping.first;
                parseZone->initialTextFileOffset = mapping.first;
                parseZone->zoneID                = currentIndex++;
                parseZone->zoneType              = DissasmParseZoneType::StructureParseZone;

                if (!parseZone->isCollapsed)
                    parseZone->endingLineIndex += parseZone->extendedSize;

                // lastEndMinusLastOffset = parseZone->endingLineIndex + parseZone->textLinesOffset;
                lastZoneEndingIndex = parseZone->endingLineIndex;
                settings->parseZones.push_back(std::move(parseZone));
            } break;
            case DissasmParseZoneType::DissasmCodeParseZone: {
                // TODO: resize vectors! -> there could be done some approximations for the best speed
                const auto convertedData  = static_cast<DisassemblyZone*>(entry.data);
                auto codeZone             = std::make_unique<DissasmCodeZone>();
                codeZone->zoneDetails     = *convertedData;
                codeZone->startLineIndex  = zoneStartingLine;
                codeZone->endingLineIndex = codeZone->startLineIndex + 1;
                codeZone->extendedSize    = DISSASM_INITIAL_EXTENDED_SIZE;
                codeZone->isCollapsed     = false; // Layout.structuresInitialCollapsedState;
                // codeZone->textLinesOffset = textLinesOffset;
                codeZone->zoneID   = currentIndex++;
                codeZone->zoneType = DissasmParseZoneType::DissasmCodeParseZone;

                codeZone->isInit = false;
                // initial offset is the entry point
                codeZone->offsetCacheMaxLine = 0;
                codeZone->cachedCodeOffsets.push_back({ convertedData->entryPoint, 0 });
                // codeZone->cachedLines.resize(DISSASM_MAX_CACHED_LINES);

                if (!codeZone->isCollapsed)
                    codeZone->endingLineIndex += codeZone->extendedSize;

                // lastEndMinusLastOffset = codeZone->endingLineIndex + codeZone->textLinesOffset;
                lastZoneEndingIndex = codeZone->endingLineIndex;
                settings->parseZones.push_back(std::move(codeZone));
            } break;
            case DissasmParseZoneType::CollapsibleAndTextZone: {
                const auto convertedData         = static_cast<CollapsibleAndTextData*>(entry.data);
                auto collapsibleZone             = std::make_unique<CollapsibleAndTextZone>();
                collapsibleZone->data            = *convertedData;
                collapsibleZone->startLineIndex  = zoneStartingLine;
                collapsibleZone->isCollapsed     = Layout.structuresInitialCollapsedState;
                collapsibleZone->endingLineIndex = collapsibleZone->startLineIndex + 1;
                // collapsibleZone->textLinesOffset = textLinesOffset;
                collapsibleZone->zoneID       = currentIndex++;
                collapsibleZone->zoneType     = DissasmParseZoneType::CollapsibleAndTextZone;
                collapsibleZone->extendedSize = static_cast<uint32>(collapsibleZone->data.size / Layout.textSize) + 1u;

                if (!collapsibleZone->isCollapsed)
                    collapsibleZone->endingLineIndex += collapsibleZone->extendedSize;

                // lastEndMinusLastOffset = collapsibleZone->endingLineIndex + collapsibleZone->textLinesOffset;
                lastZoneEndingIndex = collapsibleZone->endingLineIndex;
                settings->parseZones.push_back(std::move(collapsibleZone));
            } break;
            }
        }
    }

    if (settings->parseZones.empty())
        return; // TODO: only text -> add zone text

    const uint64 startingTextOffset = LinePositionToOffset({ textLinesOffset }, Layout.textSize);
    const uint64 totalFileSize      = this->obj->GetData().GetSize();
    if (startingTextOffset >= totalFileSize)
        return;

    const uint64 zoneSize = totalFileSize - startingTextOffset;

    auto collapsibleZone = std::make_unique<CollapsibleAndTextZone>();

    collapsibleZone->data            = { startingTextOffset, zoneSize, false };
    collapsibleZone->startLineIndex  = lastZoneEndingIndex;
    collapsibleZone->isCollapsed     = false;
    collapsibleZone->endingLineIndex = collapsibleZone->startLineIndex;
    // collapsibleZone->textLinesOffset = textLinesOffset;
    collapsibleZone->zoneID       = currentIndex++;
    collapsibleZone->zoneType     = DissasmParseZoneType::CollapsibleAndTextZone;
    collapsibleZone->extendedSize = static_cast<uint32>(collapsibleZone->data.size / Layout.textSize) + 1u;

    if (!collapsibleZone->isCollapsed)
        collapsibleZone->endingLineIndex += collapsibleZone->extendedSize;

    // lastEndMinusLastOffset = collapsibleZone->endingLineIndex + collapsibleZone->textLinesOffset;
    lastZoneEndingIndex = collapsibleZone->endingLineIndex;
    settings->parseZones.push_back(std::move(collapsibleZone));

    UpdateLayoutTotalLines();

    // vector<CollapsibleAndTextData> textData;
    // const uint32 textLinesCount = obj->GetData().GetSize() / Layout.textSize;
    // auto& zones                 = settings->parseZones;
    // if (zones[0]->startLineIndex > 0)
    //{
    //     textData.emplace_back(0, zones[0]->startLineIndex * Layout.textSize);
    // }
    // const uint32 zonesCount = settings->parseZones.size();
    // if (zonesCount == 1)
    //{
    //     uint64 size = (textLinesCount - zones[0]->endingLineIndex + zones[0]->textLinesOffset) * Layout.textSize +
    //                   obj->GetData().GetSize() % Layout.textSize;
    //     textData.emplace_back(zones[0]->endingLineIndex, size, false);
    // }
    // for (uint32 i = 0; i < zonesCount - 1; i++)
    //{
    //     if (zones[i]->endingLineIndex < zones[i + 1]->startLineIndex)
    //     {
    //         uint64 size = (zones[i + 1]->startLineIndex - zones[i]->endingLineIndex) * Layout.textSize;
    //         textData.emplace_back(zones[i]->endingLineIndex, size, false);
    //     }
    // }
    // if (zones[zonesCount - 1]->endingLineIndex <= textLinesCount)
    //{
    //     uint64 size = (textLinesCount - zones[zonesCount - 1]->endingLineIndex - zones[zonesCount - 1]->textLinesOffset) *
    //     Layout.textSize; textData.emplace_back(zones[zonesCount - 1]->endingLineIndex, size, false);
    // }
}

uint64 Instance::GetZonesMaxSize() const
{
    if (settings->parseZones.empty())
        return 0;
    uint64 linesOccupiedByZones = 0;

    for (const auto& zone : settings->parseZones)
        linesOccupiedByZones += zone->endingLineIndex - zone->startLineIndex;
    return linesOccupiedByZones * Layout.textSize;
}

void Instance::UpdateLayoutTotalLines()
{
    // TODO: check if +1 or not
    Layout.totalLinesSize = settings->parseZones[settings->parseZones.size() - 1]->endingLineIndex - 1;
}

bool Instance::ProcessSelectedDataToPrintable(UnicodeStringBuilder& usb)
{
    bool found_data = false;
    AppCUI::Graphics::CodePage cp(AppCUI::Graphics::CodePageID::PrintableAscii);
    for (uint32 i = 0; i < selection.GetCount(); i++) {
        if (selection.HasSelection(i)) {
            found_data       = true;
            auto storageData = selection.GetStorage(i);
            for (const auto c : *storageData) {
                FixSizeString<1> cc;
                if (c == '\n') {
                    CHECK(cc.AddChar((c & 0xFF)), false, "");
                    CHECK(usb.Add(cc), false, "");
                    continue;
                }
                CHECK(cc.AddChar((cp[c] & 0xFF)), false, "");
                CHECK(usb.Add(cc), false, "");
            }
        }
    }

    if (!found_data) {
        LocalString<128> message;
        CHECK(message.AddFormat("No selection", obj->GetData().GetSize()), false, "");
        Dialogs::MessageBox::ShowError("Error copying to clipboard (postprocessing)!", message);
        return false;
    }
    return true;
}

LinePosition Instance::OffsetToLinePosition(uint64 offset) const
{
    return { static_cast<uint32>(offset / Layout.textSize), static_cast<uint32>(offset % Layout.textSize) };
}

uint64 Instance::CursorDissasm::GetOffset(uint32 textSize) const
{
    return LinePositionToOffset(ToLinePosition(), textSize);
}

vector<Instance::ZoneLocation> Instance::GetZonesIndexesFromPosition(uint64 startingOffset, uint64 endingOffset) const
{
    if (settings->parseZones.empty())
        return {};

    const uint32 lineStart = OffsetToLinePosition(startingOffset).line;
    const uint32 lineEnd   = OffsetToLinePosition(endingOffset).line;

    return GetZonesIndexesFromLinePosition(lineStart, lineEnd);
}

vector<Instance::ZoneLocation> Instance::GetZonesIndexesFromLinePosition(uint32 lineStart, uint32 lineEnd) const
{
    if (lineEnd < lineStart)
        lineEnd = lineStart;

    const auto& zones     = settings->parseZones;
    const auto zonesCount = static_cast<uint32>(settings->parseZones.size());

    vector<ZoneLocation> result;

    uint32 zoneIndex = 0;
    while (zoneIndex < zonesCount && lineStart >= zones[zoneIndex]->endingLineIndex)
        zoneIndex++;

    uint32* value = nullptr;
    for (uint32 line = lineStart; line <= lineEnd && zoneIndex < zonesCount; line++) {
        if (zones[zoneIndex]->startLineIndex <= line && line < zones[zoneIndex]->endingLineIndex && (result.empty() || result.back().zoneIndex != zoneIndex)) {
            result.push_back({ zoneIndex, line - zones[zoneIndex]->startLineIndex, line - zones[zoneIndex]->startLineIndex });
            value = &result[result.size() - 1].endingLine;
        } else if (line >= zones[zoneIndex]->endingLineIndex)
            zoneIndex++;
        else if (value) {
            (*value)++;
        }
    }

    return result;
}

void GView::View::DissasmViewer::Instance::AdjustZoneExtendedSize(ParseZone* zone, uint32 newExtendedSize)
{
    if (zone->isCollapsed) {
        zone->extendedSize = newExtendedSize;
        return;
    }
    if (zone->extendedSize == newExtendedSize)
        return;
    selection.Clear();

    const int32 sizeToAdjust = static_cast<int32>(newExtendedSize) - zone->extendedSize;
    zone->endingLineIndex += sizeToAdjust;
    bool foundZone = false;
    for (const auto& availableZone : settings->parseZones) {
        if (foundZone) {
            availableZone->startLineIndex += sizeToAdjust;
            availableZone->endingLineIndex += sizeToAdjust;
        }
        if (availableZone->zoneID == zone->zoneID)
            foundZone = true;
    }
    zone->extendedSize = newExtendedSize;
    UpdateLayoutTotalLines();
    assert(foundZone);
}

bool Instance::WriteTextLineToChars(DrawLineInfo& dli)
{
    uint64 textFileOffset = ((uint64) this->Layout.textSize) * dli.textLineToDraw;

    if (textFileOffset >= this->obj->GetData().GetSize())
        return false;

    auto clearChar = this->chars.GetBuffer();
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = config.Colors.Normal;
        clearChar++;
    }

    auto buf = this->obj->GetData().Get(textFileOffset, Layout.textSize, false);

    dli.start         = buf.GetData();
    dli.end           = buf.GetData() + buf.GetLength();
    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    bool activ     = this->HasFocus();
    auto textColor = activ ? config.Colors.Normal : config.Colors.Inactive;

    while (dli.start < dli.end) {
        dli.chText->Code  = codePage[*dli.start];
        dli.chText->Color = textColor;
        dli.chText++;
        dli.start++;
    }

    HighlightSelectionAndDrawCursorText(dli, buf.GetLength(), buf.GetLength());

    // const uint32 cursorLine = Cursor.lineInView;
    // if (cursorLine == dli.screenLineToDraw)
    //{
    //     const uint32 index             = this->Cursor.offset;
    //     dli.chNameAndSize[index].Color = config.Colors.Selection;
    // }

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1, chars, true);
    return true;
}

void Instance::Paint(AppCUI::Graphics::Renderer& renderer)
{
    if (!MyLine.buttons.empty())
        MyLine.buttons.clear();
    // if (HasFocus())
    //     renderer.Clear(' ', config.Colors.Normal);
    // else
    //     renderer.Clear(' ', config.Colors.Inactive);

    if (Layout.textSize == 0)
        return;

    if (Cursor.hasMovedView) {
        for (const auto& zone : asmData.zonesToClear)
            zone->asmPreCacheData.Clear();
    } else {
        for (const auto& zone : asmData.zonesToClear)
            zone->asmPreCacheData.Reset();
    }

    DrawLineInfo dli(renderer, Layout.startingTextLineOffset, config.Colors.Normal);

    // TODO: improve this!!
    selection.ClearStorages();
    for (uint32 tr = 0; tr < this->Layout.visibleRows; tr++) {
        dli.screenLineToDraw = tr;
        if (!PrepareDrawLineInfo(dli))
            break;

        // uint64 val2 = ((uint64) tr - 1) * Layout.charactersPerLine;
        // if (dli.viewOffset <= Cursor.currentPos && Cursor.currentPos < nextOffset)
        //{
        //    uint64 val                   = this->Cursor.currentPos % dli.textSize + dli.offset;
        //    chars.GetBuffer()[val].Color = config.Colors.Cursor;
        //}
        // auto asdasdasd = CharacterView{ chars.GetBuffer(), 10 };
        // srenderer.WriteSingleLineText(0, tr + 1, asdasdasd, DefaultColorPair);

        // chars.Resize(10);
        // renderer.WriteSingleLineCharacterBuffer(0, tr + 1, chars, false);
    }

    // asmData.bufferPool.Draw(renderer, config);

    if (!MyLine.buttons.empty()) {
        for (const auto& btn : MyLine.buttons)
            renderer.WriteSpecialCharacter(btn.x, btn.y, btn.c, btn.color);
    }
}

bool Instance::ShowGoToDialog()
{
    if (settings->parseZones.empty())
        return true;
    const uint32 totalLines  = settings->parseZones[settings->parseZones.size() - 1]->endingLineIndex;
    const uint32 currentLine = Cursor.lineInView + Cursor.startViewLine;
    GoToDialog dlg(currentLine, totalLines);
    if (dlg.Show() == Dialogs::Result::Ok) {
        const auto lineToReach = dlg.GetResultedLine();
        if (lineToReach != currentLine) {
            jumps_holder.insert(Cursor.saveState());
            MoveTo(0, static_cast<int32>(lineToReach) - static_cast<int32>(currentLine), Key::None, false);
        }
    }
    /*const uint32 currentLine  = Cursor.lineInView + Cursor.startViewLine;
    constexpr auto lineToReach = 248;
    MoveTo(0, static_cast<int32>(lineToReach) - static_cast<int32>(currentLine), false);*/
    return true;
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowCopyDialog()
{
    UnicodeStringBuilder usb{};
    if (!ProcessSelectedDataToPrintable(usb))
        return false;

    if (AppCUI::OS::Clipboard::SetText(usb) == false) {
        LocalString<128> message;
        CHECK(message.AddFormat("File size %llu bytes, cache size %llu bytes!", obj->GetData().GetSize(), 100), false, "");
        Dialogs::MessageBox::ShowError("Error copying to clipboard (postprocessing)!", message);
        return false;
    }

    return true;
}

void Instance::OnAfterResize(int newWidth, int newHeight)
{
    this->RecomputeDissasmLayout();
}

void Instance::OnStart()
{
    // TODO: rethink
    if (settings->defaultLanguage == DisassemblyLanguage::Default)
        settings->defaultLanguage = DisassemblyLanguage::x86;

    this->RecomputeDissasmLayout();
    this->RecomputeDissasmZones();

    uint32 maxSize = 0;
    while (settings->maxLocationMemoryMappingSize > 0) {
        maxSize++;
        settings->maxLocationMemoryMappingSize /= 10;
    }
    // TODO: do a research! this is an imperative setting
    settings->maxLocationMemoryMappingSize = maxSize + 1;

    GView::Hashes::CRC32 crc32{};
    uint32 hashVal = 0;
    for (uint32 i = 0; i < KNOWN_FUNCTIONS.size(); i++) {
        if (!crc32.Init(Hashes::CRC32Type::JAMCRC) || !crc32.Update(KNOWN_FUNCTIONS[i].functionName) || !crc32.Final(hashVal)) {
            // show err
            return;
        }
        asmData.functions.insert({ hashVal, &KNOWN_FUNCTIONS[i] });
    }
}

void Instance::RecomputeDissasmLayout()
{
    Layout.visibleRows            = this->GetHeight() - 1;
    Layout.totalCharactersPerLine = this->GetWidth() - 1;

    Layout.textSize = std::max(this->Layout.totalCharactersPerLine, this->Layout.startingTextLineOffset) - this->Layout.startingTextLineOffset;
}

void Instance::ChangeZoneCollapseState(ParseZone* zoneToChange)
{
    selection.Clear();
    int32 sizeToAdjust = static_cast<int32>(zoneToChange->extendedSize);
    if (!zoneToChange->isCollapsed)
        sizeToAdjust *= -1;
    zoneToChange->isCollapsed = !zoneToChange->isCollapsed;
    zoneToChange->endingLineIndex += sizeToAdjust;

    bool foundZone = false;
    for (auto& zone : settings->parseZones) {
        if (foundZone) {
            zone->startLineIndex += sizeToAdjust;
            zone->endingLineIndex += sizeToAdjust;
        }
        if (zoneToChange->zoneID == zone->zoneID)
            foundZone = true;
    }
    UpdateLayoutTotalLines();
    // TODO: search for following zones and update their size
}

Instance::~Instance()
{
    while (!settings->buffersToDelete.empty()) {
        char* bufferToDelete = settings->buffersToDelete.back();
        settings->buffersToDelete.pop_back();
        delete bufferToDelete;
    }
}

void DissasmAsmPreCacheData::AnnounceCallInstruction(struct DissasmCodeZone* zone, const AsmFunctionDetails* functionDetails)
{
    if (cachedAsmLines.empty())
        return;
    constexpr uint32 MAX_LINE_DIFF = 10;

    const uint32 startingLine = cachedAsmLines.back().currentLine;
    uint32 pushIndex = 0, pushesRemaining = functionDetails->params.size();

    for (auto it = cachedAsmLines.rbegin(); it != cachedAsmLines.rend() && pushesRemaining; ++it) {
        if (startingLine - it->currentLine > MAX_LINE_DIFF)
            break;
        if (it->flags != DissasmAsmPreCacheLine::InstructionFlag::PushFlag)
            continue;

        // TODO: improve performance, remove string concatenation as much as possible
        auto param           = std::string(functionDetails->params[pushIndex].name);
        const auto commentIt = zone->comments.comments.find(it->currentLine);
        if (commentIt != zone->comments.comments.end()) {
            commentIt->second = param + " " + commentIt->second;
        } else {
            zone->comments.comments.insert({ it->currentLine, param });
        }
        pushesRemaining--;
        pushIndex++;
    }
}

void DissasmComments::AddOrUpdateComment(uint32 line, std::string comment)
{
    comments[line - 1] = std::move(comment);
}

bool DissasmComments::HasComment(uint32 line, std::string& comment) const
{
    const auto it = comments.find(line - 1);
    if (it != comments.end()) {
        comment = it->second;
        return true;
    }
    return false;
}

void DissasmComments::RemoveComment(uint32 line)
{
    const auto it = comments.find(line - 1);
    if (it != comments.end()) {
        comments.erase(it);
        return;
    }
    Dialogs::MessageBox::ShowError("Error", "No comments found on the selected line !");
}

void DissasmComments::AdjustCommentsOffsets(uint32 changedLine, bool isAddedLine)
{
    decltype(comments) commentsAjusted = {};
    for (auto& comment : comments) {
        if (comment.first >= changedLine) {
            if (isAddedLine)
                commentsAjusted.insert({ comment.first + 1, std::move(comment.second) });
            else
                commentsAjusted.insert({ comment.first - 1, std::move(comment.second) });
        }
    }

    comments = std::move(commentsAjusted);
}

void Instance::ProcessSpaceKey(bool goToEntryPoint)
{
    const uint64 offsetStart = Cursor.GetOffset(Layout.textSize);
    const uint64 offsetEnd   = offsetStart + 1;

    const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a single zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (goToEntryPoint && zone->isCollapsed) {
        ChangeZoneCollapseState(zone.get());
    }
    if (!goToEntryPoint && zonesFound[0].startingLine == 0) // extending zone
    {
        ChangeZoneCollapseState(zone.get());
        return;
    }

    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        if (goToEntryPoint)
            Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    uint64* offsetToReach    = nullptr;
    if (goToEntryPoint)
        offsetToReach = &convertedZone->zoneDetails.entryPoint;
    DissasmZoneProcessSpaceKey(convertedZone, zonesFound[0].startingLine, offsetToReach);
}

void DrawLineInfo::WriteErrorToScreen(std::string_view error) const
{
    renderer.WriteSingleLineText(lineOffset, screenLineToDraw + 1, error, errorColor);
}

LinePosition Instance::CursorDissasm::ToLinePosition() const
{
    return LinePosition{ startViewLine + lineInView, offset };
}
