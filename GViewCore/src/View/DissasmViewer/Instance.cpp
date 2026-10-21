#include <array>

#include "DissasmViewer.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmChainedFixups.hpp"
#include "DissasmObjC.hpp"
#include "DissasmRtti.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <cassert>
#include <unordered_map>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr size_t DISSASM_MAX_STORED_JUMPS = 64; // visited locations (a jump stores both its source and its destination)

Instance::Instance(Reference<GView::Object> obj, Settings* _settings)
    : ViewControl("Dissasm View"), obj(obj), settings(nullptr), jumps_holder(DISSASM_MAX_STORED_JUMPS)
{
    this->chars.Fill('*', 1024, ColorPair{ Color::Black, Color::Transparent });
    // settings
    if ((_settings) && (_settings->data)) {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr; // owned by the viewer now: the plugin settings must not use (or free) it again
    } else {
        this->settings.reset(new SettingsData());
    }
    ApplyChainedFixups(*this->settings, obj); // Mach-O: the pointers and the import slots that dyld writes
    ApplyObjCMetadata(*this->settings, obj);  // Mach-O: the methods of the Objective-C classes, the selector / class references
    ApplyCppRtti(*this->settings, obj);       // C++: the vtables, the type descriptors / typeinfo objects of the classes

    queryInterface = nullptr;
    if (config.Loaded == false)
        config.Initialize(Cfg);
    this->ColorMan.InitFromConfigColors(config.ConfigColors, HasFocus());
    // this->selection.EnableMultiSelection(true);

    this->Cursor.lineInView    = 0;
    this->Cursor.startViewLine = 0;
    this->Cursor.offset        = 0;
    this->Cursor.hasMovedView  = false;

    this->Layout.visibleRows                     = 1;
    this->Layout.textSize                        = 1;
    this->Layout.totalCharactersPerLine          = 1;
    this->Layout.startingTextLineOffset          = 5;
    this->Layout.structuresInitialCollapsedState = true;
    this->Layout.totalLinesSize                  = 0;

    this->CurrentSelection = {};
    this->cacheData        = {};

    this->codePage = CodePageID::DOS_437;

    for (const auto& submenu : RIGHT_CLICK_SUB_MENUS_COMMANDS) {
        assert(submenu.name);
        const auto handle = rightClickMenu.AddSubMenu(submenu.name);
        auto subMenu      = rightClickMenu.GetSubMenu(handle);
        for (const auto& command : submenu.commands) {
            assert(!command.text.empty());
            subMenu->AddCommandItem(command.text, command.commandID);
        }
    }

    for (auto& menu_command : RIGHT_CLICK_MENU_COMMANDS) {
        rightClickMenu.AddCommandItem(menu_command.text, menu_command.commandID);
    }
    // rightClickOffset = 0;

    // the colors of the instructions: GetX86MnemonicColor / GetX86TokenColor (x86_x64/DissasmX86.cpp)
}

inline uint64 LinePositionToOffset(LinePosition&& linePosition, uint32 textSize)
{
    return static_cast<uint64>(linePosition.line) * textSize + linePosition.offset;
}

// the other views and panels (PE exports, sections) jump to a file offset: the instruction of a code zone that contains it
bool Instance::GoTo(uint64 offset)
{
    repaintRequested = true; // asked by a panel: the view is drawn again at the next frame
    return GoToFileOffset(offset);
}

bool Instance::Select(uint64 offset, uint64 size)
{
    repaintRequested = true;
    return GoToFileOffset(offset); // the selection of this view is made of lines: the cursor goes to the start of the range
}

bool Instance::GoToFileOffset(uint64 fileOffset)
{
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto codeZone = static_cast<DissasmCodeZone*>(zone.get());
        const auto& details = codeZone->zoneDetails;
        if (fileOffset < details.startingZonePoint || fileOffset - details.startingZonePoint >= details.size)
            continue;
        if (!codeZone->isInit || !codeZone->CanReachAsmLines()) {
            // prepared when its title is drawn: the cursor goes there now, to the instruction after the zone is prepared
            pendingGoTo          = fileOffset;
            const auto from      = SaveCursorState();
            Cursor.lineInView    = 0;
            Cursor.startViewLine = codeZone->startLineIndex;
            Cursor.hasMovedView  = true;
            RecordJump(from);
            return true;
        }
        return MoveCursorToZoneFileOffset(codeZone, fileOffset, true);
    }
    return false;
}

std::optional<uint64> Instance::ResolveGoToText(std::string_view text, std::string& error, std::optional<uint32>& line)
{
    line                      = std::nullopt;
    const bool hasTranslation = settings->offsetTranslateCallback.IsValid();
    const auto shownType      = hasTranslation ? static_cast<DissasmPEConversionType>(config.AddressMode) : DissasmPEConversionType::FileOffset;
    const auto request        = ParseDissasmGoToText(text, shownType);
    if (!request.has_value()) {
        error = "Expecting a label name, a hexadecimal address or a prefix (va:, rva:, off:, line:)!";
        return {};
    }
    if (request->line.has_value()) {
        const uint32 totalLines = settings->parseZones.empty() ? 0 : settings->parseZones.back()->endingLineIndex;
        if (request->line.value() >= totalLines) {
            error = "The line must be lower than " + std::to_string(totalLines) + "!";
            return {};
        }
        line = request->line;
        return 0;
    }

    // a label name first: a name can also be a hexadecimal number (add, face)
    for (const auto& zone : settings->parseZones) {
        if (request->name.empty() || zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto codeZone = static_cast<const DissasmCodeZone*>(zone.get());
        if (codeZone->cachedCodeOffsets.empty())
            continue;
        const auto address = codeZone->FindLabelByName(request->name);
        if (address.has_value())
            return codeZone->cachedCodeOffsets[0].offset + address.value();
    }
    if (!request->address.has_value()) {
        error = "There is no label named `" + request->name + "`!";
        return {};
    }

    uint64 fileOffset = request->address.value();
    if (request->addressType != DissasmPEConversionType::FileOffset) {
        if (!hasTranslation) {
            error = "This file has no virtual addresses: use a file offset!";
            return {};
        }
        fileOffset = settings->offsetTranslateCallback->TranslateToFileOffset(request->address.value(), static_cast<uint32>(request->addressType));
        if (fileOffset == static_cast<uint64>(-1)) {
            error = "The address is not a location of the file!";
            return {};
        }
    }
    for (const auto& zone : settings->parseZones) {
        if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone)
            continue;
        const auto& details = static_cast<const DissasmCodeZone*>(zone.get())->zoneDetails;
        if (fileOffset >= details.startingZonePoint && fileOffset - details.startingZonePoint < details.size)
            return fileOffset;
    }
    error = "The address is not inside a disassembled code zone!";
    return {};
}

// bool Instance::ExtractTo(Reference<AppCUI::OS::IFile> output, ExtractItem item, uint64 size)
//{
//     NOT_IMPLEMENTED(false);
// }

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    renderer.Clear(' ', this->ColorMan.Colors.CursorNormal);

    if (Layout.textSize == 0)
        return;

    int x = 0;
    switch (height) {
    case 0:
        break;
    case 1:
        x = PrintCursorPosInfo(x, 0, 16, false, renderer);
        x = PrintCursorLineInfo(x, 0, 16, false, renderer);
        x = PrintCursorValueInfo(x, 0, renderer); // the number under the cursor first: the location can be long
        x = PrintCursorLocationInfo(x, 0, renderer);
        PrintCursorInstructionInfo(x, 0, renderer); // what the instruction does: the last, it is cut by the width
        break;
    default:
        x = std::max<int>(PrintCursorPosInfo(x, 0, 16, false, renderer), PrintCursorLineInfo(x, 1, 16, false, renderer));
        PrintCursorLocationInfo(x, 1, renderer);
        PrintCursorInstructionInfo(PrintCursorValueInfo(x, 0, renderer), 0, renderer);
        break;
    }
}

int Instance::PrintCursorValueInfo(int x, int y, Renderer& r)
{
    // the number H would convert, in both bases (and signed when the sign bit of a 32 / 64 bit value is set)
    const auto number = GetCursorLineNumber();
    if (!number)
        return x;
    LocalString<96> tmp;
    tmp.Format("0x%llX = %llu", static_cast<unsigned long long>(number->value), static_cast<unsigned long long>(number->value));
    if (number->value >= 0x80000000ULL && number->value <= 0xFFFFFFFFULL)
        tmp.AddFormat(" (%d)", static_cast<int32>(static_cast<uint32>(number->value)));
    else if (number->value >= 0x8000000000000000ULL)
        tmp.AddFormat(" (%lld)", static_cast<long long>(number->value));
    r.WriteSingleLineText(x, y, "Val:", this->ColorMan.Colors.CursorHighlighted);
    r.WriteSingleLineText(x + 5, y, tmp.GetText(), this->ColorMan.Colors.CursorNormal);
    return x + 5 + static_cast<int>(tmp.Len()) + 1;
}

bool Instance::UpdateKeys(KeyboardControlsInterface* interface)
{
    RegisterKeys(interface);
    return true;
}

int Instance::PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Pos:", this->ColorMan.Colors.CursorHighlighted);
    r.WriteSingleLineText(x + 4, y, width - 4, n.ToBase(this->Cursor.offset, 10), this->ColorMan.Colors.CursorNormal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->ColorMan.Colors.CursorLine);

    if (Layout.totalLinesSize > 0) {
        LocalString<32> tmp;
        tmp.Format("%3u%%", (static_cast<uint64>(Cursor.startViewLine) + Cursor.lineInView) * 100ULL / Layout.totalLinesSize);
        r.WriteSingleLineText(x, y, tmp.GetText(), this->ColorMan.Colors.CursorNormal);
    } else {
        r.WriteSingleLineText(x, y, "  0%", this->ColorMan.Colors.CursorLine);
    }
    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->ColorMan.Colors.CursorLine);

    return x + 5;
}

int Instance::PrintCursorLineInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r)
{
    NumericFormatter n;
    r.WriteSingleLineText(x, y, "Line:", this->ColorMan.Colors.CursorHighlighted);
    r.WriteSingleLineText(
          x + 5, y, width - 4, n.ToString(Cursor.lineInView + Cursor.startViewLine, NumericFormatFlags::None), this->ColorMan.Colors.CursorNormal);
    x += width;

    if (addSeparator)
        r.WriteSpecialCharacter(x++, y, SpecialChars::BoxVerticalSingleLine, this->ColorMan.Colors.CursorLine);

    r.WriteSpecialCharacter(x + 4, y, SpecialChars::BoxVerticalSingleLine, this->ColorMan.Colors.CursorLine);

    return x + 5;
}

void Instance::OpenCurrentSelection()
{
    if (!selection.HasAnySelection()) {
        Dialogs::MessageBox::ShowNotification("Open selection", "Select a zone first !");
        return;
    }
    UnicodeStringBuilder usb{};
    if (!ProcessSelectedDataToPrintable(usb))
        return;
    std::string out;
    usb.ToString(out);

    LocalUnicodeStringBuilder<512> fullPath;
    fullPath.Add(this->obj->GetPath());
    fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
    fullPath.Add("temp_dissasm");

    BufferView buffer = { out.data(), out.size() };
    GView::App::OpenBuffer(buffer, "temp_dissasm", fullPath, GView::App::OpenMethod::Select);
}

// TODO:Collaasible zone for text --> valid code, don't delete
// TODO: reenable this!!
// void Instance::AddNewCollapsibleTextZone()
//{
//    Dialogs::MessageBox::ShowNotification("Error", "Reenable this!");
//    // TODO: reenable this!!
//    // if (!selection.HasAnySelection())
//    //{
//    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection first!");
//    //     return;
//    // }
//
//    // const uint64 offsetStart = selection.GetSelectionStart(0);
//    // const uint64 offsetEnd   = selection.GetSelectionEnd(0);
//
//    // const auto zonesFound = GetZonesIndexesFromPosition(offsetStart, offsetEnd);
//    // if (zonesFound.empty() || zonesFound.size() != 1)
//    //{
//    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a single text zone!");
//    //     return;
//    // }
//
//    // const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
//    // if (zone->zoneType != DissasmParseZoneType::CollapsibleAndTextZone)
//    //{
//    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a text zone!");
//    //     return;
//    // }
//
//    // auto data = static_cast<CollapsibleAndTextZone*>(zone.get());
//    // if (data->data.canBeCollapsed)
//    //{
//    //     Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a text zone that cannot be collapsed!");
//    //     return;
//    // }
//
//    //// TODO:
//    // settings->collapsibleAndTextZones[offsetStart] = { offsetStart, offsetEnd - offsetStart + 1, true };
//    // RecomputeDissasmZones();
//}

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
    if (startingLine == 0 || startingLine == 1 || (Cursor.startViewLine >= startingLine && Cursor.lineInView == 0)) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please add comment inside the region, not on the title!");
        return;
    }
    startingLine -= 2;

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());

    std::string comment = {};
    convertedZone->GetComment(startingLine, comment);
    const bool hadComment = !comment.empty();

    selection.Clear();
    SingleLineEditWindow dlg(comment, "Add Comment");
    if (dlg.Show() == Dialogs::Result::Ok) {
        comment = dlg.GetResult();
        convertedZone->AddOrUpdateComment(startingLine, dlg.GetResult());
        // creation and edit are distinct telemetry events; the comment text itself is never recorded
        GView::Security::Learning::Hooks::OnSimpleEvent(
              obj, hadComment ? GView::Security::Learning::Hooks::SimpleEvent::CommentEdit : GView::Security::Learning::Hooks::SimpleEvent::CommentAdd);
    }
}

void Instance::AddRepeatableComment()
{
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() != 1 || zonesFound[0].startingLine < 2 ||
        settings->parseZones[zonesFound[0].zoneIndex]->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line of a dissasm zone!");
        return;
    }
    const auto zone = static_cast<DissasmCodeZone*>(settings->parseZones[zonesFound[0].zoneIndex].get());
    if (!zone->CanReachAsmLines() || zone->isCollapsed)
        return;
    DissasmInsnExtractLineParams params{};
    params.obj         = obj;
    params.zone        = zone;
    params.settings    = settings.get();
    params.asmData     = &asmData;
    const auto asmLine = zone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params);
    if (asmLine.isCollapsedLine || asmLine.localVariableKind == DissasmAsmPreCacheLine::LocalVariableKind::Definition) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a label or an instruction!");
        return;
    }
    // the address of the line: its label, or the instruction (a label line and its instruction share it: the label shows it)
    const auto existing = zone->repeatableComments.find(asmLine.address);
    selection.Clear();
    SingleLineEditWindow dialog(existing != zone->repeatableComments.end() ? existing->second : std::string(), "Repeatable comment");
    if (dialog.Show() != Dialogs::Result::Ok)
        return;
    std::string text = dialog.GetResult();
    if (text.size() > DISSASM_MAX_REPEATABLE_COMMENT_SIZE)
        text.resize(DISSASM_MAX_REPEATABLE_COMMENT_SIZE);
    if (zone->SetRepeatableComment(asmLine.address, text)) // Ctrl+Z gives the previous one back
        RefreshDrawnLines();                                  // the lines that refer to it, in the other zones too
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
    startingLine -= 2;

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    std::string existing     = {};
    convertedZone->GetComment(startingLine, existing);
    if (existing.empty()) {
        // no comment: the repeatable comment of the line (Delete removes it too)
        DissasmInsnExtractLineParams params{};
        params.obj         = obj;
        params.zone        = convertedZone;
        params.settings    = settings.get();
        params.asmData     = &asmData;
        const auto asmLine = convertedZone->GetCurrentAsmLine(startingLine, obj, &params);
        if (convertedZone->HasOwnRepeatableComment(asmLine)) {
            convertedZone->SetRepeatableComment(asmLine.address, {});
            RefreshDrawnLines();
            return;
        }
    }
    convertedZone->RemoveComment(startingLine);
    if (!existing.empty())
        GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::CommentRemove);
}

void Instance::RenameLabel()
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
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line inside the dissasm zone to rename it, not the title!");
        return;
    }
    startingLine--;

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    startingLine             = startingLine - 1;

    DissasmInsnExtractLineParams lineParams = {};
    lineParams.obj                          = obj;
    lineParams.asmLine                      = startingLine;
    lineParams.actualLine                   = startingLine;
    lineParams.zone                         = convertedZone;
    lineParams.dli                          = nullptr;
    lineParams.settings                     = settings.get();
    lineParams.asmData                      = &asmData;

    auto renameResult = convertedZone->TryRenameLine(startingLine, obj, nullptr, &lineParams);
    if (!renameResult.ok) {
        Dialogs::MessageBox::ShowNotification("Warning", renameResult.message);
        return;
    }
    if (renameResult.message == "renamed") // the dialog was confirmed (TryRenameLine also returns Ok on cancel)
        GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::LabelRename);
    selection.Clear();
    convertedZone->asmPreCacheData.Clear();
    ForgetLinesReferringTo(convertedZone); // the operands of the other zones show the name
}

void Instance::RemoveLocalVariable()
{
    const auto zonesFound = GetZonesIndexesFromLinePosition(Cursor.ToLinePosition().line);
    if (zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }
    if (zonesFound[0].startingLine <= 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a line inside the region, not the title!");
        return;
    }

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    const auto language      = convertedZone->zoneDetails.language;
    if (!convertedZone->isInit || !DissasmCodeZone::IsNativeCodeLanguage(language))
        return;
    if (convertedZone->localVariables.Empty()) {
        Dialogs::MessageBox::ShowNotification(
              "Warning", "There are no local variables in this zone (they are recognized only when Config.DeepScanDissasmOnStart is enabled)!");
        return;
    }

    uint64 functionStart = 0;
    int32 frameOffset    = 0;
    if (!convertedZone->GetLocalVariableFromLine(zonesFound[0].startingLine - 2u, obj, functionStart, frameOffset)) { // 2 for title and menu
        Dialogs::MessageBox::ShowNotification("Warning", "Please select a local variable or an instruction that uses one!");
        return;
    }

    bool lineRemoved  = false;
    const auto status = convertedZone->RemoveLocalVariable(functionStart, frameOffset, lineRemoved);
    if (!status.ok) {
        Dialogs::MessageBox::ShowNotification("Warning", status.message);
        return;
    }
    selection.Clear();
    if (lineRemoved)
        AdjustZoneExtendedSize(convertedZone, convertedZone->extendedSize - 1u);
    convertedZone->asmPreCacheData.Clear();
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
                  Layout.startingTextLineOffset, 1, "No structures found an File content is hidden. No content to show.", ColorMan.Colors.Normal);
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
        // UInt8, UInt16, UInt32, UInt64 then Int8, Int16, Int32, Int64: index % 4 -> 1, 2, 4, 8 bytes
        const uint32 val = 1u << ((uint8) cType.primaryType % 4u);
        if (increaseOffset)
            zone->textFileOffset += val;
        else
            zone->textFileOffset -= val;
        // zone.textFileOffset += (increaseOffset ? 1 : -1) * (((int) cType.primaryType + 1u) % 4);
    }
}

bool Instance::DrawStructureZone(DrawLineInfo& dli, DissasmParseStructureZone* structureZone)
{
    if (structureZone->structureIndex >= 0 && (uint32) structureZone->structureIndex == structureZone->extendedSize) {
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

    // TODO: consider if this value can be bigger than int16
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
            if (currentLevel >= 0 && (size_t) currentLevel < currentType.internalTypes.size()) {
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
                int32 anteriorLevel = (int32) currentType.internalTypes[currentLevel].internalTypes.size();
                if (anteriorLevel > 0)
                    anteriorLevel--;
                structureZone->levels.push_back(anteriorLevel);
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
    return true;
}

bool Instance::WriteStructureToScreen(DrawLineInfo& dli, const DissasmStructureType& currentType, uint32 spaces, DissasmParseStructureZone* structureZone)
{
    ColorPair normalColor = ColorMan.Colors.Normal;

    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;

    auto clearChar = this->chars.GetBuffer();
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = ColorMan.Colors.Normal;
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
        AddStringToChars(dli, ColorMan.Colors.StructureColor, "Array[%u]", currentType.width);
        AddStringToChars(dli, ColorMan.Colors.StructureColor, " %s", currentType.name.data());
        break;
    case GView::View::DissasmViewer::InternalDissasmType::BidimensionalArray:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UserDefined:
        AddStringToChars(dli, ColorMan.Colors.StructureColor, "Structure");
        AddStringToChars(dli, ColorMan.Colors.StructureColor, " %s", currentType.name.data());
        RegisterStructureCollapseButton(
              dli.screenLineToDraw + 1, structureZone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, structureZone);
        break;
    default:
        return false;
    }

    if (typeSize > 0) {
        // TODO: check textFileOffset!!
        const BufferView buf = this->obj->GetData().Get(structureZone->textFileOffset - typeSize, typeSize, false);

        // the cache may return fewer bytes than requested (end of file): never index past what was returned
        char buffer[9] = {};
        for (uint32 i = 0; i < typeSize && i < buf.GetLength(); i++)
            buffer[i] = static_cast<char>(buf[i]);

        if (isSignedValue) {
            int64 value;
            memcpy(&value, buffer, sizeof(value));
            // Int8 / Int16 / Int32: the bytes after the field are zero, the sign of the field is extended (-1 was shown as 255)
            if (typeSize < sizeof(value)) {
                const uint32 unusedBits = static_cast<uint32>(sizeof(value) - typeSize) * 8u;
                value                   = static_cast<int64>(static_cast<uint64>(value) << unusedBits) >> unusedBits;
            }
            AddStringToChars(dli, normalColor, "%s: %lli", currentType.name.data(), static_cast<long long>(value));
        } else {
            uint64 value;
            memcpy(&value, buffer, sizeof(value));
            AddStringToChars(dli, normalColor, "%s: %llu", currentType.name.data(), value);
        }
    }

    const uint32 buffer_size = static_cast<uint32>(dli.chText - this->chars.GetBuffer());

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
    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, bufferToDraw, false);
    return true;
}

bool Instance::DrawCollapsibleAndTextZone(DrawLineInfo& dli, CollapsibleAndTextZone* zone)
{
    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;

    auto clearChar = dli.chLineStart;
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = ColorMan.Colors.Normal;
        clearChar++;
    }
    dli.chText = dli.chNameAndSize;

    if (zone->data.canBeCollapsed && dli.textLineToDraw == 0) {
        AddStringToChars(dli, ColorMan.Colors.StructureColor, "Collapsible zone [%llu] ", zone->data.size);
        RegisterStructureCollapseButton(dli.screenLineToDraw + 1, zone->isCollapsed ? SpecialChars::TriangleRight : SpecialChars::TriangleLeft, zone);
    } else {
        if (!zone->isCollapsed) {
            // TODO: hack-ish, maybe find another alternative or reset it down
            if (!zone->data.canBeCollapsed)
                dli.textLineToDraw++;

            // the bytes of the zone shown on this line (textLineToDraw >= 1 here): a full line, the remaining bytes on the last line,
            // nothing on the last line of a collapsible zone whose size is a multiple of the line size
            const uint64 lineStart      = (static_cast<uint64>(dli.textLineToDraw) - 1ull) * Layout.textSize;
            const uint64 dataNeeded     = lineStart < zone->data.size ? std::min<uint64>(zone->data.size - lineStart, Layout.textSize) : 0;
            const uint64 startingOffset = zone->data.startingOffset + lineStart;

            if (dataNeeded == 0) {
                HighlightSelectionAndDrawCursorText(dli, 0, Layout.startingTextLineOffset);
            } else if (startingOffset + dataNeeded <= this->obj->GetData().GetSize()) {
                const auto buf = this->obj->GetData().Get(startingOffset, static_cast<uint32>(dataNeeded), false);
                if (!buf.IsValid()) {
                    AddStringToChars(dli, ColorMan.Colors.StructureColor, "\tInvalid buff at position: %llu", zone->data.startingOffset + zone->data.size);

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

                auto textColor = ColorMan.Colors.Line;
                if (!zone->data.canBeCollapsed)
                    textColor = ColorMan.Colors.Normal;

                while (dli.start < dli.end) {
                    dli.chText->Code  = codePage[*dli.start];
                    dli.chText->Color = textColor;
                    dli.chText++;
                    dli.start++;
                }

                HighlightSelectionAndDrawCursorText(dli, (uint32) buf.GetLength(), (uint32) (buf.GetLength() + Layout.startingTextLineOffset));

                // const uint32 cursorLine = Cursor.lineInView;
                // if (cursorLine == dli.screenLineToDraw)
                //{
                //     const uint32 index             = this->Cursor.offset;
                //     dli.chNameAndSize[index].Color = config.Colors.Selection;
                // }
            } else {
                AddStringToChars(dli, ColorMan.Colors.StructureColor, "\tNot enough data for offset: %llu", zone->data.startingOffset + zone->data.size);
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
    switch (zone->zoneDetails.language) {
    case DisassemblyLanguage::x86:
    case DisassemblyLanguage::x64:
    case DisassemblyLanguage::ARM64:
    case DisassemblyLanguage::ARM:
    case DisassemblyLanguage::Thumb:
        return DrawDissasmX86AndX64CodeZone(dli, zone);
    case DisassemblyLanguage::JavaByteCode:
        return DrawDissasmJavaByteCodeZone(dli, zone);
    default:
        dli.WriteErrorToScreen("Not yet supported language!");
        AdjustZoneExtendedSize(zone, 1);
        return true;
    }
}

void Instance::RegisterStructureCollapseButton(uint32 screenLine, SpecialChars c, ParseZone* zone, bool isBullet)
{
    const ButtonsData bData = { 3, static_cast<int>(screenLine), c, ColorMan.Colors.DataTypeColor, 3, zone };
    if (isBullet)
        MyLine.bullets.push_back(bData);
    else
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
                uint32 endIndex;
                //= selectionEnd.offset % Layout.textSize + 1;
                if (!isAltPressed) {
                    if (selectStartLine < lineToDrawTo)
                        startingIndex = 0;
                }
                endIndex = static_cast<uint32>(maxLineLength);
                //}
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
            dli.chNameAndSize[index].Color = ColorMan.Colors.Selection;
        else
            dli.renderer.WriteCharacter(Layout.startingTextLineOffset + index, Cursor.lineInView + 1, codePage[' '], ColorMan.Colors.Selection);

        auto ch   = dli.chLineStart;
        ch->Code  = codePage['-'];
        ch->Color = ColorMan.Colors.Highlight;
        ch++;
        ch->Code  = codePage['-'];
        ch->Color = ColorMan.Colors.Highlight;
        ch++;
        ch->Code  = codePage['>'];
        ch->Color = ColorMan.Colors.Highlight;
    }
}

struct MappingZonesData {
    void* data;
    DissasmParseZoneType zoneType;
};

uint32 GView::View::DissasmViewer::GetTextZoneExtendedSize(const CollapsibleAndTextData& data, uint32 textSize)
{
    textSize = std::max<uint32>(textSize, 1u);
    // a collapsible zone (its title is the first line) keeps a line for the remaining bytes; a text zone ends with its last byte
    const uint64 lines = data.canBeCollapsed ? data.size / textSize + 1u : data.size / textSize + (data.size % textSize != 0 ? 1u : 0u);
    return static_cast<uint32>(std::min<uint64>(lines, UINT32_MAX / 2u));
}

// end (exclusive) of [start, start + size), saturated
static uint64 GetZoneBytesEnd(uint64 start, uint64 size)
{
    return size > UINT64_MAX - start ? UINT64_MAX : start + size;
}

void GView::View::DissasmViewer::BuildDissasmParseZones(SettingsData& settings, const DissasmZonesLayoutParams& params)
{
    const uint32 textSize = std::max<uint32>(params.textSize, 1u);

    // ordered by their file offset; the zones placed at the same offset keep the order: structures, code, collapsible zones
    std::map<uint64, std::vector<MappingZonesData>> mappingData;
    for (auto& mapping : settings.dissasmTypeMapped)
        mappingData[mapping.first].push_back({ &mapping.second, DissasmParseZoneType::StructureParseZone });
    for (auto& dissasmZone : settings.disassemblyZones)
        mappingData[dissasmZone.first].push_back({ &dissasmZone.second, DissasmParseZoneType::DissasmCodeParseZone });
    for (auto& zone : settings.collapsibleAndTextZones)
        mappingData[zone.first].push_back({ &zone.second, DissasmParseZoneType::CollapsibleAndTextZone });

    auto& zones = settings.parseZones;
    zones.clear();
    uint32 currentLine   = 0; // the zones are placed one after another
    uint16 currentIndex  = 0;
    uint64 shownBytesEnd = 0; // end (exclusive) of the file bytes covered by the zones placed so far

    // the raw bytes [start, end) as text lines (they are not covered by any other zone)
    auto addTextZone = [&](uint64 start, uint64 end) {
        auto textZone             = std::make_unique<CollapsibleAndTextZone>();
        textZone->data            = { start, end - start, false };
        textZone->startLineIndex  = currentLine;
        textZone->isCollapsed     = false;
        textZone->zoneID          = currentIndex++;
        textZone->zoneType        = DissasmParseZoneType::CollapsibleAndTextZone;
        textZone->extendedSize    = GetTextZoneExtendedSize(textZone->data, textSize);
        textZone->endingLineIndex = textZone->startLineIndex + textZone->extendedSize;
        currentLine               = textZone->endingLineIndex;
        zones.push_back(std::move(textZone));
    };

    for (const auto& [zoneOffset, entries] : mappingData) {
        for (const auto& entry : entries) {
            // the bytes of the file covered by the zone: the structure fields (the structures have no size of their own), the code,
            // the collapsible zone
            uint64 zoneBytesEnd = zoneOffset;
            switch (entry.zoneType) {
            case DissasmParseZoneType::StructureParseZone:
                zoneBytesEnd = GetZoneBytesEnd(zoneOffset, static_cast<const DissasmStructureType*>(entry.data)->GetByteSize());
                break;
            case DissasmParseZoneType::DissasmCodeParseZone:
                zoneBytesEnd = GetZoneBytesEnd(zoneOffset, static_cast<const DisassemblyZone*>(entry.data)->size);
                break;
            case DissasmParseZoneType::CollapsibleAndTextZone:
                zoneBytesEnd = GetZoneBytesEnd(zoneOffset, static_cast<const CollapsibleAndTextData*>(entry.data)->size);
                break;
            }

            // the bytes between the end of the previous zones and the start of this one
            const uint64 gapEnd = std::min<uint64>(zoneOffset, params.fileSize);
            if (params.showFileContent && gapEnd > shownBytesEnd)
                addTextZone(shownBytesEnd, gapEnd);
            shownBytesEnd = std::max<uint64>(shownBytesEnd, zoneBytesEnd);

            switch (entry.zoneType) {
            case DissasmParseZoneType::StructureParseZone: {
                const auto convertedData   = static_cast<DissasmStructureType*>(entry.data);
                auto parseZone             = std::make_unique<DissasmParseStructureZone>();
                parseZone->startLineIndex  = currentLine;
                parseZone->endingLineIndex = parseZone->startLineIndex + 1;
                parseZone->isCollapsed     = params.structuresInitialCollapsedState;
                parseZone->extendedSize    = convertedData->GetExpandedSize() - 1;
                parseZone->dissasmType     = *convertedData;
                parseZone->levels.push_back(0);
                parseZone->types.emplace_back(parseZone->dissasmType);
                parseZone->structureIndex = 0;
                // the fields are read from the file offset of the structure
                parseZone->textFileOffset        = zoneOffset;
                parseZone->initialTextFileOffset = zoneOffset;
                parseZone->zoneID                = currentIndex++;
                parseZone->zoneType              = DissasmParseZoneType::StructureParseZone;

                if (!parseZone->isCollapsed)
                    parseZone->endingLineIndex += parseZone->extendedSize;

                currentLine = parseZone->endingLineIndex;
                zones.push_back(std::move(parseZone));
            } break;
            case DissasmParseZoneType::DissasmCodeParseZone: {
                // TODO: resize vectors! -> there could be done some approximations for the best speed
                const auto convertedData  = static_cast<DisassemblyZone*>(entry.data);
                auto codeZone             = std::make_unique<DissasmCodeZone>();
                codeZone->zoneDetails     = *convertedData;
                codeZone->startLineIndex  = currentLine;
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

                currentLine = codeZone->endingLineIndex;
                zones.push_back(std::move(codeZone));
            } break;
            case DissasmParseZoneType::CollapsibleAndTextZone: {
                const auto convertedData         = static_cast<CollapsibleAndTextData*>(entry.data);
                auto collapsibleZone             = std::make_unique<CollapsibleAndTextZone>();
                collapsibleZone->data            = *convertedData;
                collapsibleZone->startLineIndex  = currentLine;
                collapsibleZone->isCollapsed     = params.structuresInitialCollapsedState;
                collapsibleZone->endingLineIndex = collapsibleZone->startLineIndex + 1;
                collapsibleZone->zoneID          = currentIndex++;
                collapsibleZone->zoneType        = DissasmParseZoneType::CollapsibleAndTextZone;
                collapsibleZone->extendedSize    = GetTextZoneExtendedSize(collapsibleZone->data, textSize);

                if (!collapsibleZone->isCollapsed)
                    collapsibleZone->endingLineIndex += collapsibleZone->extendedSize;

                currentLine = collapsibleZone->endingLineIndex;
                zones.push_back(std::move(collapsibleZone));
            } break;
            }
        }
    }

    if (zones.empty())
        return; // only text: the file is drawn as text lines, without zones
    LinkCodeZones(zones);

    // the bytes after the last zone, until the end of the file
    if (params.showFileContent && shownBytesEnd < params.fileSize)
        addTextZone(shownBytesEnd, params.fileSize);
}

bool GView::View::DissasmViewer::RelayoutDissasmParseZones(std::vector<std::unique_ptr<ParseZone>>& zones, uint32 textSize)
{
    bool changed       = false;
    uint32 currentLine = 0;
    for (auto& zone : zones) {
        // the structure and code zones keep their lines (they do not depend on the text line size)
        uint32 linesCount = zone->endingLineIndex - zone->startLineIndex;
        if (zone->zoneType == DissasmParseZoneType::CollapsibleAndTextZone) {
            const auto textZone          = static_cast<CollapsibleAndTextZone*>(zone.get());
            const uint32 newExtendedSize = GetTextZoneExtendedSize(textZone->data, textSize);
            const uint32 titleLines      = textZone->data.canBeCollapsed ? 1u : 0u;
            // as ChangeZoneCollapseState: a collapsed zone keeps only its title
            linesCount = titleLines + (zone->isCollapsed ? 0u : newExtendedSize);
            changed    = changed || newExtendedSize != zone->extendedSize;
            zone->extendedSize = newExtendedSize;
        }
        changed               = changed || zone->startLineIndex != currentLine || zone->endingLineIndex != currentLine + linesCount;
        zone->startLineIndex  = currentLine;
        zone->endingLineIndex = currentLine + linesCount;
        currentLine           = zone->endingLineIndex;
    }
    return changed;
}

void Instance::RecomputeDissasmZones()
{
    // the zones are recreated below, the pointers kept for clearing their cached lines would dangle
    asmData.zonesToClear.clear();
    // the same for the zone of the cursor line numbers: they are computed again for the new zones
    cursorLineNumbers.computed = false;
    cursorLineNumbers.valid    = false;
    cursorLineNumbers.zone     = nullptr;
    cursorLineNumbers.numbers.clear();

    DissasmZonesLayoutParams params{};
    params.textSize                        = Layout.textSize;
    params.fileSize                        = this->obj->GetData().GetSize();
    params.showFileContent                 = config.ShowFileContent;
    params.structuresInitialCollapsedState = Layout.structuresInitialCollapsedState;
    BuildDissasmParseZones(*settings.get(), params);
    dataZonesLinked = false; // new zones: their data zones are linked again once prepared

    if (!settings->parseZones.empty())
        UpdateLayoutTotalLines();
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
            found_data = true;
            std::string codeText;
            if (TryGetCodeZoneSelectionText(i, codeText)) {
                for (const char c : codeText) {
                    FixSizeString<1> cc;
                    CHECK(cc.AddChar(c == '\n' ? c : static_cast<char>(cp[static_cast<uint8>(c)] & 0xFF)), false, "");
                    CHECK(usb.Add(cc), false, "");
                }
                continue;
            }
            auto storageData = selection.GetStorage(i);
            for (const auto c : *storageData) {
                FixSizeString<1> cc;
                if (c == '\n') {
                    CHECK(cc.AddChar((c & 0xFF)), false, "");
                    CHECK(usb.Add(cc), false, "");
                    continue;
                }
                CHECK(cc.AddChar((cp[c & 0xFF] & 0xFF)), false, "");
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

    const int32 sizeToAdjust = static_cast<int32>(newExtendedSize) - zone->extendedSize;
    // a selection of the zone is cleared (its lines changed), a selection below it moves with its lines
    selection.AdjustToResizedLines(zone->startLineIndex, zone->endingLineIndex, sizeToAdjust);
    // the view stays on the same lines when a zone above the cursor changes its size (a zone above analyzed in the background, its lines
    // counted): the lines below the zone move, the cursor moves with them
    if (Cursor.startViewLine + Cursor.lineInView >= zone->endingLineIndex) {
        const int64 startViewLine = static_cast<int64>(Cursor.startViewLine) + sizeToAdjust;
        Cursor.startViewLine      = static_cast<uint32>(std::max<int64>(startViewLine, 0));
        Cursor.hasMovedView       = true;
    }
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
    // the zones below moved without the view moving: their cached lines no longer match the lines shown on the screen
    for (const auto& codeZone : asmData.zonesToClear)
        codeZone->asmPreCacheData.Clear();
}

bool Instance::WriteTextLineToChars(DrawLineInfo& dli)
{
    const uint64 textFileOffset = ((uint64) this->Layout.textSize) * dli.textLineToDraw;

    if (textFileOffset >= this->obj->GetData().GetSize())
        return false;

    auto clearChar = this->chars.GetBuffer();
    for (uint32 i = 0; i < Layout.startingTextLineOffset; i++) {
        clearChar->Code  = codePage[' '];
        clearChar->Color = ColorMan.Colors.Normal;
        clearChar++;
    }

    const auto buf = this->obj->GetData().Get(textFileOffset, Layout.textSize, false);

    dli.start         = buf.GetData();
    dli.end           = buf.GetData() + buf.GetLength();
    dli.chLineStart   = this->chars.GetBuffer();
    dli.chNameAndSize = dli.chLineStart + Layout.startingTextLineOffset;
    dli.chText        = dli.chNameAndSize;

    bool activ     = this->HasFocus();
    auto textColor = activ ? ColorMan.Colors.Normal : ColorMan.Colors.Inactive;

    while (dli.start < dli.end) {
        dli.chText->Code  = codePage[*dli.start];
        dli.chText->Color = textColor;
        dli.chText++;
        dli.start++;
    }

    // same arguments as the text lines of the text zones: the text length and the line length (with the left margin); a final line
    // shorter than the margin made `length - margin` wrap around
    HighlightSelectionAndDrawCursorText(dli, (uint32) buf.GetLength(), (uint32) (buf.GetLength() + Layout.startingTextLineOffset));

    // const uint32 cursorLine = Cursor.lineInView;
    // if (cursorLine == dli.screenLineToDraw)
    //{
    //     const uint32 index             = this->Cursor.offset;
    //     dli.chNameAndSize[index].Color = config.Colors.Selection;
    // }

    dli.renderer.WriteSingleLineCharacterBuffer(0, dli.screenLineToDraw + 1u, chars, true);
    return true;
}

void Instance::Paint(AppCUI::Graphics::Renderer& renderer)
{
    if (!MyLine.buttons.empty())
        MyLine.buttons.clear();
    if (!MyLine.bullets.empty())
        MyLine.bullets.clear();
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

    // a GoTo that waited for its zone moves the cursor while the zone is drawn (its title prepares it): the rows after it were drawn
    // (and their lines cached) from the previous first line, the view is drawn again from the new one
    for (uint32 pass = 0; pass < 2; pass++) {
        DrawLineInfo dli(renderer, Layout.startingTextLineOffset, ColorMan.Colors.Normal);

        // TODO: improve this!!
        selection.ClearStorages();
        movedCursorWhileDrawing = false;
        for (uint32 tr = 0; tr < this->Layout.visibleRows; tr++) {
            dli.screenLineToDraw = tr;
            if (!PrepareDrawLineInfo(dli))
                break;
        }
        if (!movedCursorWhileDrawing)
            break;
        movedCursorWhileDrawing = false;
        for (const auto& zone : asmData.zonesToClear)
            zone->asmPreCacheData.Clear();
        MyLine.buttons.clear();
        MyLine.bullets.clear();
        renderer.Clear(' ', ColorMan.Colors.Normal);
    }

    if (!MyLine.buttons.empty()) {
        for (const auto& btn : MyLine.buttons)
            renderer.WriteSpecialCharacter(btn.x, btn.y, btn.c, btn.color);
    }
    if (!MyLine.bullets.empty()) {
        for (const auto& bullet : MyLine.bullets)
            renderer.WriteSpecialCharacter(bullet.x, bullet.y, SpecialChars::CircleFilled, bullet.color);
    }
    PaintNavigationBand(renderer);
}

AppCUI::Graphics::Color GView::View::DissasmViewer::GetDissasmBandColor(uint8 cell)
{
    switch (cell) {
    case BAND_DATA:
        return Color::Gray;
    case BAND_CODE:
        return Color::DarkGreen;
    case BAND_FILE:
        return Color::Blue;
    case BAND_LOADING:
        return Color::Green;
    case BAND_REGISTRY:
        return Color::Olive;
    case BAND_SERVICE:
        return Color::Teal;
    case BAND_CRYPTO:
        return Color::Yellow;
    case BAND_NETWORK:
        return Color::Aqua;
    case BAND_PROCESS:
        return Color::Magenta;
    case BAND_ANTIDEBUG:
        return Color::Pink;
    case BAND_INJECTION:
        return Color::Red;
    case BAND_FUNCTION:
        return Color::DarkBlue;
    default:
        return Color::Black;
    }
}

void Instance::PaintNavigationBand(AppCUI::Graphics::Renderer& renderer)
{
    // the last column is outside of the lines (totalCharactersPerLine is the width - 1); the rows of the lines are 1 .. visibleRows
    const int x         = static_cast<int>(Layout.totalCharactersPerLine);
    const uint32 rows   = Layout.visibleRows;
    const uint64 total  = Layout.totalLinesSize;
    if (rows < 2 || total == 0 || x <= 0 || x >= GetWidth())
        return;
    // built again when what it shows changes: its size, the lines of the zones, the functions of the analysis and their categories
    uint64 key = (static_cast<uint64>(rows) << 40) ^ total;
    std::vector<const ParseZone*> zones;
    zones.reserve(settings->parseZones.size());
    for (const auto& zone : settings->parseZones) {
        zones.push_back(zone.get());
        key = key * 1000003ull + (static_cast<uint64>(zone->startLineIndex) << 32 | zone->endingLineIndex) + (zone->isCollapsed ? 7u : 0u);
        if (zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone) {
            const auto* code = static_cast<const DissasmCodeZone*>(zone.get());
            key              = key * 1000003ull + code->functionStarts.size() * 31ull + code->functionApiCategories.size() + (code->isInit ? 1u : 0u);
            for (const auto& [address, description] : code->bookmarks)
                key = key * 31ull + address + 1u;
        }
    }
    if (key != navigationBandKey || navigationBand.size() != rows) {
        navigationBand    = BuildDissasmNavigationBand(zones, total, rows);
        navigationBandKey = key;
    }
    // the lines shown now: a triangle on their rows
    const auto rowOf    = [&](uint64 line) { return static_cast<uint32>(std::min<uint64>(rows - 1u, line * rows / total)); };
    const uint32 first  = rowOf(Cursor.startViewLine);
    const uint32 last   = rowOf(std::min<uint64>(total - 1, static_cast<uint64>(Cursor.startViewLine) + rows - 1));
    for (uint32 row = 0; row < rows; row++) {
        const uint8 cell       = navigationBand[row] & ~BAND_BOOKMARK;
        const ColorPair color  = { Color::White, cell == BAND_EMPTY ? ColorMan.Colors.Normal.Background : GetDissasmBandColor(cell) };
        if (row >= first && row <= last)
            renderer.WriteSpecialCharacter(x, static_cast<int>(row) + 1, SpecialChars::TriangleLeft, color);
        else if (navigationBand[row] & BAND_BOOKMARK) // a bookmark (Alt+M) in the row
            renderer.WriteSpecialCharacter(x, static_cast<int>(row) + 1, SpecialChars::CircleFilled, color);
        else
            renderer.WriteCharacter(x, static_cast<int>(row) + 1, ' ', color);
    }
}

bool Instance::ShowNavigationBandRow(int x, int y, bool recordJump)
{
    const uint32 rows  = Layout.visibleRows;
    const uint64 total = Layout.totalLinesSize;
    if (x != static_cast<int>(Layout.totalCharactersPerLine) || y < 1 || y > static_cast<int>(rows) || total == 0 || rows < 2)
        return false;
    // the first line of the row (the inverse of the row of a line: line * rows / total), a few lines below the top of the view
    const uint64 row  = static_cast<uint64>(y - 1);
    const uint64 line = std::min<uint64>(total - 1, (row * total + rows - 1) / rows);
    if (line == static_cast<uint64>(Cursor.startViewLine) + Cursor.lineInView)
        return true;
    const auto from      = SaveCursorState();
    Cursor.lineInView    = static_cast<uint32>(std::min<uint64>(std::min<uint32>(5, rows / 2), line));
    Cursor.startViewLine = static_cast<uint32>(line - Cursor.lineInView);
    Cursor.hasMovedView  = true;
    if (recordJump)
        RecordJump(from);
    return true;
}

bool Instance::ShowGoToDialog()
{
    if (settings->parseZones.empty())
        return true;
    FinishDeepScans(); // the names are the labels of the analysis

    const bool hasTranslation = settings->offsetTranslateCallback.IsValid();
    const auto shownType      = hasTranslation ? static_cast<DissasmPEConversionType>(config.AddressMode) : DissasmPEConversionType::FileOffset;
    const std::string_view shownTypeName =
          shownType == DissasmPEConversionType::VA ? "VA" : (shownType == DissasmPEConversionType::RVA ? "RVA" : "file offset");
    GoToDialog dlg(shownTypeName, [this](std::string_view text, std::string& error) {
        std::optional<uint32> line;
        return ResolveGoToText(text, error, line).has_value();
    });
    if (dlg.Show() != Dialogs::Result::Ok)
        return true;

    std::string error;
    std::optional<uint32> line;
    const auto fileOffset = ResolveGoToText(dlg.GetResultText(), error, line);
    if (line.has_value()) {
        const uint32 currentLine = Cursor.lineInView + Cursor.startViewLine;
        if (line.value() != currentLine) {
            const auto from = SaveCursorState();
            MoveTo(0, static_cast<int32>(line.value()) - static_cast<int32>(currentLine), Key::None, false);
            RecordJump(from);
        }
    } else if (fileOffset.has_value()) {
        GoToFileOffset(fileOffset.value());
    }
    return true;
}
bool Instance::ShowCopyDialog()
{
    if (GView::App::IsBlockedByPolicy(GView::Security::RestrictedMode::Feature::Copy, "copying from the disassembly view"))
        return true;
    UnicodeStringBuilder usb{};
    if (!ProcessSelectedDataToPrintable(usb))
        return false;

    if (GView::App::SetClipboardText(usb) == false) {
        LocalString<128> message;
        CHECK(message.AddFormat("File size %llu bytes, cache size %llu bytes!", static_cast<unsigned long long>(obj->GetData().GetSize()), 100ull), false, "");
        Dialogs::MessageBox::ShowError("Error copying to clipboard (postprocessing)!", message);
        return false;
    }

    return true;
}

void Instance::OnAfterResize(int newWidth, int newHeight)
{
    const uint32 oldTextSize    = Layout.textSize;
    const uint32 oldVisibleRows = Layout.visibleRows;
    // the cursor relative to its zone, taken with the lines of the previous layout
    CursorState cursorState = SaveCursorState();

    this->RecomputeDissasmLayout();
    // before OnStart there are no zones; a 0 sized view draws nothing (the zones are laid out once it has a size again)
    if (settings->parseZones.empty() || Layout.textSize == 0)
        return;
    if (oldTextSize == Layout.textSize && oldVisibleRows == Layout.visibleRows)
        return;

    if (oldTextSize != Layout.textSize) {
        // a text zone line shows textSize bytes: the cursor stays on the same byte of the zone
        if (cursorState.zoneIndex != CursorState::NO_ZONE && cursorState.zoneIndex < settings->parseZones.size() && oldTextSize > 0) {
            const auto& zone = settings->parseZones[cursorState.zoneIndex];
            if (zone->zoneType == DissasmParseZoneType::CollapsibleAndTextZone && !zone->isCollapsed) {
                const auto textZone     = static_cast<const CollapsibleAndTextZone*>(zone.get());
                const uint32 titleLines = textZone->data.canBeCollapsed ? 1u : 0u;
                if (cursorState.lineInZone >= titleLines) {
                    const uint64 byteInZone = static_cast<uint64>(cursorState.lineInZone - titleLines) * oldTextSize +
                                              std::min<uint32>(cursorState.offset, oldTextSize - 1u);
                    cursorState.lineInZone = titleLines + static_cast<uint32>(std::min<uint64>(byteInZone / Layout.textSize, UINT32_MAX - titleLines));
                    cursorState.offset     = static_cast<uint32>(byteInZone % Layout.textSize);
                }
            }
        }

        // the text zones have a different number of lines: every zone after them moves
        if (RelayoutDissasmParseZones(settings->parseZones, Layout.textSize)) {
            UpdateLayoutTotalLines();
            selection.Clear(); // the selections are kept as lines
            for (const auto& codeZone : asmData.zonesToClear)
                codeZone->asmPreCacheData.Clear();
            cursorLineNumbers.computed = false;
        }
    }

    // the same zone line, inside the new view (RestoreCursorState clamps it to the zone, to the lines and to the visible rows)
    RestoreCursorState(cursorState);
}

void Instance::OnStart()
{
    auto currentWindow     = Application::GetCurrentWindow();
    auto windowInterface   = currentWindow.ToObjectRef<GView::View::WindowInterface>();
    queryInterface = windowInterface->GetQueryInterface();

    // TODO: rethink
    if (settings->defaultLanguage == DisassemblyLanguage::Default)
        settings->defaultLanguage = DisassemblyLanguage::x86;

    this->RecomputeDissasmLayout();
    this->RecomputeDissasmZones();

    AddKnownFunctions(asmData);
    LoadCacheData();
}

void GView::View::DissasmViewer::AddKnownFunctions(AsmData& asmData)
{
    GView::Hashes::CRC32 crc32{};
    uint32 hashVal = 0;
    ForEachApiPrototype([&](const AsmFunctionDetails& details) {
        if (crc32.Init(Hashes::CRC32Type::JAMCRC) && crc32.Update(details.functionName) && crc32.Final(hashVal))
            asmData.functions.insert({ hashVal, &details });
    });
}

void Instance::RecomputeDissasmLayout()
{
    // a 0 sized control (minimized / not laid out yet) must not wrap around
    Layout.visibleRows            = static_cast<uint32>(std::max<int>(this->GetHeight() - 1, 0));
    Layout.totalCharactersPerLine = static_cast<uint32>(std::max<int>(this->GetWidth() - 1, 0));

    Layout.textSize = std::max(this->Layout.totalCharactersPerLine, this->Layout.startingTextLineOffset) - this->Layout.startingTextLineOffset;
}

void Instance::ChangeZoneCollapseState(ParseZone* zoneToChange, uint32 line)
{
    selection.Clear();
    int32 sizeToAdjust = static_cast<int32>(zoneToChange->extendedSize);
    if (!zoneToChange->isCollapsed)
        sizeToAdjust *= -1;

    bool foundZone = false;
    for (auto& zone : settings->parseZones) {
        if (foundZone) {
            zone->startLineIndex += sizeToAdjust;
            zone->endingLineIndex += sizeToAdjust;
        }
        if (zoneToChange->zoneID == zone->zoneID) {
            {
                if (zoneToChange->zoneType == DissasmParseZoneType::DissasmCodeParseZone && zone->startLineIndex != line) {
                    auto codeZone     = static_cast<DissasmCodeZone*>(zone.get());
                    uint32 insideLine = line - zone->startLineIndex - 2;
                    int32 difference  = 0;
                    if (!codeZone->CollapseOrExtendZone(insideLine, DissasmCodeZone::CollapseExpandType::NegateCurrentState, difference)) {
                        Dialogs::MessageBox::ShowError("Error", "Could not process ChangeZoneCollapseState!");
                        return;
                    }
                    codeZone->ResetZoneCaching();
                    // `difference` is the new size of the zone (as for CommandExecuteCollapsibleZoneOperation)
                    if (difference)
                        AdjustZoneExtendedSize(codeZone, static_cast<uint32>(difference));
                    break;
                }
                foundZone = true;
            }
        }
    }

    if (foundZone) {
        zoneToChange->isCollapsed = !zoneToChange->isCollapsed;
        zoneToChange->endingLineIndex += sizeToAdjust;
        UpdateLayoutTotalLines();
        // the zones below moved without the view moving: their cached lines no longer match the lines shown on the screen
        for (const auto& codeZone : asmData.zonesToClear)
            codeZone->asmPreCacheData.Clear();
    }
}

void Instance::RefreshDrawnLines()
{
    for (const auto& codeZone : asmData.zonesToClear)
        codeZone->asmPreCacheData.Clear();
    drawnLinesGeneration++; // the columns of the numbers under the cursor moved
}

Instance::~Instance()
{
    while (!settings->buffersToDelete.empty()) {
        char* bufferToDelete = settings->buffersToDelete.back();
        settings->buffersToDelete.pop_back();
        delete[] bufferToDelete; // allocated with new char[] (Settings::AddType)
    }
}

// the constant an argument line gives: push 3, mov edx, 0x80000000, mov dword ptr [rsp + 0x20], 3, mov w1, #3; 0 for xor ecx, ecx /
// and qword ptr [rsp + 0x30], 0; -1 for or eax, -1
static std::optional<uint64> GetArgumentImmediate(const DissasmAsmPreCacheLine& line)
{
    if (!line.op_str || line.size == 0)
        return std::nullopt;
    const std::string_view mnemonic = line.mnemonic;
    const std::string_view operands(line.op_str, line.op_str_size);
    const auto comma              = operands.rfind(", ");
    const std::string_view last   = comma == std::string_view::npos ? operands : operands.substr(comma + 2);
    const std::string_view first  = operands.substr(0, operands.find(", "));
    if ((mnemonic == "xor" || mnemonic == "sub") && comma != std::string_view::npos && first == last)
        return 0u;
    const auto immediate = ParseOperandImmediate(last);
    if (!immediate.has_value())
        return std::nullopt;
    if (comma == std::string_view::npos)
        return mnemonic == "push" ? std::optional<uint64>(static_cast<uint64>(immediate.value())) : std::nullopt;
    if (mnemonic == "mov" || mnemonic == "movz" || (mnemonic == "and" && immediate.value() == 0) || (mnemonic == "or" && immediate.value() == -1))
        return static_cast<uint64>(immediate.value());
    return std::nullopt;
}

void DissasmAsmPreCacheData::AnnounceCallInstruction(const AsmFunctionDetails* functionDetails, bool registerArguments)
{
    // the lines prepared so far (above the call); the call line itself is not added yet
    if (cachedAsmLines.empty())
        return;
    // the name of the argument before the generated text of the line: lpFileName "C:\\file.txt"; a constant with its symbolic name:
    // dwDesiredAccess = GENERIC_READ
    auto nameArgument = [functionDetails](DissasmAsmPreCacheLine& line, const char* name) {
        std::string text = name;
        std::string constant;
        if (const auto value = GetArgumentImmediate(line); value.has_value())
            constant = FormatApiConstant(functionDetails->functionName, name, value.value());
        if (line.constantComment) { // a status named on the line: the value of the argument (ExitStatus = STATUS_ACCESS_DENIED)
            if (constant.empty())
                constant = line.autoComment;
            line.autoComment.clear();
            line.constantComment = false;
        }
        if (!constant.empty())
            text += " = " + constant;
        if (!line.autoComment.empty() && !line.autoComment.starts_with(text)) {
            text += ' ';
            text += line.autoComment;
            line.autoComment = std::move(text);
        } else if (line.autoComment.empty()) {
            line.autoComment = std::move(text);
        }
    };
    const uint32 startingLine = cachedAsmLines.back().currentLine;
    const auto paramsCount    = static_cast<uint32>(functionDetails->params.size());

    if (registerArguments) {
        // x64: the last instruction before the call that writes an argument register / stack slot gives that argument; the search stops
        // at the start of the block (a label, another call, a jmp or ret); a conditional jump continues into the call
        constexpr uint32 MAX_LINE_DIFF_X64 = 24;
        constexpr uint32 MAX_ARGUMENTS     = 20;
        bool named[MAX_ARGUMENTS]          = {};
        uint32 remaining                   = std::min(paramsCount, MAX_ARGUMENTS);
        for (auto it = cachedAsmLines.rbegin(); it != cachedAsmLines.rend() && remaining; ++it) {
            const auto kind = static_cast<X86InstructionKind>(it->instructionKind);
            if (startingLine - it->currentLine > MAX_LINE_DIFF_X64 || it->size == 0 || (it->flags & DissasmAsmPreCacheLine::InstructionFlag::CallFlag) ||
                kind == X86InstructionKind::Call || kind == X86InstructionKind::Jump || kind == X86InstructionKind::Return)
                break;
            const uint8 slot = it->argumentSlot;
            if (slot >= paramsCount || slot >= MAX_ARGUMENTS || named[slot])
                continue;
            named[slot] = true;
            remaining--;
            if (functionDetails->params[slot].name && functionDetails->params[slot].name[0]) // not a parameter an inferred prototype does not know
                nameArgument(*it, functionDetails->params[slot].name);
        }
        return;
    }

    // x86: the pushes, the last one is the first argument; GCC stores them instead: mov dword ptr [esp + 4], ... is the second. The walk
    // goes past the calls made while the arguments are pushed (push eax; push 0; call GetProcessHeap; push eax ; hHeap; call HeapAlloc):
    // the pushes such a call takes are left to it, the arguments of a known stdcall API (its prototype) or the ones its caller removes
    // after it (cdecl: pop ecx / add esp, 8 right after the call); a call that takes what is not known ends it, as a jmp / ret
    constexpr uint32 MAX_LINE_DIFF = 32;
    uint32 pushIndex = 0, remaining = paramsCount;
    uint32 taken           = 0;     // the pushes found later that a pop / add esp / a call took (they are not arguments of this call)
    bool cleanedUpAfter    = false; // the call met next (walking back) is a cdecl one: its pushes are counted by its clean up
    const auto calleeName  = [](const DissasmAsmPreCacheLine& line) -> std::string_view {
        if (line.mapping)
            return static_cast<const MemoryMappingEntry*>(line.mapping)->name; // call dword ptr [__imp_X]
        if (!line.op_str)
            return {};
        const std::string_view operands(line.op_str, line.op_str_size); // call j_memset / call sub_401000
        size_t start = operands.size();
        while (start > 0 && (std::isalnum(static_cast<unsigned char>(operands[start - 1])) || operands[start - 1] == '_' || operands[start - 1] == '@'))
            start--;
        return operands.substr(start);
    };
    std::vector<bool> named(paramsCount, false);
    for (auto it = cachedAsmLines.rbegin(); it != cachedAsmLines.rend() && remaining; ++it) {
        if (startingLine - it->currentLine > MAX_LINE_DIFF)
            break;
        const auto kind = static_cast<X86InstructionKind>(it->instructionKind);
        if (it->size != 0 && (kind == X86InstructionKind::Jump || kind == X86InstructionKind::Return))
            break; // the block of another path
        if (it->size != 0 && kind == X86InstructionKind::Call) {
            // the CFG check of a call through a pointer (mov ecx, esi; call __guard_check_icall_fptr; call esi): it takes nothing
            if (calleeName(*it).find("guard_check_icall") != std::string_view::npos)
                continue;
            if (cleanedUpAfter) {
                cleanedUpAfter = false; // cdecl: the clean up counted its arguments
                continue;
            }
            if (it->calleePushes != DissasmAsmPreCacheLine::NO_PUSHES) {
                taken += it->calleePushes; // a function of the file: what it pops (ret 0x10), nothing for one that reads no stack argument
                continue;
            }
            const auto* inner = FindApiPrototype(calleeName(*it));
            const auto pushes = inner ? GetX86StdcallPushes(*inner) : std::nullopt; // stdcall: the callee takes its arguments
            if (!pushes.has_value())
                break; // what it takes is not known (a cdecl call cleaned up later, a function of the file)
            taken += pushes.value();
            continue;
        }
        if (it->size != 0 && it->flags != DissasmAsmPreCacheLine::InstructionFlag::PushFlag && it->op_str) {
            // pop ecx / add esp, 0xc: the pushes before them are taken (the clean up of the call right before them)
            const std::string_view operands(it->op_str, it->op_str_size);
            uint32 removed = 0;
            if (strcmp(it->mnemonic, "pop") == 0)
                removed = 1;
            else if (strcmp(it->mnemonic, "add") == 0 && operands.starts_with("esp, "))
                removed = static_cast<uint32>(std::strtoul(std::string(operands.substr(5)).c_str(), nullptr, 0) / 4);
            if (removed > 0) {
                taken += removed;
                const auto previous = std::next(it);
                cleanedUpAfter      = previous != cachedAsmLines.rend() && previous->size != 0 &&
                                 static_cast<X86InstructionKind>(previous->instructionKind) == X86InstructionKind::Call;
                continue;
            }
        }
        uint32 slot = paramsCount;
        if (it->flags == DissasmAsmPreCacheLine::InstructionFlag::PushFlag) {
            if (taken > 0) {
                taken--; // an argument of a call made in between
                continue;
            }
            slot = pushIndex++;
        } else if (it->argumentSlot != DissasmAsmPreCacheLine::NO_ARGUMENT)
            slot = it->argumentSlot;
        if (slot >= paramsCount || named[slot])
            continue;
        named[slot] = true;
        remaining--;
        if (functionDetails->params[slot].name && functionDetails->params[slot].name[0])
            nameArgument(*it, functionDetails->params[slot].name);
    }
}

void Instance::ProcessSpaceKey(bool goToEntryPoint)
{
    const auto linePos = Cursor.ToLinePosition();

    const auto zonesFound = GetZonesIndexesFromLinePosition(linePos.line);
    // F2 from anywhere: the zone of the entry point when the cursor is not in it (a structure, another executable section)
    if (goToEntryPoint) {
        const auto isEntryZone = [](const std::unique_ptr<ParseZone>& zone) {
            return zone->zoneType == DissasmParseZoneType::DissasmCodeParseZone && static_cast<DissasmCodeZone*>(zone.get())->zoneDetails.HasEntryPoint();
        };
        if (zonesFound.size() != 1 || !isEntryZone(settings->parseZones[zonesFound[0].zoneIndex])) {
            for (const auto& other : settings->parseZones) {
                if (!isEntryZone(other))
                    continue;
                if (GoToFileOffset(static_cast<DissasmCodeZone*>(other.get())->zoneDetails.entryPoint))
                    GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::GotoEntrypoint);
                return;
            }
            Dialogs::MessageBox::ShowNotification("Warning", "The entry point is not in a dissasm zone!");
            return;
        }
    }
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a single zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (goToEntryPoint && zone->isCollapsed) {
        ChangeZoneCollapseState(zone.get(), linePos.line);
    }
    if (!goToEntryPoint && zonesFound[0].startingLine == 0) // extending zone
    {
        ChangeZoneCollapseState(zone.get(), linePos.line);
        return;
    }

    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        if (goToEntryPoint)
            Dialogs::MessageBox::ShowNotification("Warning", "Please make a selection on a dissasm zone!");
        return;
    }

    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    // a collapsed zone line, or the first line of a collapsible zone that is not a jump / call: SPACE collapses / expands the zone
    if (!goToEntryPoint && zonesFound[0].startingLine >= 2 && convertedZone->CanReachAsmLines()) {
        DissasmInsnExtractLineParams params{};
        params.obj         = obj;
        params.zone        = convertedZone;
        params.settings    = settings.get();
        params.asmData     = &asmData;
        const auto asmLine = convertedZone->GetCurrentAsmLine(zonesFound[0].startingLine - 2u, obj, &params);
        const bool isBranch =
              (asmLine.flags & (DissasmAsmPreCacheLine::InstructionFlag::CallFlag | DissasmAsmPreCacheLine::InstructionFlag::JmpFlag)) != 0;
        if (asmLine.isCollapsedLine || (asmLine.shouldAddButton && !isBranch)) {
            ChangeZoneCollapseState(zone.get(), linePos.line);
            return;
        }
    }
    uint64* offsetToReach = nullptr;
    if (goToEntryPoint)
        offsetToReach = &convertedZone->zoneDetails.entryPoint;
    DissasmZoneProcessSpaceKey(convertedZone, zonesFound[0].startingLine, offsetToReach);
}

CursorState Instance::SaveCursorState() const
{
    CursorState state;
    const uint32 line = Cursor.startViewLine + Cursor.lineInView;
    state.lineInView  = Cursor.lineInView;
    state.offset      = Cursor.offset;
    state.lineInZone  = line;

    const auto zonesFound = GetZonesIndexesFromLinePosition(line);
    if (zonesFound.size() == 1) {
        state.zoneIndex  = zonesFound[0].zoneIndex;
        state.lineInZone = zonesFound[0].startingLine;
    }
    return state;
}

void Instance::RestoreCursorState(const CursorState& state)
{
    uint32 line       = state.lineInZone;
    const auto& zones = settings->parseZones;
    if (state.zoneIndex != CursorState::NO_ZONE && state.zoneIndex < zones.size()) {
        const auto& zone = zones[state.zoneIndex];
        // the zone may have been collapsed in the meantime (only its title line is left)
        const uint32 zoneLines = zone->endingLineIndex > zone->startLineIndex ? zone->endingLineIndex - zone->startLineIndex : 1u;
        line                   = zone->startLineIndex + std::min<uint32>(state.lineInZone, zoneLines - 1u);
    }
    line = std::min<uint32>(line, Layout.totalLinesSize);

    const uint32 lastRow = Layout.visibleRows > 0 ? Layout.visibleRows - 1u : 0u;
    Cursor.lineInView    = std::min<uint32>(std::min<uint32>(state.lineInView, line), lastRow);
    Cursor.startViewLine = line - Cursor.lineInView;
    Cursor.offset        = std::min<uint32>(state.offset, Layout.textSize);
    // the view changed -> the cached lines of the dissasm zones must be recomputed
    Cursor.hasMovedView = true;
}

void Instance::RecordJump(const CursorState& from)
{
    jumps_holder.Record(from, SaveCursorState());
}

bool Instance::JumpInHistory(bool back)
{
    const auto target = back ? jumps_holder.JumpBack() : jumps_holder.JumpForward();
    if (!target.has_value())
        return false;
    RestoreCursorState(target.value());
    return true;
}

void DrawLineInfo::WriteErrorToScreen(std::string_view error) const
{
    renderer.WriteSingleLineText(lineOffset, screenLineToDraw + 1, error, errorColor);
}

LinePosition Instance::CursorDissasm::ToLinePosition() const
{
    return LinePosition{ startViewLine + lineInView, offset };
}

void Instance::OnFocus()
{
    ColorMan.OnGainedFocus();
}

void Instance::OnLoseFocus()
{
    ColorMan.OnLostFocus();
}

void Instance::QuerySmartAssistant(QueryTypeSmartAssistant queryType)
{
    uint32 lineStart;
    uint32 lineEnd = 0;
    if (queryType != QueryTypeSmartAssistant::FunctionName && queryType != QueryTypeSmartAssistant::MitreTechiques &&
        queryType != QueryTypeSmartAssistant::FunctionNameAndExplanation) {
        if (!selection.HasSelection(0)) {
            Dialogs::MessageBox::ShowNotification("Warning", "Please make a single selection on a dissasm zone to select some code!");
            return;
        }
        lineStart = selection.GetSelectionStart(0).line;
        lineEnd   = selection.GetSelectionEnd(0).line;
    } else {
        lineStart = Cursor.ToLinePosition().line;
    }

    const auto zonesFound = GetZonesIndexesFromLinePosition(lineStart, lineEnd);
    if (zonesFound.empty() || zonesFound.size() != 1) {
        Dialogs::MessageBox::ShowNotification("Error", "Please make a selection on a single zone!");
        return;
    }

    const auto& zone = settings->parseZones[zonesFound[0].zoneIndex];
    if (zone->isCollapsed) {
        Dialogs::MessageBox::ShowNotification("Error", "Please make a selection on an expanded zone!");
        return;
    }
    if (zonesFound[0].startingLine <= 1) {
        Dialogs::MessageBox::ShowNotification("Warning", "Please do not select the title in the collapsible zones!");
        return;
    }
    if (zone->zoneType != DissasmParseZoneType::DissasmCodeParseZone) {
        Dialogs::MessageBox::ShowNotification("Error", "Please make a selection on a dissasm zone!");
        return;
    }
    const auto convertedZone = static_cast<DissasmCodeZone*>(zone.get());
    if (!DissasmCodeZone::IsNativeCodeLanguage(convertedZone->zoneDetails.language)) {
        Dialogs::MessageBox::ShowNotification("Error", "Query function name available only for x86, x64 and ARM64 functions!");
        return;
    }
    QuerySmartAssistantParams params = {};
    if (lineEnd >= lineStart && (queryType == QueryTypeSmartAssistant::ExplainCode || queryType == QueryTypeSmartAssistant::ConvertToHighLevel)) {
        // the selected code: from the first selected line to the last one
        params.startsAtSelectedLine = true;
        params.maxLines             = lineEnd - lineStart + 1u;
    }
    const char* architectureName = convertedZone->GetArchitectureName();
    if (queryType == QueryTypeSmartAssistant::FunctionName) {
        params.mnemonicStarsWith              = "sub_";
        params.mnemonicStartsWithError        = "This is not a function start! Please select a \"sub\" instruction! "
                                                "If they are not available please enable DeepScanning.";
        params.stopAtTheEndOfTheFunction      = true;
        params.displayPrompt                  = "Give me an appropriate name for the function: ";
        params.displayPromptUsesMnemonicParam = true;

        LocalString<320> prompt;
        prompt.SetFormat(
              "Suggest %u names for this code based on what it does separated by comma. "
              "Write only the names, separated by comma, do not write anything else. Do not write any symbols, "
              "just the names. ",
              DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST);

        params.prompt = prompt.GetText();
        QuerySmartAssistantX86X64(convertedZone, zonesFound[0].startingLine, params, queryType);
    } else if (queryType == QueryTypeSmartAssistant::ExplainCode) {
        params.displayPrompt = "Explain the selected code";
        LocalString<640> prompt;
        prompt.SetFormat(
              "Explain what this %s assembly code does. Please also add a new section at the end for comments where you explain each line "
              "in order and suggest "
              "maximum 8 words for comments describing what happens in that line. Please mark the new section by writing CommentsZoneExplained and "
              "then on the new line they start. "
              "The format for this section should be the instruction found, separated by the # character, and then the comment without additional "
              "special characters.",
              architectureName);
        params.prompt = prompt.GetText();
        QuerySmartAssistantX86X64(convertedZone, zonesFound[0].startingLine, params, queryType);
    } else if (queryType == QueryTypeSmartAssistant::ConvertToHighLevel) {
        params.displayPrompt                  = "Decompile the following assembly into a higher level language.";
        params.displayPromptUsesMnemonicParam = true;
        params.includeComments                = true;
        params.prompt                         = "Decompile the following assembly into a higher level language in C. Surround the code with \"```\"";
        QuerySmartAssistantX86X64(convertedZone, zonesFound[0].startingLine, params, queryType);
    } else if (queryType == QueryTypeSmartAssistant::FunctionNameAndExplanation) {
        LocalString<320> prompt;
        prompt.SetFormat(
              "Suggest %u pairs of name and a short statement. The name must be first and on the next line a statement. Each pair must be separated by 2 new "
              "lines."
              "Write only the text, do not write anything else. Do not write any symbols, just the pairs. ",
              DISSASM_ASSISTANT_FUNCTION_NAMES_TO_REQUEST);

        params.prompt                         = prompt.GetText();
        params.mnemonicStarsWith              = "sub_";
        params.mnemonicStartsWithError        = "This is not a function start! Please select a \"sub\" instruction! "
                                                "If they are not available please enable DeepScanning.";
        params.stopAtTheEndOfTheFunction      = true;
        params.displayPrompt                  = "Give me pairs of name and explanation for this function.";
        params.displayPromptUsesMnemonicParam = true;
        QuerySmartAssistantX86X64(convertedZone, zonesFound[0].startingLine, params, queryType);
    } else if (queryType == QueryTypeSmartAssistant::MitreTechiques) {
        params.displayPrompt                  = "What are the MITRE techniques associated with the following assembly code?";
        params.displayPromptUsesMnemonicParam = true;
        params.stopAtTheEndOfTheFunction      = true;
        params.includeComments                = true;
        params.prompt = "What is the MITRE techniques associated with the following assembly code (if any)? Only provide MITRE techniques where they can be inferred from the assembly code. Do not consider a MITRE technique if the file can potentially be part of an attack chain where you need further context to evaluate. If any technique is found, use the MITRE format: T<techniqueID>.<sub-techniqueID>.";
        QuerySmartAssistantX86X64(convertedZone, zonesFound[0].startingLine, params, queryType);
    }
}
