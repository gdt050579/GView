#include "DissasmViewer.hpp"
#include <cmath>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

void Instance::AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo)
{
    mpInfo.location = MouseLocation::Outside;
    if (y < 0) {
        mpInfo.location = MouseLocation::Outside;
        return;
    }
    if (y == 0) {
        mpInfo.location = MouseLocation::OnHeader;
        return;
    }
    // y>=1 --> check if in buffer
    auto yPoz = y - 1;
    if (x < 0) {
        mpInfo.location = MouseLocation::Outside;
        return;
    }
    const auto xPoz = static_cast<uint32>(x);
    if ((xPoz >= Layout.startingTextLineOffset) && (xPoz < Layout.startingTextLineOffset + Layout.textSize)) {
        mpInfo.location = MouseLocation::OnView;
        mpInfo.offset   = xPoz - Layout.startingTextLineOffset;
        mpInfo.lines    = yPoz;
    }
    /*if (mpInfo.location == MouseLocation::OnView)
    {
        mpInfo.bufferOffset += Cursor.startView;
        if (mpInfo.bufferOffset >= this->obj->GetData().GetSize())
            mpInfo.location = MouseLocation::Outside;
    }*/
}

void Instance::MoveTo(int32 offset, int32 lines, AppCUI::Input::Key key, bool select)
{
    // TODO-- HERE!!
    //  if (offset == this->Cursor.currentPos)
    //{
    //      this->Cursor.startView = offset;
    //      return;
    //  }

    const bool ctrl_down = ((key & Key::Ctrl) != Key::None);
    const bool alt_down  = ((key & Key::Alt) != Key::None);

    auto zoneId = -1;

    if (select)
        zoneId = this->selection.BeginSelection(Cursor.ToLinePosition(), ctrl_down, alt_down);

    MoveScrollTo(offset, lines);

    if ((select) && (zoneId >= 0)) {
        this->selection.UpdateSelection(zoneId, Cursor.ToLinePosition(), ctrl_down, alt_down);
        // UpdateCurrentSelection();
    }
    // return;

    // if (lines > 0 && static_cast<uint32>(lines) < Layout.visibleRows)
    //{
    //     this->Cursor.offset += offset;
    //     this->Cursor.lineInView += lines;
    //     if ((select) && (zoneId >= 0))
    //     {
    //         this->selection.UpdateSelection(zoneId, Cursor.GetOffset(Layout.textSize));
    //         // UpdateCurrentSelection();
    //         return; // nothing to do ... already in visual space
    //     }
    // }

    // if (Cursor.lineInView < Cursor.startViewLine)
    //     Cursor.startViewLine = Cursor.lineInView;
    //  else
    //{
    //      auto dif = this->Cursor.currentPos - this->Cursor.startView;
    //      if (offset >= dif)
    //          this->Cursor.startView = offset - dif;
    //      else
    //          this->Cursor.startView = 0;
    //  }
    //  this->Cursor.currentPos = offset;
}

void Instance::MoveScrollTo(int32 offset, int32 lines)
{
    if (!Layout.totalLinesSize)
        return;
    Cursor.hasMovedView = false;

    Cursor.offset += offset;
    // this->Cursor.startViewLine += lines;
    if (lines < 0) {
        if (lines * -1 >= static_cast<int32>(Cursor.lineInView)) {
            lines += static_cast<int32>(Cursor.lineInView);
            Cursor.lineInView = 0;
            if (lines != 0) {
                Cursor.startViewLine += lines;
                Cursor.hasMovedView = true;
            }
        } else {
            Cursor.lineInView += lines;
        }
    } else {
        Cursor.lineInView += lines;
        if (Cursor.lineInView > Layout.visibleRows - 1) {
            const auto diff = abs(static_cast<int32>(Cursor.lineInView) - static_cast<int32>(Layout.visibleRows - 1));
            Cursor.startViewLine += diff;
            Cursor.lineInView -= diff;
            Cursor.hasMovedView = true;
        }
    }
    /*if (this->Cursor.startViewLine > old)
        MoveTo(offset, 0, false);
    else
    {
        auto dif = old - Cursor.startView;
        if (dif <= this->Cursor.currentPos)
            MoveTo(this->Cursor.currentPos - dif, false);
        else
            MoveTo(0, false);
    }*/
}

void Instance::OnMousePressed(int x, int y, Input::MouseButton button, Input::Key keyCode)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if (mpInfo.location == MouseLocation::OnView) {
        if (button == MouseButton::Left && (mpInfo.lines != Cursor.lineInView || mpInfo.offset != Cursor.offset)) {
            const int32 linesDiff  = static_cast<int32>(mpInfo.lines) - Cursor.lineInView;
            const int32 offsetDiff = static_cast<int32>(mpInfo.offset) - Cursor.offset;
            MoveTo(offsetDiff, linesDiff, keyCode, false);
        } else if (button == MouseButton::Right) {
            // the menu acts on the clicked line (it acted on the line of the cursor); a click inside the selection keeps it (the selection
            // based actions: collapsible zones, assistant)
            const uint32 clickedLine = Cursor.startViewLine + mpInfo.lines;
            const bool insideSelection =
                  selection.HasSelection(0) && selection.GetSelectionStart(0).line <= clickedLine && clickedLine <= selection.GetSelectionEnd(0).line;
            if (!insideSelection && (mpInfo.lines != Cursor.lineInView || mpInfo.offset != Cursor.offset)) {
                const int32 linesDiff  = static_cast<int32>(mpInfo.lines) - Cursor.lineInView;
                const int32 offsetDiff = static_cast<int32>(mpInfo.offset) - Cursor.offset;
                MoveTo(offsetDiff, linesDiff, Key::None, false);
            }
            rightClickMenu.Show(this, x, y);
        }
    } else if (mpInfo.location == MouseLocation::Outside) {
        // the buttons of the zones and the bullets of the collapsible zones inside the code zones; they are placed on screen rows (1 for the
        // initial empty line), the zones use absolute lines
        for (const auto* buttons : { &MyLine.buttons, &MyLine.bullets }) {
            for (const auto& btn : *buttons)
                if (btn.x == x && btn.y == y) {
                    ChangeZoneCollapseState(btn.zone, Cursor.startViewLine + static_cast<uint32>(btn.y - 1));
                    return;
                }
        }
    }
}

bool Instance::OnMouseDrag(int x, int y, Input::MouseButton button, Input::Key keyCode)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if (button == MouseButton::Left && mpInfo.location == MouseLocation::OnView && (mpInfo.lines != Cursor.lineInView || mpInfo.offset != Cursor.offset)) {
        const int32 linesDiff  = static_cast<int32>(mpInfo.lines) - Cursor.lineInView;
        const int32 offsetDiff = static_cast<int32>(mpInfo.offset) - Cursor.offset;
        MoveTo(offsetDiff, linesDiff, keyCode, true);
        return true;
    }
    return false;
}

bool Instance::OnMouseWheel(int, int, Input::MouseWheel direction, Input::Key)
{
    switch (direction) {
    case MouseWheel::Up:
        return ExecuteNavigationCommand(COMMAND_NAV_SCROLL_UP, false);
    case MouseWheel::Down:
        return ExecuteNavigationCommand(COMMAND_NAV_SCROLL_DOWN, false);
    case MouseWheel::Left:
        return ExecuteNavigationCommand(COMMAND_NAV_PAGE_UP, false);
    case MouseWheel::Right:
        return ExecuteNavigationCommand(COMMAND_NAV_PAGE_DOWN, false);
    }

    return false;
}

bool Instance::ExecuteNavigationCommand(uint32 commandId, bool select)
{
    switch (commandId) {
    case COMMAND_NAV_DOWN:
        if (Cursor.startViewLine + Cursor.lineInView + 1 <= Layout.totalLinesSize)
            MoveTo(0, 1, Key::Down, select);
        return true;
    case COMMAND_NAV_UP:
        if (Cursor.startViewLine + Cursor.lineInView > 0)
            MoveTo(0, -1, Key::Up, select);
        else
            MoveTo(-static_cast<int32>(Cursor.offset), 0, Key::Up, select);
        return true;
    case COMMAND_NAV_LEFT:
        if (this->Cursor.offset > 0)
            MoveTo(-1, 0, Key::Left, select);
        return true;
    case COMMAND_NAV_RIGHT:
        // the last column is textSize - 1: a cursor placed after it was converted to the first column of the next line
        if (this->Cursor.offset + 1 < this->Layout.textSize)
            MoveTo(1, 0, Key::Right, select);
        return true;
    case COMMAND_NAV_PAGE_DOWN:
        if (Cursor.startViewLine + Cursor.lineInView + this->Layout.visibleRows <= Layout.totalLinesSize)
            MoveTo(0, this->Layout.visibleRows, Key::PageDown, select);
        else
            MoveTo(0, Layout.totalLinesSize - Cursor.startViewLine - Cursor.lineInView, Key::PageDown, select);
        return true;
    case COMMAND_NAV_PAGE_UP:
        if (Cursor.startViewLine + Cursor.lineInView >= this->Layout.visibleRows)
            MoveTo(0, -static_cast<int32>(this->Layout.visibleRows), Key::PageUp, select);
        else
            MoveTo(0, -static_cast<int32>(Cursor.startViewLine + Cursor.lineInView), Key::PageUp, select);
        return true;
    case COMMAND_NAV_HOME:
        MoveTo(-static_cast<int32>(Cursor.offset), 0, Key::Home, select);
        return true;
    case COMMAND_NAV_END:
        // move to the last character of the line (offset relative to the cursor; lines = 0)
        MoveTo(static_cast<int32>(this->Layout.textSize) - 1 - static_cast<int32>(Cursor.offset), 0, Key::End, select);
        return true;
    case COMMAND_NAV_SCROLL_UP:
        if (this->Cursor.lineInView + this->Cursor.startViewLine > 0)
            MoveScrollTo(0, -1);
        return true;
    case COMMAND_NAV_SCROLL_DOWN:
        if (Cursor.startViewLine + Cursor.lineInView + 1 < Layout.totalLinesSize)
            MoveScrollTo(0, 1);
        return true;
    case COMMAND_NAV_SCROLL_LEFT:
        if (this->Cursor.offset >= 1)
            MoveScrollTo(-1, 0);
        return true;
    case COMMAND_NAV_SCROLL_RIGHT:
        if (this->Cursor.offset + 1 < Layout.textSize)
            MoveScrollTo(1, 0);
        return true;
    case COMMAND_NAV_SPACE:
        ProcessSpaceKey();
        return true;
    case COMMAND_NAV_OPEN:
        OpenCurrentSelection();
        return true;
    case COMMAND_NAV_ADD_ZONE:
        CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation::Add);
        return true;
    case COMMAND_ADD_OR_EDIT_COMMENT:
        AddComment();
        return true;
    case COMMAND_REMOVE_COMMENT:
        RemoveComment();
        return true;
    case COMMAND_ACCEPT_AI_SUGGESTION:
        AcceptOrDismissAISuggestion(true);
        return true;
    case COMMAND_DISMISS_AI_SUGGESTION:
        AcceptOrDismissAISuggestion(false);
        return true;
    case COMMAND_RENAME_LABEL:
        RenameLabel();
        return true;
    case COMMAND_REMOVE_LOCAL_VARIABLE:
        RemoveLocalVariable();
        return true;
    case COMMAND_SAVE_DISSASM_CACHE:
        SaveCacheData();
        return true;
    case COMMAND_TOGGLE_NUMBER_BASE:
        ToggleNumberBase();
        return true;
    }
    return false;
}

bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    const auto action = Config::Map.Resolve(keyCode);
    if (keyCode == Key::Escape && aiNaming.zone) {
        aiNaming = {}; // the names received so far stay
        RefreshDrawnLines();
        return true;
    }
    if (HasPendingDeepScans()) {
        if (keyCode == Key::Escape) {
            CancelDeepScans(); // the zones keep their instructions without labels
            return true;
        }
        // the moves do not need the labels; the other actions do (rename, comments, zones); a frontend without frame updates (no FPS
        // mode) ends the scans at the first key
        const bool isMove = action.commandId >= COMMAND_NAV_DOWN && action.commandId <= COMMAND_NAV_SCROLL_RIGHT;
        if (!frameUpdatesSeen || (action.commandId != Input::KeyMap::NO_COMMAND && !isMove))
            FinishDeepScans();
    }
    if ((action.commandId != Input::KeyMap::NO_COMMAND) && (ExecuteNavigationCommand(action.commandId, action.extendSelection)))
        return true;

    if (keyCode == Key::Escape)
        SaveCacheData();

    return ViewControl::OnKeyEvent(keyCode, charCode);
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    for (const auto& cmd : config.CommandBarCommands)
        commandBar.SetCommand(cmd.get().Key, cmd.get().Caption, cmd.get().CommandId);
    commandBar.SetCommand(config.OpenSelectionCommand.Key, config.OpenSelectionCommand.Caption, COMMAND_NAV_OPEN);

    return false;
}

bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::Command) {
        FinishDeepScans(); // every command uses the analysis (labels, cross references, the cache, the export)
        switch (ID) {
        case COMMAND_ADD_NEW_TYPE:
            Dialogs::MessageBox::ShowNotification("Info", "OK!");
            return true;
        case COMMAND_ADD_SHOW_FILE_CONTENT:
            config.ShowFileContent = !config.ShowFileContent;
            this->RecomputeDissasmZones();
            return true;
        case COMMAND_CHANGE_ADDRESS_MODE:
            ChangeAddressMode();
            return true;
        case COMMAND_SHOW_XREFS:
            ShowXrefs();
            return true;
        case COMMAND_SHOW_FUNCTIONS:
            ShowFunctions();
            return true;
        case COMMAND_SHOW_STRINGS:
            ShowStrings();
            return true;
        case COMMAND_FIND_NEXT:
            FindNext();
            return true;
        case COMMAND_UNDO:
            UndoOrRedo(false);
            return true;
        case COMMAND_REDO:
            UndoOrRedo(true);
            return true;
        case COMMAND_COMMAND_PALETTE:
            ShowCommandPalette();
            return true;
        case COMMAND_SHOW_CALL_TREE:
            ShowCallTree();
            return true;
        case COMMAND_SHOW_GRAPH:
            ShowFunctionGraph();
            return true;
        case COMMAND_TOGGLE_AI_SUGGESTIONS:
            showAISuggestions = !showAISuggestions;
            RefreshDrawnLines();
            return true;
        case COMMAND_SUGGEST_NAMES:
            StartAINaming();
            return true;
        case COMMAND_SHOW_ONLY_DISSASM:
            config.ShowOnlyDissasm = !config.ShowOnlyDissasm;
            RefreshDrawnLines();
            return true;
        // case RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE:
        //     AddNewCollapsibleTextZone();
        //     return true;
        case RIGHT_CLICK_ADD_COMMENT:
            AddComment();
            return true;
        case RIGHT_CLICK_CODE_ZONE_EDIT:
            EditDissasmCodeZoneCommand();
            return true;
        case COMMAND_QUERY_FUNCTION_NAME:
        case RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_NAME_FUNCTION:
            QuerySmartAssistant(QueryTypeSmartAssistant::FunctionName);
            return true;
        case RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_EXPLAIN_CODE:
            QuerySmartAssistant(QueryTypeSmartAssistant::ExplainCode);
            return true;
        case RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_CONVERT_HIGH_LEVEL:
            QuerySmartAssistant(QueryTypeSmartAssistant::ConvertToHighLevel);
            return true;
        case RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_FN_NAME_AND_EXPLANATION:
            QuerySmartAssistant(QueryTypeSmartAssistant::FunctionNameAndExplanation);
            return true;
        case COMMAND_QUERY_MITRE_TECHNIQUE:
        case RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_MITRE_TECHNIQUES:
            QuerySmartAssistant(QueryTypeSmartAssistant::MitreTechiques);
            return true;
        case RIGHT_CLICK_REMOVE_COMMENT:
            RemoveComment();
            return true;
        case RIGHT_CLICK_DISSASM_RENAME_LOCAL_VARIABLE:
            RenameLabel();
            return true;
        case RIGHT_CLICK_DISSASM_REMOVE_LOCAL_VARIABLE:
            RemoveLocalVariable();
            return true;
        case RIGHT_CLICK_CLEAR_SELECTION:
            selection.Clear();
            return true;
        case COMMAND_EXPORT_ASM_FILE:
            CommandExportAsmFile();
            return true;
        case RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE:
            CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation::Add);
            return true;
        case RIGHT_CLICK_DISSASM_REMOVE_COLLAPSE_ZONE:
            CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation::Remove);
            return true;
        case RIGHT_CLICK_DISSASM_EXPAND_ZONE:
            CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation::Expand);
            return true;
        case RIGHT_CLICK_DISSASM_COLLAPSE_ZONE:
            CommandExecuteCollapsibleZoneOperation(CollapsibleZoneOperation::Collapse);
            return true;
        case COMMAND_JUMP_BACK:
            if (JumpInHistory(true))
                GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::JumpBack);
            return true;
        case COMMAND_JUMP_FORWARD:
            if (JumpInHistory(false))
                GView::Security::Learning::Hooks::OnSimpleEvent(obj, GView::Security::Learning::Hooks::SimpleEvent::JumpForward);
            return true;
        case COMMAND_DISSAM_GOTO_ENTRYPOINT: {
            ProcessSpaceKey(true);
            return true;
        }
        case COMMAND_NAV_OPEN:
            OpenCurrentSelection();
            return true;
        default:
            return false;
        }
    }

    return false;
}
