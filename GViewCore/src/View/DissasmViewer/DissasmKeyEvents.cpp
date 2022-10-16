#include "DissasmViewer.hpp"

constexpr uint32 COMMAND_ADD_NEW_TYPE          = 100;
constexpr uint32 COMMAND_ADD_SHOW_FILE_CONTENT = 101;

// TODO: fix remove duplicate with Instance.cpp
constexpr int32 RIGHT_CLICK_MENU_CMD_NEW      = 0;
constexpr int32 RIGHT_CLICK_MENU_CMD_EDIT     = 1;
constexpr int32 RIGHT_CLICK_MENU_CMD_DELETE   = 2;
constexpr int32 RIGHT_CLICK_MENU_CMD_COLLAPSE = 3;
constexpr int32 RIGHT_CLICK_ADD_COMMENT       = 4;
constexpr int32 RIGHT_CLICK_REMOVE_COMMENT    = 5;

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

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
    auto xPoz = static_cast<uint32>(x);
    if ((xPoz >= Layout.startingTextLineOffset) && (xPoz < Layout.startingTextLineOffset + Layout.textSize))
    {
        mpInfo.location     = MouseLocation::OnView;
        mpInfo.bufferOffset = yPoz * Layout.textSize + xPoz - Layout.startingTextLineOffset;
    }
    if (mpInfo.location == MouseLocation::OnView)
    {
        mpInfo.bufferOffset += Cursor.startView;
        if (mpInfo.bufferOffset >= this->obj->GetData().GetSize())
            mpInfo.location = MouseLocation::Outside;
    }
}

void Instance::MoveTo(uint64 offset, bool select)
{
    const uint64 dataSize = config.ShowFileContent ? obj->GetData().GetSize() : GetZonesMaxSize();
    if (dataSize == 0)
        return;
    if (offset > (dataSize - 1))
        offset = dataSize - 1;

    // if (offset == this->Cursor.currentPos)
    //{
    //     this->Cursor.startView = offset;
    //     return;
    // }

    auto h    = this->Layout.visibleRows;
    auto sz   = this->Layout.textSize * h;
    auto sidx = -1;
    if (select)
        sidx = this->selection.BeginSelection(this->Cursor.currentPos);
    if ((offset >= this->Cursor.startView) && (offset < this->Cursor.startView + sz))
    {
        this->Cursor.currentPos = offset;
        if ((select) && (sidx >= 0))
        {
            this->selection.UpdateSelection(sidx, offset);
            // UpdateCurrentSelection();
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
        // UpdateCurrentSelection();
    }
}

void Instance::MoveScrollTo(uint64 offset)
{
    if (this->obj->GetData().GetSize() == 0)
        return;
    if (offset > (obj->GetData().GetSize() - 1))
        offset = obj->GetData().GetSize() - 1;
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

void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if (mpInfo.location == MouseLocation::OnView)
    {
        if (mpInfo.bufferOffset != Cursor.currentPos && button == MouseButton::Left)
            MoveTo(mpInfo.bufferOffset, false);
        else if (button == MouseButton::Right)
        {
            rightClickOffset = mpInfo.bufferOffset;
            rightClickMenu.Show(this, x, y);
        }
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

bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button)
{
    MousePositionInfo mpInfo;
    AnalyzeMousePosition(x, y, mpInfo);
    // make sure that consecutive click on the same location will not scroll the view to that location
    if (button == MouseButton::Left && (mpInfo.location == MouseLocation::OnView) && (mpInfo.bufferOffset != Cursor.currentPos))
    {
        MoveTo(mpInfo.bufferOffset, true);
        return true;
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
    case MouseWheel::Left:
        return OnKeyEvent(Key::PageUp, false);
    case MouseWheel::Right:
        return OnKeyEvent(Key::PageDown, false);
    }

    return false;
}

bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    bool select = ((keyCode & Key::Shift) != Key::None);
    if (select)
        keyCode = static_cast<Key>((uint32) keyCode - (uint32) Key::Shift);

    switch (keyCode)
    {
    case Key::Down:
        MoveTo(this->Cursor.currentPos + this->Layout.textSize, select);
        return true;
    case Key::Up:
        if (this->Cursor.currentPos > this->Layout.textSize)
            MoveTo(this->Cursor.currentPos - this->Layout.textSize, select);
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
        MoveTo(this->Cursor.currentPos + static_cast<uint64>(this->Layout.textSize) * this->Layout.visibleRows, select);
        return true;
    case Key::PageUp:
        if (this->Cursor.currentPos > static_cast<uint64>(this->Layout.textSize) * this->Layout.visibleRows)
            MoveTo(this->Cursor.currentPos - static_cast<uint64>(this->Layout.textSize) * this->Layout.visibleRows, select);
        else
            MoveTo(0, select);
        return true;
    case Key::Home:
        MoveTo(this->Cursor.currentPos - (this->Cursor.currentPos - this->Cursor.startView) % this->Layout.textSize, select);
        return true;
    case Key::End:
        MoveTo(
              this->Cursor.currentPos - (this->Cursor.currentPos - this->Cursor.startView) % this->Layout.textSize + this->Layout.textSize -
                    1,
              select);
        return true;
    case Key::Ctrl | Key::Up:
        if (this->Cursor.startView > this->Layout.textSize)
            MoveScrollTo(this->Cursor.startView - this->Layout.textSize);
        else
            MoveScrollTo(0);
        return true;
    case Key::Ctrl | Key::Down:
        MoveScrollTo(this->Cursor.startView + this->Layout.textSize);
        return true;
    case Key::Ctrl | Key::Left:
        if (this->Cursor.startView >= 1)
            MoveScrollTo(this->Cursor.startView - 1);
        return true;
    case Key::Ctrl | Key::Right:
        MoveScrollTo(this->Cursor.startView + 1);
        return true;
    case Key::Delete:
        RemoveComment();
        return true;
    }
    if (charCode == ';')
    {
        AddComment();
        return true;
    }
    return false;
}

bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    const AppCUI::Utils::ConstString ShowFileContentText = config.ShowFileContent ? "ShowFileContent" : "HideFileContent";
    commandBar.SetCommand(config.Keys.AddNewType, "AddNewType", COMMAND_ADD_NEW_TYPE);
    commandBar.SetCommand(config.Keys.ShowFileContentKey, ShowFileContentText, COMMAND_ADD_SHOW_FILE_CONTENT);

    return false;
}

bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::Command)
    {
        switch (ID)
        {
        case COMMAND_ADD_NEW_TYPE:
            Dialogs::MessageBox::ShowNotification("Info", "OK!");
            return true;
        case COMMAND_ADD_SHOW_FILE_CONTENT:
            config.ShowFileContent = !config.ShowFileContent;
            this->RecomputeDissasmZones();
            return true;
        case RIGHT_CLICK_MENU_CMD_COLLAPSE:
            AddNewCollapsibleZone();
            return true;
        case RIGHT_CLICK_ADD_COMMENT:
            AddComment();
            return true;
        case RIGHT_CLICK_REMOVE_COMMENT:
            RemoveComment();
            return true;
        default:
            return false;
        }
    }

    return false;
}
