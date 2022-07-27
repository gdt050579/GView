#include "LexicalViewer.hpp"
#include <algorithm>

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_WORD_WRAP     = 0xBF00;
constexpr uint32 INVALID_LINE_NUMBER = 0xFFFFFFFF;


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
}

void Instance::Paint(Graphics::Renderer& renderer)
{

}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    switch (keyCode)
    {

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
    }
    return false;
}
void Instance::OnUpdateScrollBars()
{

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
    //GoToDialog dlg(this->Cursor.pos, this->obj->GetData().GetSize(), this->Cursor.lineNo + 1U, static_cast<uint32>(this->lines.size()));
    //if (dlg.Show() == (int) Dialogs::Result::Ok)
    //{

    //}
    //return true;
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
std::string_view Instance::GetName()
{
    return this->name;
}
//======================================================================[Mouse coords]==================
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button)
{

}
void Instance::OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button)
{
}
bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button)
{
    NOT_IMPLEMENTED(false);
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
//======================================================================[Cursor information]==================
//int Instance::PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r)
//{
//    //uint64 start, end;
//    //bool show = (selectionID == 0) || (this->selection.IsMultiSelectionEnabled());
//    //if (show)
//    //{
//    //    if (this->selection.GetSelection(selectionID, start, end))
//    //    {
//    //        LocalString<32> tmp;
//    //        tmp.Format("%X,%X", start, (end - start) + 1);
//    //        r.WriteSingleLineText(x, y, width, tmp.GetText(), this->Cfg.Text.Normal);
//    //    }
//    //    else
//    //    {
//    //        r.WriteSingleLineText(x, y, width, "NO Selection", Cfg.Text.Inactive, TextAlignament::Center);
//    //    }
//    //}
//    //r.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, this->Cfg.Lines.Normal);
//    return x + width + 1;
//}
void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    //LocalString<128> tmp;
    //auto xPoz = 0;
    //if (height == 1)
    //{
    //    xPoz = PrintSelectionInfo(0, 0, 0, 16, r);
    //    if (this->selection.IsMultiSelectionEnabled())
    //    {
    //        xPoz = PrintSelectionInfo(1, xPoz, 0, 16, r);
    //        xPoz = PrintSelectionInfo(2, xPoz, 0, 16, r);
    //        xPoz = PrintSelectionInfo(3, xPoz, 0, 16, r);
    //    }
    //    xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //    xPoz = this->WriteCursorInfo(r, xPoz, 0, 10, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //    xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    //}
    //else
    //{
    //    PrintSelectionInfo(0, 0, 0, 16, r);
    //    xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
    //    PrintSelectionInfo(1, xPoz, 0, 16, r);
    //    xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
    //    this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //    xPoz = this->WriteCursorInfo(r, xPoz, 1, 20, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //    xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    //}
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