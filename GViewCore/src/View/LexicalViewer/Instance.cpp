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

    // load the entire data into a file
    auto buf                = obj->GetData().GetEntireFile();
    size_t sz               = 0;
    this->text              = GView::Utils::CharacterEncoding::ConvertToUnicode16(buf, sz);
    textLength              = (uint32) sz;
    this->Scroll.x          = 0;
    this->Scroll.y          = 0;
    this->currentTokenIndex = 0;

    if (this->settings->parser)
    {
        TokensListBuilder tokensList(this);
        this->settings->parser->AnalyzeText(TextParser(this->text, this->textLength), tokensList);
        ComputeOriginalPositions();
        EnsureCurrentItemIsVisible();
    }
}

void Instance::ComputeOriginalPositions()
{
    int32 x         = 0;
    int32 y         = 0;
    const char16* p = this->text;
    const char16* e = this->text + this->textLength;
    uint32 pos      = 0;
    uint32 idx      = 0;
    uint32 tknCount = (uint32) this->tokens.size();
    uint32 tknOffs  = tknCount > 0 ? this->tokens[0].start : 0xFFFFFFFF;

    while (p < e)
    {
        if ((*p) == '\t')
            x = ((x + 3) / 4) * 4;
        // asign position
        if (pos == tknOffs)
        {
            this->tokens[idx].x = x;
            this->tokens[idx].y = y;
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
void Instance::EnsureCurrentItemIsVisible()
{
}

void Instance::PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, bool onCursor)
{
    u16string_view txt = { this->text + tok.start, (size_t) (tok.end - tok.start) };
    auto col           = onCursor ? this->Cfg.Cursor.Normal : this->Cfg.Text.Normal;
    renderer.WriteSingleLineText(tok.x - Scroll.x, tok.y - Scroll.y, txt, col);
}
void Instance::Paint(Graphics::Renderer& renderer)
{
    const int32 scroll_right  = Scroll.x + (int32) this->GetWidth() - 1;
    const int32 scroll_bottom = Scroll.y + (int32) this->GetHeight() - 1;
    uint32 idx                = 0;
    for (auto& t : this->tokens)
    {
        const auto onCursor  = idx == currentTokenIndex;
        const auto tk_right  = t.x + (int32) t.width - 1;
        const auto tk_bottom = t.y + (int32) t.height - 1;
        idx++;
        // if token not in visible screen => skip it
        if ((t.x > scroll_right) || (t.y > scroll_bottom) || (tk_right < Scroll.x) || (tk_bottom < Scroll.y))
            continue;
        PaintToken(renderer, t, onCursor);
    }
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}
void Instance::MoveLeft(bool selected)
{
}
void Instance::MoveRight(bool selected)
{
}
void Instance::MoveUp(uint32 times, bool selected)
{
}
void Instance::MoveDown(uint32 times, bool selected)
{
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
    case Key::Down:
        MoveDown(1, false);
        return true;
    case Key::Down | Key::Shift:
        MoveDown(1, true);
        return true;
    case Key::Left:
        MoveLeft(false);
        return true;
    case Key::Left | Key::Shift:
        MoveLeft(true);
        return true;
    case Key::Right:
        MoveRight(false);
        return true;
    case Key::Right | Key::Shift:
        MoveRight(true);
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
    // GoToDialog dlg(this->Cursor.pos, this->obj->GetData().GetSize(), this->Cursor.lineNo + 1U, static_cast<uint32>(this->lines.size()));
    // if (dlg.Show() == (int) Dialogs::Result::Ok)
    //{

    //}
    // return true;
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
// int Instance::PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r)
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
    // LocalString<128> tmp;
    // auto xPoz = 0;
    // if (height == 1)
    //{
    //     xPoz = PrintSelectionInfo(0, 0, 0, 16, r);
    //     if (this->selection.IsMultiSelectionEnabled())
    //     {
    //         xPoz = PrintSelectionInfo(1, xPoz, 0, 16, r);
    //         xPoz = PrintSelectionInfo(2, xPoz, 0, 16, r);
    //         xPoz = PrintSelectionInfo(3, xPoz, 0, 16, r);
    //     }
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 10, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    // }
    // else
    //{
    //     PrintSelectionInfo(0, 0, 0, 16, r);
    //     xPoz = PrintSelectionInfo(2, 0, 1, 16, r);
    //     PrintSelectionInfo(1, xPoz, 0, 16, r);
    //     xPoz = PrintSelectionInfo(3, xPoz, 1, 16, r);
    //     this->WriteCursorInfo(r, xPoz, 0, 20, "Line:", tmp.Format("%d/%d", Cursor.lineNo + 1, (uint32) lines.size()));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 1, 20, "Col:", tmp.Format("%d", Cursor.charIndex + 1));
    //     xPoz = this->WriteCursorInfo(r, xPoz, 0, 20, "File ofs: ", tmp.Format("%llu", Cursor.pos));
    // }
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