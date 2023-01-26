#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr auto SECTION_NAME_VIEW_BUFFER = "View.Buffer";

constexpr auto KEY_NAME_CHANGE_COLUMNS_COUNT      = "Key.ChangeColumnsCount";
constexpr auto KEY_NAME_CHANGE_VALUE_FORMAT_OR_CP = "Key.ChangeValueFormatOrCP";
constexpr auto KEY_NAME_CHANGE_ADDRESS_MODE       = "Key.ChangeAddressMode";
constexpr auto KEY_NAME_GO_TO_ENTRY_POINT         = "Key.GoToEntryPoint";
constexpr auto KEY_NAME_CHANGE_SELECTION_TYPE     = "Key.ChangeSelectionType";
constexpr auto KEY_NAME_SHOW_HIDE_STRINGS         = "Key.ShowHideStrings";
constexpr auto KEY_NAME_FIND_NEXT                 = "Key.FindNext";
constexpr auto KEY_NAME_FIND_PREVIOUS             = "Key.FindPrevious";
constexpr auto KEY_NAME_COPY                      = "Key.Copy";

constexpr auto KEY_CHANGE_COLUMNS_COUNT      = Key::F6;
constexpr auto KEY_CHANGE_VALUE_FORMAT_OR_CP = Key::F2;
constexpr auto KEY_CHANGE_ADDRESS_MODE       = Key::F3;
constexpr auto KEY_GO_TO_ENTRY_POINT         = Key::F7;
constexpr auto KEY_CHANGE_SELECTION_TYPE     = Key::F9;
constexpr auto KEY_SHOW_HIDE_STRINGS         = Key::Alt | Key::F3;
constexpr auto KEY_FIND_NEXT                 = Key::Ctrl | Key::F7;
constexpr auto KEY_FIND_PREVIOUS             = Key::Ctrl | Key::Shift | Key::F7;
constexpr auto KEY_COPY                      = Key::Ctrl | Key::Insert;

void Config::Update(IniSection sect)
{
    sect.UpdateValue(KEY_NAME_CHANGE_COLUMNS_COUNT, KEY_CHANGE_COLUMNS_COUNT, true);
    sect.UpdateValue(KEY_NAME_CHANGE_VALUE_FORMAT_OR_CP, KEY_CHANGE_VALUE_FORMAT_OR_CP, true);
    sect.UpdateValue(KEY_NAME_CHANGE_ADDRESS_MODE, KEY_CHANGE_ADDRESS_MODE, true);
    sect.UpdateValue(KEY_NAME_GO_TO_ENTRY_POINT, KEY_GO_TO_ENTRY_POINT, true);
    sect.UpdateValue(KEY_NAME_CHANGE_SELECTION_TYPE, KEY_CHANGE_SELECTION_TYPE, true);
    sect.UpdateValue(KEY_NAME_SHOW_HIDE_STRINGS, KEY_SHOW_HIDE_STRINGS, true);
    sect.UpdateValue(KEY_NAME_FIND_NEXT, KEY_FIND_NEXT, true);
    sect.UpdateValue(KEY_NAME_FIND_PREVIOUS, KEY_FIND_PREVIOUS, true);
    sect.UpdateValue(KEY_NAME_COPY, KEY_COPY, true);
}

void Config::Initialize()
{
    this->Colors.Ascii   = ColorPair{ Color::Red, Color::DarkBlue };
    this->Colors.Unicode = ColorPair{ Color::Yellow, Color::DarkBlue };

    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                        = ini->GetSection(SECTION_NAME_VIEW_BUFFER);
        this->Keys.ChangeColumnsNumber   = sect.GetValue(KEY_NAME_CHANGE_COLUMNS_COUNT).ToKey(KEY_CHANGE_COLUMNS_COUNT);
        this->Keys.ChangeValueFormatOrCP = sect.GetValue(KEY_NAME_CHANGE_VALUE_FORMAT_OR_CP).ToKey(KEY_CHANGE_VALUE_FORMAT_OR_CP);
        this->Keys.ChangeAddressMode     = sect.GetValue(KEY_NAME_CHANGE_ADDRESS_MODE).ToKey(KEY_CHANGE_ADDRESS_MODE);
        this->Keys.GoToEntryPoint        = sect.GetValue(KEY_NAME_GO_TO_ENTRY_POINT).ToKey(KEY_GO_TO_ENTRY_POINT);
        this->Keys.ChangeSelectionType   = sect.GetValue(KEY_NAME_CHANGE_SELECTION_TYPE).ToKey(KEY_CHANGE_SELECTION_TYPE);
        this->Keys.ShowHideStrings       = sect.GetValue(KEY_NAME_SHOW_HIDE_STRINGS).ToKey(KEY_SHOW_HIDE_STRINGS);
        this->Keys.FindNext              = sect.GetValue(KEY_NAME_FIND_NEXT).ToKey(KEY_FIND_NEXT);
        this->Keys.FindPrevious          = sect.GetValue(KEY_NAME_FIND_PREVIOUS).ToKey(KEY_FIND_PREVIOUS);
        this->Keys.Copy                  = sect.GetValue(KEY_NAME_COPY).ToKey(KEY_COPY);
    }
    else
    {
        this->Keys.ChangeColumnsNumber   = KEY_CHANGE_COLUMNS_COUNT;
        this->Keys.ChangeValueFormatOrCP = KEY_CHANGE_VALUE_FORMAT_OR_CP;
        this->Keys.ChangeAddressMode     = KEY_CHANGE_ADDRESS_MODE;
        this->Keys.GoToEntryPoint        = KEY_GO_TO_ENTRY_POINT;
        this->Keys.ChangeSelectionType   = KEY_CHANGE_SELECTION_TYPE;
        this->Keys.ShowHideStrings       = KEY_SHOW_HIDE_STRINGS;
        this->Keys.FindNext              = KEY_FIND_NEXT;
        this->Keys.FindPrevious          = KEY_FIND_PREVIOUS;
        this->Keys.Copy                  = KEY_COPY;
    }

    this->Loaded = true;
}