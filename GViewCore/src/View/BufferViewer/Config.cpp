#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

constexpr auto SECTION_NAME_VIEW_BUFFER = "View.Buffer";

constexpr auto KEY_NAME_CHANGE_COLUMNS_COUNT        = "Key.ChangeColumnsCount";
constexpr auto KEY_NAME_CHANGE_VALUE_FORMAT_OR_CP   = "Key.ChangeValueFormatOrCP";
constexpr auto KEY_NAME_CHANGE_ADDRESS_MODE         = "Key.ChangeAddressMode";
constexpr auto KEY_NAME_GO_TO_ENTRY_POINT           = "Key.GoToEntryPoint";
constexpr auto KEY_NAME_CHANGE_SELECTION_TYPE       = "Key.ChangeSelectionType";
constexpr auto KEY_NAME_SHOW_HIDE_STRINGS           = "Key.ShowHideStrings";
constexpr auto KEY_NAME_FIND_NEXT                   = "Key.FindNext";
constexpr auto KEY_NAME_FIND_PREVIOUS               = "Key.FindPrevious";
constexpr auto KEY_NAME_COPY                        = "Key.Copy";
constexpr auto KEY_NAME_DISSASM                     = "Key.DissasmDialog";
constexpr auto KEY_NAME_SHOW_COLOR_WHEN_NOT_FOCUSED = "Key.ShowColorNotFocused";

constexpr auto KEY_CHANGE_COLUMNS_COUNT        = Key::F6;
constexpr auto KEY_CHANGE_VALUE_FORMAT_OR_CP   = Key::F2;
constexpr auto KEY_CHANGE_ADDRESS_MODE         = Key::F3;
constexpr auto KEY_GO_TO_ENTRY_POINT           = Key::F7;
constexpr auto KEY_CHANGE_SELECTION_TYPE       = Key::F9;
constexpr auto KEY_SHOW_HIDE_STRINGS           = Key::Alt | Key::F3;
constexpr auto KEY_FIND_NEXT                   = Key::Ctrl | Key::F7;
constexpr auto KEY_FIND_PREVIOUS               = Key::Ctrl | Key::Shift | Key::F7;
constexpr auto KEY_DISSASM                     = Key::Ctrl | Key::D;
constexpr auto KEY_SHOW_COLOR_WHEN_NOT_FOCUSED = Key::Ctrl | Key::Alt | Key::C;

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
    sect.UpdateValue(KEY_NAME_DISSASM, KEY_DISSASM, true);
    sect.UpdateValue(KEY_NAME_SHOW_COLOR_WHEN_NOT_FOCUSED, KEY_SHOW_COLOR_WHEN_NOT_FOCUSED, true);
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
        this->Keys.DissasmDialog         = sect.GetValue(KEY_NAME_DISSASM).ToKey(KEY_DISSASM);
        this->Keys.ShowColorNotFocused   = sect.GetValue(KEY_NAME_SHOW_COLOR_WHEN_NOT_FOCUSED).ToKey(KEY_SHOW_COLOR_WHEN_NOT_FOCUSED);
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
        this->Keys.DissasmDialog         = KEY_DISSASM;
        this->Keys.ShowColorNotFocused   = KEY_SHOW_COLOR_WHEN_NOT_FOCUSED;
    }

    this->Loaded = true;
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32 {
    // display
    Columns = 0,
    CursorOffset,
    DataFormat,
    ShowAddress,
    ShowZoneName,
    ShowTypeObject,
    ShowSyncCompare,
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
    FindNext,
    FindPrevious,
    Dissasm,
    // color behavior
    ShowColorNotFocused,
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id)) {
    case PropertyID::Columns:
        value = this->Layout.nrCols;
        return true;
    case PropertyID::CursorOffset:
        value = this->cursor.GetBase() == 16;
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
    case PropertyID::ShowSyncCompare:
        value = this->showSyncCompare;
        return true;
    case PropertyID::HighlightSelection:
        value = this->CurrentSelection.highlight;
        return true;
    case PropertyID::CodePage:
        value = (uint64) ((CodePageID) this->codePage);
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
    case PropertyID::AddressType:
        value = this->currentAdrressMode;
        return true;
    case PropertyID::FindNext:
        value = config.Keys.FindNext;
        return true;
    case PropertyID::FindPrevious:
        value = config.Keys.FindPrevious;
        return true;
    case PropertyID::Dissasm:
        value = config.Keys.DissasmDialog;
        return true;
    case PropertyID::ShowColorNotFocused:
        value = config.Keys.ShowColorNotFocused;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    uint32 tmpValue;
    switch (static_cast<PropertyID>(id)) {
    case PropertyID::Columns:
        this->Layout.nrCols = (uint32) std::get<uint64>(value);
        UpdateViewSizes();
        return true;
    case PropertyID::CursorOffset:
        this->cursor.SetBase(std::get<bool>(value) ? 16 : 10);
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
        if ((tmpValue < 3) || (tmpValue > 20)) {
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
        if (tmpValue > 20) {
            error = "Address bar size must not exceed 20 characters !";
            return false;
        }
        this->Layout.lineAddressSize = tmpValue;
        UpdateViewSizes();
        return true;
    case PropertyID::ZoneNameWidth:
        tmpValue = std::get<uint32>(value);
        if (tmpValue > 20) {
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
    case PropertyID::ShowSyncCompare:
        this->showSyncCompare = std::get<bool>(value);
        return true;
    case PropertyID::HighlightSelection:
        this->CurrentSelection.highlight = std::get<bool>(value);
        return true;
    case PropertyID::CodePage:
        codePage = static_cast<CodePageID>(std::get<uint64>(value));
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
    case PropertyID::FindNext:
        config.Keys.FindNext = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::FindPrevious:
        config.Keys.FindPrevious = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::Dissasm:
        config.Keys.DissasmDialog = std::get<AppCUI::Input::Key>(value);
        return true;
    case PropertyID::AddressType:
        this->currentAdrressMode = (uint32) std::get<uint64>(value);
        return true;
    case PropertyID::ShowColorNotFocused:
        config.Keys.ShowColorNotFocused = std::get<AppCUI::Input::Key>(value);
        return true;
    }
    error.SetFormat("Unknown internal ID: %u", id);
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
    auto propID = static_cast<PropertyID>(propertyID);
    if ((propID == PropertyID::Selection_1) || (propID == PropertyID::Selection_2) || (propID == PropertyID::Selection_3) ||
        (propID == PropertyID::Selection_4)) {
        const auto idx = propertyID - (uint32) (PropertyID::Selection_1);
        SelectionEditor dlg(&this->selection, idx, this->settings.get(), this->obj->GetData().GetSize());
        dlg.Show();
    }
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    switch (static_cast<PropertyID>(propertyID)) {
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
    addressModesList.Clear();
    if (this->settings->translationMethodsCount == 0) {
        addressModesList.Set("FileOffset=0");
    } else {
        for (uint32 tr = 0; tr < settings->translationMethodsCount; tr++) {
            if (tr > 0)
                addressModesList.AddChar(',');
            addressModesList.AddFormat("%s=%u", settings->translationMethods[tr].name.GetText(), tr);
        }
    }

    return { // Display
             { BT(PropertyID::Columns), "Display", "Columns", PropertyType::List, false, "8 columns=8,16 columns=16,32 columns=32,FullScreen=0" },
             { BT(PropertyID::CursorOffset), "Display", "Cursor offset", PropertyType::Boolean, false, "Dec,Hex" },
             { BT(PropertyID::DataFormat), "Display", "Data format", PropertyType::List, false, "Hex=0,Oct=1,Signed decimal=2,Unsigned decimal=3" },
             { BT(PropertyID::ShowTypeObject), "Display", "Show Type specific patterns", PropertyType::Boolean },
             { BT(PropertyID::CodePage), "Display", "CodePage", PropertyType::List, false, CodePage::GetPropertyListValues() },

             // Address
             { BT(PropertyID::AddressType), "Address", "Type", PropertyType::List, false, addressModesList.ToStringView() },
             { BT(PropertyID::ShowAddress), "Address", "Show Address", PropertyType::Boolean },
             { BT(PropertyID::ShowZoneName), "Address", "Show Zone Name", PropertyType::Boolean },
             { BT(PropertyID::AddressBarWidth), "Address", "Address Bar Width", PropertyType::UInt32 },
             { BT(PropertyID::ZoneNameWidth), "Address", "Zone name Width", PropertyType::UInt32 },

             // Selection
             { BT(PropertyID::HighlightSelection), "Selection", "Highlight current selection", PropertyType::Boolean },
             { BT(PropertyID::SelectionType), "Selection", "Type", PropertyType::List, false, "Single=0,Multiple=1" },
             { BT(PropertyID::Selection_1), "Selection", "Selection 1", PropertyType::Custom },
             { BT(PropertyID::Selection_2), "Selection", "Selection 2", PropertyType::Custom },
             { BT(PropertyID::Selection_3), "Selection", "Selection 3", PropertyType::Custom },
             { BT(PropertyID::Selection_4), "Selection", "Selection 4", PropertyType::Custom },

             // String
             { BT(PropertyID::ShowAscii), "Strings", "Ascii", PropertyType::Boolean },
             { BT(PropertyID::ShowUnicode), "Strings", "Unicode", PropertyType::Boolean },
             { BT(PropertyID::StringCharacterSet), "Strings", "Character set", PropertyType::Ascii },
             { BT(PropertyID::MinimCharsInString), "Strings", "Minim consecutive chars", PropertyType::UInt32 },

             // shortcuts
             { BT(PropertyID::ChangeAddressMode), "Key", "ChangeAddressMode", PropertyType::Key, true },
             { BT(PropertyID::ChangeValueFormatOrCP), "Key", "ChangeValueFormatOrCP", PropertyType::Key, true },
             { BT(PropertyID::ChangeColumnsView), "Key", "ChangeColumnsCount", PropertyType::Key, true },
             { BT(PropertyID::GoToEntryPoint), "Key", "GoToEntryPoint", PropertyType::Key, true },
             { BT(PropertyID::ChangeSelectionType), "Key", "ChangeSelectionType", PropertyType::Key, true },
             { BT(PropertyID::ShowHideStrings), "Key", "ShowHideStrings", PropertyType::Key, true },
             { BT(PropertyID::Dissasm), "Key", "DissasmDialog", PropertyType::Key, true },
             { BT(PropertyID::FindNext), "Key", "FindNext", PropertyType::Key, true },
             { BT(PropertyID::FindPrevious), "Key", "FindPrevious", PropertyType::Key, true },
             { BT(PropertyID::ShowColorNotFocused), "Key", "ShowColorNotFocused", PropertyType::Key, true }
    };
}
#undef BT
