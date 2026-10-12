#include "BufferViewer.hpp"

using namespace GView::View::BufferViewer;
using namespace AppCUI::Input;

[[maybe_unused]] constexpr auto SECTION_NAME_VIEW_BUFFER = "View.Buffer";

void Config::Update(IniSection)
{
    // keys are handled by the key bindings registry ([Keys.View.Buffer], "Keyboard shortcuts" window)
}

void Config::Initialize()
{
    this->Colors.Ascii   = ColorPair{ Color::Red, Color::DarkBlue };
    this->Colors.Unicode = ColorPair{ Color::Yellow, Color::DarkBlue };
    this->Loaded         = true;
}

void GView::View::BufferViewer::Commands::RegisterKeys(KeyboardControlsInterface* interface)
{
    for (auto k : CommandKeys)
        interface->RegisterKey(k);
    interface->BeginCategory("Navigation & editing");
    for (auto k : NavigationKeys)
        interface->RegisterKey(k);
    interface->RegisterKeyText("0-9", "GoToBookmark", "Move to a bookmark (bookmarks are set from the properties)");
    interface->RegisterKeyText("[ / ]", "AddressWidth", "Decrease / increase the address column width");
    interface->RegisterKeyText("{ / }", "ZoneNameWidth", "Decrease / increase the zone name column width");
}
void GView::View::BufferViewer::Commands::OnKeysChanged()
{
    Map.Build(NavigationKeys);
}

//======================================================================[PROPERTY]============================
namespace
{
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
}
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
    case PropertyID::AddressType:
        value = this->currentAdrressMode;
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
    case PropertyID::AddressType:
        this->currentAdrressMode = (uint32) std::get<uint64>(value);
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
             { BT(PropertyID::MinimCharsInString), "Strings", "Minim consecutive chars", PropertyType::UInt32 }
    };
}
#undef BT
