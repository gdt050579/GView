#pragma once

#include "Internal.hpp"

namespace GView::View::DumpViewer
{
using namespace AppCUI;
using namespace GView::Utils;

namespace Commands
{
}

// ============================================================
// Settings data
// ============================================================

struct SettingsData {
    int data;
    String leftColumnName;
    String rightColumnName;
    std::vector<String> leftColumn;
    std::vector<String> rightColumn;
    std::vector<String> highlitedInfoLeft;
    std::vector<String> highlitedInfoRight;
    SettingsData();
};

// ============================================================
// Config
// ============================================================

struct Config {
    bool Loaded;

    static void Update(IniSection sect);
    void Initialize();
};

// ============================================================
// View instance
// ============================================================

class Instance : public View::ViewControl
{



    Pointer<SettingsData> settings;
    Reference<GView::Object> obj;
    // scrolling / selection state
    int32 cursorLine = 0;
    int32 firstLine  = 0;

    static Config config;
    int32 leftFirstLine;
    int32 leftCursorLine;
    int32 rightFirstLine;
    int32 rightCursorLine;
    bool leftActive = true;
    int splitX;
  public:

    Instance(Reference<GView::Object> _obj, Settings* _settings);


    bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
    bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
    void SetCustomPropertyValue(uint32 propertyID) override;
    bool IsPropertyValueReadOnly(uint32 propertyID) override;
    const vector<Property> GetPropertiesList() override;
    std::string_view GetCategoryNameForSerialization() const override;
    bool AddCategoryBeforePropertyNameWhenSerializing() const override;

    bool GoTo(uint64 offset) override;
    bool Select(uint64 offset, uint64 size) override;
    bool ShowGoToDialog() override;
    bool ShowFindDialog() override;
    bool ShowCopyDialog() override;
    bool Update();

    void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

    void Paint(Graphics::Renderer& renderer) override;


    bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode) override;
    void PaintColumn(
          Renderer& renderer,
          vector<String> data,
          vector<String> highlitedText,
          int32 firstLine,
          int32 cursorLine,
          int x,
          int width,
          bool active,
          const char* columnName);
};

} // namespace GView::View::DumpViewer
