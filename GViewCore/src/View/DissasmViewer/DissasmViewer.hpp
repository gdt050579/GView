#pragma once

#include "Internal.hpp"

#include <unordered_map>

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using namespace AppCUI;
        enum class CharacterFormatMode : uint8
        {
            Hex,
            Octal,
            SignedDecimal,
            UnsignedDecimal,

            Count // Must be the last
        };

        struct Config
        {
            struct
            {
                ColorPair Normal;
                ColorPair Highlight;
                ColorPair Inactive;
                ColorPair Cursor;
                ColorPair Line;
            } Colors;
            struct
            {
                AppCUI::Input::Key AddNewType;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        struct DissasemblyZone
        {
            uint64 offset;
            uint64 size;
            DissamblyLanguage language;
        };

        struct SettingsData
        {
            DissamblyLanguage defaultLanguage;
            vector<DissasemblyZone> zones;
            std::unordered_map<uint64, string_view> memoryMappings;

            SettingsData();
        };

        class Instance : public View::ViewControl
        {
            struct DrawLineInfo
            {
                uint64 offset;
                uint32 lineOffset;
                uint32 numbersSize;
                uint32 textSize;
                const uint8* start;
                const uint8* end;
                Character* chNameAndSize;
                Character* chNumbers;
                Character* chText;
                bool recomputeOffsets;
                DrawLineInfo() : recomputeOffsets(true)
                {
                }
            };

            struct
            {
                uint64 startView, currentPos;
                uint32 base;
            } Cursor;

            struct
            {
                ColorPair Normal, Line, Highlighted;
            } CursorColors;

            struct
            {
                uint32 visibleRows;
                uint32 charactersPerLine;
            } Layout;

            FixSizeString<16> name;
            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;
            static Config config;
            CharacterBuffer chars;

            void RecomputeDissasmLayout();
            void WriteLineToChars(DrawLineInfo& dli);
            void PrepareDrawLineInfo(DrawLineInfo& dli);

            void MoveTo(uint64 offset, bool select);

            int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
            bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
            bool GoTo(uint64 offset) override;
            bool Select(uint64 offset, uint64 size) override;
            std::string_view GetName() override;
            void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;
            void Paint(AppCUI::Graphics::Renderer& renderer) override;

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            void OnAfterResize(int newWidth, int newHeight) override;

            // Mouse events
            bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;

            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
        };
    } // namespace DissasmViewer
} // namespace View

}; // namespace GView