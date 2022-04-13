#pragma once

#include "Internal.hpp"

#include<unordered_map>

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
                ColorPair Inactive;
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
            std::unordered_map<uint64, string_view> memmoryMappings;

            SettingsData();
        };

        class Instance : public View::ViewControl
        {
            FixSizeString<16> name;
            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;
            static Config config;

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
            virtual bool ExtractTo(Reference<AppCUI::OS::DataObject> output, ExtractItem item, uint64 size) override;

            void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;
            void Paint(AppCUI::Graphics::Renderer& renderer) override;

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
        };
    } // namespace BufferViewer
} // namespace View

}; // namespace GView