#pragma once

#include "Internal.hpp"

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
       
        struct SettingsData
        {
            SettingsData();
        };

        class Instance : public View::ViewControl
        {
            FixSizeString<16> name;
            Reference<GView::Object> obj;
            Pointer<SettingsData> settings;

        public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            bool GetPropertyValue(uint32 propertyID, PropertyValue& value) override;
            bool SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error) override;
            void SetCustomPropetyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
            bool GoTo(uint64 offset) override;
            bool Select(uint64 offset, uint64 size) override;
            std::string_view GetName() override;
            void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;
        };
    } // namespace BufferViewer
} // namespace View

}; // namespace GView