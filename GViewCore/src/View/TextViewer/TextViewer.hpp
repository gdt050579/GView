#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace TextViewer
    {
        using namespace AppCUI;

        constexpr uint32 MAX_CHARACTERS_PER_LINE = 1024;
        enum class Encoding
        {
            Ascii,
            UTF8,
            Unicode16LE,
            Unicode16BE
        };
        struct SettingsData
        {
            uint32 tabSize;
            bool wordWrap;    
            Encoding encoding;
            SettingsData();
        };

        struct Config
        {
            
            struct
            {
                AppCUI::Input::Key WordWrap;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };


        class Instance : public View::ViewControl
        {
            Array32 lineIndex;
            Array32 subLineIndex;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            FixSizeString<29> name;
            Character chars[MAX_CHARACTERS_PER_LINE];
            uint32 lineNumberWidth;

            static Config config;

            void RecomputeLineIndexes();

            bool GetLineInfo(uint32 lineNo, uint64& offset, uint32& size);
            bool ComputeSubLineIndexes(uint32 lineNo, BufferView& buf);
            int DrawLine(uint32 xScroll, int32 y, uint32 lineNo, uint32 width, Graphics::Renderer& renderer, ControlState state);
          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Graphics::Renderer& renderer) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual void OnStart() override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;


            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };

    } // namespace ImageViewer
} // namespace View

}; // namespace GView