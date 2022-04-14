#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace GridViewer
    {
        struct SettingsData
        {
            std::map<uint64, std::pair<uint64, uint64>> lines;
            std::map<uint64, std::vector<std::pair<uint64, uint64>>> tokens;
            char separator[2]{ "," };
            uint64 rows           = 0;
            uint64 cols           = 0;
            bool firstRowAsHeader = false;
            SettingsData();
        };

        struct Config
        {
            struct
            {
                AppCUI::Input::Key replaceHeaderWith1stRow;
                AppCUI::Input::Key toggleHorizontalLines;
                AppCUI::Input::Key toggleVerticalLines;
            } keys;
            struct
            {
                struct
                {
                    ColorPair name{ Color::Yellow, Color::Transparent };
                    ColorPair value{ Color::Gray, Color::Transparent };
                } cursorInformation;
            } color;
            const unsigned int cursorInformationCellSpace = 20;
            bool loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl
        {
          private:
            Reference<GView::Object> obj;
            FixSizeString<29> name;

            Reference<AppCUI::Controls::Grid> grid;
            Pointer<SettingsData> settings;

            static Config config;

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            bool GoTo(uint64 offset) override;
            bool Select(uint64 offset, uint64 size) override;
            std::string_view GetName() override;
            virtual bool ExtractTo(Reference<AppCUI::OS::DataObject> output, ExtractItem item, uint64 size) override;
            void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height) override;

            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual void OnStart() override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;

          private:
            void PopulateGrid();
            void ProcessContent();
            void PaintCursorInformationWidth(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
            void PaintCursorInformationHeight(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
            void PaintCursorInformationCells(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
            void PaintCursorInformationCurrentLocation(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
            void PaintCursorInformationSelection(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
            void PaintCursorInformationSeparator(AppCUI::Graphics::Renderer& renderer, unsigned int x, unsigned int y);
        };
    } // namespace GridViewer
} // namespace View
}; // namespace GView