#pragma once

#include "Internal.hpp"
#include <array>
namespace GView
{
namespace View
{
    namespace GridViewer
    {
        namespace Commands
        {
            using namespace AppCUI::Input;
            constexpr uint32 COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW = 0x1000;
            constexpr uint32 COMMAND_ID_TOGGLE_HORIZONTAL_LINES     = 0x1001;
            constexpr uint32 COMMAND_ID_TOGGLE_VERTICAL_LINES       = 0x1002;
            constexpr uint32 COMMAND_ID_VIEW_CELL_CONTENT           = 0x1003;
            constexpr uint32 COMMAND_ID_EXPORT_CELL_CONTENT         = 0x1004;
            constexpr uint32 COMMAND_ID_EXPORT_COLUMN_CONTENT       = 0x1005;

            static KeyboardControl ReplaceHeader = { Key::Space, "ReplaceHeader", "Replace header with first row", COMMAND_ID_REPLACE_HEADER_WITH_1ST_ROW };

            static KeyboardControl ToggleHorizontalLines = {
                Key::H, "ToggleHorizontalLines", "Toggle horizontal lines on/off", COMMAND_ID_TOGGLE_HORIZONTAL_LINES
            };
            static KeyboardControl ToggleVerticalLines = { Key::V, "ToggleVerticalLines", "Toggle vertical lines on/off", COMMAND_ID_TOGGLE_VERTICAL_LINES };
            static KeyboardControl ViewCellContent     = {
                Key::Enter, "ViewCellContent", "View the content in the current selected cell", COMMAND_ID_VIEW_CELL_CONTENT
            };
            static KeyboardControl ExportCellContent = {
                Key::Ctrl | Key::S, "ExportCellContent", "Export the content of the current cell", COMMAND_ID_EXPORT_CELL_CONTENT
            };
            static KeyboardControl ExportColumnContent = {
                Key::Ctrl | Key::Alt | Key::S, "ExportColumnContent", "Export the content of the current column", COMMAND_ID_EXPORT_COLUMN_CONTENT
            };

            static std::array AllGridCommands = { &ReplaceHeader, &ToggleHorizontalLines, &ToggleVerticalLines, &ViewCellContent, &ExportCellContent, &ExportColumnContent };
        }


        struct SettingsData
        {
            String name;
            std::map<uint64, std::pair<uint64, uint64>> lines;
            std::map<uint64, std::vector<std::pair<uint64, uint64>>> tokens;
            char separator[2]{ "," };
            uint64 rows           = 0;
            uint64 cols           = 0;
            bool firstRowAsHeader = false;
            SettingsData();
        };

        class FindDialog : public Window, public Handlers::OnCheckInterface
        {
          private:
            Reference<GView::Object> object;
            uint64 currentPos;

            Reference<CanvasViewer> description;
            Reference<TextField> input;

            Reference<RadioBox> textOption;
            Reference<RadioBox> binaryOption;
            Reference<RadioBox> textAscii;
            Reference<RadioBox> textUnicode;
            Reference<CheckBox> textRegex;
            Reference<RadioBox> textHex;
            Reference<RadioBox> textDec;

            Reference<RadioBox> searchFile;
            Reference<RadioBox> searchSelection;

            Reference<RadioBox> bufferSelect;
            Reference<RadioBox> bufferMoveCursorTo;

            Reference<CheckBox> ignoreCase;
            Reference<CheckBox> alingTextToUpperLeftCorner;

            uint64 position{ 0 };
            uint64 length{ 0 };

            UnicodeStringBuilder usb;
            std::pair<uint64, uint64> match;
            bool newRequest{ true };
            bool ProcessInput();

          public:
            FindDialog();

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar) override;
            virtual void OnCheck(Reference<Controls::Control> control, bool value) override;
            virtual void OnFocus() override; // but it's triggered only on first show call :(
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override
            {
                return true;
            }

            bool SetDescription();
            bool Update();
            std::u16string GetFilterValue();
        };

        struct Config
        {
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
            Reference<AppCUI::Controls::Grid> grid;
            Pointer<SettingsData> settings;

            static Config config;
            FindDialog findDialog;
            std::string exportedPathUTF8;
            std::string exportedFolderPath;
          public:
            Instance(Reference<GView::Object> obj, Settings* settings, CommonInterfaces::QueryInterface* queryInterface);

            bool GoTo(uint64 offset) override;
            bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;
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
            bool UpdateKeys(KeyboardControlsInterface* interface) override;

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