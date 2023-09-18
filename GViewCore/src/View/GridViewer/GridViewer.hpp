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
                AppCUI::Input::Key replaceHeaderWith1stRow;
                AppCUI::Input::Key toggleHorizontalLines;
                AppCUI::Input::Key toggleVerticalLines;
                AppCUI::Input::Key viewCellContent;
                AppCUI::Input::Key exportCellContent;
                AppCUI::Input::Key exportColumnContent;
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
            Reference<AppCUI::Controls::Grid> grid;
            Pointer<SettingsData> settings;

            static Config config;
            FindDialog findDialog;
            std::string exportedPathUTF8;
            std::string exportedFolderPath;
          public:
            Instance(Reference<GView::Object> obj, Settings* settings);

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
            vector<uint8_t> getHexCellContent(const std::string& content);

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