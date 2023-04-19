#pragma once

#include "Internal.hpp"

namespace GView
{
enum class CharacterFormatMode : uint8
{
    Hex,
    Octal,
    SignedDecimal,
    UnsignedDecimal,

    Count // Must be the last
};

enum class StringType : uint8
{
    None,
    Ascii,
    Unicode
};
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
            bool ProcessInput(uint64 end = GView::Utils::INVALID_OFFSET, bool last = false);

          public:
            FindDialog();

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar) override;
            virtual void OnCheck(Reference<Controls::Control> control, bool value) override;
            virtual void OnFocus() override; // but it's triggered only on first show call :(

            bool SetDescription();
            bool Update();
            void UpdateData(uint64 currentPos, Reference<GView::Object> object);
            std::pair<uint64, uint64> GetNextMatch(uint64 currentPos);
            std::pair<uint64, uint64> GetPreviousMatch(uint64 currentPos);
            std::u16string GetFilterValue();

            bool SelectMatch()
            {
                CHECK(bufferSelect.IsValid(), false, "");
                return bufferSelect->IsChecked();
            }
            bool AlignToUpperRightCorner()
            {
                CHECK(alingTextToUpperLeftCorner.IsValid(), false, "");
                return alingTextToUpperLeftCorner->IsChecked();
            }
            bool HasResults() const
            {
                const auto& [start, length] = match;
                CHECK(start != GView::Utils::INVALID_OFFSET && length > 0, false, "");
                return true;
            }
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
            struct DrawLineInfo
            {
                uint64 offset{ 0 };
                uint32 offsetAndNameSize{ 0 };
                uint32 numbersSize{ 0 };
                uint32 textSize{ 0 };
                const uint8* start{ nullptr };
                const uint8* end{ nullptr };
                Character* chNameAndSize{ nullptr };
                Character* chNumbers{ nullptr };
                Character* chText{ nullptr };
                bool recomputeOffsets{ true };
                DrawLineInfo() = default;
            };
            struct
            {
                CharacterFormatMode charFormatMode;
                uint32 nrCols;
                uint32 lineAddressSize;
                uint32 lineNameSize;
                uint32 charactersPerLine;
                uint32 visibleRows;
                uint32 xName;
                uint32 xAddress;
                uint32 xNumbers;
                uint32 xText;
            } Layout;
            struct
            {
                uint64 startView, currentPos;
                uint32 base;
            } Cursor;
            struct
            {
                uint64 start, end, middle;
                uint32 minCount;
                bool AsciiMask[256];
                StringType type;
                String asciiMaskRepr;
                bool showAscii, showUnicode;
            } StringInfo;
            struct
            {
                ColorPair Normal, Line, Highlighted;
            } CursorColors;
            struct
            {
                uint8 buffer[256];
                uint32 size;
                uint64 start, end;
                bool highlight;
                void Clear()
                {
                    start     = GView::Utils::INVALID_OFFSET;
                    end       = GView::Utils::INVALID_OFFSET;
                    size      = 0;
                    buffer[0] = 0;
                }
            } CurrentSelection;

          private:
            Reference<GView::Object> obj;
            Reference<AppCUI::Controls::Grid> grid;
            Pointer<SettingsData> settings;

            static Config config;
            FindDialog findDialog;

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