#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace BufferViewer
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
        enum class StringType : uint8
        {
            None,
            Ascii,
            Unicode
        };
        struct OffsetTranslationMethod
        {
            FixSizeString<17> name;
        };
        struct SettingsData
        {
            GView::Utils::ZonesList zList;
            uint64 bookmarks[10];
            uint64 entryPointOffset;
            OffsetTranslationMethod translationMethods[16];
            uint32 translationMethodsCount;
            Reference<OffsetTranslateInterface> offsetTranslateCallback;
            Reference<PositionToColorInterface> positionToColorCallback;
            SettingsData();
        };
        enum class MouseLocation: uint8
        {
            OnView,
            OnHeader,
            Outside
        };
        struct MousePositionInfo
        {
            MouseLocation location;
            uint64 bufferOffset;
        };
        struct Config
        {
            struct
            {
                ColorPair Inactive;
                ColorPair OutsideZone;
                ColorPair Normal;
                ColorPair Header;
                ColorPair Line;
                ColorPair Cursor;
                ColorPair Selection;
                ColorPair Ascii;
                ColorPair Unicode;
                ColorPair SameSelection;
            } Colors;
            struct
            {
                AppCUI::Input::Key ChangeColumnsNumber;
                AppCUI::Input::Key ChangeBase;
                AppCUI::Input::Key ChangeAddressMode;
                AppCUI::Input::Key GoToEntryPoint;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };
        class Instance : public View::ViewControl
        {
            struct DrawLineInfo
            {
                uint64 offset;
                uint32 offsetAndNameSize;
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
            } CurrentSelection;

            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            Utils::Selection selection;
            CharacterBuffer chars;
            const char16* CodePage;
            uint32 currentAdrressMode;
            BufferColor bufColor;
            FixSizeString<29> name;

            static Config config;

            int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);
            int PrintCursorPosInfo(int x, int y, uint32 width, bool addSeparator, Renderer& r);
            int PrintCursorZone(int x, int y, uint32 width, Renderer& r);
            int Print8bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print16bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print32bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print32bitBEValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);

            void UpdateCurrentSelection();

            void PrepareDrawLineInfo(DrawLineInfo& dli);
            void WriteHeaders(Renderer& renderer);
            void WriteLineAddress(DrawLineInfo& dli);
            void WriteLineNumbersToChars(DrawLineInfo& dli);
            void WriteLineTextToChars(DrawLineInfo& dli);
            void UpdateViewSizes();
            void MoveTo(uint64 offset, bool select);
            void MoveScrollTo(uint64 offset);
            void MoveToSelection(uint32 selIndex);
            void MoveToZone(bool startOfZome, bool select);
            void SkipCurentCaracter(bool selected);
            void MoveTillEndBlock(bool selected);
            void MoveTillNextBlock(bool select, int dir);

            void UpdateStringInfo(uint64 offset);
            void ResetStringInfo();
            std::string_view GetAsciiMaskStringRepresentation();
            bool SetStringAsciiMask(string_view stringRepresentation);

            ColorPair OffsetToColorZone(uint64 offset);
            ColorPair OffsetToColor(uint64 offset);

            void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Renderer& renderer) override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual std::string_view GetName() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // mouse events
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseEnter() override;
            virtual bool OnMouseOver(int x, int y) override;
            virtual bool OnMouseLeave() override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropetyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };

    } // namespace BufferViewer
} // namespace View
}; // namespace GView