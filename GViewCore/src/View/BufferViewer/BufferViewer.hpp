#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace BufferViewer
    {
        enum class CharacterFormatMode : unsigned char
        {
            Hex,
            Octal,
            SignedDecimal,
            UnsignedDecimal,

            Count // Must be the last
        };
        enum class StringType : unsigned char
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
            uint64_t bookmarks[10];
            uint64_t entryPointOffset;
            OffsetTranslationMethod translationMethods[16];
            unsigned int translationMethodsCount;
            Reference<OffsetTranslateInterface> offsetTranslateCallback;
            Reference<PositionToColorInterface> positionToColorCallback;
            SettingsData();
        };
        enum class MouseLocation: unsigned char
        {
            OnView,
            OnHeader,
            Outside
        };
        struct MousePositionInfo
        {
            MouseLocation location;
            uint64_t bufferOffset;
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
                unsigned long long offset;
                unsigned int offsetAndNameSize;
                unsigned int numbersSize;
                unsigned int textSize;
                const unsigned char* start;
                const unsigned char* end;
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
                unsigned int nrCols;
                unsigned int lineAddressSize;
                unsigned int lineNameSize;
                unsigned int charactersPerLine;
                unsigned int visibleRows;
                unsigned int xName;
                unsigned int xAddress;
                unsigned int xNumbers;
                unsigned int xText;
            } Layout;
            struct
            {
                unsigned long long startView, currentPos;
                unsigned int base;
            } Cursor;
            struct
            {
                unsigned long long start, end, middle;
                unsigned int minCount;
                bool AsciiMask[256];
                StringType type;
            } StringInfo;
            struct
            {
                ColorPair Normal, Line, Highlighted;
            } CursorColors;

            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            Utils::Selection selection;
            CharacterBuffer chars;
            const char16_t* CodePage;
            unsigned int currentAdrressMode;
            BufferColor bufColor;
            FixSizeString<29> name;

            static Config config;

            int PrintSelectionInfo(unsigned int selectionID, int x, int y, unsigned int width, Renderer& r);
            int PrintCursorPosInfo(int x, int y, unsigned int width, bool addSeparator, Renderer& r);
            int PrintCursorZone(int x, int y, unsigned int width, Renderer& r);
            int Print8bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print16bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print32bitValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);
            int Print32bitBEValue(int x, int height, AppCUI::Utils::BufferView buffer, Renderer& r);

            void PrepareDrawLineInfo(DrawLineInfo& dli);
            void WriteHeaders(Renderer& renderer);
            void WriteLineAddress(DrawLineInfo& dli);
            void WriteLineNumbersToChars(DrawLineInfo& dli);
            void WriteLineTextToChars(DrawLineInfo& dli);
            void UpdateViewSizes();
            void MoveTo(unsigned long long offset, bool select);
            void MoveScrollTo(unsigned long long offset);
            void MoveToSelection(unsigned int selIndex);
            void MoveToZone(bool startOfZome, bool select);
            void SkipCurentCaracter(bool selected);
            void MoveTillEndBlock(bool selected);
            void MoveTillNextBlock(bool select, int dir);

            void UpdateStringInfo(unsigned long long offset);

            ColorPair OffsetToColorZone(unsigned long long offset);
            ColorPair OffsetToColor(unsigned long long offset);

            void AnalyzeMousePosition(int x, int y, MousePositionInfo& mpInfo);

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Renderer& renderer) override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16_t characterCode) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(unsigned long long offset) override;
            virtual bool Select(unsigned long long offset, unsigned long long size) override;
            virtual std::string_view GetName() override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height) override;

            // mouse events
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseEnter() override;
            virtual bool OnMouseOver(int x, int y) override;
            virtual bool OnMouseLeave() override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;
        };
    } // namespace BufferViewer
} // namespace View
}; // namespace GView