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
        enum class MouseLocation : uint8
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
                ColorPair Ascii;
                ColorPair Unicode;
            } Colors;
            struct
            {
                AppCUI::Input::Key ChangeColumnsNumber;
                AppCUI::Input::Key ChangeValueFormatOrCP;
                AppCUI::Input::Key ChangeAddressMode;
                AppCUI::Input::Key GoToEntryPoint;
                AppCUI::Input::Key ChangeSelectionType;
                AppCUI::Input::Key ShowHideStrings;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };

        class Instance : public View::ViewControl, public GView::Utils::SelectionZoneInterface
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
                bool highlight;
                void Clear()
                {
                    start     = GView::Utils::INVALID_OFFSET;
                    end       = GView::Utils::INVALID_OFFSET;
                    size      = 0;
                    buffer[0] = 0;
                }
            } CurrentSelection;

            bool showTypeObjects;
            CodePage codePage;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            Utils::Selection selection;
            CharacterBuffer chars;
            uint32 currentAdrressMode;
            String addressModesList;
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

            void OpenCurrentSelection();

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Renderer& renderer) override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;
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

            // scrollbar data
            virtual void OnUpdateScrollBars() override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;

            uint32 GetSelectionZonesCount() const override
            {
                uint32 count = 0;
                for (; count < selection.GetCount(); count++)
                {
                    CHECKBK(selection.HasSelection(count), "");
                }

                return count;
            }

            GView::TypeInterface::SelectionZone GetSelectionZone(uint32 index) const override
            {
                static auto z = GView::TypeInterface::SelectionZone{ 0, 0 };
                CHECK(index < selection.GetCount(), z, "");

                return GView::TypeInterface::SelectionZone{ .start = selection.GetSelectionStart(index),
                                                            .end   = selection.GetSelectionEnd(index) };
            }
        };
        class SelectionEditor : public Window
        {
            Reference<Utils::Selection> selection;
            Reference<SettingsData> settings;
            Reference<TextField> txOffset;
            Reference<TextField> txSize;
            Reference<ComboBox> cbOfsType;
            Reference<ComboBox> cbBase;
            uint32 zoneIndex;
            uint64 maxSize;

            void RefreshSizeAndOffset();
            void Validate();
            bool GetValues(uint64& start, uint64& size);

          public:
            SelectionEditor(Reference<Utils::Selection> selection, uint32 index, Reference<SettingsData> settings, uint64 size);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
        };
        class GoToDialog : public Window
        {
            Reference<SettingsData> settings;
            Reference<TextField> txOffset;
            Reference<ComboBox> cbOfsType;
            uint64 maxSize;
            uint64 resultedPos;

            void Validate();

          public:
            GoToDialog(Reference<SettingsData> settings, uint64 currentPos, uint64 size);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline uint64 GetResultedPos() const
            {
                return resultedPos;
            }
        };
        class FindDialog : public Window, public Handlers::OnCheckInterface
        {
          private:
            Reference<GView::Object> object;
            Reference<SettingsData> settings;
            uint64 currentPos;
            uint64 resultedPos;

            Reference<CanvasViewer> description;
            Reference<TextField> input;
            Reference<CheckBox> textOption;
            Reference<CheckBox> binaryOption;
            Reference<CheckBox> textAscii;
            Reference<CheckBox> textUnicode;
            Reference<CheckBox> textHex;
            Reference<CheckBox> textDec;
            Reference<CheckBox> searchFile;
            Reference<CheckBox> searchSelection;
            Reference<CheckBox> bufferSelect;
            Reference<CheckBox> bufferMoveCursorTo;
            Reference<CheckBox> ignoreCase;
            Reference<CheckBox> alingTextToUpperLeftCorner;

          public:
            FindDialog(Reference<SettingsData> settings, uint64 currentPos, Reference<GView::Object> object);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar) override;
            inline uint64 GetResultedPos() const
            {
                return resultedPos;
            }

            void OnCheck(Reference<Controls::Control> control, bool value) override;

            bool SetDescription();
            bool Update();
        };
    } // namespace BufferViewer
} // namespace View

}; // namespace GView