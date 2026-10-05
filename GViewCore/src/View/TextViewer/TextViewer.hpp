#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace TextViewer
    {
        using namespace AppCUI;
        using namespace GView::Utils;

        constexpr uint32 MAX_CHARACTERS_PER_LINE = 1024;
        constexpr uint32 MAX_LINES_TO_VIEW       = 256;

        struct SettingsData
        {
            String name;
            uint32 tabSize;
            CharacterEncoding::Encoding encoding;
            WrapMethod wrapMethod;
            bool highlightCurrentLine;
            bool showTabCharacter;
            SettingsData();
        };

        namespace Commands
        {
            using Input::Key;
            using KF = KeyboardControlFlags;

            constexpr int32 CMD_ID_WORD_WRAP = 0xBF00;
            // navigation commands (resolved through Map in OnKeyEvent)
            constexpr uint32 CMD_NAV_LEFT          = 0xC000;
            constexpr uint32 CMD_NAV_RIGHT         = 0xC001;
            constexpr uint32 CMD_NAV_PREVIOUS_WORD = 0xC002;
            constexpr uint32 CMD_NAV_NEXT_WORD     = 0xC003;
            constexpr uint32 CMD_NAV_UP            = 0xC004;
            constexpr uint32 CMD_NAV_DOWN          = 0xC005;
            constexpr uint32 CMD_NAV_SCROLL_UP     = 0xC006;
            constexpr uint32 CMD_NAV_SCROLL_DOWN   = 0xC007;
            constexpr uint32 CMD_NAV_PAGE_UP       = 0xC008;
            constexpr uint32 CMD_NAV_PAGE_DOWN     = 0xC009;
            constexpr uint32 CMD_NAV_LINE_START    = 0xC00A;
            constexpr uint32 CMD_NAV_LINE_END      = 0xC00B;
            constexpr uint32 CMD_NAV_FILE_START    = 0xC00C;
            constexpr uint32 CMD_NAV_FILE_END      = 0xC00D;
            constexpr uint32 CMD_NAV_OPEN_SELECTION = 0xC00E;

            inline KeyboardControl WordWrap = { Key::F2, "WrapMethod", "Change the word wrap method", CMD_ID_WORD_WRAP };

            inline KeyboardControl MoveLeft      = { Key::Left, "MoveLeft", "Move one character to the left", CMD_NAV_LEFT, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveRight     = { Key::Right, "MoveRight", "Move one character to the right", CMD_NAV_RIGHT, KF::ShiftExtendsSelection };
            inline KeyboardControl PreviousWord  = { Key::Ctrl | Key::Left, "PreviousWord", "Move to the previous word", CMD_NAV_PREVIOUS_WORD, KF::ShiftExtendsSelection };
            inline KeyboardControl NextWord      = { Key::Ctrl | Key::Right, "NextWord", "Move to the next word", CMD_NAV_NEXT_WORD, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveUp        = { Key::Up, "MoveUp", "Move one line up", CMD_NAV_UP, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveDown      = { Key::Down, "MoveDown", "Move one line down", CMD_NAV_DOWN, KF::ShiftExtendsSelection };
            inline KeyboardControl ScrollUp      = { Key::Ctrl | Key::Up, "ScrollUp", "Scroll the view one line up", CMD_NAV_SCROLL_UP };
            inline KeyboardControl ScrollDown    = { Key::Ctrl | Key::Down, "ScrollDown", "Scroll the view one line down", CMD_NAV_SCROLL_DOWN };
            inline KeyboardControl MovePageUp    = { Key::PageUp, "MovePageUp", "Move one page up", CMD_NAV_PAGE_UP, KF::ShiftExtendsSelection };
            inline KeyboardControl MovePageDown  = { Key::PageDown, "MovePageDown", "Move one page down", CMD_NAV_PAGE_DOWN, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveLineStart = { Key::Home, "MoveToLineStart", "Move to the start of the line", CMD_NAV_LINE_START, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveLineEnd   = { Key::End, "MoveToLineEnd", "Move to the end of the line", CMD_NAV_LINE_END, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveFileStart = { Key::Ctrl | Key::Home, "MoveToFileStart", "Move to the start of the file", CMD_NAV_FILE_START, KF::ShiftExtendsSelection };
            inline KeyboardControl MoveFileEnd   = { Key::Ctrl | Key::End, "MoveToFileEnd", "Move to the end of the file", CMD_NAV_FILE_END, KF::ShiftExtendsSelection };
            inline KeyboardControl OpenSelection = { Key::Enter, "OpenSelection", "Open the current selection as a new object", CMD_NAV_OPEN_SELECTION };

            inline const std::array<KeyboardControl*, 15> NavigationKeys = {
                &MoveLeft,     &MoveRight,     &PreviousWord, &NextWord,      &MoveUp,        &MoveDown,    &ScrollUp,      &ScrollDown,
                &MovePageUp,   &MovePageDown,  &MoveLineStart, &MoveLineEnd,  &MoveFileStart, &MoveFileEnd, &OpenSelection,
            };
            inline Input::KeyMap Map;

            void RegisterKeys(KeyboardControlsInterface* interface);
            void OnKeysChanged();
        } // namespace Commands

        struct Config
        {
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };
        struct LineInfo
        {
            uint64 offset;
            uint32 charsCount;
            uint32 size;
            LineInfo()
            {
            }
            LineInfo(uint64 _offset, uint32 _charsCount, uint32 _size) : offset(_offset), charsCount(_charsCount), size(_size)
            {
            }
        };
        struct SubLineInfo
        {
            uint32 relativeOffset;
            uint32 size;
            uint32 relativeCharIndex;
            uint32 charsCount;
            SubLineInfo(uint32 _relativeOffset, uint32 _size, uint32 _relativeCharIndex, uint32 _charsCount)
                : relativeOffset(_relativeOffset), size(_size), relativeCharIndex(_relativeCharIndex), charsCount(_charsCount)
            {
            }
        };
        class Instance : public View::ViewControl
        {
            enum class Direction
            {
                TopToBottom,
                BottomToTop
            };
            enum class MouseStatus
            {
                None,
                Text,
                Border
            };
            std::vector<LineInfo> lines;      
            Utils::Selection selection;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            Character chars[MAX_CHARACTERS_PER_LINE];
            uint32 lineNumberWidth;
            uint32 sizeOfBOM;
            MouseStatus mouseStatus;


            struct
            {
                std::vector<SubLineInfo> entries;
                uint32 lineNo;
                uint32 leftAlignament;
            } SubLines;
            struct
            {
                uint64 pos;
                uint32 lineNo;
                uint32 sublineNo;
                uint32 charIndex;
            } Cursor;
            struct
            {
                struct
                {
                    uint32 lineNo, subLineNo;
                } Start, End;
                struct
                {
                    uint64 offset;
                    uint32 size;
                    uint32 lineNo;
                    uint32 xStart;
                    uint32 lineCharIndex;
                } Lines[MAX_LINES_TO_VIEW];
                uint32 scrollX;
                uint32 linesCount;
                inline void Reset()
                {
                    Start.lineNo = Start.subLineNo = 0;
                    End.lineNo = End.subLineNo = 0;
                    linesCount                 = 0;
                    // never reset the scrollX -> as it has to be recomputed
                }
            } ViewPort;

            static Config config;

            void OpenCurrentSelection();

            void RecomputeLineIndexes();
            void CommputeViewPort_NoWrap(uint32 lineNo, Direction dir);
            void CommputeViewPort_Wrap(uint32 lineNo, uint32 subLineNo, Direction dir);
            void ComputeViewPort(uint32 lineNo, uint32 subLineNo, Direction dir);

            bool GetLineInfo(uint32 lineNo, LineInfo& li);
            LineInfo GetLineInfo(uint32 lineNo);
            void ComputeSubLineIndexes(uint32 lineNo, BufferView& buf, uint64& startOffset);
            void ComputeSubLineIndexes(uint32 lineNo);
            uint32 CharacterIndexToSubLineNo(uint32 charIndex);
            
            void DrawLine(uint32 viewDataIndex, Graphics::Renderer& renderer, ControlState state, bool showLineNumber);

            void MoveTo(uint32 lineNo, uint32 charIndex, bool select);
            void MoveToStartOfLine(uint32 lineNo, bool select);
            void MoveToEndOfLine(uint32 lineNo, bool select);
            void MoveToEndOfFile(bool select);
            void MoveLeft(bool select);
            void MoveToNextWord(bool select);
            void MoveRight(bool select);
            void MoveToPreviousWord(bool select);
            void MoveDown(uint32 noOfTimes, bool select);
            void MoveUp(uint32 noOfTimes, bool select);
            void MoveScrollDown();
            void MoveScrollUp();

            void UpdateCursor_NoWrap();
            void UpdateCursor_Wrap();
            void UpdateViewPort();

            int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);

            inline bool HasWordWrap() const
            {
                return this->settings->wrapMethod != WrapMethod::None;
            }
            void SetWrapMethod(WrapMethod method);

            void MousePosToTextOffset(int x, int y, uint32& lineNo, uint32& charIndex);

          public:
            Instance(Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Graphics::Renderer& renderer) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            bool UpdateKeys(KeyboardControlsInterface* interface) override;
            bool ExecuteNavigationCommand(uint32 commandId, bool select);
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual void OnStart() override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual void OnUpdateScrollBars() override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual bool ShowCopyDialog() override;

            // mouse events
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction, Input::Key) override;            

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
            std::string_view GetCategoryNameForSerialization() const override
            {
                return "View.Text";
            }
            bool AddCategoryBeforePropertyNameWhenSerializing() const override
            {
                return true;
            }
        };
        class GoToDialog : public Window
        {
            Reference<RadioBox> rbLineNumber;
            Reference<TextField> txLineNumber;
            Reference<RadioBox> rbFileOffset;
            Reference<TextField> txFileOffset;
            uint64 maxSize;
            uint32 maxLines;
            uint64 resultedPos;
            bool gotoLine;
            
            void UpdateEnableStatus();
            void Validate();

          public:
            GoToDialog(uint64 currentPos, uint64 size, uint32 currentLine, uint32 maxLines);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline uint64 GetFileOffset() const
            {
                return resultedPos;
            }
            inline uint32 GetLine() const
            {
                return static_cast<uint32>(resultedPos - 1);
            }
            inline bool ShouldGoToLine() const
            {
                return gotoLine;
            }
        };

    } // namespace TextViewer
} // namespace View

}; // namespace GView