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
            uint32 tabSize;
            CharacterEncoding::Encoding encoding;
            WrapMethod wrapMethod;
            bool highlightCurrentLine;
            bool showTabCharacter;
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
            std::vector<LineInfo> lines;      
            Utils::Selection selection;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            FixSizeString<29> name;
            Character chars[MAX_CHARACTERS_PER_LINE];
            uint32 lineNumberWidth;
            uint32 sizeOfBOM;

            enum class Direction
            {
                TopToBottom,
                BottomToTop
            };
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
            void MoveRight(bool select);
            void MoveDown(uint32 noOfTimes, bool select);
            void MoveUp(uint32 noOfTimes, bool select);

            void UpdateCursor_NoWrap();
            void UpdateCursor_Wrap();
            void UpdateViewPort();

            int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);

            inline bool HasWordWrap() const
            {
                return this->settings->wrapMethod != WrapMethod::None;
            }

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            virtual void Paint(Graphics::Renderer& renderer) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual void OnStart() override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;

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

    } // namespace TextViewer
} // namespace View

}; // namespace GView