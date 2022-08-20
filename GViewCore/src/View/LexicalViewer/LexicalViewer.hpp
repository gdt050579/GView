#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace LexicalViewer
    {
        using namespace AppCUI;
        using namespace GView::Utils;

        enum class FoldStatus: uint32
        {
            Folded,
            Expanded,
            Reverse
        };

        enum class TokenStatus : uint8
        {
            None       = 0,
            Visible    = 0x01,
            Folded     = 0x02, // only for blocks
            BlockStart = 0x04,
        };
        class TokensListBuilder : public TokensList
        {
          public:
            TokensListBuilder(void* _data)
            {
                this->data = _data;
            }
        };
        struct BlockObject
        {
            static constexpr uint32 INVALID_ID = 0xFFFFFFFF;
            uint32 tokenStart, tokenEnd;
            BlockAlignament align;
            bool hasEndMarker;
        };
        struct TokenObject
        {
            uint32 start, end, type;
            uint32 blockID; // for blocks
            int32 x, y;
            uint8 maxWidth, maxHeight, width, height;
            TokenAlignament align;
            TokenColor color;
            TokenDataType dataType;
            TokenStatus status;

            inline bool IsVisible() const
            {
                return (static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::Visible)) != 0;
            }
            inline bool IsFolded() const
            {
                return (static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::Folded)) != 0;
            }
            inline bool IsBlockStarter() const
            {
                return (static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::BlockStart)) != 0;
            }
            inline void SetVisible(bool value)
            {
                if (value)
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::Visible));
                else
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) & (~static_cast<uint8>(TokenStatus::Visible)));
            }
            inline void SetBlockStartFlag()
            {
                status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::BlockStart));
            }
            inline void SetFolded(bool value)
            {
                if (value)
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::Folded));
                else
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) & (~static_cast<uint8>(TokenStatus::Folded)));
            }
        };

        struct SettingsData
        {
            Reference<ParseInterface> parser;
            SettingsData();
        };

        struct Config
        {
            struct
            {
                AppCUI::Input::Key showMetaData;
                AppCUI::Input::Key prettyFormat;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };
        class Instance : public View::ViewControl
        {
            FixSizeString<29> name;
            Utils::Selection selection;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            char16* text;
            uint32 textLength;
            uint32 currentTokenIndex;
            int32 lineNrWidth, lastLineNumber;
            bool noItemsVisible;
            bool showMetaData;
            bool prettyFormat;

            struct
            {
                int32 x, y;
            } Scroll;

            static Config config;

            void ComputeMultiLineTokens();
            void ComputeOriginalPositions();
            void PrettyFormatForBlock(uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin);
            void PrettyFormat();
            void EnsureCurrentItemIsVisible();
            void RecomputeTokenPositions();
            void UpdateVisibilityStatus(uint32 start, uint32 end, bool visible);
            void MoveToClosestVisibleToken(uint32 startIndex, bool selected);

            void FillBlockSpace(Graphics::Renderer& renderer, const TokenObject& tok);
            void PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, bool onCursor);
            void PaintLineNumbers(Graphics::Renderer& renderer);

            void MoveToToken(uint32 index, bool selected);
            void MoveLeft(bool selected, bool stopAfterFirst);
            void MoveRight(bool selected, bool stopAfterFirst);
            void MoveUp(uint32 times, bool selected);
            void MoveDown(uint32 times, bool selected);
            void SetFoldStatus(uint32 index, FoldStatus foldStatus, bool recursive);

          public:
            std::vector<TokenObject> tokens;
            std::vector<BlockObject> blocks;

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            inline uint32 GetUnicodeTextLen() const
            {
                return textLength;
            }
            inline char16* GetUnicodeText() const
            {
                return text;
            }

            virtual void Paint(Graphics::Renderer& renderer) override;
            virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
            virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode) override;
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            virtual void OnStart() override;
            virtual void OnAfterResize(int newWidth, int newHeight) override;
            virtual void OnUpdateScrollBars() override;

            virtual bool GoTo(uint64 offset) override;
            virtual bool Select(uint64 offset, uint64 size) override;
            virtual bool ShowGoToDialog() override;
            virtual bool ShowFindDialog() override;
            virtual std::string_view GetName() override;

            // mouse events
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button) override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction) override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
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

    } // namespace LexicalViewer
} // namespace View

}; // namespace GView