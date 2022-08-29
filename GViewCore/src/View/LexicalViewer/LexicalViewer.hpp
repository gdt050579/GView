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

        enum class FoldStatus : uint32
        {
            Folded,
            Expanded,
            Reverse
        };

        enum class TokenStatus : uint8
        {
            None                       = 0,
            Visible                    = 0x01,
            Folded                     = 0x02, // only for blocks
            BlockStart                 = 0x04,
            DisableSimilarityHighlight = 0x08, // hash will not be computed for this token
            ShouldDelete               = 0x10, // token shoule be deleted on next reparse
        };
        class TokensListBuilder : public TokensList
        {
          public:
            TokensListBuilder(void* _data)
            {
                this->data = _data;
            }
        };
        class BlocksListBuilder : public BlocksList
        {
          public:
            BlocksListBuilder(void* _data)
            {
                this->data = _data;
            }
        };
        class TextEditorBuilder : public TextEditor
        {
          public:
            TextEditorBuilder(char16* _text, uint32 _size) : TextEditor()
            {
                this->text      = _text;
                this->size      = _size;
                this->allocated = _size;
            }
            TextEditorBuilder(GView::Utils::UnicodeString& str) : TextEditor()
            {
                this->text      = str.text;
                this->size      = str.size;
                this->allocated = str.allocated;
                // works like a move method --> similar to what RUST is doing
                str.text      = nullptr;
                str.size      = 0;
                str.allocated = 0;
            }
            GView::Utils::UnicodeString Release()
            {
                GView::Utils::UnicodeString result(this->text, this->size, this->allocated);
                this->text      = nullptr;
                this->size      = 0;
                this->allocated = 0;
                return result;
            }
        };
        struct BlockObject
        {
            static constexpr uint32 INVALID_ID = 0xFFFFFFFF;
            uint32 tokenStart, tokenEnd;
            int32 leftHighlightMargin;
            std::string foldMessage;
            BlockAlignament align;
            BlockFlags flags;

            inline uint32 GetStartIndex() const
            {
                return tokenStart;
            }
            inline uint32 GetEndIndex() const
            {
                return ((flags & BlockFlags::EndMarker) != BlockFlags::None) ? tokenEnd + 1 : tokenEnd;
            }
            inline bool HasEndMarker() const
            {
                return (flags & BlockFlags::EndMarker) != BlockFlags::None;
            }
            inline bool CanOnlyBeFoldedManually() const
            {
                return (flags & BlockFlags::ManualCollapse) != BlockFlags::None;
            }
        };
        struct TokenObject
        {
            UnicodeStringBuilder value;
            uint64 hash;
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
            inline bool CanChangeValue() const
            {
                return (static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::DisableSimilarityHighlight)) == 0;
            }
            inline bool IsMarkForDeletion() const
            {
                return (static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::ShouldDelete)) != 0;
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
            inline void SetShouldDeleteFlag()
            {
                status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::ShouldDelete));
            }
            inline void SetFolded(bool value)
            {
                if (value)
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::Folded));
                else
                    status = static_cast<TokenStatus>(static_cast<uint8>(status) & (~static_cast<uint8>(TokenStatus::Folded)));
            }
            inline bool HasBlock() const
            {
                return blockID != BlockObject::INVALID_ID;
            }
            inline void SetDisableSimilartyHighlightFlag()
            {
                status = static_cast<TokenStatus>(static_cast<uint8>(status) | static_cast<uint8>(TokenStatus::DisableSimilarityHighlight));
            }
            void UpdateSizes(const char16* text);
            inline void UpdateHash(const char16* text, bool ignoreCase)
            {
                if ((static_cast<uint8>(status) & static_cast<uint8>(TokenStatus::DisableSimilarityHighlight)) != 0)
                {
                    this->hash = 0;
                    return;
                }
                if (this->value.Len() == 0)
                    this->hash = TextParser::ComputeHash64({ text + start, (size_t) (end - start) }, ignoreCase);
                else
                    this->hash = TextParser::ComputeHash64(this->value.ToStringView(), ignoreCase);
            }
            inline u16string_view GetOriginalText(const char16* text) const
            {
                return { text + start, (size_t) (end - start) };
            }
            inline u16string_view GetText(const char16* text) const
            {
                if (this->value.Len() == 0)
                    return { text + start, (size_t) (end - start) };
                else
                    return this->value.ToStringView();
            }
        };

        struct SettingsData
        {
            std::vector<Reference<Plugin>> plugins;
            Reference<ParseInterface> parser;
            uint32 maxWidth;
            uint8 indentWidth;
            bool ignoreCase;
            SettingsData();
        };

        struct Config
        {
            struct
            {
                AppCUI::Input::Key showMetaData;
                AppCUI::Input::Key prettyFormat;
                AppCUI::Input::Key changeSelectionType;
                AppCUI::Input::Key foldAll;
                AppCUI::Input::Key expandAll;
            } Keys;
            bool Loaded;

            static void Update(IniSection sect);
            void Initialize();
        };
        class Instance;
        class FoldColumn
        {
            static constexpr int32 MAX_INDEXES   = 256;
            static constexpr int32 INVALID_INDEX = -1;
            uint32 indexes[MAX_INDEXES];
            int32 count, height;
            int32 mouseHoverIndex;

          public:
            FoldColumn() : count(0), mouseHoverIndex(INVALID_INDEX)
            {
            }
            void Clear(int32 height);
            void SetBlock(int32 index, uint32 blockID);
            void Paint(AppCUI::Graphics::Renderer& renderer, int32 x, Instance* instance);
            
            inline bool ClearMouseHoverIndex()
            {
                if (mouseHoverIndex != INVALID_INDEX)
                {
                    mouseHoverIndex = INVALID_INDEX;
                    return true;
                }
                return false;                
            }
            inline bool UpdateMouseHoverIndex(int32 y)
            {
                if ((y >= 0) && (y < count) && (indexes[y] != BlockObject::INVALID_ID))
                {
                    mouseHoverIndex = y;
                    return true;
                }
                return ClearMouseHoverIndex();
            }
            inline uint32 MouseToBlockIndex(int32 y)
            {
                if ((y >= 0) && (y < count))
                    return indexes[y];
                return BlockObject::INVALID_ID;
            }
        };
        class Instance : public View::ViewControl
        {
            FoldColumn foldColumn;
            FixSizeString<29> name;
            Utils::Selection selection;
            Pointer<SettingsData> settings;
            Reference<GView::Object> obj;
            uint64 currentHash;
            UnicodeString text;
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

            void UpdateTokensInformation();
            void ComputeOriginalPositions();
            void PrettyFormatIncreaseUntilNewLineXWithValue(uint32 idxStart, uint32 idxEnd, int32 currentLineYOffset, int32 diff);
            void PrettyFormatIncreaseAllXWithValue(uint32 idxStart, uint32 idxEnd, int32 diff);
            void PrettyFormatAlignToSameColumn(uint32 idxStart, uint32 idxEnd, int32 columnXOffset);
            AppCUI::Graphics::Point PrettyFormatForBlock(uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin);
            void PrettyFormat();
            void EnsureCurrentItemIsVisible();
            void RecomputeTokenPositions();
            void UpdateVisibilityStatus(uint32 start, uint32 end, bool visible);
            void MoveToClosestVisibleToken(uint32 startIndex, bool selected);

            void FillBlockSpace(Graphics::Renderer& renderer, const BlockObject& block);
            void PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, uint32 index);
            void PaintLineNumbers(Graphics::Renderer& renderer);

            void MoveToToken(uint32 index, bool selected);
            void MoveLeft(bool selected, bool stopAfterFirst);
            void MoveRight(bool selected, bool stopAfterFirst);
            void MoveUp(uint32 times, bool selected);
            void MoveDown(uint32 times, bool selected);
            void SetFoldStatus(uint32 index, FoldStatus foldStatus, bool recursive);
            void ExpandAll();
            void FoldAll();

            uint32 TokenToBlock(uint32 tokenIndex);
            uint32 CountSimilarTokens(uint32 start, uint32 end, uint64 hash);

            uint32 MousePositionToTokenID(int x, int y);

            void EditCurrentToken();
            void DeleteTokens();

            bool RebuildTextFromTokens(TextEditor& edidor);
            void Parse();
            void Reparse(bool openInNewWindow);

            int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);
            int PrintTokenTypeInfo(uint32 tokenTypeID, int x, int y, uint32 width, Renderer& r);
            int PrintDataTypeInfo(TokenDataType dataType, int x, int y, uint32 width, Renderer& r);

          public:
            std::vector<TokenObject> tokens;
            std::vector<BlockObject> blocks;

          public:
            Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings);

            inline uint32 GetUnicodeTextLen() const
            {
                return text.size;
            }
            inline char16* GetUnicodeText() const
            {
                return text.text;
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
            virtual bool OnMouseOver(int x, int y) override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
        };
        enum class ApplyMethod
        {
            CurrentToken,
            EntireProgram,
            Block,
            Selection
        };
        class NameRefactorDialog : public Window
        {
            TokenObject& tok;
            Reference<TextField> txNewValue;
            Reference<RadioBox> rbApplyOnCurrent, rbApplyOnAll, rbApplyOnBlock, rbApplyOnSelection;
            Reference<CheckBox> cbReparse;

          public:
            NameRefactorDialog(TokenObject& tok, const char16* text, bool hasSelection, bool belongsToABlock);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            inline bool ShouldReparse()
            {
                return cbReparse->IsChecked();
            }
            inline const CharacterBuffer& GetNewValue()
            {
                return txNewValue->GetText();
            }
            inline ApplyMethod GetApplyMethod()
            {
                if (rbApplyOnAll->IsChecked())
                    return ApplyMethod::EntireProgram;
                if (rbApplyOnBlock->IsChecked())
                    return ApplyMethod::Block;
                if (rbApplyOnSelection->IsChecked())
                    return ApplyMethod::Selection;
                // default
                return ApplyMethod::CurrentToken;
            }
        };
        class DeleteDialog : public Window
        {
            Reference<RadioBox> rbApplyOnCurrent, rbApplyOnBlock, rbApplyOnSelection;

          public:
            DeleteDialog(TokenObject& tok, const char16* text, bool hasSelection, bool belongsToABlock);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline ApplyMethod GetApplyMethod()
            {
                if (rbApplyOnBlock->IsChecked())
                    return ApplyMethod::Block;
                if (rbApplyOnSelection->IsChecked())
                    return ApplyMethod::Selection;
                // default
                return ApplyMethod::CurrentToken;
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

    } // namespace LexicalViewer
} // namespace View

}; // namespace GView