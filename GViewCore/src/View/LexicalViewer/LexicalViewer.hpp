#pragma once

#include "Internal.hpp"
#include <array>

namespace GView
{
namespace View
{
    namespace LexicalViewer
    {
        using namespace AppCUI;
        using namespace GView::Utils;

        namespace Commands
        {
            using namespace AppCUI::Input;
            constexpr int32 CMD_ID_SHOW_METADATA    = 0xBF00;
            constexpr int32 CMD_ID_SAVE_AS          = 0xBF01;
            constexpr int32 CMD_ID_DELETE           = 0xBF02;
            constexpr int32 CMD_ID_CHANGE_SELECTION = 0xBF03;
            constexpr int32 CMD_ID_FOLD_ALL         = 0xBF04;
            constexpr int32 CMD_ID_EXPAND_ALL       = 0xBF05;
            constexpr int32 CMD_ID_SHOW_PLUGINS     = 0xBF06;

            static KeyboardControl ShowPluginsCmd         = { Key::F2, "Plugins", "Zoom in the picture", CMD_ID_SHOW_PLUGINS };
            static KeyboardControl SaveAsCmd              = { Key::F3, "SaveAs", "Zoom out the picture", CMD_ID_SAVE_AS };
            static KeyboardControl ShowMetaDataCmd        = { Key::F7, "ShowMetaData", "Show or hide metadata", CMD_ID_SHOW_METADATA };
            static KeyboardControl ChangeSelectionTypeCmd = { Key::F9, "FoldAll", "Fold all lines", CMD_ID_FOLD_ALL };
            static KeyboardControl FoldAllCmd   = { Key::F8, "ChangeSelectionType", "Change the selection type", CMD_ID_CHANGE_SELECTION};
            static KeyboardControl ExpandAllCmd           = { Key::Ctrl | Key::F9, "ExpandAll", "Expand all lines", CMD_ID_EXPAND_ALL };
            static KeyboardControl DeleteCmd              = { Key::Delete, "Delete", "Open the delete dialog", CMD_ID_DELETE };

            static std::array LexicalViewerCommands = { &ShowPluginsCmd, &SaveAsCmd,    &ShowMetaDataCmd, &ChangeSelectionTypeCmd,
                                                        &FoldAllCmd,     &ExpandAllCmd, &DeleteCmd
            };
        }

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
            ShouldDelete               = 0x10, // token should be deleted on next reparse
            SizeableSize               = 0x20, // token size (width and height) can be modified
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
            bool Set(const CharacterBuffer& chars);
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
        struct TokenPosition
        {
            int32 x, y;
            uint32 width, height;
            TokenStatus status;
        };
        struct TokenObject
        {
            UnicodeStringBuilder value;
            UnicodeStringBuilder error;
            uint64 hash;
            uint32 start, end, type;
            uint32 blockID; // for blocks
            uint32 lineNo;
            uint32 contentWidth, contentHeight;
            TokenPosition pos;
            TokenAlignament align;
            TokenColor color;
            TokenDataType dataType;

            inline bool IsVisible() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::Visible)) != 0;
            }
            inline bool IsFolded() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::Folded)) != 0;
            }
            inline bool IsBlockStarter() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::BlockStart)) != 0;
            }
            inline bool IsSizeable() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::SizeableSize)) != 0;
            }
            inline bool CanChangeValue() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::DisableSimilarityHighlight)) == 0;
            }
            inline bool IsMarkForDeletion() const
            {
                return (static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::ShouldDelete)) != 0;
            }
            inline void SetVisible(bool value)
            {
                if (value)
                    pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::Visible));
                else
                    pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) & (~static_cast<uint8>(TokenStatus::Visible)));
            }
            inline void SetBlockStartFlag()
            {
                pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::BlockStart));
            }
            inline void SetShouldDeleteFlag()
            {
                pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::ShouldDelete));
            }
            inline void SetSizeableSizeFlag()
            {
                pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::SizeableSize));
            }
            inline void SetFolded(bool value)
            {
                if (value)
                    pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::Folded));
                else
                    pos.status = static_cast<TokenStatus>(static_cast<uint8>(pos.status) & (~static_cast<uint8>(TokenStatus::Folded)));
            }
            inline bool HasBlock() const
            {
                return blockID != BlockObject::INVALID_ID;
            }
            inline void SetDisableSimilartyHighlightFlag()
            {
                pos.status = static_cast<TokenStatus>(
                      static_cast<uint8>(pos.status) | static_cast<uint8>(TokenStatus::DisableSimilarityHighlight));
            }
            void UpdateSizes(const char16* text);
            inline void UpdateHash(const char16* text, bool ignoreCase)
            {
                if ((static_cast<uint8>(pos.status) & static_cast<uint8>(TokenStatus::DisableSimilarityHighlight)) != 0)
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
            String name;
            std::vector<Reference<Plugin>> plugins;
            Reference<ParseInterface> parser;
            AppCUI::Graphics::Size maxTokenSize;
            uint32 maxWidth;
            uint8 indentWidth;
            bool ignoreCase;
            SettingsData();
        };

        struct Config
        {
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
        struct PrettyFormatLayoutManager
        {
            int x, y, lastY;
            bool firstOnNewLine;
            bool spaceAdded;
        };
        class Instance : public View::ViewControl
        {
            FoldColumn foldColumn;
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
            bool highlightSimilarTokens;

            std::vector<TokenPosition> backupedTokenPositionList;

            struct
            {
                int32 x, y;
            } Scroll;

            static Config config;

            void UpdateTokensWidthAndHeight();
            void ComputeOriginalPositions();
            void PrettyFormatIncreaseUntilNewLineXWithValue(uint32 idxStart, uint32 idxEnd, int32 currentLineYOffset, int32 diff);
            void PrettyFormatIncreaseAllXWithValue(uint32 idxStart, uint32 idxEnd, int32 diff);
            void PrettyFormatAlignToSameColumn(uint32 idxStart, uint32 idxEnd, int32 columnXOffset);
            void PrettyFormatForBlock(
                  uint32 idxStart, uint32 idxEnd, int32 leftMargin, int32 topMargin, PrettyFormatLayoutManager& manager);
            void PrettyFormat();
            void EnsureCurrentItemIsVisible();
            void RecomputeTokenPositions();
            void UpdateVisibilityStatus(uint32 start, uint32 end, bool visible);
            void UpdateTokensInformation();
            void MoveToClosestVisibleToken(uint32 startIndex, bool selected);

            void FillBlockSpace(Graphics::Renderer& renderer, const BlockObject& block);
            void PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, uint32 index);

            void MakeTokenVisible(uint32 index);

            void MoveToToken(uint32 index, bool selected, bool makeVisibleIfHidden);
            void MoveLeft(bool selected, bool stopAfterFirst);
            void MoveRight(bool selected, bool stopAfterFirst);
            void MoveUp(uint32 times, bool selected);
            void MoveDown(uint32 times, bool selected);
            void MoveToNextSimilarToken(int32 direction);

            void SetFoldStatus(uint32 index, FoldStatus foldStatus, bool recursive);
            void ExpandAll();
            void FoldAll();

            uint32 TokenToBlock(uint32 tokenIndex);
            uint32 CountSimilarTokens(uint32 start, uint32 end, uint64 hash);
            void BakupTokensPositions();
            void RestoreTokensPositionsFromBackup();
            uint32 MousePositionToTokenID(int x, int y);

            void EditCurrentToken();
            void DeleteTokens();
            void ShowPlugins();
            void ShowSaveAsDialog();
            void ShowFindAllDialog();
            void ShowRefactorDialog(TokenObject& tok);
            void ShowStringOpDialog(TokenObject& tok);

            bool RebuildTextFromTokens(TextEditor& edidor);
            void Parse();
            void Reparse(bool openInNewWindow);

            int PrintSelectionInfo(uint32 selectionID, int x, int y, uint32 width, Renderer& r);
            int PrintTokenTypeInfo(uint32 tokenTypeID, int x, int y, uint32 width, Renderer& r);
            int PrintDataTypeInfo(TokenDataType dataType, int x, int y, uint32 width, Renderer& r);
            int PrintError(std::u16string_view error, int x, int y, uint32 width, Renderer& r);

          public:
            std::vector<TokenObject> tokens;
            std::vector<BlockObject> blocks;

          public:
            Instance(Reference<GView::Object> obj, Settings* settings);

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
            virtual bool ShowCopyDialog() override;

            // mouse events
            virtual void OnMousePressed(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual void OnMouseReleased(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button, Input::Key) override;
            virtual bool OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction, Input::Key) override;
            virtual bool OnMouseOver(int x, int y) override;

            virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) override;

            // property interface
            bool GetPropertyValue(uint32 id, PropertyValue& value) override;
            bool SetPropertyValue(uint32 id, const PropertyValue& value, String& error) override;
            void SetCustomPropertyValue(uint32 propertyID) override;
            bool IsPropertyValueReadOnly(uint32 propertyID) override;
            const vector<Property> GetPropertiesList() override;
            std::string_view GetCategoryNameForSerialization() const override
            {
                return "View.Lexical";
            }
            bool AddCategoryBeforePropertyNameWhenSerializing() const override
            {
                return true;
            }
            bool UpdateKeys(KeyboardControlsInterface* interface) override;
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
        namespace StringOperationsPlugins
        {
            void Reverse(TextEditor& editor, uint32 start, uint32 end);
            void UpperCase(TextEditor& editor, uint32 start, uint32 end);
            void LowerCase(TextEditor& editor, uint32 start, uint32 end);
            void RemoveUnnecesaryWhiteSpaces(TextEditor& editor, uint32 start, uint32 end);
            void UnescapedCharacters(TextEditor& editor, uint32 start, uint32 end);
            void EscapeNonAsciiCharacters(TextEditor& editor, uint32 start, uint32 end);
        }
        class StringOpDialog : public Window
        {
            TokenObject& tok;
            Reference<TextArea> txValue;
            Reference<ParseInterface> parser;
            TextEditorBuilder editor;
            const char16* text;
            bool openInANewWindow;
            
            void UpdateValue(bool original);
            void UpdateTokenValue();
            void RunStringOperation(uint32 commandID);
          public:
            StringOpDialog(TokenObject& tok, const char16* text, Reference<ParseInterface> parser);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline bool ShouldOpenANewWindow() const
            {
                return openInANewWindow;
            }
            inline const CharacterBuffer& GetStringValue() 
            {
                return txValue->GetText();
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
        class PluginDialog : public Window
        {
            Reference<Window> parent;
            PluginData& pluginData;
            Reference<ListView> lstPlugins;
            Reference<RadioBox> rbRunOnSelection, rbRunOnCurrentBlock, rbRunOnEntireFile;
            Reference<CheckBox> cbOpenInNewWindow;
            Reference<SettingsData> settings;
            PluginAfterActionRequest afterActionRequest;
            uint32 selectionStart, selectionEnd, blockStart, blockEnd;

            void UpdatePluginData();
            void RunPlugin();

          public:
            PluginDialog(
                  PluginData& data,
                  Reference<SettingsData> settings,
                  Reference<Window> parent,
                  uint32 selectionStart,
                  uint32 selectionEnd,
                  uint32 blockStart,
                  uint32 blockEnd);
            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline PluginAfterActionRequest GetAfterActionRequest() const
            {
                return afterActionRequest;
            }
        };
        class GoToDialog : public Window
        {
            Reference<TextField> txLineNumber;
            uint32 selectedLineNo;
            uint32 maxLines;
            void Validate();

          public:
            GoToDialog(uint32 currentLine, uint32 maxLines);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline uint32 GetSelectedLineNo() const
            {
                return selectedLineNo;
            }
        };
        class FindAllDialog : public Window
        {
            Reference<ListView> lst;
            uint32 selectedTokenIndex;
            void Validate();

          public:
            FindAllDialog(const TokenObject& currentToken,const std::vector<TokenObject>& tokens, const char16* txt);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
            inline uint32 GetSelectedTokenIndex() const
            {
                return selectedTokenIndex;
            }
        };
        class SaveAsDialog : public Window
        {
            Reference<TextField> txPath;
            Reference<ComboBox> comboEncoding, comboNewLine;
            Reference<CheckBox> cbOpenInNewWindow, cbBackupOriginalFile,cIgnoreMetadataOnSave;
            void Validate();
            void BrowseForFile();

          public:
            SaveAsDialog(Reference<Object> obj);

            virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;

            std::string_view GetNewLineFormat();
            CharacterEncoding::Encoding GetTextEncoding();
            bool HasBOM();

            inline bool ShouldBackupOriginalFile()
            {
                return cbBackupOriginalFile->IsChecked();
            }
            inline bool ShouldOpenANewWindow()
            {
                return cbOpenInNewWindow->IsChecked();
            }
            inline bool ShouldIgnoreMetadataOnSave()
            {
                return cIgnoreMetadataOnSave->IsChecked();
            }
            inline const CharacterBuffer& GetFilePath()
            {
                return txPath->GetText();
            }
        };

    } // namespace LexicalViewer
} // namespace View

}; // namespace GView