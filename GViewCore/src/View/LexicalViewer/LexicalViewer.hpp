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

        class TokensListBuilder: public TokensList
        {
          public:
            TokensListBuilder(void* _data)
            {
                this->data = _data;
            }
        };
        struct TokenObject
        {
            uint32 start, end;
            int32 x, y;
            uint8 maxWidth, maxHeight, width, height;
            TokenType type;
            
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
                AppCUI::Input::Key WordWrap;
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

            struct
            {
                int32 x, y;
            } Scroll;


            static Config config;

            void ComputeOriginalPositions();
            void EnsureCurrentItemIsVisible();
            void PaintToken(Graphics::Renderer& renderer, const TokenObject& tok, bool onCursor);
            void MoveLeft(bool selected);
            void MoveRight(bool selected);
            void MoveUp(uint32 times, bool selected);
            void MoveDown(uint32 times, bool selected);
          public:
            std::vector<TokenObject> tokens;
            
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

    } // namespace TextViewer
} // namespace View

}; // namespace GView