#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace XML
    {
        namespace TokenType
        {
            constexpr uint32 None           = 0xFFFFFFFF;
            constexpr uint32 StartTag       = 0;
            constexpr uint32 EndTag         = 1;
            constexpr uint32 TagName        = 2;
            constexpr uint32 Colon          = 3;
            constexpr uint32 Equals         = 4;
            constexpr uint32 AttributeClass = 5;
            constexpr uint32 Text           = 6;
            constexpr uint32 Slash          = 7;
            constexpr uint32 ErrorValue     = 8;

        } // namespace TokenType
        class XMLFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            void Tokenize(
                  uint32 start,
                  uint32 end,
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks);
            void Tokenize(
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& tokenList,
                  GView::View::LexicalViewer::BlocksList& blocks);

            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
            void IndentSimpleInstructions(GView::View::LexicalViewer::TokensList& list, GView::View::LexicalViewer::BlocksList& blocks);

          public:
            XMLFile();

            ~XMLFile() override = default;

            bool Update();

            std::string_view GetTypeName() override
            {
                return "XML";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;

            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

            uint32 GetSelectionZonesCount() override
            {
                CHECK(selectionZoneInterface.IsValid(), 0, "");
                return selectionZoneInterface->GetSelectionZonesCount();
            }

            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

                return selectionZoneInterface->GetSelectionZone(index);
            }

            std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
        };
    } // namespace XML
} // namespace Type
} // namespace GView
