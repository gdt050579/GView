#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace JS
    {
        namespace TokenType
        {
            constexpr uint32 None            = 0xFFFFFFFF;
            constexpr uint32 Comment         = 0;
            constexpr uint32 ArrayOpen       = 1;
            constexpr uint32 ArrayClose      = 2;
            constexpr uint32 BlockOpen       = 3;
            constexpr uint32 BlockClose      = 4;
            constexpr uint32 ExpressionOpen  = 5;
            constexpr uint32 ExpressionClose = 6;
            constexpr uint32 Number          = 7;
            constexpr uint32 String          = 8;
            constexpr uint32 Comma           = 9;
            constexpr uint32 Semicolumn      = 10;
            constexpr uint32 Preprocess      = 11;
            constexpr uint32 Word            = 12;
            constexpr uint32 Operator        = 13;
            constexpr uint32 Keyword         = 14;
            constexpr uint32 Constant        = 15;
            constexpr uint32 Datatype        = 16;

        } // namespace TokenType

        class JSFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            uint32 TokenizeWord(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            uint32 TokenizeOperator(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            uint32 TokenizePreprocessDirective(
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks,
                  uint32 pos);
            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
            void IndentSimpleInstructions(GView::View::LexicalViewer::TokensList& list);
            void CreateFoldUnfoldLinks(GView::View::LexicalViewer::SyntaxManager& syntax);
            void Tokenize(
                  uint32 start,
                  uint32 end,
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks);
            void Tokenize(
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks);
            void RemoveLineContinuityCharacter(GView::View::LexicalViewer::TextEditor& editor);

          public:
            JSFile();
            virtual ~JSFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "JavaScript";
            }
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::JS::JSFile> js;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::JS::JSFile> js);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace JS
} // namespace Type
} // namespace GView
