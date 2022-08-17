#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace CPP
    {
        class CPPFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            uint32 TokenizeWord(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            uint32 TokenizeOperator(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            uint32 TokenizePreprocessDirective(const GView::View::LexicalViewer::TextParser& text, uint32 pos);
            void Tokenize(const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& list);
          public:
            CPPFile();
            virtual ~CPPFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "C++";
            }

            virtual void AnalyzeText(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& list) override;
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::CPP::CPPFile> cpp;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::CPP::CPPFile> cpp);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace CPP
} // namespace Type
} // namespace GView
