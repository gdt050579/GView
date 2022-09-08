#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace VBA
    {

        class VBAFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            void Tokenize(GView::View::LexicalViewer::SyntaxManager& syntax);
            void CreateBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
            uint32 ParseWord(GView::View::LexicalViewer::SyntaxManager& syntax, uint32 pos);
            GView::View::LexicalViewer::TokenAlignament NewLineRequired;

          public:
            VBAFile();
            virtual ~VBAFile()
            {
            }

            std::string_view GetTypeName() override
            {
                return "VBA";
            }
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::VBA::VBAFile> vba;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::VBA::VBAFile> vba);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels

    } // namespace VBA
} // namespace Type
} // namespace GView
