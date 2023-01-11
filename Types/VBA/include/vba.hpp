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
          public:
            VBAFile();
            virtual ~VBAFile()
            {
            }

            std::string_view GetTypeName() override
            {
                return "VBA";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;
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
