#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace INI
    {
        class INIFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
          public:
            INIFile();
            virtual ~INIFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "INI";
            }

            virtual void ExtractTokens(const GView::Utils::Tokenizer::Lexer& lex) override;
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::INI::INIFile> ini;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::INI::INIFile> ini);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace INI
} // namespace Type
} // namespace GView
