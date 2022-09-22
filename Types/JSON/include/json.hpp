#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace JSON
    {
        namespace TokenType
        {
            constexpr uint32 open_brace     = 0;
            constexpr uint32 closed_brace   = 1;
            constexpr uint32 key            = 2;
            constexpr uint32 value          = 3;
            constexpr uint32 colon          = 4;
            constexpr uint32 comma          = 5;
            constexpr uint32 open_bracket   = 6;
            constexpr uint32 closed_bracket = 7;
            constexpr uint32 invalid        = 8;
        } // namespace TokenType

        namespace Plugins
        {
            class UpperCase : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
        }

        class JSONFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            void ParseFile(GView::View::LexicalViewer::SyntaxManager& syntax);
            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
          public:
            Plugins::UpperCase upper_case_plugin;

            JSONFile();
            virtual ~JSONFile()
            {
            }

            std::string_view GetTypeName() override
            {
                return "JSON";
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
                Reference<GView::Type::JSON::JSONFile> json;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::JSON::JSONFile> json);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels

    } // namespace JSON
} // namespace Type
} // namespace GView
