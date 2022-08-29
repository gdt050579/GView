#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace INI
    {
        namespace TokenType
        {
            constexpr uint32 Comment    = 0;
            constexpr uint32 Section    = 1;
            constexpr uint32 Key        = 2;
            constexpr uint32 Equal      = 3;
            constexpr uint32 Value      = 4;
            constexpr uint32 ArrayStart = 5;
            constexpr uint32 Comma      = 6;
            constexpr uint32 ArrayEnd   = 7;
            constexpr uint32 Invalid    = 0xFFFFFFFF;

        } // namespace TokenType
        namespace Plugins
        {
            class RemoveComments : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
        } // namespace Plugins
        class INIFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
          public:
            struct
            {
                Plugins::RemoveComments removeComments;
            } plugins;

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
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
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

    } // namespace INI
} // namespace Type
} // namespace GView
