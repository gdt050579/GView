#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace VBA
    {
        namespace TokenType
        {
            constexpr uint32 None        = 0xFFFFFFFF;
            constexpr uint32 Unknown     = 1;
            constexpr uint32 Equal       = 2;  // '='
            constexpr uint32 LeftParen   = 3;  // '('
            constexpr uint32 RightParen  = 4;  // ')'
            constexpr uint32 Comma       = 5;  // ','
            constexpr uint32 Dot         = 6;  // '.'
            constexpr uint32 Underscore  = 7;  // '_'
            constexpr uint32 Ampersand   = 8;  // '&'
            constexpr uint32 Dollar      = 9;  // '$'
            constexpr uint32 Plus        = 10; // '+'
            constexpr uint32 Minus       = 11; // '-'
            constexpr uint32 Asterisk    = 12; // '*'
            constexpr uint32 Slash       = 13; // '/'
            constexpr uint32 LessThan    = 14; // '<'
            constexpr uint32 GreaterThan = 15; // '>'
            constexpr uint32 Hash        = 16; // '#'
            constexpr uint32 Backslash   = 17; // '\\'
            constexpr uint32 Colon       = 18; // ':'
            constexpr uint32 String      = 19;
            constexpr uint32 Variable    = 20;
            constexpr uint32 Keyword     = 21;
            constexpr uint32 Comment     = 22;
            constexpr uint32 AplhaNum    = 23;
            constexpr uint32 VariableRef = 24;

        } // namespace TokenType

        namespace Plugins
        {
            class ReplaceVariables : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(
                      GView::View::LexicalViewer::PluginData& data, Reference<Window> parent) override;
            };
            class ConcatenateConstantStrings : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(
                      GView::View::LexicalViewer::PluginData& data, Reference<Window> parent) override;
            };
        } // namespace Plugins

        class VBAFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            std::unordered_map<std::u16string, std::u16string> variables;
          public:
            VBAFile();
            virtual ~VBAFile()
            {
            }

            struct {
                Plugins::ReplaceVariables replaceVariables;
                Plugins::ConcatenateConstantStrings concatenateConstantStrings;
            } plugins;

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
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

          public:
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
