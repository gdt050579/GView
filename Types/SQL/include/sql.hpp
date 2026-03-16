#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace SQL
    {
        namespace TokenType
        {
            constexpr uint32 None = 0xFFFFFFFF;

            constexpr uint32 Comment    = 0;
            constexpr uint32 Whitespace = 1;

            constexpr uint32 ExpressionOpen  = 2; // (
            constexpr uint32 ExpressionClose = 3; // )
            constexpr uint32 Comma           = 4; // ,
            constexpr uint32 Semicolumn      = 5; // ;
            constexpr uint32 Dot             = 6; // .
            constexpr uint32 Wildcard        = 7; // *

            constexpr uint32 Number         = 8;
            constexpr uint32 String         = 9;
            constexpr uint32 BooleanLiteral = 10;
            constexpr uint32 NullLiteral    = 11;

            constexpr uint32 Identifier       = 12;
            constexpr uint32 QuotedIdentifier = 13;

            constexpr uint32 Parameter = 14; // ?, :name, @name, $1

            constexpr uint32 Operator           = 15;
            constexpr uint32 ComparisonOperator = 16;
            constexpr uint32 LogicalOperator    = 17;

            constexpr uint32 Keyword  = 18;
            constexpr uint32 Datatype = 19;
            constexpr uint32 Constant = 20;

            constexpr uint32 BlockOpen  = 21; // BEGIN
            constexpr uint32 BlockClose = 22; // END
            constexpr uint32 ArrayOpen  = 23;
            constexpr uint32 ArrayClose = 24;

            constexpr uint32 Function = 25;
        } // namespace TokenType

        namespace Plugins
        {
            class RemoveComments : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(
                      GView::View::LexicalViewer::PluginData& data, Reference<Window> parent) override;
            };
        } // namespace Plugins

        class SQLFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            uint32 TokenizeWord(const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos, int& context);
            uint32 TokenizeOperator(const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
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
            void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str);

        public:
            struct
            {
              Plugins::RemoveComments removeComments;
            } plugins;

          public:
            SQLFile();
            virtual ~SQLFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "SQL";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;

            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;

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
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::SQL::SQLFile> sql;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::SQL::SQLFile> sql);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    } // namespace SQL
} // namespace Type
} // namespace GView
