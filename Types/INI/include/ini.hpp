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
            enum CaseFormat : uint32
            {
                None = 0,
                UpperCase,
                LowerCase,
                SentenceCase,
                TitleCase,
            };
            class Casing : public GView::View::LexicalViewer::Plugin
            {
                void ChangeCaseForToken(GView::View::LexicalViewer::Token& tok, CaseFormat format, bool isSection);

              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
            class ValueToString : public GView::View::LexicalViewer::Plugin
            {
                void ConvertToString(GView::View::LexicalViewer::Token& tok, GView::View::LexicalViewer::PluginData& data);

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
                Plugins::Casing casing;
                Plugins::ValueToString valueToString;
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
            void RunCommand(std::string_view) override
            {
            }

            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view strintValue, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;

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
