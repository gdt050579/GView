#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace Log
    {
        namespace TokenType
        {
            constexpr uint32 ip_address    = 0;
            constexpr uint32 dash          = 1;
            constexpr uint32 bracket_open  = 2;
            constexpr uint32 bracket_close = 3;
            constexpr uint32 quotes        = 4;
            constexpr uint32 space         = 5;
            constexpr uint32 alphanum      = 6;
            constexpr uint32 invalid       = 7;
            constexpr uint32 value         = 8;
        } // namespace TokenType

        class LogFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
            void ParseFile(GView::View::LexicalViewer::SyntaxManager& syntax);
            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);

          public:
            LogFile();
            virtual ~LogFile();

            std::string_view GetTypeName() override
            {
                return "Log";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result) override;
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
                Reference<GView::Type::Log::LogFile> log;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::Log::LogFile> log);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    } // namespace Log
} // namespace Type
} // namespace GView
