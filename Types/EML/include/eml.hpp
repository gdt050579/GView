#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace EML
    {
        namespace Panels
        {
            class Information;
        }

        class EMLFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
          private:
            friend class Panels::Information;

            std::multimap<std::u16string, std::u16string> headerFields;

            void ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index);
            void ParseParts(GView::View::LexicalViewer::SyntaxManager& syntax, uint32& index, string_view boundary);
            uint32 ParseHeaderFieldBody(GView::View::LexicalViewer::TextParser text, uint32 index);

          public:
            EMLFile();
            virtual ~EMLFile()
            {
            }

            virtual std::string_view GetTypeName() override
            {
                return "EML";
            }
            virtual void RunCommand(std::string_view command) override
            {
                // here
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
                Reference<GView::Type::EML::EMLFile> eml;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> headers;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::EML::EMLFile> eml);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels

    } // namespace EML
} // namespace Type
} // namespace GView
