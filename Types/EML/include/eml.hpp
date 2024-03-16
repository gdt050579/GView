#pragma once

#include "GView.hpp"

struct EML_Item_Record
{
    uint32 startIndex;
    uint32 dataLength;
    bool leafNode;
};

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

        class EMLFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
        {
          private:
            std::vector<EML_Item_Record> items{};
            uint32 itemsIndex = 0;
            std::u16string contentType;

          private:
            friend class Panels::Information;

            std::vector<std::pair<std::u16string, std::u16string>> headerFields;

            void ParsePart(GView::View::LexicalViewer::TextParser text, uint32 start, uint32 end);
            void ParseHeaders(GView::View::LexicalViewer::TextParser text, uint32& index);
            uint32 ParseHeaderFieldBody(GView::View::LexicalViewer::TextParser text, uint32 index);

          public:
            EMLFile();
            virtual ~EMLFile() override {}

            virtual std::string_view GetTypeName() override
            {
                return "EML";
            }
            virtual void RunCommand(std::string_view command) override
            {
                // here
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

            // View::ContainerViewer::EnumerateInterface
            virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
            virtual bool PopulateItem(AppCUI::Controls::TreeViewItem item) override;

            // View::ContainerViewer::OpenItemInterface
            virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

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
