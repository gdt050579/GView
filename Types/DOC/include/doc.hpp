#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace DOC
    {
        namespace Panels
        {
            class Information;
        }

        class ByteStream
        {
          private:
            void* ptr;
            size_t size;
            size_t cursor;

          public:
            ByteStream(void* ptr, size_t size) : ptr(ptr), size(size), cursor(0) {};

            BufferView Read(size_t count);
            template <typename T> T ReadAs() {
                size_t count = sizeof(T);
                if (cursor + count > size) {
                    count = size - cursor;
                }
                T value      = *(T*) ((uint8*) ptr + cursor);
                cursor += count;
                return value;
            }

            void Seek(size_t count);

            size_t GetCursor() {
                return cursor;
            };

            size_t GetSize()
            {
                return size;
            }
        };

        class DOCFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
        {
          private:
            friend class Panels::Information;

          public:
            DOCFile();
            virtual ~DOCFile() override
            {
            }

            virtual std::string_view GetTypeName() override
            {
                return "DOC";
            }
            virtual void RunCommand(std::string_view command) override
            {
                // here
            }

          public:

            bool ProcessData();
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
                Reference<GView::Type::DOC::DOCFile> doc;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> headers;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::DOC::DOCFile> doc);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels

    } // namespace DOC
} // namespace Type
} // namespace GView
