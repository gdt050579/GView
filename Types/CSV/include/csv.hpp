#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace CSV
    {
        namespace Panels
        {
            enum class IDs : unsigned char
            {
                Information = 0,
            };
        };

        class CSVFile : public TypeInterface
        {
          private:
            bool hasHeader{ false };
            unsigned int columnsNo{ 0 };
            unsigned int rowsNo{ 0 };
            char separator[2]{""};

            uint64_t panelsMask{ 0 };

          public:
            Reference<GView::Object> obj;
            Reference<GView::Utils::DataCache> file;

          public:
            CSVFile(Reference<GView::Utils::DataCache> fileCache);
            virtual ~CSVFile() = default;

            std::string_view GetTypeName() override;
            bool Update(Reference<GView::Object> obj);
            bool HasPanel(Panels::IDs id);
            void UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings);
            void UpdateGrid(GView::View::GridViewer::Settings& settings);
        };

        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
              private:
                Reference<GView::Type::CSV::CSVFile> csv;
                Reference<AppCUI::Controls::ListView> general;

              public:
                Information(Reference<GView::Type::CSV::CSVFile> csv);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override;

              private:
                void UpdateGeneralInformation();
                void RecomputePanelsPositions();
            };
        }; // namespace Panels
    }      // namespace CSV
} // namespace Type
} // namespace GView
