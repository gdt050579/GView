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
                None = 0
            };
        };

        class CSVFile : public TypeInterface
        {
        private:
            bool hasHeader{ false };
            unsigned int columnsNo{ 0 };
            unsigned int rowsNo{ 0 };
            char separator{ 0 };

          public:
            Reference<GView::Utils::FileCache> file;

          public:
            CSVFile(Reference<GView::Utils::FileCache> file);
            virtual ~CSVFile() = default;

            std::string_view GetTypeName() override;
            bool Update();
        };

        namespace Panels
        {
        }; // namespace Panels
    }      // namespace CSV
} // namespace Type
} // namespace GView
