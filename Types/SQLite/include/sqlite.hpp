#pragma once

#include "GView.hpp"

#include "../src/SQLiteDB.hpp"

namespace GView
{
namespace Type
{
    namespace SQLite
    {
        constexpr uint8_t SQLITE3_MAGIC[] = "SQLite format 3";
        constexpr char BUFFER_VIEW_SEPARATOR[] = ",";

        class SQLiteFile : public TypeInterface, public AppCUI::Controls::Handlers::OnListViewItemPressedInterface
        {
          public:
            DB db;
            Buffer buf;

          public:
            SQLiteFile()          = default;
            virtual ~SQLiteFile() = default;

            bool Update();

            std::string_view GetTypeName() override;

            virtual void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;

            void InitListView(Reference<Controls::ListView> lv);
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::SQLite::SQLiteFile> sqlite;
                Reference<AppCUI::Controls::ListView> tables;

                void UpdateTableInformation();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::SQLite::SQLiteFile> sqlite);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace SQLite
} // namespace Type
} // namespace GView
