#pragma once

#include "GView.hpp"

#include "../src/SQLiteDB.hpp"

namespace GView
{
namespace Type
{
    namespace SQLite
    {
        constexpr uint8_t SQLITE3_MAGIC[]      = "SQLite format 3";
        constexpr char BUFFER_VIEW_SEPARATOR[] = ",";
        constexpr char separator               = ',';

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

            void OnListViewItemPressed(const std::string_view& tableName);

            void InitListView(Reference<Controls::ListView> lv);
            void OnButtonPressed(const std::string_view& statement);
            void RunCommand(std::string_view commandName);
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::SQLite::SQLiteFile> sqlite;
                Reference<AppCUI::Controls::ListView> tables;
                Reference<AppCUI::Controls::ListView> general;
                void UpdateTableInformation();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::SQLite::SQLiteFile> sqlite);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar);
                void UpdateGeneralInfo();
                void UpdateTablesInfo();
            };
        }; 
        namespace PluginDialogs
        {
            class TablesDialog : public AppCUI::Controls::Window, public AppCUI::Controls::Handlers::OnListViewItemPressedInterface
            {
                Reference<GView::Type::SQLite::SQLiteFile> sqlite;
                Reference<CanvasViewer> statementDescription;
                Reference<TextArea> textArea;
                Reference<ListView> general;
                Reference<ListView> tables;

              public:
                TablesDialog(Reference<GView::Type::SQLite::SQLiteFile> _sqlite);
                bool OnEvent(Reference<Control>, Event eventType, int ID);
                void OnFocus();
                void OnCheck(Reference<Controls::Control> control, bool /* value */);
                bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar);
                bool ProcessInput();
                void Update();
                void UpdateTablesInformation();
                void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item);
                void InitListView(Reference<Controls::ListView> lv);
            };        
       }
        
        // namespace Panels
    }      // namespace SQLite
} // namespace Type
} // namespace GView