#pragma once

#include "GView.hpp"

namespace GView::Type::SQLite
{
constexpr uint8_t SQLITE3_MAGIC[]      = "SQLite format 3";
constexpr char BUFFER_VIEW_SEPARATOR[] = ",";
constexpr char separator               = ',';

class SQLiteFile : public TypeInterface
{
  public:
    GView::SQLite3::Database db;
    Buffer buf;

  public:
    SQLiteFile() = default;

    bool Update();

    std::string_view GetTypeName() override;

    void GetStatementResult(const std::string_view& entity, bool fromTable);

    virtual void RunCommand(std::string_view commandName) override;

    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<GView::Type::SQLite::SQLiteFile> sqlite;
        Reference<AppCUI::Controls::ListView> tables;
        Reference<AppCUI::Controls::ListView> general;
        void RecomputePanelsPositions();

      public:
        Information(Reference<GView::Type::SQLite::SQLiteFile> sqlite);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        void UpdateGeneralInfo();
        void UpdateTablesInfo();
    };

    class Count : public AppCUI::Controls::TabPage
    {
        Reference<GView::Type::SQLite::SQLiteFile> sqlite;
        Reference<AppCUI::Controls::ListView> tables;
        Reference<AppCUI::Controls::ListView> general;
        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };
        void RecomputePanelsPositions();

      public:
        Count(Reference<GView::Type::SQLite::SQLiteFile> sqlite);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        virtual bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        void UpdateGeneralInfo();
        void UpdateTablesInfo();
    };
}; // namespace Panels

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
        virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override;
        virtual void OnFocus() override;
        virtual bool OnKeyEvent(Input::Key keyCode, char16 UnicodeChar) override;
        bool ProcessInput();
        void Update();
        void UpdateTablesInformation();
        virtual void OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item) override;
    };
} // namespace PluginDialogs
} // namespace GView::Type::SQLite
