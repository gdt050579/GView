#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

const auto BTN_ID_OK             = 0;
constexpr uint32 SQL_SHOW_DIALOG = 1;

Panels::Information::Information(Reference<GView::Type::SQLite::SQLiteFile> _sqlite) : TabPage("&Tables")
{
    sqlite  = _sqlite;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:100%",
          std::initializer_list<ConstString>{ "n:Column,w:20", "n:Column Type,w:20", "n:Is Pk,w:20", "n:Is Unique, w:20", "n:Default Value, w:20" },
          ListViewFlags::None);
    this->Update();
}

void Panels::Information::UpdateTablesInfo()
{
    NumericFormatter n;
    LocalString<1024> tmp;

    auto tables = sqlite->db.GetTables();

    for (auto& table : tables) {
        auto tableMetadata = sqlite->db.GetTableMetadata(table);
        general->AddItem(table).SetType(ListViewItem::Type::Category);

        for (auto& columnMetadata : tableMetadata) {
            LocalString<1024> columnInfoReadable;
            LocalString<200> columnName;
            LocalString<200> columnType;
            LocalString<200> isPk;
            LocalString<200> isUnique;
            LocalString<200> defaultValue;
            columnName.Add(columnMetadata[0]);
            columnType.Add(columnMetadata[1]);
            defaultValue.Add(columnMetadata[3]);
            isPk.Add(columnMetadata[4] == "1" ? "YES" : "NO");
            isUnique.Add(columnMetadata[2] == "1" ? "YES" : "NO");
            general->AddItem({ columnName, columnType, isPk, isUnique, defaultValue });
        }
    }
}

void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!tables.IsValid())) {
        return;
    }

    this->tables->Resize(w, h);
}

void Panels::Information::UpdateGeneralInfo()
{
}

void Panels::Information::Update()
{
    // general->DeleteAllItems();

    UpdateGeneralInfo();
    UpdateTablesInfo();
}

bool Panels::Information::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Ctrl | Key::A, "ProcessData", SQL_SHOW_DIALOG);
    return true;
}
