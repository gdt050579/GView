#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

const auto BTN_ID_OK = 0;
constexpr uint32 SQL_SHOW_DIALOG = 1;

Panels::Information::Information(Reference<GView::Type::SQLite::SQLiteFile> _sqlite) : TabPage("&Tables")
{
    sqlite = _sqlite;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:100%", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);
    this->Update();
}
void Panels::Information::UpdateTablesInfo()
{
    NumericFormatter n;
    LocalString<1024> tmp;

    auto tables = sqlite->db.GetTables();
    for (auto& table : tables)
    {
        auto tableMetadata = sqlite->db.GetTableMetadata(table);
        general->AddItem(table).SetType(ListViewItem::Type::Category);

        auto noEntries = sqlite->db.GetTableCount(table);
        general->AddItem({ "Number of entries", std::to_string(noEntries) });

        for (auto& columnMetadata : tableMetadata)
        {
            
            LocalString<1024> columnInfoReadable;
            LocalString<200> columnName;
            columnName.Add(columnMetadata[0]);
            
            if (columnMetadata[4] == "1")
            {
                columnName.Add(" (PK)");   
            }

            columnInfoReadable.Add(columnMetadata[1]);
            columnInfoReadable.Add(", ");
            if (columnMetadata[3] == "NULL")
            {
                columnInfoReadable.Add("NO DEFAULT VALUE");
            }
            else
            {
                columnInfoReadable.Add("WITH DEFAULT VALUE ");
                columnInfoReadable.Add(columnMetadata[3]);
            }

            if (columnMetadata[2] == "1" && columnMetadata[4] != "1")
            {
                columnInfoReadable.Add(", UNIQUE CONSTRAINT");
            }

            general->AddItem({ columnName, columnInfoReadable });
        }
        
    }
}

void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!tables.IsValid()))
    {
        return;
    }

    this->tables->Resize(w, h);
}

void Panels::Information::UpdateGeneralInfo()
{
    LocalString<1024> ls;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);
    general->AddItem({ "SQLite lib version", sqlite->db.GetLibraryVersion() });
}

void Panels::Information::Update()
{
    //general->DeleteAllItems();

    UpdateGeneralInfo();
    UpdateTablesInfo();
}

bool Panels::Information::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Ctrl | Key::A, "ProcessData", SQL_SHOW_DIALOG);
    return true;
}
