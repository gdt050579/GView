#include "sqlite.hpp"

using namespace AppCUI::Controls;
using namespace AppCUI::Input;

namespace GView::Type::SQLite::Panels
{

Count::Count(Reference<GView::Type::SQLite::SQLiteFile> _sqlite) : TabPage("&Additional Information")
{
    sqlite  = _sqlite;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:100%", std::initializer_list<ConstString>{ "n:Field,w:50", "n:Value,w:50" }, ListViewFlags::None);
    this->Update();
}

void Count::UpdateTablesInfo()
{
    NumericFormatter n;
    LocalString<1024> tmp;

    auto tables = sqlite->db.GetTables();
    for (auto& table : tables) {
        auto tableMetadata = sqlite->db.GetTableMetadata(table);
        general->AddItem(table).SetType(ListViewItem::Type::Category);

        auto noEntries = sqlite->db.GetTableCount(table);
        general->AddItem({ "Number of entries", std::to_string(noEntries) });
    }
}

void Count::RecomputePanelsPositions()
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

void Count::UpdateGeneralInfo()
{
    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto fileSize    = nf.ToString(sqlite->obj->GetData().GetSize(), dec);
    const auto hexfileSize = nf2.ToString(sqlite->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%s bytes (%s)", fileSize.data(), hexfileSize.data()) });
    general->AddItem({ "SQLite lib version", sqlite->db.GetLibraryVersion() });
}

void Count::Update()
{
    // general->DeleteAllItems();

    UpdateGeneralInfo();
    UpdateTablesInfo();
}

bool Count::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return true;
}

} // namespace GView::Type::SQLite::Panels
