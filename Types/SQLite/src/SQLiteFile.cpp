#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;

std::string_view SQLiteFile::GetTypeName()
{
    return "SQLite";
}

bool SQLiteFile::Update()
{
    // memvfs requires a non-const buffer in order to load an in-memory database.
    // Therefore, a copy is required.
    // memOpen() -> https://www.sqlite.org/src/file/ext/misc/memvfs.c
    buf = obj->GetData().CopyEntireFile();
    CHECK(buf.IsValid(), false, "Fail to copy entire file");

    db = DB(buf);

    return true;
}

void SQLiteFile::OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item)
{
    auto table = (std::string) item.GetText(0);
    auto data = db.GetTableData(table);

    AppCUI::Utils::String contents;

    bool comma = false;

    for (const auto& column : data.first)
    {
        if (!comma)
        {
            comma = true;
        }
        else
        {
            contents.AddChar(',');
        }

        contents.Add(column);
    }

    contents.Add("\n");

    for (const auto& row : data.second)
    {
        comma = false;

        for (const auto& entry : row)
        {
            if (!comma)
            {
                comma = true;
            }
            else
            {
                contents.AddChar(',');
            }

            contents.Add(entry);
        }

        contents.Add("\n");
    }

    BufferView buff(contents.GetText(), contents.Len());
    GView::App::OpenBuffer(buff, table + ".csv", ".csv");
}

void SQLiteFile::InitListView(Reference<Controls::ListView> lv)
{
    lv->Handlers()->OnItemPressed = this;
}