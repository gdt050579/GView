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

void SQLiteFile::OnButtonPressed(const std::string_view& statement)
{
    auto data = db.GetStatementData(statement);

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
            contents.AddChar(separator);
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
                contents.AddChar(separator);
            }

            contents.Add(entry);
        }

        contents.Add("\n");
    }
    const auto content = contents.GetText();
    BufferView buff(contents.GetText(), contents.Len());
    GView::App::OpenBuffer(buff, "test.csv", "name.csv", GView::App::OpenMethod::FirstMatch, "csv");
}

void SQLiteFile::OnListViewItemPressed(const std::string_view& tableName)
{
    auto data = db.GetTableData(tableName);

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
            contents.AddChar(separator);
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
                contents.AddChar(separator);
            }

            contents.Add(entry);
        }

        contents.Add("\n");
    }
    BufferView buff(contents.GetText(), contents.Len());

    AppCUI::Utils::String tableAsCsv;
    tableAsCsv.SetFormat("%.*s.csv", tableName.size(), tableName.data());
    GView::App::OpenBuffer(buff, tableAsCsv, tableAsCsv, GView::App::OpenMethod::FirstMatch, "csv");
}

void SQLiteFile::RunCommand(std::string_view commandName)
{
    if (commandName == "ShowTablesDialog")
    {
        auto dialog = PluginDialogs::TablesDialog(this);
        dialog.Show();
    }
}