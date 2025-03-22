#include <nlohmann/json.hpp>
#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;
using nlohmann::json;

std::string_view SQLiteFile::GetTypeName()
{
    return "SQLite";
}

bool SQLiteFile::Update()
{
    auto path = obj->GetPath();
    db        = GView::SQLite3::Database(path);
    return true;
}

void SQLiteFile::GetStatementResult(const std::string_view& entity, bool fromTable)
{
    auto data = fromTable ? db.GetTableData(entity) : db.GetStatementData(entity);

    AppCUI::Utils::String content;

    bool comma = false;

    for (auto& column : data.first) {
        if (!comma) {
            comma = true;
        } else {
            content.AddChar(separator);
        }

        for (auto i = 0u; i < column.Len(); i++) {
            if (column.GetText()[i] == separator) {
                column.SetChar(i, ';');
            }
        }

        content.Add(column);
    }

    content.Add("\n");

    for (auto& row : data.second) {
        comma = false;

        for (auto& entry : row) {
            if (!comma) {
                comma = true;
            } else {
                content.AddChar(separator);
            }

            for (auto i = 0u; i < entry.Len(); i++) {
                if (entry.GetText()[i] == separator) {
                    entry.SetChar(i, ';');
                }
            }
            content.Add(entry);
        }

        content.Add("\n");
    }

    AppCUI::Utils::String filename;
    if (fromTable) {
        filename.SetFormat("%.*s.csv", entity.size(), entity.data());
    } else {
        filename.Set("extracted.csv");
    }

    BufferView buffer(content);
    GView::App::OpenBuffer(buffer, filename, filename, GView::App::OpenMethod::FirstMatch, "csv");
}

void SQLiteFile::RunCommand(std::string_view commandName)
{
    if (commandName == "ShowTablesDialog") {
        auto dialog = PluginDialogs::TablesDialog(this);
        dialog.Show();
    }
}

std::string SQLiteFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"] = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();
    return context.dump();
}
