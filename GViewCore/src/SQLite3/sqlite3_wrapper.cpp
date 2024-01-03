#include <GView.hpp>
#include <sqlite3.h>
#include <vector>

namespace GView::SQLite3
{
static bool BinaryToHex(Buffer& b, String& s)
{
    s.Create(b.GetLength() * 2);

    for (auto i = 0u; i < b.GetLength(); i++) {
        const auto byte = b[i];
        char highNibble = (byte >> 4) & 0xF;
        char lowNibble  = byte & 0xF;

        s.AddChar((highNibble < 10) ? ('0' + highNibble) : ('A' + highNibble - 10));
        s.AddChar((lowNibble < 10) ? ('0' + lowNibble) : ('A' + lowNibble - 10));
    }

    return true;
}

String Column::ValueToString(uint32 index)
{
    // TODO: out of bounds check?
    auto& value = values[index];

    String result;
    switch (type) {
    case GView::SQLite3::Column::Type::Integer:
        result.SetFormat("%lld", value.GetObject<int64>());
        break;
    case GView::SQLite3::Column::Type::Float:
        result.SetFormat("%f", value.GetObject<double>());
        break;
    case GView::SQLite3::Column::Type::Text:
        result.Set((const char*) value.GetData(), value.GetLength());
        break;
    case GView::SQLite3::Column::Type::Blob:
        BinaryToHex(value, result);
        break;
    case GView::SQLite3::Column::Type::Null:
        result.Set("NULL");
        break;
    default:
        break;
    }

    return result;
}

Database::Database(const std::u16string_view& filePath)
{
    std::u16string sanitizedFilepath{ filePath };
    auto errorCode = sqlite3_open16(sanitizedFilepath.c_str(), (sqlite3**) &handle);
    if (errorCode != SQLITE_OK) {
        if (handle) {
            sqlite3_close_v2((sqlite3*) handle);
            handle = nullptr;
        }
        const char* errorMessage = sqlite3_errstr(errorCode);
        this->errorMessage.Set(errorMessage);
    }
}

Database& Database::operator=(Database&& other) noexcept
{
    this->handle = other.handle;
    other.handle = nullptr;
    this->errorMessage.Set(other.errorMessage);
    return *this;
}

std::vector<String> Database::GetTables()
{
    std::vector<String> result;

    if (handle) {
        auto columns = ExecuteQuery("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC;");
        for (auto& column : columns) {
            for (auto& str : column.values) {
                auto& value = result.emplace_back();
                value.Set((const char*) str.GetData(), str.GetLength());
            }
            break; // only the first (that contains the tables)
        }
    }

    return result;
}

std::vector<std::vector<String>> Database::GetTableMetadata(std::string_view tableName)
{
    if (!handle) {
        return {};
    }

    AppCUI::Utils::String query;
    query.SetFormat("SELECT * FROM PRAGMA_TABLE_INFO('%.*s') as TABLE_INFO;", tableName.size(), tableName.data());
    auto value   = query.GetText();
    auto columns = ExecuteQuery(query.GetText());
    if (columns.empty()) {
        return {};
    }

    std::vector<std::vector<String>> results(columns[0].values.size());
    for (auto valueIndex = 0; valueIndex < columns[0].values.size(); valueIndex++) {
        for (auto columnIndex = 1; columnIndex < columns.size(); columnIndex++) {
            results[valueIndex].push_back((String) columns[columnIndex].ValueToString(valueIndex));
        }
    }

    return results;
}

AppCUI::int64 Database::GetTableCount(std::string_view tableName)
{
    if (!handle) {
        return -1;
    }

    AppCUI::Utils::String query;
    query.SetFormat("SELECT COUNT(*) FROM %.*s;", tableName.size(), tableName.data());
    auto columns = ExecuteQuery(query.GetText());
    return columns[0].values[0].GetObject<int64>();
}

String Database::GetLibraryVersion()
{
    return String(sqlite3_libversion());
}

std::vector<std::pair<String, String>> Database::GetTableInfo()
{
    if (!handle) {
        return {};
    }

    auto columns = ExecuteQuery("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name ASC");

    if (columns.size() == 0) {
        return {};
    }

    std::vector<std::pair<String, String>> result;

    for (int i = 0; i < columns[0].values.size(); ++i) {
        String name;
        name.Set((const char*) columns[0].values[i].GetData(), columns[0].values[i].GetLength());

        String sql;
        sql.Set((const char*) columns[1].values[i].GetData(), columns[1].values[i].GetLength());

        result.push_back(std::make_pair(name, sql));
    }

    return result;
}

std::pair<std::vector<String>, std::vector<std::vector<String>>> Database::GetTableData(std::string_view name)
{
    AppCUI::Utils::String query;
    query.SetFormat("SELECT * FROM %.*s;", name.size(), name.data());
    return this->GetStatementData(query);
}

std::pair<std::vector<String>, std::vector<std::vector<String>>> Database::GetStatementData(const std::string_view& statement)
{
    if (!handle) {
        return {};
    }

    auto columns = ExecuteQuery(statement.data());
    std::pair<std::vector<String>, std::vector<std::vector<String>>> result;

    if (columns.empty()) {
        return result;
    }

    for (int i = 0; i < columns.size(); ++i) {
        result.first.push_back(std::move(columns[i].name));
    }

    for (int i = 0; i < columns[0].values.size(); ++i) {
        result.second.emplace_back();

        for (int j = 0; j < columns.size(); ++j) {
            result.second[i].emplace_back(columns[j].ValueToString(i));
        }
    }

    return result;
}

std::vector<Column> Database::ExecuteQuery(const char* query)
{
    const char* tail = nullptr;
    sqlite3_stmt* sHandle{ nullptr };
    const int errorCode      = sqlite3_prepare_v2((sqlite3*) handle, query, -1, &sHandle, &tail);
    const char* errorMessage = sqlite3_errstr(errorCode);

    auto columnCount = sqlite3_column_count(sHandle);
    std::vector<Column> result;

    for (int i = 0; i < columnCount; ++i) {
        auto& entry = result.emplace_back();
        entry.name  = sqlite3_column_name(sHandle, i);

        int type = sqlite3_column_type(sHandle, i);

        switch (type) {
        case SQLITE_INTEGER:
            entry.type = Column::Type::Integer;
            break;
        case SQLITE_FLOAT:
            entry.type = Column::Type::Float;
            break;
        case SQLITE_TEXT:
            entry.type = Column::Type::Text;
            break;
        case SQLITE_BLOB:
            entry.type = Column::Type::Blob;
            break;
        case SQLITE_NULL:
            entry.type = Column::Type::Null;
            break;
        }
    }

    auto status = sqlite3_step(sHandle);
    if (status == SQLITE_DONE) {
        sqlite3_reset(sHandle);
        return result;
    }

    do {
        for (int i = 0; i < columnCount; ++i) {
            // If the column is null now, it may not be null in future rows.
            // Therefore, get the actual type. If the actual type is also null,
            // the column is null for every row.
            auto b    = Buffer();
            auto type = sqlite3_column_type(sHandle, i);
            switch (type) {
            case SQLITE_NULL:
                b.Add("cest12");
                break;
            case SQLITE_INTEGER: {
                result[i].type = Column::Type::Integer;

                const auto value = sqlite3_column_int64(sHandle, i);
                auto bv          = BufferView{ (uint8*) &value, sizeof(value) };
                b.Add(bv);
            } break;
            case SQLITE_FLOAT: {
                result[i].type = Column::Type::Float;

                const auto value = sqlite3_column_double(sHandle, i);
                auto bv          = BufferView{ (uint8*) &value, sizeof(value) };
                b.Add(bv);
            } break;
            case SQLITE_TEXT: {
                result[i].type = Column::Type::Text;
                b.Add(BufferView{ (const char*) sqlite3_column_text(sHandle, i), (uint32) sqlite3_column_bytes(sHandle, i) });
            } break;
            case SQLITE_BLOB:
                result[i].type = Column::Type::Blob;
                b.Add(BufferView{ (char*) sqlite3_column_blob(sHandle, i), (uint32) sqlite3_column_bytes(sHandle, i) });
                break;
            }
            result[i].values.push_back(b);
        }

        status = sqlite3_step(sHandle);
    } while (status == SQLITE_ROW);

    sqlite3_reset(sHandle);

    return result;
}

Database::~Database()
{
    if (handle) {
        sqlite3_close_v2((sqlite3*) handle);
        handle = nullptr;
    }
}
} // namespace GView::SQLite3