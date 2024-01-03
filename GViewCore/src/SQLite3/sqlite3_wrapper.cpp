#include <GView.hpp>
#include <sqlite3.h>
#include <vector>

namespace GView::SQLite3
{
static bool BinaryToHex(Buffer& b, String& s)
{
    s.Create((uint32) (b.GetLength() * 2));

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
    String result;

    auto values = reinterpret_cast<std::vector<Buffer>*>(this->values);
    if (index >= values->size()) {
        return result;
    }

    auto& value = values->at(index);

    switch (type) {
    case GView::SQLite3::Column::Type::Integer:
        result.SetFormat("%lld", value.GetObject<int64>());
        break;
    case GView::SQLite3::Column::Type::Float:
        result.SetFormat("%f", value.GetObject<double>());
        break;
    case GView::SQLite3::Column::Type::Text:
        result.Set((const char*) value.GetData(), (uint32) value.GetLength());
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

Column::Column()
{
    if (!values) {
        values = new std::vector<Buffer>();
    }
}

Column::Column(const Column& other) // copy constructor
{
    type = other.type;
    name = other.name;

    auto tmp         = new std::vector<Buffer>();
    auto otherValues = reinterpret_cast<std::vector<Buffer>*>(other.values);
    for (auto i = 0; i < otherValues->size(); i++) {
        tmp->push_back(otherValues->at(i));
    }
    values = tmp;
}

Column::Column(Column&& other) noexcept // move constructor
{
    type         = other.type;
    name         = other.name;
    values       = other.values;
    other.values = nullptr; // avoid double free!!
}

Column& Column::operator=(const Column& other) // copy assignment
{
    return *this = Column(other);
}

Column& Column::operator=(Column&& other) noexcept // move assignment
{
    std::swap(type, other.type);
    std::swap(name, other.name);
    std::swap(values, other.values);
    return *this;
}

Column::~Column()
{
    if (values) {
        delete reinterpret_cast<std::vector<Buffer>*>(values);
        values = nullptr;
    }
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
            auto values = reinterpret_cast<std::vector<Buffer>*>(column.values);
            for (auto& str : *values) {
                auto& value = result.emplace_back();
                value.Set((const char*) str.GetData(), (uint32) str.GetLength());
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

    auto values = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    std::vector<std::vector<String>> results(values->size());
    for (auto i = 0; i < values->size(); i++) {
        for (auto j = 1; j < columns.size(); j++) {
            results[i].push_back((String) columns[j].ValueToString(i));
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
    return reinterpret_cast<std::vector<Buffer>*>(columns[0].values)->at(0).GetObject<int64>();
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

    auto values0 = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    auto values1 = reinterpret_cast<std::vector<Buffer>*>(columns[1].values);
    for (int i = 0; i < values0->size(); ++i) {
        String name;
        name.Set((const char*) values0->at(i).GetData(), (uint32) values0->at(i).GetLength());

        String sql;
        sql.Set((const char*) values1->at(i).GetData(), (uint32) values1->at(i).GetLength());

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

    auto values = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    for (int i = 0; i < values->size(); ++i) {
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

            auto values = reinterpret_cast<std::vector<Buffer>*>(result[i].values);
            values->push_back(b);
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