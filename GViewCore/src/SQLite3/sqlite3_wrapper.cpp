#include <GView.hpp>
#include <sqlite3.h>
#include <cstring>
#include <string>
#include <vector>

namespace GView::SQLite3
{
// Every cell is stored as [1 byte: the SQLITE_* type of the value][the value bytes], because SQLite is dynamically typed:
// the cells of a column can hold values of different types (and NULLs), so the type of one row can not describe the others.
static int CellType(const Buffer& cell)
{
    return cell.GetLength() > 0 ? cell[0] : SQLITE_NULL;
}

static BufferView CellData(const Buffer& cell)
{
    return cell.GetLength() > 0 ? BufferView(cell.GetData() + 1, cell.GetLength() - 1) : BufferView();
}

static bool BinaryToHex(BufferView b, String& s)
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

    auto& value     = values->at(index);
    const auto data = CellData(value);

    // the type of this cell (not the column's type, see CellType)
    switch (CellType(value)) {
    case SQLITE_INTEGER:
        if (data.GetLength() == sizeof(int64)) {
            int64 number = 0;
            memcpy(&number, data.GetData(), sizeof(number));
            result.SetFormat("%lld", static_cast<long long>(number));
        }
        break;
    case SQLITE_FLOAT:
        if (data.GetLength() == sizeof(double)) {
            double number = 0;
            memcpy(&number, data.GetData(), sizeof(number));
            result.SetFormat("%f", number);
        }
        break;
    case SQLITE_TEXT:
        result.Set((const char*) data.GetData(), (uint32) data.GetLength());
        break;
    case SQLITE_BLOB:
        BinaryToHex(data, result);
        break;
    case SQLITE_NULL:
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
    for (size_t i = 0; i < otherValues->size(); i++) {
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
    // the analyzed file must not be modified: read-only (no create, no hot journal rollback into it)
    const auto utf8Filepath = GView::Utils::UTF16ToUTF8(filePath);
    auto errorCode          = sqlite3_open_v2(utf8Filepath.c_str(), (sqlite3**) &handle, SQLITE_OPEN_READONLY, nullptr);
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
    if (this == &other) {
        return *this;
    }
    if (this->handle) {
        sqlite3_close_v2((sqlite3*) this->handle);
    }
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
                auto& value     = result.emplace_back();
                const auto text = CellData(str);
                value.Set((const char*) text.GetData(), (uint32) text.GetLength());
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

    // the table name is a string literal here => %q (doubles the single quotes)
    const std::string name{ tableName };
    char* query = sqlite3_mprintf("SELECT * FROM PRAGMA_TABLE_INFO('%q') as TABLE_INFO;", name.c_str());
    if (!query) {
        return {};
    }
    auto columns = ExecuteQuery(query);
    sqlite3_free(query);
    if (columns.empty()) {
        return {};
    }

    auto values = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    std::vector<std::vector<String>> results(values->size());
    for (size_t i = 0; i < values->size(); i++) {
        for (size_t j = 1; j < columns.size(); j++) {
            results[i].push_back((String) columns[j].ValueToString(static_cast<uint32>(i)));
        }
    }

    return results;
}

AppCUI::int64 Database::GetTableCount(std::string_view tableName)
{
    if (!handle) {
        return -1;
    }

    // the table name is an identifier here => "%w" (doubles the double quotes)
    const std::string name{ tableName };
    char* query = sqlite3_mprintf("SELECT COUNT(*) FROM \"%w\";", name.c_str());
    if (!query) {
        return -1;
    }
    auto columns = ExecuteQuery(query);
    sqlite3_free(query);
    if (columns.empty()) {
        return -1;
    }

    auto values = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    if (values->empty() || CellType(values->at(0)) != SQLITE_INTEGER) {
        return -1;
    }
    const auto data = CellData(values->at(0));
    if (data.GetLength() != sizeof(int64)) {
        return -1;
    }
    int64 count = 0;
    memcpy(&count, data.GetData(), sizeof(count));
    return count;
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
    for (size_t i = 0; i < values0->size(); ++i) {
        String name;
        const auto nameData = CellData(values0->at(i));
        name.Set((const char*) nameData.GetData(), (uint32) nameData.GetLength());

        String sql;
        const auto sqlData = CellData(values1->at(i));
        sql.Set((const char*) sqlData.GetData(), (uint32) sqlData.GetLength());

        result.push_back(std::make_pair(name, sql));
    }

    return result;
}

std::pair<std::vector<String>, std::vector<std::vector<String>>> Database::GetTableData(std::string_view name)
{
    // the table name is an identifier here => "%w" (doubles the double quotes)
    const std::string tableName{ name };
    char* query = sqlite3_mprintf("SELECT * FROM \"%w\";", tableName.c_str());
    if (!query) {
        return {};
    }
    auto result = this->GetStatementData(query);
    sqlite3_free(query);
    return result;
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

    for (size_t i = 0; i < columns.size(); ++i) {
        result.first.push_back(std::move(columns[i].name));
    }

    auto values = reinterpret_cast<std::vector<Buffer>*>(columns[0].values);
    for (size_t i = 0; i < values->size(); ++i) {
        result.second.emplace_back();

        for (size_t j = 0; j < columns.size(); ++j) {
            result.second[i].emplace_back(columns[j].ValueToString(static_cast<uint32>(i)));
        }
    }

    return result;
}

std::vector<Column> Database::ExecuteQuery(const char* query)
{
    if (!handle) {
        return {};
    }

    const char* tail = nullptr;
    sqlite3_stmt* sHandle{ nullptr };
    sqlite3_prepare_v2((sqlite3*) handle, query, -1, &sHandle, &tail);

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
    if (status != SQLITE_ROW) { // no rows (SQLITE_DONE) or an error
        sqlite3_finalize(sHandle);
        return result;
    }

    do {
        for (int i = 0; i < columnCount; ++i) {
            // If the column is null now, it may not be null in future rows.
            // Therefore, get the actual type. If the actual type is also null,
            // the column is null for every row.
            auto b    = Buffer();
            auto type = sqlite3_column_type(sHandle, i);

            // every cell starts with its own type (see CellType)
            const uint8 cellType = static_cast<uint8>(type);
            b.Add(BufferView{ &cellType, sizeof(cellType) });

            switch (type) {
            case SQLITE_NULL:
                break;
            case SQLITE_INTEGER: {
                result[i].type = Column::Type::Integer;

                const auto value = sqlite3_column_int64(sHandle, i);
                auto bv          = BufferView{ &value, sizeof(value) };
                b.Add(bv);
            } break;
            case SQLITE_FLOAT: {
                result[i].type = Column::Type::Float;

                const auto value = sqlite3_column_double(sHandle, i);
                auto bv          = BufferView{ &value, sizeof(value) };
                b.Add(bv);
            } break;
            case SQLITE_TEXT: {
                result[i].type = Column::Type::Text;
                b.Add(BufferView{ (const char*) sqlite3_column_text(sHandle, i), (uint32) sqlite3_column_bytes(sHandle, i) });
            } break;
            case SQLITE_BLOB:
                result[i].type = Column::Type::Blob;
                b.Add(BufferView{ sqlite3_column_blob(sHandle, i), (uint32) sqlite3_column_bytes(sHandle, i) });
                break;
            }

            auto values = reinterpret_cast<std::vector<Buffer>*>(result[i].values);
            values->push_back(b);
        }

        status = sqlite3_step(sHandle);
    } while (status == SQLITE_ROW);

    sqlite3_finalize(sHandle);

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