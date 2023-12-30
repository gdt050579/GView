#include <GView.hpp>
#include <sqlite3.h>
#include <vector>

namespace GView::SQLite3
{
Blob::Blob(const uint8* data, int size)
{
    this->data = new uint8_t[size];
    memcpy(this->data, data, size);
    this->size = size;
}

Blob::~Blob()
{
    delete[] data;
}

std::string Column::ValueToString(uint32 index)
{
    if (type == Type::Null) {
        return "NULL";
    }

    // TODO: out of bounds check?
    auto& value = values[index];

    int intValue;
    try {
        if (type == Type::Integer) {
            int64 newValue = std::get<int64>(value);
            return std::to_string(newValue);
        }

        if (type == Type::Float) {
            double floatValue = std::get<double>(value);
            return std::to_string(floatValue);
        }

        if (type == Type::Text) {
            auto strPtr = *std::get<std::string*>(value);
            if (strPtr == "") {
                return "NULL";
            }
            return strPtr;
        }

        if (type == Type::Blob) {
            auto blob = std::get<Blob*>(value);
            if (blob->size == 4) {
                return "NULL";
            }
            std::string returnValue = "";
            std::vector<uint8> blobVector(static_cast<uint8*>(blob->data), static_cast<uint8*>(blob->data) + blob->size);

            for (auto& c : blobVector) {
                std::string data;
                for (int i = 7; i >= 0; --i) {
                    data.push_back(((c & (1 << i)) ? '1' : '0'));
                }
                returnValue.append(data);
            }
            returnValue.append("_BL");

            return returnValue;
        }
    } catch (...) {
        return "NULL";
    }
    if (type == Type::Null) {
        return "NULL";
    }

    return "Should not reach";
}

Statement::Statement(void* db, const char* query)
{
    this->query      = query;
    const char* tail = nullptr;
    auto z           = sqlite3_prepare_v2((sqlite3*) db, query, -1, (sqlite3_stmt**) &handle, &tail);
}

std::vector<Column> Statement::Exec()
{
    auto columnCount = sqlite3_column_count((sqlite3_stmt*) handle);
    std::vector<Column> result;

    for (int i = 0; i < columnCount; ++i) {
        result.push_back({});
        result[i].name = sqlite3_column_name((sqlite3_stmt*) handle, i);

        auto type = sqlite3_column_type((sqlite3_stmt*) handle, i);

        switch (type) {
        case SQLITE_INTEGER:
            result[i].type = Column::Type::Integer;
            break;
        case SQLITE_FLOAT:
            result[i].type = Column::Type::Float;
            break;
        case SQLITE_TEXT:
            result[i].type = Column::Type::Text;
            break;
        case SQLITE_BLOB:
            result[i].type = Column::Type::Blob;
            break;
        case SQLITE_NULL:
            result[i].type = Column::Type::Null;
            break;
        }
    }

    auto status = sqlite3_step((sqlite3_stmt*) handle);
    if (status == SQLITE_DONE) {
        sqlite3_reset((sqlite3_stmt*) handle);
        return {};
    }

    do {
        for (int i = 0; i < columnCount; ++i) {
            // If the column is null now, it may not be null in future rows.
            // Therefore, get the actual type. If the actual type is also null,
            // the column is null for every row.
            auto type = sqlite3_column_type((sqlite3_stmt*) handle, i);
            if (type != SQLITE_NULL) {
                switch (type) {
                case SQLITE_INTEGER:
                    result[i].type = Column::Type::Integer;
                    break;
                case SQLITE_FLOAT:
                    result[i].type = Column::Type::Float;
                    break;
                case SQLITE_TEXT:
                    result[i].type = Column::Type::Text;
                    break;
                case SQLITE_BLOB:
                    result[i].type = Column::Type::Blob;
                    break;
                }
            }

            switch (result[i].type) {
            case Column::Type::Integer: {
                result[i].values.push_back(sqlite3_column_int64((sqlite3_stmt*) handle, i));
                break;
            }
            case Column::Type::Float: {
                result[i].values.push_back(sqlite3_column_double((sqlite3_stmt*) handle, i));
                break;
            }
            case Column::Type::Text: {
                auto ptr  = sqlite3_column_text((sqlite3_stmt*) handle, i);
                auto size = sqlite3_column_bytes((sqlite3_stmt*) handle, i);

                // TODO: Don't forget to free this everywhere
                result[i].values.push_back(new std::string((const char*) ptr, (const char*) ptr + size));
                break;
            }
            case Column::Type::Blob: {
                auto ptr  = sqlite3_column_blob((sqlite3_stmt*) handle, i);
                auto size = sqlite3_column_bytes((sqlite3_stmt*) handle, i);
                if (size == 0) {
                    result[i].values.push_back(new Blob((const uint8*) "dest", 4));
                    break;
                }
                auto theContent = (const uint8*) ptr;

                result[i].values.push_back(new Blob((const uint8*) ptr, size));
                break;
            }
            case Column::Type::Null: {
                result[i].values.push_back(new Blob((const uint8*) "cest12", 4));
                break;
            }
            }
        }

        status = sqlite3_step((sqlite3_stmt*) handle);
    } while (status == SQLITE_ROW);

    for (int i = 0; i < columnCount; ++i) {
        if (result[i].type == Column::Type::Null) {
            result[i].values.clear();
        }
    }

    sqlite3_reset((sqlite3_stmt*) handle);
    return result;
}

DB::DB(const std::u16string_view& filePath)
{
    auto x = sqlite3_open16(filePath.data(), (sqlite3**) &handle);
}

DB& DB::operator=(DB&& other) noexcept
{
    handle       = other.handle;
    other.handle = nullptr;
    return *this;
}

std::vector<std::string> DB::GetTables()
{
    if (!handle) {
        return {};
    }

    auto columns = Exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC;");
    if (columns.size() == 0) {
        return {};
    }
    std::vector<std::string> result;

    for (auto& str : columns[0].values) {
        result.push_back(std::move(*std::get<std::string*>(str)));
    }

    return result;
}

std::vector<std::vector<std::string>> DB::GetTableMetadata(std::string_view tableName)
{
    if (!handle) {
        return {};
    }

    AppCUI::Utils::String query;
    query.SetFormat("SELECT * FROM PRAGMA_TABLE_INFO('%.*s') as TABLE_INFO;", tableName.size(), tableName.data());
    auto value   = query.GetText();
    auto columns = Exec(query.GetText());
    if (columns.empty()) {
        return {};
    }

    std::vector<std::vector<std::string>> results(columns[0].values.size());
    for (auto valueIndex = 0; valueIndex < columns[0].values.size(); valueIndex++) {
        for (auto columnIndex = 1; columnIndex < columns.size(); columnIndex++) {
            results[valueIndex].push_back((std::string) columns[columnIndex].ValueToString(valueIndex));
        }
    }

    return results;
}

AppCUI::int64 DB::GetTableCount(std::string_view tableName)
{
    if (!handle) {
        return -1;
    }

    AppCUI::Utils::String query;
    query.SetFormat("SELECT COUNT(*) FROM %.*s;", tableName.size(), tableName.data());
    auto columns = Exec(query.GetText());
    return std::get<AppCUI::int64>(columns[0].values[0]);
}

std::string DB::GetLibraryVersion()
{
    return sqlite3_libversion();
}

std::vector<std::pair<std::string, std::string>> DB::GetTableInfo()
{
    if (!handle) {
        return {};
    }

    auto columns = Exec("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name ASC");

    if (columns.size() == 0) {
        return {};
    }

    std::vector<std::pair<std::string, std::string>> result;

    for (int i = 0; i < columns[0].values.size(); ++i) {
        auto namePtr = std::get<std::string*>(columns[0].values[i]);
        auto sqlPtr  = std::get<std::string*>(columns[1].values[i]);

        std::string name;
        std::string sql;

        if (!namePtr) {
            name = "NULL";
        } else {
            name = std::move(*namePtr);
        }

        if (!sqlPtr) {
            sql = "NULL";
        } else {
            sql = std::move(*sqlPtr);
        }

        result.push_back(std::make_pair(name, sql));
    }

    return result;
}

std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> DB::GetTableData(std::string_view name)
{
    if (!handle) {
        return {};
    }

    AppCUI::Utils::String query;

    query.SetFormat("SELECT * FROM %.*s;", name.size(), name.data());

    auto columns = Exec(query.GetText());

    std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> result;

    if (columns.empty()) {
        return result;
    }

    for (int i = 0; i < columns.size(); ++i) {
        result.first.push_back(std::move(columns[i].name));
    }

    for (int i = 0; i < columns[0].values.size(); ++i) {
        result.second.emplace_back();

        for (int j = 0; j < columns.size(); ++j) {
            result.second[i].emplace_back(std::move(columns[j].ValueToString(i)));
        }
    }

    return result;
}

std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> DB::GetStatementData(const std::string_view& statement)
{
    auto columns = Exec(statement.data());
    std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> result;

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

std::vector<Column> DB::Exec(const char* query)
{
    Statement stmt(handle, query);
    return stmt.Exec();
}

DB::~DB()
{
    if (handle) {
        sqlite3_close_v2((sqlite3*) handle);
        handle = nullptr;
    }
}
} // namespace GView::SQLite3