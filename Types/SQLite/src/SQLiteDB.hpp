// C++ wrapper for SQLite's basic API functions
#pragma once

#include "GView.hpp"
#include "sqlite3.h"

#include <vector>

using namespace AppCUI::Utils;

namespace GView::Type::SQLite
{
struct Blob
{
    const uint8* data;
    int32 size;
};
struct Column
{
    enum class Type
    {
        Integer = SQLITE_INTEGER,
        Float   = SQLITE_FLOAT,
        Text    = SQLITE_TEXT,
        Blob    = SQLITE_BLOB,
        Null    = SQLITE_NULL
    };

    Type type;
    std::string name;
    std::vector<std::variant<AppCUI::int64, double, std::string*, Blob*, void*>> values;

    AppCUI::Utils::String ValueToString(uint32 index)
    {
        AppCUI::Utils::String str;

        if (type == Type::Null)
        {
            str = "NULL";
            return str;
        }

        // TODO: out of bounds check?
        auto& value = values[index];

        switch (type)
        {
        case Type::Integer:
            str.SetFormat("%lld", std::get<int64>(value));
            break;
        case Type::Float:
            str.SetFormat("%f", std::get<double>(value));
            break;
        case Type::Text:
            str.Set(*std::get<std::string*>(value));
            break;
        case Type::Blob:
        {
            auto blob = std::get<Blob*>(value);
            for (int32 i = 0; i < blob->size; ++i)
            {
                str.AddFormat("%02x", blob->data[i]);
            }
            break;
        }
        case Type::Null:
            str = "NULL";
            break;
        }

        return str;
    }

    ~Column()
    {
        for (auto& value : values)
        {
            switch (type)
            {
            case Type::Text:
                delete std::get<std::string*>(value);
                break;
            case Type::Blob:
                delete std::get<Blob*>(value);
                break;
            }
        }
    }
};

class Statement
{
    sqlite3_stmt* handle;
    bool shouldReset;

  public:
    const char* query;

    Statement(sqlite3* db, const char* query)
    {
        this->query      = query;
        const char* tail = nullptr;

        // -1 = read until the null terminator
        auto z = sqlite3_prepare_v2(db, query, -1, &handle, &tail);

        shouldReset = false;
    }

    std::vector<Column> Exec()
    {
        if (shouldReset)
        {
            // TODO: Move this logic at the bottom and get rid of this ugly edge case
            sqlite3_reset(handle);
        }
        else
        {
            shouldReset = true;
        }

        auto status = sqlite3_step(handle);

        if (status == SQLITE_DONE)
        {
            return {};
        }

        auto columnCount = sqlite3_column_count(handle);

        std::vector<Column> result;

        for (int i = 0; i < columnCount; ++i)
        {
            result.push_back({});
            result[i].name = sqlite3_column_name(handle, i);

            auto type = sqlite3_column_type(handle, i);

            switch (type)
            {
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

        do
        {
            for (int i = 0; i < columnCount; ++i)
            {
                // If the column is null now, it may not be null in future rows.
                // Therefore, get the actual type. If the actual type is also null,
                // the column is null for every row.
                if (result[i].type == Column::Type::Null)
                {
                    auto type = sqlite3_column_type(handle, i);

                    switch (type)
                    {
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
                        break;
                    }
                }

                switch (result[i].type)
                {
                case Column::Type::Integer:
                {
                    result[i].values.push_back(sqlite3_column_int64(handle, i));
                    break;
                }
                case Column::Type::Float:
                {
                    result[i].values.push_back(sqlite3_column_double(handle, i));
                    break;
                }
                case Column::Type::Text:
                {
                    auto ptr  = sqlite3_column_text(handle, i);
                    auto size = sqlite3_column_bytes(handle, i);

                    // TODO: Don't forget to free this everywhere
                    result[i].values.push_back(new std::string((const char*) ptr, size));
                    break;
                }
                case Column::Type::Blob:
                {
                    auto ptr  = sqlite3_column_blob(handle, i);
                    auto size = sqlite3_column_bytes(handle, i);

                    result[i].values.push_back(new Blob{(const uint8*) ptr, size});
                    break;
                }
                case Column::Type::Null:
                {
                    // When retrieving the name and SQL query for a specific table,
                    // the columns are expected to have the string type. Therefore,
                    // return nullptr of type string
                    result[i].values.push_back((std::string*) nullptr);
                    break;
                }
                }
            }

            status = sqlite3_step(handle);
        } while (status == SQLITE_ROW);

        for (int i = 0; i < columnCount; ++i)
        {
            // No need to store a list full of nulls
            if (result[i].type == Column::Type::Null)
            {
                result[i].values.clear();
            }
        }

        return result;
    }
};

class DB
{
    sqlite3* handle = nullptr;

  public:
    DB()
    {
    }

    DB(BufferView buffer)
    {
        auto path = AppCUI::OS::GetCurrentApplicationPath();
        path.remove_filename();
        // TODO: This is hardcoded, the DLL needs to be compiled manually
        // Do it better
        path /= "Types";
        path /= "memvfs.dll";

        // Open the database from an in-memory buffer by using memvfs.
        // https://www.sqlite.org/src/file/ext/misc/memvfs.c
        auto x = sqlite3_open(":memory:", &handle);
        auto y = sqlite3_enable_load_extension(handle, 1);
        auto z = sqlite3_load_extension(handle, path.string().c_str(), nullptr, nullptr);
        auto t = sqlite3_close(handle);

        auto uri = sqlite3_mprintf("file:mem?ptr=0x%p&sz=%lld", buffer.GetData(), (long long) buffer.GetLength());
        auto w   = sqlite3_open_v2(uri, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, "memvfs");
        sqlite3_free(uri);
    }

    DB& operator=(DB&& other) noexcept
    {
        handle       = other.handle;
        other.handle = nullptr;
    }

    std::vector<std::string> GetTables()
    {
        if (!handle)
        {
            return {};
        }

        auto columns = Exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC;");
        std::vector<std::string> result;

        for (auto str : columns[0].values)
        {
            result.push_back(std::move(*std::get<std::string*>(str)));
        }

        return result;
    }

    std::vector<std::pair<std::string, std::string>> GetTableInfo()
    {
        if (!handle)
        {
            return {};
        }

        auto columns = Exec("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name ASC;");
        std::vector<std::pair<std::string, std::string>> result;

        for (int i = 0; i < columns[0].values.size(); ++i)
        {
            auto namePtr = std::get<std::string*>(columns[0].values[i]);
            auto sqlPtr  = std::get<std::string*>(columns[1].values[i]);

            std::string name;
            std::string sql;

            if (!namePtr)
            {
                name = "NULL";
            }
            else
            {
                name = std::move(*namePtr);
            }

            if (!sqlPtr)
            {
                sql = "NULL";
            }
            else
            {
                sql = std::move(*sqlPtr);
            }

            result.push_back(std::make_pair(name, sql));
        }

        return result;
    }

    std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> GetTableData(std::string_view name)
    {
        if (!handle)
        {
            return {};
        }

        AppCUI::Utils::String query;

        query.SetFormat("SELECT * FROM %.*s;", name.size(), name.data());

        auto columns = Exec(query.GetText());

        std::pair<std::vector<std::string>, std::vector<std::vector<std::string>>> result;

        if (columns.empty())
        {
            return result;
        }

        for (int i = 0; i < columns.size(); ++i)
        {
            result.first.push_back(std::move(columns[i].name));
        }

        for (int i = 0; i < columns[0].values.size(); ++i)
        {
            result.second.emplace_back();

            for (int j = 0; j < columns.size(); ++j)
            {
                result.second[i].emplace_back(columns[j].ValueToString(i));
            }
        }

        return result;
    }

    std::vector<Column> Exec(const char* query)
    {
        Statement stmt(handle, query);
        return stmt.Exec();
    }

    ~DB()
    {
        if (handle)
        {
            sqlite3_close_v2(handle);
            handle = nullptr;
        }
    }
};
} // namespace GView::Type::SQLite