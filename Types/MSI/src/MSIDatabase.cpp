#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

constexpr int MSICOL_INTEGER = 1 << 15;

std::string MSIFile::GetString(uint32 index)
{
    if (index >= stringPool.size())
        return "";
    return stringPool[index];
}

std::string MSIFile::ExtractLongFileName(const std::string& rawName)
{
    auto pos = rawName.find('|');
    return (pos != std::string::npos && pos + 1 < rawName.size()) ? rawName.substr(pos + 1) : rawName;
}

//
bool MSIFile::LoadStringPool()
{
    DirEntry* entryPool = nullptr;
    DirEntry* entryData = nullptr;

    for (auto* e : linearDirList) {
        if (e->decodedName == u"!_StringPool")
            entryPool = e;
        else if (e->decodedName == u"!_StringData")
            entryData = e;
    }

    if (!entryPool || !entryData)
        return false;

    bool isMiniPool = entryPool->data.streamSize < header.miniStreamCutoffSize;
    Buffer bufPool  = GetStream(entryPool->data.startingSectorLocation, entryPool->data.streamSize, isMiniPool);

    bool isMiniData = entryData->data.streamSize < header.miniStreamCutoffSize;
    Buffer bufData  = GetStream(entryData->data.startingSectorLocation, entryData->data.streamSize, isMiniData);

    if (bufPool.GetLength() == 0 || bufData.GetLength() == 0)
        return false;

    stringPool.clear();

    uint32 count          = bufPool.GetLength() / 4;
    const uint16* poolPtr = (const uint16*) bufPool.GetData();
    const char* dataPtr   = (const char*) bufData.GetData();
    uint32 dataOffset     = 0;

    // --- HEURISTIC: Detect Length Position ---
    // MSI String Entry = [Val1 (16-bit)] [Val2 (16-bit)]
    // One is Length, one is RefCount. Standard is [Ref][Len], but can swap.
    // Entry 1 (Index 1) is usually "Name" (4 bytes) followed by "Table" (5 bytes).

    bool lengthIsHighWord = true; // Default to Standard

    if (count > 1) {
        // Inspect Entry 1 (Index 1)
        uint16 v1 = poolPtr[2]; // Low Word
        uint16 v2 = poolPtr[3]; // High Word

        // Sanity Check: If data starts with "Name" (common MSI header)
        if (bufData.GetLength() >= 4 && strncmp(dataPtr, "Name", 4) == 0) {
            // If Low is 4 and High is NOT 4, Low is Length
            if (v1 == 4 && v2 != 4) {
                lengthIsHighWord = false;
            }
            // If High is 4 and Low is NOT 4, High is Length (Standard)
            else if (v2 == 4 && v1 != 4) {
                lengthIsHighWord = true;
            }
        }
    }

    for (uint32 i = 0; i < count; i++) {
        // Entry 0 is Codepage (Length always 0)
        if (i == 0) {
            stringPool.push_back("");
            continue;
        }

        // Extract Length based on heuristic
        // We also mask with 0x7FFF just in case there is a high-bit flag
        uint16 len = lengthIsHighWord ? poolPtr[i * 2 + 1] : poolPtr[i * 2];

        // Safety clamp
        if (dataOffset + len > bufData.GetLength()) {
            stringPool.push_back("<Error>");
            break;
        }

        // Extract String
        // NOTE: MSI strings in _StringData are NOT null-terminated. They are packed.
        stringPool.emplace_back(dataPtr + dataOffset, len);
        dataOffset += len;
    }

    return stringPool.size() > 0;
}

bool MSIFile::LoadDatabase()
{
    // If StringPool failed, we can't load the database
    if (stringPool.empty())
        return false;

    // 1. Determine String Index Size (Standard is 2 bytes)
    // If pool is huge (>65536), it might be 3 bytes, but usually 2 for tables.
    this->stringBytes = 2;

    // Find !_Columns table
    DirEntry* columnsEntry = nullptr;
    for (auto* e : linearDirList) {
        if (e->decodedName == u"!_Columns") {
            columnsEntry = e;
            break;
        }
    }
    if (!columnsEntry)
        return false;

    bool isMini = columnsEntry->data.streamSize < header.miniStreamCutoffSize;
    Buffer buf  = GetStream(columnsEntry->data.startingSectorLocation, columnsEntry->data.streamSize, isMini);
    if (buf.GetLength() == 0)
        return false;

    // Parse !_Columns
    // Structure: Table(s2), Number(i2), Name(s2), Type(i2) => 8 Bytes
    uint32 colRowSize = 8;
    uint32 numRows    = buf.GetLength() / colRowSize;
    const uint8* ptr  = buf.GetData();

    tableDefs.clear();

    for (uint32 i = 0; i < numRows; i++) {
        uint32 offset = i * colRowSize;

        // Read Indices (Always 16-bit for _Columns)
        uint16 tableIdx = *(uint16*) (ptr + offset);
        uint16 colNum   = *(uint16*) (ptr + offset + 2);
        uint16 nameIdx  = *(uint16*) (ptr + offset + 4);
        uint16 type     = *(uint16*) (ptr + offset + 6);

        std::string tableNameStr = GetString(tableIdx);
        std::string colNameStr   = GetString(nameIdx);

        // Skip invalid entries
        if (tableNameStr.empty() || tableNameStr == "<Error>")
            continue;
        if (colNum == 0 || colNum > 64)
            continue; // Sanity check

        MsiTableDef& def = tableDefs[tableNameStr];
        def.name         = tableNameStr;

        MsiColumnInfo col{ colNameStr, (int) type, 0, 0 };

        if (def.columns.size() < (size_t) colNum)
            def.columns.resize(colNum);
        def.columns[colNum - 1] = col;
    }

    // Calculate Row Sizes & Offsets
    for (auto& [name, def] : tableDefs) {
        uint32 currentOffset = 0;
        for (auto& col : def.columns) {
            col.offset = currentOffset;

            // MSI Column Types:
            // 0x8000 (Integer)
            // 0x0400 (2-byte Integer) -> else 4-byte
            if (col.type & (1 << 15)) {
                col.size = (col.type & 0x400) ? 2 : 4;
            } else {
                col.size = stringBytes; // String Index (2 bytes)
            }
            currentOffset += col.size;
        }
        def.rowSize = currentOffset;
    }

    // Populate File List for the UI (Optional)
    if (tableDefs.count("File")) {
        // Clear old data
        msiFiles.clear();

        auto fileData = ReadTableData("File");
        // Re-implement your File/Component mapping logic here if needed
        // to populate 'msiFiles' vector for the Tree View
    }

    return true;
}

bool MSIFile::LoadTables()
{
    tables.clear();

    // Iterate over the valid tables found in !_Columns
    for (const auto& [name, def] : tableDefs) {
        uint32 count = 0;

        // Find the stream for this table (e.g. "!File")
        std::u16string targetName = u"!" + std::u16string(name.begin(), name.end());

        for (auto* e : linearDirList) {
            if (e->decodedName == targetName) {
                if (def.rowSize > 0) {
                    count = (uint32) (e->data.streamSize / def.rowSize);
                }
                break;
            }
        }
        tables.push_back({ name, "Table", count });
    }
    return true;
}

std::vector<std::vector<AppCUI::Utils::String>> MSIFile::ReadTableData(const std::string& tableName)
{
    std::vector<std::vector<AppCUI::Utils::String>> results;
    if (tableDefs.find(tableName) == tableDefs.end())
        return results;

    const auto& def           = tableDefs[tableName];
    std::u16string targetName = u"!" + std::u16string(tableName.begin(), tableName.end());

    DirEntry* tableEntry = nullptr;
    for (auto* e : linearDirList) {
        if (e->decodedName == targetName) {
            tableEntry = e;
            break;
        }
    }
    if (!tableEntry)
        return results;

    bool isMini = tableEntry->data.streamSize < header.miniStreamCutoffSize;
    Buffer buf  = GetStream(tableEntry->data.startingSectorLocation, tableEntry->data.streamSize, isMini);

    uint32 numRows   = buf.GetLength() / def.rowSize;
    const uint8* ptr = buf.GetData();

    for (uint32 i = 0; i < numRows; i++) {
        std::vector<AppCUI::Utils::String> row;
        uint32 rowStart = i * def.rowSize;

        for (const auto& col : def.columns) {
            uint32 valOffset = rowStart + col.offset;

            if (col.type & MSICOL_INTEGER) {
                uint32 val = 0;
                if (col.size == 2)
                    val = *(uint16*) (ptr + valOffset);
                else
                    val = *(uint32*) (ptr + valOffset);
                row.emplace_back(std::to_string(val).c_str());
            } else {
                uint32 strIdx = *(uint16*) (ptr + valOffset);
                if (stringBytes == 3)
                    strIdx |= ((uint32) * (ptr + valOffset + 2) << 16);
                row.emplace_back(GetString(strIdx).c_str());
            }
        }
        results.push_back(row);
    }
    return results;
}

const MsiTableDef* MSIFile::GetTableDefinition(const std::string& tableName) const
{
    auto it = tableDefs.find(tableName);
    if (it != tableDefs.end()) {
        return &it->second;
    }
    return nullptr;
}
