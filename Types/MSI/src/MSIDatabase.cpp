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

bool MSIFile::LoadStringPool()
{
    DirEntry* entryPool = nullptr;
    DirEntry* entryData = nullptr;

    // Search using the pre-decoded names populated in LoadDirectory
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

    // Parse String Pool
    // Format: Array of [Length(u16), RefCount(u16)]
    stringPool.clear();
    stringPool.push_back(""); // Index 0 is null

    uint32 count          = bufPool.GetLength() / 4;
    const uint16* poolPtr = (const uint16*) bufPool.GetData();
    const char* dataPtr   = (const char*) bufData.GetData();
    uint32 dataOffset     = 0;

    for (uint32 i = 0; i < count; i++) {
        uint16 len = poolPtr[i * 2];
        if (len == 0) {
            stringPool.push_back("");
            continue;
        }
        if (dataOffset + len > bufData.GetLength())
            break;

        // Use UTF-8 for internal storage if possible, or CP1252.
        // For now assuming 1-byte charsets.
        stringPool.emplace_back(dataPtr + dataOffset, len);
        dataOffset += len;
    }
    return true;
}

bool MSIFile::LoadTables()
{
    tables.clear();
    for (auto* e : linearDirList) {
        if (e->decodedName.length() > 1 && e->decodedName[0] == u'!') {
            std::u16string tableOnly = e->decodedName.substr(1);
            AppCUI::Utils::String utf8Name;
            utf8Name.Set(tableOnly);
            std::string nameStr = utf8Name.GetText();

            if (nameStr == "_StringPool" || nameStr == "_StringData" || nameStr == "_Columns")
                continue;
            tables.push_back({ nameStr, "User Table", 0 });
        }
    }
    return true;
}

bool MSIFile::LoadDatabase()
{
    this->stringBytes = (stringPool.size() > 65536) ? 3 : 2;

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

    // Parse _Columns manually
    uint32 colRowSize = stringBytes + 2 + stringBytes + 2;
    uint32 numRows    = buf.GetLength() / colRowSize;
    const uint8* ptr  = buf.GetData();

    for (uint32 i = 0; i < numRows; i++) {
        uint32 offset = i * colRowSize;

        // Read Table Name Index
        uint32 tableIdx = *(uint16*) (ptr + offset);
        if (stringBytes == 3)
            tableIdx |= ((uint32) * (ptr + offset + 2) << 16);

        // Read Column Number
        uint32 numValOffset = offset + stringBytes;
        uint16 number       = *(uint16*) (ptr + numValOffset);

        // Read Column Name Index
        uint32 nameOffset = numValOffset + 2;
        uint32 nameIdx    = *(uint16*) (ptr + nameOffset);
        if (stringBytes == 3)
            nameIdx |= ((uint32) * (ptr + nameOffset + 2) << 16);

        // Read Type
        uint32 typeOffset = nameOffset + stringBytes;
        uint16 type       = *(uint16*) (ptr + typeOffset);

        std::string tableNameStr = GetString(tableIdx);
        std::string colNameStr   = GetString(nameIdx);

        MsiTableDef& def = tableDefs[tableNameStr];
        def.name         = tableNameStr;
        MsiColumnInfo col{ colNameStr, type, 0, 0 };

        if (def.columns.size() < (size_t) number)
            def.columns.resize(number);
        def.columns[number - 1] = col;
    }

    // Calculate Offsets
    for (auto& [name, def] : tableDefs) {
        uint32 currentOffset = 0;
        for (auto& col : def.columns) {
            col.offset = currentOffset;
            if (col.type & MSICOL_INTEGER) {
                col.size = (col.type & 0x400) ? 2 : 4;
            } else {
                col.size = stringBytes;
            }
            currentOffset += col.size;
        }
        def.rowSize = currentOffset;
    }

    // Load File Data
    auto fileData = ReadTableData("File");
    auto compData = ReadTableData("Component");

    // Map Component -> Directory
    std::map<std::string, std::string> compToDir;
    int compKeyIdx = -1, compDirIdx = -1;

    if (tableDefs.count("Component")) {
        const auto& cols = tableDefs["Component"].columns;
        for (size_t i = 0; i < cols.size(); i++) {
            if (cols[i].name == "Component")
                compKeyIdx = i;
            if (cols[i].name == "Directory_")
                compDirIdx = i;
        }
    }

    if (compKeyIdx >= 0 && compDirIdx >= 0) {
        for (const auto& row : compData) {
            if (row.size() > (size_t) compDirIdx)
                compToDir[row[compKeyIdx].GetText()] = row[compDirIdx].GetText();
        }
    }

    msiFiles.clear();
    if (tableDefs.count("File")) {
        const auto& cols = tableDefs["File"].columns;
        int nameIdx = -1, sizeIdx = -1, verIdx = -1, compRefIdx = -1;

        for (size_t i = 0; i < cols.size(); i++) {
            if (cols[i].name == "FileName")
                nameIdx = i;
            if (cols[i].name == "FileSize")
                sizeIdx = i;
            if (cols[i].name == "Version")
                verIdx = i;
            if (cols[i].name == "Component_")
                compRefIdx = i;
        }

        if (nameIdx >= 0 && sizeIdx >= 0) {
            for (const auto& row : fileData) {
                MsiFileEntry f;
                f.Name = ExtractLongFileName(row[nameIdx].GetText());

                try {
                    f.Size = std::stoul(row[sizeIdx].GetText());
                } catch (...) {
                    f.Size = 0;
                }

                if (verIdx >= 0)
                    f.Version = row[verIdx].GetText();

                if (compRefIdx >= 0) {
                    f.Component = row[compRefIdx].GetText();
                    if (compToDir.count(f.Component))
                        f.Directory = compToDir[f.Component];
                }
                msiFiles.push_back(f);
            }
        }
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
