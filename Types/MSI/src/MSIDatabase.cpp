#include "msi.hpp"
#include <set>
#include <map>
#include <algorithm>
#include <vector>

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

constexpr int MSICOL_INTEGER = 1 << 15;
constexpr int MSICOL_INT2    = 1 << 10;

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

    if (bufPool.GetLength() == 0)
        return false;

    stringPool.clear();
    uint32 count          = bufPool.GetLength() / 4;
    const uint16* poolPtr = (const uint16*) bufPool.GetData();
    const char* dataPtr   = (const char*) bufData.GetData();
    uint32 dataSize       = (uint32) bufData.GetLength();

    // Standard detection for Long vs Short string references in the pool
    bool highValid      = true;
    uint32 calcSizeHigh = 0;
    for (uint32 i = 1; i < count; i++) {
        uint32 len = poolPtr[i * 2 + 1];
        if (calcSizeHigh + len > dataSize) {
            highValid = false;
            break;
        }
        calcSizeHigh += len;
    }
    if (highValid && calcSizeHigh != dataSize)
        highValid = false;

    bool lowValid      = true;
    uint32 calcSizeLow = 0;
    for (uint32 i = 1; i < count; i++) {
        uint32 len = poolPtr[i * 2];
        if (calcSizeLow + len > dataSize) {
            lowValid = false;
            break;
        }
        calcSizeLow += len;
    }
    if (lowValid && calcSizeLow != dataSize)
        lowValid = false;

    bool useHighWord = true;
    if (lowValid && !highValid)
        useHighWord = false;

    stringPool.reserve(count);
    uint32 currentOffset = 0;

    for (uint32 i = 0; i < count; i++) {
        if (i == 0) {
            stringPool.push_back("");
            continue;
        }
        uint16 len = useHighWord ? poolPtr[i * 2 + 1] : poolPtr[i * 2];

        if (currentOffset + len > dataSize) {
            stringPool.push_back("<Error>");
            break;
        }

        std::string temp(dataPtr + currentOffset, len);
        while (!temp.empty() && temp.back() == '\0')
            temp.pop_back();
        stringPool.push_back(temp);
        currentOffset += len;
    }
    return stringPool.size() > 0;
}

bool MSIFile::LoadDatabase()
{
    if (stringPool.empty())
        return false;

    // 1. Detect String Index Size (2-byte vs 3-byte)
    // Heuristic: Check if !_Columns stream size is divisible by 8 (2-byte) or 10 (3-byte)
    this->stringBytes      = 2;
    DirEntry* columnsEntry = nullptr;
    for (auto* e : linearDirList) {
        if (e->decodedName == u"!_Columns") {
            columnsEntry = e;
            break;
        }
    }

    if (columnsEntry && columnsEntry->data.streamSize > 0) {
        uint64 sz = columnsEntry->data.streamSize;
        if (sz % 10 == 0 && sz % 8 != 0)
            this->stringBytes = 3;
        else if (sz % 8 == 0 && sz % 10 != 0)
            this->stringBytes = 2;
        else
            this->stringBytes = (stringPool.size() > 65536) ? 3 : 2;
    }

    // 2. Parse Schema from !_Columns
    // Note: Parsing uses the Column-Oriented logic implemented in ReadTableData equivalent
    tableDefs.clear();
    if (columnsEntry) {
        bool isMini = columnsEntry->data.streamSize < header.miniStreamCutoffSize;
        Buffer buf  = GetStream(columnsEntry->data.startingSectorLocation, columnsEntry->data.streamSize, isMini);

        if (buf.GetLength() > 0) {
            uint32 colRowSize = (this->stringBytes * 2) + 4;
            uint32 numRows    = buf.GetLength() / colRowSize;
            const uint8* ptr  = buf.GetData();

            // Calculate Start Offsets for !_Columns (Column-Oriented)
            // Layout: [Table Name Strings...] [Col Numbers...] [Col Name Strings...] [Types...]
            uint32 startTable = 0;
            uint32 startNum   = startTable + (numRows * stringBytes);
            uint32 startName  = startNum + (numRows * 2);
            uint32 startType  = startName + (numRows * stringBytes);

            for (uint32 i = 0; i < numRows; i++) {
                // Table Name
                uint32 offsetTable = startTable + (i * stringBytes);
                uint32 tableIdx =
                      (stringBytes == 2) ? *(uint16*) (ptr + offsetTable) : (ptr[offsetTable] | (ptr[offsetTable + 1] << 8) | (ptr[offsetTable + 2] << 16));

                // Column Number
                uint32 offsetNum = startNum + (i * 2);
                uint16 colNum    = *(uint16*) (ptr + offsetNum);

                // Column Name
                uint32 offsetName = startName + (i * stringBytes);
                uint32 nameIdx =
                      (stringBytes == 2) ? *(uint16*) (ptr + offsetName) : (ptr[offsetName] | (ptr[offsetName + 1] << 8) | (ptr[offsetName + 2] << 16));

                // Type
                uint32 offsetType = startType + (i * 2);
                uint16 type       = *(uint16*) (ptr + offsetType);

                std::string tableNameStr = GetString(tableIdx);
                std::string colNameStr   = GetString(tableIdx + offsetName);

                if (tableNameStr.empty() || tableNameStr == "<Error>")
                    continue;
                if (colNum == 0 || colNum > 255)
                    continue;

                MsiTableDef& def = tableDefs[tableNameStr];
                def.name         = tableNameStr;
                MsiColumnInfo col{ colNameStr, (int) type, 0, 0 };

                if (def.columns.size() < (size_t) colNum)
                    def.columns.resize(colNum);
                def.columns[colNum - 1] = col;
            }
        }
    }

    // 3. Override Critical Tables (Fail-Safe Schema)
    // We enforce the correct schema for File, Directory, and Component to prevent parsing errors
    // from custom flags or corrupted types in the MSI metadata.

    MsiTableDef fileDef;
    fileDef.name      = "File";
    fileDef.columns   = { { "File", 0, 0, 0 },    { "Component_", 0, 0, 0 }, { "FileName", 0, 0, 0 },        { "FileSize", 0x8004, 0, 0 },
                          { "Version", 0, 0, 0 }, { "Language", 0, 0, 0 },   { "Attributes", 0x8002, 0, 0 }, { "Sequence", 0x8004, 0, 0 } };
    tableDefs["File"] = fileDef;

    MsiTableDef dirDef;
    dirDef.name            = "Directory";
    dirDef.columns         = { { "Directory", 0, 0, 0 }, { "Directory_Parent", 0, 0, 0 }, { "DefaultDir", 0, 0, 0 } };
    tableDefs["Directory"] = dirDef;

    MsiTableDef compDef;
    compDef.name           = "Component";
    compDef.columns        = { { "Component", 0, 0, 0 },       { "ComponentId", 0, 0, 0 }, { "Directory_", 0, 0, 0 },
                               { "Attributes", 0x8002, 0, 0 }, { "Condition", 0, 0, 0 },   { "KeyPath", 0, 0, 0 } };
    tableDefs["Component"] = compDef;

    // 4. Calculate Column Sizes
    // Note: In Column-Oriented storage, we only need the size to calculate the total block size.
    for (auto& [name, def] : tableDefs) {
        uint32 rowWidth = 0;
        for (auto& col : def.columns) {
            bool isInt = (col.type & MSICOL_INTEGER) != 0;
            // Fixup logic for missing flags based on known bitmasks
            if (!isInt) {
                if ((col.type & 0xF) == 4 && col.type < 0x2000) {
                    isInt    = true;
                    col.size = 4;
                    col.type |= MSICOL_INTEGER;
                } else if ((col.type & 0xF) == 2 && col.type < 0x2000) {
                    isInt    = true;
                    col.size = 2;
                    col.type |= (MSICOL_INTEGER | MSICOL_INT2);
                }
            }

            if (isInt)
                col.size = ((col.type & 0xF) > 0) ? (col.type & 0xF) : ((col.type & MSICOL_INT2) ? 2 : 4);
            else
                col.size = stringBytes;

            rowWidth += col.size;
        }
        def.rowSize = rowWidth;
    }

    // 5. Populate Files Panel
    if (tableDefs.count("File")) {
        msiFiles.clear();

        // Load Directories
        std::map<std::string, std::pair<std::string, std::string>> dirStructure;
        auto dirRows = ReadTableData("Directory");
        for (const auto& row : dirRows) {
            if (row.size() < 3)
                continue;
            std::string key    = std::string(row[0].GetText());
            std::string parent = std::string(row[1].GetText());
            std::string defDir = ExtractLongFileName(std::string(row[2].GetText()));
            if (!key.empty())
                dirStructure[key] = { parent, defDir };
        }

        // Load Components
        std::map<std::string, std::string> compToDir;
        auto compRows = ReadTableData("Component");
        for (const auto& row : compRows) {
            if (row.size() < 3)
                continue;
            std::string key = std::string(row[0].GetText());
            std::string dir = std::string(row[2].GetText());
            if (!key.empty())
                compToDir[key] = dir;
        }

        // Path Resolution Helper
        std::map<std::string, std::string> pathCache;
        std::function<std::string(std::string)> resolvePath = [&](std::string key) -> std::string {
            if (pathCache.count(key))
                return pathCache[key];
            if (dirStructure.find(key) == dirStructure.end())
                return key;
            auto& info = dirStructure[key];
            if (info.first.empty() || info.first == key)
                return pathCache[key] = info.second;
            std::string p         = resolvePath(info.first);
            std::string f         = info.second;
            return pathCache[key] = (p.back() == '\\') ? p + f : p + "\\" + f;
        };

        // Load Files
        auto fileRows = ReadTableData("File");
        msiFiles.reserve(fileRows.size());
        for (const auto& row : fileRows) {
            if (row.size() < 5)
                continue;
            MsiFileEntry entry;
            entry.Name      = ExtractLongFileName(std::string(row[2].GetText()));
            entry.Component = std::string(row[1].GetText());
            try {
                entry.Size = std::stoul(std::string(row[3].GetText()));
            } catch (...) {
                entry.Size = 0;
            }
            entry.Version = std::string(row[4].GetText());

            if (compToDir.count(entry.Component))
                entry.Directory = resolvePath(compToDir[entry.Component]);
            else
                entry.Directory = "<Orphaned>";
            msiFiles.push_back(entry);
        }
    }
    return true;
}

bool MSIFile::LoadTables()
{
    tables.clear();
    for (const auto& [name, def] : tableDefs) {
        uint32 count              = 0;
        std::u16string targetName = u"!" + std::u16string(name.begin(), name.end());
        DirEntry* stream          = nullptr;
        for (auto* e : linearDirList) {
            if (e->decodedName == targetName) {
                stream = e;
                break;
            }
        }

        if (stream && def.rowSize > 0)
            count = (uint32) (stream->data.streamSize / def.rowSize);
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
    DirEntry* tableEntry      = nullptr;
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
    if (def.rowSize == 0)
        return results;

    // --- COLUMN-ORIENTED READ LOGIC ---
    uint32 numRows   = buf.GetLength() / def.rowSize;
    const uint8* ptr = buf.GetData();

    // 1. Pre-calculate Start Offsets for each Column Block
    std::vector<uint32> colStartOffsets;
    uint32 currentOffset = 0;
    for (const auto& col : def.columns) {
        colStartOffsets.push_back(currentOffset);
        currentOffset += (col.size * numRows);
    }

    // 2. Read rows by jumping between column blocks
    for (uint32 i = 0; i < numRows; i++) {
        std::vector<AppCUI::Utils::String> row;

        for (size_t c = 0; c < def.columns.size(); c++) {
            const auto& col = def.columns[c];
            // Offset = Start of Block + (Row Index * Item Size)
            uint32 valOffset = colStartOffsets[c] + (i * col.size);

            if (valOffset + col.size > buf.GetLength()) {
                row.emplace_back("<Corrupt>");
                continue;
            }

            if (col.type & MSICOL_INTEGER) {
                uint32 val = 0;
                if (col.size == 2)
                    val = *(uint16*) (ptr + valOffset);
                else
                    val = *(uint32*) (ptr + valOffset);

                // Mask high bit for large integers (MSI internal flag)
                if (col.size == 4)
                    val &= 0x7FFFFFFF;

                row.emplace_back(std::to_string(val).c_str());
            } else {
                uint32 strIdx = 0;
                if (stringBytes == 2)
                    strIdx = *(uint16*) (ptr + valOffset);
                else
                    strIdx = ptr[valOffset] | (ptr[valOffset + 1] << 8) | (ptr[valOffset + 2] << 16);
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
    if (it != tableDefs.end())
        return &it->second;
    return nullptr;
}