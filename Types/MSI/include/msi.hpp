#pragma once

#include "GView.hpp"
#include <vector>
#include <string>
#include <map>
#include <functional>

namespace GView::Type::MSI
{
// Constants
constexpr uint64 OLE_SIGNATURE = 0xE11AB1A1E011CFD0;
constexpr uint32 FREESECT      = 0xFFFFFFFF;
constexpr uint32 ENDOFCHAIN    = 0xFFFFFFFE;
constexpr uint32 NOSTREAM      = 0xFFFFFFFF;

#pragma pack(push, 1)
struct OLEHeader {
    uint64 signature;
    uint8 clsid[16];
    uint16 minorVersion;
    uint16 majorVersion;
    uint16 byteOrder;
    uint16 sectorShift;
    uint16 miniSectorShift;
    uint8 reserved[6];
    uint32 numDirSectors;
    uint32 numFatSectors;
    uint32 firstDirSector;
    uint32 transactionSignature;
    uint32 miniStreamCutoffSize;
    uint32 firstMiniFatSector;
    uint32 numMiniFatSectors;
    uint32 firstDifatSector;
    uint32 numDifatSectors;
    uint32 difat[109];
};

struct DirectoryEntryData {
    char16 name[32];
    uint16 nameLength;
    uint8 objectType; // 0=Unknown 1=Storage, 2=Stream, 5=Root
    uint8 colorFlag;
    uint32 leftSiblingId;
    uint32 rightSiblingId;
    uint32 childId;
    uint8 clsid[16];
    uint32 stateBits;
    uint64 creationTime;
    uint64 modifiedTime;
    uint32 startingSectorLocation;
    uint64 streamSize;
};
#pragma pack(pop)

struct DirEntry {
    uint32 id;
    DirectoryEntryData data;
    std::vector<DirEntry> children;
    std::u16string name;        // Raw name from Entry (potentially encoded)
    std::u16string decodedName; // Decoded MSI name for display/lookup
};

// Database Structures
struct MsiFileEntry {
    std::string Name;
    std::string Directory;
    std::string Component;
    uint32 Size;
    std::string Version;
};

struct MsiColumnInfo {
    std::string name;
    int type;
    int offset;
    int size;
};

struct MsiTableDef {
    std::string name;
    std::vector<MsiColumnInfo> columns;
    uint32 rowSize;
};

struct MSITableInfo {
    std::string name;
    std::string type;
    uint32 rowCount;
};

class MSIFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    struct Metadata {
        std::string title;
        std::string subject;
        std::string author;
        std::string keywords;
        std::string comments;
        std::string revisionNumber;
        std::string creatingApp;

        uint16_t codepage = 0;
        std::string templateStr;
        std::string lastSavedBy;

        std::time_t createTime      = 0;
        std::time_t lastSaveTime    = 0;
        std::time_t lastPrintedTime = 0;

        uint32_t pageCount      = 0;
        uint32_t wordCount      = 0;
        uint32_t characterCount = 0;
        uint32_t security       = 0;

        uint64_t totalSize = 0;
    } msiMeta;

    uint32 sectorSize;
    uint32 miniSectorSize;

  private:
    OLEHeader header;
    std::vector<uint32> FAT;
    std::vector<uint32> miniFAT;
    AppCUI::Utils::Buffer miniStream;

    DirEntry rootDir;
    std::vector<DirEntry*> linearDirList;

    // Database
    std::vector<std::string> stringPool;
    std::vector<MSITableInfo> tables;
    std::vector<MsiFileEntry> msiFiles;
    std::map<std::string, MsiTableDef> tableDefs;
    uint32 stringBytes = 2;

    // Iteration State
    DirEntry* currentIterFolder = nullptr;
    size_t currentIterIndex     = 0;

    // Internal methods
    bool LoadFAT();
    bool LoadMiniFAT();
    bool LoadDirectory();
    void BuildTree(DirEntry& parent);
    AppCUI::Utils::Buffer GetStream(uint32 startSector, uint64 size, bool isMini);
    void ParseSummaryInformation();

    // Database Methods
    static std::u16string MsiDecompressName(std::u16string_view encoded);
    static std::string ExtractLongFileName(const std::string& rawName);

    bool LoadStringPool();
    bool LoadTables();
    bool LoadDatabase();

    std::string GetString(uint32 index);

  public:
    MSIFile();
    virtual ~MSIFile() override;

    bool Update();
    void UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings);

    const std::vector<MSITableInfo>& GetTableList() const
    {
        return tables;
    }
    const std::vector<std::string>& GetStringPool() const
    {
        return stringPool;
    }
    const std::vector<MsiFileEntry>& GetMsiFiles() const
    {
        return msiFiles;
    }

    std::vector<std::vector<AppCUI::Utils::String>> ReadTableData(const std::string& tableName);
    const MsiTableDef* GetTableDefinition(const std::string& tableName) const;

    // TypeInterface
    virtual std::string_view GetTypeName() override
    {
        return "MSI";
    }
    virtual void RunCommand(std::string_view command) override
    {
    }
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    virtual uint32 GetSelectionZonesCount() override
    {
        return 0;
    }
    virtual TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        return { 0, 0 };
    }

    // Viewer
    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(AppCUI::Controls::TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;
    virtual GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;

    static inline bool read_u16_le(const uint8_t* p, size_t n, uint16_t& out)
    {
        if (n < 2)
            return false;
        out = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        return true;
    }

    static inline bool read_u32_le(const uint8_t* p, size_t n, uint32_t& out)
    {
        if (n < 4)
            return false;
        out = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
        return true;
    }

    static inline bool read_u64_le(const uint8_t* p, size_t n, uint64_t& out)
    {
        if (n < 8)
            return false;
        out = uint64_t(p[0]) | (uint64_t(p[1]) << 8) | (uint64_t(p[2]) << 16) | (uint64_t(p[3]) << 24) | (uint64_t(p[4]) << 32) | (uint64_t(p[5]) << 40) |
              (uint64_t(p[6]) << 48) | (uint64_t(p[7]) << 56);
        return true;
    }

    static inline bool filetime_to_time_t(uint64_t ft100ns, std::time_t& out)
    {
        constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL; // 1601 -> 1970
        if (ft100ns < EPOCH_DIFF)
            return false;

        uint64_t seconds = (ft100ns - EPOCH_DIFF) / 10000000ULL;
        if (seconds > uint64_t(std::numeric_limits<std::time_t>::max()))
            return false;

        out = static_cast<std::time_t>(seconds);
        return true;
    }
    std::string parse_lpstr(const uint8_t* ptr, size_t avail)
    {
        if (avail < 8)
            return "";

        uint32_t stringLen = 0;
        if (!read_u32_le(ptr + 4, avail - 4, stringLen))
            return "";

        if (stringLen == 0)
            return "";

        if (stringLen > (avail - 8))
            stringLen = static_cast<uint32_t>(avail - 8);

        std::string s(reinterpret_cast<const char*>(ptr + 8), stringLen);

        // MSI/OLE include adesea terminatorul \0 în lungime.
        while (!s.empty() && s.back() == '\0') {
            s.pop_back();
        }

        return s;
    }
    std::string parse_lpwstr(const uint8_t* ptr, size_t avail)
    {
        if (avail < 8)
            return "";

        uint32_t charCount = 0;
        if (!read_u32_le(ptr + 4, avail - 4, charCount))
            return "";

        if (charCount == 0)
            return "";

        size_t bytesNeeded = charCount * 2;
        if (bytesNeeded > (avail - 8))
            bytesNeeded = (avail - 8) & ~1; // 2 byte alignment

        std::u16string tempW;
        tempW.resize(bytesNeeded / 2);
        memcpy(tempW.data(), ptr + 8, bytesNeeded);

        while (!tempW.empty() && tempW.back() == u'\0') {
            tempW.pop_back();
        }

        AppCUI::Utils::String utf8;
        utf8.Set(tempW);
        return std::string(utf8.GetText());
    }
    
    static inline void size_to_string(uint64 value, std::string& result)
    {
        const char* units[] = { "Bytes", "KB", "MB", "GB", "TB", "PB" };
        int unitIndex       = 0;
        double doubleValue  = static_cast<double>(value);

        while (doubleValue >= 1024.0 && unitIndex < 5) {
            doubleValue /= 1024.0;
            unitIndex++;
        }

        char buffer[32];
        if (unitIndex == 0) {
            snprintf(buffer, sizeof(buffer), "%llu %s", value, units[unitIndex]);
        } else {
            snprintf(buffer, sizeof(buffer), "%.2f %s", doubleValue, units[unitIndex]);
        }

        result = buffer;
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<MSIFile> msi;
        Reference<AppCUI::Controls::ListView> general;
        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

      public:
        Information(Reference<MSIFile> msi);
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Tables : public AppCUI::Controls::TabPage, public AppCUI::Controls::Handlers::OnListViewItemPressedInterface
    {
        Reference<MSIFile> msi;
        Reference<AppCUI::Controls::ListView> list;

      public:
        Tables(Reference<MSIFile> msi);
        void Update();
        void OnListViewItemPressed(Reference<ListView> lv, ListViewItem item) override;
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            if (list.IsValid())
                list->Resize(GetWidth(), GetHeight());
        }
    };

    class Files : public AppCUI::Controls::TabPage
    {
        Reference<MSIFile> msi;
        Reference<AppCUI::Controls::ListView> list;

      public:
        Files(Reference<MSIFile> msi);
        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            if (list.IsValid())
                list->Resize(GetWidth(), GetHeight());
        }
    };
} // namespace Panels

namespace Dialogs
{
    class TableViewer : public AppCUI::Controls::Window
    {
        AppCUI::Utils::Reference<AppCUI::Controls::ListView> list;

      public:
        TableViewer(AppCUI::Utils::Reference<MSIFile> msi, const std::string& tableName);
        virtual bool OnEvent(AppCUI::Utils::Reference<AppCUI::Controls::Control>, AppCUI::Controls::Event eventType, int ID) override;
        virtual bool OnKeyEvent(AppCUI::Input::Key keyCode, char16 UnicodeChar) override;
    };
} // namespace Dialogs

} // namespace GView::Type::MSI


