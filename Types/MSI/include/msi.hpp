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
    uint8 objectType; // 1=Storage, 2=Stream, 5=Root
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
        uint64 totalSize;
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
    std::vector<std::vector<AppCUI::Utils::String>> ReadTableData(const std::string& tableName);

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

    class Tables : public AppCUI::Controls::TabPage
    {
        Reference<MSIFile> msi;
        Reference<AppCUI::Controls::ListView> list;

      public:
        Tables(Reference<MSIFile> msi);
        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            if (list.IsValid())
                list->Resize(GetWidth(), GetHeight());
        }
    };
} // namespace Panels
} // namespace GView::Type::MSI
