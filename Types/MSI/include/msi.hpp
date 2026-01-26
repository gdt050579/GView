#pragma once

#include "GView.hpp"

// Minimal ByteStream definition for MSI parsing (adapted from DOC/ByteStream)
class ByteStream
{
  private:
    void* ptr;
    size_t size;
    size_t cursor;

  public:
    ByteStream(void* ptr, size_t size) : ptr(ptr), size(size), cursor(0) {}
    ByteStream(AppCUI::Utils::BufferView view) : ptr((void*) view.GetData()), size(view.GetLength()), cursor(0) {}

    AppCUI::Utils::BufferView Read(size_t count)
    {
        size_t available = (cursor + count > size) ? (size - cursor) : count;
        AppCUI::Utils::BufferView bv((uint8*)ptr + cursor, available);
        cursor += available;
        return bv;
    }

    template <typename T>
    T ReadAs()
    {
        size_t count = sizeof(T);
        if (cursor + count > size)
            count = size - cursor;
        T value = *(T*) ((uint8*) ptr + cursor);
        cursor += count;
        return value;
    }

    ByteStream& Seek(size_t count)
    {
        cursor = (count > size) ? size : count;
        return *this;
    }

    size_t GetCursor() const { return cursor; }
    size_t GetSize() const { return size; }
};

namespace GView::Type::MSI
{
// Constants for OLE/CFBF format
constexpr uint64 OLE_SIGNATURE = 0xE11AB1A1E011CFD0;

// FAT Special Values
constexpr uint32 FREESECT   = 0xFFFFFFFF; // Unallocated sector
constexpr uint32 ENDOFCHAIN = 0xFFFFFFFE; // End of linked chain
constexpr uint32 FATSECT    = 0xFFFFFFFD; // Sector belongs to FAT
constexpr uint32 DIFSECT    = 0xFFFFFFFC; // Sector belongs to DIFAT
constexpr uint32 NOSTREAM   = 0xFFFFFFFF; // Invalid ID / Empty

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
    char16 name[32]; // Fixed size in structure, but name length is defined
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

// Helper class to manage Directory Entries tree
struct DirEntry {
    uint32 id;
    DirectoryEntryData data;
    std::vector<DirEntry> children;
    std::u16string name;
};

class MSIFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    // Metadata fields for the Information Panel
    struct Metadata {
        std::string title;
        std::string subject;
        std::string author;
        std::string keywords;
        std::string comments;       // Often contains the Installer description
        std::string revisionNumber; // The Package Code (UUID)
        std::string creatingApp;
        uint64 totalSize;
    } msiMeta;

    uint32 sectorSize;
    uint32 miniSectorSize;

  private:
    AppCUI::Utils::Buffer fileBuffer; // The entire file

    // OLE Parsing internals
    OLEHeader header;

    // Caches for FAT tables
    std::vector<uint32> FAT;
    std::vector<uint32> miniFAT;
    AppCUI::Utils::Buffer miniStream;

    DirEntry rootDir;
    std::vector<DirEntry*> linearDirList; // For easier indexing if needed

    // Iteration State
    DirEntry* currentIterFolder = nullptr;
    size_t currentIterIndex     = 0;

    // Internal parsing methods
    bool LoadFAT();
    bool LoadMiniFAT();
    bool LoadDirectory();
    void BuildTree(DirEntry& parent);
    AppCUI::Utils::Buffer GetStream(uint32 startSector, uint64 size, bool isMini);
    void ParseSummaryInformation();

  public:
    MSIFile();
    virtual ~MSIFile() override
    {
        // Cleanup memory allocated in LoadDirectory
        for (auto* entry : linearDirList) {
            delete entry;
        }
        linearDirList.clear();
    }

    bool Update(); // Main entry to parse the file

    void UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings);

    // TypeInterface Implementation
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

    // ContainerViewer::EnumerateInterface
    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(AppCUI::Controls::TreeViewItem item) override;

    // ContainerViewer::OpenItemInterface
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

    // Smart Assistant
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
} // namespace Panels
} // namespace GView::Type::MSI
