#pragma once

#include "GView.hpp"

#define NOSTREAM 0xffffffff

namespace GView::Type::DOC
{
namespace Panels
{
    class Information;
}

class ByteStream
{
  private:
    void* ptr;
    size_t size;
    size_t cursor;

  public:
    ByteStream(void* ptr, size_t size) : ptr(ptr), size(size), cursor(0){};
    ByteStream(BufferView view) : ptr((void*) view.GetData()), size(view.GetLength()), cursor(0){};

    BufferView Read(size_t count);
    template <typename T>
    T ReadAs()
    {
        size_t count = sizeof(T);
        if (cursor + count > size) {
            count = size - cursor;
        }
        T value = *(T*) ((uint8*) ptr + cursor);
        cursor += count;
        return value;
    }

    ByteStream& Seek(size_t count);

    size_t GetCursor()
    {
        return cursor;
    };

    size_t GetSize()
    {
        return size;
    }
};

#pragma pack(1)
struct CFDirEntry_Data {
    uint8 nameUnicode[64];
    uint16 nameLength;
    uint8 objectType;
    uint8 colorFlag; // 0x00 (red) or 0x01 (black)
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

class CFDirEntry
{
  private:
    void AppendChildren(uint32 childId);

  public:
    CFDirEntry();
    CFDirEntry(BufferView _directoryData, uint32 _entryId);

    bool Load(BufferView _directoryData, uint32 _entryId);
    void BuildStorageTree();
    bool FindChildByName(std::u16string_view entryName, CFDirEntry& entry);

  private:
    BufferView directoryData;
    bool initialized = false;

  public:
    uint32 entryId{};
    CFDirEntry_Data data{};
    std::vector<CFDirEntry> children;
};

// REFERENCE records
struct REFERENCECONTROL_Record {
    uint32 recordIndex;
    String libidTwiddled;
    String nameRecordExtended;
    String libidExtended;
    BufferView originalTypeLib;
    uint32 cookie;
};

struct REFERENCEORIGINAL_Record {
    uint32 recordIndex;
    String libidOriginal;
    REFERENCECONTROL_Record referenceControl;
};

struct REFERENCEREGISTERED_Record {
    uint32 recordIndex;
    String libid;
};

struct REFERENCEPROJECT_Record {
    uint32 recordIndex;
    String libidAbsolute;
    String libidRelative;
    uint32 majorVersion;
    uint16 minorVersion;
};

struct MODULE_Record {
    String moduleName;
    String streamName;
    String docString;
    uint32 textOffset;
    uint32 helpContext;
};

enum SysKind { Win16Bit = 0, Win32Bit, Macintosh, Win64Bit };

class DOCFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  private:
    constexpr static uint8 CF_HEADER_SIGNATURE[]  = { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 };
    constexpr static size_t DIFAT_LOCATIONS_COUNT = 109;

    friend class Panels::Information;

    // displayed info about the file
    uint16 cfMinorVersion;
    uint16 cfMajorVersion;
    uint32 transactionSignatureNumber;
    uint32 numberOfFatSectors;
    uint32 numberOfMiniFatSectors;
    uint32 numberOfDifatSectors;
    uint32 firstDirectorySectorLocation;
    uint32 firstMiniFatSectorLocation;
    uint32 firstDifatSectorLocation;

    uint32 dirMajorVersion;
    uint16 dirMinorVersion;
    SysKind sysKind;
    String projectName;
    String docString;
    String helpFile;
    String constants;
    uint16 modulesCount;

    // compound files (vbaProject.bin) helper member variables
    AppCUI::Utils::Buffer vbaProjectBuffer;
    AppCUI::Utils::Buffer FAT;
    AppCUI::Utils::Buffer miniStream;
    AppCUI::Utils::Buffer miniFAT;

  public:
    uint16 sectorSize{};
    uint16 miniSectorSize{};
    uint16 miniStreamCutoffSize{};

  private:
    std::u16string modulesPath;
    CFDirEntry root;

    // VBA streams helper member variables
    std::vector<REFERENCECONTROL_Record> referenceControlRecords;
    std::vector<REFERENCEORIGINAL_Record> referenceOriginalRecords;
    std::vector<REFERENCEREGISTERED_Record> referenceRegisteredRecords;
    std::vector<REFERENCEPROJECT_Record> referenceProjectRecords;

    std::vector<MODULE_Record> moduleRecords;
    uint32 moduleRecordIndex = 0;

  public:
    DOCFile();
    virtual ~DOCFile() override
    {
    }

    virtual std::string_view GetTypeName() override
    {
        return "DOC";
    }
    virtual void RunCommand(std::string_view command) override
    {
        // here
    }

  public:
    bool ProcessData();
    Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

    uint32 GetSelectionZonesCount() override
    {
        CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        CHECK(selectionZoneInterface.IsValid(), d, "");
        CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }

    // View::ContainerViewer::EnumerateInterface
    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(AppCUI::Controls::TreeViewItem item) override;

    // View::ContainerViewer::OpenItemInterface
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

    // compound files (vbaProject.bin) helper methods
    bool ParseVBAProject();
    Buffer OpenCFStream(const CFDirEntry& entry);
    Buffer OpenCFStream(uint32 sect, uint32 size, bool useMiniFAT);
    void DisplayAllVBAProjectFiles(CFDirEntry& entry);

    // VBA streams helper methods
    bool DecompressStream(BufferView bv, Buffer& decompressed);
    bool ParseUncompressedDirStream(BufferView bv);
    bool ParseModuleStream(BufferView bv, const MODULE_Record& moduleRecord, Buffer& text);
    bool FindModulesPath(const CFDirEntry& entry, UnicodeStringBuilder& path);
    bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<GView::Type::DOC::DOCFile> doc;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> compoundFileInfo;
        Reference<AppCUI::Controls::ListView> vbaStreamsInfo;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        Information(Reference<GView::Type::DOC::DOCFile> doc);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };
}; // namespace Panels
} // namespace GView::Type::DOC
