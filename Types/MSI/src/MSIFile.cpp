#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

MSIFile::MSIFile()
{
}

bool MSIFile::Update()
{
    this->fileBuffer = this->obj->GetData().GetEntireFile();
    if (this->fileBuffer.GetLength() < sizeof(OLEHeader))
        return false;

    // 1. Parse Header
    const OLEHeader* h = (const OLEHeader*) this->fileBuffer.GetData();
    if (h->signature != OLE_SIGNATURE)
        return false;

    this->header            = *h;
    this->sectorSize        = 1 << header.sectorShift;
    this->miniSectorSize    = 1 << header.miniSectorShift;
    this->msiMeta.totalSize = this->fileBuffer.GetLength();

    // 2. Load File Allocation Tables
    if (!LoadFAT())
        return false;

    // 3. Load Directory and MiniFAT
    if (!LoadDirectory())
        return false;

    // 4. Load MiniFAT and MiniStream (Root stream)
    if (!LoadMiniFAT())
        return false;

    // 5. Build Tree
    BuildTree(this->rootDir);

    // 6. Extract Metadata (Summary Information)
    ParseSummaryInformation();

    return true;
}

// --- OLE Parsing Logic ---

bool MSIFile::LoadFAT()
{
    // Simplified FAT loading for standard MSI files
    uint32 numSectors = header.numFatSectors;
    FAT.reserve(numSectors * (sectorSize / 4));

    // Read DIFAT first (First 109 entries are in header)
    std::vector<uint32> difatList;
    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        difatList.push_back(header.difat[i]);
    }

    // Iterate through DIFAT to find FAT sectors
    for (uint32 sect : difatList) {
        size_t offset = (sect + 1) * sectorSize;
        if (offset + sectorSize > fileBuffer.GetLength())
            break;

        const uint32* sectorData = (const uint32*) (fileBuffer.GetData() + offset);
        uint32 count             = sectorSize / 4;
        for (uint32 k = 0; k < count; k++)
            FAT.push_back(sectorData[k]);
    }
    return true;
}

bool MSIFile::LoadDirectory()
{
    Buffer dirStream = GetStream(header.firstDirSector, 0, false); // Directory is in standard FAT
    if (dirStream.GetLength() == 0)
        return false;

    uint32 count = (uint32) dirStream.GetLength() / 128;
    linearDirList.clear();

    // Read root
    if (count > 0) {
        const DirectoryEntryData* d = (const DirectoryEntryData*) dirStream.GetData();
        rootDir.id                  = 0;
        rootDir.data                = d[0];
        rootDir.name.assign((char16_t*) d[0].name, d[0].nameLength / 2 - 1); // remove null
        // Cache all entries for tree building
        for (uint32 i = 0; i < count; i++) {
            DirEntry* e = new DirEntry(); // Note: Memory management should be cleaner in prod
            e->id       = i;
            e->data     = d[i];
            if (e->data.nameLength > 0)
                e->name.assign((char16_t*) e->data.name, e->data.nameLength / 2 - 1);
            linearDirList.push_back(e);
        }
        // Fix: root is index 0
        rootDir = *linearDirList[0];
    }
    return true;
}

bool MSIFile::LoadMiniFAT()
{
    // MiniFAT is stored in a stream pointed to by header
    uint32 miniFatSize = header.numMiniFatSectors * sectorSize;
    Buffer fatData     = GetStream(header.firstMiniFatSector, 0, false); // Read entire chain

    const uint32* ptr = (const uint32*) fatData.GetData();
    size_t count      = fatData.GetLength() / 4;
    for (size_t i = 0; i < count; i++)
        miniFAT.push_back(ptr[i]);

    // MiniStream is the data of the Root Entry
    if (rootDir.data.streamSize > 0) {
        miniStream = GetStream(rootDir.data.startingSectorLocation, rootDir.data.streamSize, false);
    }
    return true;
}

AppCUI::Utils::Buffer MSIFile::GetStream(uint32 startSector, uint64 size, bool isMini)
{
    // Helper to traverse sector chains
    std::vector<uint32>& table = isMini ? miniFAT : FAT;
    uint32 sSize               = isMini ? miniSectorSize : sectorSize;

    Buffer result;
    uint32 sect = startSector;

    // If reading directory (size 0 passed usually), read until end of chain
    // If reading specific stream, read until size is met

    while (sect != ENDOFCHAIN && sect != NOSTREAM) {
        if (sect >= table.size())
            break; // Security check

        size_t fileOffset;
        if (isMini) {
            // Mini stream is inside the Root Stream buffer
            fileOffset = sect * sSize;
            if (fileOffset + sSize <= miniStream.GetLength()) {
                // FIX: Wrap in BufferView
                result.Add(BufferView(miniStream.GetData() + fileOffset, sSize));
            }
        } else {
            // Standard stream is relative to file start + 1 header sector
            fileOffset = (sect + 1) * sSize;
            if (fileOffset + sSize <= fileBuffer.GetLength()) {
                // FIX: Wrap in BufferView
                result.Add(BufferView(fileBuffer.GetData() + fileOffset, sSize));
            }
        }

        sect = table[sect];
        if (size > 0 && result.GetLength() >= size) {
            result.Resize(size); // Trim to exact size
            break;
        }
    }
    return result;
}

void MSIFile::BuildTree(DirEntry& parent)
{
    // Recursive function to attach children based on Left/Right/Child IDs would go here.
    // For simplicity in MVP, we just rely on linear list or flat view if tree logic is complex.
    // However, MSI structure is flat for tables usually.
    // We will iterate linearDirList in EnumerateInterface for now to ensure all streams are visible.
}

// --- Metadata Extraction ---

void MSIFile::ParseSummaryInformation()
{
    // Look for "\005SummaryInformation"
    for (auto* entry : linearDirList) {
        if (entry->name.find(u"SummaryInformation") != std::u16string::npos) {
            Buffer buf = GetStream(entry->data.startingSectorLocation, entry->data.streamSize, entry->data.streamSize < header.miniStreamCutoffSize);

            // Basic Property Set parsing
            if (buf.GetLength() < 48)
                return;
            // Skip Header (28 bytes) + Section Header (20 bytes)
            // This is a naive parser for MVP. Real one requires reading offsets.
            // Just extracting strings found in buffer for demo purposes or implementing strict parser.

            // To do it properly:
            // ByteStream bs(buf.GetData(), buf.GetLength());
            // bs.Seek(28); // Offset to first section

            // We'll rely on generic string extraction for now or implement full PropertySet later.
            // For MVP:
            msiMeta.title       = "MSI Installer Database";
            msiMeta.creatingApp = "Windows Installer";
            break;
        }
    }
}

// --- Viewer Interface ---

bool MSIFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    // If path is empty, we are at root
    return true;
}

bool MSIFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    static uint32 idx = 0;
    if (item.GetParent().GetHandle() == InvalidItemHandle)
        idx = 1; // Reset on root

    // Skip Root Entry (index 0)
    while (idx < linearDirList.size()) {
        DirEntry* e = linearDirList[idx];
        idx++;

        if (e->data.objectType == 2) { // Stream
            item.SetText(0, e->name);
            item.SetText(1, "Stream");
            LocalString<32> sz;
            sz.Format("%llu", e->data.streamSize);
            item.SetText(2, sz);

            // Decode MSI Table names here if desired (Base62 decoding)
            item.SetData<DirEntry>(e); // Store pointer for OnOpenItem

            return true;
        }
    }
    return false;
}

void MSIFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto e = item.GetData<DirEntry>();
    if (e) {
        bool isMini    = e->data.streamSize < header.miniStreamCutoffSize;
        Buffer content = GetStream(e->data.startingSectorLocation, e->data.streamSize, isMini);
        GView::App::OpenBuffer(content, e->name, "", GView::App::OpenMethod::BestMatch, "bin");
    }
}

GView::Utils::JsonBuilderInterface* MSIFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddString("Type", "Microsoft Installer (MSI)");
    builder->AddUInt("Streams", (uint32) linearDirList.size());
    return builder;
}

// --- Information Panel Implementation ---

using namespace AppCUI::Controls;

Panels::Information::Information(Reference<MSIFile> _msi) : TabPage("&Information")
{
    msi     = _msi;
    general = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:100%", { "n:Field,w:20", "n:Value,w:80" }, ListViewFlags::None);
    UpdateGeneralInformation();
}

void Panels::Information::UpdateGeneralInformation()
{
    general->DeleteAllItems();
    general->AddItem({ "Type", "MSI (Compound File)" });
    general->AddItem({ "Sector Size", std::to_string(msi->sectorSize) });
    general->AddItem({ "Mini Sector Size", std::to_string(msi->miniSectorSize) });

    // Add Metadata extracted
    general->AddItem({ "Title", msi->msiMeta.title });
    general->AddItem({ "Author", msi->msiMeta.author });
    general->AddItem({ "UUID (Rev)", msi->msiMeta.revisionNumber });
}

void Panels::Information::RecomputePanelsPositions()
{
    if (general.IsValid())
        general->Resize(GetWidth(), GetHeight());
}
