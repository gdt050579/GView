#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

MSIFile::MSIFile()
{
}

bool MSIFile::Update()
{
    // 1. Parse Header safely using Copy
    OLEHeader h;
    CHECK(this->obj->GetData().Copy<OLEHeader>(0, h), false, "Failed to read OLE Header");

    // 2. Validate Signature
    CHECK(h.signature == OLE_SIGNATURE, false, "Invalid OLE Signature");

    this->header         = h;
    this->sectorSize     = 1 << header.sectorShift;
    this->miniSectorSize = 1 << header.miniSectorShift;

    // We can fetch the real file size from the data object
    this->msiMeta.totalSize = this->obj->GetData().GetSize();

    // 3. Load File Allocation Tables
    CHECK(LoadFAT(), false, "Failed to load FAT");

    // 4. Load Directory
    CHECK(LoadDirectory(), false, "Failed to load Directory");

    // 5. Load MiniFAT and MiniStream
    CHECK(LoadMiniFAT(), false, "Failed to load MiniFAT");

    // 6. Build Tree
    BuildTree(this->rootDir);

    // 7. Extract Metadata
    ParseSummaryInformation();

    return true;
}

// --- OLE Parsing Logic ---

bool MSIFile::LoadFAT()
{
    // 1. Calculate capacity
    uint32 numSectors = header.numFatSectors;
    FAT.clear();
    FAT.reserve(numSectors * (sectorSize / 4));

    // 2. Build the complete list of FAT sector locations (DIFAT)
    std::vector<uint32> difatList;
    difatList.reserve(numSectors);

    // Step A: Read first 109 entries from Header
    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        difatList.push_back(header.difat[i]);
    }

    // Step B: Read external DIFAT chain (if file is large)
    // The header points to the start of this chain
    uint32 currentDifatSector = header.firstDifatSector;
    uint32 difatCount         = header.numDifatSectors;

    // Number of valid FAT pointers per DIFAT sector.
    // The last 4 bytes are used for chaining to the next DIFAT sector.
    uint32 entriesPerDifatSector = (sectorSize / 4) - 1;

    for (uint32 i = 0; i < difatCount; i++) {
        if (currentDifatSector == ENDOFCHAIN || currentDifatSector == NOSTREAM)
            break;

        // Calculate offset: (SectorID + 1) * SectorSize
        uint64 offset = (uint64) (currentDifatSector + 1) * sectorSize;

        auto view = this->obj->GetData().Get(offset, sectorSize, true);
        CHECK(view.IsValid(), false, "Failed to read DIFAT sector at %u", currentDifatSector);

        const uint32* data = reinterpret_cast<const uint32*>(view.GetData());

        // Read the FAT pointers (all except the last one)
        for (uint32 k = 0; k < entriesPerDifatSector; k++) {
            if (data[k] == ENDOFCHAIN || data[k] == NOSTREAM)
                continue; // Or break, depending on fragmentation
            difatList.push_back(data[k]);
        }

        // The last entry points to the NEXT DIFAT sector
        currentDifatSector = data[entriesPerDifatSector];
    }

    // 3. Load the actual FAT sectors using the complete DIFAT list
    for (uint32 sect : difatList) {
        uint64 offset = (uint64) (sect + 1) * sectorSize;

        auto sectorView = this->obj->GetData().Get(offset, sectorSize, true);
        CHECK(sectorView.IsValid(), false, "Failed to read FAT sector at offset %llu", offset);

        const uint32* sectorData = reinterpret_cast<const uint32*>(sectorView.GetData());
        uint32 count             = sectorSize / 4;

        for (uint32 k = 0; k < count; k++) {
            FAT.push_back(sectorData[k]);
        }
    }

    return true;
}

std::u16string DecodeMSIName(const uint8* rawName, uint16 cbLength)
{
    if (cbLength < 2)
        return u"";

    // OLE Directory names are technically UTF-16LE.
    // However, if we are seeing Chinese, it means the bytes are NOT valid UTF-16LE
    // for the Latin alphabet (e.g. "File" is 0x46 0x00 0x69 0x00...).
    // If we see bytes like 0x46 0x69 0x6C 0x65, interpreting as U16 yields garbage.

    // Simple heuristic: Count nulls in odd positions
    int nulls = 0;
    for (int i = 1; i < cbLength; i += 2) {
        if (rawName[i] == 0)
            nulls++;
    }

    // If > 50% of odd bytes are 0, assume valid UTF-16
    if (nulls > (cbLength / 4)) {
        return std::u16string((const char16_t*) rawName, (cbLength / 2) - 1);
    }

    // Otherwise, treat as ASCII and inflate
    std::u16string res;
    res.reserve(cbLength);
    for (int i = 0; i < cbLength; i++) {
        if (rawName[i] == 0)
            break; // Stop at null
        res.push_back((char16_t) rawName[i]);
    }
    return res;
}

bool MSIFile::LoadDirectory()
{
    // Directory is a standard stream starting at firstDirSector
    Buffer dirStream = GetStream(header.firstDirSector, 0, false);
    CHECK(dirStream.GetLength() > 0, false, "Failed to read Directory stream");

    uint32 count = (uint32) dirStream.GetLength() / 128;
    linearDirList.clear();

    // Read root
    if (count > 0) {
        // Safe casting from Buffer data
        const DirectoryEntryData* d = (const DirectoryEntryData*) dirStream.GetData();

        rootDir.id   = 0;
        rootDir.data = d[0];

        // Safely assign name
        if (d[0].nameLength > 0) {
            // FIX: Explicit cast to (const uint8*)
            rootDir.name = DecodeMSIName((const uint8*) d[0].name, d[0].nameLength);
        }

        // Cache all entries
        for (uint32 i = 0; i < count; i++) {
            DirEntry* e = new DirEntry();
            e->id       = i;
            e->data     = d[i];

            if (e->data.nameLength > 0) {
                // nameLength includes null terminator, so we subtract 1 char
                // FIX: Explicit cast to (const uint8*)
                e->name = DecodeMSIName((const uint8*) d[i].name, d[i].nameLength);
            }
            linearDirList.push_back(e);
        }

        CHECK(linearDirList.size() > 0, false, "Directory list empty after parsing");
        rootDir = *linearDirList[0];
    }
    return true;
}

bool MSIFile::LoadMiniFAT()
{
    // MiniFAT is stored in a stream pointed to by header
    // We read it just like a normal stream
    Buffer fatData = GetStream(header.firstMiniFatSector, 0, false);

    // It's possible for a file to have no MiniFAT if it has no small streams
    if (fatData.GetLength() > 0) {
        const uint32* ptr = (const uint32*) fatData.GetData();
        size_t count      = fatData.GetLength() / 4;
        miniFAT.reserve(count);
        for (size_t i = 0; i < count; i++) {
            miniFAT.push_back(ptr[i]);
        }
    }

    // MiniStream is the data contained inside the Root Entry
    if (rootDir.data.streamSize > 0) {
        miniStream = GetStream(rootDir.data.startingSectorLocation, rootDir.data.streamSize, false);
    }

    return true;
}

AppCUI::Utils::Buffer MSIFile::GetStream(uint32 startSector, uint64 size, bool isMini)
{
    std::vector<uint32>& table = isMini ? miniFAT : FAT;
    uint32 sSize               = isMini ? miniSectorSize : sectorSize;
    Buffer result;
    uint32 sect = startSector;

    // Safety check loop count to prevent infinite loops in corrupted files
    uint32 loopSafety = 0;
    uint32 maxLoops   = 100000;

    while (sect != ENDOFCHAIN && sect != NOSTREAM) {
        if (loopSafety++ > maxLoops)
            break;
        if (sect >= table.size())
            break;

        if (isMini) {
            // Mini streams are inside the RAM buffer `miniStream`
            uint64 fileOffset = (uint64) sect * sSize;
            if (fileOffset + sSize <= miniStream.GetLength()) {
                result.Add(BufferView(miniStream.GetData() + fileOffset, sSize));
            }
        } else {
            // Standard streams are in the file on disk
            // OLE Formula: (SectorID + 1) * SectorSize
            uint64 fileOffset = (uint64) (sect + 1) * sSize;

            // Use CopyToBuffer to extract specific chunks from the file object
            auto chunk = this->obj->GetData().CopyToBuffer(fileOffset, sSize);
            if (chunk.IsValid()) {
                result.Add(chunk);
            }
        }

        sect = table[sect];

        // Optimization: Stop if we have enough data
        if (size > 0 && result.GetLength() >= size) {
            result.Resize(size);
            break;
        }
    }
    return result;
}

void MSIFile::BuildTree(DirEntry& parent)
{
    if (parent.data.childId == NOSTREAM)
        return;

    // 1. Collect all direct children by traversing the Red-Black Tree of siblings.
    // The parent.data.childId is just the root of this RB-Tree.
    std::vector<uint32> siblingIDs;

    // Recursive lambda to flatten the RB-Tree into a list
    std::function<void(uint32)> traverseSiblings = [&](uint32 nodeId) {
        if (nodeId == NOSTREAM || nodeId >= linearDirList.size())
            return;

        DirEntry* node = linearDirList[nodeId];

        // Traverse Left
        traverseSiblings(node->data.leftSiblingId);

        // Visit Node
        siblingIDs.push_back(nodeId);

        // Traverse Right
        traverseSiblings(node->data.rightSiblingId);
    };

    traverseSiblings(parent.data.childId);

    // 2. Add collected siblings to the parent's children list and recurse
    parent.children.reserve(siblingIDs.size());
    for (uint32 id : siblingIDs) {
        DirEntry* src = linearDirList[id];

        // Create a copy for the tree structure
        DirEntry childNode = *src;
        childNode.children.clear(); // Ensure we start fresh

        // If this child is a Storage (Folder), build its subtree recursively
        if (childNode.data.objectType == 1 || childNode.data.objectType == 5) {
            BuildTree(childNode);
        }

        parent.children.push_back(childNode);
    }
}

// --- Metadata Extraction ---

void MSIFile::ParseSummaryInformation()
{
    // 1. Find the SummaryInformation stream
    for (auto* entry : linearDirList) {
        // Name is often "\005SummaryInformation" (0x0005 followed by string)
        if (entry->name.find(u"SummaryInformation") != std::u16string::npos) {
            // Determine if we use MiniStream or Main Stream
            bool isMini = entry->data.streamSize < header.miniStreamCutoffSize;
            Buffer buf  = GetStream(entry->data.startingSectorLocation, entry->data.streamSize, isMini);

            if (buf.GetLength() < 48)
                return;

            // --- Property Set Parsing ---

            // Validate Header (Byte Order = 0xFFFE)
            uint16 byteOrder = *(uint16*) buf.GetData();
            if (byteOrder != 0xFFFE)
                return; // Only Little Endian supported for now

            // Read First Section Offset (at 0x2C usually, inside the Section List)
            // Header is 28 bytes. Immediately after is the Section Locator array (CLSID + Offset).
            // We assume the first section is the one we want (FMTID_SummaryInformation).
            uint32 sectionOffset = *(uint32*) (buf.GetData() + 44); // 28 (Header) + 16 (CLSID) = 44

            if (sectionOffset > buf.GetLength())
                return;

            // Pointer to the start of the section
            const uint8* sectionStart = buf.GetData() + sectionOffset;
            uint32 sectionSize        = *(uint32*) sectionStart;
            uint32 propertyCount      = *(uint32*) (sectionStart + 4);

            // Property offsets are relative to the Section Start
            const uint8* propertyList = sectionStart + 8;

            for (uint32 i = 0; i < propertyCount; i++) {
                // Read Property ID and Offset
                uint32 propID     = *(uint32*) (propertyList + (i * 8));
                uint32 propOffset = *(uint32*) (propertyList + (i * 8) + 4);

                // Pointer to the Property Value
                const uint8* valuePtr = sectionStart + propOffset;
                uint32 type           = *(uint32*) valuePtr;

                // Extract String Value (VT_LPSTR = 30)
                if (type == 30) {
                    uint32 len          = *(uint32*) (valuePtr + 4);
                    const char* strData = (const char*) (valuePtr + 8);

                    // Sanity check length
                    if (reinterpret_cast<const uint8_t*>(strData + len) > buf.GetData() + buf.GetLength())
                        continue;

                    std::string value(strData, len > 0 ? len - 1 : 0); // Remove null terminator

                    // Map IDs to Metadata fields
                    switch (propID) {
                    case 2: // PID_TITLE
                        msiMeta.title = value;
                        break;
                    case 3: // PID_SUBJECT
                        msiMeta.subject = value;
                        break;
                    case 4: // PID_AUTHOR
                        msiMeta.author = value;
                        break;
                    case 5: // PID_KEYWORDS
                        msiMeta.keywords = value;
                        break;
                    case 6: // PID_COMMENTS
                        msiMeta.comments = value;
                        break;
                    case 9: // PID_REVNUMBER (Package Code)
                        msiMeta.revisionNumber = value;
                        break;
                    case 18: // PID_APPNAME
                        msiMeta.creatingApp = value;
                        break;
                    }
                }
            }
            break; // Stop after finding the stream
        }
    }
}

// --- Viewer Interface ---

bool MSIFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    // Reset iteration state
    currentIterIndex = 0;

    if (path.empty()) {
        // Root case
        currentIterFolder = &rootDir;
    } else {
        // Navigation case: Retrieve the folder pointer stored in the parent item
        // This works because we set SetData<DirEntry>(child) in PopulateItem
        currentIterFolder = parent.GetData<DirEntry*>();
    }

    // Safety check
    return currentIterFolder != nullptr;
}

bool MSIFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    // Ensure we have a valid folder and index
    if (!currentIterFolder || currentIterIndex >= currentIterFolder->children.size()) {
        return false;
    }

    // Get the current child
    // Note: children is a vector<DirEntry>, not pointers, so we take the address
    DirEntry* child = &currentIterFolder->children[currentIterIndex];
    currentIterIndex++;

    // 1. Name
    item.SetText(0, child->name);

    // 2. Type & Size
    if (child->data.objectType == 1 || child->data.objectType == 5) {
        // Storage (Folder)
        item.SetText(1, "Folder");
        item.SetText(2, ""); // No size for folders
        item.SetPriority(1); // Sort folders first

        // Crucial: Set the item as expandable so GView allows navigation into it
        item.SetExpandable(true);
    } else if (child->data.objectType == 2) {
        // Stream (File)
        item.SetText(1, "Stream");
        LocalString<32> sz;
        sz.Format("%llu", child->data.streamSize);
        item.SetText(2, sz);
        item.SetPriority(0);
        item.SetExpandable(false);
    }

    // 3. Store Data for Navigation/Opening
    // We assume the children vector in DirEntry is stable or we should rely on IDs.
    // However, since we rebuilt the tree, 'child' is a persistent address inside the parent's vector
    // as long as we don't resize the parent's vector after building.
    // Better approach: Find the original entry in linearDirList using ID to be safe.
    if (child->id < linearDirList.size()) {
        item.SetData<DirEntry>(linearDirList[child->id]);
    }

    return true;
}

void MSIFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto e = item.GetData<DirEntry>();
    if (e && e->data.objectType == 2) { // Only open Streams
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
    general->AddItem({ "Subject", msi->msiMeta.subject });
    general->AddItem({ "Author", msi->msiMeta.author });
    general->AddItem({ "Keywords", msi->msiMeta.keywords });
    general->AddItem({ "Comments", msi->msiMeta.comments });
    general->AddItem({ "UUID (Rev)", msi->msiMeta.revisionNumber });
    general->AddItem({ "Creating Application", msi->msiMeta.creatingApp });
}

void Panels::Information::RecomputePanelsPositions()
{
    if (general.IsValid())
        general->Resize(GetWidth(), GetHeight());
}

void MSIFile::UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings)
{
    // 1. Highlight Header (First 512 bytes)
    settings.AddZone(0, 512, ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");

    // Helper lambda to calculate offset: (SectorIndex + 1) * SectorSize
    // In OLE/MSI, Sector 0 starts at offset 512 (if sector size is 512).
    auto addSectorZone = [&](uint32 sect, ColorPair col, std::string_view name) {
        uint64 offset = (uint64) (sect + 1) * sectorSize;
        settings.AddZone(offset, sectorSize, col, name);
    };

    // 2. Highlight FAT Sectors (Green)
    // We need to re-scan DIFAT to find where FAT sectors are located on disk
    std::vector<uint32> fatSectorLocations;

    // A. Internal DIFAT (Header)
    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        fatSectorLocations.push_back(header.difat[i]);
    }

    // B. External DIFAT Chains (Red)
    uint32 currDifatSect = header.firstDifatSector;
    while (currDifatSect != ENDOFCHAIN && currDifatSect != NOSTREAM) {
        // Highlight the DIFAT sector itself
        addSectorZone(currDifatSect, ColorPair{ Color::DarkRed, Color::DarkBlue }, "DIFAT");

        // Read the DIFAT sector to find more FAT sectors
        uint64 offset = (uint64) (currDifatSect + 1) * sectorSize;
        auto view     = this->obj->GetData().Get(offset, sectorSize, true);
        if (!view.IsValid())
            break;

        const uint32* ptr = reinterpret_cast<const uint32*>(view.GetData());
        uint32 count      = sectorSize / 4;

        // The last entry is the pointer to the next DIFAT sector, so iterate count-1
        for (uint32 k = 0; k < count - 1; k++) {
            if (ptr[k] != ENDOFCHAIN && ptr[k] != NOSTREAM)
                fatSectorLocations.push_back(ptr[k]);
        }

        currDifatSect = ptr[count - 1]; // Next DIFAT sector
    }

    // Now highlight all collected FAT sectors
    for (auto sect : fatSectorLocations) {
        addSectorZone(sect, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "FAT");
    }

    // 3. Highlight Directory Sectors (Olive)
    // Trace the chain from header.firstDirSector using the loaded FAT
    uint32 dirSect = header.firstDirSector;
    while (dirSect != ENDOFCHAIN && dirSect != NOSTREAM && dirSect < FAT.size()) {
        addSectorZone(dirSect, ColorPair{ Color::Olive, Color::DarkBlue }, "Directory");
        dirSect = FAT[dirSect];
    }

    // 4. Highlight MiniFAT Sectors (Teal)
    // Trace the chain from header.firstMiniFatSector
    uint32 minifatSect = header.firstMiniFatSector;
    while (minifatSect != ENDOFCHAIN && minifatSect != NOSTREAM && minifatSect < FAT.size()) {
        addSectorZone(minifatSect, ColorPair{ Color::Teal, Color::DarkBlue }, "MiniFAT");
        minifatSect = FAT[minifatSect];
    }
}