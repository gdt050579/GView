#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

MSIFile::MSIFile()
{
}

MSIFile::~MSIFile()
{
    for (auto* entry : linearDirList)
        delete entry;
    linearDirList.clear();
}

bool MSIFile::Update()
{
    OLEHeader h;
    CHECK(this->obj->GetData().Copy<OLEHeader>(0, h), false, "Failed to read OLE Header");
    CHECK(h.signature == OLE_SIGNATURE, false, "Invalid OLE Signature");

    this->header            = h;
    this->sectorSize        = 1 << header.sectorShift;
    this->miniSectorSize    = 1 << header.miniSectorShift;
    this->msiMeta.totalSize = this->obj->GetData().GetSize();

    CHECK(LoadFAT(), false, "Failed to load FAT");
    CHECK(LoadDirectory(), false, "Failed to load Directory");
    CHECK(LoadMiniFAT(), false, "Failed to load MiniFAT");

    BuildTree(this->rootDir);
    ParseSummaryInformation();

    // Database Loading
    if (LoadStringPool()) {
        LoadDatabase(); // 1. Load Schema first
        LoadTables();   // 2. Then build UI list based on Schema
    }

    return true;
}

// --- OLE Parsing ---

bool MSIFile::LoadFAT()
{
    uint32 numSectors = header.numFatSectors;
    FAT.clear();
    FAT.reserve(numSectors * (sectorSize / 4));

    std::vector<uint32> difatList;
    difatList.reserve(numSectors);

    // 1. Header DIFAT
    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        difatList.push_back(header.difat[i]);
    }

    // 2. External DIFAT
    uint32 currentDifatSector = header.firstDifatSector;
    uint32 entriesPerDifat    = (sectorSize / 4) - 1;

    while (currentDifatSector != ENDOFCHAIN && currentDifatSector != NOSTREAM) {
        uint64 offset = (uint64) (currentDifatSector + 1) * sectorSize;
        auto view     = this->obj->GetData().Get(offset, sectorSize, true);
        if (!view.IsValid())
            break;

        const uint32* data = reinterpret_cast<const uint32*>(view.GetData());
        for (uint32 k = 0; k < entriesPerDifat; k++) {
            if (data[k] != ENDOFCHAIN && data[k] != NOSTREAM)
                difatList.push_back(data[k]);
        }
        currentDifatSector = data[entriesPerDifat];
    }

    // 3. Load FAT Sectors
    for (uint32 sect : difatList) {
        uint64 offset = (uint64) (sect + 1) * sectorSize;
        auto view     = this->obj->GetData().Get(offset, sectorSize, true);
        if (view.IsValid()) {
            const uint32* data = reinterpret_cast<const uint32*>(view.GetData());
            uint32 count       = sectorSize / 4;
            for (uint32 k = 0; k < count; k++)
                FAT.push_back(data[k]);
        }
    }
    return true;
}

bool MSIFile::LoadDirectory()
{
    Buffer dirStream = GetStream(header.firstDirSector, 0, false);
    CHECK(dirStream.GetLength() > 0, false, "Failed to read Directory stream");

    uint32 count = (uint32) dirStream.GetLength() / 128;
    linearDirList.clear();

    if (count > 0) {
        const DirectoryEntryData* d = (const DirectoryEntryData*) dirStream.GetData();

        // [REMOVED] The manual parsing of d[0] (Root Entry) here was useless
        // because the loop below starts at i=0 and does the exact same thing.

        for (uint32 i = 0; i < count; i++) {
            DirEntry* e = new DirEntry();
            e->id       = i;
            e->data     = d[i];

            if (e->data.nameLength > 0) {
                size_t charCount = e->data.nameLength / 2;

                // Safety clamp (OLE name max is 32 chars)
                if (charCount > 32)
                    charCount = 32;

                // Strip the null terminator if present
                if (charCount > 0 && d[i].name[charCount - 1] == 0) {
                    charCount--;
                }

                e->name.assign(d[i].name, charCount);
                e->decodedName = MsiDecompressName(e->name);
            }
            linearDirList.push_back(e);
        }

        // Copy the parsed root entry (index 0) to the class member
        if (!linearDirList.empty())
            rootDir = *linearDirList[0];
    }
    return true;
}

bool MSIFile::LoadMiniFAT()
{
    Buffer fatData = GetStream(header.firstMiniFatSector, 0, false);
    if (fatData.GetLength() > 0) {
        const uint32* ptr = (const uint32*) fatData.GetData();
        size_t count      = fatData.GetLength() / 4;
        miniFAT.reserve(count);
        for (size_t i = 0; i < count; i++)
            miniFAT.push_back(ptr[i]);
    }

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

    // Safety
    uint32 limit      = 0;
    uint32 maxSectors = (uint32) (size / sSize) + 5;

    while (sect != ENDOFCHAIN && sect != NOSTREAM) {
        if (sect >= table.size() || limit++ > maxSectors + 1000)
            break;

        if (isMini) {
            uint64 fileOffset = (uint64) sect * sSize;
            if (fileOffset + sSize <= miniStream.GetLength())
                result.Add(BufferView(miniStream.GetData() + fileOffset, sSize));
        } else {
            uint64 fileOffset = (uint64) (sect + 1) * sSize;
            auto chunk        = this->obj->GetData().CopyToBuffer(fileOffset, sSize);
            if (chunk.IsValid())
                result.Add(chunk);
        }

        sect = table[sect];
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

    std::vector<uint32> siblingIDs;
    std::function<void(uint32)> traverse = [&](uint32 nodeId) {
        if (nodeId == NOSTREAM || nodeId >= linearDirList.size())
            return;
        DirEntry* node = linearDirList[nodeId];
        traverse(node->data.leftSiblingId);
        siblingIDs.push_back(nodeId);
        traverse(node->data.rightSiblingId);
    };

    traverse(parent.data.childId);

    parent.children.reserve(siblingIDs.size());
    for (uint32 id : siblingIDs) {
        DirEntry* src      = linearDirList[id];
        DirEntry childNode = *src;
        childNode.children.clear();

        if (childNode.data.objectType == 1 || childNode.data.objectType == 5) {
            BuildTree(childNode);
        }
        parent.children.push_back(childNode);
    }
}

// Metadata Extraction 

void MSIFile::ParseSummaryInformation()
{
    for (auto* entry : linearDirList) {
        if (entry->name.find(u"SummaryInformation") != std::u16string::npos) {
            bool isMini = entry->data.streamSize < header.miniStreamCutoffSize;
            
            Buffer buf  = GetStream(entry->data.startingSectorLocation, entry->data.streamSize, isMini);
            
            if (buf.GetLength() < 48)
                return;

            const uint8* data    = buf.GetData();
            uint32 sectionOffset = *(uint32*) (data + 44);
            if (sectionOffset > buf.GetLength())
                return;

            const uint8* sectionStart = data + sectionOffset;
            uint32 propertyCount      = *(uint32*) (sectionStart + 4);
            
            const uint8* propertyList = sectionStart + 8;

            for (uint32 i = 0; i < propertyCount; i++) {
                uint32 propID         = *(uint32*) (propertyList + (i * 8));
                uint32 propOffset     = *(uint32*) (propertyList + (i * 8) + 4);
                const uint8* valuePtr = sectionStart + propOffset;
                uint32 type           = *(uint32*) valuePtr;

                if (type == 30) { // VT_LPSTR
                    uint32 len          = *(uint32*) (valuePtr + 4);
                    const char* strData = (const char*) (valuePtr + 8);
                    
                    if ((const uint8*) (strData + len) > data + buf.GetLength())
                        continue;
                    
                    std::string value(strData, len > 0 ? len - 1 : 0);

                    switch (propID) {
                    case 2:
                        msiMeta.title = value;
                        break;
                    case 3:
                        msiMeta.subject = value;
                        break;
                    case 4:
                        msiMeta.author = value;
                        break;
                    case 5:
                        msiMeta.keywords = value;
                        break;
                    case 6:
                        msiMeta.comments = value;
                        break;
                    case 9:
                        msiMeta.revisionNumber = value;
                        break;
                    case 18:
                        msiMeta.creatingApp = value;
                        break;
                    }
                }
            }
            break;
        }
    }
}

// --- MSI Decoding Helper ---

// [FIX] Correct Base62 Decoding for MSI
std::u16string MSIFile::MsiDecompressName(std::u16string_view encoded)
{
    // MSI Base62 Charset (0-63)
    // 0-9, A-Z, a-z, ., _
    static const char16_t charset[] = u"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

    std::u16string result;
    result.reserve(encoded.length() * 2);

    for (size_t i = 0; i < encoded.length(); ++i) {
        uint16_t val = (uint16_t) encoded[i];

        // Range 1: Two characters packed (0x3800 - 0x47FF)
        if (val >= 0x3800 && val <= 0x47FF) {
            uint16_t packed = val - 0x3800;
            result += charset[packed & 0x3F];        // Lower 6 bits
            result += charset[(packed >> 6) & 0x3F]; // Upper 6 bits
        }
        // Range 2: One character packed (0x4800 - 0x483F)
        // This was the missing piece causing "garbage" characters at the end of strings.
        else if (val >= 0x4800 && val <= 0x483F) {
            uint16_t index = val - 0x4800;
            result += charset[index];
        }
        // Range 3: Special Sentinel (0x4840) -> '!'
        // Used for table names like "!Property" or "!_Columns"
        else if (val == 0x4840) {
            result += u'!';
        }
        // Range 4: Raw Characters (Pass-through)
        else {
            result += (char16_t) val;
        }
    }

    return result;
}

// Update PopulateItem to use SanitizeName
bool MSIFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    // Mode 1: Parsed Files
    if (!msiFiles.empty()) {
        // ... (Same as before) ...
        if (currentIterIndex >= msiFiles.size())
            return false;
        const auto& file = msiFiles[currentIterIndex];
        item.SetText(0, file.Name);
        item.SetText(1, file.Directory);
        item.SetText(2, file.Component);
        LocalString<32> sz;
        sz.Format("%u", file.Size);
        item.SetText(3, sz);
        item.SetText(4, file.Version);
        currentIterIndex++;
        return true;
    }

    // Mode 2: Raw Streams
    if (!currentIterFolder || currentIterIndex >= currentIterFolder->children.size())
        return false;

    DirEntry* child = &currentIterFolder->children[currentIterIndex];
    currentIterIndex++;

    item.SetText(0, child->decodedName);

    if (child->data.objectType == 1 || child->data.objectType == 5) {
        item.SetText(1, "Folder");
        item.SetText(2, "");
        item.SetExpandable(true);
    } else {
        item.SetText(1, "Stream");
        LocalString<32> sz;
        sz.Format("%llu", child->data.streamSize);
        item.SetText(2, sz);
        item.SetExpandable(false);
    }

    if (child->id < linearDirList.size()) {
        item.SetData<DirEntry>(linearDirList[child->id]);
    }
    return true;
}

// --- Viewer Interface ---

bool MSIFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    if (!msiFiles.empty()) {
        if (path.empty()) {
            currentIterIndex = 0;
            return true;
        }
        return false;
    }

    currentIterIndex = 0;
    if (path.empty())
        currentIterFolder = &rootDir;
    else
        currentIterFolder = parent.GetData<DirEntry*>();

    return currentIterFolder != nullptr;
}

void MSIFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto e = item.GetData<DirEntry>();
    if (e && e->data.objectType == 2) {
        bool isMini    = e->data.streamSize < header.miniStreamCutoffSize;
        Buffer content = GetStream(e->data.startingSectorLocation, e->data.streamSize, isMini);
        GView::App::OpenBuffer(content, e->decodedName, "", GView::App::OpenMethod::BestMatch, "bin");
    }
}

GView::Utils::JsonBuilderInterface* MSIFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddString("Type", "Microsoft Installer (MSI)");
    builder->AddUInt("Streams", (uint32) linearDirList.size());
    builder->AddUInt("TablesFound", (uint32) tables.size());
    return builder;
}

void MSIFile::UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings)
{
    settings.AddZone(0, 512, ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");

    auto addSectorZone = [&](uint32 sect, ColorPair col, std::string_view name) {
        uint64 offset = (uint64) (sect + 1) * sectorSize;
        settings.AddZone(offset, sectorSize, col, name);
    };

    // FAT & DIFAT
    std::vector<uint32> fatSectorLocations;
    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        fatSectorLocations.push_back(header.difat[i]);
    }

    uint32 currDifatSect = header.firstDifatSector;
    while (currDifatSect != ENDOFCHAIN && currDifatSect != NOSTREAM) {
        addSectorZone(currDifatSect, ColorPair{ Color::DarkRed, Color::DarkBlue }, "DIFAT");
        uint64 offset = (uint64) (currDifatSect + 1) * sectorSize;
        auto view     = this->obj->GetData().Get(offset, sectorSize, true);
        if (!view.IsValid())
            break;
        const uint32* ptr = reinterpret_cast<const uint32*>(view.GetData());
        uint32 count      = sectorSize / 4;
        for (uint32 k = 0; k < count - 1; k++) {
            if (ptr[k] != ENDOFCHAIN && ptr[k] != NOSTREAM)
                fatSectorLocations.push_back(ptr[k]);
        }
        currDifatSect = ptr[count - 1];
    }
    for (auto sect : fatSectorLocations) {
        addSectorZone(sect, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "FAT");
    }

    // Directory
    uint32 dirSect = header.firstDirSector;
    while (dirSect != ENDOFCHAIN && dirSect != NOSTREAM && dirSect < FAT.size()) {
        addSectorZone(dirSect, ColorPair{ Color::Olive, Color::DarkBlue }, "Directory");
        dirSect = FAT[dirSect];
    }

    // MiniFAT
    uint32 minifatSect = header.firstMiniFatSector;
    while (minifatSect != ENDOFCHAIN && minifatSect != NOSTREAM && minifatSect < FAT.size()) {
        addSectorZone(minifatSect, ColorPair{ Color::Teal, Color::DarkBlue }, "MiniFAT");
        minifatSect = FAT[minifatSect];
    }
}
