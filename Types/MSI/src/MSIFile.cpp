#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Utils;

MSIFile::MSIFile()
{
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

    LoadStringPool();
    LoadTables();

    return true;
}

// OLE Parsing Logic

bool MSIFile::LoadFAT()
{
    uint32 numSectors = header.numFatSectors;
    FAT.clear();
    FAT.reserve(numSectors * (sectorSize / 4));

    std::vector<uint32> difatList;
    difatList.reserve(numSectors);

    for (int i = 0; i < 109; i++) {
        if (header.difat[i] == ENDOFCHAIN || header.difat[i] == NOSTREAM)
            break;
        difatList.push_back(header.difat[i]);
    }

    uint32 currentDifatSector    = header.firstDifatSector;
    uint32 difatCount            = header.numDifatSectors;
    uint32 entriesPerDifatSector = (sectorSize / 4) - 1;

    for (uint32 i = 0; i < difatCount; i++) {
        if (currentDifatSector == ENDOFCHAIN || currentDifatSector == NOSTREAM)
            break;

        uint64 offset = (uint64) (currentDifatSector + 1) * sectorSize;
        auto view     = this->obj->GetData().Get(offset, sectorSize, true);
        CHECK(view.IsValid(), false, "Failed to read DIFAT sector");

        const uint32* data = reinterpret_cast<const uint32*>(view.GetData());
        for (uint32 k = 0; k < entriesPerDifatSector; k++) {
            if (data[k] == ENDOFCHAIN || data[k] == NOSTREAM)
                continue;
            difatList.push_back(data[k]);
        }

        currentDifatSector = data[entriesPerDifatSector];
    }

    for (uint32 sect : difatList) {
        uint64 offset   = (uint64) (sect + 1) * sectorSize;
        auto sectorView = this->obj->GetData().Get(offset, sectorSize, true);
        if (sectorView.IsValid()) {
            const uint32* sectorData = reinterpret_cast<const uint32*>(sectorView.GetData());
            uint32 count             = sectorSize / 4;
            for (uint32 k = 0; k < count; k++) {
                FAT.push_back(sectorData[k]);
            }
        }
    }
    return true;
}

std::u16string DecodeMSIName(const uint8* rawName, uint16 cbLength)
{
    if (cbLength < 2)
        return u"";

    int nulls = 0;
    for (int i = 1; i < cbLength; i += 2) {
        if (rawName[i] == 0)
            nulls++;
    }

    if (nulls > (cbLength / 4)) {
        return std::u16string((const char16_t*) rawName, (cbLength / 2) - 1);
    }

    std::u16string res;
    res.reserve(cbLength);
    for (int i = 0; i < cbLength; i++) {
        if (rawName[i] == 0)
            break;
        res.push_back((char16_t) rawName[i]);
    }

    return res;
}

bool MSIFile::LoadDirectory()
{
    Buffer dirStream = GetStream(header.firstDirSector, 0, false);
    CHECK(dirStream.GetLength() > 0, false, "Failed to read Directory stream");

    uint32 count = (uint32) dirStream.GetLength() / 128;
    linearDirList.clear();

    if (count > 0) {
        const DirectoryEntryData* d = (const DirectoryEntryData*) dirStream.GetData();

        rootDir.id   = 0;
        rootDir.data = d[0];
        if (d[0].nameLength > 0) {
            rootDir.name = DecodeMSIName((const uint8*) d[0].name, d[0].nameLength);
        }

        for (uint32 i = 0; i < count; i++) {
            DirEntry* e = new DirEntry();
            e->id       = i;
            e->data     = d[i];
            if (e->data.nameLength > 0) {
                e->name = DecodeMSIName((const uint8*) d[i].name, d[i].nameLength);
            }
            linearDirList.push_back(e);
        }
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
        for (size_t i = 0; i < count; i++) {
            miniFAT.push_back(ptr[i]);
        }
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
    uint32 sect       = startSector;
    uint32 loopSafety = 0;
    uint32 maxLoops   = 100000;

    while (sect != ENDOFCHAIN && sect != NOSTREAM) {
        if (loopSafety++ > maxLoops ||
            sect >= table.size())
            break;

        if (isMini) {
            uint64 fileOffset = (uint64) sect * sSize;
            if (fileOffset + sSize <= miniStream.GetLength()) {
                result.Add(BufferView(miniStream.GetData() + fileOffset, sSize));
            }
        } else {
            uint64 fileOffset = (uint64) (sect + 1) * sSize;
            auto chunk        = this->obj->GetData().CopyToBuffer(fileOffset, sSize);
            if (chunk.IsValid()) {
                result.Add(chunk);
            }
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
    
    std::function<void(uint32)> traverseSiblings = [&](uint32 nodeId) {
        if (nodeId == NOSTREAM || nodeId >= linearDirList.size())
            return;
        DirEntry* node = linearDirList[nodeId];
        traverseSiblings(node->data.leftSiblingId);
        siblingIDs.push_back(nodeId);
        traverseSiblings(node->data.rightSiblingId);
    };

    traverseSiblings(parent.data.childId);

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

// Database Logic 

std::u16string MsiDecompressName(std::u16string_view encoded)
{
    if (encoded.empty() || encoded[0] != 0x4840)
        return std::u16string(encoded);

    std::u16string result;
    result.reserve(encoded.length() * 2);
    result += u'!'; // Prefixul pentru stream-uri de sistem MSI

    static const char16_t charset[] = u"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";

    for (size_t i = 1; i < encoded.length(); ++i) {
        uint16_t val = (uint16_t) encoded[i];

        // MSI comprimã 2 caractere într-un singur uint16 în range-ul 0x3800 - 0x4840
        if (val >= 0x3800 && val < 0x4840) {
            uint16_t packed = val - 0x3800;
            result += charset[packed % 64];
            result += charset[packed / 64];
        } else {
            // Caracter literal sau marker de final
            result += (char16_t) val;
        }
    }
    return result;
}

bool MSIFile::LoadStringPool()
{
    DirEntry* entryPool = nullptr;
    DirEntry* entryData = nullptr;

    for (auto* e : linearDirList) {
        // IMPORTANT: Decodãm numele real al stream-ului
        std::u16string realName = MsiDecompressName(e->name);

        if (realName == u"!_StringPool")
            entryPool = e;
        else if (realName == u"!_StringData")
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
    stringPool.push_back(""); // Index 0 is null

    uint32 count          = bufPool.GetLength() / 4;
    const uint16* poolPtr = (const uint16*) bufPool.GetData();
    const char* dataPtr   = (const char*) bufData.GetData();
    uint32 dataOffset     = 0;

    for (uint32 i = 0; i < count; i++) {
        uint16 len = poolPtr[i * 2];
        uint16 ref = poolPtr[i * 2 + 1];

        if (len == 0) {
            stringPool.push_back("");
            continue;
        }

        if (dataOffset + len > bufData.GetLength())
            break;

        // Note: encoding can be checked here, assuming ASCII/CP1252 for viewer
        std::string s(dataPtr + dataOffset, len);
        stringPool.push_back(s);
        dataOffset += len;
    }
    return true;
}

bool MSIFile::LoadTables()
{
    tables.clear();
    for (auto* e : linearDirList) {
        std::u16string realName = MsiDecompressName(e->name);

        if (realName.length() > 1 && realName[0] == u'!') {
            std::u16string tableOnly = realName.substr(1);

            AppCUI::Utils::String utf8Name;
            utf8Name.Set(tableOnly);

            std::string nameStr = utf8Name.GetText();

            // Ignorãm stream-urile de sistem care nu sunt tabele de date
            if (nameStr == "_StringPool" || nameStr == "_StringData" || nameStr == "_Tables" || nameStr == "_Columns")
                continue;

            tables.push_back({ nameStr, "User Table", 0 });
        }
    }
    return true;
}
// Viewer Interface

bool MSIFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    currentIterIndex = 0;
    if (path.empty()) {
        currentIterFolder = &rootDir;
    } else {
        currentIterFolder = parent.GetData<DirEntry*>();
    }
    return currentIterFolder != nullptr;
}

bool MSIFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    if (!currentIterFolder || currentIterIndex >= currentIterFolder->children.size()) {
        return false;
    }

    DirEntry* child = &currentIterFolder->children[currentIterIndex];
    currentIterIndex++;

    item.SetText(0, child->name);

    if (child->data.objectType == 1 || child->data.objectType == 5) {
        item.SetText(1, "Folder");
        item.SetText(2, "");
        item.SetPriority(1);
        item.SetExpandable(true);
    } else if (child->data.objectType == 2) {
        item.SetText(1, "Stream");
        LocalString<32> sz;
        sz.Format("%llu", child->data.streamSize);
        item.SetText(2, sz);
        item.SetPriority(0);
        item.SetExpandable(false);
    }

    if (child->id < linearDirList.size()) {
        item.SetData<DirEntry>(linearDirList[child->id]);
    }
    return true;
}

void MSIFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto e = item.GetData<DirEntry>();
    if (e && e->data.objectType == 2) {
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