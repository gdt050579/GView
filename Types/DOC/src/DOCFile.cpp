#include "doc.hpp"

#include <fstream> // TODO: remove

namespace GView::Type::DOC
{
using namespace GView::View::LexicalViewer;

#define ENDOFCHAIN 0xfffffffe
#define FREESECT 0xffffffff
#define FATSECT 0xfffffffd
#define DIFSECT 0xfffffffc

DOCFile::DOCFile()
{
}

bool DOCFile::DecompressStream(BufferView bv, Buffer& decompressed)
{
    // TODO: document the compression algorithm and expose it into the core

    CHECK(bv[0] == 0x01, false, "");  // signature byte

    size_t index = 1;

    while (index < bv.GetLength()) {
        // loop over chunks

        size_t chunkStartIndex = index;

        uint16 header = bv[index] + (bv[index + 1] << 8);
        index += 2;

        uint16 chunkLength = header & 0x0fff; // + 3, for total size
        bool isCompressed  = header & 0x8000; // most significant bit

        uint8 headerSignature = (header & 0x7000) >> 12;
        CHECK(headerSignature == 0b011, false, ""); // fixed value

        if (!isCompressed) {
            CHECK(index + 4096 < bv.GetLength(), false, "");
            decompressed.Add(BufferView(bv.GetData() + index, 4096));
            index += 4096;
            continue;
        }

        // Token Sequence series
        size_t end = chunkStartIndex + chunkLength + 3;
        size_t decompressedChunkStart = decompressed.GetLength();
        while (index < end) {
            unsigned char flags = bv[index++];
            for (int i = 0; i < 8; ++i) {
                if (index >= end) {
                    break;
                }

                if (flags & 0x01) {
                    // 2 bytes (Copy Token)

                    int offsetBits = ceil(log2(decompressed.GetLength() - decompressedChunkStart)); // number of bits used for the offset value

                    if (offsetBits < 4) {
                        offsetBits = 4;
                    } else if (offsetBits > 12) {
                        offsetBits = 12;
                    }

                    uint16 token = bv[index] + (bv[index + 1] << 8);
                    uint16 offsetMask = 0xffff << (16 - offsetBits);

                    int offset = ((token & offsetMask) >> (16 - offsetBits)) + 1; // negative offset from the current decompressed position
                    int length = (token & ~offsetMask) + 3;                       // the stored value is 3 less than the actual value

                    // tail copy bytes may be written to the decompressed buffer while starting to copy the chunk
                    size_t startOffset = decompressed.GetLength() - offset;
                    for (size_t cursor = startOffset; cursor < startOffset + length; ++cursor) {
                        unsigned char byte = decompressed[cursor];
                        decompressed.Add(BufferView(&byte, 1));
                    }

                    index += 2;
                } else {
                    // 1 byte (Literal token)

                    unsigned char byte = bv[index];
                    decompressed.Add(BufferView(&byte, 1));
                    index++;
                }

                flags >>= 1;
            }
        }
    }

    return true;
}

bool DOCFile::ParseUncompressedDirStream(BufferView bv)
{
    ByteStream stream((void*) bv.GetData(), bv.GetLength());
    uint16 check;

    // PROJECTINFORMATION
    CHECK(stream.ReadAs<uint16>() == 0x01, false, "projectsyskind_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectsyskind_size");

    sysKind = (SysKind) stream.ReadAs<uint32>();

    check = stream.ReadAs<uint16>();
    if (check == 0x4a) {
        // PROJECTCOMPATVERSION
        CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectcompat_size");
        stream.Seek(sizeof(uint32)); // compatVersion skipped for now
        check = stream.ReadAs<uint16>();
    }

    CHECK(check == 0x02, false, "projectlcid_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectlcid_size");
    CHECK(stream.ReadAs<uint32>() == 0x0409, false, "projectlcid_lcid");

    CHECK(stream.ReadAs<uint16>() == 0x14, false, "projectlcidinvoke_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectlcidinvoke_size");
    CHECK(stream.ReadAs<uint32>() == 0x0409, false, "lcidinvoke");

    CHECK(stream.ReadAs<uint16>() == 0x03, false, "projectcodepage_id");
    CHECK(stream.ReadAs<uint32>() == 0x02, false, "projectcodepage_size");
    auto codePage = stream.ReadAs<uint16>();

    CHECK(stream.ReadAs<uint16>() == 0x04, false, "projectname_id");
    auto projectName_size = stream.ReadAs<uint32>();
    CHECK(projectName_size >= 1 && projectName_size <= 128, false, "projectname_size");
    projectName = String(stream.Read(projectName_size));
    
    CHECK(stream.ReadAs<uint16>() == 0x05, false, "projectdocstring_id");
    auto projectDocString_size = stream.ReadAs<uint32>();
    CHECK(projectDocString_size <= 2000, false, "projectdocstring_size");
    docString = String(stream.Read(projectDocString_size));

    CHECK(stream.ReadAs<uint16>() == 0x40, false, "reserved");
    auto projectDocStringUnicode_size = stream.ReadAs<uint32>();
    CHECK(projectDocStringUnicode_size % 2 == 0, false, "projectDocStringUnicode_size");
    UnicodeStringBuilder projectDocStringUnicode(stream.Read(projectDocStringUnicode_size)); 

    CHECK(stream.ReadAs<uint16>() == 0x06, false, "helpFile1_id");
    auto helpFile1_size = stream.ReadAs<uint32>();
    CHECK(helpFile1_size <= 260, false, "helpFile1_size");
    String helpFile1(stream.Read(helpFile1_size));
    CHECK(stream.ReadAs<uint16>() == 0x3d, false, "reserved");
    auto helpFile2_size = stream.ReadAs<uint32>();
    CHECK(helpFile2_size == helpFile1_size, false, "helpFile2_size");
    String helpFile2(stream.Read(helpFile2_size));
    for (uint32 i = 0; i < helpFile1_size; ++i) {
        CHECK(helpFile1[i] == helpFile2[i], false, "helpFiles");
    }

    helpFile = helpFile1;

    CHECK(stream.ReadAs<uint16>() == 0x07, false, "projectHelpContext_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectHelpContext_size");
    auto projectHelpContext = stream.ReadAs<uint32>();
    
    CHECK(stream.ReadAs<uint16>() == 0x08, false, "projectLibFlags_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectLibFlags_size");
    CHECK(stream.ReadAs<uint32>() == 0x00, false, "projectLibFlags");

    CHECK(stream.ReadAs<uint16>() == 0x09, false, "projectVersoin_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "reserved");
    dirMajorVersion = stream.ReadAs<uint32>();
    dirMinorVersion = stream.ReadAs<uint16>();

    CHECK(stream.ReadAs<uint16>() == 0x0c, false, "projectConstants_id");
    auto projectConstants_size = stream.ReadAs<uint32>();
    CHECK(projectConstants_size <= 1015, false, "projectConstants_size");
    
    constants = String(stream.Read(projectConstants_size));
    CHECK(stream.ReadAs<uint16>() == 0x3c, false, "reserved");

    auto projectConstantsUnicode_size = stream.ReadAs<uint32>();
    CHECK(projectConstantsUnicode_size % 2 == 0, false, "projectConstantsUnicode_size");
    UnicodeStringBuilder constantsUnicode(stream.Read(projectConstantsUnicode_size));

    uint32 recordIndex = 0;

    // PROJECTREFERENCES
    while (true) {
        // NameRecord
        auto referenceName_id = stream.ReadAs<uint16>();
        if (referenceName_id == 0x0f) {
            // end of Records array and beginning of PROJECTMODULES Record
            break;
        }

        CHECK(referenceName_id == 0x16, false, "referenceName_id");
        auto referenceName_size = stream.ReadAs<uint32>();
        String referenceName(stream.Read(referenceName_size));
        CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
        auto referenceNameUnicode_size = stream.ReadAs<uint32>();
        UnicodeStringBuilder referenceNameUnicode(stream.Read(referenceNameUnicode_size));

        // ReferenceRecord
        auto referenceRecord_type = stream.ReadAs<uint16>();
        switch (referenceRecord_type) {
        case 0x2f:
        {
            // REFERENCECONTROL Record

            auto& record = referenceControlRecords.emplace_back();
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // SizeTwiddled
            auto sizeOfLibidTwiddled = stream.ReadAs<uint32>();
            record.libidTwiddled = String(stream.Read(sizeOfLibidTwiddled));
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved1");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved2");

            check = stream.ReadAs<uint16>();

            if (check == 0x16) {
                // optional NameRecordExtended
                auto sizeOfName = stream.ReadAs<uint32>();
                record.nameRecordExtended = String(stream.Read(sizeOfName));
                CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
                auto sizeOfNameUnicode = stream.ReadAs<uint32>();
                UnicodeStringBuilder nameUnicode(stream.Read(sizeOfNameUnicode));
                check = stream.ReadAs<uint16>();
            }

            CHECK(check == 0x30, false, "reserved3");
            stream.Seek(sizeof(uint32)); // SizeExtended
            auto sizeOfLibidExtended = stream.ReadAs<uint32>();
            record.libidExtended = String(stream.Read(sizeOfLibidExtended));
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved4");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved5");
            record.originalTypeLib = BufferView(stream.Read(16));
            record.cookie = stream.ReadAs<uint32>();

            break;
        }
        case 0x33: {
            // REFERENCEORIGINAL Record

            auto& record = referenceOriginalRecords.emplace_back();
            record.recordIndex = recordIndex;

            auto sizeOfLibidOriginal = stream.ReadAs<uint32>();
            record.libidOriginal = String(stream.Read(sizeOfLibidOriginal));
            CHECK(stream.ReadAs<uint16>() == 0x2f, false, "referenceControl_id");

            stream.Seek(sizeof(uint32)); // SizeTwiddled
            auto sizeOfLibidTwiddled = stream.ReadAs<uint32>();
            record.referenceControl.libidTwiddled = String(stream.Read(sizeOfLibidTwiddled));
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved1");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved2");

            check = stream.ReadAs<uint16>();

            if (check == 0x16) {
                // optional NameRecordExtended
                auto sizeOfName = stream.ReadAs<uint32>();
                record.referenceControl.nameRecordExtended = String(stream.Read(sizeOfName));
                CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
                auto sizeOfNameUnicode = stream.ReadAs<uint32>();
                UnicodeStringBuilder nameUnicode(stream.Read(sizeOfNameUnicode));
                check = stream.ReadAs<uint16>();
            }

            CHECK(check == 0x30, false, "reserved3");
            stream.Seek(sizeof(uint32)); // SizeExtended
            auto sizeOfLibidExtended = stream.ReadAs<uint32>();
            record.referenceControl.libidExtended = String(stream.Read(sizeOfLibidExtended));
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved4");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved5");
            record.referenceControl.originalTypeLib = BufferView(stream.Read(16));
            record.referenceControl.cookie = stream.ReadAs<uint32>();

            break;
        }
        case 0x0d: {
            // REFERENCEREGISTERED Record

            auto& record = referenceRegisteredRecords.emplace_back();
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // ignored Size

            auto sizeOfLibid = stream.ReadAs<uint32>();
            record.libid = String(stream.Read(sizeOfLibid));
            
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved1");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved2");

            break;
        }
        case 0x0e: {
            // REFERENCEPROJECT Record

            auto& record = referenceProjectRecords.emplace_back();
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // ignored Size
            auto sizeOfLibidAbsolute = stream.ReadAs<uint32>();
            record.libidAbsolute = String(stream.Read(sizeOfLibidAbsolute));
            auto sizeOfLibidRelative = stream.ReadAs<uint32>();
            record.libidRelative = String(stream.Read(sizeOfLibidRelative));

            record.majorVersion = stream.ReadAs<uint32>();
            record.minorVersion = stream.ReadAs<uint16>();

            break;
        }
        default:
            return false;
        }

        recordIndex++;
    }

    // PROJECTMODULES
    CHECK(stream.ReadAs<uint32>() == 0x02, false, "size");
    modulesCount = stream.ReadAs<uint16>();
    CHECK(stream.ReadAs<uint16>() == 0x13, false, "projectCookie_id");
    CHECK(stream.ReadAs<uint32>() == 0x02, false, "projectCookie_size");
    stream.Seek(sizeof(uint16));  // ignored Cookie

    moduleRecords.reserve(modulesCount);

    // array of MODULE records
    for (uint32 moduleIndex = 0; moduleIndex < modulesCount; ++moduleIndex) {
        // TODO: check this - MUST have a corresponding <ProjectModule> specified in PROJECT Stream
        MODULE_Record& moduleRecord = moduleRecords.emplace_back();

        CHECK(stream.ReadAs<uint16>() == 0x19, false, "moduleName_id");
        auto sizeOfModuleName = stream.ReadAs<uint32>();
 
        moduleRecord.moduleName = String(stream.Read(sizeOfModuleName));

        CHECK(stream.ReadAs<uint16>() == 0x47, false, "moduleNameUnicode_id");
        auto sizeOfModuleNameUnicode = stream.ReadAs<uint32>();
        CHECK(sizeOfModuleNameUnicode % 2 == 0, false, "sizeOfModuleNameUnicode");
        UnicodeStringBuilder moduleNameUnicode(stream.Read(sizeOfModuleNameUnicode));

        CHECK(stream.ReadAs<uint16>() == 0x1a, false, "moduleStreamName_id");
        auto sizeOfStreamName = stream.ReadAs<uint32>();
        moduleRecord.streamName = String(stream.Read(sizeOfStreamName));
        CHECK(stream.ReadAs<uint16>() == 0x32, false, "reserved");

        auto sizeOfStreamNameUnicode = stream.ReadAs<uint32>();
        CHECK(sizeOfStreamNameUnicode % 2 == 0, false, "sizeOfStreamNameUnicode");
        String streamNameUnicode(stream.Read(sizeOfStreamNameUnicode));

        CHECK(stream.ReadAs<uint16>() == 0x1c, false, "moduleDocString_id");
        auto sizeOfDocString = stream.ReadAs<uint32>();
 
        moduleRecord.docString = String(stream.Read(sizeOfDocString));
        CHECK(stream.ReadAs<uint16>() == 0x48, false, "reserved");
        auto sizeOfDocStringUnicode = stream.ReadAs<uint32>();
        CHECK(sizeOfDocStringUnicode % 2 == 0, false, "sizeOfDocStringUnicode");
        UnicodeStringBuilder docStringUnicode(stream.Read(sizeOfDocStringUnicode));

        CHECK(stream.ReadAs<uint16>() == 0x31, false, "moduleOffset_id");
        CHECK(stream.ReadAs<uint32>() == 0x04, false, "moduleOffset_size");
        moduleRecord.textOffset = stream.ReadAs<uint32>();

        CHECK(stream.ReadAs<uint16>() == 0x1e, false, "moduleHelpContext_id");
        CHECK(stream.ReadAs<uint32>() == 0x04, false, "moduleHelpContext_size");
        moduleRecord.helpContext = stream.ReadAs<uint32>();

        CHECK(stream.ReadAs<uint16>() == 0x2c, false, "moduleCookie_id");
        CHECK(stream.ReadAs<uint32>() == 0x02, false, "moduleCookie_size");
        stream.Seek(sizeof(uint16)); // ignored Cookie

        auto moduleType_id = stream.ReadAs<uint16>();
        CHECK(moduleType_id == 0x21 || moduleType_id == 0x22, false, "moduleType_id");
        stream.Seek(sizeof(uint32)); // ignored Reserved

        check = stream.ReadAs<uint16>();
        if (check == 0x25) {
            // optional MODULEREADONLY
            stream.Seek(sizeof(uint32)); // ignored Reserved
            check = stream.ReadAs<uint16>();
        }

        if (check == 0x28) {
            // optional MODULEPRIVATE
            stream.Seek(sizeof(uint32)); // ignored Reserved
            check = stream.ReadAs<uint16>();
        }

        auto terminator = check;
        CHECK(terminator == 0x2b, false, "terminator");
        stream.Seek(sizeof(uint32)); // ignored Reserved
    }

    CHECK(stream.ReadAs<uint16>() == 0x10, false, "terminator");
    stream.Seek(sizeof(uint32)); // ignored Reserved

    CHECK(stream.GetCursor() == stream.GetSize(), false, "buffer still available");
    return true;
}

bool DOCFile::ParseModuleStream(BufferView bv, const MODULE_Record& moduleRecord, Buffer& text)
{
    size_t moduleTextOffset = moduleRecord.textOffset;
    ByteStream stream(bv);
    stream.Seek(moduleTextOffset);
    auto compressed = stream.Read(stream.GetSize() - stream.GetCursor());
    CHECK(DecompressStream(compressed, text), false, "decompress");

    return true;
}


Buffer DOCFile::OpenCFStream(const CFDirEntry& entry)
{
    CHECK(entry.data.objectType == 0x02, Buffer(), "incorrect entry");

    auto sect                    = entry.data.startingSectorLocation;
    auto size                    = entry.data.streamSize;
    bool useMiniFAT              = size < miniStreamCutoffSize;
    
    return OpenCFStream(sect, size, useMiniFAT);
}

Buffer DOCFile::OpenCFStream(uint32 sect, uint32 size, bool useMiniFAT)
{
    BufferView stream;
    BufferView fat;
    uint32 usedSectorSize;
    uint32 offset;

    if (useMiniFAT) {
        // use miniFAT
        stream         = miniStream;
        fat            = miniFAT;
        usedSectorSize = miniSectorSize;
        offset         = 0;
    } else {
        // use FAT
        stream         = vbaProjectBuffer;
        fat            = FAT;
        usedSectorSize = sectorSize;
        offset         = usedSectorSize;
    }

    Buffer data;
    uint16 actualNumberOfSectors = ((size + usedSectorSize - 1) / usedSectorSize);
    for (uint32 i = 0; i < actualNumberOfSectors; ++i) {
        if (sect == ENDOFCHAIN) {
            // end of sector chain
            break;
        }

        data.Add(ByteStream(stream).Seek(offset + usedSectorSize * sect).Read(usedSectorSize));

        if (sect * sizeof(uint32) >= fat.GetLength()) {
            return Buffer();
        }
        sect = *(((uint32*) fat.GetData()) + sect); // get the next sect
    }

    if (data.GetLength() > size) {
        data.Resize(size);
    }

    return data;
}


void DOCFile::DisplayAllVBAProjectFiles(CFDirEntry& entry)
{
    auto type = entry.data.objectType;
    char16* name = (char16*) entry.data.nameUnicode;

    if (type == 0x02) {
        Buffer entryBuffer = DOCFile::OpenCFStream(entry);

        GView::App::OpenBuffer(entryBuffer, name, "", GView::App::OpenMethod::BestMatch, "bin");
    }

    for (auto& child : entry.children) {
        DisplayAllVBAProjectFiles(child);
    }
}


bool DOCFile::FindModulesPath(const CFDirEntry& entry, UnicodeStringBuilder& path)
{
    std::u16string_view name((char16*) entry.data.nameUnicode, entry.data.nameLength / 2 - 1); // take into account the null character

    if (!entry.children.size()) {
        return name == u"dir";
    }

    for (const CFDirEntry& child : entry.children) {
        UnicodeStringBuilder pathPart;
        if (FindModulesPath(child, pathPart)) {
            path.Add(name);
            path.Add("/");
            path.Add(pathPart);
            return true;
        }
    }

    return false;
}


bool DOCFile::ParseVBAProject()
{
    ByteStream stream(vbaProjectBuffer);

    for (uint32 i = 0; i < ARRAY_LEN(CF_HEADER_SIGNATURE); ++i) {
        CHECK(stream.ReadAs<uint8>() == CF_HEADER_SIGNATURE[i], false, "headerSignature");
    }

    CHECK(stream.ReadAs<uint64>() == 0, false, "headerCLSID");
    CHECK(stream.ReadAs<uint64>() == 0, false, "headerCLSID");

    cfMinorVersion = stream.ReadAs<uint16>();  // TODO: This field SHOULD be set to 0x003E if the major version field is either 0x0003 or 0x0004.
    cfMajorVersion = stream.ReadAs<uint16>();
    CHECK(cfMajorVersion == 0x03 || cfMajorVersion == 0x04, false, "majorVersion");

    CHECK(stream.ReadAs<uint16>() == 0xfffe, false, "byteOrder");
    auto sectorShift = stream.ReadAs<uint16>();
    CHECK((cfMajorVersion == 0x03 && sectorShift == 0x09) || (cfMajorVersion == 0x04 && sectorShift == 0x0c), false, "sectorShift");
    sectorSize = 1 << sectorShift;
    
    auto miniSectorShift = stream.ReadAs<uint16>();
    CHECK(miniSectorShift == 0x06, false, "miniSectorShift");
    miniSectorSize = 1 << miniSectorShift;

    CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved");
    CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved");

    auto numberOfDirectorySectors = stream.ReadAs<uint32>();
    if (cfMajorVersion == 0x03) {
        CHECK(numberOfDirectorySectors == 0x00, false, "numberOfDirectorySectors");
    }

    numberOfFatSectors = stream.ReadAs<uint32>();
    firstDirectorySectorLocation = stream.ReadAs<uint32>();
    transactionSignatureNumber = stream.ReadAs<uint32>();  // incremented every time the file is saved
    
    miniStreamCutoffSize = stream.ReadAs<uint32>();
    CHECK(miniStreamCutoffSize == 0x1000, false, "miniStreamCutoffSize");

    firstMiniFatSectorLocation = stream.ReadAs<uint32>();
    numberOfMiniFatSectors     = stream.ReadAs<uint32>();
    firstDifatSectorLocation   = stream.ReadAs<uint32>();
    numberOfDifatSectors       = stream.ReadAs<uint32>();

    uint32 DIFAT[DIFAT_LOCATIONS_COUNT]; // the first DIFAT sector locations of the compound file
    {
        auto difatBv = stream.Read(DIFAT_LOCATIONS_COUNT * sizeof(*DIFAT));
        memcpy(DIFAT, (void*) difatBv.GetData(), difatBv.GetLength());
    }

    if (cfMajorVersion == 0x04) {
        // check if the next 3584 bytes are 0
        while (stream.GetCursor() < sectorSize) {
            CHECK(stream.ReadAs<uint8>() == 0x00, false, "zeroCheck");
        }
    }

    // load FAT
    for (size_t locationIndex = 0; locationIndex < DIFAT_LOCATIONS_COUNT; ++locationIndex) {
        uint32 sect = DIFAT[locationIndex];
        if (sect == ENDOFCHAIN || sect == FREESECT) {
            // end of sector chain
            break;
        }

        // get the sector data
        size_t byteOffset = sectorSize * (sect + 1);
        BufferView sector(vbaProjectBuffer.GetData() + byteOffset, sectorSize);
        FAT.Add(sector);
    }

    uint16 actualNumberOfSectors = ((vbaProjectBuffer.GetLength() + sectorSize - 1) / sectorSize) - 1;
    if (FAT.GetLength() > actualNumberOfSectors * sizeof(uint32)) {
        FAT.Resize(actualNumberOfSectors * sizeof(uint32));
    }

    // load directory
    Buffer directoryData = OpenCFStream(firstDirectorySectorLocation, vbaProjectBuffer.GetLength(), false);

    // parse dir entries, starting with root entry
    root = CFDirEntry(directoryData, 0);
    root.BuildStorageTree();

    uint32 streamSize = numberOfMiniFatSectors * sectorSize;
    uint16 actualNumberOfMinisectors = (root.data.streamSize + miniSectorSize - 1) / miniSectorSize;

    // load miniFAT
    miniFAT = OpenCFStream(firstMiniFatSectorLocation, streamSize, false); // will be interpreted as uint32*
    if (miniFAT.GetLength() > actualNumberOfMinisectors * sizeof(uint32)) {
        miniFAT.Resize(actualNumberOfMinisectors * sizeof(uint32));
    }

    // load ministream
    uint32 miniStreamSize = root.data.streamSize;
    miniStream            = OpenCFStream(root.data.startingSectorLocation, miniStreamSize, false);

    // find file
    UnicodeStringBuilder modulesPathUsb;
    CHECK(FindModulesPath(root, modulesPathUsb), false, "modulesPath");
    modulesPath = modulesPathUsb;

    CFDirEntry dir;
    CHECK(root.FindChildByName(modulesPath + u"dir", dir), false, "");
    Buffer dirData = OpenCFStream(dir);

    Buffer decompressedDirData;
    CHECK(DecompressStream(dirData, decompressedDirData), false, "decompress dir stream");
    CHECK(ParseUncompressedDirStream(decompressedDirData), false, "parse dir stream");

    return true;
}

bool DOCFile::ProcessData()
{
    vbaProjectBuffer = obj->GetData().GetEntireFile();
    CHECK(ParseVBAProject(), false, "");
    return true;
}

bool DOCFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    moduleRecordIndex = 0;
    return true;
}

bool DOCFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    MODULE_Record& moduleRecord = moduleRecords[moduleRecordIndex];

    item.SetText(0, moduleRecord.moduleName);
    item.SetText(1, moduleRecord.streamName);

    std::u16string absoluteStreamName = modulesPath;
    absoluteStreamName.append(UnicodeStringBuilder(moduleRecord.streamName));
    CFDirEntry moduleEntry;
    CHECK(root.FindChildByName(absoluteStreamName, moduleEntry), false, "");
    Buffer moduleBuffer = OpenCFStream(moduleEntry);
    Buffer decompressed;
    ParseModuleStream(moduleBuffer, moduleRecord, decompressed);

    // TODO: add the creation time and modified time of the module stream

    item.SetText(2, String().Format("%u", decompressed.GetLength()));

    item.SetText(3, moduleRecord.docString);

    item.SetData<MODULE_Record>(&moduleRecord);

    moduleRecordIndex++;
    return moduleRecordIndex < moduleRecords.size();
}

void DOCFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    auto moduleRecord = item.GetData<MODULE_Record>();

    std::u16string absoluteStreamName = modulesPath;
    absoluteStreamName.append(UnicodeStringBuilder(moduleRecord->streamName));
    CFDirEntry moduleEntry;
    CHECKRET(root.FindChildByName(absoluteStreamName, moduleEntry), "");
    Buffer moduleBuffer = OpenCFStream(moduleEntry);

    Buffer decompressed;
    if (!ParseModuleStream(moduleBuffer, moduleRecord, decompressed)) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Module parse error!");
    }
    GView::App::OpenBuffer(decompressed, moduleRecord->streamName, "", GView::App::OpenMethod::ForceType, "VBA");
}
} // namespace GView::Type::DOC
