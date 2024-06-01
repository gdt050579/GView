#include "doc.hpp"

#include <fstream>  // TODO: remove

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

bool DecompressStream(BufferView bv, Buffer& decompressed)
{
    // TODO: document the compression algorithm and expose it into the core

    CHECK(bv[0] == 0x01, false, "");  // signature byte

    size_t index = 1;

    while (index < bv.GetLength()) {
        // loop over chunks

        uint16 header = bv[index] + (bv[index + 1] << 8);
        index += 2;

        uint16 chunkLength = header & 0x0fff; // + 3, for total size
        bool isCompressed  = header & 0x8000; // most significant bit

        CHECK((header & 0x7000) >> 12 == 0b011, false, ""); // fixed value

        if (!isCompressed) {
            // TODO: verify
            CHECK(index + 4096 < bv.GetLength(), false, "");
            decompressed.Add(BufferView(bv.GetData() + index, 4096));
            index += 4096;
            continue;
        }

        // Token Sequence series
        while (index < chunkLength + 3) {
            unsigned char flags = bv[index++];
            for (int i = 0; i < 8; ++i) {
                if (index > chunkLength + 3) {
                    break;
                }

                if (flags & 0x01) {
                    // 2 bytes (Copy Token)

                    int offsetBits = ceil(log2(decompressed.GetLength())); // number of bits used for the offset value

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

    BufferView view(decompressed.GetData(), decompressed.GetLength());

    GView::App::OpenBuffer(decompressed, "decompressed", "", GView::App::OpenMethod::BestMatch, "bin");

    return true;
}

enum SysKind { Win16Bit = 0, Win32Bit, Macintosh, Win64Bit };


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


bool ParseUncompressedDirStream(BufferView bv)
{
    ByteStream stream((void*) bv.GetData(), bv.GetLength());
    uint16 check;

    // PROJECTINFORMATION
    CHECK(stream.ReadAs<uint16>() == 0x01, false, "projectsyskind_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectsyskind_size");

    SysKind sysKind = (SysKind) stream.ReadAs<uint32>();

    CHECK(stream.ReadAs<uint16>() == 0x02, false, "projectlcid_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectlcid_size");
    CHECK(stream.ReadAs<uint32>() == 0x0409, false, "projectlcid_lcid");

    CHECK(stream.ReadAs<uint16>() == 0x14, false, "projectlcidinvoke_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectlcidinvoke_size");
    CHECK(stream.ReadAs<uint32>() == 0x0409, false, "lcidinvoke");

    CHECK(stream.ReadAs<uint16>() == 0x03, false, "projectcodepage_id");
    CHECK(stream.ReadAs<uint32>() == 0x02, false, "projectcodepage_size");
    auto codePage = stream.ReadAs<uint16>();  // TODO: what to do with the codec? 

    CHECK(stream.ReadAs<uint16>() == 0x04, false, "projectname_id");
    auto projectName_size = stream.ReadAs<uint32>();
    CHECK(projectName_size >= 1 && projectName_size <= 128, false, "projectname_size");
    String projectName(stream.Read(projectName_size));
    
    CHECK(stream.ReadAs<uint16>() == 0x05, false, "projectdocstring_id");
    auto projectDocString_size = stream.ReadAs<uint32>();
    CHECK(projectDocString_size <= 2000, false, "projectdocstring_size");
    String docstring(stream.Read(projectDocString_size));  // TODO: decode

    CHECK(stream.ReadAs<uint16>() == 0x40, false, "reserved");
    auto projectDocStringUnicode_size = stream.ReadAs<uint32>();
    CHECK(projectDocStringUnicode_size % 2 == 0, false, "projectDocStringUnicode_size");
    UnicodeStringBuilder projectDocStringUnicode(stream.Read(projectDocStringUnicode_size));  // TODO: decode

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

    CHECK(stream.ReadAs<uint16>() == 0x07, false, "projectHelpContext_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectHelpContext_size");
    auto projectHelpContext = stream.ReadAs<uint32>();
    
    CHECK(stream.ReadAs<uint16>() == 0x08, false, "projectLibFlags_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "projectLibFlags_size");
    CHECK(stream.ReadAs<uint32>() == 0x00, false, "projectLibFlags");

    CHECK(stream.ReadAs<uint16>() == 0x09, false, "projectVersoin_id");
    CHECK(stream.ReadAs<uint32>() == 0x04, false, "reserved");
    auto versionMajor = stream.ReadAs<uint32>();
    auto versionMinor = stream.ReadAs<uint16>();

    CHECK(stream.ReadAs<uint16>() == 0x0c, false, "projectConstants_id");
    auto projectConstants_size = stream.ReadAs<uint32>();
    CHECK(projectConstants_size <= 1015, false, "projectConstants_size");
    
    String constants(stream.Read(projectConstants_size));  // TODO: decode and ABNF
    CHECK(stream.ReadAs<uint16>() == 0x3c, false, "reserved");

    auto projectConstantsUnicode_size = stream.ReadAs<uint32>();
    CHECK(projectConstantsUnicode_size % 2 == 0, false, "projectConstantsUnicode_size");
    UnicodeStringBuilder constantsUnicode(stream.Read(projectConstantsUnicode_size));  // TODO: decode and ABNF

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
        String referenceName(stream.Read(referenceName_size));  // TODO: decode and ABNF
        CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
        auto referenceNameUnicode_size = stream.ReadAs<uint32>();
        UnicodeStringBuilder referenceNameUnicode(stream.Read(referenceNameUnicode_size));

        // ReferenceRecord
        auto referenceRecord_type = stream.ReadAs<uint16>();
        switch (referenceRecord_type) {
        case 0x2f:
        {
            // REFERENCECONTROL Record

            REFERENCECONTROL_Record record;
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // SizeTwiddled
            auto sizeOfLibidTwiddled = stream.ReadAs<uint32>();
            // TODO: check string - https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/d64485fa-8562-4726-9c5e-11e8f01a81c0
            record.libidTwiddled = String(stream.Read(sizeOfLibidTwiddled));
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved1");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved2");

            check = stream.ReadAs<uint16>();

            if (check == 0x16) {
                // optional NameRecordExtended
                auto sizeOfName = stream.ReadAs<uint32>();
                record.nameRecordExtended = String(stream.Read(sizeOfName));  // TODO: decode and ABNF
                CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
                auto sizeOfNameUnicode = stream.ReadAs<uint32>();
                UnicodeStringBuilder nameUnicode(stream.Read(sizeOfNameUnicode));
                check = stream.ReadAs<uint16>();
            }

            CHECK(check == 0x30, false, "reserved3");
            stream.Seek(sizeof(uint32)); // SizeExtended
            auto sizeOfLibidExtended = stream.ReadAs<uint32>();
            record.libidExtended = String(stream.Read(sizeOfLibidExtended));  // TODO: decode and ABNF
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved4");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved5");
            record.originalTypeLib = BufferView(stream.Read(16));
            record.cookie = stream.ReadAs<uint32>();

            break;
        }
        case 0x33: {
            // REFERENCEORIGINAL Record

            REFERENCEORIGINAL_Record record;
            record.recordIndex = recordIndex;

            auto sizeOfLibidOriginal = stream.ReadAs<uint32>();
            record.libidOriginal = String(stream.Read(sizeOfLibidOriginal));  // TODO: decode and ABNF
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
                record.referenceControl.nameRecordExtended = String(stream.Read(sizeOfName));  // TODO: decode and ABNF
                CHECK(stream.ReadAs<uint16>() == 0x3e, false, "reserved");
                auto sizeOfNameUnicode = stream.ReadAs<uint32>();
                UnicodeStringBuilder nameUnicode(stream.Read(sizeOfNameUnicode));
                check = stream.ReadAs<uint16>();
            }

            CHECK(check == 0x30, false, "reserved3");
            stream.Seek(sizeof(uint32)); // SizeExtended
            auto sizeOfLibidExtended = stream.ReadAs<uint32>();
            record.referenceControl.libidExtended = String(stream.Read(sizeOfLibidExtended));  // TODO: decode and ABNF
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved4");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved5");
            record.referenceControl.originalTypeLib = BufferView(stream.Read(16));
            record.referenceControl.cookie = stream.ReadAs<uint32>();

            break;
        }
        case 0x0d: {
            // REFERENCEREGISTERED Record

            REFERENCEREGISTERED_Record record;
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // ignored Size

            auto sizeOfLibid = stream.ReadAs<uint32>();
            record.libid = String(stream.Read(sizeOfLibid));  // TODO: decode and ABNF
            
            CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved1");
            CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved2");

            break;
        }
        case 0x0e: {
            // REFERENCEPROJECT Record

            REFERENCEPROJECT_Record record;
            record.recordIndex = recordIndex;

            stream.Seek(sizeof(uint32)); // ignored Size
            auto sizeOfLibidAbsolute = stream.ReadAs<uint32>();
            record.libidAbsolute = String(stream.Read(sizeOfLibidAbsolute));  // TODO: decode and ABNF
            auto sizeOfLibidRelative = stream.ReadAs<uint32>();
            record.libidRelative = String(stream.Read(sizeOfLibidRelative));  // TODO: decode and ABNF

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
    auto modulesCount = stream.ReadAs<uint16>();
    CHECK(stream.ReadAs<uint16>() == 0x13, false, "projectCookie_id");
    CHECK(stream.ReadAs<uint32>() == 0x02, false, "projectCookie_size");
    stream.Seek(sizeof(uint16));  // ignored Cookie

    std::vector<MODULE_Record> moduleRecords(modulesCount);

    // array of MODULE records
    for (uint32 moduleIndex = 0; moduleIndex < modulesCount; ++moduleIndex) {
        // TODO: check this - MUST have a corresponding <ProjectModule> specified in PROJECT Stream

        MODULE_Record& moduleRecord = moduleRecords[moduleIndex];

        CHECK(stream.ReadAs<uint16>() == 0x19, false, "moduleName_id");
        auto sizeOfModuleName = stream.ReadAs<uint32>();
        // TODO: decode and ABNF
        moduleRecord.moduleName = String(stream.Read(sizeOfModuleName));

        CHECK(stream.ReadAs<uint16>() == 0x47, false, "moduleNameUnicode_id");
        auto sizeOfModuleNameUnicode = stream.ReadAs<uint32>();
        CHECK(sizeOfModuleNameUnicode % 2 == 0, false, "sizeOfModuleNameUnicode");
        UnicodeStringBuilder moduleNameUnicode(stream.Read(sizeOfModuleNameUnicode));  // TODO: decode and ABNF

        CHECK(stream.ReadAs<uint16>() == 0x1a, false, "moduleStreamName_id");
        auto sizeOfStreamName = stream.ReadAs<uint32>();
        moduleRecord.streamName = String(stream.Read(sizeOfStreamName)); // TODO: decode and ABNF
        CHECK(stream.ReadAs<uint16>() == 0x32, false, "reserved");

        auto sizeOfStreamNameUnicode = stream.ReadAs<uint32>();
        CHECK(sizeOfStreamNameUnicode % 2 == 0, false, "sizeOfStreamNameUnicode");
        String streamNameUnicode(stream.Read(sizeOfStreamNameUnicode));  // TODO: decode and ABNF

        CHECK(stream.ReadAs<uint16>() == 0x1c, false, "moduleDocString_id");
        auto sizeOfDocString = stream.ReadAs<uint32>();
        // TODO: decode and ABNF
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

bool ParseModuleStream(BufferView bv)
{
    constexpr size_t moduleTextOffset = 2607;  // TODO: in the future get this from the parsed dir stream

    ByteStream stream((void*) bv.GetData(), bv.GetLength());

    stream.Seek(moduleTextOffset);

    auto compressed = stream.Read(stream.GetSize() - stream.GetCursor());

    Buffer decompressed;

    DecompressStream(compressed, decompressed);
    return true;
}

bool ParseVBAProject(BufferView bv)
{
    ByteStream stream((void*) bv.GetData(), bv.GetLength());

    // TODO: extract in outer stuff
    constexpr uint8 headerSignature[] = { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 };
    for (uint32 i = 0; i < ARRAY_LEN(headerSignature); ++i) {
        CHECK(stream.ReadAs<uint8>() == headerSignature[i], false, "headerSignature");
    }

    CHECK(stream.ReadAs<uint64>() == 0, false, "headerCLSID");
    CHECK(stream.ReadAs<uint64>() == 0, false, "headerCLSID");

    auto minorVersion = stream.ReadAs<uint16>();  // TODO: This field SHOULD be set to 0x003E if the major version field is either 0x0003 or 0x0004.
    auto majorVersion = stream.ReadAs<uint16>();
    CHECK(majorVersion == 0x03 || majorVersion == 0x04, false, "majorVersion");

    CHECK(stream.ReadAs<uint16>() == 0xfffe, false, "byteOrder");
    auto sectorShift = stream.ReadAs<uint16>();
    CHECK((majorVersion == 0x03 && sectorShift == 0x09) || (majorVersion == 0x04 && sectorShift == 0x0c), false, "sectorShift");
    uint16 sectorSize = 1 << sectorShift;
    
    auto miniSectorShift = stream.ReadAs<uint16>();
    CHECK(miniSectorShift == 0x06, false, "miniSectorShift");
    uint16 miniSectorSize = 1 << miniSectorShift;

    CHECK(stream.ReadAs<uint32>() == 0x00, false, "reserved");
    CHECK(stream.ReadAs<uint16>() == 0x00, false, "reserved");

    auto numberOfDirectorySectors = stream.ReadAs<uint32>();
    if (majorVersion == 0x03) {
        CHECK(numberOfDirectorySectors == 0x00, false, "numberOfDirectorySectors");
    }

    auto numberOfFatSectors = stream.ReadAs<uint32>();
    auto firstDirectorySectorLocation = stream.ReadAs<uint32>();
    auto transactionSignatureNumber = stream.ReadAs<uint32>();  // incremented every time the file is saved
    
    CHECK(stream.ReadAs<uint32>() == 0x1000, false, "miniStreamCutoffSize");

    auto firstMiniFatSectorLocation = stream.ReadAs<uint32>();
    auto numberOfMiniFatSectors     = stream.ReadAs<uint32>();
    auto firstDifatSectorLocation   = stream.ReadAs<uint32>();
    auto numberOfDifatSectors       = stream.ReadAs<uint32>();

    constexpr size_t locationsCount = 109;
    uint32 DIFAT[locationsCount];  // the first 109 FAT sector locations of the compound file
    {
        auto difatBv = stream.Read(locationsCount * sizeof(*DIFAT));
        memcpy(DIFAT, (void*) difatBv.GetData(), difatBv.GetLength());
    }

    if (majorVersion == 0x04) {
        stream.Seek(3584);  // TODO: MUST check if they are all zeros
    }

    {  // TODO: remove
        std::ofstream out("D:\\temp\\ceva", std::ios::binary | std::ios::trunc);
        auto temp = stream.Read(stream.GetSize());
        out.write((const char*) temp.GetData(), temp.GetLength());
    }

    uint16 actualNumberOfSectors = ((bv.GetLength() + sectorSize - 1) / sectorSize) - 1;

    // load FAT

    Buffer fat;

    for (size_t locationIndex = 0; locationIndex < locationsCount; ++locationIndex) {
        uint32 sect = DIFAT[locationIndex];
        if (sect == ENDOFCHAIN || sect == FREESECT) {
            // end of sector chain
            break;
        }

        // get the sector data
        size_t byteOffset = sectorSize * (sect + 1);
        BufferView sector(bv.GetData() + byteOffset, sectorSize);
        fat.Add(sector);
    }

    if (fat.GetLength() > actualNumberOfSectors * sizeof(uint32)) {
        fat.Resize(actualNumberOfSectors * sizeof(uint32));
    }

    // load directory

    BufferView view = fat;

    auto left = stream.GetSize() - stream.GetCursor();

    return true;
}

bool DOCFile::ProcessData()
{
    BufferView bv = obj->GetData().GetEntireFile();

    ////// decompress the "dir" stream
    ////Buffer decompressed;
    ////DecompressStream(bv, decompressed);

    ////// parse the decompressed dir stream
    ////ParseUncompressedDirStream(decompressed);

    //// parse a module file
    //ParseModuleStream(bv);

    // TODO: parse the compound file binary format

    ParseVBAProject(bv);

    return true;
}

bool DOCFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    return true;
}

bool DOCFile::PopulateItem(AppCUI::Controls::TreeViewItem item)
{
    return false;
}

void DOCFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
}
} // namespace GView::Type::DOC
