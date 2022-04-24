#pragma once

#include <GView.hpp>

#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

namespace GView::Type::Prefetch
{
// https://forensicswiki.xyz/wiki/index.php?title=Windows_Prefetch_File_Format#Format_version
enum class Magic : uint32
{
    WIN_XP_2003 = 0x00000011, // 11
    WIN_VISTA_7 = 0x00000017, // 23
    WIN_8       = 0x0000001A, // 26
    WIN_10      = 0x0000001E, // 30
    WIN_10_MAM  = 0x044D414D  // Windows 10 compressed
};

static const std::map<Magic, std::string_view> MagicNames{
    GET_PAIR_FROM_ENUM(Magic::WIN_XP_2003), GET_PAIR_FROM_ENUM(Magic::WIN_VISTA_7), GET_PAIR_FROM_ENUM(Magic::WIN_8),
    GET_PAIR_FROM_ENUM(Magic::WIN_10),      GET_PAIR_FROM_ENUM(Magic::WIN_10_MAM),
};

constexpr uint32 SIGNATURE = 0x41434353;

/* clang-format off
     * Field	Offset	Length	Type	Notes
     * H1	    0x0000	4	    DWORD	Format version (see format version section below)
     * H2	    0x0004	4	    DWORD	Signature 'SCCA' (or in hexadecimal representation 0x53 0x43 0x43 0x41)
     * H3	    0x0008	4	    DWORD?	Unknown - Values observed: 0x0F - Windows XP, 0x11 - Windows 7, Windows 8.1
     * H4	    0x000C	4	    DWORD	Prefetch file size (or length) (sometimes referred to as End of File (EOF)).
     * H5	    0x0010	60	    USTR	The name of the (original) executable as a Unicode (UTF-16 litte-endian string), up to 29 characters and terminated by an end-of-string character (U+0000). This name should correspond with the one in the prefetch file filename.
     * H6	    0x004C	4	    DWORD	The prefetch hash. This hash value should correspond with the one in the prefetch file filename.
     * H7	    0x0050	4	    ?	    Unknown (flags)? Values observed: 0 for almost all prefetch files (XP); 1 for NTOSBOOT-B00DFAAD.pf (XP)
     * clang-format on
    */

struct Header
{
    Magic version;
    uint32 signature;
    uint32 H3;
    uint32 fileSize;
    uint8 executableName[60];
    uint32 H6;
    uint32 H7;
};

/* clang-format off
 * --------------------------------------------------------------- 17 START -------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang-format off
     * The file information – version 17 is 68 bytes of size and consists of:
     *
     * Field	Offset	Length	 Type	  Notes
     *          0x0054	4	     DWORD	  The offset to section A. The offset is relative from the start of the file.
     *          0x0058	4	     DWORD	  The number of entries in section A.
     *          0x005C	4	     DWORD	  The offset to section B. The offset is relative from the start of the file.
     *          0x0060	4	     DWORD	  The number of entries in section B.
     *          0x0064	4	     DWORD	  The offset to section C. The offset is relative from the start of the file.
     *          0x0068	4	     DWORD	  Length of section C.
     *          0x006C	4	     DWORD	  Offset to section D. The offset is relative from the start of the file.
     *          0x0070	4	     DWORD	  The number of entries in section D.
     *          0x0074	4	     DWORD	  Length of section D.
     *          0x0078	8	     FILETIME Latest execution time (or run time) of executable (FILETIME)
     *          0x0080	16	     ?	      Unknown ? Possibly structured as 4 DWORD. Observed values: /0x00000000 0x00000000 0x00000000 0x00000000/, /0x47868c00 0x00000000 0x47860c00 0x00000000/ (don't exclude the possibility here that this is remnant data)
     *          0x0090	4	     DWORD	  Execution counter (or run count)
     *          0x0094	4	     DWORD?	  Unknown ? Observed values: 1, 2, 3, 4, 5, 6 (XP)
     * clang-format on
    */

#pragma pack(push, 4)
struct FileInformation_17
{
    struct SectionA
    {
        uint32 offset;
        uint32 entries;
    } sectionA; // 8
    struct SectionB
    {
        uint32 offset;
        uint32 entries;
    } sectionB; // 16
    struct SectionC
    {
        uint32 offset;
        uint32 length;
    } sectionC; // 24
    struct SectionD
    {
        uint32 offset;
        uint32 entries;
        uint32 size;
    } sectionD;                 // 36
    uint64 latestExecutionTime; // 44
    uint64 unknown[2];          // 60
    uint32 executionCount;      // 64
    uint32 unknown2;            // 68
};
#pragma pack(pop)

static_assert(sizeof(FileInformation_17) == 68);

/* clang-format off
     * The file metrics entry records – version 17 is 20 bytes in size and consists of:
     *
     * Field Offset	Length	Type	Notes
     *       0	    4	    DWORD	Start time in ms
     *       4	    4	    DWORD	Duration in ms
     *       8	    4	    DWORD	Filename string offset The offset is relative to the start of the filename string section (section C)
     *       12	    4	    DWORD	Filename string number of characters without end-of-string character
     *       16	    4	    DWORD	Unknown, flags?
     * clang-format on
     */

struct FileMetricsEntryRecord_17
{
    uint32 startTime;
    uint32 duration;
    uint32 filenameOffset;
    uint32 filenameSize;
    uint32 unknown;
};

/* clang-format off
 * This section contains an array with 12 byte (version 17, 23 and 26) entry records.
 * Field Offset	Length	Type Notes
 *       0	    4		     Next array entry index. Contains the next trace chain array entry index in the chain, where the first entry index starts with 0, or -1 (0xffffffff) for the end-of-chain.
 *       4	    4		     Total block load count. Number of blocks loaded (or fetched). The block size 512k (512 x 1024) bytes.
 *       8	    1		     Unknown
 *       9	    1		     Sample duration in ms?
 *       10    	2	        Unknown
 * clang-format on
 */

struct TraceChainEntry_17_23_26
{
    uint32 nextEntryIndex;
    uint32 blocksFetched;
    uint8 unknown;
    uint8 duration;
    uint16 unknown2;
};

/* clang-format off
 * The volume information – version 17 is 40 bytes in size and consists of:
 * Field	Offset	Length	Type	 Notes
 * VI1	    +0x0000	4	    DWORD	 Offset to volume device path (Unicode, terminated by U+0000)
 * VI2	    +0x0004	4	    DWORD	 Length of volume device path (nr of characters, including terminating U+0000)
 * VI3	    +0x0008	8	    FILETIME Volume creation time.
 * VI4	    +0x0010	4	    DWORD	 Volume serial number of volume indicated by volume string
 * VI5	    +0x0014	4	    DWORD	 Offset to sub section E
 * VI6	    +0x0018	4	    DWORD	 Length of sub section E (in bytes)
 * VI7	    +0x001C	4	    DWORD	 Offset to sub section F
 * VI8	    +0x0020	4	    DWORD	 Number of strings in sub section F
 * VI9	    +0x0024	4	    ?	     Unknown
 * clang-format on
 */

struct VolumeInformationEntry_17
{
    uint32 devicePathOffset;
    uint32 devicePathLength;
    uint64 creationTime;
    uint32 serialNumber;
    uint32 fileReferencesOffset;
    uint32 fileReferencesSize;
    uint32 directoryStringsOffset;
    uint32 directoryStringsEntries;
    uint32 VI9;
};

static_assert(sizeof(VolumeInformationEntry_17) == 40);

/*
    The directory string entry is variable of size and consists of:
    Offset	Size	Value	Description
    0       2               String number of characters. The value does not include the end-of-string character.
    2       ...             Array of UTF-16 little-endian strings with end-of-string character
*/

struct DirectoryStringEntry
{
    uint16 size;
    char16_t path[0];
};

/*
    The NTFS file reference is 8 bytes of size and consists of:
    Offset	Size	Value	Description
    0       6               MFT entry index
    6       2               Sequence number
*/

struct FileReference
{
    uint8 entryIndex[3];
    uint8 sequenceNumber;
};

/*
    The file references - version 17 are variable of size and consists of:
    Offset	Size	Value	Description
    0       4       1       Unknown (Version?)
    4       4               Number of file references
    8       …               Array of file references. Contains a file reference or 0 if not set.
*/

struct FileReferences_17
{
    uint32 version;
    uint32 numberOfFileReferences;
    FileReference fileReferences[0];
};

static int64 SSCA_XP_HASH(BufferView bv)
{
    CHECK(bv.IsValid(), 0, "");
    int64 hash_value = 0;
    for (auto i = 0; i < bv.GetLength(); i++)
    {
        const auto& character = *(bv.GetData() + i);
        hash_value            = ((hash_value * 37) + (character)) % 0x100000000;
    }

    hash_value = (hash_value * 314159269) % 0x100000000;

    if (hash_value > 0x80000000)
    {
        hash_value = 0x100000000 - hash_value;
    }

    return (std::abs(hash_value) % 1000000007) % 0x100000000;
}

/* clang-format off
 * ---------------------------------------------------------------- 17 END -------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang-format off
 * --------------------------------------------------------------- 23 START ------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang-format off
 * The file information - version 23 is 156 bytes of size and consists of:
 * Field Offset	Length Type	    Notes
 *       0x0054	4	   DWORD	The offset to section A. The offset is relative from the start of the file.
 *       0x0058	4	   DWORD	The number of entries in section A.
 *       0x005C	4	   DWORD	The offset to section B. The offset is relative from the start of the file.
 *       0x0060	4	   DWORD	The number of entries in section B.
 *       0x0064	4	   DWORD	The offset to section C. The offset is relative from the start of the file.
 *       0x0068	4	   DWORD	Length of section C.
 *       0x006C	4	   DWORD	Offset to section D. The offset is relative from the start of the file.
 *       0x0070	4	   DWORD	The number of entries in section D.
 *       0x0074	4	   DWORD	Length of section D.
 *       0x0078	8	   ?	    Unknown
 *       0x0080	8	   FILETIME Latest execution time (or run time) of executable (FILETIME)
 *       0x0088	16	   ?	    Unknown
 *       0x0098	4	   DWORD	Execution counter (or run count)
 *       0x009C	4	   DWORD?	Unknown
 *       0x00A0	80	   ?	    Unknown
 * clang-format on
 */

#pragma pack(push, 4)
struct FileInformation_23
{
    struct SectionA
    {
        uint32 offset;
        uint32 entries;
    } sectionA;
    struct SectionB
    {
        uint32 offset;
        uint32 entries;
    } sectionB;
    struct SectionC
    {
        uint32 offset;
        uint32 length;
    } sectionC;
    struct SectionD
    {
        uint32 offset;
        uint32 entries;
        uint32 size;
    } sectionD;
    uint64 unknown0;
    uint64 latestExecutionTime;
    uint64 unknown[2];
    uint32 executionCount;
    uint32 unknown2;
    uint8 unknown4[80];
};
#pragma pack(pop)

static_assert(sizeof(FileInformation_23) == 156);

/* clang-format off
 * The file metrics entry records - version 23 is 32 bytes in size and consists of:
 * Field Offset	Length	Type  Notes
 *       0	    4	    DWORD Start time in ms
 *       4	    4	    DWORD Duration in ms
 *       8	    4	    DWORD Average duration in ms?
 *       12	    4	    DWORD Filename string offset. The offset is relative to the start of the filename string section (section C)
 *       16	    4	    DWORD Filename string number of characters without end-of-string character
 *       20	    4	    DWORD Unknown, flags?
 *       24	    8	    	  NTFS file reference. 0 if not set.
 * clang-format on
 */

struct FileMetricsEntryRecord_23_26_30
{
    uint32 startTime;
    uint32 duration;
    uint32 averageDuration;
    uint32 filenameOffset;
    uint32 filenameSize;
    uint32 unknown;
    uint64 ntfsFileReference;
};

static_assert(sizeof(FileMetricsEntryRecord_23_26_30) == 32);

/* clang-format off
 * Volume information - version 23/26
 * The volume information entry – version 23 is 104 bytes in size and consists of:
 * 
 * Field	Offset	Length	Type	 Notes
 * VI1	    +0x0000	4	    DWORD	 Offset to volume device path (Unicode, terminated by U+0000). The offset is relative from the start of the volume information
 * VI2	    +0x0004	4	    DWORD	 Length of volume device path (nr of characters, including terminating U+0000)
 * VI3	    +0x0008	8	    FILETIME Volume creation time.
 * VI4	    +0x0010	4	    DWORD	 Volume serial number of volume indicated by volume string
 * VI5	    +0x0014	4	    DWORD	 File references offset
 * VI6	    +0x0018	4	    DWORD	 File references data size
 * VI7	    +0x001C	4	    DWORD	 Directory strings offset
 * VI8	    +0x0020	4	    DWORD	 Number of directory strings
 * VI9	    +0x0024	4	    ?	     Unknown
 * VI10	    +0x0028	28	    ?	     Unknown
 * VI11	    +0x0044	4	    ?	     Unknown
 * VI12	    +0x0048	28	    ?	     Unknown
 * VI13	    +0x0064	4	    ?	     Unknown
 * clang-format on
 */

struct VolumeInformationEntry_23_26
{
    uint32 devicePathOffset;
    uint32 devicePathLength;
    uint64 creationTime;
    uint32 serialNumber;
    uint32 fileReferencesOffset;
    uint32 fileReferencesSize;
    uint32 directoryStringsOffset;
    uint32 directoryStringsEntries;
    uint32 VI9;
    uint8 unknown[28];
    uint32 unknown0;
    uint8 unknown1[28];
    uint32 unknown2;
};

static_assert(sizeof(VolumeInformationEntry_23_26) == 104);

/*
    The file references - version 23/26/30 are variable of size and consists of:
    Offset	Size	Value	Description
    0       4       3       Unknown (Version?)
    4       4               Number of file references
    8       8               Unknown
    1       ...             Array of file references. Contains a file reference or 0 if not set.
*/

struct FileReferences_23_26_30
{
    uint32 version;
    uint32 numberOfFileReferences;
    uint64 unknown;
    FileReference fileReferences[0];
};

static int64 SSCA_VISTA_HASH(BufferView bv)
{
    CHECK(bv.IsValid(), 0, "");
    int64 hash_value = 314159;
    for (auto i = 0; i < bv.GetLength(); i++)
    {
        const auto& character = *(bv.GetData() + i);
        hash_value            = ((hash_value * 37) + character) % 0x100000000;
    }

    return hash_value;
}

/* clang-format off
 * --------------------------------------------------------------- 23 END --------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang-format off
 * --------------------------------------------------------------- 26 START ------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang-format off
 * The file information - version 26 is 224 bytes of size and consists of:
 * Field  Offset Length	    Type	 Notes
 *        0x0054 4	        DWORD	 The offset to section A. The offset is relative from the start of the file.
 *        0x0058 4	        DWORD	 The number of entries in section A.
 *        0x005C 4	        DWORD	 The offset to section B. The offset is relative from the start of the file.
 *        0x0060 4	        DWORD	 The number of entries in section B.
 *        0x0064 4	        DWORD	 The offset to section C. The offset is relative from the start of the file.
 *        0x0068 4	        DWORD	 Length of section C.
 *        0x006C 4	        DWORD	 Offset to section D. The offset is relative from the start of the file.
 *        0x0070 4	        DWORD	 The number of entries in section D.
 *        0x0074 4	        DWORD	 Length of section D.
 *        0x0078 8	        ?	     Unknown
 *        0x0080 8	        FILETIME Latest execution time (or run time) of executable (FILETIME)
 *        0x0088 7 x 8 = 56	FILETIME Older (most recent) latest execution time (or run time) of executable (FILETIME)
 *        0x00C0 16	        ?	     Unknown
 *        0x00D0 4	        DWORD	 Execution counter (or run count)
 *        0x00D4 4	        ?	     Unknown
 *        0x00D8 4	        ?	     Unknown
 *        0x00DC 88	        ?	     Unknown
 * clang-format on
 */

#pragma pack(push, 4)
struct FileInformation_26
{
    struct SectionA
    {
        uint32 offset;
        uint32 entries;
    } sectionA;
    struct SectionB
    {
        uint32 offset;
        uint32 entries;
    } sectionB;
    struct SectionC
    {
        uint32 offset;
        uint32 length;
    } sectionC;
    struct SectionD
    {
        uint32 offset;
        uint32 entries;
        uint32 size;
    } sectionD;
    uint64 unknown0;
    uint64 latestExecutionTime;
    uint64 olderExecutionTime[8];
    uint64 unknown[2];
    uint32 executionCount;
    uint32 unknown2;
    uint32 unknown3;
    uint8 unknown4[80];
};
#pragma pack(pop)

static_assert(sizeof(FileInformation_26) == 224);

/* clang-format off
 * --------------------------------------------------------------- 26 END --------------------------------------------------------------------------------------
 * clang-format on
 */

/* clang - format off
 * --------------------------------------------------------------- 30 START
 * ------------------------------------------------------------------------------------- clang - format on
 */

/* clang-format off
 * The file information - version 30 is 216 bytes of size and consists of:
 * Field  Offset Length	    Type	 Notes
 *        0x0054 4	        DWORD	 The offset to section A. The offset is relative from the start of the file.
 *        0x0058 4	        DWORD	 The number of entries in section A.
 *        0x005C 4	        DWORD	 The offset to section B. The offset is relative from the start of the file.
 *        0x0060 4	        DWORD	 The number of entries in section B.
 *        0x0064 4	        DWORD	 The offset to section C. The offset is relative from the start of the file.
 *        0x0068 4	        DWORD	 Length of section C.
 *        0x006C 4	        DWORD	 Offset to section D. The offset is relative from the start of the file.
 *        0x0070 4	        DWORD	 The number of entries in section D.
 *        0x0074 4	        DWORD	 Length of section D.
 *        0x0078 8	        ?	     Unknown
 *        0x0080 8	        FILETIME Latest execution time (or run time) of executable (FILETIME)
 *        0x0088 7 x 8 = 56	FILETIME Older (most recent) latest execution time (or run time) of executable (FILETIME)
 *        0x00C0 8	        ?	     Unknown
 *        0x00C8 4	        DWORD	 Execution counter (or run count)
 *        0x00D0 4	        ?	     Unknown
 *        0x00D4 4	        ?	     Unknown
 *        0x00D8 88	        ?	     Unknown
 * clang-format on
 */

#pragma pack(push, 4)
struct FileInformation_30
{
    struct SectionA
    {
        uint32 offset;
        uint32 entries;
    } sectionA;
    struct SectionB
    {
        uint32 offset;
        uint32 entries;
    } sectionB;
    struct SectionC
    {
        uint32 offset;
        uint32 length;
    } sectionC;
    struct SectionD
    {
        uint32 offset;
        uint32 entries;
        uint32 size;
    } sectionD;
    uint32 unknown;
    uint32 unknown0;
    uint64 latestExecutionTime;
    uint64 olderExecutionTime[8];
    uint32 unknown1;
    uint32 unknown2;
    uint32 executionCount;
    uint32 executablePathOffset;
    uint32 executablePathSize;
    uint8 unknown4[80];
};
#pragma pack(pop)

static_assert(sizeof(FileInformation_30) == 216);

/* clang-format off
 * The trace chain array entry - version 30 is 8 bytes in size and consists of:.
 * Field Offset	Length	Type Notes
 *       0	    4		     Next array entry index. Contains the next trace chain array entry index in the chain, where the first entry index starts with 0, or -1 (0xffffffff) for the end-of-chain.
 *       4	    1		     Unknown. Seen: 0x02, 0x03, 0x04, 0x08, 0x0a
 *       5	    1		     Unknown (Sample duration in ms?). Seen: 1
 *       6	    2		     Unknown. Seen: 0x0001, 0xffff, etc.
 * clang-format on
 */

struct TraceChainEntry_30
{
    uint32 nextEntryIndex;
    uint8 unknown0;
    uint8 unknown1;
    uint16 unknown2;
};

static int64 SSCA_2008_HASH(BufferView bv)
{
    CHECK(bv.IsValid(), 0, "");
    int64 hash_value = 314159;

    uint64 i = 0;
    while (i + 8 < bv.GetLength())
    {
        auto character_value = bv.GetData()[i + 1] * 37;
        character_value += bv.GetData()[i + 2];
        character_value *= 37;
        character_value += bv.GetData()[i + 3];
        character_value *= 37;
        character_value += bv.GetData()[i + 4];
        character_value *= 37;
        character_value += bv.GetData()[i + 5];
        character_value *= 37;
        character_value += bv.GetData()[i + 6];
        character_value *= 37;
        character_value += bv.GetData()[i] * 442596621;
        character_value += bv.GetData()[i + 7];

        hash_value = ((character_value - (hash_value * 803794207)) % 0x100000000);

        i += 8;
    }

    while (i < bv.GetLength())
    {
        hash_value = (((37 * hash_value) + bv.GetData()[i]) % 0x100000000);

        i += 1;
    }

    return hash_value;
}

/* clang-format off
 * The volume information entry - version 30 is 96 bytes in size and consists of:
 * Field	Offset	Length	Type	 Notes
 * VI1	    +0x0000	4	    DWORD	 Offset to volume device path (Unicode, terminated by U+0000). The offset is relative from the start of the volume information
 * VI2	    +0x0004	4	    DWORD	 Length of volume device path (nr of characters, including terminating U+0000)
 * VI3	    +0x0008	8	    FILETIME Volume creation time.
 * VI4	    +0x0010	4	    DWORD	 Volume serial number of volume indicated by volume string
 * VI5	    +0x0014	4	    DWORD	 File references offset
 * VI6	    +0x0018	4	    DWORD	 File references data size
 * VI7	    +0x001C	4	    DWORD	 Directory strings offset
 * VI8	    +0x0020	4	    DWORD	 Number of directory strings
 * VI9	    +0x0024	4	    ?	     Unknown
 * VI10	    +0x0028	24	    ?	     Unknown
 * VI11	    +0x0040	4	    ?	     Unknown
 * VI12	    +0x0040	24	    ?	     Unknown
 * VI13	    +0x0058	4	    ?	     Unknown
 * clang-format on
 */

struct VolumeInformationEntry_30
{
    uint32 devicePathOffset;
    uint32 devicePathLength;
    uint64 creationTime;
    uint32 serialNumber;
    uint32 fileReferencesOffset;
    uint32 fileReferencesSize;
    uint32 directoryStringsOffset;
    uint32 directoryStringsEntries;
    uint32 VI9;
    uint8 unknown[24];
    uint32 unknown0;
    uint8 unknown1[24];
    uint32 unknown2;
};

static_assert(sizeof(VolumeInformationEntry_30) == 96);

/* clang-format off
 * --------------------------------------------------------------- 30 END --------------------------------------------------------------------------------------
 * clang-format on
 */

} // namespace GView::Type::Prefetch
