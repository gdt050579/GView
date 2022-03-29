#pragma once

#include "GView.hpp"

namespace GView::Type::ISO
{
#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

constexpr uint64 SECTOR_SIZE        = 0x800;                            // 2.048
constexpr uint64 NUM_SYSTEM_SECTORS = 0x10;                             // 16
constexpr uint64 SYSTEM_AREA_SIZE   = NUM_SYSTEM_SECTORS * SECTOR_SIZE; // 0x8000 | 32.768

enum class Identifier
{
    ECMA_119,
    ECMA_167_PREVIOUS, // ECMA-167 Edition 2
    ECMA_167,          // ECMA-167 has a different identifiers for nearly each volume descriptor.
    ECMA_167_EXTENDED,
    ECMA_167_BOOT,
    ECMO_167_TERMINATOR,
    ECMA_168,
    UNKNOWN
};

// clang-format off
static const std::map<std::string_view, Identifier> identifiers
{
    { "CD001", Identifier::ECMA_119 },           
    { "NSR03", Identifier::ECMA_167 },
    { "NSR02", Identifier::ECMA_167_PREVIOUS },  
    { "BEA01", Identifier::ECMA_167_EXTENDED }, 
    { "BOOT2", Identifier::ECMA_167_BOOT },
    { "TEA01", Identifier::ECMO_167_TERMINATOR },
    { "CDW02", Identifier::ECMA_168 }
};
// clang-format on

enum class SectorType : uint8
{
    BootRecord    = 0,
    Primary       = 1,
    Supplementary = 2,
    Partition     = 3,
    SetTerminator = 255
};

static const std::map<SectorType, std::string_view> SectorTypeNames{
    GET_PAIR_FROM_ENUM(SectorType::BootRecord),    GET_PAIR_FROM_ENUM(SectorType::Primary),
    GET_PAIR_FROM_ENUM(SectorType::Supplementary), GET_PAIR_FROM_ENUM(SectorType::Partition),
    GET_PAIR_FROM_ENUM(SectorType::SetTerminator),
};

/* clang-format off
* https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
* Offset Length (bytes) Field name	Datatype Description
* 0	  1	             Type	    int8	 Volume Descriptor type code (see below).
* 1	  5	             Identifier	strA	 Always 'CD001'.
* 6	  1	             Version	int8	 Volume Descriptor Version (0x01).
* 7	  2041	         Data	    -	     Depends on the volume descriptor type.
* clang-format on
*/
#pragma pack(push, 1)
struct VolumeDescriptorHeader
{
    SectorType type;
    char identifier[0x5];
    int8 version;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct VolumeDescriptor // https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
{
    VolumeDescriptorHeader vdh;
    char data[0x7F9];
};
#pragma pack(pop)

static_assert(sizeof(VolumeDescriptor) == SECTOR_SIZE);

/* clang-format off
 * https://wiki.osdev.org/ISO_9660 | ECMA_119 | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
 * Offset Length (bytes) Field name	            Datatype Description
 * 0	   1	         Type	                int8	 Zero indicates a boot record.
 * 1	   5	         Identifier	            strA	 Always "CD001".
 * 6	   1	         Version	            int8	 Volume Descriptor Version (0x01).
 * 7	   32	         Boot System Identifier strA	 ID of the system which can act on and boot the system from the boot record.
 * 39	   32	         Boot Identifier	    strA	 Identification of the boot system defined in the rest of this descriptor.
 * 71	   1977	         Boot System Use	    -	     Custom - used by the boot system.
 * clang-format on
 */
struct BootRecord
{
    VolumeDescriptorHeader vdh;
    char bootSystemIdentifier[0x20];
    char bootIdentifier[0x20];
    char bootSystemUse[0x7B9];
};

static_assert(sizeof(BootRecord) == SECTOR_SIZE);

struct int32_LSB_MSB
{
    int32 LSB;
    int32 MSB;
};

struct int16_LSB_MSB
{
    int16 LSB;
    int16 MSB;
};

/* clang-format off
 *   The date/time format used in the Primary Volume Descriptor is denoted as dec-datetime 
 *   and uses ASCII digits to represent the main parts of the date/time:
 *   Offset	Size Datatype Description
 *   0	    4	 strD	  Year from 1 to 9999.
 *   4	    2	 strD	  Month from 1 to 12.
 *   6	    2	 strD	  Day from 1 to 31.
 *   8	    2	 strD	  Hour from 0 to 23.
 *   10	    2	 strD	  Minute from 0 to 59.
 *   12	    2	 strD	  Second from 0 to 59.
 *   14	    2	 strD	  Hundredths of a second from 0 to 99.
 *   16	    1	 int8	  Time zone offset from GMT in 15 minute intervals, starting at interval -48 (west) and running up to interval 52 (east). So value 0 indicates interval -48 which equals GMT-12 hours, and value 100 indicates interval 52 which equals GMT+13 hours.
 * clang-format on
 */

#pragma pack(push, 1)
struct dec_datetime
{
    char year[4];
    char months[2];
    char days[2];
    char hours[2];
    char minutes[2];
    char seconds[2];
    char milliseconds[2];
    int8 timezone;
};
#pragma pack(pop)

/* clang-format off
 * https://wiki.osdev.org/ISO_9660 | ECMA_119 | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
 * Offset	Length (bytes)	Field name	                               Datatype	     Description
 * 0	    1	            Type Code	                               int8	         Always 0x01 for a Primary Volume Descriptor.
 * 1	    5	            Standard Identifier	                       strA	         Always 'CD001'.
 * 6	    1	            Version	                                   int8	         Always 0x01.
 * 7	    1	            Unused	                                   -	         Always 0x00.
 * 8	    32	            System Identifier	                       strA	         The name of the system that can act upon sectors 0x00-0x0F for the volume.
 * 40	    32	            Volume Identifier	                       strD	         Identification of this volume.
 * 72	    8	            Unused Field	                           -	         All zeroes.
 * 80	    8	            Volume Space Size	                       int32_LSB-MSB Number of Logical Blocks in which the volume is recorded.
 * 88	    32	            Unused Field	                           -	         All zeroes.
 * 120	    4	            Volume Set Size	                           int16_LSB-MSB The size of the set in this logical volume (number of disks).
 * 124	    4	            Volume Sequence Number                     int16_LSB-MSB The number of this disk in the Volume Set.
 * 128	    4	            Logical Block Size	                       int16_LSB-MSB The size in bytes of a logical block. NB: This means that a logical block on a CD could be something other than 2 KiB!
 * 132	    8	            Path Table Size	                           int32_LSB-MSB The size in bytes of the path table.
 * 140	    4	            Location of Type-L Path Table	           int32_LSB	 LBA location of the path table. The path table pointed to contains only little-endian values.
 * 144	    4	            Location of the Optional Type-L Path Table int32_LSB	 LBA location of the optional path table. The path table pointed to contains only little-endian values. Zero means that no optional path table exists.
 * 148	    4	            Location of Type-M Path Table	           int32_MSB	 LBA location of the path table. The path table pointed to contains only big-endian values.
 * 152	    4	            Location of Optional Type-M Path Table	   int32_MSB	 LBA location of the optional path table. The path table pointed to contains only big-endian values. Zero means that no optional path table exists.
 * 156	    34	            Directory entry for the root directory	   -	         Note that this is not an LBA address, it is the actual Directory Record, which contains a single byte Directory Identifier (0x00), hence the fixed 34 byte size.
 * 190	    128	            Volume Set Identifier	                   strD	         Identifier of the volume set of which this volume is a member.
 * 318	    128	            Publisher Identifier	                   strA	         The volume publisher. For extended publisher information, the first byte should be 0x5F, followed by the filename of a file in the root directory. If not specified, all bytes should be 0x20.
 * 446	    128	            Data Preparer Identifier	               strA	         The identifier of the person(s) who prepared the data for this volume. For extended preparation information, the first byte should be 0x5F, followed by the filename of a file in the root directory. If not specified, all bytes should be 0x20.
 * 574	    128	            Application Identifier	                   strA	         Identifies how the data are recorded on this volume. For extended information, the first byte should be 0x5F, followed by the filename of a file in the root directory. If not specified, all bytes should be 0x20.
 * 702	    37	            Copyright File Identifier	               strD	         Filename of a file in the root directory that contains copyright information for this volume set. If not specified, all bytes should be 0x20.
 * 739	    37	            Abstract File Identifier	               strD	         Filename of a file in the root directory that contains abstract information for this volume set. If not specified, all bytes should be 0x20.
 * 776	    37	            Bibliographic File Identifier	           strD	         Filename of a file in the root directory that contains bibliographic information for this volume set. If not specified, all bytes should be 0x20.
 * 813	    17	            Volume Creation Date and Time	           dec-datetime  The date and time of when the volume was created.
 * 830	    17	            Volume Modification Date and Time	       dec-datetime  The date and time of when the volume was modified.
 * 847	    17	            Volume Expiration Date and Time	           dec-datetime  The date and time after which this volume is considered to be obsolete. If not specified, then the volume is never considered to be obsolete.
 * 864	    17	            Volume Effective Date and Time	           dec-datetime  The date and time after which the volume may be used. If not specified, the volume may be used immediately.
 * 881	    1	            File Structure Version	                   int8	         The directory records and path table version (always 0x01).
 * 882	    1	            Unused	                                   -	         Always 0x00.
 * 883	    512	            Application Used	                       -	         Contents not defined by ISO 9660.
 * 1395	    653	            Reserved	                               -	         Reserved by ISO.
 * clang-format on
 */

#pragma pack(push, 1)
struct VolumeDescriptorData
{
    char unused;
    char systemIdentifier[0x20];
    char volumeIdentifier[0x20];
    char unusedField[0x8];
    int32_LSB_MSB volumeSpaceSize;
    char unusedField2[0x20];
    int16_LSB_MSB volumeSetSize;
    int16_LSB_MSB volumeSequenceNumber;
    int16_LSB_MSB logicalBlockSize;
    int32_LSB_MSB pathTableSize;
    int32 locationOfTypeLPathTable;
    int32 locationOfTheOptionalTypeLPathTable;
    int32 locationOfTypeMPathTable;
    int32 locationOfTheOptionalTypeMPathTable;
    char directoryEntryForTheRootDirectory[0x22];
    char volumeSetIdentifier[0x80];
    char publisherIdentifier[0x80];
    char dataPreparerIdentifier[0x80];
    char applicationIdentifier[0x80];
    char copyrightFileIdentifier[0x25];
    char abstractFileIdentifier[0x25];
    char bibliographicFileIdentifier[0x25];
    dec_datetime volumeCreationDateAndTime;
    dec_datetime volumeModificationDateAndTime;
    dec_datetime volumeExpirationDateAndTime;
    dec_datetime volumeEffectiveDateAndTime;
    int8 fileStructureVersion;
    char unused2;
    char applicationUsed[0x200];
    char reserved[0x28D];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PrimaryVolumeDescriptor
{
    VolumeDescriptorHeader vdh;
    VolumeDescriptorData vdd;
};
#pragma pack(pop)

static_assert(sizeof(PrimaryVolumeDescriptor) == SECTOR_SIZE);

#pragma pack(push, 1)
struct SupplementaryVolumeDescriptor
{
    VolumeDescriptorHeader vdh;
    VolumeDescriptorData vdd;
};
#pragma pack(pop)

/* clang-format off
 * https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
 * BP         Field name                  Content
 * 1          Volume Descriptor Type      numerical value
 * 2          to 6 Standard Identifier    CD001
 * 7          Volume Descriptor Version   numerical value
 * 8          Unused Field                (00) byte
 * 9 to 40    System Identifier           a-characters
 * 41 to 72   Volume Partition Identifier d-characters
 * 73 to 80   Volume Partition Location   numerical value
 * 81 to 88   Volume Partition Size       numerical value
 * 89 to 2048 System Use                  not specified
 * clang-format on
 */
#pragma pack(push, 1)
struct VolumePartitionDescriptor
{
    VolumeDescriptorHeader vdh;
    uint8 unused;
    char systemIdentifier[0x20];
    char volumePartitionIdentifier[0x20];
    int32_LSB_MSB volumePartitionLocation;
    int32_LSB_MSB volumePartitionSize;
    char systemUse[0x7A8];
};
#pragma pack(pop)

static_assert(sizeof(VolumePartitionDescriptor) == SECTOR_SIZE);

/* clang-format off
 * BP                Field name                                       Content
 * 1                 Length of Directory Identifier (LEN_DI)          numerical value
 * 2                 Extended Attribute Record Length                 numerical value
 * 3 to 6            Location of Extent                               numerical value
 * 7 to 8            Parent Directory Number                          numerical value
 * 9 to (8 + LEN_DI) Directory Identifier d-characters, d1-characters (00) byte
 * (9 + LEN_DI)      Padding Field                                    (00) byte
 * clang-format on
 */
#pragma pack(push, 1)
struct PathTableRecord
{
    uint8 lengthOfDirectoryIdentifier;
    uint8 extendedAttributeRecordLength;
    uint32 locationOfExtent;
    uint16 parentDirectoryNumber;
    char dirID[8];
};
#pragma pack(pop)

// https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf
enum FileFlags
{
    Existence      = 1 << 0,
    Directory      = 1 << 1,
    AssociatedFile = 1 << 2,
    Record         = 1 << 3,
    Protection     = 1 << 4,
    Reserved1      = 1 << 5,
    Reserved2      = 1 << 6,
    MultiExtent    = 1 << 7
};

/* clang-format off
 * BP                              Field name                          Content
 * 1                               Length of Directory Record (LEN-DR) numerical value
 * 2                               Extended Attribute Record Length    numerical value
 * 3  to 10                        Location of Extent                  numerical value
 * 11 to 18                        Data Length                         numerical value
 * 19 to 25                        Recording Date and Time             numerical values
 * 26                              File Flags                          8 bits
 * 27                              File Unit Size                      numerical value
 * 28                              Interleave Gap Size                 numerical value
 * 29 to 32                        Volume Sequence Number              numerical value
 * 33                              Length of File Identifier (LEN_FI)  numerical value
 * 34 to (33 + LEN_FI)             File Identifier                     d-characters, d1-characters, SEPARATOR 1, SEPARATOR 2, (00) or (01) byte
 * (34 + LEN_FI)                   Padding Field                       (00) byte
 * (LEN_DR - LEN_SU + 1) to LEN_DR System Use                          LEN_SU bytes
 * clang-format on
 */
#pragma pack(push, 1)
struct DirectoryRecord
{
    uint8 lengthOfDirectoryRecord;
    uint8 extendedAttributeRecordLength;
    int32_LSB_MSB locationOfExtent;
    int32_LSB_MSB dataLength;
    unsigned char recordingDateAndTime[7];
    uint8 fileFlags;
    uint8 fileUnitSize;
    uint8 interleaveGapSize;
    uint32 volumeSequenceNumber;
    uint8 lengthOfFileIdentifier;
    char fileIdentifier[0x22];
    /* here is paadded to len of DR */
};
#pragma pack(pop)

class ISOFile : public TypeInterface
{
  public:
    Reference<GView::Utils::FileCache> file;

    struct MyVolumeDescriptorHeader
    {
        VolumeDescriptorHeader header;
        uint64 offsetInFile;
    };

    std::vector<MyVolumeDescriptorHeader> headers;
    std::vector<DirectoryRecord> records;

  public:
    ISOFile(Reference<GView::Utils::FileCache> file);
    virtual ~ISOFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "ISO";
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<GView::Type::ISO::ISOFile> iso;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateVolumeHeader(const VolumeDescriptorHeader& vdh);
        void UpdateBootRecord(const BootRecord& br);
        void UpdatePrimaryVolumeDescriptor(const PrimaryVolumeDescriptor& pvd);
        void UpdateSupplementaryVolumeDescriptor(const SupplementaryVolumeDescriptor& pvd);
        void UpdateVolumeDescriptor(const VolumeDescriptorData& vdd);
        void UpdateVolumePartitionDescriptor(const VolumePartitionDescriptor& vpd);
        void UpdateIssues();
        void UpdateVolumeDescriptors();
        void RecomputePanelsPositions();

        template <typename T>
        void AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            const auto v    = nf.ToString(value, dec);
            const auto hexV = nf2.ToString(value, hex);
            general->AddItem(name, ls.Format(format.data(), v.data(), hexV.data()));
        }

        template <typename T>
        void AddNameAndHexElement(std::string_view name, std::string_view format, const T& value)
        {
            LocalString<1024> ls;
            LocalString<1024> ls2;

            constexpr auto size = sizeof(value) / sizeof(value[0]);
            ls2.Format("0x");
            for (auto i = 0ULL; i < size; i++)
            {
                ls2.AddFormat("%.2x", value[i]);
            }
            const auto vHex = ls2.GetText();
            general->AddItem(name, ls.Format(format.data(), std::string{ value, sizeof(value) }.c_str(), vHex));
        }

        void AddDateAndHexElement(std::string_view name, std::string_view format, const dec_datetime& date)
        {
            LocalString<1024> ls;
            LocalString<1024> ls2;
            LocalString<1024> ls3;

            ls.Format(
                  "%s-%s-%s %s:%s:%s:%s +%u",
                  date.year,
                  date.months,
                  date.days,
                  date.hours,
                  date.minutes,
                  date.seconds,
                  date.milliseconds,
                  date.timezone);

            const auto dateBuffer = (unsigned char*) &date;
            constexpr auto size   = sizeof(date);
            ls2.Format("0x");
            for (auto i = 0ULL; i < size; i++)
            {
                ls2.AddFormat("%.2x", dateBuffer[i]);
            }
            const auto dateHex = ls2.GetText();
            general->AddItem(name, ls3.Format(format.data(), ls.GetText(), dateHex));
        }

      public:
        Information(Reference<GView::Type::ISO::ISOFile> iso);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<ISOFile> iso;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<ISOFile> iso, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ISO
