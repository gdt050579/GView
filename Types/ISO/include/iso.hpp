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
    ECMA_168,
    ECMA_167_PREVIOUS, // ECMA-167 Edition 2
    ECMA_167,          // ECMA-167 has a different identifiers for nearly each volume descriptor.
    ECMA_167_EXTENDED,
    ECMA_167_BOOT,
    ECMO_167_TERMINATOR,
    UNKNOWN
};

static const std::map<std::string_view, Identifier> identifiers = {
    { "CD001", Identifier::ECMA_119 },           { "CDW02", Identifier::ECMA_168 },          { "NSR03", Identifier::ECMA_167 },
    { "NSR02", Identifier::ECMA_167_PREVIOUS },  { "BEA01", Identifier::ECMA_167_EXTENDED }, { "BOOT2", Identifier::ECMA_167_BOOT },
    { "TEA01", Identifier::ECMO_167_TERMINATOR }
};

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

struct VolumeDescriptor
{
    VolumeDescriptorHeader vdh;
    char data[0x7F9];
};

/* clang-format off
 * https://wiki.osdev.org/ISO_9660 | ECMA_119
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

struct dec_datetime
{
    char value[17];
};

/* clang-format off
 * https://wiki.osdev.org/ISO_9660 | ECMA_119
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
    char systemIdentifier[32];
    char volumeIdentifier[32];
    char unusedField[8];
    int32_LSB_MSB volumeSpaceSize;
    char unusedField2[8];
    int16_LSB_MSB volumeSetSize;
    int16_LSB_MSB volumeSequenceNumber;
    int16_LSB_MSB logicalBlockSize;
    int32_LSB_MSB pathTableSize;
    int32_LSB_MSB locationOfTypeLPathTable;
    int32_LSB_MSB locationOfTheOptionalTypeLPathTable;
    int32_LSB_MSB locationOfTypeMPathTable;
    int32_LSB_MSB locationOfTheOptionalTypeMPathTable;
    char directoryEntryForTheRootDirectory[34];
    char volumeSetIdentifier[128];
    char publisherIdentifier[128];
    char dataPreparerIdentifier[128];
    char applicationIdentifier[128];
    char copyrightFileIdentifier[37];
    char abstractFileIdentifier[37];
    char bibliographicFileIdentifier[37];
    dec_datetime volumeCreationDateAndTime;
    dec_datetime volumeModificationDateAndTime;
    dec_datetime volumeExpirationDateAndTime;
    dec_datetime volumeEffectiveDateAndTime;
    int8 fileStructureVersion;
    char unused2;
    char applicationUsed[512];
    char reserved[653];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PrimaryVolumeDescriptor
{
    VolumeDescriptorHeader vdh;
    VolumeDescriptorData vdd;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct SupplementaryVolumeDescriptor
{
    VolumeDescriptorHeader vdh;
    VolumeDescriptorData vdd;
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
        void UpdateIssues();
        void UpdateVolumeDescriptors();
        void RecomputePanelsPositions();

      public:
        Information(Reference<GView::Type::ISO::ISOFile> iso);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };
}; // namespace Panels
} // namespace GView::Type::ISO
