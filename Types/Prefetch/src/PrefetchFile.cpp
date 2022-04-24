#include "prefetch.hpp"

using namespace GView::Type::Prefetch;

PrefetchFile::PrefetchFile()
{
}

bool PrefetchFile::Update_17()
{
    FileInformation_17 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_17>(sizeof(header), fileInformation), false, "");

    CHECK(SetEntries(
                fileInformation.sectionA.offset,
                fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_17),
                fileInformation.sectionB.offset,
                fileInformation.sectionB.entries * sizeof(TraceChainEntry_17_23_26),
                fileInformation.sectionC.offset,
                fileInformation.sectionC.length,
                fileInformation.sectionD.offset),
          false,
          "");

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_17>(sizeof(VolumeInformationEntry_17) * i);

        CHECK(AddVolumeEntry(
                    fileInformation.sectionD.offset,
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    CHECK(SetFilename(), false, "");

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_17>(sizeof(FileMetricsEntryRecord_17) * i);

        if (ComputeHashForMainExecutable(entry->filenameOffset, entry->filenameSize))
        {
            break;
        }
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_23()
{
    FileInformation_23 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_23>(sizeof(header), fileInformation), false, "");

    CHECK(SetEntries(
                fileInformation.sectionA.offset,
                fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_23_26_30),
                fileInformation.sectionB.offset,
                fileInformation.sectionB.entries * sizeof(TraceChainEntry_17_23_26),
                fileInformation.sectionC.offset,
                fileInformation.sectionC.length,
                fileInformation.sectionD.offset),
          false,
          "");

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_23_26>(i * sizeof(VolumeInformationEntry_23_26));

        CHECK(AddVolumeEntry(
                    fileInformation.sectionD.offset,
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    CHECK(SetFilename(), false, "");

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

        if (ComputeHashForMainExecutable(entry->filenameOffset, entry->filenameSize))
        {
            break;
        }
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_26()
{
    FileInformation_26 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_26>(sizeof(header), fileInformation), false, "");

    CHECK(SetEntries(
                fileInformation.sectionA.offset,
                fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_23_26_30),
                fileInformation.sectionB.offset,
                fileInformation.sectionB.entries * sizeof(TraceChainEntry_17_23_26),
                fileInformation.sectionC.offset,
                fileInformation.sectionC.length,
                fileInformation.sectionD.offset),
          false,
          "");

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_23_26>(i * sizeof(VolumeInformationEntry_23_26));

        CHECK(AddVolumeEntry(
                    fileInformation.sectionD.offset,
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    CHECK(SetFilename(), false, "");

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

        if (ComputeHashForMainExecutable(entry->filenameOffset, entry->filenameSize))
        {
            break;
        }
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_30()
{
    FileInformation_30 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_30>(sizeof(header), fileInformation), false, "");

    const auto end  = fileInformation.sectionC.offset + fileInformation.sectionC.length;
    const auto diff = fileInformation.sectionD.offset - end;

    CHECK(SetEntries(
                fileInformation.sectionA.offset,
                fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_23_26_30),
                fileInformation.sectionB.offset,
                fileInformation.sectionB.entries * sizeof(TraceChainEntry_30),
                fileInformation.sectionC.offset,
                diff < 0 ? fileInformation.sectionC.length : fileInformation.sectionC.length + diff,
                fileInformation.sectionD.offset),
          false,
          "");

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_30>(i * sizeof(VolumeInformationEntry_30));

        CHECK(AddVolumeEntry(
                    fileInformation.sectionD.offset,
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    CHECK(SetFilename(), false, "");

    if (header.version == Magic::WIN_10)
    {
        if (diff > 0)
        {
            std::u16string_view sv{ (char16*) (bufferSectionC.GetData() + bufferSectionC.GetLength() - diff), diff };
            auto pos = sv.find_first_of(char16{ 0 });
            if (pos == std::string::npos)
            {
                pos = diff;
            }
            ComputeHashForMainExecutable(bufferSectionC.GetLength() - diff, pos);
        }
    }
    else
    {
        for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
        {
            auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

            if (ComputeHashForMainExecutable(entry->filenameOffset, entry->filenameSize))
            {
                break;
            }
        }
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::SetFilename()
{
    ConstString cs{ u16string_view{ (char16_t*) &header.executableName,
                                    sizeof(header.executableName) / sizeof(header.executableName[0]) } };
    LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
    CHECK(lsub.Set(cs), false, "");
    lsub.ToString(filename);
    const auto actualSize = strlen(filename.c_str());
    filename.resize(actualSize);

    return true;
}

bool PrefetchFile::ComputeHashForMainExecutable(uint32 filenameOffset, uint32 filenameSize)
{
    ConstString cs(std::u16string_view{ (char16_t*) (bufferSectionC.GetData() + filenameOffset), filenameSize });
    LocalUnicodeStringBuilder<512> lusb;
    CHECK(lusb.Set(cs), false, "");
    lusb.ToString(exePath);

    bool found = exePath.ends_with(filename);
    if (found == false && exePath.ends_with(".EXE") &&
        exePath.find(filename) != std::string::npos) // filename such as DCODEDCODEDCODEDCODEDCODEDCOD-9054DA3F.pf
    {
        const auto sepPos = exePath.find_last_of('\\');
        const auto fPos   = exePath.find_first_of(filename, sepPos);
        found             = fPos != std::string::npos;
    }

    if (found)
    {
        xpHash    = SSCA_XP_HASH({ (bufferSectionC.GetData() + filenameOffset), exePath.size() * sizeof(char16) });
        vistaHash = SSCA_VISTA_HASH({ (bufferSectionC.GetData() + filenameOffset), exePath.size() * sizeof(char16) });
        hash2008  = SSCA_2008_HASH({ (bufferSectionC.GetData() + filenameOffset), exePath.size() * sizeof(char16) });
    }

    return found;
}

bool PrefetchFile::AddVolumeEntry(
      uint32 sectionDOffset,
      uint32 devicePathOffset,
      uint32 devicePathLength,
      uint32 fileReferencesOffset,
      uint32 fileReferencesSize,
      uint32 directoryStringsOffset,
      uint32 i)
{
    VolumeEntry ve;

    const auto nOffset = sectionDOffset + devicePathOffset;
    {
        const auto b = obj->GetData().CopyToBuffer(
              nOffset, static_cast<uint32>(std::min<>(devicePathLength * sizeof(char16*), obj->GetData().GetSize() - nOffset - 4)));
        ConstString cs{ u16string_view{ (char16_t*) b.GetData(), b.GetLength() } };
        LocalUnicodeStringBuilder<1024> lsub;
        CHECK(lsub.Set(cs), false, "");
        lsub.ToString(ve.name);
    }

    const auto fOffset = sectionDOffset + fileReferencesOffset;
    ve.files           = obj->GetData().CopyToBuffer(fOffset, fileReferencesSize);

    const auto dOffset = sectionDOffset + directoryStringsOffset;
    ve.directories     = obj->GetData().CopyToBuffer(dOffset, static_cast<uint32>(obj->GetData().GetSize() - dOffset)); // lazy

    volumeEntries.emplace(std::pair<uint32, VolumeEntry>{ i, ve });

    return true;
}

bool PrefetchFile::SetEntries(
      uint32 sectionAOffset,
      uint32 sectionASize,
      uint32 sectionBOffset,
      uint32 sectionBSize,
      uint32 sectionCOffset,
      uint32 sectionCSize,
      uint32 sectionDOffset)
{
    bufferSectionAEntries = obj->GetData().CopyToBuffer(sectionAOffset, sectionASize);
    bufferSectionBEntries = obj->GetData().CopyToBuffer(sectionBOffset, sectionBSize);
    bufferSectionC        = obj->GetData().CopyToBuffer(sectionCOffset, sectionCSize);
    bufferSectionD        = obj->GetData().CopyToBuffer(sectionDOffset, obj->GetData().GetSize() - sectionDOffset);

    return true;
}

bool PrefetchFile::Update()
{
    CHECK(obj->GetData().Copy<Header>(0, header), false, "");

    switch (header.version)
    {
    case Magic::WIN_XP_2003:
        return Update_17();
    case Magic::WIN_VISTA_7:
        return Update_23();
    case Magic::WIN_8:
        return Update_26();
    case Magic::WIN_10:
        return Update_30();
    default:
        throw std::runtime_error("Header version not recognized!");
    }

    return true;
}
