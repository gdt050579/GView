#include "Prefetch.hpp"

using namespace GView::Type::Prefetch;

PrefetchFile::PrefetchFile()
{
}

bool PrefetchFile::Update_17()
{
    for (auto i = 0U; i < area.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_17>(sizeof(VolumeInformationEntry_17) * i);

        CHECK(AddVolumeEntry(
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    for (auto i = 0U; i < area.sectionA.entries; i++)
    {
        auto entry = bufferSectionA.GetObject<FileMetricsEntryRecord_17>(sizeof(FileMetricsEntryRecord_17) * i);

        const std::u16string_view sv{ (char16*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize };
        if (ComputeHashForMainExecutable(sv))
        {
            break;
        }
    }

    FileInformation_17 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_17>(sizeof(header), fileInformation), false, "");
    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_23()
{
    for (auto i = 0U; i < area.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_23_26>(i * sizeof(VolumeInformationEntry_23_26));

        CHECK(AddVolumeEntry(
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    for (auto i = 0U; i < area.sectionA.entries; i++)
    {
        auto entry = bufferSectionA.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

        const std::u16string_view sv{ (char16*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize };
        if (ComputeHashForMainExecutable(sv))
        {
            break;
        }
    }

    FileInformation_23 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_23>(sizeof(header), fileInformation), false, "");
    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_26()
{
    for (auto i = 0U; i < area.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_23_26>(i * sizeof(VolumeInformationEntry_23_26));

        CHECK(AddVolumeEntry(
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    for (auto i = 0U; i < area.sectionA.entries; i++)
    {
        auto entry = bufferSectionA.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

        const std::u16string_view sv{ (char16*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize };
        if (ComputeHashForMainExecutable(sv))
        {
            break;
        }
    }

    FileInformation_26 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_26>(sizeof(header), fileInformation), false, "");
    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_30()
{
    for (auto i = 0U; i < area.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_30>(i * sizeof(VolumeInformationEntry_30));

        CHECK(AddVolumeEntry(
                    entry->devicePathOffset,
                    entry->devicePathLength,
                    entry->fileReferencesOffset,
                    entry->fileReferencesSize,
                    entry->directoryStringsOffset,
                    i),
              false,
              "");
    }

    if (header.version == Magic::WIN_10)
    {
        const auto fiSize = area.sectionA.offset - sizeof(header);
        if (fiSize == 220)
        {
            win10Version = Win10Version::V1;

            FileInformation_30v1 fileInformation{};
            CHECK(obj->GetData().Copy<FileInformation_30v1>(sizeof(header), fileInformation), false, "");
            this->fileInformation = fileInformation;
        }
        else if (fiSize == 212)
        {
            win10Version = Win10Version::V2;

            FileInformation_30v2 fi{};
            CHECK(obj->GetData().Copy<FileInformation_30v2>(sizeof(header), fi), false, "");
            this->fileInformation = fi;

            executablePath = obj->GetData().CopyToBuffer(fi.executablePathOffset, fi.executablePathSize * sizeof(char16));
        }
        else
        {
            throw std::runtime_error("Unknown Windows 10 File Information Version!");
        }
    }

    if (win10Version == Win10Version::V1)
    {
        for (auto i = 0U; i < area.sectionA.entries; i++)
        {
            auto entry = bufferSectionA.GetObject<FileMetricsEntryRecord_23_26_30>(sizeof(FileMetricsEntryRecord_23_26_30) * i);

            const std::u16string_view sv{ (char16*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize };
            if (ComputeHashForMainExecutable(sv))
            {
                break;
            }
        }
    }
    else
    {
        const std::u16string_view sv{ (char16*) executablePath.GetData(), executablePath.GetLength() / sizeof(char16) };
        ComputeHashForMainExecutable(sv);
    }

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

bool PrefetchFile::ComputeHashForMainExecutable(std::u16string_view path)
{
    ConstString cs(path);
    LocalUnicodeStringBuilder<512> lusb;
    CHECK(lusb.Set(cs), false, "");
    lusb.ToString(exePath);
    exePath.resize(strlen(exePath.c_str()));

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
        xpHash    = SSCA_XP_HASH({ path.data(), exePath.size() * sizeof(char16) });
        vistaHash = SSCA_VISTA_HASH({ path.data(), exePath.size() * sizeof(char16) });
        hash2008  = SSCA_2008_HASH({ path.data(), exePath.size() * sizeof(char16) });
    }

    return found;
}

bool PrefetchFile::AddVolumeEntry(
      uint32 devicePathOffset,
      uint32 devicePathLength,
      uint32 fileReferencesOffset,
      uint32 fileReferencesSize,
      uint32 directoryStringsOffset,
      uint32 i)
{
    VolumeEntry ve;

    const auto nOffset = area.sectionD.offset + devicePathOffset;
    {
        const auto buffer = obj->GetData().CopyToBuffer(
              nOffset,
              static_cast<uint32>(std::min<uint64>((uint64) devicePathLength * sizeof(char16), obj->GetData().GetSize() - nOffset - 4ULL)));
        ConstString cs{ u16string_view{ (char16*) buffer.GetData(), buffer.GetLength() } };
        LocalUnicodeStringBuilder<1024> lsub;
        CHECK(lsub.Set(cs), false, "");
        lsub.ToString(ve.name);
        ve.name.resize(devicePathLength);
    }

    const auto fOffset = area.sectionD.offset + fileReferencesOffset;
    ve.files           = obj->GetData().CopyToBuffer(fOffset, fileReferencesSize);

    const auto dOffset = area.sectionD.offset + directoryStringsOffset;
    ve.directories     = obj->GetData().CopyToBuffer(dOffset, static_cast<uint32>(obj->GetData().GetSize() - dOffset)); // lazy

    volumeEntries.emplace(std::pair<uint32, VolumeEntry>{ i, ve });

    return true;
}

bool PrefetchFile::SetEntries(uint32 sectionASize, uint32 sectionBSize, uint32 sectionCSize)
{
    bufferSectionA = obj->GetData().CopyToBuffer(area.sectionA.offset, sectionASize);
    bufferSectionB = obj->GetData().CopyToBuffer(area.sectionB.offset, sectionBSize);
    bufferSectionC = obj->GetData().CopyToBuffer(area.sectionC.offset, sectionCSize);
    bufferSectionD = obj->GetData().CopyToBuffer(area.sectionD.offset, (uint32) obj->GetData().GetSize() - area.sectionD.offset);

    return true;
}

bool PrefetchFile::UpdateSectionArea()
{
    const auto end  = area.sectionC.offset + area.sectionC.length;
    const auto diff = area.sectionD.offset - end;

    CHECK(SetEntries(
                area.sectionA.entries * (uint32) FileMetricsSizes.at(header.version),
                area.sectionB.entries * (uint32) TraceChainEntrySizes.at(header.version),
                (uint32) (diff < 0 ? area.sectionC.length : area.sectionC.length + diff)),
          false,
          "");

    CHECK(SetFilename(), false, "");

    return true;
}

bool PrefetchFile::Update()
{
    CHECK(obj->GetData().Copy<Header>(0, header), false, "");
    CHECK(obj->GetData().Copy<SectionArea>(sizeof(header), area), false, "");
    CHECK(UpdateSectionArea(), false, "");

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
