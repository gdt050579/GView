#include "prefetch.hpp"

using namespace GView::Type::Prefetch;

PrefetchFile::PrefetchFile()
{
}

bool PrefetchFile::Update_17()
{
    FileInformation_17 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_17>(sizeof(header), fileInformation), false, "");

    bufferSectionAEntries = obj->GetData().CopyToBuffer(
          fileInformation.sectionA.offset, fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_17));

    bufferSectionBEntries =
          obj->GetData().CopyToBuffer(fileInformation.sectionB.offset, fileInformation.sectionB.entries * sizeof(TraceChainEntry_17_23_26));

    bufferSectionC = obj->GetData().CopyToBuffer(fileInformation.sectionC.offset, fileInformation.sectionC.length);

    bufferSectionD = obj->GetData().CopyToBuffer(
          fileInformation.sectionD.offset, fileInformation.sectionD.entries * sizeof(VolumeInformationEntry_17));

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
            hashComputed = SSCA_XP_HASH({ (bufferSectionC.GetData() + entry->filenameOffset), exePath.size() * sizeof(char16_t) });
            break;
        }
    }

    if (hashComputed == 0)
    {
        exePath = "";
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_23()
{
    FileInformation_23 fileInformation{};
    CHECK(obj->GetData().Copy<FileInformation_23>(sizeof(header), fileInformation), false, "");

    bufferSectionAEntries = obj->GetData().CopyToBuffer(
          fileInformation.sectionA.offset, fileInformation.sectionA.entries * sizeof(FileMetricsEntryRecord_23));

    bufferSectionBEntries =
          obj->GetData().CopyToBuffer(fileInformation.sectionB.offset, fileInformation.sectionB.entries * sizeof(TraceChainEntry_17_23_26));

    bufferSectionC = obj->GetData().CopyToBuffer(fileInformation.sectionC.offset, fileInformation.sectionC.length);

    bufferSectionD =
          obj->GetData().CopyToBuffer(fileInformation.sectionD.offset, obj->GetData().GetSize() - fileInformation.sectionD.offset);

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
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23>(sizeof(FileMetricsEntryRecord_23) * i);

        if (ComputeHashForMainExecutable(entry->filenameOffset, entry->filenameSize))
        {
            hashComputed = SSCA_VISTA_HASH({ (bufferSectionC.GetData() + entry->filenameOffset), exePath.size() * sizeof(char16_t) });
            break;
        }
    }

    if (hashComputed == 0)
    {
        exePath = "";
    }

    this->fileInformation = fileInformation;

    return true;
}

bool PrefetchFile::Update_26()
{
    throw std::runtime_error("Not implemented!");
}

bool PrefetchFile::Update_30()
{
    throw std::runtime_error("Not implemented!");
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
    if (found == false && exePath.find(filename) != std::string::npos) // filename such as DCODEDCODEDCODEDCODEDCODEDCOD-9054DA3F.pf
    {
        const auto sepPos = exePath.find_last_of('\\');
        const auto fPos   = exePath.find_first_of(filename, sepPos);
        found             = fPos != std::string::npos;
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
        const auto b =
              obj->GetData().CopyToBuffer(nOffset, std::min<>(devicePathLength * sizeof(char16_t*), obj->GetData().GetSize() - nOffset));
        ConstString cs{ u16string_view{ (char16_t*) b.GetData(), b.GetLength() } };
        LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
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
