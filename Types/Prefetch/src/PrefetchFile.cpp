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

        VolumeEntry ve;

        const auto nOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_17) * i + entry->devicePathOffset;
        {
            const auto b = obj->GetData().CopyToBuffer(nOffset, entry->devicePathLength * sizeof(char16_t*));
            ConstString cs{ u16string_view{ (char16_t*) b.GetData(), b.GetLength() } };
            LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
            lsub.Set(cs);
            lsub.ToString(ve.name);
        }

        const auto fOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_17) * i + entry->fileReferencesOffset;
        ve.files           = obj->GetData().CopyToBuffer(fOffset, entry->fileReferencesSize);

        const auto dOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_17) * i + entry->directoryStringsOffset;

        ve.directories = obj->GetData().CopyToBuffer(dOffset, static_cast<uint32>(obj->GetData().GetSize() - dOffset)); // lazy

        volumeEntries.emplace(std::pair<uint32, VolumeEntry>{ i, ve });
    }

    // compute hash on exe path
    std::string filename;
    uint64 filenameSize = 0;
    {
        ConstString cs{ u16string_view{ (char16_t*) &header.executableName,
                                        sizeof(header.executableName) / sizeof(header.executableName[0]) } };
        LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
        lsub.Set(cs);
        lsub.ToString(filename);
        filenameSize = strlen(filename.c_str());
    }

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_17>(sizeof(FileMetricsEntryRecord_17) * i);

        ConstString cs(std::u16string_view{ (char16_t*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize });
        LocalUnicodeStringBuilder<512> lusb;
        lusb.Set(cs);

        lusb.ToString(exePath);

        if (exePath.ends_with(std::string_view{ filename.c_str(), filenameSize }))
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

    bufferSectionD = obj->GetData().CopyToBuffer(
          fileInformation.sectionD.offset, fileInformation.sectionD.entries * sizeof(VolumeInformationEntry_23_26));

    for (auto i = 0U; i < fileInformation.sectionD.entries; i++)
    {
        auto entry = bufferSectionD.GetObject<VolumeInformationEntry_23_26>(sizeof(VolumeInformationEntry_23_26) * i);

        VolumeEntry ve;

        const auto nOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_23_26) * i + entry->devicePathOffset;
        {
            const auto b = obj->GetData().CopyToBuffer(nOffset, entry->devicePathLength * sizeof(char16_t*));
            ConstString cs{ u16string_view{ (char16_t*) b.GetData(), b.GetLength() } };
            LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
            lsub.Set(cs);
            lsub.ToString(ve.name);
        }

        const auto fOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_23_26) * i + entry->fileReferencesOffset;
        ve.files           = obj->GetData().CopyToBuffer(fOffset, entry->fileReferencesSize);

        const auto dOffset = fileInformation.sectionD.offset + sizeof(VolumeInformationEntry_23_26) * i + entry->directoryStringsOffset;

        ve.directories = obj->GetData().CopyToBuffer(dOffset, static_cast<uint32>(obj->GetData().GetSize() - dOffset)); // lazy

        volumeEntries.emplace(std::pair<uint32, VolumeEntry>{ i, ve });
    }

    // compute hash on exe path
    std::string filename;
    uint64 filenameSize = 0;
    {
        ConstString cs{ u16string_view{ (char16_t*) &header.executableName,
                                        sizeof(header.executableName) / sizeof(header.executableName[0]) } };
        LocalUnicodeStringBuilder<sizeof(header.executableName) / sizeof(header.executableName[0])> lsub;
        lsub.Set(cs);
        lsub.ToString(filename);
        filenameSize = strlen(filename.c_str());
    }

    for (auto i = 0U; i < fileInformation.sectionA.entries; i++)
    {
        auto entry = bufferSectionAEntries.GetObject<FileMetricsEntryRecord_23>(sizeof(FileMetricsEntryRecord_23) * i);

        ConstString cs(std::u16string_view{ (char16_t*) (bufferSectionC.GetData() + entry->filenameOffset), entry->filenameSize });
        LocalUnicodeStringBuilder<512> lusb;
        lusb.Set(cs);

        lusb.ToString(exePath);

        if (exePath.ends_with(std::string_view{ filename.c_str(), filenameSize }))
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
