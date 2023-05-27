#include "pyextractor.hpp"

namespace GView::Type::PYEXTRACTOR
{
PYEXTRACTORFile::PYEXTRACTORFile()
{
}

bool PYEXTRACTORFile::Update()
{
    panelsMask |= (1ULL << (uint8) Panels::IDs::Information);
    panelsMask |= (1ULL << (uint8) Panels::IDs::TOCEntries);

    CHECK(SetCookiePosition(), false, "");
    CHECK(SetInstallerVersion(), false, "");
    CHECK(SetInfo(), false, "");
    CHECK(SetTableOfContentEntries(), false, "");

    return true;
}

bool PYEXTRACTORFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8) id))) != 0;
}

bool PYEXTRACTORFile::SetCookiePosition()
{
    const auto buffer = obj->GetData().GetEntireFile();
    if (buffer.IsValid())
    {
        const std::string_view view{ reinterpret_cast<char*>(const_cast<uint8*>(buffer.GetData())), buffer.GetLength() };
        if (const auto index = view.find(PYINSTALLER_MAGIC, 0); index != std::string::npos)
        {
            archive.cookiePosition = index;
            return true;
        }
        return false;
    }

    const auto fileSize  = obj->GetData().GetSize();
    const auto cacheSize = (uint64) obj->GetData().GetCacheSize();
    uint64 sizeToRead    = cacheSize;
    uint64 index         = 0;

    do
    {
        const auto buffer = obj->GetData().CopyToBuffer(index, sizeToRead);
        CHECK(buffer.IsValid(), false, "");

        const std::string_view view{ reinterpret_cast<char*>(const_cast<uint8*>(buffer.GetData())), buffer.GetLength() };
        if (const auto index = view.find(PYINSTALLER_MAGIC, 0); index != std::string::npos)
        {
            archive.cookiePosition = index;
            return true;
        }

        index += sizeToRead;
        sizeToRead = std::min(fileSize, cacheSize);
    } while (index < fileSize);

    return false;
}

inline void tolower(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
}

bool PYEXTRACTORFile::SetInstallerVersion()
{
    constexpr std::string_view marker{ "python" };
    const auto bufferView = obj->GetData().CopyToBuffer(archive.cookiePosition + PYINSTALLER20_COOKIE_SIZE, 64);
    CHECK(bufferView.IsValid(), false, "");
    std::string version{ (char*) bufferView.GetData(), bufferView.GetLength() };
    tolower(version);
    if (version.find(marker))
    {
        archive.version = PyInstallerVersion::V21Plus;
    }
    else
    {
        archive.version = PyInstallerVersion::V20;
    }

    return true;
}

inline void Swap(Archive& archive)
{
    archive.info.lengthofPackage        = AppCUI::Endian::BigToNative(archive.info.lengthofPackage);
    archive.info.tableOfContentPosition = AppCUI::Endian::BigToNative(archive.info.tableOfContentPosition);
    archive.info.tableOfContentSize     = AppCUI::Endian::BigToNative(archive.info.tableOfContentSize);
    archive.info.pyver                  = AppCUI::Endian::BigToNative(archive.info.pyver);
}

bool PYEXTRACTORFile::SetInfo()
{
    const uint64 size = (archive.version == PyInstallerVersion::V20 ? PYINSTALLER20_COOKIE_SIZE : PYINSTALLER21_COOKIE_SIZE);

    const auto bufferView = obj->GetData().CopyToBuffer(archive.cookiePosition, static_cast<uint32>(size));
    CHECK(bufferView.IsValid(), false, "");
    memcpy(&archive.info, bufferView.GetData(), size);
    Swap(archive);

    return true;
}

inline void Swap(TOCEntry& entry)
{
    entry.entrySize        = AppCUI::Endian::BigToNative(entry.entrySize);
    entry.entryPos         = AppCUI::Endian::BigToNative(entry.entryPos);
    entry.cmprsdDataSize   = AppCUI::Endian::BigToNative(entry.cmprsdDataSize);
    entry.uncmprsdDataSize = AppCUI::Endian::BigToNative(entry.uncmprsdDataSize);
    entry.cmprsFlag        = AppCUI::Endian::BigToNative(entry.cmprsFlag);
    entry.typeCmprsData    = AppCUI::Endian::BigToNative(entry.typeCmprsData);
}

bool PYEXTRACTORFile::SetTableOfContentEntries()
{
    const auto a = obj->GetData().CopyToBuffer(archive.info.tableOfContentPosition, archive.info.tableOfContentSize);
    const auto b = a.GetData();

    uint64 i             = archive.info.tableOfContentPosition;
    const auto maxOffset = archive.info.tableOfContentPosition + archive.info.tableOfContentSize;
    while (i < maxOffset)
    {
        const auto bufferView = obj->GetData().CopyToBuffer(i, TOC_ENTRY_KNOWN_SIZE);
        CHECK(bufferView.IsValid(), false, "");

        auto& entry = tocEntries.emplace_back();
        memcpy(&entry, bufferView.GetData(), TOC_ENTRY_KNOWN_SIZE);
        Swap(entry);

        const auto nameLen = entry.entrySize - TOC_ENTRY_KNOWN_SIZE;

        if (nameLen != 0)
        {
            entry.name = obj->GetData().CopyToBuffer(i + TOC_ENTRY_KNOWN_SIZE, static_cast<uint32>(nameLen));
        }
        else
        {
            static uint32 countUnnamed = 0;
            LocalString<30> ls;
            ls.Format("unnamed_%u", countUnnamed);
            entry.name.Add(ls);
        }
        i += entry.entrySize;
    }

    return true;
}

bool PYEXTRACTORFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    CHECK(tocEntries.empty() == false, false, "");
    currentItemIndex = 0;
    return true;
}

bool PYEXTRACTORFile::PopulateItem(TreeViewItem item)
{
    const static auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, '.' };
    const static auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };
    NumericFormatter n;
    LocalString<128> tmp;

    auto& entry = tocEntries.at(currentItemIndex);
    item.SetText(std::string_view{ reinterpret_cast<char*>(entry.name.GetData()), entry.name.GetLength() });
    item.SetData<PYEXTRACTOR::TOCEntry>(&tocEntries.at(currentItemIndex));

    item.SetText(1, n.ToString((uint64) entry.entrySize, dec));
    item.SetText(2, n.ToString((uint64) entry.entryPos, dec));
    item.SetText(3, n.ToString((uint64) entry.cmprsdDataSize, dec));
    item.SetText(4, n.ToString((uint64) entry.uncmprsdDataSize, dec));
    item.SetText(5, n.ToString((uint64) entry.cmprsFlag, dec));
    item.SetText(6, n.ToString((uint64) entry.typeCmprsData, dec));

    item.SetPriority(0);
    item.SetExpandable(false);

    currentItemIndex++;

    return currentItemIndex != tocEntries.size();
}

/*
    const auto& pos  = entry->entryPos;
    const auto& size = entry->cmprsdDataSize;

    const auto bufferCompressed = py->obj->GetData().CopyToBuffer(pos, size);
    CHECKRET(bufferCompressed.IsValid(), "");

    Buffer bufferDecompressed{};
    CHECKRET(ZLIB::Decompress(bufferCompressed, bufferCompressed.GetLength(), bufferDecompressed, entry->uncmprsdDataSize), "");

    GView::App::OpenBuffer(BufferView{ bufferDecompressed }, entry->name);

*/

void PYEXTRACTORFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    auto data         = item.GetData<TOCEntry>();
    const auto offset = (uint64) data->entryPos;
    const auto length = (uint32) data->cmprsdDataSize;
    const auto name   = std::string_view{ reinterpret_cast<char*>(data->name.GetData()), data->name.GetLength() };
    const auto buffer = obj->GetData().CopyToBuffer(offset, length);

    GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch);
}
} // namespace GView::Type::PYEXTRACTOR
