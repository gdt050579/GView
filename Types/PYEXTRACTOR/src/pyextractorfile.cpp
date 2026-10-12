#include "pyextractor.hpp"
#include <cstring>

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
    if (buffer.IsValid()) {
        const std::string_view view{ reinterpret_cast<char*>(const_cast<uint8*>(buffer.GetData())), buffer.GetLength() };
        if (const auto index = view.find(PYINSTALLER_MAGIC, 0); index != std::string::npos) {
            archive.cookiePosition = index;
            return true;
        }
        return false;
    }

    // Chunked search. Consecutive chunks overlap by (magic size - 1) bytes so a magic split across two chunks is still
    // found, and a match is converted back to a file offset.
    const auto fileSize    = obj->GetData().GetSize();
    const uint64 chunkSize = std::max<uint64>(obj->GetData().GetCacheSize(), PYINSTALLER_MAGIC.size() * 2);
    const uint64 overlap   = PYINSTALLER_MAGIC.size() - 1;
    uint64 position        = 0;

    while (position < fileSize) {
        const auto toRead = std::min<uint64>(chunkSize, fileSize - position);
        const auto buffer = obj->GetData().CopyToBuffer(position, static_cast<uint32>(toRead));
        CHECK(buffer.IsValid(), false, "");

        const std::string_view view{ reinterpret_cast<const char*>(buffer.GetData()), buffer.GetLength() };
        if (const auto found = view.find(PYINSTALLER_MAGIC, 0); found != std::string::npos) {
            archive.cookiePosition = position + found;
            return true;
        }

        if (position + toRead >= fileSize) {
            break;
        }
        position += toRead - overlap;
    }

    return false;
}

inline void tolower(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
}

bool PYEXTRACTORFile::SetInstallerVersion()
{
    constexpr std::string_view marker{ "python" };
    // a 2.0 cookie can be the last bytes of the file, so the 2.1+ library name that would follow it may be missing
    const auto bufferView = obj->GetData().CopyToBuffer(archive.cookiePosition + PYINSTALLER20_COOKIE_SIZE, 64, false);
    std::string version;
    if (bufferView.IsValid()) {
        version.assign(reinterpret_cast<const char*>(bufferView.GetData()), bufferView.GetLength());
    }
    tolower(version);
    if (version.find(marker) != std::string::npos) {
        archive.version = PyInstallerVersion::V21Plus;
    } else {
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
    // 64-bit sum (no wrap) and never past the end of the file: every entry is at least TOC_ENTRY_KNOWN_SIZE bytes, so the loop is bounded
    uint64 i             = archive.info.tableOfContentPosition;
    const auto maxOffset = std::min<uint64>(static_cast<uint64>(archive.info.tableOfContentPosition) + archive.info.tableOfContentSize,
                                            obj->GetData().GetSize());
    uint32 countUnnamed  = 0;
    while (i < maxOffset) {
        const auto bufferView = obj->GetData().CopyToBuffer(i, TOC_ENTRY_KNOWN_SIZE);
        CHECK(bufferView.IsValid(), false, "");

        auto& entry = tocEntries.emplace_back();
        memcpy(static_cast<TOCEntryHeader*>(&entry), bufferView.GetData(), TOC_ENTRY_KNOWN_SIZE);
        Swap(entry);

        // an entry smaller than its own header would underflow the name length and never advance (entrySize == 0)
        if (entry.entrySize < TOC_ENTRY_KNOWN_SIZE) {
            tocEntries.pop_back();
            return false;
        }
        const auto nameLen = entry.entrySize - TOC_ENTRY_KNOWN_SIZE;

        if (nameLen != 0) {
            entry.name = obj->GetData().CopyToBuffer(i + TOC_ENTRY_KNOWN_SIZE, static_cast<uint32>(nameLen));
        } else {
            LocalString<30> ls;
            ls.Format("unnamed_%u", countUnnamed++);
            entry.name.Add(ls);
        }
        i += entry.entrySize;
    }

    return true;
}

GView::Utils::JsonBuilderInterface* PYEXTRACTORFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddUInt("CookiePosition", archive.cookiePosition);
    builder->AddString("PyInstallerVersion", archive.version == PyInstallerVersion::V20 ? "2.0" : "2.1+");
    builder->AddUInt("TableOfContentPosition", archive.info.tableOfContentPosition);
    builder->AddUInt("TableOfContentSize", archive.info.tableOfContentSize);
    builder->AddUInt("PyVersion", archive.info.pyver);
    // pylibname comes from the file and is not guaranteed to be NUL terminated
    const std::string_view pylibname{ archive.info.pylibname, strnlen(archive.info.pylibname, sizeof(archive.info.pylibname)) };
    if (!pylibname.empty())
        builder->AddString("PylibName", pylibname);

    return builder;
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
    [[maybe_unused]] const static auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };
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
