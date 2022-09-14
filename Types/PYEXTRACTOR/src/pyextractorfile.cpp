#include "pyextractor.hpp"

namespace GView::Type::PYEXTRACTOR
{
PYEXTRACTORFile::PYEXTRACTORFile()
{
}

bool PYEXTRACTORFile::Update()
{
    panelsMask |= (1ULL << (uint8) Panels::IDs::Information);

    CHECK(SetCookiePosition(), false, "");
    CHECK(SetInstallerVersion(), false, "");
    CHECK(SetInfo(), false, "");

    return true;
}

bool PYEXTRACTORFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << ((uint8) id))) != 0;
}

bool PYEXTRACTORFile::SetCookiePosition()
{
    const auto fullBuffer = obj->GetData().GetEntireFile();
    if (fullBuffer.IsValid())
    {
        const std::string_view fullView{ reinterpret_cast<char*>(const_cast<uint8*>(fullBuffer.GetData())), fullBuffer.GetLength() };
        if (const auto index = fullView.find(PYINSTALLER_MAGIC, 0); index != std::string::npos)
        {
            archive.cookiePosition = index;
            return true;
        }
    }
    else
    {
        throw std::runtime_error("Not implemented!");
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

bool PYEXTRACTORFile::SetInfo()
{
    const uint64 size = (archive.version == PyInstallerVersion::V20 ? PYINSTALLER20_COOKIE_SIZE : PYINSTALLER21_COOKIE_SIZE);

    const auto bufferView = obj->GetData().CopyToBuffer(archive.cookiePosition, static_cast<uint32>(size));
    CHECK(bufferView.IsValid(), false, "");
    memcpy(&archive.info, bufferView.GetData(), size);

    archive.info.lengthofPackage = AppCUI::Endian::BigToNative(archive.info.lengthofPackage);
    archive.info.toc             = AppCUI::Endian::BigToNative(archive.info.toc);
    archive.info.tocLen          = AppCUI::Endian::BigToNative(archive.info.tocLen);
    archive.info.pyver           = AppCUI::Endian::BigToNative(archive.info.pyver);

    return true;
}
} // namespace GView::Type::PYEXTRACTOR
