#pragma once

#include <GView.hpp>

namespace GView::DigitalSignature
{
constexpr auto SIGNATURE_NOT_FOUND = 0x800B0100;

// 'file' must exist on disk: the object itself or its copy from GView::App::DropToTemporaryFile
bool VerifySignatureForPE(const std::filesystem::path& file, AuthenticodeMS& data);
bool GetSignaturesInformation(const std::filesystem::path& file, AuthenticodeMS& container);
} // namespace GView::DigitalSignature
