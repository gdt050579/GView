#pragma once

#include <GView.hpp>

namespace GView::DigitalSignature
{
constexpr auto SIGNATURE_NOT_FOUND = 0x800B0100;

bool VerifySignatureForPE(ConstString source, Utils::DataCache& cache, AuthenticodeMS& data);
bool GetSignaturesInformation(ConstString source, AuthenticodeMS& container);
} // namespace GView::DigitalSignature
