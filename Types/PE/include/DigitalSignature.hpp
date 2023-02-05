#pragma once

#include <GView.hpp>

namespace GView::DigitalSignature
{
bool __VerifyEmbeddedSignature__(ConstString source, Utils::DataCache& cache, AuthenticodeMS& data);
bool GetSignaturesInformation(ConstString source, AuthenticodeMS& container);
} // namespace GView::DigitalSignature
