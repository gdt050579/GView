#include <cstring>
#include <inttypes.h>
#include "utils/Hashing.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

Reference<std::array<uint8, 32>> HashSHA256(Reference<GView::Object> object)
{
    const char* format   = "Read %+" PRIu64 "/%+" PRIu64 " bytes";
    const uint64 size    = object->GetData().GetSize();
    const uint32 block   = object->GetData().GetCacheSize();
    uint64 offset        = 0;
    uint64 requestedSize = 0;
    LocalString<512> ls;
    OpenSSLHash sha256(OpenSSLHashKind::Sha256);

    ProgressStatus::Init("Computing the hash", size);

    do {
        requestedSize         = offset + block > size ? size - offset : block;
        BufferView bufferView = object->GetData().Get(offset, requestedSize, true);

        CHECK(bufferView.IsValid(), NULL, "");
        CHECK(sha256.Update(bufferView.GetData(), bufferView.GetLength()), NULL, "");
        CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, size)) == false, NULL, "");

        offset += block;
    } while (offset < size);

    CHECK(sha256.Final(), NULL, "");

    Reference<std::array<uint8, 32>> hash;
    std::memcpy(hash->data(), sha256.Get(), 32);
    return hash;
};

} // namespace GView::GenericPlugins::OnlineAnalytics::Utils