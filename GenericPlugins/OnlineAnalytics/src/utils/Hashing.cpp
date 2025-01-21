#include "utils/Hashing.hpp"
#include <inttypes.h>

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

String hashSha256(Reference<GView::Object> object)
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

        CHECK(bufferView.IsValid(), String(""), "");
        CHECK(sha256.Update(bufferView.GetData(), bufferView.GetLength()), String(""), "");
        CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, size)) == false, String(""), "");

        offset += block;
    } while (offset < size);

    CHECK(sha256.Final(), String(""), "");

    String hash = sha256.GetHexValue();
    return hash;
};

} // namespace GView::GenericPlugins::OnlineAnalytics::Utils