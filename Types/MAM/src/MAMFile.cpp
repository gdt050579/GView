#include "MAM.hpp"

using namespace GView::Type::MAM;

MAMFile::MAMFile()
{
}

bool MAMFile::Update()
{
    auto b = obj->GetData().Get(0, 8, true);
    CHECK(b.IsValid(), false, "");
    signature        = *(uint32*) b.GetData();
    uncompressedSize = *(uint32*) (b.GetData() + 4);
    compressedSize   = static_cast<uint32>(obj->GetData().GetSize() - 8);

    return true;
}
