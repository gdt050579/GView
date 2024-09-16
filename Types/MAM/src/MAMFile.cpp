#include "MAM.hpp"

using namespace GView::Type::MAM;

bool MAMFile::Update()
{
    auto b = obj->GetData().Get(0, 8, true);
    CHECK(b.IsValid(), false, "");
    signature        = *(uint32*) b.GetData();
    uncompressedSize = *(uint32*) (b.GetData() + 4);
    compressedSize   = static_cast<uint32>(obj->GetData().GetSize() - 8);

    return true;
}

void MAMFile::RunCommand(std::string_view commandName)
{
    if (commandName == "Decompress")
    {
        CHECKRET(Decompress(), "");
    }
}

bool MAMFile::UpdateKeys(KeyboardControlsInterface* interface)
{
    for (auto& entry : MAM_COMMANDS)
        interface->RegisterKey(&entry);
    return true;
}

bool MAMFile::Decompress()
{
    Buffer uncompressed;
    uncompressed.Resize(uncompressedSize);

    const auto chunk = obj->GetData().GetCacheSize();
    uint64 pos       = 8ULL;
    const auto size  = obj->GetData().GetSize() - pos;

    Buffer compressed;
    compressed.Resize(size);

    while (pos < obj->GetData().GetSize())
    {
        auto toRead    = std::min<uint64>((uint64) chunk, obj->GetData().GetSize() - pos);
        const Buffer b = obj->GetData().CopyToBuffer(pos, chunk, false);
        memcpy(compressed.GetData() + pos - 8ULL, b.GetData(), toRead);
        pos += toRead;
    }

    CHECK(GView::Decoding::LZXPRESS::Huffman::Decompress(compressed, uncompressed), false, "");

    LocalUnicodeStringBuilder<2048> fullPath;
    fullPath.Add(obj->GetPath());
    fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
    fullPath.Add(obj->GetName());

    GView::App::OpenBuffer(uncompressed, obj->GetName(), fullPath, GView::App::OpenMethod::BestMatch);

    return true;
}
