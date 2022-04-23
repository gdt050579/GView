#pragma once

#include <GView.hpp>

namespace GView::Type::MAM
{
constexpr uint32 SIGNATURE = 0x044D414D; // "MAM\x04"

enum class CompressionStatus : uint32
{
    Success                = 0x00000000,
    InvalidParameter       = 0xC000000D,
    UnsupportedCompression = 0xC000025F,
    BadCompressionBuffer   = 0xC0000242
};

bool Decompress(const BufferView& compressed, Buffer& decompressed);
} // namespace GView::Type::MAM
