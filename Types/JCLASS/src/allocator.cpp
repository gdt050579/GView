#include "global.hpp"
#include "ast.hpp"

using std::max;
using std::swap;

namespace GView::Type::JClass
{
static uint8* safe_malloc(size_t size)
{
    auto ptr = malloc(size);
    if (ptr == nullptr)
        abort();
    return static_cast<uint8*>(ptr);
}

void BumpPtrAlloc::fill_last_block(size_t size)
{
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (blocks[i].size >= size) {
            last_block = i;
            break;
        }
    }

    // make a new block if we're at this point
    auto new_size = max(size, BLOCK_SIZE);
    auto ptr      = safe_malloc(new_size);
    blocks.push_back({ ptr, ptr, new_size });
    last_block = blocks.size() - 1;
}

BumpPtrAlloc::~BumpPtrAlloc()
{
    for (auto& i : blocks) {
        free(i.original);
    }
}

uint8* BumpPtrAlloc::alloc(size_t size)
{
    size = (size + (ALIGNMENT - 1)) & (0 - ALIGNMENT);
    if (last_block == static_cast<size_t>(-1) || blocks[last_block].size < size) {
        fill_last_block(size);
    }
    auto& block = blocks[last_block];
    auto ptr    = block.ptr;
    block.ptr += size;
    block.size -= size;

    if (block.size == 0) {
        swap(blocks[last_block], blocks.back());
        blocks.pop_back();
        last_block = static_cast<size_t>(-1);
    }

    return ptr;
}

string_view BumpPtrAlloc::alloc(string_view x)
{
    auto ptr = reinterpret_cast<char*>(alloc(x.size()));
    memcpy(ptr, x.data(), x.size());
    return { ptr, x.size() };
}

} // namespace GView::Type::JClass