#pragma once

// Memory hygiene primitives for Learning and Evaluation Mode secrets (access token, content key, decrypted task bytes).
//
// - SecureAllocator zeroes every block before releasing it, so std::vector/std::basic_string growth and destruction
//   never leave stale copies on the heap.
// - LockedBuffer is a fixed-size, page-aligned region that is (best effort) pinned in RAM (VirtualLock / mlock) and
//   wiped on destruction. Whether pinning succeeded is observable through IsLocked().

#include "Internal.hpp"

#include <memory>
#include <string>
#include <vector>

namespace GView::Security::Learning
{
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept = default;
    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept
    {
    }

    T* allocate(size_t n)
    {
        return std::allocator<T>{}.allocate(n);
    }
    void deallocate(T* p, size_t n) noexcept
    {
        if (p != nullptr)
            Crypto::Internal::SecureErase(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }
    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept
    {
        return true;
    }
    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept
    {
        return false;
    }
};

using SecureBytes  = std::vector<uint8, SecureAllocator<uint8>>;
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

inline BufferView ToView(const SecureBytes& b) noexcept
{
    return BufferView(b.data(), b.size());
}
inline BufferView ToView(const SecureString& s) noexcept
{
    return BufferView(s.data(), s.size());
}

// Wipes the characters of a std::string in place (including inline SSO storage) before clearing it.
inline void WipeString(std::string& s) noexcept
{
    if (!s.empty())
        Crypto::Internal::SecureErase(s.data(), s.size());
    s.clear();
}

class LockedBuffer
{
    uint8* data{ nullptr };
    size_t size{ 0 };
    size_t reserved{ 0 };
    bool locked{ false };

    void Release() noexcept;

  public:
    // hard cap on a single locked allocation (largest deliverable is 256 MiB)
    static constexpr size_t MAX_SIZE = 256ull * 1024ull * 1024ull;

    LockedBuffer() noexcept = default;
    ~LockedBuffer();
    LockedBuffer(const LockedBuffer&)            = delete;
    LockedBuffer& operator=(const LockedBuffer&) = delete;
    LockedBuffer(LockedBuffer&& other) noexcept;
    LockedBuffer& operator=(LockedBuffer&& other) noexcept;

    // Allocates (zero-filled) storage. Pinning is attempted; failure to pin is not an error (see IsLocked()).
    bool Allocate(size_t bytes) noexcept;
    // Shrinks the logical size (e.g. after decryption); the tail is wiped.
    void Truncate(size_t newSize) noexcept;
    void Wipe() noexcept;

    inline uint8* Data() noexcept
    {
        return data;
    }
    inline const uint8* Data() const noexcept
    {
        return data;
    }
    inline size_t Size() const noexcept
    {
        return size;
    }
    inline bool IsLocked() const noexcept
    {
        return locked;
    }
    inline bool Empty() const noexcept
    {
        return size == 0;
    }
    inline BufferView View() const noexcept
    {
        return BufferView(data, size);
    }
};
} // namespace GView::Security::Learning
