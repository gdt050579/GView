#include "SecureMemory.hpp"

#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#else
#    include <sys/mman.h>
#    include <unistd.h>
#endif

namespace GView::Security::Learning
{
namespace
{
    size_t PageSize() noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return si.dwPageSize ? si.dwPageSize : 4096;
#else
        const long ps = sysconf(_SC_PAGESIZE);
        return ps > 0 ? static_cast<size_t>(ps) : 4096;
#endif
    }

    bool TryLock(void* p, size_t n) noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        if (VirtualLock(p, n))
            return true;
        if (GetLastError() != ERROR_WORKING_SET_QUOTA)
            return false;
        // The default minimum working set (~200 KiB-1.3 MiB) is too small for task binaries; grow it by the size of
        // this region and retry once.
        SIZE_T minWs = 0, maxWs = 0;
        HANDLE self  = GetCurrentProcess();
        if (!GetProcessWorkingSetSize(self, &minWs, &maxWs))
            return false;
        const SIZE_T margin = 1024 * 1024;
        if (!SetProcessWorkingSetSize(self, minWs + n + margin, maxWs + n + margin))
            return false;
        return VirtualLock(p, n) != FALSE;
#else
        return mlock(p, n) == 0;
#endif
    }

    void Unlock(void* p, size_t n) noexcept
    {
#ifdef BUILD_FOR_WINDOWS
        VirtualUnlock(p, n);
#else
        munlock(p, n);
#endif
    }
} // namespace

LockedBuffer::~LockedBuffer()
{
    Release();
}

LockedBuffer::LockedBuffer(LockedBuffer&& other) noexcept
    : data(other.data), size(other.size), reserved(other.reserved), locked(other.locked)
{
    other.data     = nullptr;
    other.size     = 0;
    other.reserved = 0;
    other.locked   = false;
}

LockedBuffer& LockedBuffer::operator=(LockedBuffer&& other) noexcept
{
    if (this != &other)
    {
        Release();
        data           = other.data;
        size           = other.size;
        reserved       = other.reserved;
        locked         = other.locked;
        other.data     = nullptr;
        other.size     = 0;
        other.reserved = 0;
        other.locked   = false;
    }
    return *this;
}

void LockedBuffer::Release() noexcept
{
    if (data == nullptr)
        return;
    Crypto::Internal::SecureErase(data, reserved);
    if (locked)
        Unlock(data, reserved);
#ifdef BUILD_FOR_WINDOWS
    VirtualFree(data, 0, MEM_RELEASE);
#else
    munmap(data, reserved);
#endif
    data     = nullptr;
    size     = 0;
    reserved = 0;
    locked   = false;
}

bool LockedBuffer::Allocate(size_t bytes) noexcept
{
    Release();
    if (bytes == 0 || bytes > MAX_SIZE)
        return false;
    const size_t page = PageSize();
    const size_t full = ((bytes + page - 1) / page) * page;
#ifdef BUILD_FOR_WINDOWS
    void* p = VirtualAlloc(nullptr, full, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p == nullptr)
        return false;
#else
    void* p = mmap(nullptr, full, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return false;
#    ifdef MADV_DONTDUMP
    madvise(p, full, MADV_DONTDUMP); // keep task content out of core dumps
#    endif
#endif
    // freshly committed pages are zero-filled by the OS
    data     = static_cast<uint8*>(p);
    size     = bytes;
    reserved = full;
    locked   = TryLock(p, full);
    return true;
}

void LockedBuffer::Truncate(size_t newSize) noexcept
{
    if (data == nullptr || newSize >= size)
        return;
    Crypto::Internal::SecureErase(data + newSize, size - newSize);
    size = newSize;
}

void LockedBuffer::Wipe() noexcept
{
    Release();
}
} // namespace GView::Security::Learning
