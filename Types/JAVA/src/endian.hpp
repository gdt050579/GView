#pragma once

#include <cstdint>
#ifdef _MSC_VER
#    include <stdlib.h>
#endif

namespace GView::Java::Endian
{

#ifdef _MSC_VER
// if it's msvc, we assume little endian
#    define GVIEW_LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__)
#    if __BYTE_ORDER__ == __LITTLE_ENDIAN__
#        define GVIEW_LITTLE_ENDIAN
#    else
#        define GVIEW_BIG_ENDIAN
#    endif
#else
#    error "Unknown endianness"
#endif

inline uint8_t swap(uint8_t x)
{
    return x;
}

inline uint16_t swap(uint16_t x)
{
#ifdef _MSC_VER
    return _byteswap_ushort(x);
#else
    return __builtin_bswap16(x);
#endif
}

inline uint32_t swap(uint32_t x)
{
#ifdef _MSC_VER
    return _byteswap_ulong(x);
#else
    return __builtin_bswap32(x);
#endif
}

inline uint64_t swap(uint64_t x)
{
#ifdef _MSC_VER
    return _byteswap_uint64(x);
#else
    return __builtin_bswap64(x);
#endif
}

#define SWAP_SIGNED(fn, t)                                                                                                                 \
    inline int##t##_t fn(int##t##_t x)                                                                                                     \
    {                                                                                                                                      \
        return fn(static_cast<uint##t##_t>(x));                                                                                            \
    }
SWAP_SIGNED(swap, 8);
SWAP_SIGNED(swap, 16);
SWAP_SIGNED(swap, 32);
SWAP_SIGNED(swap, 64);

inline uint8_t native_to_big(uint8_t x)
{
    return x;
}

inline uint16_t native_to_big(uint16_t x)
{
#ifdef GVIEW_BIG_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

inline uint32_t native_to_big(uint32_t x)
{
#ifdef GVIEW_BIG_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

inline uint64_t native_to_big(uint64_t x)
{
#ifdef GVIEW_BIG_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

SWAP_SIGNED(native_to_big, 8);
SWAP_SIGNED(native_to_big, 16);
SWAP_SIGNED(native_to_big, 32);
SWAP_SIGNED(native_to_big, 64);

inline uint8_t big_to_native(uint8_t x)
{
    return x;
}

inline uint16_t big_to_native(uint16_t x)
{
#ifdef GVIEW_LITTLE_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

inline uint32_t big_to_native(uint32_t x)
{
#ifdef GVIEW_LITTLE_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

inline uint64_t big_to_native(uint64_t x)
{
#ifdef GVIEW_LITTLE_ENDIAN
    return swap(x);
#else
    return x;
#endif
}

SWAP_SIGNED(big_to_native, 8);
SWAP_SIGNED(big_to_native, 16);
SWAP_SIGNED(big_to_native, 32);
SWAP_SIGNED(big_to_native, 64);

#undef SWAP_SIGNED

} // namespace GView::Java::Endian