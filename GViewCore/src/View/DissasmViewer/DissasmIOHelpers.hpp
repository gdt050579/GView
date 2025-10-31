#pragma once
#include "AppCUI/include/AppCUI.hpp"
using AppCUI::uint32;

// ------------------ constexpr bswap for 16/32/64 ------------------
constexpr inline std::uint16_t bswap16(std::uint16_t x) noexcept
{
    return static_cast<std::uint16_t>((x << 8) | (x >> 8));
}

constexpr inline std::uint32_t bswap32(std::uint32_t x) noexcept
{
    return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) | ((x & 0x00FF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
}

constexpr inline std::uint64_t bswap64(std::uint64_t x) noexcept
{
    return ((x & 0x00000000000000FFull) << 56) | ((x & 0x000000000000FF00ull) << 40) | ((x & 0x0000000000FF0000ull) << 24) |
           ((x & 0x00000000FF000000ull) << 8) | ((x & 0x000000FF00000000ull) >> 8) | ((x & 0x0000FF0000000000ull) >> 24) | ((x & 0x00FF000000000000ull) >> 40) |
           ((x & 0xFF00000000000000ull) >> 56);
}

// Generic byteswap for integral or enum (8/16/32/64-bit). 1-byte is a no-op.
template <class T>
constexpr inline std::enable_if_t<std::is_integral_v<T> || std::is_enum_v<T>, T> byteswap(T v) noexcept
{
    using U0 = std::conditional_t<std::is_enum_v<T>, std::underlying_type_t<T>, T>;
    using U  = std::make_unsigned_t<U0>;
    if constexpr (sizeof(U) == 1) {
        return v;
    } else if constexpr (sizeof(U) == 2) {
        auto r = static_cast<U>(bswap16(static_cast<std::uint16_t>(static_cast<U>(v))));
        return static_cast<T>(static_cast<U0>(r));
    } else if constexpr (sizeof(U) == 4) {
        auto r = static_cast<U>(bswap32(static_cast<std::uint32_t>(static_cast<U>(v))));
        return static_cast<T>(static_cast<U0>(r));
    } else if constexpr (sizeof(U) == 8) {
        auto r = static_cast<U>(bswap64(static_cast<std::uint64_t>(static_cast<U>(v))));
        return static_cast<T>(static_cast<U0>(r));
    } else {
        static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8, "byteswap only supports 8/16/32/64-bit types");
        return v; // unreachable
    }
}

// ------------------ Endian detection (compile-time where possible) ------------------
#if defined(__has_include) && __has_include(<bit>) && defined(__cpp_lib_endian) && __cpp_lib_endian >= 201907L
#    include <bit>
constexpr bool kHostIsLittleEndian = (std::endian::native == std::endian::little);
#elif defined(_WIN32) || defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
constexpr bool kHostIsLittleEndian = true;
#else
// Fallback: assume big if we can't prove little at compile time
constexpr bool kHostIsLittleEndian = false;
#endif

// Convert LE-on-disk <-> native
template <class T>
constexpr inline T to_native_little_integral_or_enum(T v) noexcept
{
    static_assert(std::is_integral_v<T> || std::is_enum_v<T>, "integral/enum only");
    if constexpr (kHostIsLittleEndian)
        return v;
    else
        return byteswap(v);
}

template <class T>
inline T to_native_little_float(T v) noexcept
{
    static_assert(std::is_floating_point_v<T>, "float/double only");
    if constexpr (kHostIsLittleEndian) {
        return v;
    } else {
        if constexpr (sizeof(T) == 4) {
            std::uint32_t u;
            std::memcpy(&u, &v, 4);
            u = bswap32(u);
            std::memcpy(&v, &u, 4);
            return v;
        } else { // sizeof(double)==8
            std::uint64_t u;
            std::memcpy(&u, &v, 8);
            u = bswap64(u);
            std::memcpy(&v, &u, 8);
            return v;
        }
    }
}

template <class T>
constexpr inline T from_native_to_little(T v) noexcept
{
    static_assert(std::is_integral_v<T> || std::is_enum_v<T>, "integral or enum required");
    if constexpr (kHostIsLittleEndian)
        return v;
    else
        return byteswap(v);
}

// Read primitives

template <class T>
static inline bool read_primitive(const std::byte*& p, const std::byte* end, T& out) noexcept
{
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

    const std::ptrdiff_t need  = static_cast<std::ptrdiff_t>(sizeof(T));
    const std::ptrdiff_t avail = end - p;
    if (avail < need)
        return false;

    std::memcpy(&out, p, sizeof(T)); // defined behavior (no alignment requirement)
    p += need;                       // advance carefully in ptrdiff_t units

    if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) {
        out = to_native_little_integral_or_enum(out); // LE on disk -> native
    } else if constexpr (std::is_floating_point_v<T>) {
        out = to_native_little_float(out); // LE on disk -> native
    } // else: trivially copyable POD with no defined endian format; leave as-is

    return true;
}

static inline bool read_bytes(const std::byte*& p, const std::byte* end, std::size_t len, const std::byte*& out_begin) noexcept
{
    const std::ptrdiff_t avail = end - p;
    if (len > static_cast<std::size_t>(avail))
        return false;
    out_begin = p;
    p += static_cast<std::ptrdiff_t>(len);
    return true;
}

static inline bool read_u32_len_prefixed_string(const std::byte*& p, const std::byte* end, std::string& out)
{
    uint32 len_u32 = 0;
    if (!read_primitive(p, end, len_u32))
        return false;
    const std::size_t len    = static_cast<std::size_t>(len_u32);
    const std::byte* s_begin = nullptr;
    if (!read_bytes(p, end, len, s_begin))
        return false;

    try {
        out.assign(reinterpret_cast<const char*>(s_begin), len);
        return true;
    } catch (...) {
        return false; // bad_alloc or other string exception
    }
}

// Writting pimitives

template <typename T>
inline void append_bytes(std::vector<std::byte>& buffer, const T& value)
{
    static_assert(std::is_trivially_copyable_v<T>, "append_bytes requires trivially copyable type");

    if constexpr (std::is_same_v<T, bool>) {
        const std::uint8_t b = value ? 1u : 0u;
        const auto* ptr      = reinterpret_cast<const std::byte*>(&b);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(b));
    } else if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) {
        const auto le   = from_native_to_little(value);
        const auto* ptr = reinterpret_cast<const std::byte*>(&le);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(le));
    } else {
        const auto* ptr = reinterpret_cast<const std::byte*>(&value);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(T));
    }
}

inline void append_string(std::vector<std::byte>& buffer, const std::string& s)
{
    if (s.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("append_string: size exceeds uint32_t");
    }
    const std::uint32_t size = static_cast<std::uint32_t>(s.size());
    append_bytes(buffer, size); // writes size in LE if you use the integral branch above
    const auto* ptr = reinterpret_cast<const std::byte*>(s.data());
    buffer.insert(buffer.end(), ptr, ptr + size);
}