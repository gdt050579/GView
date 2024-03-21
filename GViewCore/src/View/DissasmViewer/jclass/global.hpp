#pragma once

#include <cassert>
#include <GView.hpp>

namespace GView::View::DissasmViewer::JClass
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace GView;

template <typename T>
class ArrayRef
{
    const T* ptr;
    size_t ptr_size;

  public:
    ArrayRef(const T* ptr, size_t ptr_size)
    {
        this->ptr      = ptr;
        this->ptr_size = ptr_size;
    }
};

template <typename T>
class ArrayRefMut
{
    T* ptr;
    size_t ptr_size;

  public:
    ArrayRefMut()
    {
        ptr      = nullptr;
        ptr_size = 0;
    }
    ArrayRefMut(T* ptr, size_t ptr_size)
    {
        this->ptr      = ptr;
        this->ptr_size = ptr_size;
    }

    ArrayRefMut(ArrayRefMut& other)
    {
        ptr      = other.ptr;
        ptr_size = other.ptr_size;
    }

    ArrayRefMut& operator=(const ArrayRefMut& other)
    {
        ptr      = other.ptr;
        ptr_size = other.ptr_size;
        return *this;
    }

    T& operator[](size_t i)
    {
        assert(i < size());
        return ptr[i];
    }

    size_t size() const
    {
        return ptr_size;
    }
};

struct Opcode {
    struct Arg {
        bool exists;
        bool is_unsigned;
        uint32 value;
    };
    uint8 opcode;
    Arg args[3];

    const char* get_name() const;
};

class BufferReader
{
    const uint8* ptr_start;
    const uint8* ptr_current;
    const uint8* ptr_end;

  public:
    BufferReader(const uint8* ptr_start, size_t size);

    size_t available() const;
    size_t offset() const;
    bool has_more() const;
    bool done() const;
    const uint8* get() const;
    bool read(void* buffer, size_t size);
    bool skip(size_t size);

    template <typename T>
    bool read(T& x)
    {
        return read(&x, sizeof(x));
    }

    template <typename T>
    bool read_little(T& x)
    {
        if (!read(&x, sizeof(x)))
            return false;
        x = Endian::LittleToNative(x);
        return true;
    }

    template <typename T>
    bool read_big(T& x)
    {
        if (!read(&x, sizeof(x)))
            return false;
        x = Endian::BigToNative(x);
        return true;
    }
};

struct ColoredArea {
    uint32 start;
    uint32 end;
    const char* name;
};

struct ConstPanel {
    LocalString<256> data;
};

#define READL(x)                                                                                                                                               \
    if (!reader.read_little(x))                                                                                                                                \
    return false

#define READB(x)                                                                                                                                               \
    if (!reader.read_big(x))                                                                                                                                   \
    return false

#define SKIPTYPE(x)                                                                                                                                            \
    if (!reader.skip(sizeof(x)))                                                                                                                               \
    return false

#define SKIP(x)                                                                                                                                                \
    if (!reader.skip(x))                                                                                                                                       \
    return false

#define FCHECK(x)     CHECK(x, false, #x)
#define FCHECKNULL(x) CHECK(x, nullptr, #x)

#ifndef DISSASM_JCLASS_DEV
#    define unreachable return false;
#    define unimplemented unreachable
#else
#define unreachable std::abort()
#define unimplemented unreachable
#endif
} // namespace GView::View::DissasmViewer::JClass
