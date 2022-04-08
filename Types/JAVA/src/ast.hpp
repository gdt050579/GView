#pragma once

#include "global.hpp"

namespace GView::Java
{
class BumpPtrAlloc
{
    struct Block
    {
        uint8* original;
        uint8* ptr;
        size_t size;
    };

    static constexpr size_t ALIGNMENT  = alignof(void*);
    static constexpr size_t BLOCK_SIZE = 256 * 1024;
    vector<Block> blocks;
    size_t last_block = -1;

    void fill_last_block(size_t size);

  public:
    ~BumpPtrAlloc();

    uint8* alloc(size_t size);

    template <typename T>
    ArrayRefMut<T> alloc_array(size_t count)
    {
        static_assert(alignof(T) <= ALIGNMENT);
        static_assert(std::is_trivially_destructible_v<T>);

        auto ptr = reinterpret_cast<T*>(alloc(sizeof(T) * count));
        for (size_t i = 0; i < count; ++i)
        {
            new (ptr + i) T();
        }

        return { ptr, count };
    }

    template <typename T, typename... Args>
    T* alloc(Args&&... args)
    {
        static_assert(alignof(T) <= ALIGNMENT);
        static_assert(std::is_trivially_destructible_v<T>);
        auto ptr = alloc(sizeof(T));
        return new (ptr) T(args...);
    }

    string_view alloc(string_view x);
};

struct FieldAccessFlags
{
    bool acc_public : 1;
    bool acc_private : 1;
    bool acc_protected : 1;
    bool acc_static : 1;
    bool acc_final : 1;
    bool acc_volatile : 1;
    bool acc_transient : 1;
    bool acc_synthetic : 1;
    bool acc_enum : 1;
};

struct Field
{
    FieldAccessFlags access_flags;
    string_view name;
    uint32_t unknown_attributes;
};

struct MethodAccessFlags
{
    bool acc_public : 1;
    bool acc_private : 1;
    bool acc_protected : 1;
    bool acc_static : 1;
    bool acc_final : 1;
    bool acc_synchronized : 1;
    bool acc_bridge : 1;
    bool acc_varargs : 1;
    bool acc_native : 1;
    bool acc_abstract : 1;
    bool acc_strict : 1;
    bool acc_synthetic : 1;
};

struct Method
{
    string_view name;
    string_view name2;
    MethodAccessFlags access_flags;
    BufferView code;
    uint32_t unknown_attributes;
};

struct Class
{
    ArrayRefMut<Field*> fields;
    ArrayRefMut<Method*> methods;
};

struct AstContext
{
    BumpPtrAlloc alloc;

    vector<Class*> classes;
};

} // namespace GView::Java