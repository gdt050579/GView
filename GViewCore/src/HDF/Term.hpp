#pragma once

// Hybrid Disclosure Framework (HDF) - identifiers, limits and the term representation.
// Formal counterpart: constants c : s, variables x : s and terms t ::= x | c of the many-sorted vocabulary.

#include "GView.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace GView::HDF
{
using AssertionId    = uint32; // index of a ground assertion in an AssertionBase (Gamma)
using RuleId         = uint32; // index of an assertion rule or of an action rule (separate index spaces)
using StringId       = uint32; // index of an interned string (StringArena)
using GroundActionId = uint32; // index of a ground action in a GroundActionSet
using GeneratorId    = uint16; // index of a generator name ("Plugin:PE", "Rule:X", ...)
using VariableIndex  = uint8;  // rule-scoped variable index

constexpr AssertionId INVALID_ASSERTION_ID        = 0xFFFFFFFFu;
constexpr RuleId INVALID_RULE_ID                  = 0xFFFFFFFFu;
constexpr GroundActionId INVALID_GROUND_ACTION_ID = 0xFFFFFFFFu;
constexpr StringId EMPTY_STRING_ID                = 0; // the empty string; also "no explanation"
constexpr uint32 INVALID_INDEX                    = 0xFFFFFFFFu;

// hard limits, validated when the specification is loaded
constexpr uint32 MAX_RULE_VARIABLES   = 16;
constexpr uint32 MAX_BODY_LITERALS    = 16;
constexpr uint32 MAX_CONSTANT_ID      = 0x7FFFFFFFu; // 31 bits (bit 31 of a Term tags variables)
constexpr uint32 DEFAULT_MAX_DERIVED  = 1000000;     // MAX_DERIVED_PER_STEP default (safety cap of one closure)
constexpr uint32 MAX_SUBJECT_NAME_LEN = 4096;
constexpr uint32 MAX_STRING_CONSTANT  = 1u << 20; // longest String-kind constant accepted from a plugin (1 MiB)

static_assert(MAX_ARITY <= 255 && MAX_BODY_LITERALS <= 255 && MAX_RULE_VARIABLES <= 16);

// t ::= x | c (4 bytes): bit 31 set -> variable (index in the low 8 bits), otherwise a ConstantId
struct Term {
    uint32 raw{ 0 };

    static constexpr uint32 VARIABLE_FLAG = 0x80000000u;

    static constexpr Term Variable(VariableIndex index)
    {
        return Term{ VARIABLE_FLAG | index };
    }
    static constexpr Term Constant(ConstantId id)
    {
        return Term{ id & MAX_CONSTANT_ID };
    }
    constexpr bool IsVariable() const
    {
        return (raw & VARIABLE_FLAG) != 0;
    }
    constexpr bool IsConstant() const
    {
        return (raw & VARIABLE_FLAG) == 0;
    }
    constexpr VariableIndex Variable() const
    {
        return static_cast<VariableIndex>(raw & 0xFFu);
    }
    constexpr ConstantId Constant() const
    {
        return raw;
    }
    constexpr bool operator==(const Term& other) const = default;
};
static_assert(sizeof(Term) == 4, "Term must stay a 4-byte tagged id");

// heterogeneous std::string_view lookup for every name table (no std::string temporaries on lookup paths)
struct TransparentHash {
    using is_transparent = void;
    size_t operator()(std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }
};
struct TransparentEqual {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept
    {
        return a == b;
    }
};
template <typename T>
using StringKeyMap = std::unordered_map<std::string, T, TransparentHash, TransparentEqual>;

// 64-bit mixing (splitmix64 finalizer, bijective) and FNV-1a over 32-bit words
constexpr uint64 Mix64(uint64 x)
{
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}
constexpr uint64 FNV_OFFSET = 0xCBF29CE484222325ULL;
constexpr uint64 FNV_PRIME  = 0x100000001B3ULL;
constexpr uint64 FnvAddWord(uint64 h, uint32 word)
{
    for (uint32 i = 0; i < 4; i++) {
        h ^= (word >> (i * 8)) & 0xFFu;
        h *= FNV_PRIME;
    }
    return h;
}
// hash of a ground atom p(c1..ck) (used by AssertionBase and GroundActionSet)
inline uint64 HashAtom(uint32 symbol, const ConstantId* args, uint32 count)
{
    uint64 h = FnvAddWord(FNV_OFFSET, symbol);
    for (uint32 i = 0; i < count; i++)
        h = FnvAddWord(h, args[i]);
    return Mix64(h);
}

// Open-addressing hash set of 32-bit ids keyed by a 64-bit hash (power-of-two capacity, linear probing, load <= 0.5).
// The table stores ids only; the caller verifies equality (and provides the hash of an id when the table grows).
class HashIndex
{
    std::vector<uint32> slots; // INVALID_INDEX = empty
    uint32 count{ 0 };

  public:
    inline uint32 Count() const
    {
        return count;
    }
    inline size_t MemoryBytes() const
    {
        return slots.capacity() * sizeof(uint32);
    }
    void Clear()
    {
        slots.clear();
        count = 0;
    }
    // returns the id for which eq(id) is true, or INVALID_INDEX
    template <typename Eq>
    uint32 Find(uint64 hash, Eq&& eq) const
    {
        if (slots.empty())
            return INVALID_INDEX;
        const size_t mask = slots.size() - 1;
        for (size_t pos = static_cast<size_t>(hash) & mask;; pos = (pos + 1) & mask) {
            const uint32 id = slots[pos];
            if (id == INVALID_INDEX)
                return INVALID_INDEX;
            if (eq(id))
                return id;
        }
    }
    // id must not be present; hashOf(existingId) is used to rehash when growing
    template <typename HashOf>
    void Insert(uint64 hash, uint32 id, HashOf&& hashOf)
    {
        if ((static_cast<size_t>(count) + 1) * 2 > slots.size())
            Grow(hashOf);
        Place(hash, id);
        count++;
    }

  private:
    void Place(uint64 hash, uint32 id)
    {
        const size_t mask = slots.size() - 1;
        size_t pos        = static_cast<size_t>(hash) & mask;
        while (slots[pos] != INVALID_INDEX)
            pos = (pos + 1) & mask;
        slots[pos] = id;
    }
    template <typename HashOf>
    void Grow(HashOf&& hashOf)
    {
        const size_t newSize = slots.empty() ? 64 : slots.size() * 2;
        std::vector<uint32> old;
        old.swap(slots);
        slots.assign(newSize, INVALID_INDEX);
        for (const uint32 id : old)
            if (id != INVALID_INDEX)
                Place(hashOf(id), id);
    }
};

} // namespace GView::HDF
