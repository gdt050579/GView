#pragma once

// The constant universe C: interned, sort-tagged constants stored as structure-of-arrays.
// A constant is identified by a 31-bit ConstantId; equal (sort, value) pairs always get the same id.

#include "Signature.hpp"

#include <memory>

namespace GView::HDF
{
// Append-only string storage with stable views (64 KiB chunks; larger strings get a chunk of their own).
class StringArena
{
    struct Location {
        uint32 chunk;
        uint32 offset;
        uint32 length;
    };
    static constexpr uint32 CHUNK_SIZE = 64 * 1024;
    std::vector<std::unique_ptr<char[]>> chunks;
    uint32 openChunk{ INVALID_INDEX }; // chunk that receives small strings
    uint32 used{ 0 };                  // bytes used in the open chunk
    std::vector<Location> locations;
    std::unordered_map<std::string_view, StringId, TransparentHash, TransparentEqual> index; // views point into the arena
    size_t bytes{ 0 };

  public:
    StringArena();
    StringId Intern(std::string_view text);
    StringId Find(std::string_view text) const; // INVALID_INDEX when absent
    std::string_view Get(StringId id) const;
    inline uint32 Count() const
    {
        return static_cast<uint32>(locations.size());
    }
    inline size_t MemoryBytes() const
    {
        return bytes + locations.capacity() * sizeof(Location) + index.size() * (sizeof(std::string_view) + sizeof(StringId) + 2 * sizeof(void*));
    }
};

class ConstantPool
{
    const SortTable* sorts;
    std::vector<SortId> sort; // per ConstantId
    std::vector<uint64> bits; // Int: int64 bits, Real: double bits, Bool: 0/1, Subject: SubjectId, String kinds: StringId
    HashIndex index;          // (sort, bits) -> ConstantId
    StringArena strings;

    static inline uint64 KeyHash(SortId s, uint64 b)
    {
        return (static_cast<uint64>(s) << 48) ^ Mix64(b);
    }
    ConstantId InternBits(SortId s, uint64 b);
    ConstantId FindBits(SortId s, uint64 b) const;

  public:
    explicit ConstantPool(const SortTable& sortTable);

    // converts value to a constant of sort s; nullopt when the value is not representable in the sort's kind
    // (Subject values are accepted only for SubjectIds known to the registry: the caller validates them)
    std::optional<ConstantId> Intern(SortId s, const ArgValue& value);
    ConstantId InternString(SortId s, std::string_view text);
    std::optional<ConstantId> InternInt(SortId s, int64 value);
    std::optional<ConstantId> InternReal(SortId s, double value);
    ConstantId InternBool(SortId s, bool value);
    ConstantId InternSubject(SortId s, SubjectId subject);
    // lookup without creating (INVALID_CONSTANT_ID when absent)
    ConstantId FindString(SortId s, std::string_view text) const;
    ConstantId FindSubject(SortId s, SubjectId subject) const;

    inline bool IsValid(ConstantId c) const
    {
        return c != INVALID_CONSTANT_ID && c < sort.size();
    }
    inline uint32 Count() const
    {
        return static_cast<uint32>(sort.size());
    }
    inline SortId Sort(ConstantId c) const
    {
        return sort[c];
    }
    inline SortKind Kind(ConstantId c) const
    {
        return sorts->Kind(sort[c]);
    }
    int64 AsInt(ConstantId c) const;
    double AsReal(ConstantId c) const;
    bool AsBool(ConstantId c) const;
    SubjectId AsSubject(ConstantId c) const;
    std::string_view AsString(ConstantId c) const;
    inline const StringArena& Strings() const
    {
        return strings;
    }
    inline StringArena& Strings()
    {
        return strings;
    }
    // textual form: strings quoted (when quoteStrings), reals with %.2f, subjects as #id
    std::string Format(ConstantId c, bool quoteStrings) const;
    size_t MemoryBytes() const;
};

} // namespace GView::HDF
