#pragma once

// Gamma: an append-only set of ground assertions p(c1..ck). Set semantics (a duplicate insert returns the existing id),
// structure-of-arrays storage, a 64-bit hash index, per-predicate posting lists and a (predicate, first argument) index.
// A knowledge state Gamma_i is a prefix [0, count) of this log (Gamma_i is a subset of Gamma_i+1 by construction).

#include "Term.hpp"

#include <span>

namespace GView::HDF
{
class AssertionBase
{
  public:
    using HashFunction = uint64 (*)(PredicateId p, const ConstantId* args, uint32 count);
    struct InsertResult {
        AssertionId id;
        bool inserted;
    };

  private:
    std::vector<PredicateId> pred;     // per AssertionId
    std::vector<uint32> argOffset;     // per AssertionId + 1 sentinel (arity = argOffset[i+1] - argOffset[i])
    std::vector<ConstantId> args;      // flat
    std::vector<uint64> hash;          // per AssertionId
    std::vector<StringId> explanation; // expl(gamma) side table (EMPTY_STRING_ID = none)
    HashIndex byHash;
    std::vector<std::vector<AssertionId>> byPredicate; // posting lists, ascending ids
    std::unordered_map<uint64, std::vector<AssertionId>> byPredicateArg0;
    HashFunction hashFunction;

    static inline uint64 Arg0Key(PredicateId p, ConstantId c)
    {
        return (static_cast<uint64>(p) << 32) | c;
    }
    uint32 FindId(PredicateId p, std::span<const ConstantId> values, uint64 h) const;

  public:
    AssertionBase();
    explicit AssertionBase(HashFunction function); // tests: force hash collisions

    // predicateCount pre-sizes the posting lists (more predicates are accepted, the vector grows)
    void Reserve(uint32 predicateCount, uint32 assertionCount = 0);

    InsertResult Insert(PredicateId p, std::span<const ConstantId> values, StringId expl = EMPTY_STRING_ID);
    bool Contains(PredicateId p, std::span<const ConstantId> values) const;
    AssertionId Find(PredicateId p, std::span<const ConstantId> values) const; // INVALID_ASSERTION_ID when absent

    inline uint32 Size() const
    {
        return static_cast<uint32>(pred.size());
    }
    inline PredicateId Predicate(AssertionId id) const
    {
        return pred[id];
    }
    inline std::span<const ConstantId> Args(AssertionId id) const
    {
        return { args.data() + argOffset[id], argOffset[id + 1] - argOffset[id] };
    }
    inline uint32 Arity(AssertionId id) const
    {
        return argOffset[id + 1] - argOffset[id];
    }
    inline StringId Explanation(AssertionId id) const
    {
        return explanation[id];
    }
    // all assertions of p (ascending ids)
    inline std::span<const AssertionId> WithPredicate(PredicateId p) const
    {
        return p < byPredicate.size() ? std::span<const AssertionId>(byPredicate[p]) : std::span<const AssertionId>();
    }
    // all assertions p(c, ...) (ascending ids)
    std::span<const AssertionId> WithPredicateAndFirst(PredicateId p, ConstantId first) const;

    // approximate heap usage (bytes) for the benchmarks / thesis document
    size_t MemoryBytes() const;
};

} // namespace GView::HDF
