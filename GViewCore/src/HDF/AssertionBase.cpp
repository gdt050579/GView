#include "AssertionBase.hpp"

#include <cstring>

namespace GView::HDF
{
namespace
{
    uint64 DefaultHash(PredicateId p, const ConstantId* values, uint32 count)
    {
        return HashAtom(p, values, count);
    }
} // namespace

AssertionBase::AssertionBase() : AssertionBase(&DefaultHash)
{
}

AssertionBase::AssertionBase(HashFunction function) : hashFunction(function ? function : &DefaultHash)
{
    argOffset.push_back(0);
}

void AssertionBase::Reserve(uint32 predicateCount, uint32 assertionCount)
{
    if (byPredicate.size() < predicateCount)
        byPredicate.resize(predicateCount);
    if (assertionCount > 0) {
        pred.reserve(assertionCount);
        argOffset.reserve(static_cast<size_t>(assertionCount) + 1);
        hash.reserve(assertionCount);
        explanation.reserve(assertionCount);
    }
}

uint32 AssertionBase::FindId(PredicateId p, std::span<const ConstantId> values, uint64 h) const
{
    return byHash.Find(h, [&](uint32 id) {
        if (hash[id] != h || pred[id] != p)
            return false;
        const auto existing = Args(id);
        return existing.size() == values.size() && (values.empty() || std::memcmp(existing.data(), values.data(), values.size() * sizeof(ConstantId)) == 0);
    });
}

AssertionBase::InsertResult AssertionBase::Insert(PredicateId p, std::span<const ConstantId> values, StringId expl)
{
    const uint64 h       = hashFunction(p, values.data(), static_cast<uint32>(values.size()));
    const uint32 present = FindId(p, values, h);
    if (present != INVALID_INDEX)
        return { present, false };
    if (pred.size() >= 0xFFFFFFF0u || args.size() + values.size() >= 0xFFFFFFF0u)
        return { INVALID_ASSERTION_ID, false }; // 32-bit ids/offsets exhausted

    const auto id = static_cast<AssertionId>(pred.size());
    pred.push_back(p);
    args.insert(args.end(), values.begin(), values.end());
    argOffset.push_back(static_cast<uint32>(args.size()));
    hash.push_back(h);
    explanation.push_back(expl);
    byHash.Insert(h, id, [this](uint32 existing) { return hash[existing]; });
    if (p >= byPredicate.size())
        byPredicate.resize(static_cast<size_t>(p) + 1);
    byPredicate[p].push_back(id);
    if (!values.empty())
        byPredicateArg0[Arg0Key(p, values[0])].push_back(id);
    return { id, true };
}

AssertionId AssertionBase::Find(PredicateId p, std::span<const ConstantId> values) const
{
    const uint32 id = FindId(p, values, hashFunction(p, values.data(), static_cast<uint32>(values.size())));
    return id == INVALID_INDEX ? INVALID_ASSERTION_ID : id;
}

bool AssertionBase::Contains(PredicateId p, std::span<const ConstantId> values) const
{
    return Find(p, values) != INVALID_ASSERTION_ID;
}

std::span<const AssertionId> AssertionBase::WithPredicateAndFirst(PredicateId p, ConstantId first) const
{
    auto it = byPredicateArg0.find(Arg0Key(p, first));
    if (it == byPredicateArg0.end())
        return {};
    return it->second;
}

size_t AssertionBase::MemoryBytes() const
{
    size_t total = pred.capacity() * sizeof(PredicateId) + argOffset.capacity() * sizeof(uint32) + args.capacity() * sizeof(ConstantId) +
                   hash.capacity() * sizeof(uint64) + explanation.capacity() * sizeof(StringId) + byHash.MemoryBytes();
    for (const auto& list : byPredicate)
        total += sizeof(list) + list.capacity() * sizeof(AssertionId);
    // unordered_map node: key + vector header + next pointer + cached hash (typical implementations), plus the bucket array
    total += byPredicateArg0.bucket_count() * sizeof(void*);
    for (const auto& [key, list] : byPredicateArg0)
        total += sizeof(key) + sizeof(list) + 2 * sizeof(void*) + list.capacity() * sizeof(AssertionId);
    return total;
}

} // namespace GView::HDF
