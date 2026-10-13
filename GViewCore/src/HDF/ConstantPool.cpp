#include "ConstantPool.hpp"

#include <bit>
#include <cmath>
#include <cstdio>
#include <limits>

namespace GView::HDF
{
StringArena::StringArena()
{
    Intern(""); // EMPTY_STRING_ID
}

StringId StringArena::Find(std::string_view text) const
{
    auto it = index.find(text);
    return it == index.end() ? INVALID_INDEX : it->second;
}

StringId StringArena::Intern(std::string_view text)
{
    auto it = index.find(text);
    if (it != index.end())
        return it->second;
    const auto length = static_cast<uint32>(text.size());
    if (length > CHUNK_SIZE) {
        // a dedicated chunk; the open chunk (if any) stays open
        chunks.push_back(std::make_unique<char[]>(length));
        std::memcpy(chunks.back().get(), text.data(), length);
        locations.push_back({ static_cast<uint32>(chunks.size() - 1), 0, length });
        bytes += length;
    } else {
        if (openChunk == INVALID_INDEX || used + length > CHUNK_SIZE) {
            chunks.push_back(std::make_unique<char[]>(CHUNK_SIZE));
            openChunk = static_cast<uint32>(chunks.size() - 1);
            used      = 0;
            bytes += CHUNK_SIZE;
        }
        if (length > 0)
            std::memcpy(chunks[openChunk].get() + used, text.data(), length);
        locations.push_back({ openChunk, used, length });
        used += length;
    }
    const auto id = static_cast<StringId>(locations.size() - 1);
    index.emplace(Get(id), id);
    return id;
}

std::string_view StringArena::Get(StringId id) const
{
    if (id >= locations.size())
        return {};
    const auto& loc = locations[id];
    if (loc.length == 0)
        return std::string_view();
    return std::string_view(chunks[loc.chunk].get() + loc.offset, loc.length);
}

ConstantPool::ConstantPool(const SortTable& sortTable) : sorts(&sortTable)
{
    // slot 0 = INVALID_CONSTANT_ID
    sort.push_back(INVALID_SORT_ID);
    bits.push_back(0);
}

ConstantId ConstantPool::FindBits(SortId s, uint64 b) const
{
    const auto id = index.Find(KeyHash(s, b), [&](uint32 c) { return sort[c] == s && bits[c] == b; });
    return id == INVALID_INDEX ? INVALID_CONSTANT_ID : id;
}

ConstantId ConstantPool::InternBits(SortId s, uint64 b)
{
    const auto existing = FindBits(s, b);
    if (existing != INVALID_CONSTANT_ID)
        return existing;
    if (sort.size() > MAX_CONSTANT_ID)
        return INVALID_CONSTANT_ID; // 2^31 constants: the pool is full
    const auto id = static_cast<ConstantId>(sort.size());
    sort.push_back(s);
    bits.push_back(b);
    index.Insert(KeyHash(s, b), id, [this](uint32 c) { return KeyHash(sort[c], bits[c]); });
    return id;
}

ConstantId ConstantPool::InternString(SortId s, std::string_view text)
{
    return InternBits(s, strings.Intern(text));
}

ConstantId ConstantPool::FindString(SortId s, std::string_view text) const
{
    const auto sid = strings.Find(text);
    if (sid == INVALID_INDEX)
        return INVALID_CONSTANT_ID;
    return FindBits(s, sid);
}

std::optional<ConstantId> ConstantPool::InternInt(SortId s, int64 value)
{
    const auto id = InternBits(s, static_cast<uint64>(value));
    return id == INVALID_CONSTANT_ID ? std::nullopt : std::optional<ConstantId>(id);
}

std::optional<ConstantId> ConstantPool::InternReal(SortId s, double value)
{
    if (!std::isfinite(value))
        return std::nullopt; // NaN would break set semantics (NaN != NaN), infinities are not scores
    if (value == 0.0)
        value = 0.0; // -0.0 and +0.0 are the same constant
    const auto id = InternBits(s, std::bit_cast<uint64>(value));
    return id == INVALID_CONSTANT_ID ? std::nullopt : std::optional<ConstantId>(id);
}

ConstantId ConstantPool::InternBool(SortId s, bool value)
{
    return InternBits(s, value ? 1 : 0);
}

ConstantId ConstantPool::InternSubject(SortId s, SubjectId subject)
{
    return InternBits(s, subject);
}

ConstantId ConstantPool::FindSubject(SortId s, SubjectId subject) const
{
    return FindBits(s, subject);
}

std::optional<ConstantId> ConstantPool::Intern(SortId s, const ArgValue& value)
{
    if (s >= sorts->Count())
        return std::nullopt;
    ConstantId id = INVALID_CONSTANT_ID;
    switch (sorts->Kind(s)) {
    case SortKind::Subject:
        if (value.kind != ArgValue::Kind::Subject || value.subject == INVALID_SUBJECT_ID)
            return std::nullopt;
        id = InternSubject(s, value.subject);
        break;
    case SortKind::String:
        if (value.kind != ArgValue::Kind::String || value.s.size() > MAX_STRING_CONSTANT)
            return std::nullopt;
        id = InternString(s, value.s);
        break;
    case SortKind::Int:
        if (value.kind == ArgValue::Kind::Int)
            return InternInt(s, value.i);
        if (value.kind == ArgValue::Kind::UInt && value.u <= static_cast<uint64>(std::numeric_limits<int64>::max()))
            return InternInt(s, static_cast<int64>(value.u));
        return std::nullopt;
    case SortKind::Real:
        if (value.kind == ArgValue::Kind::Real)
            return InternReal(s, value.d);
        if (value.kind == ArgValue::Kind::Int)
            return InternReal(s, static_cast<double>(value.i));
        if (value.kind == ArgValue::Kind::UInt)
            return InternReal(s, static_cast<double>(value.u));
        return std::nullopt;
    case SortKind::Bool:
        if (value.kind != ArgValue::Kind::Bool)
            return std::nullopt;
        id = InternBool(s, value.b);
        break;
    }
    return id == INVALID_CONSTANT_ID ? std::nullopt : std::optional<ConstantId>(id);
}

int64 ConstantPool::AsInt(ConstantId c) const
{
    return IsValid(c) && Kind(c) == SortKind::Int ? static_cast<int64>(bits[c]) : 0;
}
double ConstantPool::AsReal(ConstantId c) const
{
    if (!IsValid(c))
        return 0.0;
    if (Kind(c) == SortKind::Real)
        return std::bit_cast<double>(bits[c]);
    if (Kind(c) == SortKind::Int)
        return static_cast<double>(static_cast<int64>(bits[c]));
    return 0.0;
}
bool ConstantPool::AsBool(ConstantId c) const
{
    return IsValid(c) && Kind(c) == SortKind::Bool && bits[c] != 0;
}
SubjectId ConstantPool::AsSubject(ConstantId c) const
{
    return IsValid(c) && Kind(c) == SortKind::Subject ? static_cast<SubjectId>(bits[c]) : INVALID_SUBJECT_ID;
}
std::string_view ConstantPool::AsString(ConstantId c) const
{
    return IsValid(c) && Kind(c) == SortKind::String ? strings.Get(static_cast<StringId>(bits[c])) : std::string_view();
}

std::string ConstantPool::Format(ConstantId c, bool quoteStrings) const
{
    if (!IsValid(c))
        return "<invalid>";
    char buffer[64];
    switch (Kind(c)) {
    case SortKind::Subject:
        snprintf(buffer, sizeof(buffer), "#%u", static_cast<uint32>(bits[c]));
        return buffer;
    case SortKind::String:
        if (quoteStrings) {
            std::string result = "\"";
            result.append(AsString(c));
            result.push_back('"');
            return result;
        }
        return std::string(AsString(c));
    case SortKind::Int:
        snprintf(buffer, sizeof(buffer), "%lld", static_cast<long long>(AsInt(c)));
        return buffer;
    case SortKind::Real:
        snprintf(buffer, sizeof(buffer), "%.2f", AsReal(c));
        return buffer;
    case SortKind::Bool:
        return AsBool(c) ? "true" : "false";
    }
    return "?";
}

size_t ConstantPool::MemoryBytes() const
{
    return sort.capacity() * sizeof(SortId) + bits.capacity() * sizeof(uint64) + index.MemoryBytes() + strings.MemoryBytes();
}

} // namespace GView::HDF
