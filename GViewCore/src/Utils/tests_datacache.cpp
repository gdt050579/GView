// Unit tests for GView::Utils::DataCache. Offsets and sizes passed to the cache usually come straight from parsed
// (attacker-controlled) files, so out-of-range and overflowing requests are exercised next to the I/O behaviour
// (number of reads issued to the underlying object for sequential, backward and random access patterns).

#include <catch.hpp>

#include "Internal.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

using namespace GView::Utils;

namespace
{
struct ReadStats {
    uint32 reads{ 0 };
    uint64 bytes{ 0 };
    bool failReads{ false };
};

// MemoryFile that records every read issued by the cache (and can simulate I/O failures)
class CountingMemoryFile : public AppCUI::OS::MemoryFile
{
    ReadStats& stats;

  protected:
    bool ReadBuffer(void* buffer, uint32 bufferSize, uint32& bytesRead) override
    {
        stats.reads++;
        stats.bytes += bufferSize;
        if (stats.failReads) {
            bytesRead = 0;
            return false;
        }
        return MemoryFile::ReadBuffer(buffer, bufferSize, bytesRead);
    }

  public:
    explicit CountingMemoryFile(ReadStats& s) : stats(s)
    {
    }
};

std::vector<uint8> MakeContent(size_t size)
{
    std::vector<uint8> content(size);
    for (size_t i = 0; i < size; i++)
        content[i] = (uint8) ((i * 0x9D) ^ (i >> 8) ^ (i >> 16));
    return content;
}

// 'cacheSize' is rounded up by DataCache::Init to the next 64K multiple (minimum 64K)
bool InitCache(DataCache& cache, const std::vector<uint8>& content, ReadStats& stats, uint32 cacheSize)
{
    auto file = std::make_unique<CountingMemoryFile>(stats);
    if (!content.empty() && !file->Create(content.data(), content.size()))
        return false;
    if (content.empty() && !file->Create(0))
        return false;
    return cache.Init(std::move(file), cacheSize);
}

bool Matches(const BufferView& view, const std::vector<uint8>& content, uint64 offset, size_t size)
{
    if (!view.IsValid() || view.GetLength() != size || offset + size > content.size())
        return false;
    return memcmp(view.GetData(), content.data() + offset, size) == 0;
}

constexpr uint32 CACHE_64K = 1; // rounded up to 64K by Init
constexpr uint32 CACHE_SZ  = 0x10000;
} // namespace

TEST_CASE("DataCache: small file is read once", "[DataCache]")
{
    const auto content = MakeContent(10000);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));
    REQUIRE(cache.GetCacheSize() == CACHE_SZ);

    for (uint64 ofs = 0; ofs + 7 <= content.size(); ofs += 7)
        REQUIRE(Matches(cache.Get(ofs, 7, true), content, ofs, 7));
    REQUIRE(Matches(cache.GetEntireFile(), content, 0, content.size()));
    REQUIRE(stats.reads == 1);
}

TEST_CASE("DataCache: forward sequential small reads use read-ahead", "[DataCache]")
{
    const auto content = MakeContent(4 * 1024 * 1024);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    constexpr uint32 OBJ = 24;
    for (uint64 ofs = 0; ofs + OBJ <= content.size(); ofs += OBJ) {
        REQUIRE(Matches(cache.Get(ofs, OBJ, true), content, ofs, OBJ));
        REQUIRE(cache.GetCurrentPos() == ofs + OBJ);
    }
    // every refill advances by at least (cacheSize - slack); before the fix this was one refill per object
    const uint64 maxReads = content.size() / (CACHE_SZ - (CACHE_SZ >> 4)) + 2;
    REQUIRE(stats.reads <= maxReads);
}

TEST_CASE("DataCache: backward sequential small reads use read-behind", "[DataCache]")
{
    const auto content = MakeContent(4 * 1024 * 1024);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    constexpr uint32 OBJ = 16;
    for (uint64 ofs = content.size() - OBJ;; ofs -= OBJ) {
        REQUIRE(Matches(cache.Get(ofs, OBJ, true), content, ofs, OBJ));
        if (ofs < OBJ)
            break;
    }
    const uint64 maxReads = content.size() / (CACHE_SZ - (CACHE_SZ >> 4)) + 2;
    REQUIRE(stats.reads <= maxReads);
}

TEST_CASE("DataCache: re-reading just before a forward request is a hit", "[DataCache]")
{
    const auto content = MakeContent(1024 * 1024);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    REQUIRE(Matches(cache.Get(500000, 64, true), content, 500000, 64));
    REQUIRE(stats.reads == 1);
    REQUIRE(Matches(cache.Get(500000 - 1024, 64, true), content, 500000 - 1024, 64));
    REQUIRE(Matches(cache.Get(500000 + 32768, 64, true), content, 500000 + 32768, 64));
    REQUIRE(stats.reads == 1);
}

TEST_CASE("DataCache: random access returns correct data", "[DataCache]")
{
    const auto content = MakeContent(3 * 1024 * 1024 + 123);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    uint64 state = 0x1234567890ABCDEFULL; // deterministic xorshift
    for (int i = 0; i < 20000; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const uint64 ofs = state % content.size();
        const uint32 sz  = (uint32) ((state >> 32) % (CACHE_SZ + 16)) + 1;
        const auto avail = content.size() - ofs;

        const auto strict = cache.Get(ofs, sz, true);
        if (sz <= avail && sz <= CACHE_SZ)
            REQUIRE(Matches(strict, content, ofs, sz));
        else
            REQUIRE(!strict.IsValid());

        const auto loose  = cache.Get(ofs, sz, false);
        const size_t want = std::min<size_t>({ (size_t) sz, (size_t) avail, (size_t) CACHE_SZ });
        REQUIRE(Matches(loose, content, ofs, want));
        REQUIRE(cache.GetCurrentPos() == ofs + want);
    }
}

TEST_CASE("DataCache: requests at or past EOF never read out of bounds", "[DataCache]")
{
    for (size_t fileSize : { (size_t) 1000, (size_t) (512 * 1024) }) {
        const auto content = MakeContent(fileSize);
        ReadStats stats;
        DataCache cache;
        REQUIRE(InitCache(cache, content, stats, CACHE_64K));

        // bring the end of the file into the cache first (the window then ends exactly at EOF)
        REQUIRE(Matches(cache.Get(fileSize - 10, 10, true), content, fileSize - 10, 10));

        for (bool fail : { true, false }) {
            REQUIRE(!cache.Get(fileSize, 1, fail).IsValid());
            REQUIRE(!cache.Get(fileSize + 1, 16, fail).IsValid());
            REQUIRE(!cache.Get(fileSize + 100000, 16, fail).IsValid());
            // 'offset + size' wraps around 2^64
            REQUIRE(!cache.Get(0xFFFFFFFFFFFFFFF0ULL, 0x20, fail).IsValid());
            REQUIRE(!cache.Get(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF, fail).IsValid());
        }

        // partial read at EOF
        REQUIRE(!cache.Get(fileSize - 4, 16, true).IsValid());
        REQUIRE(Matches(cache.Get(fileSize - 4, 16, false), content, fileSize - 4, 4));
        REQUIRE(cache.GetCurrentPos() == fileSize);
    }
}

TEST_CASE("DataCache: requests larger than the cache", "[DataCache]")
{
    const auto content = MakeContent(1024 * 1024);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    REQUIRE(!cache.Get(1000, CACHE_SZ + 1, true).IsValid());
    REQUIRE(Matches(cache.Get(1000, CACHE_SZ + 1, false), content, 1000, CACHE_SZ));
    REQUIRE(Matches(cache.Get(1000, CACHE_SZ, true), content, 1000, CACHE_SZ));
    // the last cache-sized block of the file
    REQUIRE(Matches(cache.Get(content.size() - CACHE_SZ, CACHE_SZ, true), content, content.size() - CACHE_SZ, CACHE_SZ));
}

TEST_CASE("DataCache: CopyToBuffer reads each byte once", "[DataCache]")
{
    const auto content = MakeContent(1024 * 1024 + 77);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    auto b = cache.CopyEntireFile();
    REQUIRE(b.GetLength() == content.size());
    REQUIRE(memcmp(b.GetData(), content.data(), content.size()) == 0);
    // ceil(size / cacheSize) refills; the last one is a full window ending at EOF
    REQUIRE(stats.reads == (content.size() + CACHE_SZ - 1) / CACHE_SZ);

    auto part = cache.CopyToBuffer(12345, 300000);
    REQUIRE(part.GetLength() == 300000);
    REQUIRE(memcmp(part.GetData(), content.data() + 12345, 300000) == 0);

    REQUIRE(cache.CopyToBuffer(content.size() - 10, 20, true).GetLength() == 0);
    auto tail = cache.CopyToBuffer(content.size() - 10, 20, false);
    REQUIRE(tail.GetLength() == 10);
    REQUIRE(memcmp(tail.GetData(), content.data() + content.size() - 10, 10) == 0);
}

TEST_CASE("DataCache: empty file", "[DataCache]")
{
    const std::vector<uint8> content;
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));
    REQUIRE(cache.GetSize() == 0);
    REQUIRE(!cache.Get(0, 1, true).IsValid());
    REQUIRE(!cache.Get(0, 1, false).IsValid());
    REQUIRE(stats.reads == 0);
}

TEST_CASE("DataCache: read failure invalidates the cache", "[DataCache]")
{
    const auto content = MakeContent(512 * 1024);
    ReadStats stats;
    DataCache cache;
    REQUIRE(InitCache(cache, content, stats, CACHE_64K));

    REQUIRE(Matches(cache.Get(0, 100, true), content, 0, 100));
    stats.failReads = true;
    REQUIRE(!cache.Get(300000, 100, true).IsValid());
    // the previously cached window is gone (its buffer may have been partially overwritten)
    REQUIRE(!cache.Get(0, 100, true).IsValid());
    REQUIRE(cache.GetFromCache(0, 0xAB) == 0xAB);
    stats.failReads = false;
    REQUIRE(Matches(cache.Get(0, 100, true), content, 0, 100));
}
