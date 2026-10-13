#include "GView.hpp"

using namespace GView::Utils;

constexpr uint32 MAX_CACHE_SIZE = 0x20000000U; // 512 M

DataCache::DataCache()
{
    this->fileObj    = nullptr;
    this->cache      = nullptr;
    this->cacheSize  = 0;
    this->start      = 0;
    this->end        = 0;
    this->fileSize   = 0;
    this->currentPos = 0;
}
DataCache::DataCache(DataCache&& obj)
{
    fileObj        = obj.fileObj;
    fileSize       = obj.fileSize;
    start          = obj.start;
    end            = obj.end;
    currentPos     = obj.currentPos;
    cache          = obj.cache;
    cacheSize      = obj.cacheSize;
    obj.fileObj    = nullptr;
    obj.fileSize   = 0;
    obj.start      = 0;
    obj.end        = 0;
    obj.currentPos = 0;
    obj.cache      = nullptr;
    obj.cacheSize  = 0;
}
DataCache::~DataCache()
{
    if (this->fileObj)
    {
        this->fileObj->Close();
        delete this->fileObj;
    }
    this->fileObj = nullptr;
    if (this->cache)
        delete[] this->cache;
    this->cache = nullptr;
}

bool DataCache::Init(std::unique_ptr<AppCUI::OS::DataObject> file, uint32 _cacheSize)
{
    CHECK(this->cacheSize == 0, false, "Cache object already initialized !");
    this->fileObj = file.release(); // take ownership of the pointer
    CHECK(this->fileObj, false, "Expecting a valid file object poiner !");
    _cacheSize = (_cacheSize | 0xFFFF) + 1; // a minimum of 64 K for cache
    if (_cacheSize == 0)
        _cacheSize = MAX_CACHE_SIZE;
    _cacheSize     = std::min(_cacheSize, MAX_CACHE_SIZE);
    this->fileSize = fileObj->GetSize();

    this->cache = new uint8[_cacheSize];
    CHECK(this->cache, false, "Fail to allocate: %u bytes", _cacheSize);
    this->cacheSize = _cacheSize;
    this->start     = 0;
    this->end       = 0;

    return true;
}
BufferView DataCache::Get(uint64 offset, uint32 requestedSize, bool failIfRequestedSizeCanNotBeRead)
{
    CHECK(this->fileObj, BufferView(), "File was not properly initialized !");
    CHECK(requestedSize > 0, BufferView(), "'requestedSize' has to be bigger than 0 ");

    // request outside file (this also covers empty files)
    if (offset >= this->fileSize)
        return BufferView();

    // number of bytes that can be returned: limited by the end of the file and by the cache size
    // (offset < fileSize, so the subtraction can not underflow and no 'offset + size' sum is ever computed)
    const uint64 availableInFile = this->fileSize - offset;
    const uint32 sz              = (uint32) std::min<uint64>(std::min<uint64>(requestedSize, availableInFile), this->cacheSize);
    if ((sz < requestedSize) && (failIfRequestedSizeCanNotBeRead))
        return BufferView();

    // data is cached --> return from here
    if ((offset >= this->start) && (offset < this->end) && (sz <= this->end - offset)) {
        this->currentPos = offset + sz;
        return BufferView(&this->cache[offset - this->start], sz);
    }

    // data is not available in cache ==> read it
    uint64 newStart, newEnd;
    if (this->fileSize <= this->cacheSize)
    {
        // read everything
        newStart = 0;
        newEnd   = this->fileSize;
    }
    else
    {
        // Always fill the entire cache, positioned so that most of it is read-ahead in the direction of the access.
        // A small slack is kept on the opposite side so that re-reading data just before (or after) the request is still a hit.
        // Without this, a forward sequential parse of small objects reloads the whole cache for every object.
        const uint64 slack   = std::min<uint64>(this->cacheSize >> 4, this->cacheSize - sz);
        const bool backwards = (offset < this->start) && (this->start - offset <= this->cacheSize);
        if (backwards) {
            // scrolling / reading backwards --> keep the request at the end of the window
            const uint64 before = this->cacheSize - (sz + slack);
            newStart            = offset > before ? offset - before : 0;
        } else {
            // forward or random access --> keep the request at the start of the window
            newStart = offset > slack ? offset - slack : 0;
        }
        // keep the window inside the file (and full)
        newStart = std::min<uint64>(newStart, this->fileSize - this->cacheSize);
        newEnd   = newStart + this->cacheSize;
    }
    // read new data in cache
    if (this->fileObj->SetCurrentPos(newStart) == false)
        return BufferView();
    if (this->fileObj->Read(this->cache, (uint32) (newEnd - newStart)) == false) {
        this->start = 0;
        this->end   = 0;
        return BufferView();
    }
    this->start = newStart;
    this->end   = newEnd;
    // the new window always contains [offset, offset + sz) - fail closed if that invariant is ever broken
    CHECK((offset >= this->start) && (offset < this->end) && (sz <= this->end - offset), BufferView(), "Invalid cache window computed !");
    this->currentPos = offset + sz;
    return BufferView(&this->cache[offset - this->start], sz);
}
bool DataCache::CopyObject(void* buffer, uint64 offset, uint32 requestedSize)
{
    CHECK(buffer, false, "Expecting a valid pointer for a buffer !");
    auto b = Get(offset, requestedSize, true);
    CHECK(b.IsValid(), false, "Unable to read %u bytes from %llu offset ", requestedSize, offset);
    memcpy(buffer, b.GetData(), b.GetLength());
    return true;
}
Buffer DataCache::CopyToBuffer(uint64 offset, uint32 requestedSize, bool failIfRequestedSizeCanNotBeRead)
{
    // sanity checks
    CHECK(requestedSize > 0, Buffer(), "Invalid requested size (should be bigger than 0)");
    CHECK(offset <= this->fileSize, Buffer(), "Invalid offset (%llu) , should be less than %llu ", offset, this->fileSize);
    if (failIfRequestedSizeCanNotBeRead)
    {
        CHECK(offset + (uint64) requestedSize <= this->fileSize, Buffer(), "Unable to read %u bytes from %llu", requestedSize, offset);
    }

    Buffer b{};
    b.Resize(requestedSize);
    // whole-cache chunks: every cache refill is fully consumed
    uint32 toRead = this->cacheSize;
    auto p        = b.GetData();
    while (requestedSize)
    {
        toRead  = std::min(toRead, requestedSize);
        auto bv = this->Get(offset, toRead, false);
        if (bv.Empty())
        {
            LOG_ERROR("Empty buffer received when reading %u bytes from %llu offset", toRead, offset);
            if (failIfRequestedSizeCanNotBeRead)
                return Buffer();
            // trim the buffer size to the amount of data that was read
            b.Resize(p - b.GetData());
            return b;
        }
        if (toRead != bv.GetLength())
        {
            LOG_ERROR("Only %u bytes received when trying to read %u bytes from %llu offset", bv.GetLength(), toRead, offset);
            if (failIfRequestedSizeCanNotBeRead)
                return Buffer();
            // copy the buffer that was read
            if (bv.GetLength() > 0)
            {
                memcpy(p, bv.GetData(), bv.GetLength());
            }
            p += bv.GetLength();
            // trim the buffer size to the amount of data that was read
            b.Resize(p - b.GetData());
            return b;
        }
        memcpy(p, bv.GetData(), toRead);
        p += toRead;
        offset += toRead;
        requestedSize -= toRead;
    }
    return b;
}
bool DataCache::WriteTo(Reference<AppCUI::OS::DataObject> output, uint64 offset, uint32 size)
{
    CHECK(output->SetSize(size), false, "");
    CHECK(output->SetCurrentPos(0), false, "");

    if (size == 0)
        return true; // nothing to write

    // whole-cache chunks: every cache refill is fully consumed
    uint32 toRead = this->cacheSize;
    while (size)
    {
        toRead  = std::min(toRead, size);
        auto bv = this->Get(offset, toRead, true);
        CHECK(bv.IsValid(), false, "");
        CHECK(output->Write(bv.begin(), toRead), false, "");
        offset += toRead;
        size -= toRead;
    }
    return true;
}
