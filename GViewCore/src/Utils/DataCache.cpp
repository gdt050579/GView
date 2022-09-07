#include "GView.hpp"

using namespace GView::Utils;

constexpr uint32 MAX_CACHE_SIZE = 0x1000000U; // 16 M

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

    if (offset >= this->start)
    {
        // data is cached --> return from here
        if ((offset + requestedSize) <= this->end)
        {
            this->currentPos = offset + requestedSize;
            return BufferView(&this->cache[offset - this->start], requestedSize);
        }
        if (this->end == this->fileSize)
        {
            // data is not cache (and we are at the end of the file with the case)
            if (failIfRequestedSizeCanNotBeRead)
                return BufferView();
            this->currentPos = this->fileSize;
            return BufferView(&this->cache[offset - this->start], (uint32) (this->end - offset));
        }
    }
    // request outside file
    if (offset >= this->fileSize)
        return BufferView();
    // data is not available in cache ==> read it
    uint64 _start, _end;
    if (this->fileSize <= this->cacheSize)
    {
        // read everything
        _start = 0;
        _end   = this->fileSize;
    }
    else
    {
        // compute the new buffer to read
        auto sz = requestedSize;
        if ((offset + sz) > this->fileSize)
            sz = (uint32) (this->fileSize - offset);
        if (sz > this->cacheSize)
            sz = this->cacheSize;
        auto diff = this->cacheSize - sz;
        if (diff <= offset)
            _start = offset - diff;
        else
            _start = 0;
        _end = _start + this->cacheSize;
        if (_end > this->fileSize)
            _end = this->fileSize;
    }
    // read new data in cache
    if (this->fileObj->SetCurrentPos(_start) == false)
        return BufferView();
    if (this->fileObj->Read(this->cache, (uint32) (_end - _start)) == false)
    {
        this->start = 0;
        this->end   = 0;
        return BufferView();
    }
    // return new pointer
    this->start = _start;
    this->end   = _end;
    if ((offset + requestedSize) <= this->end)
    {
        this->currentPos = offset + requestedSize;
        return BufferView(&this->cache[offset - this->start], requestedSize);
    }
    // the entire data is not in our cache
    if (failIfRequestedSizeCanNotBeRead)
        return BufferView();
    if (this->end == this->fileSize)
    {
        this->currentPos = this->fileSize;
        return BufferView(&this->cache[offset - this->start], (uint32) (this->end - offset));
    }
    this->currentPos = this->end;
    return BufferView(&this->cache[offset - this->start], (uint32) (this->end - offset));
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
    uint32 toRead = this->cacheSize >> 1;
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

    uint32 toRead = this->cacheSize >> 1;
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
