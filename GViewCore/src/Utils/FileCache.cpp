#include "GView.hpp"

using namespace GView::Utils;

constexpr unsigned int MAX_CACHE_SIZE = 0x1000000U; // 16 M

FileCache::FileCache()
{
    this->fileObj = nullptr;
    this->cache = nullptr;
    this->cacheSize = 0;
    this->start = 0;
    this->end = 0;
    this->fileSize = 0;
	this->currentPos = 0;
}
FileCache::~FileCache()
{
    if (this->fileObj)
    {
        this->fileObj->Close();
        delete this->fileObj;
    }
    this->fileObj = nullptr;
    if (this->cache)
        delete[]this->cache;
    this->cache = nullptr;
}

bool FileCache::Init(std::unique_ptr<AppCUI::OS::IFile> file, unsigned int _cacheSize)
{
    CHECK(this->cacheSize == 0, false, "Cache object already initialized !");
    this->fileObj = file.release(); // take ownership of the pointer
    CHECK(this->fileObj, false, "Expecting a valid file object poiner !");
    _cacheSize = (_cacheSize | 0xFFFF) + 1; // a minimum of 64 K for cache
    if (_cacheSize == 0)
        _cacheSize = MAX_CACHE_SIZE;
    _cacheSize = std::min(_cacheSize, MAX_CACHE_SIZE);
    this->fileSize = fileObj->GetSize();

    this->cache = new unsigned char[_cacheSize];
    CHECK(this->cache, false, "Fail to allocate: %u bytes", _cacheSize);
    this->cacheSize = _cacheSize;
    this->start = 0;
    this->end = 0;
    
    return true;
}
Buffer FileCache::Get(unsigned long long  offset, unsigned int requestedSize)
{
	CHECK(this->fileObj, Buffer(), "File was not properly initialized !");
	CHECK(requestedSize > 0, Buffer(), "'requestedSize' has to be bigger than 0 ");
	
	if (offset >= this->start)
	{
		// data is cached --> return from here
		if ((offset + requestedSize) <= this->end)
		{
			this->currentPos = offset + requestedSize;
			return Buffer(&this->cache[offset - this->start], requestedSize);
		}
		if (this->end == this->fileSize)
		{
			this->currentPos = this->fileSize;
			return Buffer(&this->cache[offset - this->start], (unsigned int)(this->end - offset));
		}
	}
	// request outside file
	if (offset >= this->fileSize)
		return Buffer();
	// data is not available in cache ==> read it
	unsigned long long  _start, _end;
	if (this->fileSize <= this->cacheSize)
	{
		// read everything
		_start = 0;
		_end = this->fileSize;
	}
	else
	{
		// compute the new buffer to read
		auto sz = requestedSize;
		if ((offset + sz) > this->fileSize)
			sz = (unsigned int)(this->fileSize - offset);
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
		return Buffer();
	if (this->fileObj->Read(this->cache, (unsigned int)(_end - _start)) == false)
	{
		this->start = 0;
		this->end = 0;
		return Buffer();
	}
	// return new pointer
	this->start = _start;
	this->end = _end;
	if ((offset + requestedSize) <= this->end)
	{
		this->currentPos = offset + requestedSize;
		return Buffer(&this->cache[offset - this->start], requestedSize);
	}
	if (this->end == this->fileSize)
	{
		this->currentPos = this->fileSize;
		return Buffer(&this->cache[offset - this->start], (unsigned int)(this->end - offset));
	}
	this->currentPos = this->end;
	return Buffer(&this->cache[offset - this->start], (unsigned int)(this->end - offset));
}
