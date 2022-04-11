#include "global.hpp"

namespace GView::Java
{

BufferReader::BufferReader(const uint8* ptr_start, size_t size)
{
    this->ptr_start   = ptr_start;
    this->ptr_current = ptr_start;
    this->ptr_end     = ptr_start + size;
}

bool BufferReader::read(void* buffer, size_t size)
{
    if (size > available())
        return false;
    memcpy(buffer, ptr_current, size);
    ptr_current += size;
    return true;
}

bool BufferReader::skip(size_t size)
{
    if (size > available())
        return false;
    ptr_current += size;
    return true;
}

size_t BufferReader::available() const
{
    return ptr_end - ptr_current;
}

size_t BufferReader::offset() const
{
    return ptr_current - ptr_start;
}

bool BufferReader::done() const
{
    return available() == 0;
}

const uint8* BufferReader::get() const
{
    return ptr_current;
}

} // namespace GView::Java