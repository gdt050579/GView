#include "doc.hpp"

namespace GView::Type::DOC
{
BufferView ByteStream::Read(size_t count)
{
    if (cursor + count > size) {
        count = size - cursor;
    }

    BufferView view((uint8*) ptr + cursor, count);
    cursor += count;

    return view;
}

ByteStream& ByteStream::Seek(size_t count)
{
    if (cursor + count > size) {
        count = size - cursor;
    }
    cursor += count;
    return *this;
}
} // namespace GView::Type::DOC
