#include "../include/GView.hpp"
#include <zlib.h>

namespace GView::Decoding::ZLIB
{
bool Decompress(const Buffer& input, uint64 inputSize, Buffer& output, uint64 outputSize)
{
    CHECK(input.IsValid(), false, "");
    CHECK(inputSize > 0, false, "");
    CHECK(outputSize > inputSize, false, "");

    output.Resize(outputSize);

    uint64 outputSizeCopy = outputSize;
    int32 ret             = uncompress(output.GetData(), (uLongf*) &outputSizeCopy, input.GetData(), static_cast<uLong>(inputSize));
    CHECK(outputSize == outputSizeCopy, false, "ZLIB error: %d!", ret);
    CHECK(ret == Z_OK, false, "ZLIB error: %d!", ret);

    return true;
}

bool DecompressStream(const BufferView& input, Buffer& output, String& message, uint64& sizeConsumed)
{
    CHECK(input.IsValid(), false, "");
    CHECK(input.GetLength() > 0, false, "");
    output.Resize(input.GetLength());
    sizeConsumed = 0;

    z_stream stream;
    memset(&stream, Z_NULL, sizeof(stream));

    stream.avail_in  = static_cast<uInt>(input.GetLength());
    stream.next_in   = const_cast<Bytef*>(input.GetData());
    stream.avail_out = static_cast<uInt>(input.GetLength());
    stream.next_out  = reinterpret_cast<Bytef*>(output.GetData());

    int ret = inflateInit(&stream);
    CHECK(ret == Z_OK, false, "");

    struct ZWrapper {
        z_stream& z;

        ZWrapper(z_stream& z) : z(z)
        {
        }
        ~ZWrapper()
        {
            inflateEnd(&z);
        }
    } zWrapper(stream);

    while (ret == Z_OK || ret == Z_BUF_ERROR) {
        ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_BUF_ERROR) {
            output.Resize(stream.total_out * 2);
            stream.avail_out = static_cast<uInt>(stream.total_out);
            stream.next_out  = reinterpret_cast<Bytef*>(output.GetData() + stream.total_out);
        }
    }

    output.Resize(stream.total_out);
    sizeConsumed = stream.total_in;
    message.Format("Return code: %d with msg: %s", ret, stream.msg);

    CHECK(ret == Z_OK || ret == Z_STREAM_END, false, "");

    return true;
}
} // namespace GView::ZLIB
