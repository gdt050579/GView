#include "../include/GView.hpp"
#include <zlib.h>

#include <algorithm>
#include <limits>

namespace GView::Decoding::ZLIB
{
bool Decompress(const Buffer& input, uint64 inputSize, Buffer& output, uint64 outputSize)
{
    CHECK(input.IsValid(), false, "");
    CHECK(inputSize > 0, false, "");
    CHECK(inputSize <= input.GetLength(), false, "");
    CHECK(outputSize > inputSize, false, "");
    // uLong / uLongf is 32 bits on Windows
    CHECK(static_cast<uLong>(inputSize) == inputSize, false, "");
    CHECK(static_cast<uLongf>(outputSize) == outputSize, false, "");

    output.Resize(outputSize);

    uLongf outputSizeCopy = static_cast<uLongf>(outputSize);
    int32 ret             = uncompress(output.GetData(), &outputSizeCopy, input.GetData(), static_cast<uLong>(inputSize));
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
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            break; // Z_STREAM_END or an error
        }
        if (stream.avail_out == 0) {
            // output is full => grow it
            const uint64 produced = stream.total_out;
            output.Resize(produced * 2);
            stream.avail_out = static_cast<uInt>((std::min<uint64>)(produced, (std::numeric_limits<uInt>::max)()));
            stream.next_out  = reinterpret_cast<Bytef*>(output.GetData() + produced);
            ret              = Z_OK;
        } else if (stream.avail_in == 0 || ret == Z_BUF_ERROR) {
            // all the input was consumed (or no progress is possible) but the stream did not end => truncated stream
            ret = Z_BUF_ERROR;
            break;
        }
    }

    output.Resize(stream.total_out);
    sizeConsumed = stream.total_in;
    message.Format("Return code: %d with msg: %s", ret, stream.msg ? stream.msg : "");

    CHECK(ret == Z_OK || ret == Z_STREAM_END, false, "");

    return true;
}
} // namespace GView::ZLIB
