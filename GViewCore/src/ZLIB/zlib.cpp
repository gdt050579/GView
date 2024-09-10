#include "../include/GView.hpp"
#include <zlib.h>

namespace GView::ZLIB
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
bool DecompressStream(const Buffer& input, uint64 inputSize, Buffer& output, uint64& outputSize)
{
    CHECK(input.IsValid(), false, "");
    CHECK(inputSize > 0, false, "");

    uint64 bufferSize = inputSize * 2;
    output.Resize(bufferSize);

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;

    struct ZWrapper {
        z_stream& strm;

        ZWrapper(z_stream& strmRef) : strm(strmRef)
        {
        }
        ~ZWrapper()
        {
            inflateEnd(&strm);
        }
    };

    ZWrapper zWrapper(strm);

    strm.avail_in  = static_cast<uInt>(inputSize);
    strm.next_in   = const_cast<Bytef*>(input.GetData());
    strm.avail_out = static_cast<uInt>(bufferSize);
    strm.next_out  = reinterpret_cast<Bytef*>(output.GetData());

    int ret = inflateInit(&strm);
    CHECK(ret == Z_OK, false, "");

    ret = Z_BUF_ERROR;
    while (ret == Z_BUF_ERROR || ret == Z_MEM_ERROR || ret == Z_DATA_ERROR) {
        if (ret == Z_BUF_ERROR) {
            bufferSize *= 2;
            output.Resize(bufferSize);
            strm.avail_out = static_cast<uInt>(bufferSize);
            strm.next_out  = reinterpret_cast<Bytef*>(output.GetData());
        } 
        ret = inflate(&strm, Z_NO_FLUSH);
        CHECK(ret != Z_MEM_ERROR && ret != Z_DATA_ERROR, false, "");
    }

    CHECK(ret == Z_OK || ret == Z_STREAM_END, false, "");

    outputSize = bufferSize - strm.avail_out;
    output.Resize(outputSize);

    return true;
}
} // namespace GView::ZLIB
