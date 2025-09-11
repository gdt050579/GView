#include "pdf.hpp"
#include <openjpeg.h>
#include <jbig2.h>
// #include <tiffio.h>

using namespace GView::Type;
using namespace GView;

void PDF::PDFFile::GetPreviousRow(const Buffer& data, uint64_t offset, uint8_t* buffer, const uint64_t rowLength)
{
    if (offset >= rowLength) {
        memcpy(buffer, data.GetData() + offset - rowLength, rowLength);
    } else {
        memset(buffer, 0, rowLength);
    }
}

void PDF::PDFFile::ApplyFilter(
      Buffer& data, uint64_t offset, uint8_t* rowBuffer, const uint64_t rowLength, const uint8_t bytesPerComponent, const uint8_t predictor)
{
    PDF::PDFFile::GetPreviousRow(data, offset, rowBuffer, rowLength);

    for (uint64_t i = 0; i < rowLength; ++i) {
        uint8_t newValue       = data.GetData()[offset];
        uint8_t left           = (offset % bytesPerComponent == 0) ? 0 : data.GetData()[offset - bytesPerComponent];
        uint8_t above          = rowBuffer[i];
        uint8_t aboveLeft      = (offset >= rowLength && (offset - bytesPerComponent) >= rowLength) ? rowBuffer[i - bytesPerComponent] : 0;
        uint8_t paethPredictor = 0, p = 0, pLeft = 0, pAbove = 0, pAboveLeft = 0;

        switch (predictor) {
        case PDF::PREDICTOR::SUB:
            newValue = data.GetData()[offset] + left;
            break;
        case PDF::PREDICTOR::UP:
            newValue = data.GetData()[offset] + above;
            break;
        case PDF::PREDICTOR::AVERAGE:
            newValue = data.GetData()[offset] + ((left + above) / 2);
            break;
        case PDF::PREDICTOR::PAETH:
            paethPredictor = left + above - aboveLeft;
            p              = data.GetData()[offset] - paethPredictor;
            pLeft          = std::abs(p - left);
            pAbove         = std::abs(p - above);
            pAboveLeft     = std::abs(p - aboveLeft);
            newValue       = data.GetData()[offset] + (pLeft <= pAbove && pLeft <= pAboveLeft ? left : pAbove <= pAboveLeft ? above : aboveLeft);
            break;
        case PDF::PREDICTOR::NONE:
        case PDF::PREDICTOR::OPTIMUM:
            return; // No filtering needed for None or Optimum
        default:
            // unknown predictor
            return;
        }

        data.GetData()[offset] = newValue;
        ++offset;
    }
}

void PDF::PDFFile::ApplyPNGFilter(Buffer& data, const uint16_t& column, const uint8_t& predictor, const uint8_t& bitsPerComponent)
{
    if (!data.IsValid()) {
        return;
    }

    const uint8_t bytesPerComponent = (bitsPerComponent + 7) / 8; // ceil(bitsPerComponent / 8)
    const uint64_t rowLength        = column * bytesPerComponent + 1;
    const uint64_t dataLength       = data.GetLength();

    Buffer rowBuffer;
    rowBuffer.Resize(rowLength);

    for (uint64_t offset = 0; offset < dataLength;) {
        ApplyFilter(data, offset, rowBuffer.GetData(), rowLength, bytesPerComponent, predictor);
        offset += rowLength;
    }

    const uint64_t newSize = dataLength - (dataLength / (rowLength + 1));
    Buffer filteredData;
    filteredData.Resize(newSize);

    uint64_t srcOffset = 0;
    uint64_t dstOffset = 0;
    while (srcOffset < dataLength) {
        if (srcOffset % rowLength != 0) { // Skip filter type byte
            filteredData.GetData()[dstOffset++] = data.GetData()[srcOffset];
        }
        ++srcOffset;
    }

    data = std::move(filteredData);
}

bool PDF::PDFFile::RunLengthDecode(const BufferView& input, Buffer& output, String& message)
{
    message.Clear();
    uint64_t inPos   = 0;
    const uint64_t n = input.GetLength();
    while (true) {
        if (inPos >= n) {
            message.Set("Not enough data to read the length byte!");
            return false;
        }
        const uint8_t lengthByte = input[inPos++];
        if (lengthByte == 128) {
            break;
        }
        if (lengthByte < 128) {
            size_t literalCount = static_cast<size_t>(lengthByte) + 1;
            if (inPos + literalCount > n) {
                message.Set("Not enough data to copy literal bytes!");
                return false;
            }
            BufferView chunk(input.GetData() + inPos, literalCount);
            output.Add(chunk);
            inPos += literalCount;
        }
        else {
            if (inPos >= n) {
                message.Set("Not enough data to read the repeated byte!");
                return false;
            }
            uint8_t repeatedByte = input[inPos++];
            size_t repeatCount   = 257 - static_cast<size_t>(lengthByte);
            output.AddMultipleTimes(BufferView(&repeatedByte, 1), static_cast<uint32_t>(repeatCount));
        }
    }
    return true;
}

bool PDF::PDFFile::ASCIIHexDecode(const BufferView& input, Buffer& output, AppCUI::Utils::String& message)
{
    message.Clear();
    int16_t halfNibble = -1;
    output.Resize(0);

    const uint64_t n    = input.GetLength();
    bool foundEndMarker = false;

    for (uint64_t i = 0; i < n; i++) {
        const uint8 c = input[i];

        if (c == PDF::DC::GREATER_THAN) {
            foundEndMarker = true;
            break;
        }

        if (c == PDF::WSC::SPACE || c == PDF::WSC::HORIZONAL_TAB || c == PDF::WSC::CARRIAGE_RETURN || c == PDF::WSC::LINE_FEED || c == PDF::WSC::FORM_FEED) {
            continue;
        }

        int nibble = -1;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'A' && c <= 'F') {
            nibble = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            nibble = c - 'a' + 10;
        } else {
            message.Set("Invalid hex digit in ASCIIHexDecode!");
            return false;
        }

        if (halfNibble == -1) {
            halfNibble = nibble;
        } else {
            const int fullByte = (halfNibble << 4) | nibble;
            halfNibble   = -1;
            const uint8 oneByte = static_cast<uint8>(fullByte);
            BufferView singleByte(&oneByte, 1);
            output.Add(singleByte);
        }
    }

    if (halfNibble != -1) {
        const uint8 oneByte = static_cast<uint8>(halfNibble << 4);
        BufferView singleByte(&oneByte, 1);
        output.Add(singleByte);
        halfNibble = -1;
    }

    if (!foundEndMarker) {
        message.Set("Missing '>' marker in ASCIIHexDecode data!");
    }

    return true;
}

bool PDF::PDFFile::ASCII85Decode(const BufferView& input, Buffer& output, String& message)
{
    message.Clear();
    output.Resize(0);
    const uint64_t len = input.GetLength();
    bool endOfData     = false;
    std::vector<char> accum;
    accum.reserve(5);

    // helper lambda to decode a full 5-char group into 4 bytes
    auto decodeGroup = [&](const char group[5], bool isPartial, size_t partialLen) -> bool {
        uint64_t value = 0;
        for (int i = 0; i < 5; i++) {
            const uint8_t c = static_cast<uint8_t>(group[i]);
            if (c < '!' || c > 'u') {
                message.Set("Invalid ASCII85 character (not in '!'..'u').");
                return false;
            }
            uint64_t digit = c - '!';
            if (digit > 84) {
                message.Set("Invalid digit in ASCII85Decode (larger than 84).");
                return false;
            }
            value = value * 85ULL + digit;
        }
        uint8_t b[4];
        b[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        b[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        b[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        b[3] = static_cast<uint8_t>((value >> 0) & 0xFF);

        size_t outBytes = 4; // full group
        if (isPartial) {
            if (partialLen < 2 || partialLen > 4) {
                message.Set("Invalid partial ASCII85 group size (must be 2..4).");
                return false;
            }
            outBytes = partialLen - 1;
        }

        if (outBytes > 4) {
            message.Set("Internal error in ASCII85 partial decode size!");
            return false;
        }

        BufferView chunk(b, outBytes);
        output.Add(chunk);

        return true;
    };

    for (size_t i = 0; i < len; i++) {
        const uint8_t c = input[i];

        // check for EOD marker "~>"
        if (c == '~') {
            if (i + 1 < len && input[i + 1] == PDF::DC::GREATER_THAN) {
                endOfData = true;
                i++; // skip '>' too
                break;
            }
            // if not '>', just continue processing
            message.Set("ASCII85Decode: '~' not followed by '>' => skipping.");
            continue;
        }

        if (c == PDF::WSC::SPACE || c == PDF::WSC::HORIZONAL_TAB || c == PDF::WSC::CARRIAGE_RETURN || c == PDF::WSC::LINE_FEED || c == PDF::WSC::FORM_FEED) {
            continue;
        }

        // 'z' -> means 4 zero bytes -> only if accum is empty
        if (c == 'z') {
            // 'z' can only appear by itself, not in the middle of a group
            if (!accum.empty()) {
                message.Set("ASCII85Decode: 'z' found in the middle of a group => invalid.");
                return false;
            }
            const uint8_t zeros[4] = { 0, 0, 0, 0 };
            BufferView chunk(zeros, 4);
            output.Add(chunk);
            continue;
        }

        if (c < '!' || c > 'u') {
            message.Set("ASCII85Decode: Invalid character (not whitespace, not z, not ~>): out of '!'..'u' range.");
            continue;
        }

        accum.push_back(static_cast<char>(c));
        if (accum.size() == 5) {
            // decode the group of 5 characters
            if (!decodeGroup(accum.data(), false, 5)) {
                return false;
            }
            accum.clear();
        }
    }

    if (!endOfData) {
        message.Set("Missing '~>' EOD marker in ASCII85 data! Processing incomplete data.");
    }

    if (!accum.empty()) {
        if (accum.size() == 1) {
            message.Set("ASCII85Decode: Partial group of only 1 char => invalid.");
            accum.clear();
            return true;
        }

        if (accum.size() >= 2 && accum.size() <= 4) {
            if (!decodeGroup(accum.data(), true, accum.size())) {
                return false;
            }
        } else {
            message.Set("ASCII85Decode: Invalid partial group size.");
            return false;
        }
    }

    return true;
}

struct MemoryStreamData {
    const uint8_t* data  = nullptr;
    size_t size          = 0;
    size_t currentOffset = 0;
};

static OPJ_SIZE_T read_fn(void* buffer, OPJ_SIZE_T nbBytes, void* userData)
{
    auto* msd = reinterpret_cast<MemoryStreamData*>(userData);
    if (!msd || !msd->data) {
        return (OPJ_SIZE_T) -1;
    }

    size_t remaining = msd->size - msd->currentOffset;

    if (remaining == 0) {
        return (OPJ_SIZE_T) -1;
    }

    if (nbBytes > remaining) {
        nbBytes = remaining;
    }

    memcpy(buffer, msd->data + msd->currentOffset, static_cast<size_t>(nbBytes));
    msd->currentOffset += static_cast<size_t>(nbBytes);

    return nbBytes;
}

static OPJ_OFF_T skip_fn(OPJ_OFF_T n, void* userData)
{
    auto* msd = reinterpret_cast<MemoryStreamData*>(userData);
    if (!msd) {
        return -1;
    }

    OPJ_OFF_T oldOffset = static_cast<OPJ_OFF_T>(msd->currentOffset);
    OPJ_OFF_T newOffset = oldOffset + n;

    // clamp newOffset to [0, msd->size]
    if (newOffset < 0) {
        newOffset = 0;
    } else if (newOffset > static_cast<OPJ_OFF_T>(msd->size)) {
        newOffset = static_cast<OPJ_OFF_T>(msd->size);
    }

    msd->currentOffset = static_cast<size_t>(newOffset);
    return newOffset - oldOffset;
}

static OPJ_BOOL seek_fn(OPJ_OFF_T pos, void* userData)
{
    auto* msd = reinterpret_cast<MemoryStreamData*>(userData);
    if (!msd) {
        return OPJ_FALSE;
    }

    if (pos < 0) {
        pos = 0;
    } else if (pos > static_cast<OPJ_OFF_T>(msd->size)) {
        pos = static_cast<OPJ_OFF_T>(msd->size);
    }

    msd->currentOffset = static_cast<size_t>(pos);
    return OPJ_TRUE;
}

static void close_fn(void* userData)
{
    auto* msd = reinterpret_cast<MemoryStreamData*>(userData);
    delete msd; // Ensure MemoryStreamData is properly freed
}

opj_stream_t* CreateMemoryStream(MemoryStreamData* msd)
{
    const OPJ_SIZE_T kChunkSize = 4096;
    opj_stream_t* stream = opj_stream_create(kChunkSize, OPJ_TRUE);
    if (!stream) {
        return nullptr;
    }

    opj_stream_set_read_function(stream, read_fn);
    opj_stream_set_skip_function(stream, skip_fn);
    opj_stream_set_seek_function(stream, seek_fn);

    opj_stream_set_user_data(stream, msd, close_fn); // Assign close function
    opj_stream_set_user_data_length(stream, msd->size);

    return stream;
}

bool PDF::PDFFile::JPXDecode(const BufferView& jpxData, Buffer& output, uint32_t& width, uint32_t& height, uint8_t& components, String& message)
{
    message.Clear();
    output.Resize(0);

    MemoryStreamData* msd = new MemoryStreamData;
    msd->data             = jpxData.GetData();
    msd->size             = jpxData.GetLength();
    msd->currentOffset    = 0;

    opj_stream_t* stream = CreateMemoryStream(msd);
    if (!stream) {
        delete msd; // since close_fn won't be called if create fails
        message.Set("Failed to create OpenJPEG memory stream!");
        return false;
    }

    opj_codec_t* codec = opj_create_decompress(OPJ_CODEC_JP2);
    if (!codec) {
        message.Set("Failed to create JPX codec!");
        opj_stream_destroy(stream); // automatically calls close_fn, which deletes msd
        return false;
    }

    opj_set_info_handler(codec, [](const char* msg, void*) { /* info */ }, nullptr);
    opj_set_warning_handler(codec, [](const char* msg, void*) { /* warning */ }, nullptr);
    opj_set_error_handler(codec, [](const char* msg, void*) { /* error */ }, nullptr);

    opj_dparameters_t parameters;
    opj_set_default_decoder_parameters(&parameters);

    if (!opj_setup_decoder(codec, &parameters)) {
        message.Set("JPXDecode: opj_setup_decoder failed!");
        opj_destroy_codec(codec);
        opj_stream_destroy(stream);
        return false;
    }

    opj_image_t* image = nullptr;
    if (!opj_read_header(stream, codec, &image)) {
        message.Set("JPXDecode: opj_read_header failed!");
        opj_destroy_codec(codec);
        opj_stream_destroy(stream);
        return false;
    }

    if (!opj_decode(codec, stream, image)) {
        message.Set("JPXDecode: opj_decode failed!");
        opj_destroy_codec(codec);
        opj_stream_destroy(stream);
        if (image) {
            opj_image_destroy(image);
        }
        return false;
    }

    if (!opj_end_decompress(codec, stream)) {
        message.Set("JPXDecode: opj_end_decompress failed!");
        opj_destroy_codec(codec);
        opj_stream_destroy(stream);
        if (image) {
            opj_image_destroy(image);
        }
        return false;
    }

    width      = image->x1 - image->x0;
    height     = image->y1 - image->y0;
    components = static_cast<uint8_t>(image->numcomps);

    const size_t pixelCount = static_cast<size_t>(width) * static_cast<size_t>(height);
    const size_t outSize    = pixelCount * components;

    output.Resize(outSize);
    uint8_t* outPtr = output.GetData();

    for (uint32_t c = 0; c < components; c++) {
        const opj_image_comp_t& comp = image->comps[c];
        for (size_t p = 0; p < pixelCount; p++) {
            int val = 0;
            if (p < static_cast<size_t>(comp.w) * static_cast<size_t>(comp.h)) {
                val = comp.data[p];
            }
            if (val < 0) {
                val = 0;
            }
            if (val > 255) {
                val = 255;
            }

            outPtr[p * components + c] = static_cast<uint8_t>(val);
        }
    }

    opj_destroy_codec(codec);
    opj_stream_destroy(stream);
    if (image) {
        opj_image_destroy(image);
    }

    return true;
}

bool PDF::PDFFile::LZWDecodeStream(const BufferView& input, Buffer& output, uint8_t earlyChange, AppCUI::Utils::String& message)
{
    message.Clear();
    output.Resize(0);

    if (!input.IsValid() || input.GetLength() == 0) {
        message.Set("Empty or invalid LZW input!");
        return false;
    }

    std::vector<std::vector<uint8_t>> dict;
    dict.reserve(4096);

    auto reInitDictionary = [&]() {
        dict.clear();
        dict.resize(258); // 0..255 -> single bytes, plus two special codes: CLEAR=256, EOD=257
        for (int i = 0; i < 256; i++) {
            dict[i].clear();
            dict[i].push_back(static_cast<uint8_t>(i));
        }
        // 256 -> CLEAR, 257 -> EOD -> no data
    };

    reInitDictionary();
    uint16_t nextCode     = 258;
    uint16_t codeSize     = 9;
    uint16_t maxCodeSize  = 12;
    uint16_t maxCodeValue = (1 << codeSize);
    bool pendingIncrement = false;
    size_t inPos          = 0;
    uint64_t bitBuf       = 0;
    int bitCount          = 0;

    auto readCode = [&](int bitsNeeded) -> int {
        while (bitCount < bitsNeeded && inPos < input.GetLength()) {
            bitBuf |= (static_cast<uint64_t>(input[inPos++]) << bitCount);
            bitCount += 8;
        }
        if (bitCount < bitsNeeded) {
            // truncated
            return -1;
        }
        int code = static_cast<int>(bitBuf & ((1ULL << bitsNeeded) - 1));
        bitBuf >>= bitsNeeded;
        bitCount -= bitsNeeded;
        return code;
    };

    reInitDictionary();
    nextCode         = 258;
    codeSize         = 9;
    maxCodeValue     = (1 << codeSize);
    pendingIncrement = false;

    int prevCode = readCode(codeSize);
    if (prevCode < 0) {
        // no data
        return true;
    }

    if (prevCode == 256)
    {
        // reinit dictionary again
        reInitDictionary();
        nextCode     = 258;
        codeSize     = 9;
        maxCodeValue = (1 << codeSize);
        prevCode     = readCode(codeSize);
        if (prevCode < 0) {
            return true;
        }
    }
    if (prevCode == 257) {
        // EOD -> done
        return true;
    }
    if (prevCode < 0 || prevCode > 255) {
        // invalid
        message.Set("LZW invalid initial code!");
        return false;
    }
    output.Add(BufferView(&dict[prevCode][0], dict[prevCode].size()));
    std::vector<uint8_t> oldString = dict[prevCode];

    while (true) {
        int code = readCode(codeSize);
        if (code < 0) {
            break;
        }

        if (code == 256) {
            reInitDictionary();
            nextCode         = 258;
            codeSize         = 9;
            maxCodeValue     = (1 << codeSize);
            pendingIncrement = false;

            code = readCode(codeSize);
            if (code < 0) {
                break;
            }
            if (code == 257) {
                break; // EOD
            }

            if (code < 0 || code > 255) {
                message.Set("LZW invalid code after CLEAR!");
                return false;
            }
            output.Add(BufferView(&dict[code][0], dict[code].size()));
            oldString = dict[code];
            continue;
        } else if (code == 257) {
            break;
        } else if (static_cast<size_t>(code) < dict.size() && !dict[code].empty()) {
            output.Add(BufferView(&dict[code][0], dict[code].size()));
            std::vector<uint8_t> newEntry = oldString;
            newEntry.push_back(dict[code][0]);
            if (nextCode < 4096) {
                dict.resize(std::max<size_t>(dict.size(), nextCode + 1));
                dict[nextCode] = std::move(newEntry);
                nextCode++;
            }
        } else if (code == static_cast<int>(nextCode)) {
            // "K+K[0]" scenario -> code is next to be assigned -> oldString + oldString[0]
            std::vector<uint8_t> newEntry = oldString;
            newEntry.push_back(oldString[0]);
            dict.resize(std::max<size_t>(dict.size(), nextCode + 1));
            dict[nextCode] = std::move(newEntry);
            nextCode++;
            output.Add(BufferView(&dict[nextCode - 1][0], dict[nextCode - 1].size()));
        } else {
            message.Set("LZW invalid code, out of dictionary range!");
            return false;
        }
        if (nextCode >= maxCodeValue) {
            if (codeSize < maxCodeSize) {
                if (earlyChange == 1) {
                    codeSize++;
                    maxCodeValue = (1 << codeSize);
                } else {
                    if (!pendingIncrement) {
                        pendingIncrement = true;
                    } else {
                        codeSize++;
                        maxCodeValue     = (1 << codeSize);
                        pendingIncrement = false;
                    }
                }
            }
        } else {
            if (pendingIncrement) {
                codeSize++;
                if (codeSize > maxCodeSize)
                    codeSize = maxCodeSize;
                maxCodeValue     = (1 << codeSize);
                pendingIncrement = false;
            }
        }
        if (code >= 0 && static_cast<size_t>(code) < dict.size()) {
            oldString = dict[code];
        }
    }
    return true;
}

bool PDF::PDFFile::JBIG2Decode(const BufferView& input, Buffer& output, String& message)
{
    message.Clear();
    output.Resize(0);

    if (!input.IsValid() || input.GetLength() == 0) {
        message.Set("JBIG2Decode: empty input!");
        return false;
    }

    Jbig2Ctx* ctx = jbig2_ctx_new(nullptr, JBIG2_OPTIONS_EMBEDDED, nullptr, nullptr, nullptr);
    if (!ctx) {
        message.Set("JBIG2Decode: failed to create jbig2 context!");
        return false;
    }

    const int parse_result = jbig2_data_in(ctx, (unsigned char*) input.GetData(), (size_t) input.GetLength());
    if (parse_result < 0) {
        jbig2_ctx_free(ctx);
        message.Set("JBIG2Decode: parse error from jbig2_data_in!");
        return false;
    }
    jbig2_complete_page(ctx);
    Jbig2Image* pageImage = jbig2_page_out(ctx);
    if (!pageImage) {
        jbig2_ctx_free(ctx);
        message.Set("JBIG2Decode: no page image found!");
        return false;
    }
    const uint32_t w        = pageImage->width;
    const uint32_t h        = pageImage->height;
    const uint32_t stride   = pageImage->stride;
    const size_t totalBytes = (size_t) stride * (size_t) h;

    if (totalBytes == 0) {
        jbig2_release_page(ctx, pageImage);
        jbig2_ctx_free(ctx);
        message.Set("JBIG2Decode: zero-sized page image!");
        return false;
    }

    output.Resize(totalBytes);
    uint8_t* dst       = output.GetData();
    const uint8_t* src = pageImage->data;

    for (uint32_t row = 0; row < h; row++) {
        memcpy(dst + row * stride, src + row * stride, stride);
    }

    jbig2_release_page(ctx, pageImage);
    jbig2_ctx_free(ctx);
    return true;
}