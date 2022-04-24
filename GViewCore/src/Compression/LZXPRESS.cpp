#include "Internal.hpp"

namespace GView::Compression::LZXPRESS::Huffman
{
constexpr uint32 MAX_BITS_COUNT = 32U;
constexpr uint32 CHUNK_SIZE     = 0x10000;

struct Stream
{
    const uint8* stream;
    size_t size;
    size_t offset;

    uint32 bits;
    uint8 bitsCount;

    bool Initialize(const uint8* _stream, size_t _size)
    {
        CHECK(_stream != nullptr, false, "");
        CHECK(_size <= (size_t) INT32_MAX, false, "");

        stream = _stream;
        size   = _size;

        return true;
    }

    bool Read(uint8 bitsToRead)
    {
        CHECK(bitsToRead != 0, false, "");
        CHECK(bitsToRead <= MAX_BITS_COUNT, false, "");

        while (bitsCount < bitsToRead)
        {
            if ((size < 2) || (offset > (size - 2)))
            {
                bits <<= 16;
                bitsCount += 16;
            }
            else
            {
                bits <<= 8;
                bits |= stream[offset + 1];
                bits <<= 8;
                bits |= stream[offset];
                bitsCount += 16;

                offset += 2;
            }
        }

        return true;
    }

    bool GetValue(uint8 bitsToRead, uint32& value)
    {
        CHECK(bitsToRead <= MAX_BITS_COUNT, false, "");

        value = 0;
        CHECK(bitsToRead != 0, true, "");

        if (bitsCount < bitsToRead)
        {
            CHECK(Read(bitsToRead), false, "");
        }

        value = bits;

        if (bitsToRead < MAX_BITS_COUNT)
        {
            value >>= bitsCount - bitsToRead;
        }
        bitsCount -= bitsToRead;

        if (bitsCount == 0)
        {
            bits = 0;
        }
        else
        {
            const uint8 bitBufferSizeLeft = MAX_BITS_COUNT - bitsCount;
            bits &= 0xffffffffUL >> bitBufferSizeLeft;
        }

        return true;
    }
};

struct HuffmanTree
{
    uint8 maximumCodeSize;
    std::unique_ptr<int32> symbols;
    std::unique_ptr<int32> codeSizeCounts;

    bool Initialize(int32 symbolsCount, uint8 _maximumCodeSize)
    {
        CHECK(symbolsCount >= 0, false, "");
        CHECK(symbolsCount <= 1024, false, "");

        size_t size = sizeof(int32) * symbolsCount;

        symbols.reset(new int32[size]);
        CHECK(symbols.get() != nullptr, false, "");
        memset(symbols.get(), 0, size);

        size = sizeof(int) * (_maximumCodeSize + 1);

        codeSizeCounts.reset(new int32[size]);
        CHECK(codeSizeCounts.get() != nullptr, false, "");
        memset(codeSizeCounts.get(), 0, size);

        maximumCodeSize = _maximumCodeSize;

        return true;
    }

    bool Build(const uint8* codeSizes, int32 _codeSizesCount)
    {
        CHECK(codeSizes != nullptr, false, "");
        CHECK(_codeSizesCount >= 0, false, "");

        size_t size = sizeof(int32) * (maximumCodeSize + 1ULL);
        memset(codeSizeCounts.get(), 0, size);

        for (int32 symbol = 0; symbol < _codeSizesCount; symbol++)
        {
            const uint8 code_size = codeSizes[symbol];
            CHECK(code_size <= maximumCodeSize, false, "");

            codeSizeCounts.get()[code_size] += 1;
        }

        CHECK(codeSizeCounts.get()[0] != _codeSizesCount, true, "");

        int32 leftValue = 1;
        for (auto i = 1; i <= maximumCodeSize; i++)
        {
            leftValue <<= 1;
            leftValue -= codeSizeCounts.get()[i];
            CHECK(leftValue >= 0, false, "");
        }

        std::unique_ptr<int32> symbolOffsets(new int32[size]);
        CHECK(symbolOffsets.get() != nullptr, false, "");

        symbolOffsets.get()[0] = 0;
        symbolOffsets.get()[1] = 0;

        for (uint8 i = 1; i < maximumCodeSize; i++)
        {
            symbolOffsets.get()[i + 1] = symbolOffsets.get()[i] + codeSizeCounts.get()[i];
        }

        for (int32 symbol = 0; symbol < _codeSizesCount; symbol++)
        {
            const uint8 codeSize = codeSizes[symbol];
            if (codeSize == 0)
            {
                continue;
            }

            const int32 offset = symbolOffsets.get()[codeSize];
            CHECK(offset >= 0, false, "");
            CHECK(offset <= _codeSizesCount, false, "");

            symbolOffsets.get()[codeSize] += 1;
            symbols.get()[offset] = symbol;
        }

        return true;
    }

    bool GetSymbol(Stream& stream, uint32& symbol)
    {
        while (stream.bitsCount < maximumCodeSize)
        {
            CHECK(stream.Read(maximumCodeSize), false, "");
        }

        const uint8 bitsCount = maximumCodeSize < stream.bitsCount ? maximumCodeSize : stream.bitsCount;

        uint32 value        = 0;
        int32 codeSizeCount = 0;
        int32 code          = 0;
        int32 initialCode   = 0;
        int32 initialIndex  = 0;
        symbol              = 0;
        bool result         = false;
        for (uint8 i = 1; i <= bitsCount; i++)
        {
            CHECK(stream.GetValue(1, value), false, "");

            code <<= 1;
            code |= (int32) value;

            codeSizeCount = codeSizeCounts.get()[i];

            if ((code - codeSizeCount) < initialCode)
            {
                symbol = symbols.get()[initialIndex + (code - initialCode)];
                result = true;
                break;
            }
            initialCode += codeSizeCount;
            initialCode <<= 1;
            initialIndex += codeSizeCount;
        }

        CHECK(result, false, "");

        return true;
    }
};

bool Update(Stream& stream, Buffer& uncompressed, size_t& uncompressedDataOffset)
{
    CHECK((stream.size - stream.offset) >= 260, false, "");
    CHECK(uncompressed.GetLength() <= (size_t) INT32_MAX, false, "");
    CHECK(uncompressedDataOffset < uncompressed.GetLength(), false, "");

    constexpr auto ARRAY_SIZE = 512U;

    uint32 symbol = 0;
    uint8 codeSizes[ARRAY_SIZE]{ 0 };
    while (symbol < ARRAY_SIZE)
    {
        uint8 value         = stream.stream[stream.offset];
        codeSizes[symbol++] = value & 0x0f;
        value >>= 4;
        codeSizes[symbol++] = value & 0x0f;
        stream.offset += 1;
    }

    HuffmanTree tree{};
    CHECK(tree.Initialize(ARRAY_SIZE, 15), false, "");
    CHECK(tree.Build(codeSizes, ARRAY_SIZE), false, "");

    CHECK(stream.Read(MAX_BITS_COUNT), false, "");

    size_t nextChunk = uncompressedDataOffset + CHUNK_SIZE;
    if (nextChunk > uncompressed.GetLength())
    {
        nextChunk = uncompressed.GetLength();
    }

    while ((stream.offset < stream.size) || (stream.bitsCount > 0))
    {
        if (uncompressedDataOffset >= nextChunk)
        {
            stream.bitsCount = 0;
            break;
        }

        CHECK(tree.GetSymbol(stream, symbol), false, "");

        if (symbol < 256)
        {
            uncompressed.GetData()[uncompressedDataOffset++] = (uint8) symbol;
        }

        if (stream.bitsCount < 16)
        {
            CHECK(stream.Read(16), false, "");
        }

        if (stream.bits == 0 && uncompressedDataOffset >= uncompressed.GetLength())
        {
            break;
        }

        if (symbol >= 256)
        {
            symbol -= 256;
            uint32 compressionSize = symbol & 0x000f;
            symbol >>= 4;

            uint32 compressionOffset = 0;
            if (symbol != 0)
            {
                CHECK(stream.GetValue((uint8) symbol, compressionOffset), false, "");
            }
            compressionOffset = (uint32) ((1 << symbol) | compressionOffset);

            if (compressionSize == 15)
            {
                CHECK(stream.offset <= (stream.size - 1), false, "");
                compressionSize = stream.stream[stream.offset] + 15;
                stream.offset += 1;

                if (compressionSize == 270)
                {
                    CHECK(stream.offset <= (stream.size - 2), false, "");
                    compressionSize = *(uint16*) &(stream.stream[stream.offset]);
                    stream.offset += 2;

                    if (compressionSize == 0)
                    {
                        CHECK(stream.offset <= (stream.size - 4), false, "");
                        compressionSize = *(uint32*) &(stream.stream[stream.offset]);
                        stream.offset += 4;
                    }
                }
            }
            compressionSize += 3;

            CHECK(compressionOffset <= uncompressedDataOffset, false, "");
            CHECK(compressionSize <= (uncompressed.GetLength() - uncompressedDataOffset), false, "");

            compressionOffset = (uint32) (uncompressedDataOffset - compressionOffset);

            while (compressionSize > 0)
            {
                uncompressed.GetData()[uncompressedDataOffset++] = uncompressed.GetData()[compressionOffset++];
                compressionSize--;
            }

            if (stream.bitsCount < 16)
            {
                CHECK(stream.Read(16), false, "");
            }
        }
    }

    return true;
}

bool Decompress(const BufferView& compressed, Buffer& uncompressed)
{
    Stream stream{};
    CHECK(stream.Initialize(compressed.GetData(), compressed.GetLength()), false, "");

    size_t offset = 0;
    while (stream.offset < stream.size && offset < uncompressed.GetLength())
    {
        CHECK(Update(stream, uncompressed, offset), false, "");
    }
    CHECK(uncompressed.GetLength() == offset, false, "");

    return true;
}
} // namespace GView::Compression::LZXPRESS::Huffman
