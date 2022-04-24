#include "Internal.hpp"

// https://github.com/libyal/libfwnt/blob/main/documentation/Compression%20methods.asciidoc
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8

namespace GView::Compression::LZXPRESS::Huffman
{
constexpr uint32 MAX_BITS_COUNT     = 32U;
constexpr uint32 UINT32_BITS_COUNT  = 32U;
constexpr uint32 UINT16_BITS_COUNT  = 16U;
constexpr uint32 CHUNK_SIZE         = 0x10000;
constexpr uint32 MAXIMUM_CODE_SIZE  = 15U;
constexpr uint32 SYMBOLS_ARRAY_SIZE = 512U;
constexpr uint32 SYMBOL_MAX_SIZE    = 256U;

struct Stream
{
  private:
    const uint8* stream;
    size_t size;
    size_t offset;

    uint32 bits;
    uint8 bitsCount;

  public:
    bool Initialize(const uint8* _stream, size_t _size)
    {
        CHECK(_stream != nullptr, false, "");
        CHECK(_size <= (size_t) INT32_MAX, false, "");

        stream = _stream;
        size   = _size;

        return true;
    }

    inline void PushUInt16()
    {
        bits <<= UINT16_BITS_COUNT;
        bitsCount += UINT16_BITS_COUNT;

        if (size >= sizeof(uint16) || offset <= (size - sizeof(uint16)))
        {
            *((uint16*) &bits) = *((uint16*) (stream + offset));
            offset += sizeof(uint16);
        }
    }

    inline void Next()
    {
        if (bitsCount < UINT16_BITS_COUNT)
        {
            PushUInt16();
        }
    }

    inline void PushUInt32()
    {
        PushUInt16();
        PushUInt16();
    }

    inline uint32 GetBits() const
    {
        return bits;
    }

    inline uint8 GetBitsCount() const
    {
        return bitsCount;
    }

    inline void ResetBits()
    {
        bitsCount = 0;
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

    template <typename V>
    inline bool Read(V& value)
    {
        CHECK(offset <= size - sizeof(V), false, "");

        value = *(V*) (stream + offset);
        offset += sizeof(V);

        return true;
    }

    inline size_t GetSize() const
    {
        return size;
    }

    inline size_t GetOffset() const
    {
        return offset;
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

        size = sizeof(int32) * (_maximumCodeSize + 1ULL);

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

        for (int32 i = 0; i < _codeSizesCount; i++)
        {
            const uint8 size = codeSizes[i];
            CHECK(size <= maximumCodeSize, false, "");

            codeSizeCounts.get()[size] += 1;
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
        while (stream.GetBitsCount() < maximumCodeSize)
        {
            CHECK(stream.Read(maximumCodeSize), false, "");
        }

        const uint8 bitsCount = maximumCodeSize < stream.GetBitsCount() ? maximumCodeSize : stream.GetBitsCount();

        uint32 value       = 0;
        int32 code         = 0;
        int32 initialCode  = 0;
        int32 initialIndex = 0;
        symbol             = 0;
        bool result        = false;
        for (uint8 i = 1; i <= bitsCount; i++)
        {
            CHECK(stream.GetValue(1, value), false, "");

            code <<= 1;
            code |= (int32) value;

            const int32 codeSizeCount = codeSizeCounts.get()[i];

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
    CHECK((stream.GetSize() - stream.GetOffset()) >= 260, false, "");
    CHECK(uncompressed.GetLength() <= (size_t) INT32_MAX, false, "");
    CHECK(uncompressedDataOffset < uncompressed.GetLength(), false, "");

    uint32 i = 0;
    uint8 codeSizes[SYMBOLS_ARRAY_SIZE]{ 0 };
    while (i < SYMBOLS_ARRAY_SIZE)
    {
        uint8 value;
        CHECK(stream.Read<decltype(value)>(value), false, "");
        codeSizes[i++] = value & 0x0f;
        codeSizes[i++] = (value & 0xf0) >> 4;
    }

    HuffmanTree tree{};
    CHECK(tree.Initialize(SYMBOLS_ARRAY_SIZE, MAXIMUM_CODE_SIZE), false, "");
    CHECK(tree.Build(codeSizes, SYMBOLS_ARRAY_SIZE), false, "");

    stream.PushUInt32();

    size_t nextChunk = uncompressedDataOffset + CHUNK_SIZE;
    if (nextChunk > uncompressed.GetLength())
    {
        nextChunk = uncompressed.GetLength();
    }

    while ((stream.GetOffset() < stream.GetSize()) || (stream.GetBitsCount() > 0))
    {
        CHECKBK(uncompressedDataOffset < nextChunk, "");

        uint32 symbol = 0;
        CHECK(tree.GetSymbol(stream, symbol), false, "");

        if (symbol < SYMBOL_MAX_SIZE)
        {
            uncompressed.GetData()[uncompressedDataOffset++] = (uint8) symbol;
        }

        stream.Next();

        if (stream.GetBits() == 0 && uncompressedDataOffset >= uncompressed.GetLength())
        {
            break;
        }

        if (symbol >= SYMBOL_MAX_SIZE)
        {
            symbol -= SYMBOL_MAX_SIZE;
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
                uint8 val8;
                CHECK(stream.Read<decltype(val8)>(val8), false, "");
                compressionSize += val8;

                if (compressionSize == 270)
                {
                    uint16 val16;
                    CHECK(stream.Read<decltype(val16)>(val16), false, "");
                    compressionSize = val16;

                    if (compressionSize == 0)
                    {
                        CHECK(stream.Read<decltype(compressionSize)>(compressionSize), false, "");
                    }
                }
            }
            compressionSize += 3;

            CHECK(compressionOffset <= uncompressedDataOffset, false, "");
            CHECK(compressionSize <= (uncompressed.GetLength() - uncompressedDataOffset), false, "");

            compressionOffset = (uint32) (uncompressedDataOffset - compressionOffset);

            memcpy(uncompressed.GetData() + uncompressedDataOffset, uncompressed.GetData() + compressionOffset, compressionSize);
            uncompressedDataOffset += compressionSize;
            compressionOffset += compressionSize;
            compressionSize = 0;

            stream.Next();
        }
    }

    return true;
}

bool Decompress(const BufferView& compressed, Buffer& uncompressed)
{
    Stream stream{};
    CHECK(stream.Initialize(compressed.GetData(), compressed.GetLength()), false, "");

    size_t offset = 0;
    while (stream.GetOffset() < stream.GetSize() && offset < uncompressed.GetLength())
    {
        stream.ResetBits();
        CHECK(Update(stream, uncompressed, offset), false, "");
    }
    CHECK(uncompressed.GetLength() == offset, false, "");

    return true;
}
} // namespace GView::Compression::LZXPRESS::Huffman
