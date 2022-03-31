#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 MD4_BLOCKSIZE  = 0x0200;
constexpr uint32 MD4_DIGESTSIZE = 0x80;
constexpr uint32 IV_A           = 0x67452301;
constexpr uint32 IV_B           = 0xEFCDAB89;
constexpr uint32 IV_C           = 0x98BADCFE;
constexpr uint32 IV_D           = 0x10325476;
constexpr uint32 K_0            = 0x00000000;
constexpr uint32 K_1            = 0x5A827999;
constexpr uint32 K_2            = 0x6ED9EBA1;
constexpr uint32 S11            = 0x03;
constexpr uint32 S12            = 0x07;
constexpr uint32 S13            = 0x0B;
constexpr uint32 S14            = 0x13;
constexpr uint32 S21            = 0x03;
constexpr uint32 S22            = 0x05;
constexpr uint32 S23            = 0x09;
constexpr uint32 S24            = 0x0D;
constexpr uint32 S31            = 0x03;
constexpr uint32 S32            = 0x09;
constexpr uint32 S33            = 0x0B;
constexpr uint32 S34            = 0x0F;

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTL(a, n) ((a) << (n)) | ((a) >> (32 - (n)))

#define MD4_ROUND1(a, b, c, d, k, s) (a = ROTL(a + F(b, c, d) + k + K_0, s))
#define MD4_ROUND2(a, b, c, d, k, s) (a = ROTL(a + G(b, c, d) + k + K_1, s))
#define MD4_ROUND3(a, b, c, d, k, s) (a = ROTL(a + H(b, c, d) + k + K_2, s))

bool MD4::Init()
{
    hash[0] = IV_A;
    hash[1] = IV_B;
    hash[2] = IV_C;
    hash[3] = IV_D;
    size    = 0;
    init    = true;

    return true;
}

bool ProcessBlock(uint32* hash, uint32* input)
{
    CHECK(input != nullptr, false, "");
    CHECK(hash != nullptr, false, "");

    uint32 a = hash[0];
    uint32 b = hash[1];
    uint32 c = hash[2];
    uint32 d = hash[3];

    MD4_ROUND1(a, b, c, d, input[0], S11);
    MD4_ROUND1(d, a, b, c, input[1], S12);
    MD4_ROUND1(c, d, a, b, input[2], S13);
    MD4_ROUND1(b, c, d, a, input[3], S14);
    MD4_ROUND1(a, b, c, d, input[4], S11);
    MD4_ROUND1(d, a, b, c, input[5], S12);
    MD4_ROUND1(c, d, a, b, input[6], S13);
    MD4_ROUND1(b, c, d, a, input[7], S14);
    MD4_ROUND1(a, b, c, d, input[8], S11);
    MD4_ROUND1(d, a, b, c, input[9], S12);
    MD4_ROUND1(c, d, a, b, input[10], S13);
    MD4_ROUND1(b, c, d, a, input[11], S14);
    MD4_ROUND1(a, b, c, d, input[12], S11);
    MD4_ROUND1(d, a, b, c, input[13], S12);
    MD4_ROUND1(c, d, a, b, input[14], S13);
    MD4_ROUND1(b, c, d, a, input[15], S14);

    MD4_ROUND2(a, b, c, d, input[0], S21);
    MD4_ROUND2(d, a, b, c, input[4], S22);
    MD4_ROUND2(c, d, a, b, input[8], S23);
    MD4_ROUND2(b, c, d, a, input[12], S24);
    MD4_ROUND2(a, b, c, d, input[1], S21);
    MD4_ROUND2(d, a, b, c, input[5], S22);
    MD4_ROUND2(c, d, a, b, input[9], S23);
    MD4_ROUND2(b, c, d, a, input[13], S24);
    MD4_ROUND2(a, b, c, d, input[2], S21);
    MD4_ROUND2(d, a, b, c, input[6], S22);
    MD4_ROUND2(c, d, a, b, input[10], S23);
    MD4_ROUND2(b, c, d, a, input[14], S24);
    MD4_ROUND2(a, b, c, d, input[3], S21);
    MD4_ROUND2(d, a, b, c, input[7], S22);
    MD4_ROUND2(c, d, a, b, input[11], S23);
    MD4_ROUND2(b, c, d, a, input[15], S24);

    MD4_ROUND3(a, b, c, d, input[0], S31);
    MD4_ROUND3(d, a, b, c, input[8], S32);
    MD4_ROUND3(c, d, a, b, input[4], S33);
    MD4_ROUND3(b, c, d, a, input[12], S34);
    MD4_ROUND3(a, b, c, d, input[2], S31);
    MD4_ROUND3(d, a, b, c, input[10], S32);
    MD4_ROUND3(c, d, a, b, input[6], S33);
    MD4_ROUND3(b, c, d, a, input[14], S34);
    MD4_ROUND3(a, b, c, d, input[1], S31);
    MD4_ROUND3(d, a, b, c, input[9], S32);
    MD4_ROUND3(c, d, a, b, input[5], S33);
    MD4_ROUND3(b, c, d, a, input[13], S34);
    MD4_ROUND3(a, b, c, d, input[3], S31);
    MD4_ROUND3(d, a, b, c, input[11], S32);
    MD4_ROUND3(c, d, a, b, input[7], S33);
    MD4_ROUND3(b, c, d, a, input[15], S34);

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;

    return true;
}

bool MD4::Update(const unsigned char* input, uint32 length)
{
    CHECK(init, false, "");
    CHECK(input != nullptr, false, "");

    const uint32 left = sizeof(block) - (size & 0x3f);
    size += length;

    if (left > length)
    {
        memcpy(reinterpret_cast<char*>(block) + (sizeof(block) - left), input, length);
        return true;
    }

    memcpy(reinterpret_cast<char*>(block) + (sizeof(block) - left), input, left);
    ProcessBlock(hash, block);
    input += left;
    length -= left;

    while (length >= sizeof(block))
    {
        memcpy(block, input, sizeof(block));
        input += sizeof(block);
        length -= sizeof(block);
    }

    memcpy(block, input, length);

    return true;
}

bool MD4::Update(Buffer buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool MD4::Final(uint8 hash[16])
{
    CHECK(init, false, "");

    const uint32 offset = size & 0x3F;
    int32 padding       = 0x38 - (offset + 1);

    *(reinterpret_cast<char*>(block) + offset) = static_cast<uint8>(0x80);
    char* p                                    = (reinterpret_cast<char*>(block) + offset + 1);

    if (padding < 0)
    {
        memset(p, 0, padding + sizeof(uint64));
        ProcessBlock(this->hash, block);
        p       = reinterpret_cast<char*>(block);
        padding = 0x38;
    }

    memset(p, 0, padding);
    block[14] = static_cast<uint8>(size << 0x03);
    block[15] = static_cast<uint8>(size >> 0x1D);
    ProcessBlock(this->hash, block);

    memcpy(hash, this->hash, sizeof(this->hash));

    return true;
}
} // namespace GView::Hashes
