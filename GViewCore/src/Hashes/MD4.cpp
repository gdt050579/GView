#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 MD4_BLOCKSIZE  = 0x40;
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

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) ((x & y) | (z & (x | y)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTL(a, n) ((a) << (n)) | ((a) >> (32 - (n)))

#define FF(a, b, c, d, x, s)                                                                                                               \
    {                                                                                                                                      \
        (a) += F((b), (c), (d)) + (x) + K_0;                                                                                               \
        (a) = ROTL((a), (s));                                                                                                              \
    }
#define GG(a, b, c, d, x, s)                                                                                                               \
    {                                                                                                                                      \
        (a) += G((b), (c), (d)) + (x) + K_1;                                                                                               \
        (a) = ROTL((a), (s));                                                                                                              \
    }
#define HH(a, b, c, d, x, s)                                                                                                               \
    {                                                                                                                                      \
        (a) += H((b), (c), (d)) + (x) + K_2;                                                                                               \
        (a) = ROTL((a), (s));                                                                                                              \
    }

bool MD4::Init()
{
    state[0] = IV_A;
    state[1] = IV_B;
    state[2] = IV_C;
    state[3] = IV_D;
    length   = 0;
    curlen   = 0;
    init     = true;

    return true;
}

bool MD4_ProcessBlock(uint32* state, const unsigned char* buf)
{
    CHECK(state != nullptr, false, "");
    CHECK(buf != nullptr, false, "");

    uint32 x[16];
    for (auto i = 0; i < 16; i++)
    {
        memcpy(x + i, buf + (4 * i), 4);
    }

    uint32 a = state[0];
    uint32 b = state[1];
    uint32 c = state[2];
    uint32 d = state[3];

    FF(a, b, c, d, x[0], S11);
    FF(d, a, b, c, x[1], S12);
    FF(c, d, a, b, x[2], S13);
    FF(b, c, d, a, x[3], S14);
    FF(a, b, c, d, x[4], S11);
    FF(d, a, b, c, x[5], S12);
    FF(c, d, a, b, x[6], S13);
    FF(b, c, d, a, x[7], S14);
    FF(a, b, c, d, x[8], S11);
    FF(d, a, b, c, x[9], S12);
    FF(c, d, a, b, x[10], S13);
    FF(b, c, d, a, x[11], S14);
    FF(a, b, c, d, x[12], S11);
    FF(d, a, b, c, x[13], S12);
    FF(c, d, a, b, x[14], S13);
    FF(b, c, d, a, x[15], S14);

    GG(a, b, c, d, x[0], S21);
    GG(d, a, b, c, x[4], S22);
    GG(c, d, a, b, x[8], S23);
    GG(b, c, d, a, x[12], S24);
    GG(a, b, c, d, x[1], S21);
    GG(d, a, b, c, x[5], S22);
    GG(c, d, a, b, x[9], S23);
    GG(b, c, d, a, x[13], S24);
    GG(a, b, c, d, x[2], S21);
    GG(d, a, b, c, x[6], S22);
    GG(c, d, a, b, x[10], S23);
    GG(b, c, d, a, x[14], S24);
    GG(a, b, c, d, x[3], S21);
    GG(d, a, b, c, x[7], S22);
    GG(c, d, a, b, x[11], S23);
    GG(b, c, d, a, x[15], S24);

    HH(a, b, c, d, x[0], S31);
    HH(d, a, b, c, x[8], S32);
    HH(c, d, a, b, x[4], S33);
    HH(b, c, d, a, x[12], S34);
    HH(a, b, c, d, x[2], S31);
    HH(d, a, b, c, x[10], S32);
    HH(c, d, a, b, x[6], S33);
    HH(b, c, d, a, x[14], S34);
    HH(a, b, c, d, x[1], S31);
    HH(d, a, b, c, x[9], S32);
    HH(c, d, a, b, x[5], S33);
    HH(b, c, d, a, x[13], S34);
    HH(a, b, c, d, x[3], S31);
    HH(d, a, b, c, x[11], S32);
    HH(c, d, a, b, x[7], S33);
    HH(b, c, d, a, x[15], S34);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    return true;
}

bool MD4::Update(const unsigned char* in, uint32 inlen)
{
    CHECK(init, false, "");
    CHECK(in != nullptr, false, "");

    CHECK(curlen <= sizeof(buf), false, "");
    CHECK((length + inlen * 8ULL) >= length, false, "");

    while (inlen > 0)
    {
        if (curlen == 0 && inlen >= MD4_BLOCKSIZE)
        {
            CHECK(MD4_ProcessBlock(state, in), false, "");

            length += MD4_BLOCKSIZE * 8ULL;
            in += MD4_BLOCKSIZE;
            inlen -= MD4_BLOCKSIZE;
        }
        else
        {
            const uint32 n = std::min<>(inlen, (MD4_BLOCKSIZE - curlen));
            memcpy(buf + curlen, in, n);
            curlen += n;
            in += n;
            inlen -= n;
            if (curlen == MD4_BLOCKSIZE)
            {
                CHECK(MD4_ProcessBlock(state, buf), false, "");
                this->length += 8ULL * MD4_BLOCKSIZE;
                this->curlen = 0;
            }
        }
    }

    return true;
}

bool MD4::Update(Buffer buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool MD4::Final(uint8 hash[16])
{
    CHECK(Final(), false, "");
    memcpy(hash, state, sizeof(state));
    return true;
}

bool MD4::Final()
{
    CHECK(init, false, "");
    CHECK(curlen <= sizeof(buf), false, "");

    length += curlen * 8ULL;

    buf[curlen++] = 0x80;

    if (curlen > 56)
    {
        while (curlen < MD4_BLOCKSIZE)
        {
            buf[curlen++] = 0;
        }
        MD4_ProcessBlock(state, buf);
        curlen = 0;
    }

    while (curlen < 56)
    {
        buf[curlen++] = 0;
    }

    *(uint64*) (buf + 56) = length;
    MD4_ProcessBlock(state, buf);

    init = false;

    return true;
}

std::string_view MD4::GetName()
{
    return "MD4";
}

const std::string MD4::GetHexValue()
{
    Final();
    LocalString<ResultBytesLength * 2> ls;
    for (auto i = 0U; i < ResultBytesLength; i++)
    {
        ls.AddFormat("%.2X", ((uint8*) (state))[i]);
    }
    return std::string{ ls };
}
} // namespace GView::Hashes
