#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 MD5_BLOCKSIZE = 64;
constexpr uint32 IV_A          = 0x67452301;
constexpr uint32 IV_B          = 0xEFCDAB89;
constexpr uint32 IV_C          = 0x98BADCFE;
constexpr uint32 IV_D          = 0x10325476;

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) (y ^ (z & (y ^ x)))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | (~z)))

#define ROTL(a, n) ((a) << (n) | (a) >> (32 - (n)))

#define FF(a, b, c, d, M, s, t)                                                                                                            \
    a = (a + F(b, c, d) + M + t);                                                                                                          \
    a = ROTL(a, s) + b;

#define GG(a, b, c, d, M, s, t)                                                                                                            \
    a = (a + G(b, c, d) + M + t);                                                                                                          \
    a = ROTL(a, s) + b;

#define HH(a, b, c, d, M, s, t)                                                                                                            \
    a = (a + H(b, c, d) + M + t);                                                                                                          \
    a = ROTL(a, s) + b;

#define II(a, b, c, d, M, s, t)                                                                                                            \
    a = (a + I(b, c, d) + M + t);                                                                                                          \
    a = ROTL(a, s) + b;

bool MD5::Init()
{
    state[0] = IV_A;
    state[1] = IV_B;
    state[2] = IV_C;
    state[3] = IV_D;
    curlen   = 0;
    length   = 0;
    init     = true;

    return true;
}

static bool MD5_ProcessBlock(uint32* state, const unsigned char* buf)
{
    CHECK(buf != nullptr, false, "");
    CHECK(state != nullptr, false, "");

    uint32 W[MD5_BLOCKSIZE / 4];
    memcpy(W, buf, MD5_BLOCKSIZE);

    uint32 a = state[0];
    uint32 b = state[1];
    uint32 c = state[2];
    uint32 d = state[3];

    FF(a, b, c, d, W[0], 7, 0xd76aa478UL)
    FF(d, a, b, c, W[1], 12, 0xe8c7b756UL)
    FF(c, d, a, b, W[2], 17, 0x242070dbUL)
    FF(b, c, d, a, W[3], 22, 0xc1bdceeeUL)
    FF(a, b, c, d, W[4], 7, 0xf57c0fafUL)
    FF(d, a, b, c, W[5], 12, 0x4787c62aUL)
    FF(c, d, a, b, W[6], 17, 0xa8304613UL)
    FF(b, c, d, a, W[7], 22, 0xfd469501UL)
    FF(a, b, c, d, W[8], 7, 0x698098d8UL)
    FF(d, a, b, c, W[9], 12, 0x8b44f7afUL)
    FF(c, d, a, b, W[10], 17, 0xffff5bb1UL)
    FF(b, c, d, a, W[11], 22, 0x895cd7beUL)
    FF(a, b, c, d, W[12], 7, 0x6b901122UL)
    FF(d, a, b, c, W[13], 12, 0xfd987193UL)
    FF(c, d, a, b, W[14], 17, 0xa679438eUL)
    FF(b, c, d, a, W[15], 22, 0x49b40821UL)

    GG(a, b, c, d, W[1], 5, 0xf61e2562UL)
    GG(d, a, b, c, W[6], 9, 0xc040b340UL)
    GG(c, d, a, b, W[11], 14, 0x265e5a51UL)
    GG(b, c, d, a, W[0], 20, 0xe9b6c7aaUL)
    GG(a, b, c, d, W[5], 5, 0xd62f105dUL)
    GG(d, a, b, c, W[10], 9, 0x02441453UL)
    GG(c, d, a, b, W[15], 14, 0xd8a1e681UL)
    GG(b, c, d, a, W[4], 20, 0xe7d3fbc8UL)
    GG(a, b, c, d, W[9], 5, 0x21e1cde6UL)
    GG(d, a, b, c, W[14], 9, 0xc33707d6UL)
    GG(c, d, a, b, W[3], 14, 0xf4d50d87UL)
    GG(b, c, d, a, W[8], 20, 0x455a14edUL)
    GG(a, b, c, d, W[13], 5, 0xa9e3e905UL)
    GG(d, a, b, c, W[2], 9, 0xfcefa3f8UL)
    GG(c, d, a, b, W[7], 14, 0x676f02d9UL)
    GG(b, c, d, a, W[12], 20, 0x8d2a4c8aUL)

    HH(a, b, c, d, W[5], 4, 0xfffa3942UL)
    HH(d, a, b, c, W[8], 11, 0x8771f681UL)
    HH(c, d, a, b, W[11], 16, 0x6d9d6122UL)
    HH(b, c, d, a, W[14], 23, 0xfde5380cUL)
    HH(a, b, c, d, W[1], 4, 0xa4beea44UL)
    HH(d, a, b, c, W[4], 11, 0x4bdecfa9UL)
    HH(c, d, a, b, W[7], 16, 0xf6bb4b60UL)
    HH(b, c, d, a, W[10], 23, 0xbebfbc70UL)
    HH(a, b, c, d, W[13], 4, 0x289b7ec6UL)
    HH(d, a, b, c, W[0], 11, 0xeaa127faUL)
    HH(c, d, a, b, W[3], 16, 0xd4ef3085UL)
    HH(b, c, d, a, W[6], 23, 0x04881d05UL)
    HH(a, b, c, d, W[9], 4, 0xd9d4d039UL)
    HH(d, a, b, c, W[12], 11, 0xe6db99e5UL)
    HH(c, d, a, b, W[15], 16, 0x1fa27cf8UL)
    HH(b, c, d, a, W[2], 23, 0xc4ac5665UL)

    II(a, b, c, d, W[0], 6, 0xf4292244UL)
    II(d, a, b, c, W[7], 10, 0x432aff97UL)
    II(c, d, a, b, W[14], 15, 0xab9423a7UL)
    II(b, c, d, a, W[5], 21, 0xfc93a039UL)
    II(a, b, c, d, W[12], 6, 0x655b59c3UL)
    II(d, a, b, c, W[3], 10, 0x8f0ccc92UL)
    II(c, d, a, b, W[10], 15, 0xffeff47dUL)
    II(b, c, d, a, W[1], 21, 0x85845dd1UL)
    II(a, b, c, d, W[8], 6, 0x6fa87e4fUL)
    II(d, a, b, c, W[15], 10, 0xfe2ce6e0UL)
    II(c, d, a, b, W[6], 15, 0xa3014314UL)
    II(b, c, d, a, W[13], 21, 0x4e0811a1UL)
    II(a, b, c, d, W[4], 6, 0xf7537e82UL)
    II(d, a, b, c, W[11], 10, 0xbd3af235UL)
    II(c, d, a, b, W[2], 15, 0x2ad7d2bbUL)
    II(b, c, d, a, W[9], 21, 0xeb86d391UL)

    state[0] = state[0] + a;
    state[1] = state[1] + b;
    state[2] = state[2] + c;
    state[3] = state[3] + d;

    return true;
}

bool MD5::Update(const unsigned char* in, uint32 inlen)
{
    CHECK(init, false, "");
    CHECK(in != nullptr, false, "");

    CHECK(curlen <= sizeof(buf), false, "");
    CHECK((length + inlen * 8ULL) >= length, false, "");

    while (inlen > 0)
    {
        if (curlen == 0 && inlen >= MD5_BLOCKSIZE)
        {
            CHECK(MD5_ProcessBlock(state, in), false, "");

            length += MD5_BLOCKSIZE * 8ULL;
            in += MD5_BLOCKSIZE;
            inlen -= MD5_BLOCKSIZE;
        }
        else
        {
            const uint32 n = std::min<>(inlen, (MD5_BLOCKSIZE - curlen));
            memcpy(buf + curlen, in, n);
            curlen += n;
            in += n;
            inlen -= n;
            if (curlen == MD5_BLOCKSIZE)
            {
                CHECK(MD5_ProcessBlock(state, buf), false, "");
                this->length += 8ULL * MD5_BLOCKSIZE;
                this->curlen = 0;
            }
        }
    }

    return true;
}

bool MD5::Update(const Buffer& buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool MD5::Final(uint8 hash[16])
{
    CHECK(Final(), false, "");
    memcpy(hash, state, 16);

    return true;
}

bool MD5::Final()
{
    CHECK(init, false, "");
    CHECK(curlen <= sizeof(buf), false, "");

    length += curlen * 8ULL;

    buf[curlen++] = 0x80;

    if (curlen > 56)
    {
        while (curlen < MD5_BLOCKSIZE)
        {
            buf[curlen++] = 0;
        }
        MD5_ProcessBlock(state, buf);
        curlen = 0;
    }

    while (curlen < 56)
    {
        buf[curlen++] = 0;
    }

    *(uint64*) (buf + 56) = length;
    MD5_ProcessBlock(state, buf);

    init = false;

    return true;
}

const std::string MD5::GetHexValue()
{
    Final();
    LocalString<ResultBytesLength * 2> ls;
    for (auto i = 0U; i < ResultBytesLength; i++)
    {
        ls.AddFormat("%.2X", ((uint8*) (state))[i]);
    }
    return std::string{ ls };
}

std::string_view MD5::GetName()
{
    return "MD5";
}
} // namespace GView::Hashes
