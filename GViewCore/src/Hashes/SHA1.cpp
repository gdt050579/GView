#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 SHA1_BLOCKSIZE = 64;
constexpr uint32 IV_A           = 0x67452301;
constexpr uint32 IV_B           = 0xEFCDAB89;
constexpr uint32 IV_C           = 0x98BADCFE;
constexpr uint32 IV_D           = 0x10325476;
constexpr uint32 IV_E           = 0xC3D2E1F0;
constexpr uint32 K_0            = 0x5A827999;
constexpr uint32 K_1            = 0x6ED9EBA1;
constexpr uint32 K_2            = 0x8F1BBCDC;
constexpr uint32 K_3            = 0xCA62C1D6;

#define ROTL(a, n) ((a) << (n) | (a) >> (0x20 - (n)))

#define F0(x, y, z) (z ^ (x & (y ^ z)))
#define F1(x, y, z) (x ^ y ^ z)
#define F2(x, y, z) ((x & y) | (z & (x | y)))
#define F3(x, y, z) (x ^ y ^ z)

#define FF0(a, b, c, d, e, i)                                                                                                              \
    e = (ROTL(a, 5) + F0(b, c, d) + e + W[i] + K_0);                                                                                       \
    b = ROTL(b, 30);
#define FF1(a, b, c, d, e, i)                                                                                                              \
    e = (ROTL(a, 5) + F1(b, c, d) + e + W[i] + K_1);                                                                                       \
    b = ROTL(b, 30);
#define FF2(a, b, c, d, e, i)                                                                                                              \
    e = (ROTL(a, 5) + F2(b, c, d) + e + W[i] + K_2);                                                                                       \
    b = ROTL(b, 30);
#define FF3(a, b, c, d, e, i)                                                                                                              \
    e = (ROTL(a, 5) + F3(b, c, d) + e + W[i] + K_3);                                                                                       \
    b = ROTL(b, 30);

#define STORE64H(x, y)                                                                                                                     \
    do                                                                                                                                     \
    {                                                                                                                                      \
        (y)[0] = (uint8) (((x) >> 0x38) & 0xFF);                                                                                           \
        (y)[1] = (uint8) (((x) >> 0x30) & 0xFF);                                                                                           \
        (y)[2] = (uint8) (((x) >> 0x28) & 0xFF);                                                                                           \
        (y)[3] = (uint8) (((x) >> 0x20) & 0xFF);                                                                                           \
        (y)[4] = (uint8) (((x) >> 0x18) & 0xFF);                                                                                           \
        (y)[5] = (uint8) (((x) >> 0x10) & 0xFF);                                                                                           \
        (y)[6] = (uint8) (((x) >> 0x08) & 0xFF);                                                                                           \
        (y)[7] = (uint8) (((x) >> 0x00) & 0xFF);                                                                                           \
    } while (0)

#define STORE32H(x, y)                                                                                                                     \
    do                                                                                                                                     \
    {                                                                                                                                      \
        (y)[0] = (uint8) (((x) >> 0x18) & 0xFF);                                                                                           \
        (y)[1] = (uint8) (((x) >> 0x10) & 0xFF);                                                                                           \
        (y)[2] = (uint8) (((x) >> 0x08) & 0xFF);                                                                                           \
        (y)[3] = (uint8) (((x) >> 0x00) & 0xFF);                                                                                           \
    } while (0)

#define LOAD32H(x, y)                                                                                                                      \
    do                                                                                                                                     \
    {                                                                                                                                      \
        x = ((uint32) ((y)[0] & 0xFF) << 0x18) | ((uint32) ((y)[1] & 0xFF) << 0x10) | ((uint32) ((y)[2] & 0xFF) << 0x08) |                 \
            ((uint32) ((y)[3] & 0xFF) << 0x00);                                                                                            \
    } while (0)

bool SHA1::Init()
{
    state[0] = IV_A;
    state[1] = IV_B;
    state[2] = IV_C;
    state[3] = IV_D;
    state[4] = IV_E;
    curlen   = 0;
    length   = 0;
    init     = true;

    return true;
}

static bool SHA1_ProcessBlock(uint32* state, const unsigned char* buf)
{
    CHECK(buf != nullptr, false, "");
    CHECK(state != nullptr, false, "");

    uint32 W[80];
    for (auto i = 0; i < 16; i++)
    {
        LOAD32H(W[i], buf + (4 * i));
    }

    uint32 a = state[0];
    uint32 b = state[1];
    uint32 c = state[2];
    uint32 d = state[3];
    uint32 e = state[4];

    for (auto i = 16; i < 80; i++)
    {
        W[i] = ROTL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    auto i = 0U;
    for (; i < 20;)
    {
        FF0(a, b, c, d, e, i++);
        FF0(e, a, b, c, d, i++);
        FF0(d, e, a, b, c, i++);
        FF0(c, d, e, a, b, i++);
        FF0(b, c, d, e, a, i++);
    }

    for (; i < 40;)
    {
        FF1(a, b, c, d, e, i++);
        FF1(e, a, b, c, d, i++);
        FF1(d, e, a, b, c, i++);
        FF1(c, d, e, a, b, i++);
        FF1(b, c, d, e, a, i++);
    }

    for (; i < 60;)
    {
        FF2(a, b, c, d, e, i++);
        FF2(e, a, b, c, d, i++);
        FF2(d, e, a, b, c, i++);
        FF2(c, d, e, a, b, i++);
        FF2(b, c, d, e, a, i++);
    }

    for (; i < 80;)
    {
        FF3(a, b, c, d, e, i++);
        FF3(e, a, b, c, d, i++);
        FF3(d, e, a, b, c, i++);
        FF3(c, d, e, a, b, i++);
        FF3(b, c, d, e, a, i++);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    return true;
}

bool SHA1::Update(const unsigned char* in, uint32 inlen)
{
    CHECK(init, false, "");
    CHECK(in != nullptr, false, "");

    CHECK(curlen <= sizeof(buf), false, "");
    CHECK((length + inlen * 8ULL) >= length, false, "");

    while (inlen > 0)
    {
        if (curlen == 0 && inlen >= SHA1_BLOCKSIZE)
        {
            CHECK(SHA1_ProcessBlock(state, in), false, "");

            length += SHA1_BLOCKSIZE * 8ULL;
            in += SHA1_BLOCKSIZE;
            inlen -= SHA1_BLOCKSIZE;
        }
        else
        {
            const uint32 n = std::min<>(inlen, (SHA1_BLOCKSIZE - curlen));
            memcpy(buf + curlen, in, n);
            curlen += n;
            in += n;
            inlen -= n;
            if (curlen == SHA1_BLOCKSIZE)
            {
                CHECK(SHA1_ProcessBlock(state, buf), false, "");
                this->length += 8ULL * SHA1_BLOCKSIZE;
                this->curlen = 0;
            }
        }
    }

    return true;
}

bool SHA1::Update(Buffer buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool SHA1::Final(uint8 hash[20])
{
    CHECK(Final(), false, "");

    for (auto i = 0; i < 5; i++)
    {
        STORE32H(state[i], hash + (4 * i));
    }

    return true;
}

bool SHA1::Final()
{
    CHECK(init, false, "");
    CHECK(curlen < SHA1_BLOCKSIZE, false, "");

    length += curlen * 8ULL;
    buf[curlen++] = 0x80;

    if (curlen > 56)
    {
        while (curlen < SHA1_BLOCKSIZE)
        {
            buf[curlen++] = 0;
        }
        SHA1_ProcessBlock(state, buf);
        curlen = 0;
    }

    while (curlen < 56)
    {
        buf[curlen++] = 0;
    }

    STORE64H(length, buf + 56);
    SHA1_ProcessBlock(state, buf);

    init = false;

    return true;
}

std::string_view SHA1::GetName()
{
    return "SHA1";
}

const std::string SHA1::GetHexValue()
{
    Final();
    LocalString<ResultBytesLength * 2> ls;
    ls.Format("0x");
    for (auto i = 0U; i < ResultBytesLength; i++)
    {
        ls.AddFormat("%.2X", ((uint8*)(state))[i]);
    }
    return std::string{ ls };
}
} // namespace GView::Hashes
