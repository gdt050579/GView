#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 SHA256_BLOCKSIZE = 64;
constexpr uint32 IV_A             = 0x6A09E667;
constexpr uint32 IV_B             = 0xBB67AE85;
constexpr uint32 IV_C             = 0x3C6EF372;
constexpr uint32 IV_D             = 0xA54FF53A;
constexpr uint32 IV_E             = 0x510E527F;
constexpr uint32 IV_F             = 0x9B05688C;
constexpr uint32 IV_G             = 0x1F83D9AB;
constexpr uint32 IV_H             = 0x5BE0CD19;

#define SHR(a, n)  (((a) &0xFFFFFFFF) >> (n))
#define ROTR(a, n) (SHR(a, n) | ((a) << (0x20 - (n))))

#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n)      ROTR((x), (n))
#define R(x, n)      (((x) &0xFFFFFFFFUL) >> (n))
#define Sigma0(x)    (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)    (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)    (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)    (S(x, 17) ^ S(x, 19) ^ R(x, 10))

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

bool SHA256::Init()
{
    state[0] = IV_A;
    state[1] = IV_B;
    state[2] = IV_C;
    state[3] = IV_D;
    state[4] = IV_E;
    state[5] = IV_F;
    state[6] = IV_G;
    state[7] = IV_H;
    curlen   = 0;
    length   = 0;
    init     = true;

    return true;
}

static bool SHA256_ProcessBlock(uint32* state, const unsigned char* buf)
{
    CHECK(buf != nullptr, false, "");
    CHECK(state != nullptr, false, "");

    uint32 S[8];
    uint32 W[64];
    uint32 t0;
    uint32 t1;

    for (auto i = 0; i < 8; i++)
    {
        S[i] = state[i];
    }

    for (auto i = 0; i < 16; i++)
    {
        LOAD32H(W[i], buf + (4 * i));
    }

    for (auto i = 16; i < 64; i++)
    {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

#define RND(a, b, c, d, e, f, g, h, i, ki)                                                                                                 \
    t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];                                                                                          \
    t1 = Sigma0(a) + Maj(a, b, c);                                                                                                         \
    d += t0;                                                                                                                               \
    h = t0 + t1;

    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 0, 0x428a2f98);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 1, 0x71374491);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 2, 0xb5c0fbcf);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 3, 0xe9b5dba5);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 4, 0x3956c25b);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 5, 0x59f111f1);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 6, 0x923f82a4);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 7, 0xab1c5ed5);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 8, 0xd807aa98);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 9, 0x12835b01);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 10, 0x243185be);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 11, 0x550c7dc3);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 12, 0x72be5d74);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 13, 0x80deb1fe);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 14, 0x9bdc06a7);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 15, 0xc19bf174);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 16, 0xe49b69c1);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 17, 0xefbe4786);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 18, 0x0fc19dc6);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 19, 0x240ca1cc);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 20, 0x2de92c6f);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 21, 0x4a7484aa);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 22, 0x5cb0a9dc);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 23, 0x76f988da);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 24, 0x983e5152);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 25, 0xa831c66d);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 26, 0xb00327c8);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 27, 0xbf597fc7);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 28, 0xc6e00bf3);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 29, 0xd5a79147);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 30, 0x06ca6351);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 31, 0x14292967);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 32, 0x27b70a85);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 33, 0x2e1b2138);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 34, 0x4d2c6dfc);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 35, 0x53380d13);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 36, 0x650a7354);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 37, 0x766a0abb);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 38, 0x81c2c92e);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 39, 0x92722c85);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 40, 0xa2bfe8a1);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 41, 0xa81a664b);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 42, 0xc24b8b70);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 43, 0xc76c51a3);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 44, 0xd192e819);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 45, 0xd6990624);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 46, 0xf40e3585);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 47, 0x106aa070);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 48, 0x19a4c116);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 49, 0x1e376c08);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 50, 0x2748774c);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 51, 0x34b0bcb5);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 52, 0x391c0cb3);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 53, 0x4ed8aa4a);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 54, 0x5b9cca4f);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 55, 0x682e6ff3);
    RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], 56, 0x748f82ee);
    RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], 57, 0x78a5636f);
    RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], 58, 0x84c87814);
    RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], 59, 0x8cc70208);
    RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], 60, 0x90befffa);
    RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], 61, 0xa4506ceb);
    RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], 62, 0xbef9a3f7);
    RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], 63, 0xc67178f2);
#undef RND

    for (auto i = 0; i < 8; i++)
    {
        state[i] += S[i];
    }

    return true;
}

bool SHA256::Update(const unsigned char* in, uint32 inlen)
{
    CHECK(init, false, "");
    CHECK(in != nullptr, false, "");

    CHECK(curlen <= sizeof(buf), false, "");
    CHECK((length + inlen * 8ULL) >= length, false, "");

    while (inlen > 0)
    {
        if (curlen == 0 && inlen >= SHA256_BLOCKSIZE)
        {
            CHECK(SHA256_ProcessBlock(state, in), false, "");

            length += SHA256_BLOCKSIZE * 8ULL;
            in += SHA256_BLOCKSIZE;
            inlen -= SHA256_BLOCKSIZE;
        }
        else
        {
            const uint32 n = std::min<>(inlen, (SHA256_BLOCKSIZE - curlen));
            memcpy(buf + curlen, in, n);
            curlen += n;
            in += n;
            inlen -= n;
            if (curlen == SHA256_BLOCKSIZE)
            {
                CHECK(SHA256_ProcessBlock(state, buf), false, "");
                this->length += 8ULL * SHA256_BLOCKSIZE;
                this->curlen = 0;
            }
        }
    }

    return true;
}

bool SHA256::Update(const Buffer& buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool SHA256::Final(uint8 hash[32])
{
    CHECK(Final(), false, "");

    for (auto i = 0; i < 8; i++)
    {
        STORE32H(state[i], hash + (4 * i));
    }

    return true;
}

bool SHA256::Final()
{
    CHECK(init, false, "");
    CHECK(curlen < SHA256_BLOCKSIZE, false, "");

    length += curlen * 8ULL;
    buf[curlen++] = 0x80;

    if (curlen > 56)
    {
        while (curlen < SHA256_BLOCKSIZE)
        {
            buf[curlen++] = 0;
        }
        SHA256_ProcessBlock(state, buf);
        curlen = 0;
    }

    while (curlen < 56)
    {
        buf[curlen++] = 0;
    }

    STORE64H(length, buf + 56);
    SHA256_ProcessBlock(state, buf);

    init = false;

    return true;
}

std::string_view SHA256::GetName()
{
    return "SHA256";
}

const std::string SHA256::GetHexValue()
{
    Final();

    uint8 hash[ResultBytesLength]{ 0 };
    for (auto i = 0; i < 8; i++)
    {
        STORE32H(state[i], hash + (4 * i));
    }

    LocalString<ResultBytesLength * 2> ls;
    for (auto i = 0U; i < ResultBytesLength; i++)
    {
        ls.AddFormat("%.2X", hash[i]);
    }
    return std::string{ ls };
}
} // namespace GView::Hashes
