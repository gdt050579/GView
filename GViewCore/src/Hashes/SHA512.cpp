#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 SHA512_BLOCKSIZE = 128;
constexpr uint64 IV_A             = 0x6A09E667F3BCC908;
constexpr uint64 IV_B             = 0xBB67AE8584CAA73B;
constexpr uint64 IV_C             = 0x3C6EF372FE94F82B;
constexpr uint64 IV_D             = 0xA54FF53A5F1D36F1;
constexpr uint64 IV_E             = 0x510E527FADE682D1;
constexpr uint64 IV_F             = 0x9B05688C2B3E6C1F;
constexpr uint64 IV_G             = 0x1F83D9ABFB41BD6B;
constexpr uint64 IV_H             = 0x5BE0CD19137E2179;

static const uint64 K[80] = { 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
                              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
                              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
                              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
                              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
                              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
                              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

#define ROR64(x, y)                                                                                                                        \
    (((((x) & (0xFFFFFFFFFFFFFFFF)) >> ((uint64) (y) & (63))) | ((x) << (((uint64) 64 - ((y) &63)) & 63))) & (0xFFFFFFFFFFFFFFFF))

#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) (((x | y) & z) | (x & y))
#define S(x, n)      ROR64(x, n)
#define R(x, n)      (((x) & (0xFFFFFFFFFFFFFFFF)) >> ((uint64) n))
#define Sigma0(x)    (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)    (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)    (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)    (S(x, 19) ^ S(x, 61) ^ R(x, 6))

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

#define LOAD64H(x, y)                                                                                                                      \
    do                                                                                                                                     \
    {                                                                                                                                      \
        x = (((uint64) ((y)[0] & 0xFF)) << 0x38) | (((uint64) ((y)[1] & 0xFF)) << 0x30) | (((uint64) ((y)[2] & 0xFF)) << 0x28) |           \
            (((uint64) ((y)[3] & 0xFF)) << 0x20) | (((uint64) ((y)[4] & 0xFF)) << 0x18) | (((uint64) ((y)[5] & 0xFF)) << 0x10) |           \
            (((uint64) ((y)[6] & 0xFF)) << 0x08) | (((uint64) ((y)[7] & 0xFF)) << 0x00);                                                   \
    } while (0)

bool SHA512::Init()
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

static bool SHA512_ProcessBlock(uint64* state, const unsigned char* buf)
{
    CHECK(buf != nullptr, false, "");
    CHECK(state != nullptr, false, "");

    uint64 S[8];
    uint64 W[80];
    uint64 t0;
    uint64 t1;

    for (auto i = 0; i < 8; i++)
    {
        S[i] = state[i];
    }

    for (auto i = 0; i < 16; i++)
    {
        LOAD64H(W[i], buf + (8 * i));
    }

    for (auto i = 16; i < 80; i++)
    {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

#define RND(a, b, c, d, e, f, g, h, i)                                                                                                     \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];                                                                                        \
    t1 = Sigma0(a) + Maj(a, b, c);                                                                                                         \
    d += t0;                                                                                                                               \
    h = t0 + t1;

    for (auto i = 0; i < 80; i += 8)
    {
        RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i + 0);
        RND(S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1);
        RND(S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2);
        RND(S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3);
        RND(S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4);
        RND(S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5);
        RND(S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6);
        RND(S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7);
    }
#undef RND

    for (auto i = 0; i < 8; i++)
    {
        state[i] += S[i];
    }

    return true;
}

bool SHA512::Update(const unsigned char* in, uint32 inlen)
{
    CHECK(init, false, "");
    CHECK(in != nullptr, false, "");

    CHECK(curlen <= sizeof(buf), false, "");
    CHECK((length + inlen * 8ULL) >= length, false, "");

    while (inlen > 0)
    {
        if (curlen == 0 && inlen >= SHA512_BLOCKSIZE)
        {
            CHECK(SHA512_ProcessBlock(state, in), false, "");

            length += SHA512_BLOCKSIZE * 8ULL;
            in += SHA512_BLOCKSIZE;
            inlen -= SHA512_BLOCKSIZE;
        }
        else
        {
            const uint32 n = std::min<>(inlen, (SHA512_BLOCKSIZE - curlen));
            memcpy(buf + curlen, in, n);
            curlen += n;
            in += n;
            inlen -= n;
            if (curlen == SHA512_BLOCKSIZE)
            {
                CHECK(SHA512_ProcessBlock(state, buf), false, "");
                this->length += 8ULL * SHA512_BLOCKSIZE;
                this->curlen = 0;
            }
        }
    }

    return true;
}

bool SHA512::Update(Buffer buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool SHA512::Final(uint8 hash[64])
{
    CHECK(init, false, "");
    CHECK(curlen < SHA512_BLOCKSIZE, false, "");

    length += curlen * 8ULL;
    buf[curlen++] = 0x80;

    if (curlen > 112)
    {
        while (curlen < SHA512_BLOCKSIZE)
        {
            buf[curlen++] = 0;
        }
        SHA512_ProcessBlock(state, buf);
        curlen = 0;
    }

    while (curlen < 120)
    {
        buf[curlen++] = 0;
    }

    STORE64H(length, buf + 120);
    SHA512_ProcessBlock(state, buf);

    for (auto i = 0; i < 8; i++)
    {
        STORE64H(state[i], hash + (8 * i));
    }

    return true;
}
} // namespace GView::Hashes
