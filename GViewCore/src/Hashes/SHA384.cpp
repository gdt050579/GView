#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint64 IV_A = 0xCBBB9D5DC1059ED8;
constexpr uint64 IV_B = 0x629A292A367CD507;
constexpr uint64 IV_C = 0x9159015A3070DD17;
constexpr uint64 IV_D = 0x152FECD8F70E5939;
constexpr uint64 IV_E = 0x67332667FFC00B31;
constexpr uint64 IV_F = 0x8EB44A8768581511;
constexpr uint64 IV_G = 0xDB0C2E0D64F98FA7;
constexpr uint64 IV_H = 0x47B5481DBEFA4FA4;

bool SHA384::Init()
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

bool SHA384::Final(uint8 hash[48])
{
    uint8 hash256[64];
    CHECK(SHA512::Final(hash256), false, "");

    memcpy(hash, hash256, 48);

    return true;
}
} // namespace GView::Hashes
