#include "Internal.hpp"

// Tested
#define CRC16_DNP   0x3D65 // DNP, IEC 870, M-BUS, wM-BUS, ...
#define CRC16_CCITT 0x1021 // X.25, V.41, HDLC FCS, Bluetooth, ...

// Other polynoms not tested
#define CRC16_IBM     0x8005 // ModBus, USB, Bisync, CRC-16, CRC-16-ANSI, ...
#define CRC16_T10_DIF 0x8BB7 // SCSI DIF
#define CRC16_DECT    0x0589 // Cordeless Telephones
#define CRC16_ARINC   0xA02B // ACARS Aplications

#define POLYNOM CRC16_XXX // Define the used polynom from one of the aboves

unsigned short crc16(const unsigned char* data_p, unsigned char length)
{
    unsigned char x;
    unsigned short crc = 0xFFFF;

    while (length--)
    {
        x = crc >> 8 ^ *data_p++;
        x ^= x >> 4;
        crc = (crc << 8) ^ ((unsigned short) (x << 12)) ^ ((unsigned short) (x << 5)) ^ ((unsigned short) x);
    }
    return crc;
}

namespace GView::Hashes
{
bool CRC16::Init()
{
    value = 0xFFFF;
    init  = true;

    return true;
}

bool CRC16::Update(const unsigned char* input, uint32 length)
{
    CHECK(input != nullptr, false, "");

    auto crc = value;

    while (length--)
    {
        uint8 x = crc >> 8 ^ *input++;
        x ^= x >> 4;
        crc = (crc << 8) ^ ((uint16) (x << 12)) ^ ((uint16) (x << 5)) ^ ((uint16) x);
    }

    value = crc;

    return true;
}

bool CRC16::Update(Buffer buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool CRC16::Final(uint32& hash)
{
    CHECK(init, false, "");

    hash = value;

    return true;
}
} // namespace GView::Hashes