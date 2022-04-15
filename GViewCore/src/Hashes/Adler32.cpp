#include "Internal.hpp"

namespace GView::Hashes
{
constexpr uint32 ADLER32_BASE         = 65521;
constexpr uint32 ADLER32_MODULO_VALUE = 8;

bool Adler32::Init()
{
    a = 1;
    b = 0;

    init = true;

    return true;
}

bool Adler32::Update(const unsigned char* input, uint32 length)
{
    CHECK(input != nullptr, false, "");

    uint32 s1 = a;
    uint32 s2 = b;

    if (length % ADLER32_MODULO_VALUE != 0)
    {
        do
        {
            s1 += *input++;
            s2 += s1;
            length--;
        } while (length % ADLER32_MODULO_VALUE != 0);

        if (s1 >= ADLER32_BASE)
        {
            s1 -= ADLER32_BASE;
        }
        s2 %= ADLER32_BASE;
    }

    while (length > 0)
    {
        s1 += input[0];
        s2 += s1;
        s1 += input[1];
        s2 += s1;
        s1 += input[2];
        s2 += s1;
        s1 += input[3];
        s2 += s1;
        s1 += input[4];
        s2 += s1;
        s1 += input[5];
        s2 += s1;
        s1 += input[6];
        s2 += s1;
        s1 += input[7];
        s2 += s1;

        length -= ADLER32_MODULO_VALUE;
        input += ADLER32_MODULO_VALUE;

        if (s1 >= ADLER32_BASE)
        {
            s1 -= ADLER32_BASE;
        }
        s2 %= ADLER32_BASE;
    }

    CHECK(s1 < ADLER32_BASE, false, "");
    CHECK(s2 < ADLER32_BASE, false, "");

    a = static_cast<uint16>(s1);
    b = static_cast<uint16>(s2);

    return true;
}

bool Adler32::Update(const Buffer& buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool Adler32::Update(const BufferView& buffer)
{
    CHECK(buffer.IsValid(), false, "");
    return Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength()));
}

bool Adler32::Final(uint32& hash)
{
    CHECK(init, false, "");

    hash = (int32) ((((uint32) b) << 16) + (uint32) a);

    return true;
}

std::string_view Adler32::GetName()
{
    return "Adler32";
}

const std::string_view Adler32::GetHexValue()
{
    hexDigest.Format("%.8X", static_cast<uint32>((static_cast<uint32>(b) << 16) + (static_cast<uint32>(a))));
    return hexDigest;
}
} // namespace GView::Hashes
