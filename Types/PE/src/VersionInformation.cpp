#include "pe.hpp"

using namespace GView::Type::PE;

static uint16 ReadU16(const uint8* p)
{
    uint16 value;
    memcpy(&value, p, sizeof(value));
    return value;
}
static uint32 ReadU32(const uint8* p)
{
    uint32 value;
    memcpy(&value, p, sizeof(value));
    return value;
}

bool StartWith(const uint16_t* Buffer, int size, const char* text)
{
    int tr;
    for (tr = 0; (tr < size) && (text[tr] != 0); tr++)
    {
        if (Buffer[tr] != (uint16_t) text[tr])
            return false;
    }
    if (text[tr] != 0)
        return false;
    return true;
}
//===========================================================================
VersionInformation::VersionInformation(void)
{
    nrPairs = 0;
}
VersionInformation::~VersionInformation(void)
{
}
bool VersionInformation::TestIfValidKey(const uint8* Buffer, int size, int poz)
{
    auto* w = (const uint16_t*) &Buffer[poz];
    int szW = (size - poz) / 2 - 1;

    if (StartWith(w, szW, "Comments"))
        return true;
    if (StartWith(w, szW, "CompanyName"))
        return true;
    if (StartWith(w, szW, "FileDescription"))
        return true;
    if (StartWith(w, szW, "FileVersion"))
        return true;
    if (StartWith(w, szW, "InternalName"))
        return true;
    if (StartWith(w, szW, "LegalCopyright"))
        return true;
    if (StartWith(w, szW, "LegalTrademarks"))
        return true;
    if (StartWith(w, szW, "OriginalFilename"))
        return true;
    if (StartWith(w, szW, "PrivateBuild"))
        return true;
    if (StartWith(w, szW, "ProductName"))
        return true;
    if (StartWith(w, szW, "ProductVersion"))
        return true;
    if (StartWith(w, szW, "SpecialBuild"))
        return true;

    return false;
}
int VersionInformation::AddPair(const uint8* Buffer, int size, int poz)
{
    String *Key, *Value;
    const uint8_t* tmp;
    int tr, u_poz;

    if (poz + sizeof(VersionString) >= (unsigned) size)
        return -1;
    const int wLength = ReadU16(&Buffer[poz] + offsetof(VersionString, wLength));
    if (poz + wLength > size)
        return -1;
    if (nrPairs >= MAX_VERION_PAIRS)
        return -1;

    Key   = &Pairs[nrPairs].Key;
    Value = &Pairs[nrPairs].Value;

    Key->Set("");
    Value->Set("");
    tmp = &Buffer[poz] + offsetof(VersionString, Key);
    // adaug la cheie
    for (tr = 0; (tr < wLength - 1) && (ReadU16(&tmp[tr]) != 0); tr += 2)
        Key->AddChar((char) tmp[tr]);
    // merg pana gasesc ceva diferit de 0
    for (; (tr < wLength - 1) && (ReadU16(&tmp[tr]) == 0); tr += 2)
        ;
    // adaug la cheie
    u_poz = 0;
    for (; (tr < wLength - 1) && (ReadU16(&tmp[tr]) != 0); tr += 2, u_poz++)
    {
        Value->AddChar((char) tmp[tr]);
        if (u_poz < MAX_VERSION_UNICODE - 1)
            Pairs[nrPairs].Unicode[u_poz] = ReadU16(&tmp[tr]);
    }
    // u_poz keeps counting past the buffer capacity, so clamp the terminator to the last slot
    Pairs[nrPairs].Unicode[std::min(u_poz, MAX_VERSION_UNICODE - 1)] = 0;
    nrPairs++;
    return poz + wLength;
}
bool VersionInformation::ComputeVersionInformation(const uint8* Buffer, int size)
{
    int tr, gasit, poz;

    nrPairs = 0;

    //_asm int 3;
    for (tr = 0, gasit = -1; (tr < size - 4) && (gasit == -1); tr++)
        if (ReadU32(&Buffer[tr]) == VERSION_VSFIX_SIG)
            gasit = tr;

    if (gasit == -1)
        return false;
    gasit += sizeof(VS_FIXEDFILEINFO);
    // gasit+=(sizeof(VersionString));

    poz = gasit;
    // caut un word 1
    while (poz < size)
    {
        for (tr = poz, gasit = -1; (tr + 3 < size) && (gasit == -1); tr++)
            if (ReadU16(&Buffer[tr]) == 1)
            {
                if (TestIfValidKey(Buffer, size, tr + 2))
                    gasit = tr;
            }

        if (gasit > 5)
        {
            poz   = gasit;
            gasit = AddPair(Buffer, size, gasit - 4);
            if (gasit > 0)
                poz = gasit;
            else
                poz++;
        }
        else
        {
            poz = size;
        }
    }

    return true;
}