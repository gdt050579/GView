#pragma once

#include "IDrop.hpp"

namespace GView::GenericPlugins::Droppper::Cryptographic
{
enum class Types {
    CRC16Table,
    CRC16Table8bit1,
    CRC16Table8bit2,
    CRC32Table,
    CRC64Table,
    MD5InitValues,
    SHA1InitValues,
    ZinflateLengthStarts,
    ZinflateLengthExtraBits,
    ZinflateDistanceStarts,
    ZinflateDistanceExtraBits,
    ZdeflateLengthCodes,
    BlowfishPInit,
    BlowfishSInit,
    RijndaelTe0,
    RijndaelTe1,
    RijndaelTe2,
    RijndaelTe3,
    RijndaelTe4,
    RijndaelTd0,
    RijndaelTd1,
    RijndaelTd2,
    RijndaelTd3,
    RijndaelTd4,
    RC2PITABLE,
    PKCSDigestDecorationMD2,
    PKCSDigestDecorationMD5,
    PKCSDigestDecorationRIPEMD160,
    PKCSDigestDecorationTiger,
    PKCSDigestDecorationSHA256,
    PKCSDigestDecorationSHA384,
    PKCSDigestDecorationSHA512,
    RC6Stub,
};

static const std::string_view DEFAULT_CRC_DESCRIPTION{ "A cyclic redundancy check (CRC) is an error-detecting code commonly used in digital networks and "
                                                       "storage devices to detect accidental changes to digital data." };
static const std::string_view MISSING_DESCRIPTION{ "Missing description." };

static const std::map<Types, Metadata> TYPES_MAP{
    { Types::CRC16Table, { "CRC 16 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Types::CRC16Table8bit1, { "CRC 16 Table (8 bit - 1)", DEFAULT_CRC_DESCRIPTION, false } },
    { Types::CRC16Table8bit2, { "CRC 16 Table (8 bit - 2)", DEFAULT_CRC_DESCRIPTION, false } },
    { Types::CRC32Table, { "CRC 32 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Types::CRC64Table, { "CRC 64 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Types::MD5InitValues, { "MD5 Init Values", MISSING_DESCRIPTION, false } },
    { Types::SHA1InitValues, { "SHA1 Init Values", MISSING_DESCRIPTION, false } },
    { Types::ZinflateLengthStarts, { "Zinflate LengthStarts", MISSING_DESCRIPTION, false } },
    { Types::ZinflateLengthExtraBits, { "Zinflate LengthExtraBits", MISSING_DESCRIPTION, false } },
    { Types::ZinflateDistanceStarts, { "Zinflate DistanceStarts", MISSING_DESCRIPTION, false } },
    { Types::ZinflateDistanceExtraBits, { "Zinflate DistanceExtraBits", MISSING_DESCRIPTION, false } },
    { Types::ZdeflateLengthCodes, { "Zdeflate LengthCodes", MISSING_DESCRIPTION, false } },
    { Types::BlowfishPInit, { "Blowfish P-Init", MISSING_DESCRIPTION, false } },
    { Types::BlowfishSInit, { "Blowfish S-Init", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTe0, { "Rijndael Te0", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTe1, { "Rijndael Te1", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTe2, { "Rijndael Te2", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTe3, { "Rijndael Te3", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTe4, { "Rijndael Te4", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTd0, { "Rijndael Td0", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTd1, { "Rijndael Td1", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTd2, { "Rijndael Td2", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTd3, { "Rijndael Td3", MISSING_DESCRIPTION, false } },
    { Types::RijndaelTd4, { "Rijndael Td4", MISSING_DESCRIPTION, false } },
    { Types::RC2PITABLE, { "RC2 PITABLE", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationMD2, { "PKCS DigestDecoration MD2", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationMD5, { "PKCS DigestDecoration MD5", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationRIPEMD160, { "PKCS DigestDecoration RIPEMD160", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationTiger, { "PKCS DigestDecoration Tiger", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationSHA256, { "PKCS DigestDecoration SHA256", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationSHA384, { "PKCS DigestDecoration SHA384", MISSING_DESCRIPTION, false } },
    { Types::PKCSDigestDecorationSHA512, { "PKCS DigestDecoration SHA512", MISSING_DESCRIPTION, false } },
    { Types::RC6Stub, { "RC6 Stub", MISSING_DESCRIPTION, false } },
};
} // namespace GView::GenericPlugins::Droppper::Cryptographic
