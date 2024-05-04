#include "SpecialStrings.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
constexpr uint32 MIN_LENGTH = 42;
constexpr uint32 MAX_LENGTH = 69;
constexpr std::string_view Bitcoin_P2WPKH_MAGIC{ "bc1q" };
constexpr std::string_view Bitcoin_P2WSH_MAGIC{ "bc1q" };
constexpr std::string_view Bitcoin_P2TR_MAGIC{ "bc1p" };
constexpr std::string_view Ethereum_MAGIC{ "0x" };
constexpr std::string_view Stellar_MEMO_MAGIC{ "G" };
constexpr std::string_view Stellar_MUXED_MAGIC{ "M" };

static std::map<WalletType, uint32> WALLET_ADDRESS_LENGTH{
    { WalletType::Bitcoin_P2WPKH, 42 }, { WalletType::Bitcoin_P2WSH, 62 }, { WalletType::Bitcoin_P2TR, 62 },
    { WalletType::Ethereum, 42 },       { WalletType::Stellar_MEMO, 56 },  { WalletType::Stellar_MUXED, 69 },
};

static std::map<WalletType, std::string_view> WALLET_PREFIX{
    { WalletType::Bitcoin_P2WPKH, Bitcoin_P2WPKH_MAGIC }, { WalletType::Bitcoin_P2WSH, Bitcoin_P2WSH_MAGIC },
    { WalletType::Bitcoin_P2TR, Bitcoin_P2TR_MAGIC },     { WalletType::Ethereum, Ethereum_MAGIC },
    { WalletType::Stellar_MEMO, Stellar_MEMO_MAGIC },     { WalletType::Stellar_MUXED, Stellar_MUXED_MAGIC },
};

Wallet::Wallet(bool caseSensitive, bool unicode)
{
    this->unicode       = unicode;
    this->caseSensitive = caseSensitive;
}

const std::string_view Wallet::GetName() const
{
    return "Wallet";
}

const std::string_view Wallet::GetOutputExtension() const
{
    return "wallet";
}

Subcategory Wallet::GetSubcategory() const
{
    return Subcategory::Wallet;
}

bool Wallet::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding)
{
    CHECK(precachedBuffer.GetLength() > 0, false, "");
    CHECK(IsAsciiPrintable(precachedBuffer.GetData()[0]), false, "");

    const auto isUnicode = precachedBuffer.GetData()[1] == 0;
    if (isUnicode) {
        CHECK(unicode, false, "");
    }

    uint8 magic[4] = { precachedBuffer[0], precachedBuffer[1], precachedBuffer[2], precachedBuffer[3] };
    std::string_view sMagic{ reinterpret_cast<char*>(magic), sizeof(magic) };

    if (isUnicode) {
        magic[0] = precachedBuffer[0];
        magic[1] = precachedBuffer[2];
        magic[2] = precachedBuffer[4];
        magic[3] = precachedBuffer[6];
    }

    const bool hasWalletPrefix = sMagic == Bitcoin_P2WPKH_MAGIC || sMagic == Bitcoin_P2WSH_MAGIC || sMagic == Bitcoin_P2TR_MAGIC || sMagic == Ethereum_MAGIC ||
                                 sMagic == Stellar_MEMO_MAGIC || sMagic == Stellar_MUXED_MAGIC;
    CHECK(hasWalletPrefix, false, "");

    auto buffer = file.Get(offset, MAX_LENGTH * (isUnicode ? 2 : 1), false);
    CHECK(buffer.GetLength() >= MIN_LENGTH * (isUnicode ? 2 : 1), false, "");

    finding.start = offset;
    finding.end   = offset;

    for (uint64 i = 0; i < buffer.GetLength(); i++) {
        const auto c = buffer.GetData()[i];
        CHECKBK(std::isalnum(c), "");

        if (isUnicode && unicode) {
            CHECKBK(buffer.GetData()[i + 1] == 0, "");
            finding.end++;
            i++;
        }

        finding.end++;
    }

    CHECK(finding.start < finding.end, false, "");

    const auto length = finding.end - finding.start;
    CHECK(unicode ? length >= MIN_LENGTH * 2 : length >= MIN_LENGTH, false, "");

    for (const auto& [k, v] : WALLET_PREFIX) {
        if (sMagic == v && length == WALLET_ADDRESS_LENGTH.at(k)) {
            this->checkResult = k;
            finding.result    = isUnicode ? Result::Unicode : Result::Ascii;
            finding.details   = static_cast<uint32>(k);
            return true;
        }
    }

    return true;
}

WalletType Wallet::GetLastCheckResult() const
{
    return this->checkResult;
}
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
