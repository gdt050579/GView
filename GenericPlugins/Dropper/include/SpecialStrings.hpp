#pragma once

#include "IDrop.hpp"

#include <string>

namespace GView::GenericPlugins::Droppper::SpecialStrings
{
constexpr std::string_view DEFAULT_STRINGS_CHARSET{ "\\x20-\\x7e" };
constexpr int32 STRINGS_CHARSET_MATRIX_SIZE{ 256 };

/*
 * Bitcoin addresses -> https://unchained.com/blog/bitcoin-address-types-compared | https://bitcoin.design/guide/glossary/address/
 *
 *     Type	  First Seen    BTC Supply*	 Use*	    Encoding	Prefix	Characters
 *     P2PK	  Jan 2009	    9% (1.7M)	 Obsolete
 *     P2PKH  Jan 2009	    43% (8.3M)	 Decreasing	Base58	    1	    26 – 34
 *     P2MS	  Jan 2012	    Negligible	 Obsolete
 *     P2SH	  Apr 2012	    24% (4.6M)	 Decreasing	Base58	    3	    34
 *     P2WPKH Aug 2017	    20% (3.8M)	 Increasing	Bech32	    bc1q	42
 *     P2WSH  Aug 2017	    4% (0.8M)	 Increasing	Bech32	    bc1q	62
 *     P2TR	  Nov 2021	    0.1% (0.02M) Increasing	Bech32m	    bc1p	62
 */

// bitcoin + ethereum + stellar

enum class WalletType {
    Bitcoin_P2WPKH = 0, // Native SegWit: bc1q42lja79elem0anu8q8s3h2n687re9jax556pcc
    Bitcoin_P2WSH  = 1, // Pay-to-Witness-Script-Hash: bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak
    Bitcoin_P2TR   = 2, // Taproot: bc1pmzfrwwndsqmk5yh69yjr5lfgfg4ev8c0tsc06e

    Ethereum = 3, // 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed => prefix 0x and are followed by 40 alphanumeric characters (numerals and letters)

    Stellar_MEMO  = 4, // a 56-alphanumeric sequence that starts with 'G'
    Stellar_MUXED = 5, // a 69-alphanumeric sequence that starts with 'M'
};

static const std::map<WalletType, std::string_view> WALLET_TYPE_NAMES{
    { WalletType::Bitcoin_P2WPKH, "Bitcoin P2WPKH" }, { WalletType::Bitcoin_P2WSH, "Bitcoin P2WSH" },
    { WalletType::Bitcoin_P2TR, "Bitcoin P2TR" },     { WalletType::Ethereum, "Ethereum" },
    { WalletType::Stellar_MEMO, "Stellar MEMO" },     { WalletType::Stellar_MUXED, "Stellar MUXED" },
};

class SpecialStrings : public IDrop
{
  protected:
    bool unicode{ false };
    bool caseSensitive{ false };
    GView::Regex::Matcher matcherAscii{};
    GView::Regex::Matcher matcherUnicode{};

  public:
    virtual Category GetCategory() const override;
    virtual Priority GetPriority() const override;
    virtual bool ShouldGroupInOneFile() const override;
};

class IpAddress : public SpecialStrings
{
  public:
    IpAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class EmailAddress : public SpecialStrings
{
  public:
    EmailAddress(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class Filepath : public SpecialStrings
{
  public:
    Filepath(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class URL : public SpecialStrings
{
  public:
    URL(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};
class Wallet : public SpecialStrings
{
  public:
    WalletType checkResult{};

  public:
    Wallet(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;

    WalletType GetLastCheckResult() const;
};
class Registry : public SpecialStrings
{
  public:
    Registry(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;
};

// text class has a separate purpose
class Text : public SpecialStrings
{
  private:
    bool ascii{ false };
    uint32 minLength{ 8 };
    uint32 maxLength{ 128 };
    bool stringsCharSetMatrix[STRINGS_CHARSET_MATRIX_SIZE]{};

  public:
    Text(bool caseSensitive, bool unicode);

    virtual const std::string_view GetName() const override;
    virtual const std::string_view GetOutputExtension() const override;
    virtual Subcategory GetSubcategory() const override;

    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) override;

    bool SetMinLength(uint32 minLength);
    bool SetMaxLength(uint32 maxLength);
    bool SetAscii(bool value);
    bool SetUnicode(bool value);
    void SetMatrix(bool stringsCharSetMatrix[STRINGS_CHARSET_MATRIX_SIZE]);
    bool IsValidChar(char c) const;
};
} // namespace GView::GenericPlugins::Droppper::SpecialStrings
