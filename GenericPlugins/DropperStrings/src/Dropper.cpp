#include "Dropper.hpp"

#include <array>
#include <regex>
#include <charconv>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

namespace GView::GenericPlugins::DroppperStrings
{
const std::string_view EMAIL_REGEX_ASCII{ R"(([a-z0-9\_\.]+@[a-z\_]+\.[a-z]{2,5}))" };
const std::u16string_view EMAIL_REGEX_UNICODE{ uR"(([a-z0-9\_\.]+@[a-z\_]+\.[a-z]{2,5}))" };

const std::string_view URL_REGEX_ASCII{ R"((((https*:\/\/)|((https*:\/\/www)|(www)\.))[a-zA-Z0-9_]+\.[a-zA-Z0-9_\.]+(\/[a-zA-Z0-9_\.]*)*))" };
const std::u16string_view URL_REGEX_UNICODE{ uR"((((https*:\/\/)|((https*:\/\/www)|(www)\.))[a-zA-Z0-9_]+\.[a-zA-Z0-9_\.]+(\/[a-zA-Z0-9_\.]*)*))" };

const std::string_view PATH_WINDOWS_REGEX_ASCII{ R"(([a-zA-Z]{1}\:\\[a-zA-Z0-9\\_\. ]+))" };
const std::u16string_view PATH_WINDOWS_REGEX_UNICODE{ uR"(([a-zA-Z]{1}\:\\[a-zA-Z0-9\\_\. ]+))" };

const std::string_view REGISTRY_HKLM_REGEX_ASCII{ R"(((HKEY_LOCAL_MACHINE|HKLM)\\[a-zA-Z .0-9\_\\]+))" };

const std::string_view PATH_UNIX_REGEX_ASCII{ R"(((\/|\.\.)[a-zA-Z\/\.0-9]+\/[a-zA-Z\/\.0-9]+))" };

const std::string_view IPS_REGEX_ASCII{ R"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,5})*))" };

const std::string_view WALLET_BITCOIN_REGEX_ASCII{ R"(((bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}))" };
const std::string_view WALLET_ETHEREUM_REGEX_ASCII{ R"((0x[a-fA-F0-9]{40}))" };
const std::string_view WALLET_STERLLAR_REGEX_ASCII{ R"((G[a-zA-Z0-9]{55}))" };

const std::string_view TEXT_ASCII{ R"(([a-zA-Z .0-9\_\<\>\(\)@]{4,}))" };
const std::u16string_view TEXT_UNICODE{ uR"(([a-zA-Z .0-9\_\<\>\(\)@]{4,}))" };

constexpr int CMD_BUTTON_CLOSE = 1;

enum class ArtefactType
{
    Unknown,
    Email,
    URL,
    Path,
    Registry,
    RegistryPersistence,
    IP,
    Wallet,
    Text
};

struct Entry
{
    ArtefactType type{ ArtefactType::Unknown };
    std::pair<uint64, uint64> position;
};

bool operator<(const Entry& a, const Entry& b)
{
    return memcmp(&a, &b, sizeof(Entry)) < 0;
}

const static std::map<Entry, std::string_view> GetAsciiMatches(
      const Buffer& buffer, ArtefactType type, std::string_view asciiPattern, bool caseSensitive = false)
{
    const auto initialStart = reinterpret_cast<char const*>(buffer.GetData());
    auto start              = reinterpret_cast<char const*>(buffer.GetData());
    const auto end          = reinterpret_cast<char const*>(start + buffer.GetLength());

    std::map<Entry, std::string_view> matchesMap;

    std::cmatch matches{};
    const std::regex pattern(
          asciiPattern.data(),
          caseSensitive ? std::regex_constants::ECMAScript | std::regex_constants::optimize
                        : std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);
    while (std::regex_search(start, end, matches, pattern))
    {
        const auto m  = std::pair<uint64, uint64>{ uint64((start - initialStart) + matches.position()), matches.length() };
        const auto sv = std::string_view{ (char*) (buffer.GetData() + m.first), m.second };

        if (sv.find_first_not_of(' ') != std::string::npos)
        {
            matchesMap[{ type, m }] = sv;
        }
        start += matches.position() + matches.length();
    }

    return matchesMap;
}

const static std::map<Entry, std::u16string_view> GetUnicodeMatches(const Buffer& buffer, ArtefactType type, std::u16string_view unicodePattern)
{
    const auto initialStart = reinterpret_cast<wchar_t const*>(buffer.GetData());
    auto start              = reinterpret_cast<wchar_t const*>(buffer.GetData());
    const auto end          = reinterpret_cast<wchar_t const*>(start + buffer.GetLength());

    std::map<Entry, std::u16string_view> matchesMap;

    std::wcmatch matches{};
    const std::wregex pattern(
          reinterpret_cast<wchar_t const* const>(unicodePattern.data()),
          std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);
    while (std::regex_search(start, end, matches, pattern))
    {
        const auto m  = std::pair<uint64, uint64>{ uint64((start - initialStart) * sizeof(wchar_t) + matches.position()), matches.length() };
        const auto sv = std::u16string_view{ (char16_t*) ((char16_t*) buffer.GetData() + m.first), m.second };

        if (sv.find_first_not_of(u' ') != std::string::npos)
        {
            matchesMap[{ type, m }] = sv;
        }
        start += matches.position() + matches.length();
    }

    return matchesMap;
}

class Dropper : public Window, public Handlers::OnButtonPressedInterface
{
  public:
    Dropper(Reference<Object> object) : Window("Strings", "d:c,w:80%,h:90%", WindowFlags::Sizeable)
    {
        const auto buffer = object->GetData().CopyEntireFile(true);
        CHECKRET(buffer.IsValid(), "");

        const auto emails          = GetAsciiMatches(buffer, ArtefactType::Email, EMAIL_REGEX_ASCII);
        const auto urls            = GetAsciiMatches(buffer, ArtefactType::URL, URL_REGEX_ASCII);
        const auto windowsPaths    = GetAsciiMatches(buffer, ArtefactType::Path, PATH_WINDOWS_REGEX_ASCII);
        const auto unixPaths       = GetAsciiMatches(buffer, ArtefactType::Path, PATH_UNIX_REGEX_ASCII);
        const auto ips             = GetAsciiMatches(buffer, ArtefactType::IP, IPS_REGEX_ASCII);
        const auto walletsBitcoin  = GetAsciiMatches(buffer, ArtefactType::Wallet, WALLET_BITCOIN_REGEX_ASCII, true);
        const auto walletsEthereum = GetAsciiMatches(buffer, ArtefactType::Wallet, WALLET_ETHEREUM_REGEX_ASCII, true);
        const auto walletsStellar  = GetAsciiMatches(buffer, ArtefactType::Wallet, WALLET_STERLLAR_REGEX_ASCII, true);
        const auto registries      = GetAsciiMatches(buffer, ArtefactType::Registry, REGISTRY_HKLM_REGEX_ASCII);
        const auto texts           = GetAsciiMatches(buffer, ArtefactType::Text, TEXT_ASCII);
        const auto uTexts = std::map<Entry, std::u16string_view>(); // TODO: re-enable unicode GetUnicodeMatches(buffer, ArtefactType::Text, TEXT_UNICODE);

        auto lv = Factory::ListView::Create(
              this, "x:0,y:0,w:100%,h:90%", { "n:Type,w:10%", "n:Offset,w:5%", "n:Value,w:35%", "n:Hint,w:50%" }, ListViewFlags::AllowMultipleItemsSelection);

        NumericFormatter n;

        const auto getSortedKeys = [](std::map<Entry, std::string_view> map)
        {
            std::vector<Entry> keys;
            for (const auto& [k, _] : map)
            {
                keys.emplace_back(k);
            }
            std::sort(keys.begin(), keys.end(), [](const Entry& a, const Entry& b) { return a.position.first < b.position.first; });

            return keys;
        };

        const auto getUSortedKeys = [](std::map<Entry, std::u16string_view> map)
        {
            std::vector<Entry> keys;
            for (const auto& [k, _] : map)
            {
                keys.emplace_back(k);
            }
            std::sort(keys.begin(), keys.end(), [](const Entry& a, const Entry& b) { return a.position.first < b.position.first; });

            return keys;
        };

        const auto sortedEmails = getSortedKeys(emails);
        if (emails.empty() == false)
        {
            lv->AddItem({ "Emails" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedEmails)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = emails.at(key);
                lv->AddItem({ "Email", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const auto sortedURLs = getSortedKeys(urls);
        if (urls.empty() == false)
        {
            lv->AddItem({ "URLs" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedURLs)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = urls.at(key);
                lv->AddItem({ "URL", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const auto sortedIPs = getSortedKeys(ips);
        if (sortedIPs.empty() == false)
        {
            lv->AddItem({ "IPs" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedIPs)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = ips.at(key);
                lv->AddItem({ "IP", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const auto sortedWalletsBitcoin  = getSortedKeys(walletsBitcoin);
        const auto sortedWalletsEthereum = getSortedKeys(walletsEthereum);
        const auto sortedWalletsStellar  = getSortedKeys(walletsStellar);
        if (sortedWalletsBitcoin.empty() == false || sortedWalletsEthereum.empty() == false || sortedWalletsStellar.empty() == false)
        {
            lv->AddItem({ "Wallets" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedWalletsBitcoin)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = walletsBitcoin.at(key);
                lv->AddItem({ "Wallet (Bitcoin)", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }

            for (const auto& key : sortedWalletsEthereum)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = walletsEthereum.at(key);
                lv->AddItem({ "Wallet (Ethereum)", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }

            for (const auto& key : sortedWalletsStellar)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = walletsStellar.at(key);
                lv->AddItem({ "Wallet (Stellar)", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const auto sortedWindowsPaths = getSortedKeys(windowsPaths);
        const auto sortedUnixPaths    = getSortedKeys(unixPaths);
        if (windowsPaths.empty() == false || sortedUnixPaths.empty() == false)
        {
            lv->AddItem({ "Paths" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedWindowsPaths)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = windowsPaths.at(key);

                if (value.ends_with(R"(\StartUp)"))
                {
                    lv->AddItem({ "Path (Win) (Persistence)",
                                  svp.data(),
                                  std::string{ value.data(), key.position.second }.c_str(),
                                  "Everything that is in this folder gets executed as start up, as long as it is in an executable format." })
                          .SetType(ListViewItem::Type::Emphasized_2);
                }
                else
                {
                    lv->AddItem({ "Path (Win)", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
                }
            }

            for (const auto& key : sortedUnixPaths)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = unixPaths.at(key);

                if (value.ends_with(R"(/passwd)"))
                {
                    lv->AddItem({ "Path (Unix) (Credentials)", svp.data(), std::string{ value.data(), key.position.second }.c_str() })
                          .SetType(ListViewItem::Type::Emphasized_2);
                }
                else
                {
                    lv->AddItem({ "Path (Unix)", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
                }
            }
        }

        const auto sortedRegistries = getSortedKeys(registries);
        if (registries.empty() == false)
        {
            lv->AddItem({ "Registries" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedRegistries)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = registries.at(key);
                if (value.ends_with(R"(\Run)"))
                {
                    lv->AddItem({ "Registry (Persistence)",
                                  svp.data(),
                                  std::string{ value.data(), key.position.second }.c_str(),
                                  "The command added here gets executed everytime an user logs in (HCKU) or the system boots up (HKLM)." })
                          .SetType(ListViewItem::Type::Emphasized_2);
                }
                else
                {
                    lv->AddItem({ "Registry", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
                }
            }
        }

        const auto sortedTexts = getSortedKeys(texts);
        if (texts.empty() == false)
        {
            lv->AddItem({ "Strings" }).SetType(ListViewItem::Type::Category);

            const auto shouldSkip = [](const Entry& e, const std::vector<Entry>& entries) -> bool
            {
                for (const auto& eKey : entries)
                {
                    if (e.position == eKey.position)
                    {
                        if (e.type == eKey.type)
                        {
                            return false;
                        }
                    }

                    if (e.position.first >= eKey.position.first && e.position.first <= eKey.position.first + eKey.position.second)
                    {
                        return true;
                    }
                }

                return false;
            };

            for (const auto& key : sortedTexts)
            {
                if (shouldSkip(key, sortedEmails))
                    continue;
                if (shouldSkip(key, sortedURLs))
                    continue;
                if (shouldSkip(key, sortedWindowsPaths))
                    continue;
                if (shouldSkip(key, sortedUnixPaths))
                    continue;
                if (shouldSkip(key, sortedRegistries))
                    continue;
                if (shouldSkip(key, sortedIPs))
                    continue;
                if (shouldSkip(key, sortedTexts))
                    continue;

                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = texts.at(key);
                lv->AddItem({ "Text", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const std::vector<Entry> uSortedTexts{}; // = getUSortedKeys(uTexts); // TODO: re-enable unicode strings
        if (uSortedTexts.empty() == false)
        {
            if (texts.empty())
            {
                lv->AddItem({ "Strings" }).SetType(ListViewItem::Type::Category);
            }

            for (const auto& key : uSortedTexts)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = uTexts.at(key);

                UnicodeStringBuilder usb{};
                usb.Set(value);

                std::string sValue;
                usb.ToString(sValue);

                auto item = lv->AddItem({ "(U) Text", svp.data(), sValue.c_str() });
                item.SetType(ListViewItem::Type::SubItemColored);
                item.SetColor(0, { Color::Yellow, Color::Transparent });
            }
        }

        Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE)->Handlers()->OnButtonPressed = this;
    }

    void OnButtonPressed(Reference<Button>) override
    {
        this->Exit();
    }
};

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
    {
        // all good
        if (command == "DropperStrings")
        {
            Dropper dlg(object);
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.DropperStrings"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F2;
    }
}
} // namespace GView::GenericPlugins::DroppperStrings
