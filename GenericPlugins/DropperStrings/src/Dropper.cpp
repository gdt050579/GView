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
const std::string_view EMAIL_REGEX_ASCII{ R"(^[\w-\.]+@([\w-]+\.)+[\w-]{2,4})" };
const std::u16string_view EMAIL_REGEX_UNICODE{ uR"(^[\w-\.]+@([\w-]+\.)+[\w-]{2,4})" };

const std::string_view URL_REGEX_ASCII{ R"((http:\/\/www\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\/[a-zA-Z0-9_\.]+))" };
const std::u16string_view URL_REGEX_UNICODE{ uR"((http:\/\/www\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\/[a-zA-Z0-9_\.]+))" };

const std::string_view PATH_WINDOWS_REGEX_ASCII{ R"(([a-zA-Z]{1}\:\\[a-zA-Z0-9\\_\.]+))" };
const std::u16string_view PATH_WINDOWS_REGEX_UNICODE{ uR"(([a-zA-Z]{1}\:\\[a-zA-Z0-9\\_\.]+))" };

const std::string_view REGISTRY_HKLM_REGEX_ASCII{ R"((HKEY_LOCAL_MACHINE\\[a-zA-Z .0-9\_\\]+))" };

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

const static std::map<Entry, std::string_view> GetAsciiMatches(const Buffer& buffer, ArtefactType type, std::string_view asciiPattern)
{
    const auto initialStart = reinterpret_cast<char const*>(buffer.GetData());
    auto start              = reinterpret_cast<char const*>(buffer.GetData());
    const auto end          = reinterpret_cast<char const*>(start + buffer.GetLength());

    std::map<Entry, std::string_view> matchesMap;

    std::cmatch matches{};
    const std::regex pattern(asciiPattern.data(), std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);
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
        const auto m  = std::pair<uint64, uint64>{ uint64((start - initialStart) + matches.position()), matches.length() };
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
    Dropper(Reference<Object> object) : Window("Strings", "d:c,w:60%,h:80%", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        const auto buffer = object->GetData().CopyEntireFile(true);
        CHECKRET(buffer.IsValid(), "");

        const auto emails     = GetAsciiMatches(buffer, ArtefactType::Email, EMAIL_REGEX_ASCII);
        const auto urls       = GetAsciiMatches(buffer, ArtefactType::URL, URL_REGEX_ASCII);
        const auto paths      = GetAsciiMatches(buffer, ArtefactType::Path, PATH_WINDOWS_REGEX_ASCII);
        const auto registries = GetAsciiMatches(buffer, ArtefactType::Registry, REGISTRY_HKLM_REGEX_ASCII);
        const auto texts      = GetAsciiMatches(buffer, ArtefactType::Text, TEXT_ASCII);
        const auto uTexts     = GetUnicodeMatches(buffer, ArtefactType::Text, TEXT_UNICODE);

        auto lv = Factory::ListView::Create(
              this, "x:0,y:0,w:100%,h:90%", { "n:Type,w:15%", "n:Offset,w:10%", "n:Value,w:75%" }, ListViewFlags::AllowMultipleItemsSelection);

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

        const auto sortedPaths = getSortedKeys(paths);
        if (paths.empty() == false)
        {
            lv->AddItem({ "Paths" }).SetType(ListViewItem::Type::Category);

            for (const auto& key : sortedPaths)
            {
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = paths.at(key);
                lv->AddItem({ "Path", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
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
                    lv->AddItem({ "Registry (Persistence)", svp.data(), std::string{ value.data(), key.position.second }.c_str() })
                          .SetType(ListViewItem::Type::Emphasized_3);
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
                {
                    continue;
                }

                if (shouldSkip(key, sortedURLs))
                {
                    continue;
                }

                if (shouldSkip(key, sortedPaths))
                {
                    continue;
                }

                if (shouldSkip(key, sortedRegistries))
                {
                    continue;
                }
                const auto svp    = n.ToString(key.position.first, { NumericFormatFlags::HexPrefix, 16 });
                const auto& value = texts.at(key);

                if (shouldSkip(key, sortedTexts))
                {
                    continue;
                }

                lv->AddItem({ "Text", svp.data(), std::string{ value.data(), key.position.second }.c_str() });
            }
        }

        const auto uSortedTexts = getUSortedKeys(uTexts);
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

                lv->AddItem({ "(U) Text", svp.data(), sValue.c_str() });
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
