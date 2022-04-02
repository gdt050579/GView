#include "Hashes.hpp"

namespace GView::GenericPlugins::Hashes
{
constexpr const char* Command_Name_Hashes        = "Hashes";
constexpr const char* Command_Name_ComputeMD5    = "ComputeMD5";
constexpr const char* Command_Name_ComputeSHA256 = "ComputeSHA256";

HashesDialog::HashesDialog() : Window("Hashes", "d:c,w:90,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
{
    hashesList = Factory::ListView::Create(this, "l:0,t:0,r:0,b:3");
    hashesList->AddColumn("Type", TextAlignament::Left, 17);
    hashesList->AddColumn("Value", TextAlignament::Left, 100);

    close                              = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
}

bool HashesDialog::ComputeHashes(Reference<GView::Object> object)
{
    std::map<std::string, std::string> outputs;
    ComputeHash(outputs, static_cast<uint32>(Hashes::ALL), object);

    for (const auto& [name, value] : outputs)
    {
        hashesList->AddItem(name, value);
    }

    return true;
}

void HashesDialog::OnButtonPressed(Reference<Button>)
{
    Exit(0);
}

static bool ComputeHash(std::map<std::string, std::string>& outputs, uint32 hashFlags, Reference<GView::Object> object)
{
    const auto objectSize = object->cache.GetSize();
    ProgressStatus::Init("Computing...", objectSize);

    static constexpr std::array<Hashes, 11> hashList{
        Hashes::Adler32, Hashes::CRC16, Hashes::CRC32_JAMCRC_0, Hashes::CRC32_JAMCRC, Hashes::CRC64_ECMA_182, Hashes::CRC64_WE, Hashes::MD2,
        Hashes::MD4,     Hashes::MD5,   Hashes::SHA1,           Hashes::SHA256
    };
    Adler32 adler32{};
    CRC16 crc16{};
    CRC32 crc32Zero{};
    CRC32 crc32Neg{};
    CRC64 crc64Zero{};
    CRC64 crc64Neg{};
    MD2 md2{};
    MD4 md4{};
    MD5 md5{};
    SHA1 sha1{};
    SHA256 sha256{};

    for (const auto& hash : hashList)
    {
        switch (static_cast<Hashes>(hashFlags & static_cast<uint32>(hash)))
        {
        case Hashes::Adler32:
            CHECK(adler32.Init(), false, "");
            break;
        case Hashes::CRC16:
            CHECK(crc16.Init(), false, "");
            break;
        case Hashes::CRC32_JAMCRC_0:
            CHECK(crc32Zero.Init(CRC32Type::ZERO), false, "");
            break;
        case Hashes::CRC32_JAMCRC:
            CHECK(crc32Neg.Init(CRC32Type::NEGL), false, "");
            break;
        case Hashes::CRC64_ECMA_182:
            CHECK(crc64Zero.Init(CRC64Type::ECMA_182), false, "");
            break;
        case Hashes::CRC64_WE:
            CHECK(crc64Neg.Init(CRC64Type::WE), false, "");
            break;
        case Hashes::MD2:
            CHECK(md2.Init(), false, "");
            break;
        case Hashes::MD4:
            CHECK(md4.Init(), false, "");
            break;
        case Hashes::MD5:
            CHECK(md5.Init(), false, "");
            break;
        case Hashes::SHA1:
            CHECK(sha1.Init(), false, "");
            break;
        case Hashes::SHA256:
            CHECK(sha256.Init(), false, "");
            break;
        default:
            break;
        }
    }

    const auto block = object->cache.GetCacheSize();
    auto offset      = 0ULL;
    auto left        = object->cache.GetSize();
    LocalString<256> ls;

    const char* format = "Reading [0x%.8llX/0x%.8llX] bytes...";
    if (objectSize > 0xFFFFFFFF)
    {
        format = "[0x%.16llX/0x%.16llX] bytes...";
    }

    do
    {
        CHECK(ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)) == false, false, "");

        const auto sizeToRead = (left >= block ? block : left);
        left -= (left >= block ? block : left);

        const Buffer buffer = object->cache.CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
        CHECK(buffer.IsValid(), false, "");

        for (const auto& hash : hashList)
        {
            switch (static_cast<Hashes>(hashFlags & static_cast<uint32>(hash)))
            {
            case Hashes::Adler32:
                CHECK(adler32.Update(buffer), false, "");
                break;
            case Hashes::CRC16:
                CHECK(crc16.Update(buffer), false, "");
                break;
            case Hashes::CRC32_JAMCRC_0:
                CHECK(crc32Zero.Update(buffer), false, "");
                break;
            case Hashes::CRC32_JAMCRC:
                CHECK(crc32Neg.Update(buffer), false, "");
                break;
            case Hashes::CRC64_ECMA_182:
                CHECK(crc64Zero.Update(buffer), false, "");
                break;
            case Hashes::CRC64_WE:
                CHECK(crc64Neg.Update(buffer), false, "");
                break;
            case Hashes::MD2:
                CHECK(md2.Update(buffer), false, "");
                break;
            case Hashes::MD4:
                CHECK(md4.Update(buffer), false, "");
                break;
            case Hashes::MD5:
                CHECK(md5.Update(buffer), false, "");
                break;
            case Hashes::SHA1:
                CHECK(sha1.Update(buffer), false, "");
                break;
            case Hashes::SHA256:
                CHECK(sha256.Update(buffer), false, "");
                break;
            default:
                break;
            }
        }

        offset += sizeToRead;
    } while (left > 0);

    NumericFormatter nf;
    for (const auto& hash : hashList)
    {
        switch (static_cast<Hashes>(hashFlags & static_cast<uint32>(hash)))
        {
        case Hashes::Adler32:
        {
            uint32 hash = 0;
            CHECK(adler32.Final(hash), false, "");
            outputs.emplace(std::pair{ "Adler32", ls.Format("0x%.8X", hash) });
        }
        break;
        case Hashes::CRC16:
        {
            uint16 hash = 0;
            CHECK(crc16.Final(hash), false, "");
            outputs.emplace(std::pair{ "CRC16 (CCITT)", ls.Format("0x%.8X", hash) });
        }
        break;
        case Hashes::CRC32_JAMCRC_0:
        {
            uint32 hash = 0;
            CHECK(crc32Zero.Final(hash), false, "");
            outputs.emplace(std::pair{ "CRC32 (JAMCRC(0))", ls.Format("0x%.8X", hash) });
        }
        break;
        case Hashes::CRC32_JAMCRC:
        {
            uint32 hash = 0;
            CHECK(crc32Neg.Final(hash), false, "");
            outputs.emplace(std::pair{ "CRC32 (JAMCRC)", ls.Format("0x%.8X", hash) });
        }
        break;
        case Hashes::CRC64_ECMA_182:
        {
            uint64 hash = 0;
            CHECK(crc64Zero.Final(hash), false, "");
            outputs.emplace(std::pair{ "CRC64 (ECMA_182)", ls.Format("0x%.16llX", hash) });
        }
        break;
        case Hashes::CRC64_WE:
        {
            uint64 hash = 0;
            CHECK(crc64Neg.Final(hash), false, "");
            outputs.emplace(std::pair{ "CRC64 (WE)", ls.Format("0x%.16llX", hash) });
        }
        break;
        case Hashes::MD2:
        {
            uint8 hash[16]{ 0 };
            CHECK(md2.Final(hash), false, "");
            ls.Format("0x");
            for (auto i = 0U; i < 16; i++)
            {
                ls.AddFormat("%X", hash[i]);
            }
            outputs.emplace(std::pair{ "MD2", ls.GetText() });
        }
        break;
        case Hashes::MD4:
        {
            uint8 hash[16]{ 0 };
            CHECK(md4.Final(hash), false, "");
            ls.Format("0x");
            for (auto i = 0U; i < 16; i++)
            {
                ls.AddFormat("%X", hash[i]);
            }
            outputs.emplace(std::pair{ "MD4", ls.GetText() });
        }
        break;
        case Hashes::MD5:
        {
            uint8 hash[16]{ 0 };
            CHECK(md5.Final(hash), false, "");
            ls.Format("0x");
            for (auto i = 0U; i < 16; i++)
            {
                ls.AddFormat("%X", hash[i]);
            }
            outputs.emplace(std::pair{ "MD5", ls.GetText() });
        }
        break;
        case Hashes::SHA1:
        {
            uint8 hash[20]{ 0 };
            CHECK(sha1.Final(hash), false, "");
            ls.Format("0x");
            for (auto i = 0U; i < 20; i++)
            {
                ls.AddFormat("%X", hash[i]);
            }
            outputs.emplace(std::pair{ "SHA1", ls.GetText() });
        }
        break;
        case Hashes::SHA256:
        {
            uint8 hash[32]{ 0 };
            CHECK(sha256.Final(hash), false, "");
            ls.Format("0x");
            for (auto i = 0U; i < 32; i++)
            {
                ls.AddFormat("%X", hash[i]);
            }
            outputs.emplace(std::pair{ "SHA256", ls.GetText() });
        }
        break;
        default:
            break;
        }
    }

    return true;
}
} // namespace GView::GenericPlugins::Hashes

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
    {
        if (command == GView::GenericPlugins::Hashes::Command_Name_Hashes)
        {
            GView::GenericPlugins::Hashes::HashesDialog dlg;
            CHECK(dlg.ComputeHashes(object), true, "");
            dlg.Show();
            return true;
        }
        else if (command == GView::GenericPlugins::Hashes::Command_Name_ComputeMD5)
        {
            std::map<std::string, std::string> outputs;
            if (GView::GenericPlugins::Hashes::ComputeHash(
                      outputs, static_cast<uint32>(GView::GenericPlugins::Hashes::Hashes::MD5), object) == false)
            {
                Dialogs::MessageBox::ShowError("Error!", "Failed computing MD5!");
                RETURNERROR(false, "Failed computing MD5!");
            }

            if (outputs.size() == 1)
            {
                AppCUI::OS::Clipboard::SetText(outputs.begin()->second);
                Dialogs::MessageBox::ShowNotification("MD5 copied to clipboard!", outputs.begin()->second);
            }
            else
            {
                Dialogs::MessageBox::ShowError("Error!", "Failed computing MD5!");
                RETURNERROR(false, "Failed computing MD5!");
            }

            return true;
        }
        else if (command == GView::GenericPlugins::Hashes::Command_Name_ComputeSHA256)
        {
            std::map<std::string, std::string> outputs;
            if (GView::GenericPlugins::Hashes::ComputeHash(
                      outputs, static_cast<uint32>(GView::GenericPlugins::Hashes::Hashes::SHA256), object) == false)
            {
                Dialogs::MessageBox::ShowError("Error!", "Failed computing SHA256!");
                RETURNERROR(false, "Failed computing SHA256!");
            }

            if (outputs.size() == 1)
            {
                AppCUI::OS::Clipboard::SetText(outputs.begin()->second);
                Dialogs::MessageBox::ShowNotification("SHA256 copied to clipboard!", outputs.begin()->second);
            }
            else
            {
                Dialogs::MessageBox::ShowError("Error!", "Failed computing SHA256!");
                RETURNERROR(false, "Failed computing SHA256!");
            }

            return true;
        }

        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.Hashes"]        = Input::Key::Shift | Input::Key::F5;
        sect["command.ComputeMD5"]    = Input::Key::Ctrl | Input::Key::Shift | Input::Key::F5;
        sect["command.ComputeSHA256"] = Input::Key::Ctrl | Input::Key::Shift | Input::Key::F6;
    }
}
