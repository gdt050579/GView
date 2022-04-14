#include "Hashes.hpp"

namespace GView::GenericPlugins::Hashes
{
constexpr int CMD_BUTTON_CLOSE                      = 1;
constexpr int CMD_BUTTON_COMPUTE                    = 2;
constexpr const char* CMD_SHORT_NAME_HASHES         = "Hashes";
constexpr const char* CMD_SHORT_NAME_COMPUTE_MD5    = "ComputeMD5";
constexpr const char* CMD_SHORT_NAME_COMPUTE_SHA256 = "ComputeSHA256";

constexpr const char* CMD_FULL_NAME_HASHES         = "Command.Hashes";
constexpr const char* CMD_FULL_NAME_COMPUTE_MD5    = "Command.ComputeMD5";
constexpr const char* CMD_FULL_NAME_COMPUTE_SHA256 = "Command.ComputeSHA256";

constexpr const char* TYPES_ADLER32        = "Types.Adler32";
constexpr const char* TYPES_CRC16          = "Types.CRC16";
constexpr const char* TYPES_CRC32_JAMCRC_0 = "Types.CRC32_JAMCRC_0";
constexpr const char* TYPES_CRC32_JAMCRC   = "Types.CRC32_JAMCRC";
constexpr const char* TYPES_CRC64_ECMA_182 = "Types.CRC64_ECMA_182";
constexpr const char* TYPES_CRC64_WE       = "Types.CRC64_WE";
constexpr const char* TYPES_MD2            = "Types.MD2";
constexpr const char* TYPES_MD4            = "Types.MD4";
constexpr const char* TYPES_MD5            = "Types.MD5";
constexpr const char* TYPES_SHA1           = "Types.SHA1";
constexpr const char* TYPES_SHA256         = "Types.SHA256";
constexpr const char* TYPES_SHA384         = "Types.SHA384";
constexpr const char* TYPES_SHA512         = "Types.SHA512";

const uint32 widthPicking = 40;
const uint32 widthShowing = 160;

HashesDialog::HashesDialog(Reference<GView::Object> object)
    : Window("Hashes", "d:c,w:40,h:21", WindowFlags::Sizeable | WindowFlags::Maximized)
{
    this->object = object;

    hashesList = Factory::ListView::Create(
          this, "l:0,t:0,r:0,b:3", { { "Type", TextAlignament::Left, 17 }, { "Value", TextAlignament::Left, 130 } });

    hashesList->SetVisible(false);

    close                              = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
    close->SetVisible(false);

    options = Factory::ListView::Create(
          this,
          "l:0,t:0,r:0,b:3",
          { { "", TextAlignament::Left, 30 } },
          Controls::ListViewFlags::CheckBoxes | Controls::ListViewFlags::HideColumns);

    Adler32        = options->AddItem(Adler32::GetName());
    CRC16          = options->AddItem(CRC16::GetName());
    CRC32_JAMCRC_0 = options->AddItem(CRC32::GetName(CRC32Type::JAMCRC_0));
    CRC32_JAMCRC   = options->AddItem(CRC32::GetName(CRC32Type::JAMCRC));
    CRC64_ECMA_182 = options->AddItem(CRC64::GetName(CRC64Type::ECMA_182));
    CRC64_WE       = options->AddItem(CRC64::GetName(CRC64Type::WE));
    MD2            = options->AddItem(MD2::GetName());
    MD4            = options->AddItem(MD4::GetName());
    MD5            = options->AddItem(MD5::GetName());
    SHA1           = options->AddItem(SHA1::GetName());
    SHA256         = options->AddItem(SHA256::GetName());
    SHA384         = options->AddItem(SHA384::GetName());
    SHA512         = options->AddItem(SHA512::GetName());

    compute                              = Factory::Button::Create(this, "&Ok", "d:b,w:20", CMD_BUTTON_COMPUTE);
    compute->Handlers()->OnButtonPressed = this;

    SetFlagsFromSettings();
    SetCheckBoxesFromFlags();

    this->Resize(widthPicking, this->GetHeight());
}

void HashesDialog::OnButtonPressed(Reference<Button> b)
{
    if (b->GetControlID() == CMD_BUTTON_CLOSE)
    {
        Exit(0);
    }
    else if (b->GetControlID() == CMD_BUTTON_COMPUTE)
    {
        SetFlagsFromCheckBoxes();
        SetSettingsFromFlags();

        std::map<std::string, std::string> outputs;
        CHECKRET(ComputeHash(outputs, flags, object), "");

        this->Resize(widthShowing, static_cast<uint32>(outputs.size() + 8ULL));
        this->CenterScreen();

        options->SetVisible(false);
        compute->SetVisible(false);

        hashesList->Resize(hashesList->GetWidth(), static_cast<uint32>(outputs.size() + 3ULL));

        hashesList->SetVisible(true);
        close->SetVisible(true);

        for (const auto& [name, value] : outputs)
        {
            hashesList->AddItem({ name, value });
        }

        return;
    }

    Exit(0);
}

void HashesDialog::SetCheckBoxesFromFlags()
{
    for (const auto& hash : hashList)
    {
        switch (static_cast<Hashes>(flags & static_cast<uint32>(hash)))
        {
        case Hashes::Adler32:
            Adler32.SetCheck(true);
            break;
        case Hashes::CRC16:
            CRC16.SetCheck(true);
            break;
        case Hashes::CRC32_JAMCRC_0:
            CRC32_JAMCRC_0.SetCheck(true);
            break;
        case Hashes::CRC32_JAMCRC:
            CRC32_JAMCRC.SetCheck(true);
            break;
        case Hashes::CRC64_ECMA_182:
            CRC64_ECMA_182.SetCheck(true);
            break;
        case Hashes::CRC64_WE:
            CRC64_WE.SetCheck(true);
            break;
        case Hashes::MD2:
            MD2.SetCheck(true);
            break;
        case Hashes::MD4:
            MD4.SetCheck(true);
            break;
        case Hashes::MD5:
            MD5.SetCheck(true);
            break;
        case Hashes::SHA1:
            SHA1.SetCheck(true);
            break;
        case Hashes::SHA256:
            SHA256.SetCheck(true);
            break;
        case Hashes::SHA384:
            SHA384.SetCheck(true);
            break;
        case Hashes::SHA512:
            SHA512.SetCheck(true);
            break;
        default:
            break;
        }
    }
}

void HashesDialog::SetFlagsFromCheckBoxes()
{
    flags = static_cast<uint32>(Hashes::None);

    if (Adler32.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::Adler32);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::Adler32);
    }

    if (CRC16.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::CRC16);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::CRC16);
    }

    if (CRC32_JAMCRC_0.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::CRC32_JAMCRC_0);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::CRC32_JAMCRC_0);
    }

    if (CRC32_JAMCRC.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::CRC32_JAMCRC);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::CRC32_JAMCRC);
    }

    if (CRC64_ECMA_182.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::CRC64_ECMA_182);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::CRC64_ECMA_182);
    }

    if (CRC64_WE.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::CRC64_WE);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::CRC64_WE);
    }

    if (MD2.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::MD2);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::MD2);
    }

    if (MD4.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::MD4);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::MD4);
    }

    if (MD5.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::MD5);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::MD5);
    }

    if (SHA1.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA1);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA1);
    }

    if (SHA256.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA256);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA256);
    }

    if (SHA384.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA384);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA384);
    }

    if (SHA512.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA512);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA512);
    }
}

void HashesDialog::SetFlagsFromSettings()
{
    flags = static_cast<uint32>(Hashes::None);

    auto allSettings = Application::GetAppSettings();
    if (allSettings->HasSection("Generic.Hashes"))
    {
        auto hashesSettings = allSettings->GetSection("Generic.Hashes");
        for (auto type : hashesSettings)
        {
            const auto& name  = type.GetName();
            const auto& value = type.AsBool();

            if (value.has_value())
            {
                if (*value == false)
                {
                    continue;
                }
            }
            else
            {
                continue;
            }

            if (name == TYPES_ADLER32)
            {
                flags |= static_cast<uint32>(Hashes::Adler32);
            }
            else if (name == TYPES_CRC16)
            {
                flags |= static_cast<uint32>(Hashes::CRC16);
            }
            else if (name == TYPES_CRC32_JAMCRC_0)
            {
                flags |= static_cast<uint32>(Hashes::CRC32_JAMCRC_0);
            }
            else if (name == TYPES_CRC32_JAMCRC)
            {
                flags |= static_cast<uint32>(Hashes::CRC32_JAMCRC);
            }
            else if (name == TYPES_CRC64_ECMA_182)
            {
                flags |= static_cast<uint32>(Hashes::CRC64_ECMA_182);
            }
            else if (name == TYPES_CRC64_WE)
            {
                flags |= static_cast<uint32>(Hashes::CRC64_WE);
            }
            else if (name == TYPES_MD2)
            {
                flags |= static_cast<uint32>(Hashes::MD2);
            }
            else if (name == TYPES_MD4)
            {
                flags |= static_cast<uint32>(Hashes::MD4);
            }
            else if (name == TYPES_MD5)
            {
                flags |= static_cast<uint32>(Hashes::MD5);
            }
            else if (name == TYPES_SHA1)
            {
                flags |= static_cast<uint32>(Hashes::SHA1);
            }
            else if (name == TYPES_SHA256)
            {
                flags |= static_cast<uint32>(Hashes::SHA256);
            }
            else if (name == TYPES_SHA384)
            {
                flags |= static_cast<uint32>(Hashes::SHA384);
            }
            else if (name == TYPES_SHA512)
            {
                flags |= static_cast<uint32>(Hashes::SHA512);
            }
        }
    }
}

void HashesDialog::SetSettingsFromFlags()
{
    auto allSettings    = Application::GetAppSettings();
    auto hashesSettings = allSettings->GetSection("Generic.Hashes");

    hashesSettings[TYPES_ADLER32]        = Adler32.IsChecked();
    hashesSettings[TYPES_CRC16]          = CRC16.IsChecked();
    hashesSettings[TYPES_CRC32_JAMCRC_0] = CRC32_JAMCRC_0.IsChecked();
    hashesSettings[TYPES_CRC32_JAMCRC]   = CRC32_JAMCRC.IsChecked();
    hashesSettings[TYPES_CRC64_ECMA_182] = CRC64_ECMA_182.IsChecked();
    hashesSettings[TYPES_CRC64_WE]       = CRC64_WE.IsChecked();
    hashesSettings[TYPES_MD2]            = MD2.IsChecked();
    hashesSettings[TYPES_MD4]            = MD4.IsChecked();
    hashesSettings[TYPES_MD5]            = MD5.IsChecked();
    hashesSettings[TYPES_SHA1]           = SHA1.IsChecked();
    hashesSettings[TYPES_SHA256]         = SHA256.IsChecked();
    hashesSettings[TYPES_SHA384]         = SHA384.IsChecked();
    hashesSettings[TYPES_SHA512]         = SHA512.IsChecked();

    allSettings->Save(Application::GetAppSettingsFile());
}

static bool ComputeHash(std::map<std::string, std::string>& outputs, uint32 hashFlags, Reference<GView::Object> object)
{
    const auto objectSize = object->GetData().GetSize();
    ProgressStatus::Init("Computing...", objectSize);

    Adler32 adler32{};
    CRC16 crc16{};
    CRC32 crc32JAMCRC0{};
    CRC32 crc32JAMCRC{};
    CRC64 crc64ECMA182{};
    CRC64 crc64WE{};
    MD2 md2{};
    MD4 md4{};
    MD5 md5{};
    SHA1 sha1{};
    SHA256 sha256{};
    SHA512 sha512{};

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
            CHECK(crc32JAMCRC0.Init(CRC32Type::JAMCRC_0), false, "");
            break;
        case Hashes::CRC32_JAMCRC:
            CHECK(crc32JAMCRC.Init(CRC32Type::JAMCRC), false, "");
            break;
        case Hashes::CRC64_ECMA_182:
            CHECK(crc64ECMA182.Init(CRC64Type::ECMA_182), false, "");
            break;
        case Hashes::CRC64_WE:
            CHECK(crc64WE.Init(CRC64Type::WE), false, "");
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
        case Hashes::SHA384:
        case Hashes::SHA512:
            CHECK(sha512.Init(), false, "");
            break;
        default:
            break;
        }
    }

    const auto block = object->GetData().GetCacheSize();
    auto offset      = 0ULL;
    auto left        = object->GetData().GetSize();
    LocalString<512> ls;

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

        const Buffer buffer = object->GetData().CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
        CHECK(buffer.IsValid(), false, "");

        bool sha512UpdateCalled = false;
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
                CHECK(crc32JAMCRC0.Update(buffer), false, "");
                break;
            case Hashes::CRC32_JAMCRC:
                CHECK(crc32JAMCRC.Update(buffer), false, "");
                break;
            case Hashes::CRC64_ECMA_182:
                CHECK(crc64ECMA182.Update(buffer), false, "");
                break;
            case Hashes::CRC64_WE:
                CHECK(crc64WE.Update(buffer), false, "");
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
            case Hashes::SHA384:
            case Hashes::SHA512:
                if (sha512UpdateCalled == false)
                {
                    sha512UpdateCalled = true;
                    CHECK(sha512.Update(buffer), false, "");
                }
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
        const auto flag = static_cast<Hashes>(hashFlags & static_cast<uint32>(hash));
        switch (flag)
        {
        case Hashes::Adler32:
            outputs.emplace(std::pair{ Adler32::GetName(), adler32.GetHexValue() });
            break;
        case Hashes::CRC16:
            outputs.emplace(std::pair{ CRC16::GetName(), crc16.GetHexValue() });
            break;
        case Hashes::CRC32_JAMCRC_0:
            outputs.emplace(std::pair{ CRC32::GetName(CRC32Type::JAMCRC_0), crc32JAMCRC0.GetHexValue() });
            break;
        case Hashes::CRC32_JAMCRC:
            outputs.emplace(std::pair{ CRC32::GetName(CRC32Type::JAMCRC), crc32JAMCRC.GetHexValue() });
            break;
        case Hashes::CRC64_ECMA_182:
            outputs.emplace(std::pair{ CRC64::GetName(CRC64Type::ECMA_182), crc64ECMA182.GetHexValue() });
            break;
        case Hashes::CRC64_WE:
            outputs.emplace(std::pair{ CRC64::GetName(CRC64Type::WE), crc64WE.GetHexValue() });
            break;
        case Hashes::MD2:
            outputs.emplace(std::pair{ MD2::GetName(), md2.GetHexValue() });
            break;
        case Hashes::MD4:
            outputs.emplace(std::pair{ MD4::GetName(), md4.GetHexValue() });
            break;
        case Hashes::MD5:
            outputs.emplace(std::pair{ MD5::GetName(), md5.GetHexValue() });
            break;
        case Hashes::SHA1:
            outputs.emplace(std::pair{ SHA1::GetName(), sha1.GetHexValue() });
            break;
        case Hashes::SHA256:
            outputs.emplace(std::pair{ SHA256::GetName(), sha256.GetHexValue() });
            break;
        case Hashes::SHA384:
            outputs.emplace(std::pair{ SHA384::GetName(), ((SHA384*) &sha512)->GetHexValue() });
            break;
        case Hashes::SHA512:
            outputs.emplace(std::pair{ SHA512::GetName(), sha512.GetHexValue() });
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
        if (command == GView::GenericPlugins::Hashes::CMD_SHORT_NAME_HASHES)
        {
            GView::GenericPlugins::Hashes::HashesDialog dlg(object);
            dlg.Show();
            return true;
        }
        else if (command == GView::GenericPlugins::Hashes::CMD_SHORT_NAME_COMPUTE_MD5)
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
        else if (command == GView::GenericPlugins::Hashes::CMD_SHORT_NAME_COMPUTE_SHA256)
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
        sect[GView::GenericPlugins::Hashes::CMD_FULL_NAME_HASHES]         = Input::Key::Shift | Input::Key::F5;
        sect[GView::GenericPlugins::Hashes::CMD_FULL_NAME_COMPUTE_MD5]    = Input::Key::Ctrl | Input::Key::Shift | Input::Key::F5;
        sect[GView::GenericPlugins::Hashes::CMD_FULL_NAME_COMPUTE_SHA256] = Input::Key::Ctrl | Input::Key::Shift | Input::Key::F6;

        sect[GView::GenericPlugins::Hashes::TYPES_ADLER32]        = true;
        sect[GView::GenericPlugins::Hashes::TYPES_CRC16]          = true;
        sect[GView::GenericPlugins::Hashes::TYPES_CRC32_JAMCRC_0] = true;
        sect[GView::GenericPlugins::Hashes::TYPES_CRC32_JAMCRC]   = true;
        sect[GView::GenericPlugins::Hashes::TYPES_CRC64_ECMA_182] = true;
        sect[GView::GenericPlugins::Hashes::TYPES_CRC64_WE]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_MD2]            = true;
        sect[GView::GenericPlugins::Hashes::TYPES_MD4]            = true;
        sect[GView::GenericPlugins::Hashes::TYPES_MD5]            = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA1]           = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA256]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA384]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA512]         = true;
    }
}
