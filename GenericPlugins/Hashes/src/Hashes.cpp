#include "Hashes.hpp"

namespace GView::GenericPlugins::Hashes
{
constexpr int32 CMD_BUTTON_CLOSE  = 1;
constexpr int32 CMD_BUTTON_OK     = 2;
constexpr int32 CMD_BUTTON_CANCEL = 3;

constexpr std::string_view CMD_SHORT_NAME_HASHES         = "Hashes";
constexpr std::string_view CMD_SHORT_NAME_COMPUTE_MD5    = "ComputeMD5";
constexpr std::string_view CMD_SHORT_NAME_COMPUTE_SHA256 = "ComputeSHA256";

constexpr std::string_view CMD_FULL_NAME_HASHES         = "Command.Hashes";
constexpr std::string_view CMD_FULL_NAME_COMPUTE_MD5    = "Command.ComputeMD5";
constexpr std::string_view CMD_FULL_NAME_COMPUTE_SHA256 = "Command.ComputeSHA256";

constexpr std::string_view TYPES_ADLER32        = "Types.Adler32";
constexpr std::string_view TYPES_CRC16          = "Types.CRC16";
constexpr std::string_view TYPES_CRC32_JAMCRC_0 = "Types.CRC32_JAMCRC_0";
constexpr std::string_view TYPES_CRC32_JAMCRC   = "Types.CRC32_JAMCRC";
constexpr std::string_view TYPES_CRC64_ECMA_182 = "Types.CRC64_ECMA_182";
constexpr std::string_view TYPES_CRC64_WE       = "Types.CRC64_WE";
constexpr std::string_view TYPES_MD5            = "Types.MD5";
constexpr std::string_view TYPES_BLAKE2S256     = "Types.BLAKE2S256";
constexpr std::string_view TYPES_BLAKE2B512     = "Types.BLAKE2B512";
constexpr std::string_view TYPES_SHA1           = "Types.SHA1";
constexpr std::string_view TYPES_SHA224         = "Types.SHA224";
constexpr std::string_view TYPES_SHA256         = "Types.SHA256";
constexpr std::string_view TYPES_SHA384         = "Types.SHA384";
constexpr std::string_view TYPES_SHA512         = "Types.SHA512";
constexpr std::string_view TYPES_SHA512_224     = "Types.SHA512_224";
constexpr std::string_view TYPES_SHA512_256     = "Types.SHA512_256";
constexpr std::string_view TYPES_SHA3_224       = "Types.SHA3_224";
constexpr std::string_view TYPES_SHA3_256       = "Types.SHA3_256";
constexpr std::string_view TYPES_SHA3_384       = "Types.SHA3_384";
constexpr std::string_view TYPES_SHA3_512       = "Types.SHA3_512";
constexpr std::string_view TYPES_SHAKE128       = "Types.SHAKE128";
constexpr std::string_view TYPES_SHAKE256       = "Types.SHAKE256";

const uint32 widthPicking = 70;
const uint32 widthShowing = 160;

HashesDialog::HashesDialog(Reference<GView::Object> object) : Window("Hashes", "d:c,w:70,h:21", WindowFlags::ProcessReturn)
{
    this->object = object;

    hashesList = Factory::ListView::Create(this, "l:0,t:0,r:0,b:3", { "n:Type,w:17", "n:Value,w:130" });

    hashesList->SetVisible(false);

    close                              = Factory::Button::Create(this, "&Close", "d:b,w:20", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
    close->SetVisible(false);

    computeForFile = Factory::RadioBox::Create(this, "Compute for the &entire file", "x:1,y:1,w:31", 1);
    computeForFile->SetChecked(true);
    computeForSelection = Factory::RadioBox::Create(this, "Compute for the &selection", "x:1,y:2,w:31", 1);
    computeForSelection->SetEnabled(false); /* TODO: when selection object will be passed */

    options = Factory::ListView::Create(
          this, "l:1,t:3,r:1,b:3", { "w:30" }, Controls::ListViewFlags::CheckBoxes | Controls::ListViewFlags::HideColumns);

    Adler32        = options->AddItem(Adler32::GetName());
    CRC16          = options->AddItem(CRC16::GetName());
    CRC32_JAMCRC_0 = options->AddItem(CRC32::GetName(CRC32Type::JAMCRC_0));
    CRC32_JAMCRC   = options->AddItem(CRC32::GetName(CRC32Type::JAMCRC));
    CRC64_ECMA_182 = options->AddItem(CRC64::GetName(CRC64Type::ECMA_182));
    CRC64_WE       = options->AddItem(CRC64::GetName(CRC64Type::WE));
    MD5            = options->AddItem("MD5");
    BLAKE2S256     = options->AddItem("BLAKE2S256");
    BLAKE2B512     = options->AddItem("BLAKE2B512");
    SHA1           = options->AddItem("SHA1");
    SHA224         = options->AddItem("SHA224");
    SHA256         = options->AddItem("SHA256");
    SHA384         = options->AddItem("SHA384");
    SHA512         = options->AddItem("SHA512");
    SHA512_224     = options->AddItem("SHA512_224");
    SHA512_256     = options->AddItem("SHA512_256");
    SHA3_224       = options->AddItem("SHA3_224");
    SHA3_256       = options->AddItem("SHA3_256");
    SHA3_384       = options->AddItem("SHA3_384");
    SHA3_512       = options->AddItem("SHA3_512");
    SHAKE128       = options->AddItem("SHAKE128");
    SHAKE256       = options->AddItem("SHAKE256");

    ok                              = Factory::Button::Create(this, "&Ok", "x:25%,y:100%,a:b,w:12", CMD_BUTTON_OK);
    ok->Handlers()->OnButtonPressed = this;
    ok->SetFocus();

    cancel                              = Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", CMD_BUTTON_CANCEL);
    cancel->Handlers()->OnButtonPressed = this;

    SetFlagsFromSettings();
    SetCheckBoxesFromFlags();

    this->Resize(widthPicking, this->GetHeight());
}

void HashesDialog::OnButtonPressed(Reference<Button> b)
{
    if (b->GetControlID() == CMD_BUTTON_CLOSE || b->GetControlID() == CMD_BUTTON_CANCEL)
    {
        Exit();
    }
    else if (b->GetControlID() == CMD_BUTTON_OK)
    {
        SetFlagsFromCheckBoxes();
        SetSettingsFromFlags();

        std::map<std::string, std::string> outputs;
        CHECKRET(ComputeHash(outputs, flags, object), "");

        this->Resize(widthShowing, static_cast<uint32>(outputs.size() + 8ULL));
        this->CenterScreen();

        options->SetVisible(false);
        ok->SetVisible(false);
        cancel->SetVisible(false);
        computeForFile->SetVisible(false);
        computeForSelection->SetVisible(false);

        hashesList->SetVisible(true);
        close->SetVisible(true);

        for (const auto& [name, value] : outputs)
        {
            hashesList->AddItem({ name, value });
        }

        return;
    }

    Exit();
}

bool HashesDialog::OnEvent(Reference<Control> c, Event eventType, int id)
{
    if (Window::OnEvent(c, eventType, id))
    {
        return true;
    }

    if (eventType == Event::WindowAccept)
    {
        OnButtonPressed(ok);
        return true;
    }

    return false;
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
        case Hashes::MD5:
            MD5.SetCheck(true);
            break;
        case Hashes::BLAKE2S256:
            BLAKE2S256.SetCheck(true);
            break;
        case Hashes::BLAKE2B512:
            BLAKE2B512.SetCheck(true);
            break;
        case Hashes::SHA1:
            SHA1.SetCheck(true);
            break;
        case Hashes::SHA224:
            SHA224.SetCheck(true);
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
        case Hashes::SHA512_224:
            SHA512_224.SetCheck(true);
            break;
        case Hashes::SHA512_256:
            SHA512_256.SetCheck(true);
            break;
        case Hashes::SHA3_224:
            SHA3_224.SetCheck(true);
            break;
        case Hashes::SHA3_256:
            SHA3_256.SetCheck(true);
            break;
        case Hashes::SHA3_384:
            SHA3_384.SetCheck(true);
            break;
        case Hashes::SHA3_512:
            SHA3_512.SetCheck(true);
            break;
        case Hashes::SHAKE128:
            SHAKE128.SetCheck(true);
            break;
        case Hashes::SHAKE256:
            SHAKE256.SetCheck(true);
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

    if (MD5.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::MD5);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::MD5);
    }

    if (BLAKE2S256.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::BLAKE2S256);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::BLAKE2S256);
    }

    if (BLAKE2B512.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::BLAKE2B512);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::BLAKE2B512);
    }

    if (SHA1.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA1);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA1);
    }

    if (SHA224.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA224);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA224);
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

    if (SHA512_224.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA512_224);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA512_224);
    }

    if (SHA512_256.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA512_256);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA512_256);
    }

    if (SHA3_224.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA3_224);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA3_224);
    }

    if (SHA3_256.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA3_256);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA3_256);
    }

    if (SHA3_384.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA3_384);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA3_384);
    }

    if (SHA3_512.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHA3_512);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHA3_512);
    }

    if (SHAKE128.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHAKE128);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHAKE128);
    }

    if (SHAKE256.IsChecked())
    {
        flags |= static_cast<uint32>(Hashes::SHAKE256);
    }
    else
    {
        flags &= ~static_cast<uint32>(Hashes::SHAKE256);
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
            else if (name == TYPES_MD5)
            {
                flags |= static_cast<uint32>(Hashes::MD5);
            }
            else if (name == TYPES_BLAKE2S256)
            {
                flags |= static_cast<uint32>(Hashes::BLAKE2S256);
            }
            else if (name == TYPES_BLAKE2B512)
            {
                flags |= static_cast<uint32>(Hashes::BLAKE2B512);
            }
            else if (name == TYPES_SHA1)
            {
                flags |= static_cast<uint32>(Hashes::SHA1);
            }
            else if (name == TYPES_SHA224)
            {
                flags |= static_cast<uint32>(Hashes::SHA224);
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
            else if (name == TYPES_SHA512_224)
            {
                flags |= static_cast<uint32>(Hashes::SHA512_224);
            }
            else if (name == TYPES_SHA512_256)
            {
                flags |= static_cast<uint32>(Hashes::SHA512_256);
            }
            else if (name == TYPES_SHA3_224)
            {
                flags |= static_cast<uint32>(Hashes::SHA3_224);
            }
            else if (name == TYPES_SHA3_256)
            {
                flags |= static_cast<uint32>(Hashes::SHA3_256);
            }
            else if (name == TYPES_SHA3_384)
            {
                flags |= static_cast<uint32>(Hashes::SHA3_384);
            }
            else if (name == TYPES_SHA3_512)
            {
                flags |= static_cast<uint32>(Hashes::SHA3_512);
            }
            else if (name == TYPES_SHAKE128)
            {
                flags |= static_cast<uint32>(Hashes::SHAKE128);
            }
            else if (name == TYPES_SHAKE256)
            {
                flags |= static_cast<uint32>(Hashes::SHAKE256);
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
    hashesSettings[TYPES_MD5]            = MD5.IsChecked();
    hashesSettings[TYPES_BLAKE2S256]     = BLAKE2S256.IsChecked();
    hashesSettings[TYPES_BLAKE2B512]     = BLAKE2B512.IsChecked();
    hashesSettings[TYPES_SHA1]           = SHA1.IsChecked();
    hashesSettings[TYPES_SHA224]         = SHA224.IsChecked();
    hashesSettings[TYPES_SHA256]         = SHA256.IsChecked();
    hashesSettings[TYPES_SHA384]         = SHA384.IsChecked();
    hashesSettings[TYPES_SHA512]         = SHA512.IsChecked();
    hashesSettings[TYPES_SHA512_224]     = SHA512_224.IsChecked();
    hashesSettings[TYPES_SHA512_256]     = SHA512_256.IsChecked();
    hashesSettings[TYPES_SHA3_224]       = SHA3_224.IsChecked();
    hashesSettings[TYPES_SHA3_256]       = SHA3_256.IsChecked();
    hashesSettings[TYPES_SHA3_384]       = SHA3_384.IsChecked();
    hashesSettings[TYPES_SHA3_512]       = SHA3_512.IsChecked();
    hashesSettings[TYPES_SHAKE128]       = SHAKE128.IsChecked();
    hashesSettings[TYPES_SHAKE256]       = SHAKE256.IsChecked();

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
    OpenSSLHash md5(OpenSSLHashKind::Md5);
    OpenSSLHash blake2s256(OpenSSLHashKind::Blake2s256);
    OpenSSLHash blake2b512(OpenSSLHashKind::Blake2b512);
    OpenSSLHash sha1(OpenSSLHashKind::Sha1);
    OpenSSLHash sha224(OpenSSLHashKind::Sha224);
    OpenSSLHash sha256(OpenSSLHashKind::Sha256);
    OpenSSLHash sha384(OpenSSLHashKind::Sha384);
    OpenSSLHash sha512(OpenSSLHashKind::Sha512);
    OpenSSLHash sha512_224(OpenSSLHashKind::Sha512_224);
    OpenSSLHash sha512_256(OpenSSLHashKind::Sha512_256);
    OpenSSLHash sha3_224(OpenSSLHashKind::Sha3_224);
    OpenSSLHash sha3_256(OpenSSLHashKind::Sha3_256);
    OpenSSLHash sha3_384(OpenSSLHashKind::Sha3_384);
    OpenSSLHash sha3_512(OpenSSLHashKind::Sha3_512);
    OpenSSLHash shake128(OpenSSLHashKind::Shake128);
    OpenSSLHash shake256(OpenSSLHashKind::Shake256);

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
        case Hashes::MD5:
        case Hashes::BLAKE2S256:
        case Hashes::BLAKE2B512:
        case Hashes::SHA1:
        case Hashes::SHA224:
        case Hashes::SHA256:
        case Hashes::SHA384:
        case Hashes::SHA512:
        case Hashes::SHA512_224:
        case Hashes::SHA512_256:
        case Hashes::SHA3_224:
        case Hashes::SHA3_256:
        case Hashes::SHA3_384:
        case Hashes::SHA3_512:
        case Hashes::SHAKE128:
        case Hashes::SHAKE256:
            /* openssl */
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
            case Hashes::MD5:
                CHECK(md5.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::BLAKE2S256:
                CHECK(blake2s256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::BLAKE2B512:
                CHECK(blake2b512.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA1:
                CHECK(sha1.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA224:
                CHECK(sha224.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA256:
                CHECK(sha256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA384:
                CHECK(sha384.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA512:
                CHECK(sha512.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA512_224:
                CHECK(sha512_224.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA512_256:
                CHECK(sha512_256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA3_224:
                CHECK(sha3_224.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA3_256:
                CHECK(sha3_256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA3_384:
                CHECK(sha3_384.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHA3_512:
                CHECK(sha3_512.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHAKE128:
                CHECK(shake128.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
                break;
            case Hashes::SHAKE256:
                CHECK(shake256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
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
        case Hashes::MD5:
            md5.Final();
            outputs.emplace(std::pair{ "MD5", md5.GetHexValue() });
            break;
        case Hashes::BLAKE2S256:
            blake2s256.Final();
            outputs.emplace(std::pair{ "BLAKE2S256", blake2s256.GetHexValue() });
            break;
        case Hashes::BLAKE2B512:
            blake2b512.Final();
            outputs.emplace(std::pair{ "BLAKE2B512", blake2b512.GetHexValue() });
            break;
        case Hashes::SHA1:
            sha1.Final();
            outputs.emplace(std::pair{ "SHA1", sha1.GetHexValue() });
            break;
        case Hashes::SHA224:
            sha224.Final();
            outputs.emplace(std::pair{ "SHA224", sha224.GetHexValue() });
            break;
        case Hashes::SHA256:
            sha256.Final();
            outputs.emplace(std::pair{ "SHA256", sha256.GetHexValue() });
            break;
        case Hashes::SHA384:
            sha384.Final();
            outputs.emplace(std::pair{ "SHA384", sha384.GetHexValue() });
            break;
        case Hashes::SHA512:
            sha512.Final();
            outputs.emplace(std::pair{ "SHA512", sha512.GetHexValue() });
            break;
        case Hashes::SHA512_224:
            sha512_224.Final();
            outputs.emplace(std::pair{ "SHA512_224", sha512_224.GetHexValue() });
            break;
        case Hashes::SHA512_256:
            sha512_256.Final();
            outputs.emplace(std::pair{ "SHA512_256", sha512_256.GetHexValue() });
            break;
        case Hashes::SHA3_224:
            sha3_224.Final();
            outputs.emplace(std::pair{ "SHA3_224", sha3_224.GetHexValue() });
            break;
        case Hashes::SHA3_256:
            sha3_256.Final();
            outputs.emplace(std::pair{ "SHA3_256", sha3_256.GetHexValue() });
            break;
        case Hashes::SHA3_384:
            sha3_384.Final();
            outputs.emplace(std::pair{ "SHA3_384", sha3_384.GetHexValue() });
            break;
        case Hashes::SHA3_512:
            sha3_384.Final();
            outputs.emplace(std::pair{ "SHA3_512", sha3_512.GetHexValue() });
            break;
        case Hashes::SHAKE128:
            shake128.Final();
            outputs.emplace(std::pair{ "SHAKE128", shake128.GetHexValue() });
            break;
        case Hashes::SHAKE256:
            shake256.Final();
            outputs.emplace(std::pair{ "SHAKE256", shake256.GetHexValue() });
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
        sect[GView::GenericPlugins::Hashes::TYPES_MD5]            = true;
        sect[GView::GenericPlugins::Hashes::TYPES_BLAKE2S256]     = true;
        sect[GView::GenericPlugins::Hashes::TYPES_BLAKE2B512]     = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA1]           = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA224]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA256]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA384]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA512]         = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA512_224]     = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA512_256]     = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA3_224]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA3_256]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA3_384]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHA3_512]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHAKE128]       = true;
        sect[GView::GenericPlugins::Hashes::TYPES_SHAKE256]       = true;
    }
}
