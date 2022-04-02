#pragma once

#include "GView.hpp"

#include <any>
#include <array>
#include <map>

namespace GView::GenericPlugins::Hashes
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::View;
using namespace GView::Hashes;

constexpr int CMD_BUTTON_CLOSE = 1;

class HashesDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<ListView> hashesList;
    Reference<Button> close;

    Adler32 adler32;
    CRC16 crc16;
    CRC32 crc32Zero;
    CRC32 crc32Neg;
    CRC64 crc64Zero;
    CRC64 crc64Neg;
    MD2 md2;
    MD4 md4;
    MD5 md5;
    SHA1 sha1;
    SHA256 sha256;

  public:
    HashesDialog();
    bool ComputeHashes(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button>) override;
};

enum class Hashes : uint32
{
    Adler32        = 0x00000001,
    CRC16          = 0x00000002,
    CRC32_JAMCRC_0 = 0x00000004,
    CRC32_JAMCRC   = 0x00000008,
    CRC64_ECMA_182 = 0x00000010,
    CRC64_WE       = 0x00000020,
    MD2            = 0x00000040,
    MD4            = 0x00000080,
    MD5            = 0x00000100,
    SHA1           = 0x00000200,
    SHA256         = 0x00000400,
    ALL            = 0xFFFFFFFF,
};

static bool ComputeHash(std::map<std::string, std::string>& outputs, uint32 hashFlags, Reference<GView::Object> object);
} // namespace GView::GenericPlugins::Hashes
