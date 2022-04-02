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

class HashesDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<ListView> hashesList;
    Reference<Button> close;

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
    SHA384         = 0x00000800,
    SHA512         = 0x00001000,
    ALL            = 0xFFFFFFFF,
};

static bool ComputeHash(std::map<std::string, std::string>& outputs, uint32 hashFlags, Reference<GView::Object> object);
} // namespace GView::GenericPlugins::Hashes
