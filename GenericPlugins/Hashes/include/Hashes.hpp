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

enum class Hashes : uint32
{
    None           = 0x00000000,
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

static constexpr std::array<Hashes, 13> hashList{
    Hashes::Adler32, Hashes::CRC16, Hashes::CRC32_JAMCRC_0, Hashes::CRC32_JAMCRC, Hashes::CRC64_ECMA_182, Hashes::CRC64_WE, Hashes::MD2,
    Hashes::MD4,     Hashes::MD5,   Hashes::SHA1,           Hashes::SHA256,       Hashes::SHA384,         Hashes::SHA512
};

class HashesDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;

    Reference<ListView> hashesList;
    Reference<Button> close;

    Reference<ListView> options;
    ListViewItem Adler32;
    ListViewItem CRC16;
    ListViewItem CRC32_JAMCRC_0;
    ListViewItem CRC32_JAMCRC;
    ListViewItem CRC64_ECMA_182;
    ListViewItem CRC64_WE;
    ListViewItem MD2;
    ListViewItem MD4;
    ListViewItem MD5;
    ListViewItem SHA1;
    ListViewItem SHA256;
    ListViewItem SHA384;
    ListViewItem SHA512;

    Reference<Button> cancel;
    Reference<Button> ok;

    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;

  public:
    inline static uint32 flags = static_cast<uint32>(Hashes::None);

  public:
    HashesDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
    bool OnEvent(Reference<Control> c, Event eventType, int id) override;

  private:
    void SetCheckBoxesFromFlags();
    void SetFlagsFromCheckBoxes();
    void SetFlagsFromSettings();
    void SetSettingsFromFlags();
};

static bool ComputeHash(std::map<std::string, std::string>& outputs, uint32 hashFlags, Reference<GView::Object> object);
} // namespace GView::GenericPlugins::Hashes
