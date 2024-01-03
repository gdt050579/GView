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
    MD5            = 0x00000100,
    BLAKE2S256     = 0x00000200,
    BLAKE2B512     = 0x00000400,
    SHA1           = 0x00000800,
    SHA224         = 0x00001000,
    SHA256         = 0x00002000,
    SHA384         = 0x00004000,
    SHA512         = 0x00008000,
    SHA512_224     = 0x00010000,
    SHA512_256     = 0x00020000,
    SHA3_224       = 0x00040000,
    SHA3_256       = 0x00080000,
    SHA3_384       = 0x00100000,
    SHA3_512       = 0x00200000,
    SHAKE128       = 0x00400000,
    SHAKE256       = 0x00800000,
    ALL            = 0xFFFFFFFF,
};

static constexpr std::array<Hashes, 24> hashList{
    Hashes::Adler32,  Hashes::CRC16,      Hashes::CRC32_JAMCRC_0, Hashes::CRC32_JAMCRC, Hashes::CRC64_ECMA_182, Hashes::CRC64_WE,
    Hashes::MD5,      Hashes::BLAKE2S256, Hashes::BLAKE2B512,     Hashes::SHA1,         Hashes::SHA224,         Hashes::SHA256,
    Hashes::SHA384,   Hashes::SHA512,     Hashes::SHA512_224,     Hashes::SHA512_256,   Hashes::SHA3_224,       Hashes::SHA3_256,
    Hashes::SHA3_384, Hashes::SHA3_512,   Hashes::SHAKE128,       Hashes::SHAKE256
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
    ListViewItem MD5;
    ListViewItem BLAKE2S256;
    ListViewItem BLAKE2B512;
    ListViewItem SHA1;
    ListViewItem SHA224;
    ListViewItem SHA256;
    ListViewItem SHA384;
    ListViewItem SHA512;
    ListViewItem SHA512_224;
    ListViewItem SHA512_256;
    ListViewItem SHA3_224;
    ListViewItem SHA3_256;
    ListViewItem SHA3_384;
    ListViewItem SHA3_512;
    ListViewItem SHAKE128;
    ListViewItem SHAKE256;

    Reference<Button> cancel;
    Reference<Button> ok;

    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;

    std::vector<TypeInterface::SelectionZone> selectedZones;

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

static bool ComputeHash(
      std::map<std::string, std::string>& outputs,
      uint32 hashFlags,
      Reference<GView::Object> object,
      bool computeForFileOption,
      const std::vector<TypeInterface::SelectionZone>& selectedZones);
} // namespace GView::GenericPlugins::Hashes
