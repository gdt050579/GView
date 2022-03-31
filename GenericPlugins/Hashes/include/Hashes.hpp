#pragma once

#include "GView.hpp"

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

  public:
    HashesDialog();
    bool ComputeHashes(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button>) override;
};
} // namespace GView::GenericPlugins::Hashes
