#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::Unpacker
{
using namespace AppCUI::Graphics;
using namespace GView::View;

class Plugin : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;

    Reference<ListView> list;

    Reference<Button> cancel;
    Reference<Button> decode;

    std::vector<TypeInterface::SelectionZone> selectedZones;

  public:
    Plugin(Reference<GView::Object> object);

    bool SetAreaToDecode(Buffer& b, BufferView& bv, uint64& start, uint64& end);
    bool DecodeBase64(BufferView input, uint64 start, uint64 end);
    bool DecodeZLib(BufferView input, uint64 start, uint64 end);

    void OnButtonPressed(Reference<Button> button) override;
};
} // namespace GView::GenericPlugins::Unpacker
