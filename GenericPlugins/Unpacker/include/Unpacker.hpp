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
    Reference<Window> parent;

    Reference<ListView> list;
    Reference<Label> description;

    Reference<Button> cancel;
    Reference<Button> decode;

    std::vector<TypeInterface::SelectionZone> selectedZones;

  public:
    Plugin(Reference<GView::Object> object, Reference<Window> parent);

    bool SetAreaToDecode(Buffer& b, BufferView& bv, uint64& start, uint64& end);
    bool DecodeBase64(BufferView input, uint64 start, uint64 end);
    bool DecodeQuotedPrintable(BufferView input, uint64 start, uint64 end);
    bool DecodeZLib(BufferView input, uint64 start, uint64 end);
    bool DecodeHexCharacters(BufferView input, uint64 start, uint64 end);
    bool DecodeVBSEncoding(BufferView input, uint64 start, uint64 end);
    bool DecodeXOREncoding(BufferView input, uint64 start, uint64 end);

    void OnButtonPressed(Reference<Button> button) override;
    bool OnEvent(Reference<Control> control, Event eventType, int32 id) override;
};
} // namespace GView::GenericPlugins::Unpacker
