#pragma once

#include "GView.hpp"
#include <cmath>

namespace GView::GenericPlugins::Unpackers
{
using namespace AppCUI::Graphics;
using namespace GView::View;

class Plugin : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<ListView> list;
    Reference<CheckBox> sync;

  public:
    Plugin();

    void OnButtonPressed(Reference<Button> button) override;
    void Update();

    bool Base64Decode(BufferView view, Buffer& output);
    void Base64Encode(BufferView view, Buffer& output);
};
} // namespace GView::GenericPlugins::Unpackers
