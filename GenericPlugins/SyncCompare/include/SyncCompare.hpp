#pragma once

#include "GView.hpp"
#include <cmath>

namespace GView::GenericPlugins::SyncCompare
{
using namespace AppCUI::Graphics;
using namespace GView::View;

class Plugin : public Window, public Handlers::OnButtonPressedInterface, public BufferColorInterface, public OnStartViewMoveInterface
{
    Reference<ListView> list;
    Reference<CheckBox> sync;

  public:
    Plugin();

    void OnButtonPressed(Reference<Button> button) override;
    void Update();
    void SetAllWindowsWithGivenViewName(const std::string_view& viewName);
    void ArrangeFilteredWindows(const std::string_view& filterName);
    bool GetColorForByteAt(uint64 offset, const ViewData& vd, ColorPair& cp) override;
    virtual bool GenerateActionOnMove(Reference<Control> sender, int64 deltaStartView, const ViewData& vd) override;
    void SetUpCallbackForViews(bool remove);
    bool ToggleSync();
    bool FindNextDifference();
    static bool FindNextDifferentCharacter();
};
} // namespace GView::GenericPlugins::SyncCompare
