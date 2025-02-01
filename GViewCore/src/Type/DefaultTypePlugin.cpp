#include "Internal.hpp"

using namespace GView::Utils;
using namespace GView;

class DefaultType : public TypeInterface
{
  public:
    std::string_view GetTypeName() override
    {
        return "GENERIC";
    }
    void RunCommand(std::string_view) override
    {
    }
    bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    ~DefaultType()
    {
    }

    Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

    uint32 GetSelectionZonesCount() override
    {
        CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        CHECK(selectionZoneInterface.IsValid(), d, "");
        CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }

    std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override
    {
        NOT_IMPLEMENTED("NOT IMPLEMENTED")
    }
};

class DefaultInformationPanel : public TabPage
{
  public:
    DefaultInformationPanel(Reference<Object>) : TabPage("&Information")
    {
        Factory::ListView::Create(this, "d:c", { "n:Field,a:l,w:10", "n:Value,a:l,w:100" }, ListViewFlags::None);
    }
};

namespace GView::Type::DefaultTypePlugin
{
bool Validate(const AppCUI::Utils::BufferView&, const std::string_view&)
{
    return true; // always match everything
}
TypeInterface* CreateInstance()
{
    return new DefaultType();
}

bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto dt = win->GetObject()->GetContentType<DefaultType>();

    // at least one view and one information panel
    // 1. info panel
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);

    // 2. views
    auto buf       = win->GetObject()->GetData().Get(0, 4096, false);
    auto bomLength = 0U;
    auto enc       = CharacterEncoding::AnalyzeBufferForEncoding(buf, true, bomLength);

    if (enc != CharacterEncoding::Encoding::Binary)
        win->CreateViewer<View::TextViewer::Settings>();

    // add a buffer view as a default view
    GView::View::BufferViewer::Settings s{};
    dt->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(s);

    return true;
}
} // namespace GView::Type::DefaultTypePlugin
