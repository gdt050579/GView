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
    ~DefaultType()
    {
    }
};

class DefaultInformationPanel : public TabPage
{
  public:
    DefaultInformationPanel(Reference<Object> obj) : TabPage("&Information")
    {
        auto lv = Factory::ListView::Create(this, "d:c", { "n:Field,a:l,w:10", "n:Value,a:l,w:100" }, ListViewFlags::None);
    }
};

namespace GView::Type::DefaultTypePlugin
{
bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    return true; // always match everything
}
TypeInterface* CreateInstance()
{
    return new DefaultType();
}

bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    // at least one view and one information panel
    // 1. info panel
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);

    // 2. views
    auto buf       = win->GetObject()->GetData().Get(0, 4096, false);
    auto bomLength = 0U;
    auto enc       = CharacterEncoding::AnalyzeBufferForEncoding(buf, true, bomLength);

    if (enc != CharacterEncoding::Encoding::Binary)
        win->CreateViewer<View::TextViewer::Settings>("Text view");
    // add a buffer view as a default view
    win->CreateViewer<View::BufferViewer::Settings>("Buffer view");
    return true;
}
} // namespace GView::Type::DefaultTypePlugin