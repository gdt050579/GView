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
        auto lv = Factory::ListView::Create(
              this, "d:c", { { "Field", TextAlignament::Left, 10 }, { "Value", TextAlignament::Left, 100 } }, ListViewFlags::None);
    }
};

namespace GView::Type::DefaultTypePlugin
{
bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    return true; // always match everything
}
TypeInterface* CreateInstance(Reference<GView::Utils::DataCache> fileCache)
{
    return new DefaultType();
}

bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    // at least one view and one information panel
    // 1. info panel
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);

    // 2. views
    auto b   = win->GetObject()->GetData().Get(0, 4096, false);
    auto z   = 0U;
    auto asc = 0U;

    for (auto ch : b)
    {
        if (ch == 0)
            z++;
        else if (((ch >= 32) && (ch <= 127)) || (ch == '\t') || (ch == '\n') || (ch == '\r'))
            asc++;
    }
    auto add_textview = false;
    if (b.GetLength() > 0)
    {
        asc *= 100;
        z *= 100;
        add_textview = ((size_t) asc / b.GetLength()) >= 75;
    }
    if (add_textview)
    {
        View::TextViewer::Settings settings;
        win->CreateViewer("Text view", settings);
    }
    // add a buffer view as a default view
    View::BufferViewer::Settings settings;
    win->CreateViewer("Buffer view", settings);
    return true;
}
} // namespace GView::Type::DefaultTypePlugin