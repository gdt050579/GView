#include "pe.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::PE::Panels
{
GoFiles::GoFiles(Reference<Object> _object, Reference<PEFile> _pe) : TabPage("Go&Modules"), object(_object), pe(_pe)
{
    list = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ConstString>{ "n:Index,a:r,w:7", "n:Name,w:20", "n:Path,w:200" },
          ListViewFlags::None);

    Update();
}

void GoFiles::UpdateGoFiles()
{
    CHECKRET(pe->pcLnTab.GetHeader() != nullptr, "");

    LocalString<1024> ls;
    const auto filesCount = pe->pcLnTab.GetFilesCount();
    list->AddItem(ls.Format("#%u files", filesCount)).SetType(ListViewItem::Type::Category);

    for (auto i = 0U; i < filesCount; i++)
    {
        std::string_view file;
        CHECKRET(pe->pcLnTab.GetFile(i, file), "");

        const auto pos        = file.find_last_of('/');
        std::string_view name = file;
        if (pos != std::string::npos)
        {
            name = { file.data() + pos + 1, file.size() - pos - 1 };
        }
        list->AddItem({ ls.Format("%u", i), name.data(), file.data() });
    }
}

void GoFiles::Update()
{
    list->DeleteAllItems();

    UpdateGoFiles();
}

void GoFiles::OnAfterResize(int newWidth, int newHeight)
{
    auto h1 = std::max(8, ((newHeight - 4) * 6) / 10);
    if (list.IsValid())
    {
        list->Resize(newWidth, h1);
    };
}
} // namespace GView::Type::PE::Panels
