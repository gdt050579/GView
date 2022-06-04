#include "elf.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::ELF::Panels
{
GoFiles::GoFiles(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf) : TabPage("Go&Modules"), object(_object), elf(_elf)
{
    list = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ConstString>{ "n:Index,a:r,w:7", "n:Name,w:20", "n:Path,w:200" },
          ListViewFlags::None);

    Update();
}

void GoFiles::UpdateGoFiles()
{
    CHECKRET(elf->pclntab112.header != nullptr, "");

    LocalString<1024> ls;
    list->AddItem(ls.Format("#%u files", (uint32) elf->pclntab112.files.size())).SetType(ListViewItem::Type::Category);

    for (const auto& [i, file] : elf->pclntab112.files)
    {
        std::string_view name = file;
        const auto pos        = file.find_last_of('/');
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
} // namespace GView::Type::ELF::Panels
