#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

Main::Main(Reference<MachOFile> _machO) : TabPage("&Main")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void Main::UpdateGeneralInformation()
{
    ItemHandle item;
    LocalString<256> tmp;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("MAIN");
    general->SetItemType(item, ListViewItemType::Category);

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    uint32_t cmd;       /* LC_MAIN only used in MH_EXECUTE filetypes */
    uint32_t cmdsize;   /* 24 */
    uint64_t entryoff;  /* file (__TEXT) offset of main() */
    uint64_t stacksize; /* if not zero, initial stack size */

    general->AddItem(
          "Command",
          tmp.Format(
                "%s (%s)",
                std::string(MAC::LoadCommandNames.at(machO->main.ep.cmd)).c_str(),
                std::string(n.ToString(static_cast<uint32_t>(machO->main.ep.cmd), hex).data()).c_str()));

    general->AddItem(
          "Cmd Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->main.ep.cmdsize, dec).data(),
                std::string(n.ToString(machO->main.ep.cmdsize, hex).data()).c_str()));
    general->AddItem(
          "EP offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->main.ep.entryoff, dec).data(),
                std::string(n.ToString(machO->main.ep.entryoff, hex).data()).c_str()));
    general->AddItem(
          "Stack Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->main.ep.stacksize, dec).data(),
                std::string(n.ToString(machO->main.ep.stacksize, hex).data()).c_str()));
}

void Main::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

void Main::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
