#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

DyldInfo::DyldInfo(Reference<MachOFile> _machO) : TabPage("&DyldInfo")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void DyldInfo::UpdateBasicInfo()
{
    ItemHandle item;
    LocalString<256> tmp;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("DYLD INFO");
    general->SetItemType(item, ListViewItemType::Category);

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->AddItem(
          "Command",
          tmp.Format(
                "%s (%s)",
                std::string(MAC::LoadCommandNames.at(machO->dyldInfo->cmd)).c_str(),
                std::string(n.ToString(static_cast<uint32_t>(machO->dyldInfo->cmd), hex).data()).c_str()));

    general->AddItem(
          "Cmd Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->cmdsize, dec).data(),
                std::string(n.ToString(machO->dyldInfo->cmdsize, hex).data()).c_str()));
    general->AddItem(
          "Rebase Info File Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->rebase_off, dec).data(),
                std::string(n.ToString(machO->dyldInfo->rebase_off, hex).data()).c_str()));
    general->AddItem(
          "Rebase Info Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->rebase_size, dec).data(),
                std::string(n.ToString(machO->dyldInfo->rebase_size, hex).data()).c_str()));
    general->AddItem(
          "Binding Info File Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->bind_off, dec).data(),
                std::string(n.ToString(machO->dyldInfo->bind_off, hex).data()).c_str()));
    general->AddItem(
          "Binding Info Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->bind_size, dec).data(),
                std::string(n.ToString(machO->dyldInfo->bind_size, hex).data()).c_str()));
    general->AddItem(
          "Weak Binding File Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->weak_bind_off, dec).data(),
                std::string(n.ToString(machO->dyldInfo->weak_bind_off, hex).data()).c_str()));
    general->AddItem(
          "Weak Binding Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->weak_bind_size, dec).data(),
                std::string(n.ToString(machO->dyldInfo->weak_bind_size, hex).data()).c_str()));
    general->AddItem(
          "Lazy Binding File Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->lazy_bind_off, dec).data(),
                std::string(n.ToString(machO->dyldInfo->lazy_bind_off, hex).data()).c_str()));
    general->AddItem(
          "Lazy Binding Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->lazy_bind_size, dec).data(),
                std::string(n.ToString(machO->dyldInfo->lazy_bind_size, hex).data()).c_str()));
    general->AddItem(
          "Export File Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->export_off, dec).data(),
                std::string(n.ToString(machO->dyldInfo->export_off, hex).data()).c_str()));
    general->AddItem(
          "Export Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->dyldInfo->export_size, dec).data(),
                std::string(n.ToString(machO->dyldInfo->export_size, hex).data()).c_str()));
}

void DyldInfo::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

void DyldInfo::Update()
{
    UpdateBasicInfo();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
