#include "MachO.hpp"

namespace GView::Type::MachO::Panels
{
using namespace AppCUI::Controls;

IdDylib::IdDylib(Reference<MachOFile> _machO) : TabPage("&IdDylib")
{
    machO   = _machO;
    general = CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    Update();
}

void IdDylib::UpdateGeneralInformation()
{
    ItemHandle item;
    LocalString<256> tmp;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("ID DYLIB");
    general->SetItemType(item, ListViewItemType::Category);

    static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
    static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

    general->AddItem(
          "Command",
          tmp.Format(
                "%s (%s)",
                std::string(MAC::LoadCommandNames.at(machO->idDylib.value.cmd)).c_str(),
                std::string(n.ToString(static_cast<uint32_t>(machO->idDylib.value.cmd), hex).data()).c_str()));

    general->AddItem(
          "Cmd Size",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->idDylib.value.cmdsize, dec).data(),
                std::string(n.ToString(machO->idDylib.value.cmdsize, hex).data()).c_str()));

    general->AddItem("Name", machO->idDylib.name.c_str());

    general->AddItem(
          "Name Offset",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->idDylib.value.dylib.name.offset, dec).data(),
                std::string(n.ToString(machO->idDylib.value.dylib.name.offset, hex).data()).c_str()));

    if (machO->is64)
    {
        general->AddItem(
              "Name Ptr",
              tmp.Format(
                    "%s (%s)",
                    n.ToString((uintptr_t) (machO->idDylib.value.dylib.name.ptr), dec).data(),
                    std::string(n.ToString((uintptr_t) (machO->idDylib.value.dylib.name.ptr), hex).data()).c_str()));
    }

    general->AddItem(
          "Timestamp",
          tmp.Format(
                "%s (%s)",
                n.ToString(machO->idDylib.value.dylib.timestamp, dec).data(),
                std::string(n.ToString(machO->idDylib.value.dylib.timestamp, hex).data()).c_str()));
    general->AddItem(
          "Current Version",
          tmp.Format(
                "%u.%u.%u (%s)",
                machO->idDylib.value.dylib.current_version >> 16,
                (machO->idDylib.value.dylib.current_version >> 8) & 0xff,
                machO->idDylib.value.dylib.current_version & 0xff,
                std::string(n.ToString(machO->idDylib.value.dylib.current_version, hex).data()).c_str()));
    general->AddItem(
          "Compatibility Version",
          tmp.Format(
                "%u.%u.%u (%s)",
                machO->idDylib.value.dylib.compatibility_version >> 16,
                (machO->idDylib.value.dylib.compatibility_version >> 8) & 0xff,
                machO->idDylib.value.dylib.compatibility_version & 0xff,
                std::string(n.ToString(machO->idDylib.value.dylib.compatibility_version, hex).data()).c_str()));
}

void IdDylib::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

void IdDylib::Update()
{
    UpdateGeneralInformation();
    RecomputePanelsPositions();
}
} // namespace GView::Type::MachO::Panels
