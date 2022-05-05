#include "PCAP.hpp"

using namespace GView::Type::PCAP;
using namespace GView::Type::PCAP::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Information::Information(Reference<Object> _object, Reference<GView::Type::PCAP::PCAPFile> _pcap) : TabPage("Informa&tion")
{
    pcap    = _pcap;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });
    AddDecAndHexElement("Size", "%-20s (%s)", pcap->obj->GetData().GetSize());

    general->AddItem("Header").SetType(ListViewItem::Type::Category);

    const auto magicName = PCAP::MagicNames.at(pcap->header.magicNumber).data();
    const auto magicHex  = nf.ToString((uint32) pcap->header.magicNumber, hexUint32);
    general->AddItem({ "Magic", ls.Format("%-20s (%s)", magicName, magicHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    AddDecAndHexElement("Version Major", "%-20s (%s)", pcap->header.versionMajor);
    AddDecAndHexElement("Version Minor", "%-20s (%s)", pcap->header.versionMinor);
    AddDecAndHexElement("Thiszone", "%-20s (%s)", pcap->header.thiszone);
    AddDecAndHexElement("Sigfigs", "%-20s (%s)", pcap->header.sigfigs);
    AddDecAndHexElement("Snaplen", "%-20s (%s)", pcap->header.snaplen);

    const auto networkName        = PCAP::LinkTypeNames.at(pcap->header.network).data();
    const auto networkDescription = PCAP::LinkTypeDescriptions.at(pcap->header.network).data();
    const auto networkHex         = nf.ToString((uint32) pcap->header.network, hexUint32);
    general->AddItem({ "Network", ls.Format("%-20s (%s) %s", networkName, networkHex.data(), networkDescription) })
          .SetType(ListViewItem::Type::Emphasized_2);

    AddDecAndHexElement("Packets #", "%-20s (%s)", (uint32) pcap->packetHeaders.size()).SetType(ListViewItem::Type::Emphasized_1);
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<>(this->GetHeight(), (int) general->GetItemsCount() + 3));

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Information::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Information::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        default:
            break;
        }
    }

    return false;
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
