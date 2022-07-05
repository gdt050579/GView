#include "JT.hpp"

using namespace GView::Type::JT;
using namespace GView::Type::JT::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Information::Information(Reference<Object> _object, Reference<GView::Type::JT::JTFile> _jt) : TabPage("Informa&tion")
{
    jt      = _jt;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:32", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });
    AddDecAndHexElement("Size", "%-20s (%s)", jt->obj->GetData().GetSize());

    general->AddItem("File header").SetType(ListViewItem::Type::Category);
    general->AddItem({ "Version", ls.Format("%s", jt->fh.version) }).SetType(ListViewItem::Type::Emphasized_1);
    AddDecAndHexElement("Byte Order", "%-20s (%s)", jt->fh.byteOrder);
    general->AddItem({ "", jt->fh.byteOrder == 0 ? "LSB" : "MSB" }).SetType(ListViewItem::Type::Emphasized_1);
    AddDecAndHexElement("Empty Field", "%-20s (%s)", jt->fh.emptyField);
    AddDecAndHexElement("TOC Offset", "%-20s (%s)", jt->fh.tocOffset);
    AddGUIDElement(general, "LSG Segment ID", jt->fh.lsgSegmentId);

    general->AddItem("TOC Segment").SetType(ListViewItem::Type::Category);
    AddDecAndHexElement("Entry Count", "%-20s (%s)", jt->tc.entryCount);

    auto totalDataSize = 0U;
    for (uint32 i = 0U; i < jt->tc.entryCount; i++)
    {
        auto& entry = jt->tc.entries.at(i);
        totalDataSize += entry.segmentLength;
    }
    AddDecAndHexElement("Total Entry Size", "%-20s (%s)", totalDataSize);
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
