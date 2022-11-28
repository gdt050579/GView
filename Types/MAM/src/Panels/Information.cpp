#include "MAM.hpp"

using namespace GView::Type::MAM;
using namespace GView::Type::MAM::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::Controls;

Information::Information(Reference<Object> _object, Reference<GView::Type::MAM::MAMFile> _mam) : TabPage("Informa&tion")
{
    mam     = _mam;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });

    const auto fileSize    = nf.ToString(mam->obj->GetData().GetSize(), dec);
    const auto hexfileSize = nf2.ToString(mam->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()) });

    general->AddItem("Content").SetType(ListViewItem::Type::Category);

    const auto signature    = nf.ToString(mam->signature, dec);
    const auto hexSignature = nf2.ToString(mam->signature, hex);
    general->AddItem({ "Signature", ls.Format("%-14s (%s)", signature.data(), hexSignature.data()) });

    const auto uncompressedSize    = nf.ToString(mam->uncompressedSize, dec);
    const auto hexUncompressedSize = nf2.ToString(mam->uncompressedSize, hex);
    general->AddItem({ "Uncompressed Size", ls.Format("%-14s (%s)", uncompressedSize.data(), hexUncompressedSize.data()) });

    const auto compressedSize    = nf.ToString(mam->compressedSize, dec);
    const auto hexCompressedSize = nf2.ToString(mam->compressedSize, hex);
    general->AddItem({ "Compressed Size", ls.Format("%-14s (%s)", compressedSize.data(), hexCompressedSize.data()) });
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");
    general->Resize(GetWidth(), general->GetItemsCount() + 3);
}

bool Information::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
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
