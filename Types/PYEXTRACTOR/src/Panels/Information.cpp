#include "pyextractor.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::PYEXTRACTOR::Panels
{
Information::Information(Reference<Object> _object, Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> _py)
    : TabPage("Informa&tion"), object(_object), py(_py)
{
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);
    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    Update();
}

void Information::UpdateGeneralInformation()
{
    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });
    AddDecAndHexElement("Size", format.data(), py->obj->GetData().GetSize());

    general->AddItem("Archive").SetType(ListViewItem::Type::Category);
    UpdateArchive();
}

void Information::UpdateArchive()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    const auto magicName = PYEXTRACTOR::GetNameForPyInstallerVersion(py->archive.version).data();
    const auto magicHex  = nf.ToString((uint32) py->archive.version, hex);
    general->AddItem({ "Version", ls.Format(format.data(), magicName, magicHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    general->AddItem(
          { "Magic", ls.Format("%.*s", sizeof(py->archive.info.magic) / sizeof(py->archive.info.magic[0]), py->archive.info.magic) });
    AddDecAndHexElement("Length Of Package", format, py->archive.info.lengthofPackage);
    AddDecAndHexElement("Toc", format, py->archive.info.toc);
    AddDecAndHexElement("Toc Len", format, py->archive.info.tocLen);

    uint32 major;
    uint32 minor;
    if (py->archive.info.pyver >= 100)
    {
        major = uint32(py->archive.info.pyver / 100);
        minor = uint32(py->archive.info.pyver % 100);
    }
    else
    {
        major = uint32(py->archive.info.pyver / 10);
        minor = uint32(py->archive.info.pyver % 10);
    }
    general->AddItem({ "Version", ls.Format("%u.%u", major, minor) });

    general->AddItem(
          { "PyLibName",
            ls.Format("%.*s", sizeof(py->archive.info.pylibname) / sizeof(py->archive.info.pylibname[0]), py->archive.info.pylibname) });
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
        return;

    issues->SetVisible(false);
    this->general->Resize(w, h);
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

void Information::OnAfterResize(int newWidth, int newHeight)
{
    RecomputePanelsPositions();
}
} // namespace GView::Type::PYEXTRACTOR::Panels
