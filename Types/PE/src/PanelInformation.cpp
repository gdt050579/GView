#include "pe.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::PE::Panels
{
Information::Information(Reference<Object> _object, Reference<GView::Type::PE::PEFile> _pe) : TabPage("Informa&Tion")
{
    object = _object;
    pe     = _pe;

    general   = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:10", { "n:Field,w:30", "n:Value,w:100" }, ListViewFlags::None);
    imageView = Factory::ImageView::Create(this, "Icon", "x:0,y:11,w:100%,h:16", ViewerFlags::Border);
    imageView->SetVisible(false);
    issues = Factory::ListView::Create(this, "x:0,y:21,w:100%,h:10", { "n:Info,w:200" }, ListViewFlags::HideColumns);

    Update();
}

void Information::UpdateGeneralInformation()
{
    ListViewItem item;
    LocalString<256> tmp;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("PE Info");
    item.SetType(ListViewItem::Type::Category);
    general->AddItem({ "File", object->GetName() });

    general->AddItem(
          { "Size", tmp.Format("%s bytes", n.ToString(pe->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) });
    general->AddItem({ "Computed", tmp.Format("%llu (0x%llX) bytes", pe->computedSize, pe->computedSize) });
    general->AddItem({ "Computed(Cert)", tmp.Format("%llu (0x%llX) bytes", pe->computedWithCertificate, pe->computedWithCertificate) });
    general->AddItem({ "Memory", tmp.Format("%llu (0x%llX) bytes", pe->virtualComputedSize, pe->virtualComputedSize) });

    if (pe->computedSize < pe->obj->GetData().GetSize()) // overlay
    {
        const auto sz = pe->obj->GetData().GetSize() - pe->computedSize;
        item          = general->AddItem(
              { "Overlay", tmp.Format("%lld (0x%llX) [%3d%%] bytes", sz, sz, (uint64_t) ((sz * 100) / pe->obj->GetData().GetSize())) });
        item.SetXOffset(2);
        item.SetType(ListViewItem::Type::Emphasized_1);
    }

    if (pe->computedSize > pe->obj->GetData().GetSize()) // Missing
    {
        const auto sz = pe->computedSize - pe->obj->GetData().GetSize();
        item          = general->AddItem(
              { "Missing", tmp.Format("%lld (0x%llX) [%3d%%] bytes", sz, sz, (uint64_t) ((sz * 100) / pe->obj->GetData().GetSize())) });
        item.SetXOffset(2);
        item.SetType(ListViewItem::Type::ErrorInformation);
    }

    std::string_view format;
    if (pe->isMetroApp)
    {
        format = "Metro APP (%s)";
    }
    else if ((pe->nth32.FileHeader.Characteristics & __IMAGE_FILE_DLL) != 0)
    {
        format = "DLL (%s)";
    }
    else
    {
        format = "EXE (%s)";
    }
    general->AddItem({ "Type", tmp.Format(format.data(), pe->GetSubsystem().data()) });

    general->AddItem({ "Machine", pe->GetMachine() });

    if (pe->dllName)
    {
        general->AddItem({ "ExportName", pe->dllName }).SetType(ListViewItem::Type::Emphasized_1);
    }

    if (pe->pdbName)
    {
        general->AddItem({ "PDB File", pe->pdbName }).SetType(ListViewItem::Type::Emphasized_3);
    }

    // verific si language-ul
    for (const auto& r : pe->res)
    {
        if (r.Type == ResourceType::Version)
        {
            general->AddItem({ "Language", PEFile::LanguageIDToName(r.Language) });
            break;
        }
    }

    SetCertificate();

    if (pe->Ver.GetNrItems() > 0)
    {
        general->AddItem("Version").SetType(ListViewItem::Type::Category);
        // description/Copyright/Company/Comments/IntName/OrigName/FileVer/ProdName/ProdVer
        for (int tr = 0; tr < pe->Ver.GetNrItems(); tr++)
        {
            auto itemID = general->AddItem(pe->Ver.GetKey(tr)->ToStringView());
            itemID.SetText(1, pe->Ver.GetValue(tr)->ToStringView());
        }
    }

    ChooseIcon();
}

void Information::SetCertificate()
{
    LocalString<256> tmp;
    NumericFormatter n;

    const auto secVA = pe->dirs[(uint8) DirectoryType::Security].VirtualAddress;
    if ((pe->dirs[(uint8) DirectoryType::Security].Size > sizeof(WinCertificate)) && (secVA > 0))
    {
        WinCertificate cert{};
        if (pe->obj->GetData().Copy<WinCertificate>(secVA, cert))
        {
            switch (cert.wCertificateType)
            {
            case __WIN_CERT_TYPE_X509:
                tmp.Set("X.509");
                break;
            case __WIN_CERT_TYPE_PKCS_SIGNED_DATA:
                tmp.Set("PKCS SignedData");
                break;
            case __WIN_CERT_TYPE_RESERVED_1:
                tmp.Set("Reserved");
                break;
            case __WIN_CERT_TYPE_TS_STACK_SIGNED:
                tmp.Set("Terminal Server Protocol Stack");
                break;
            default:
                tmp.Set("Unknown !!");
                break;
            };

            tmp.AddFormat(" (0x%s)", n.ToString(cert.wCertificateType, { NumericFormatFlags::None, 10, 3, ',' }).data());
            tmp.AddFormat(", Revision: 0x%s", n.ToString(cert.wRevision, { NumericFormatFlags::None, 10, 3, ',' }).data());
            general->AddItem({ "Certificate", tmp }).SetType(ListViewItem::Type::Emphasized_1);
        }
    }
}

void Information::ChooseIcon()
{
    CHECKRET(imageView.IsValid() && imageView->IsVisible() == false, "");

    std::vector<PEFile::ResourceInformation*> resources;
    for (auto& r : pe->res)
    {
        if (r.Type != ResourceType::Icon)
            continue;

        if (r.Image.type != PEFile::ImageType::DIB)
            continue;

        if (r.Image.width >= 20 && r.Image.width <= 64 && r.Image.height >= 20 && r.Image.height <= 64)
        {
            resources.push_back(&r);
        }
    }

    if (resources.empty() == false)
    {
        std::sort(
              resources.begin(),
              resources.end(),
              [](PEFile::ResourceInformation* a, PEFile::ResourceInformation* b)
              {
                  if (a->Image.width == b->Image.width)
                  {
                      return a->Image.bitsPerPixel < b->Image.bitsPerPixel;
                  }

                  return a->Image.width < b->Image.width;
              });

        const auto r = resources.at(0);
        SetIcon(*r);
        iconSize = std::min<>(imageView->GetHeight() * 2 - (int32) (issues.IsValid() ? 6 : 0), (int32) r->Image.height / 2);
        imageView->SetVisible(true);
    }
    else
    {
        for (auto& r : pe->res)
        {
            if (r.Type != ResourceType::Icon)
                continue;

            if (r.Image.type != PEFile::ImageType::DIB)
                continue;

            SetIcon(r);
            iconSize = std::min<>(imageView->GetHeight() * 2 - (int32) (issues.IsValid() ? 6 : 0), (int32) r.Image.height / 2);
            imageView->SetVisible(true);
            break;
        }
    }
}

void Information::UpdateIssues()
{
    pe->errList.PopulateListView(this->issues);
    issues->SetVisible(!pe->errList.Empty());
}

void Information::RecomputePanelsPositions()
{
    int32 py   = 0;
    int32 last = 0;
    int32 w    = this->GetWidth();
    int32 h    = this->GetHeight();

    if ((!general.IsValid()) || (!issues.IsValid()))
    {
        return;
    }

    if (this->issues->IsVisible())
    {
        last = 1;
    }

    // resize
    if (last == 0)
    {
        this->general->Resize(w, std::min<>(h - py - iconSize, (int32) this->general->GetItemsCount() + 3));
    }
    else
    {
        if (this->general->GetItemsCount() > 15)
        {
            this->general->Resize(w, 18);
            py += 18 + iconSize;
        }
        else
        {
            this->general->Resize(w, this->general->GetItemsCount() + 3);
            py += (this->general->GetItemsCount() + 3) + iconSize;
        }
    }

    if (this->issues->IsVisible())
    {
        this->issues->MoveTo(0, py);
        if (last == 1)
        {
            this->issues->Resize(w, h - py);
        }
        else
        {
            if (this->issues->GetItemsCount() > 6)
            {
                this->issues->Resize(w, 8);
                py += 8;
            }
            else
            {
                this->issues->Resize(w, this->issues->GetItemsCount() + 2);
                py += (this->issues->GetItemsCount() + 2);
            }
        }
    }

    if (imageView.IsValid() && imageView->IsVisible())
    {
        imageView->Resize(imageView->GetWidth(), iconSize);
        this->imageView->MoveTo(this->general->GetX(), this->general->GetHeight());
    }
}

void Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

void Information::SetIcon(const PEFile::ResourceInformation& ri)
{
    AppCUI::Graphics::Image img;
    if (pe->LoadIcon(ri, img))
    {
        this->imageView->SetImage(img, ImageRenderingMethod::PixelTo16ColorsSmallBlock, ImageScaleMethod::NoScale);
        this->imageView->SetVisible(true);
    }
}
} // namespace GView::Type::PE::Panels
