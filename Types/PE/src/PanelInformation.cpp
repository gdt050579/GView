#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;


Panels::Information::Information(Reference<GView::Type::PE::PEFile> _pe) : TabPage("Informa&Tion")
{
    pe      = _pe;
    general = this->CreateChildControl<ListView>("x:0,y:0,w:100%,h:10", ListViewFlags::None);
    general->AddColumn("Field", TextAlignament::Left, 12);
    general->AddColumn("Value", TextAlignament::Left, 100);

    issues = this->CreateChildControl<ListView>("x:0,y:21,w:100%,h:10", ListViewFlags::HideColumns);
    issues->AddColumn("Info", TextAlignament::Left, 200);

    this->Update();
}
void Panels::Information::UpdateGeneralInformation()
{
    ItemHandle item;
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    item = general->AddItem("PE Info");
    general->SetItemType(item, ListViewItemType::Category);
    general->AddItem("File");
    //general->SetItemText(poz++, 1, (char*) pe->file->GetFileName(true));
    // size
    general->AddItem("Size", tempStr.Format("%s bytes",n.ToString(pe->file->GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()));
    // computed
    general->AddItem("Computed", tempStr.Format("%llu (0x%llX) bytes", pe->computedSize, pe->computedSize));
    // cert
    general->AddItem("Computed(Cert)", tempStr.Format("%llu (0x%llX) bytes", pe->computedWithCertificate, pe->computedWithCertificate));
    // memory
    general->AddItem("Memory", tempStr.Format("%llu (0x%llX) bytes", pe->virtualComputedSize, pe->virtualComputedSize));

    if (pe->computedSize < pe->file->GetSize()) // overlay
    {
        const auto sz = pe->file->GetSize() - pe->computedSize;
        item          = general->AddItem(
              "Overlay", tempStr.Format("%lld (0x%llX) [%3d%%] bytes", sz, sz, (uint64_t) ((sz * 100) / pe->file->GetSize())));
        general->SetItemXOffset(item, 2);
        general->SetItemType(item, ListViewItemType::WarningInformation);
    }
    if (pe->computedSize > pe->file->GetSize()) // Missing
    {
        const auto sz = pe->computedSize - pe->file->GetSize();
        item          = general->AddItem(
              "Missing", tempStr.Format("%lld (0x%llX) [%3d%%] bytes", sz, sz, (uint64_t) ((sz * 100) / pe->file->GetSize())));
        general->SetItemXOffset(item, 2);
        general->SetItemType(item, ListViewItemType::ErrorInformation);
    }

    // type
    if (pe->isMetroApp)
        general->AddItem("Type", tempStr.Format("Metro APP (%s)", pe->GetSubsystem().data()));
    else if ((pe->nth32.FileHeader.Characteristics & __IMAGE_FILE_DLL) != 0)
        general->AddItem("Type", tempStr.Format("DLL (%s)", pe->GetSubsystem().data()));
    else
        general->AddItem("Type", tempStr.Format("EXE (%s)", pe->GetSubsystem().data()));

    // machine
    general->AddItem("Machine", pe->GetMachine());

    // export Name
    if (pe->dllName)
    {
        item = general->AddItem("ExportName", pe->dllName);
        general->SetItemType(item, ListViewItemType::Emphasized_1);
    }
    // pdb folder
    if (pe->pdbName)
    {
        general->AddItem("PDB File", pe->pdbName);
    }

    // verific si language-ul
    for (const auto & r: pe->res)
    {
        if (r.Type == ResourceType::Version)
        {
            general->AddItem("Language", PEFile::LanguageIDToName(r.Language));
            break;
        }
    }

    // certificat
    //if ((pe->dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].Size > sizeof(WinCertificate)) &&
    //    (pe->dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress > 0))
    //{
    //    WinCertificate cert;
    //    if (pe->file->CopyToBuffer(pe->dirs[__IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, sizeof(cert), &cert))
    //    {
    //        switch (cert.wCertificateType)
    //        {
    //        case __WIN_CERT_TYPE_X509:
    //            tempStr.Set("X.509");
    //            break;
    //        case __WIN_CERT_TYPE_PKCS_SIGNED_DATA:
    //            tempStr.Set("PKCS SignedData");
    //            break;
    //        case __WIN_CERT_TYPE_RESERVED_1:
    //            tempStr.Set("Reserved");
    //            break;
    //        case __WIN_CERT_TYPE_TS_STACK_SIGNED:
    //            tempStr.Set("Terminal Server Protocol Stack");
    //            break;
    //        default:
    //            tempStr.Set("Unknown !!");
    //            break;
    //        };
    //        // tempStr.AddFormatedEx(" (0x%X), Revision:0x%X", cert.wCertificateType, cert.wRevision);
    //        tempStr.AddFormatedEx(" (0x%{uint16,hex}), Revision:0x%{uint16,hex}", cert.wCertificateType, cert.wRevision);
    //        general->AddItem("Certificate");
    //        general->SetItemColor(poz, SC(3 + 8, 0) | GLib::Constants::Colors::TransparentBackground);
    //        general->SetItemText(poz++, 1, tempStr.GetText());
    //    }
    //}
    if (pe->Ver.GetNrItems() > 0)
    {
        auto item = general->AddItem("Version");
        general->SetItemType(item, ListViewItemType::Category);
        // description/Copyright/Company/Comments/IntName/OrigName/FileVer/ProdName/ProdVer
        for (int tr = 0; tr < pe->Ver.GetNrItems(); tr++)
        {
            auto itemID = general->AddItem(pe->Ver.GetKey(tr)->ToStringView());
            general->SetItemText(itemID, 1, pe->Ver.GetValue(tr)->ToStringView());
        }
    }
}
void Panels::Information::UpdateIssues()
{
    pe->errList.PopulateListView(this->issues);
    // hide if no issues
    issues->SetVisible(!pe->errList.Empty());
}
void Panels::Information::RecomputePanelsPositions()
{
    int py   = 0;
    int last = 0;
    int w    = this->GetWidth();
    int h    = this->GetHeight();
    
    if ((!general.IsValid()) || (!issues.IsValid()))
        return;
    if (this->issues->IsVisible())
        last = 1;
    // if (InfoPanelCtx.pnlIcon->IsVisible()) last = 3;
    
    // resize
    if (last == 0)
    {
        this->general->Resize(w, h - py);
    }
    else
    {
        if (this->general->GetItemsCount() > 15)
        {
            this->general->Resize(w, 18);
            py += 18;
        }
        else
        {
            this->general->Resize(w, this->general->GetItemsCount() + 3);
            py += (this->general->GetItemsCount() + 3);
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
}
void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}

