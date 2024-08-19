#include "pdf.hpp"

using namespace GView::Type::PDF;

PDFFile::PDFFile()
{
}

bool PDFFile::Update()
{
    memset(&header, 0, sizeof(Header));

    auto& data = this->obj->GetData();
    CHECK(data.Copy<Header>(0, header), false, "");

    versionUnder5 = (header.versionN < '5');

    return true;
}

void PDFFile::AddPDFObject(Reference<GView::Type::PDF::PDFFile> pdf, const PDFObject& obj)
{
    auto it = std::lower_bound(
          pdf->pdfObjects.begin(), pdf->pdfObjects.end(), obj, [](const PDFObject& a, const PDFObject& b) { return a.startBuffer < b.startBuffer; });

    pdf->pdfObjects.insert(it, obj);
}

bool PDFFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    return true;
}

bool PDFFile::PopulateItem(TreeViewItem item)
{
    return true;
}

void PDFFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
}