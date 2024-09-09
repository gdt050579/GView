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
    // TODO: BeginIteration for each item which is SetExpandable
    index = 0;
    return true;
}

bool PDFFile::PopulateItem(TreeViewItem item)
{
    LocalString<128> tmp;
    NumericFormatter n;
    
    if (trailer_processed) {
        if (objectNodeRoot.type == PDFObjectType::Trailer) {
            item.SetText(0, "Trailer");
            item.SetText(1, "Dictionary");
        }

        item.SetText(2, String().Format("%u", objectNodeRoot.offset));
        item.SetText(3, String().Format("%u", objectNodeRoot.size));
        item.SetData<ObjectNode>(&objectNodeRoot);
        trailer_processed = false;
        //item.SetExpandable(true);
    } else {
        auto& obj = objectNodeRoot.keyValues[index];

        item.SetText(0, obj.key);
        if (obj.keyType == PDFObjectType::Dictionary) {
            item.SetText(1, "Dictionary");
        } else if (obj.keyType == PDFObjectType::Name) {
            item.SetText(1, "Name");
        }
        item.SetText(2, String().Format("%u", obj.offset));
        item.SetText(3, String().Format("%u", obj.key.GetLength()));
        index++;
    }

    /*if (objectNodeRoot.children.size() > 0) {
        item.SetExpandable(true);
        for (auto& obj : objectNodeRoot.children) {
            item.SetText(0, obj.object);
            item.SetText(1, obj.value);
            if (obj.type == PDFObjectType::Dictionary) {
                item.SetText(2, "Dictionary");
            } else if (obj.type == PDFObjectType::Name) {
                item.SetText(2, "Name");
            }
            item.SetText(3, String().Format("%u", obj.offset));
            item.SetText(4, String().Format("%u", obj.size));
        }
    }*/

    return index < objectNodeRoot.keyValues.size();
}

void PDFFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    // TODO: open stream content in a new window for each obj
}