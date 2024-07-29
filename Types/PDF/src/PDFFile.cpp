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