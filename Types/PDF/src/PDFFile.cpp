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

    if (header.version_N < '5') {
        version_under_5 = true;
    } else {
        version_under_5 = false;
    }

    return true;
}