#include "bmp.hpp"

using namespace GView::Type::BMP;

constexpr uint32 IMAGE_PNG_MAGIC = 0x474E5089;

BMPFile::BMPFile()
{
}

bool BMPFile::Update()
{
    memset(&header, 0, sizeof(header));
    memset(&infoHeader, 0, sizeof(infoHeader));

    CHECK(this->obj->GetData().Copy<Header>(0, header), false, "");
    CHECK(this->obj->GetData().Copy<InfoHeader>(sizeof(Header), infoHeader), false, "");

    return true;
}
bool BMPFile::LoadImageToObject(Image& img, uint32 index)
{
    Buffer buf;
    auto bf = obj->GetData().GetEntireFile();
    if (bf.IsValid() == false)
    {
        // unable to use the cache --> need to make a copy of the entire buffer
        buf = this->obj->GetData().CopyEntireFile();
        CHECK(buf.IsValid(), false, "Fail to copy Entire file");
        bf = (BufferView) buf;
    }
    CHECK(img.Create(bf), false, "");

    return true;
}