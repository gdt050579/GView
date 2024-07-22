#include "jpg.hpp"

using namespace GView::Type::JPG;

JPGFile::JPGFile()
{
}

bool JPGFile::Update()
{
    memset(&header, 0, sizeof(header));
    memset(&app0MarkerSegment, 0, sizeof(app0MarkerSegment));
    memset(&sof0MarkerSegment, 0, sizeof(sof0MarkerSegment));

    auto& data = this->obj->GetData();

    if (!data.Copy<Header>(0, header))
        return false;
    if (!data.Copy<App0MarkerSegment>(sizeof(Header), app0MarkerSegment))
        return false;

    uint64 offset = sizeof(Header) + sizeof(App0MarkerSegment);
    while (offset < data.GetSize())
    {
        uint16 marker;
        if (!data.Copy<uint16>(offset, marker))
            return false;
        if (marker == JPG_SOF0_MARKER)
        {
            if (!data.Copy<SOF0MarkerSegment>(offset + 2, sof0MarkerSegment))
                return false;
            break;
        }
        offset += 2;
        uint16 segmentLength;
        if (!data.Copy<uint16>(offset, segmentLength))
            return false;
        offset += segmentLength;
    }

    return true;
}

bool JPGFile::LoadImageToObject(Image& img, uint32 index)
{
    Buffer buf;
    auto bf = obj->GetData().GetEntireFile();
    if (bf.IsValid() == false) {
        buf = this->obj->GetData().CopyEntireFile();
        CHECK(buf.IsValid(), false, "Fail to copy Entire file");
        bf = (BufferView) buf;
    }
    CHECK(img.Create(buf), false, "");

    return true;
}