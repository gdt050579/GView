#include "ico.hpp"

using namespace GView::Type::ICO;

constexpr uint32 IMAGE_PNG_MAGIC = 0x474E5089;

ICOFile::ICOFile()
{
    isIcoFormat = false;
    dirs.reserve(64);
}

void ICOFile::UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings)
{
    LocalString<128> tempStr;

    settings.AddZone(0, sizeof(Header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
    settings.AddZone(sizeof(Header), sizeof(DirectoryEntry) * dirs.size(), ColorPair{ Color::Olive, Color::DarkBlue }, "Image entries");

    auto idx = 1;
    for (auto& e : dirs)
    {
        settings.AddZone(e.cursor.offset, e.cursor.size, ColorPair{ Color::Silver, Color::DarkBlue }, tempStr.Format("Img #%d", idx));
        idx++;
    }
}
bool ICOFile::Update()
{
    Header h;
    CHECK(this->obj->GetData().Copy<Header>(0, h), false, "");
    this->isIcoFormat = (h.magic == MAGIC_FORMAT_ICO);
    this->dirs.clear();
    size_t offset = sizeof(Header);
    for (auto i = 0U; i < h.count; i++, offset += sizeof(DirectoryEntry))
    {
        auto bf = this->obj->GetData().Get(offset, sizeof(DirectoryEntry), true);
        if (bf.Empty())
            break;
        dirs.push_back(bf.GetObject<DirectoryEntry>());
    }

    return true;
}
bool ICOFile::LoadImageToObject(Image& img, uint32 index)
{
    CHECK(index < dirs.size(), false, "Invalid image index: %u", index);
    uint64 offset = dirs[index].ico.offset;
    uint32 size   = dirs[index].ico.size;
    auto bf       = obj->GetData().Get(offset, size, true);
    Buffer buf;
    if (bf.IsValid() == false)
    {
        // unable to use the cache --> need to make a copy of the entire buffer
        buf = this->obj->GetData().CopyToBuffer(offset, size, true);
        CHECK(buf.IsValid(), false, "Fail to copy %u bytes from offset: %llu", size, offset);
        bf = (BufferView) buf;
    }
    // now `bf` points to the image buffer
    if ((bf.GetLength() >= 4) && ((*(uint32*) bf.GetData()) == IMAGE_PNG_MAGIC))
    {
        // PNG file
        CHECK(img.Create(bf), false, "");
    }
    else
    {
        // DIB
        CHECK(img.CreateFromDIB(bf, true), false, "");
    }
    return true;
}