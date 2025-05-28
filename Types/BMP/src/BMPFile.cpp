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
    if (bf.IsValid() == false) {
        // unable to use the cache --> need to make a copy of the entire buffer
        buf = this->obj->GetData().CopyEntireFile();
        CHECK(buf.IsValid(), false, "Fail to copy Entire file");
        bf = (BufferView) buf;
    }
    CHECK(img.Create(bf), false, "");

    return true;
}

GView::Utils::JsonBuilderInterface* BMPFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder     = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddUInt("ImageSize", infoHeader.imageSize);
    builder->AddUInt("Width", infoHeader.width);
    builder->AddUInt("Height", infoHeader.height);
    builder->AddUInt("BitsPerPixel", infoHeader.bitsPerPixel);
    builder->AddUInt("CompressionMethod", infoHeader.comppresionMethod);
    builder->AddUInt("NumberOfColors", infoHeader.numberOfColors);
    builder->AddUInt("NumberOfImportantColors", infoHeader.numberOfImportantColors);
    return builder;
}
