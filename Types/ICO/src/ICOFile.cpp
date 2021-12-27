#include "ico.hpp"

using namespace GView::Type::ICO;

ICOFile::ICOFile(Reference<GView::Utils::FileCache> fileCache)
{
    file        = fileCache;
    isIcoFormat = false;
    dirs.reserve(64);
}

void ICOFile::AddError(ErrorType type, std::string_view message)
{
    // auto& item = errList.emplace_back();
    // item.type  = type;
    // item.text  = message;
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
    CHECK(this->file->Copy<Header>(0, h), false, "");
    this->isIcoFormat = (h.magic == MAGIC_FORMAT_ICO);
    this->dirs.clear();
    size_t offset = sizeof(Header);
    for (auto i = 0U; i < h.count; i++, offset += sizeof(DirectoryEntry))
    {
        auto bf = this->file->Get(offset, sizeof(DirectoryEntry));
        if (bf.Empty())
            break;
        dirs.push_back(bf.GetObject<DirectoryEntry>());
    }

    return true;
}