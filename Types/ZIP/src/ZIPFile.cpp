#include "zip.hpp"

#include <queue>
#include <map>

namespace GView::Type::ZIP
{

ZIPFile::ZIPFile()
{
}

bool ZIPFile::Update()
{
    CHECK(GView::ZIP::GetInfo(obj->GetPath(), this->info), false, "");
    return true;
}

bool ZIPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    const auto count = this->info.GetCount();
    CHECK(count > 0, false, "");

    currentItemIndex = 0;
    curentChildIndexes.clear();

    if (path.empty())
    {
        for (uint32 i = 0; i < count; i++)
        {
            GView::ZIP::Entry entry{ 0 };
            CHECK(this->info.GetEntry(i, entry), false, "");

            auto filename        = entry.GetFilename();
            const auto entryType = entry.GetType();

            if (entryType == GView::ZIP::EntryType::Directory)
            {
                if (filename.find_first_of('/') == filename.size() - 1)
                {
                    curentChildIndexes.push_back(i);
                }
            }
        }

        if (curentChildIndexes.empty())
        {
            curentChildIndexes.reserve(count);
            for (uint32 i = 0; i < count; i++)
            {
                curentChildIndexes.push_back(i);
            }
        }

        return currentItemIndex != this->curentChildIndexes.size();
    }

    UnicodeStringBuilder usb;
    for (uint32 i = 0; i < count; i++)
    {
        GView::ZIP::Entry entry{ 0 };
        CHECK(this->info.GetEntry(i, entry), false, "");

        auto filename        = entry.GetFilename();
        const auto entryType = entry.GetType();

        if (entryType == GView::ZIP::EntryType::Directory)
        {
            if (filename[filename.size() - 1] == '/')
            {
                filename = { filename.data(), filename.size() - 1 };
            }
        }

        CHECK(usb.Set(filename), false, "");

        const auto sv = usb.ToStringView();
        if (sv != path && usb.ToStringView().starts_with(path))
        {
            curentChildIndexes.push_back(i);
        }
    }

    return currentItemIndex != this->curentChildIndexes.size();
}

bool ZIPFile::PopulateItem(TreeViewItem item)
{
    LocalString<128> tmp;
    NumericFormatter n;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::HexPrefix, 16 };

    const auto realIndex = curentChildIndexes.at(currentItemIndex);
    GView::ZIP::Entry entry{ 0 };
    CHECK(this->info.GetEntry(realIndex, entry), false, "");

    auto filename = entry.GetFilename();

    const auto entryType = entry.GetType();
    item.SetPriority(entryType == GView::ZIP::EntryType::Directory);
    item.SetExpandable(entryType == GView::ZIP::EntryType::Directory);

    if (entryType == GView::ZIP::EntryType::Directory)
    {
        if (filename[filename.size() - 1] == '/')
        {
            filename = { filename.data(), filename.size() - 1 };
        }
    }

    const auto f = filename.find_last_of('/');
    if (f != std::string::npos)
    {
        filename = { filename.data() + f + 1, filename.size() - f - 1 };
    }

    item.SetText(filename);
    item.SetText(1, tmp.Format("%s (%s)", entry.GetTypeName().data(), n.ToString((uint32) entryType, NUMERIC_FORMAT).data()));
    item.SetText(2, tmp.Format("%s", n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(3, tmp.Format("%s", n.ToString(entry.GetUncompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(
          4, tmp.Format("%s (%s)", entry.GetCompressionMethodName().data(), n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(5, tmp.Format("%s", n.ToString(entry.GetDiskNumber(), NUMERIC_FORMAT).data()));
    item.SetText(6, tmp.Format("%s", n.ToString(entry.GetDiskOffset(), NUMERIC_FORMAT).data()));

    item.SetData(realIndex);

    currentItemIndex++;

    return currentItemIndex != this->curentChildIndexes.size();
}

void ZIPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    const auto index = item.GetData(-1);
    CHECKRET(index != -1, "");
    GView::ZIP::Entry entry{ 0 };
    CHECKRET(this->info.GetEntry((uint32) index, entry), "");

    const auto name = entry.GetFilename();
    Buffer buffer{};
    CHECKRET(this->info.Decompress(buffer, (uint32) index), "");

    GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch);
}
} // namespace GView::Type::ZIP
