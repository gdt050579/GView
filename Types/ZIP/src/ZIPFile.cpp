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
    currentItemIndex = 0;
    return this->info.GetCount() > 0;
}

bool ZIPFile::PopulateItem(TreeViewItem item)
{
    LocalString<128> tmp;
    NumericFormatter n;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::HexPrefix, 16 };

    GView::ZIP::Entry entry{ 0 };
    CHECK(this->info.GetEntry(currentItemIndex, entry), false, "");

    const auto filename = entry.GetFilename();
    item.SetText(filename);
    item.SetText(1, tmp.Format("%s (%s)", entry.GetTypeName().data(), n.ToString((uint32) entry.GetType(), NUMERIC_FORMAT).data()));
    item.SetText(2, tmp.Format("%s", n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(3, tmp.Format("%s", n.ToString(entry.GetUncompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(
          4, tmp.Format("%s (%s)", entry.GetCompressionMethodName().data(), n.ToString(entry.GetCompressedSize(), NUMERIC_FORMAT).data()));
    item.SetText(5, tmp.Format("%s", n.ToString(entry.GetDiskNumber(), NUMERIC_FORMAT).data()));
    item.SetText(6, tmp.Format("%s", n.ToString(entry.GetDiskOffset(), NUMERIC_FORMAT).data()));

    item.SetData(currentItemIndex);

    currentItemIndex++;

    return currentItemIndex != this->info.GetCount();
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
