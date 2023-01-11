#include "zip.hpp"

#include <queue>
#include <map>

using namespace GView::Type::ZIP;

ZIPFile::ZIPFile()
{
}

bool ZIPFile::Update()
{
    return true;
}

bool ZIPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    return true;
}

bool ZIPFile::PopulateItem(TreeViewItem item)
{
    return false;
}

void ZIPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    CHECKRET(item.GetParent().GetHandle() != InvalidItemHandle, "");

    // auto data         = item.GetData<ECMA_119_DirectoryRecord>();
    // const auto offset = (uint64) data->locationOfExtent.LSB * pvd.vdd.logicalBlockSize.LSB;
    // const auto length = (uint32) data->dataLength.LSB;
    // const auto name   = std::string_view{ data->fileIdentifier, data->lengthOfFileIdentifier };
    // const auto buffer = obj->GetData().CopyToBuffer(offset, length);
    // 
    // GView::App::OpenBuffer(buffer, name, name, GView::App::OpenMethod::BestMatch);
}
