#include "csv.hpp"

using namespace GView::Type::CSV;

CSVFile::CSVFile(Reference<GView::Utils::FileCache> fileCache) : file(fileCache)
{
}

std::string_view CSVFile::CSVFile::GetTypeName()
{
    return "CSV";
}
