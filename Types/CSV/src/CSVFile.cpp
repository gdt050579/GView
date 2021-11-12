#include "csv.hpp"

using namespace GView::Type::CSV;

CSVFile::CSVFile(Reference<GView::Utils::FileCache> fileCache) : file(fileCache)
{
}

std::string_view CSVFile::CSVFile::GetTypeName()
{
    return "CSV";
}

bool GView::Type::CSV::CSVFile::Update()
{
    if (this->file->GetExtension() == ".tsv")
    {
        this->separator = '\t';
    }
    else if (this->file->GetExtension() == ".csv")
    {
        this->separator = ',';
    }
    else
    {
        return false;
    }

    return true;
}
