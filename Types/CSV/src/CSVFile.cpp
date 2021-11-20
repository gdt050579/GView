#include "csv.hpp"

using namespace GView::Type::CSV;

CSVFile::CSVFile(Reference<GView::Utils::FileCache> fileCache) : file(fileCache), panelsMask(0)
{
    this->panelsMask |= (1ULL << (unsigned char) Panels::IDs::Information);
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

bool GView::Type::CSV::CSVFile::HasPanel(Panels::IDs id)
{
    return (this->panelsMask & (1ULL << ((unsigned char) id))) != 0;
}

void GView::Type::CSV::CSVFile::UpdateBufferViewZones(Reference<GView::View::BufferViewerInterface> bufferView)
{
    // get every row here
    const auto color         = ColorPair{ Color::Gray, Color::Transparent };
    const auto bf            = file->Get(0, file->GetSize());
    unsigned long long rowNo = 0;
    for (auto i = 0ULL; i < file->GetSize(); i++)
    {
        if (i == file->GetSize() - 1)
        {
            bufferView->AddZone(rowNo, i, color, std::to_string(rowNo));
            rowNo++;
            break;
        }

        const auto character = bf[i];
        if (character == '\r')
        {
            const auto nextCharacter = bf[i + 1];
            if (nextCharacter == '\n')
            {
                i++;
            }
            bufferView->AddZone(rowNo, i, color, std::to_string(rowNo));
            rowNo++;
        }
    }
}
