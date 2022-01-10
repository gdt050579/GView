#include "csv.hpp"

using namespace GView::Type::CSV;

CSVFile::CSVFile(Reference<GView::Utils::FileCache> fileCache) : file(fileCache), panelsMask(0)
{
    this->panelsMask |= (1ULL << (unsigned char) Panels::IDs::Information);
}

std::string_view CSVFile::CSVFile::GetTypeName()
{
    if (separator[0] == ',')
    {
        return "CSV";
    }
    else if (separator[0] == '\t')
    {
        return "TSV";
    }

    return "Unknown";
}

bool GView::Type::CSV::CSVFile::Update(Reference<GView::Object> obj)
{
    this->obj = obj;
    std::string name{ this->obj->name };

    if (name.ends_with(".tsv"))
    {
        separator[0] = '\t';
    }
    else if (name.ends_with(".csv"))
    {
        separator[0] = ',';
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

void GView::Type::CSV::CSVFile::UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings)
{
    // get every row here
    const auto color = ColorPair{ Color::Gray, Color::Transparent };
    // GDT: possible problem here (for large files only the cache will be returned)
    const auto bf            = file->Get(0, static_cast<unsigned int>(file->GetSize()), false);
    unsigned long long rowNo = 0;
    for (auto i = 0ULL; i < file->GetSize() && i < bf.GetLength(); i++) // TODO: fix this
    {
        if (i == file->GetSize() - 1)
        {
            settings.AddZone(rowNo, i, color, std::to_string(rowNo));
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
            settings.AddZone(rowNo, i, color, std::to_string(rowNo));
            rowNo++;
        }
        else if (character == '\n')
        {
            settings.AddZone(rowNo, i, color, std::to_string(rowNo));
            rowNo++;
        }
    }
}

void GView::Type::CSV::CSVFile::UpdateGrid(GView::View::GridViewer::Settings& settings)
{
    settings.SetSeparator(separator);
}
