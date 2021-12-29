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

bool GView::Type::CSV::CSVFile::Update(Reference<GView::Object> obj)
{
    this->obj = obj;
    std::string name{ this->obj->name };

    if (name.ends_with(".tsv"))
    {
        separator = '\t';
    }
    else if (name.ends_with(".csv"))
    {
        separator = ',';
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
    const auto color         = ColorPair{ Color::Gray, Color::Transparent };
    const auto bf            = file->Get(0, static_cast<unsigned int>(file->GetSize()));
    unsigned long long rowNo = 0;
    for (auto i = 0ULL; i < file->GetSize(); i++)
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
    // TODO: it's bad reading the entire content -> implement a read line or something
    file->SetCurrentPos(0);
    const auto buffer = file->CopyToBuffer(0, static_cast<unsigned int>(file->GetSize()));

    for (auto i = 0; i < buffer.GetLength() && buffer[i] != '\n'; i++)
    {
        if (buffer[i] == separator)
        {
            columnsNo++;
        }
    }
    columnsNo++;

    for (auto i = 0; i < buffer.GetLength(); i++)
    {
        if (buffer[i] == '\n')
        {
            rowsNo++;
        }
    }

    data.clear();
    data.reserve(rowsNo);

    auto i = 0ULL;
    while (i < buffer.GetLength())
    {
        data.push_back({});
        data.back().reserve(columnsNo);

        auto s = i;
        auto e = i;

        while (buffer[e] != '\r' && buffer[e] != '\n' && e < buffer.GetLength())
        {
            if (buffer[e] == separator || buffer[e] == '\r' || buffer[e] == '\n' || e == buffer.GetLength() - 1)
            {
                std::string_view v{ reinterpret_cast<char*>(buffer.GetData()) + s, e - s };
                data.back().emplace_back(v);

                s = e + 1;
            }
            e++;
        }

        std::string_view v{ reinterpret_cast<char*>(buffer.GetData()) + s, e - s };
        data.back().emplace_back(v);

        i = e;
        while ((buffer[i] == '\r' || buffer[i] == '\n') && i < buffer.GetLength())
        {
            i++;
        }
    }

    settings.SetDimensions(rowsNo, columnsNo);
    settings.SetContent(&data);
}
