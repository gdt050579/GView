#include "csv.hpp"

using namespace GView::Type::CSV;

CSVFile::CSVFile() : panelsMask(0)
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
    this->obj = obj; //GDT: this is already set up

    if (this->obj->GetName().ends_with(u".tsv"))
    {
        separator[0] = '\t';
    }
    else if (this->obj->GetName().ends_with(u".csv"))
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
    const auto color = ColorPair{ Color::Gray, Color::Transparent };

    const auto oSize = obj->GetData().GetSize();
    const auto cSize = obj->GetData().GetCacheSize();

    auto oSizeProcessed = 0ULL;
    auto currentLine    = 0ULL;

    do
    {
        const auto buf = obj->GetData().Get(oSizeProcessed, static_cast<uint32>(cSize), false);
        const std::string_view data{ reinterpret_cast<const char*>(buf.GetData()), buf.GetLength() };

        const auto nPos = data.find_first_of('\n', 0);
        const auto rPos = data.find_first_of('\r', 0);

        const auto oldOSizeProcessed = oSizeProcessed;

        if (nPos < rPos)
        {
            if (nPos + 1 < data.size() && data[nPos + 1] == '\r')
            {
                oSizeProcessed += nPos + 2;
            }
            else
            {
                oSizeProcessed += nPos + 1;
            }
        }
        else if (nPos > rPos)
        {
            if (rPos + 1 < data.size() && data[rPos + 1] == '\n')
            {
                oSizeProcessed += rPos + 2;
            }
            else
            {
                oSizeProcessed += rPos + 1;
            }
        }
        else
        {
            throw std::runtime_error("Not enough cache to read a line!");
        }

        settings.AddZone(oldOSizeProcessed, oSizeProcessed - oldOSizeProcessed, color, std::to_string(currentLine));

        currentLine++;

    } while (oSizeProcessed < oSize);
}

void GView::Type::CSV::CSVFile::UpdateGrid(GView::View::GridViewer::Settings& settings)
{
    settings.SetSeparator(separator);
}
