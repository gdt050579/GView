#include "pdf.hpp"

using namespace GView::Type;
using namespace GView;

void PDF::PDFFile::GetPreviousRow(const Buffer& data, uint64_t offset, uint8_t* buffer, const uint64_t rowLength)
{
    if (offset >= rowLength) {
        memcpy(buffer, data.GetData() + offset - rowLength, rowLength);
    } else {
        memset(buffer, 0, rowLength);
    }
}

void PDF::PDFFile::ApplyFilter(
      Buffer& data, uint64_t offset, uint8_t* rowBuffer, const uint64_t rowLength, const uint8_t bytesPerComponent, const uint8_t predictor)
{
    PDF::PDFFile::GetPreviousRow(data, offset, rowBuffer, rowLength);

    for (uint64_t i = 0; i < rowLength; ++i) {
        uint8_t newValue       = data.GetData()[offset];
        uint8_t left           = (offset % bytesPerComponent == 0) ? 0 : data.GetData()[offset - bytesPerComponent];
        uint8_t above          = rowBuffer[i];
        uint8_t aboveLeft      = (offset >= rowLength && (offset - bytesPerComponent) >= rowLength) ? rowBuffer[i - bytesPerComponent] : 0;
        uint8_t paethPredictor = 0, p = 0, pLeft = 0, pAbove = 0, pAboveLeft = 0;

        switch (predictor) {
        case PDF::PREDICTOR::SUB:
            newValue = data.GetData()[offset] + left;
            break;
        case PDF::PREDICTOR::UP:
            newValue = data.GetData()[offset] + above;
            break;
        case PDF::PREDICTOR::AVERAGE:
            newValue = data.GetData()[offset] + ((left + above) / 2);
            break;
        case PDF::PREDICTOR::PAETH:
            paethPredictor = left + above - aboveLeft;
            p              = data.GetData()[offset] - paethPredictor;
            pLeft          = std::abs(p - left);
            pAbove         = std::abs(p - above);
            pAboveLeft     = std::abs(p - aboveLeft);
            newValue       = data.GetData()[offset] + (pLeft <= pAbove && pLeft <= pAboveLeft ? left : pAbove <= pAboveLeft ? above : aboveLeft);
            break;
        case PDF::PREDICTOR::NONE:
        case PDF::PREDICTOR::OPTIMUM:
            return; // No filtering needed for None or Optimum
        default:
            // unknown predictor
            return;
        }

        data.GetData()[offset] = newValue;
        ++offset;
    }
}

void PDF::PDFFile::ApplyPNGFilter(Buffer& data, const uint16_t& column, const uint8_t& predictor, const uint8_t& bitsPerComponent)
{
    if (!data.IsValid()) {
        return;
    }

    const uint8_t bytesPerComponent = (bitsPerComponent + 7) / 8; // ceil(bitsPerComponent / 8)
    const uint64_t rowLength        = column * bytesPerComponent + 1;
    const uint64_t dataLength       = data.GetLength();

    Buffer rowBuffer;
    rowBuffer.Resize(rowLength);

    for (uint64_t offset = 0; offset < dataLength;) {
        ApplyFilter(data, offset, rowBuffer.GetData(), rowLength, bytesPerComponent, predictor);
        offset += rowLength;
    }

    const uint64_t newSize = dataLength - (dataLength / (rowLength + 1));
    Buffer filteredData;
    filteredData.Resize(newSize);

    uint64_t srcOffset = 0;
    uint64_t dstOffset = 0;
    while (srcOffset < dataLength) {
        if (srcOffset % rowLength != 0) { // Skip filter type byte
            filteredData.GetData()[dstOffset++] = data.GetData()[srcOffset];
        }
        ++srcOffset;
    }

    data = std::move(filteredData);
}