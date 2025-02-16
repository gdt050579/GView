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

bool PDF::PDFFile::RunLengthDecode(const BufferView& input, Buffer& output, String& message)
{
    message.Clear();
    uint64_t inPos   = 0;
    const uint64_t n = input.GetLength();
    while (true) {
        if (inPos >= n) {
            message.Set("Not enough data to read the length byte!");
            return false;
        }
        uint8_t lengthByte = input[inPos++];
        if (lengthByte == 128) {
            break;
        }
        if (lengthByte < 128) {
            size_t literalCount = static_cast<size_t>(lengthByte) + 1;
            if (inPos + literalCount > n) {
                message.Set("Not enough data to copy literal bytes!");
                return false;
            }
            BufferView chunk(input.GetData() + inPos, literalCount);
            output.Add(chunk);
            inPos += literalCount;
        }
        else {
            if (inPos >= n) {
                message.Set("Not enough data to read the repeated byte!");
                return false;
            }
            uint8_t repeatedByte = input[inPos++];
            size_t repeatCount   = 257 - static_cast<size_t>(lengthByte);
            output.AddMultipleTimes(BufferView(&repeatedByte, 1), static_cast<uint32_t>(repeatCount));
        }
    }
    return true;
}

bool PDF::PDFFile::ASCIIHexDecode(const BufferView& input, Buffer& output, AppCUI::Utils::String& message)
{
    message.Clear();
    int16_t halfNibble = -1;
    output.Resize(0);

    const uint64_t n    = input.GetLength();
    bool foundEndMarker = false;

    for (uint64_t i = 0; i < n; i++) {
        uint8 c = input[i];

        if (c == PDF::DC::GREATER_THAN) {
            foundEndMarker = true;
            break;
        }

        if (c == PDF::WSC::SPACE || c == PDF::WSC::HORIZONAL_TAB || c == PDF::WSC::CARRIAGE_RETURN || c == PDF::WSC::LINE_FEED || c == PDF::WSC::FORM_FEED) {
            continue;
        }

        int nibble = -1;
        if (c >= '0' && c <= '9') {
            nibble = c - '0';
        } else if (c >= 'A' && c <= 'F') {
            nibble = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            nibble = c - 'a' + 10;
        } else {
            message.Set("Invalid hex digit in ASCIIHexDecode!");
            return false;
        }

        if (halfNibble == -1) {
            halfNibble = nibble;
        } else {
            int fullByte = (halfNibble << 4) | nibble;
            halfNibble   = -1;
            uint8 oneByte = static_cast<uint8>(fullByte);
            BufferView singleByte(&oneByte, 1);
            output.Add(singleByte);
        }
    }

    if (halfNibble != -1) {
        uint8 oneByte = static_cast<uint8>(halfNibble << 4);
        BufferView singleByte(&oneByte, 1);
        output.Add(singleByte);
        halfNibble = -1;
    }

    if (!foundEndMarker) {
        message.Set("Missing '>' marker in ASCIIHexDecode data!");
        return false;
    }

    return true;
}

bool PDF::PDFFile::ASCII85Decode(const BufferView& input, Buffer& output, String& message)
{
    message.Clear();
    output.Resize(0);
    const uint64_t len = input.GetLength();
    bool endOfData     = false;
    std::vector<char> accum;
    accum.reserve(5);

    // helper lambda to decode a full 5-char group into 4 bytes
    auto decodeGroup = [&](const char group[5], bool isPartial, size_t partialLen) -> bool {

        uint64_t value = 0;
        for (int i = 0; i < 5; i++) {
            uint8_t c = static_cast<uint8_t>(group[i]);
            if (c < '!' || c > 'u') {
                message.Set("Invalid ASCII85 character (not in '!'..'u').");
                return false;
            }
            uint64_t digit = c - '!';
            if (digit > 84) {
                message.Set("Invalid digit in ASCII85Decode (larger than 84).");
                return false;
            }
            value = value * 85ULL + digit;
        }
        uint8_t b[4];
        b[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        b[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        b[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        b[3] = static_cast<uint8_t>((value >> 0) & 0xFF);

        size_t outBytes = 4; // full group
        if (isPartial) {
            if (partialLen < 2 || partialLen > 4) {
                message.Set("Invalid partial ASCII85 group size (must be 2..4).");
                return false;
            }
            outBytes = partialLen - 1;
        }

        // add these 'outBytes' to output
        if (outBytes > 4) {
            message.Set("Internal error in ASCII85 partial decode size!");
            return false;
        }

        BufferView chunk(b, outBytes);
        output.Add(chunk);

        return true;
    };

    for (size_t i = 0; i < len; i++) {
        uint8_t c = input[i];

        // check for EOD marker "~>"
        if (c == '~') {
            // must check if next char is '>' or if this is truncated
            if (i + 1 < len && input[i + 1] == PDF::DC::GREATER_THAN) {
                endOfData = true;
                i++; // skip '>' too
                break;
            }
            // if not '>'
            message.Set("ASCII85Decode: '~' not followed by '>' => invalid EOD marker!");
            return false;
        }

        if (c == PDF::WSC::SPACE || c == PDF::WSC::HORIZONAL_TAB || c == PDF::WSC::CARRIAGE_RETURN || c == PDF::WSC::LINE_FEED || c == PDF::WSC::FORM_FEED) {
            continue;
        }

        // 'z' -> means 4 zero bytes -> only if accum is empty
        if (c == 'z') {
            // 'z' can only appear by itself, not in the middle of a group
            if (!accum.empty()) {
                message.Set("ASCII85Decode: 'z' found in the middle of a group => invalid.");
                return false;
            }
            uint8_t zeros[4] = { 0, 0, 0, 0 };
            BufferView chunk(zeros, 4);
            output.Add(chunk);
            continue;
        }

        // must be in range '!'..'u' or it's an error
        if (c < '!' || c > 'u') {
            message.Set("ASCII85Decode: Invalid character (not whitespace, not z, not ~>): out of '!'..'u' range.");
            return false;
        }

        accum.push_back(static_cast<char>(c));
        if (accum.size() == 5) {
            // decode
            if (!decodeGroup(accum.data(), false, 5)) {
                return false;
            }
            accum.clear();
        }
    }

    // if we never found "~>", check if that’s an error
    if (!endOfData) {
        // the PDF spec says you must end with "~>" for correct EOD
        message.Set("Missing '~>' EOD marker in ASCII85Decode data!");
        return false;
    }

    if (!accum.empty()) {
        if (accum.size() == 1) {
            message.Set("ASCII85Decode: Partial group of only 1 char => invalid.");
            return false;
        }
        while (accum.size() < 5) {
            accum.push_back('u'); //  'u' => 84 => max
        }
        if (!decodeGroup(accum.data(), true, accum.size())) {
            return false;
        }
        accum.clear();
    }
    return true;
}