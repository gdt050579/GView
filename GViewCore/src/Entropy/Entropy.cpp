#include "Internal.hpp"

#include <math.h>

namespace GView::Entropy
{
double ShannonEntropy(const BufferView& buffer)
{
    char frequency[256]{};

    // Count frequency of each byte in the buffer
    for (uint32 i = 0; i < buffer.GetLength(); i++) {
        const auto c = buffer[i];
        frequency[c]++;
    }

    // Calculate entropy
    double entropy = 0.0;
    for (const auto& value : frequency) {
        if (value == 0) {
            continue;
        }
        double probability = static_cast<double>(value) / buffer.GetLength();
        entropy -= probability * log2(probability);
    }

    return entropy; // max log2(n) = 8
}
} // namespace GView::Entropy
