#include "Internal.hpp"

#include <math.h>

constexpr uint32 MAX_NUMBER_OF_BYTES = 256;

namespace GView::Entropy
{
void SetFrequencies(const BufferView& buffer, std::array<char, MAX_NUMBER_OF_BYTES>& frequency)
{
    // Count frequency of each byte in the buffer
    for (uint32 i = 0; i < buffer.GetLength(); i++) {
        const auto c = buffer[i];
        frequency[c]++;
    }
}

double ShannonEntropy_private(const BufferView& buffer, std::array<char, MAX_NUMBER_OF_BYTES>& frequency)
{
    double entropy = 0.0;
    for (auto f : frequency) {
        if (f == 0) {
            continue;
        }
        double probability = static_cast<double>(f) / buffer.GetLength();
        entropy -= probability * log2(probability);
    }

    return entropy; // max log2(n) = 8
}

double ShannonEntropy(const BufferView& buffer)
{
    std::array<char, MAX_NUMBER_OF_BYTES> frequency{};
    SetFrequencies(buffer, frequency);
    return ShannonEntropy_private(buffer, frequency);
}

double RenyiEntropy(const BufferView& buffer, double alpha)
{
    std::array<char, MAX_NUMBER_OF_BYTES> frequency{};
    SetFrequencies(buffer, frequency);

    if (alpha == 1.0) {
        return ShannonEntropy_private(buffer, frequency);
    }

    double sum = 0.0;
    for (auto f : frequency) {
        double probability = static_cast<double>(f) / buffer.GetLength();
        if (probability > 0) {
            sum += pow(probability, alpha);
        }
    }

    // Convert to bits if using log base e
    return ((1.0 / (1.0 - alpha)) * log(sum)) / log(2);
}
} // namespace GView::Entropy
