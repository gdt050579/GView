#include "Internal.hpp"

#include <math.h>
#include <array>

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

/*
    In physics, the word entropy has important physical implications as the amount of "disorder" of a system.
    In mathematics, a more abstract definition is used.

    The (Shannon) entropy of a variable X is defined as
    H(X) congruent - sum_x P(x) log_2[P(x)]
    bits, where P(x) is the probability that X is in the state x, and P log_2 P is defined as 0 if P = 0.

    The joint entropy of variables X_1, ..., X_n is then defined by
    H(X_1, ..., X_n) congruent - sum_(x_1) ... sum_(x_n) P(x_1, ..., x_n) log_2[P(x_1, ..., x_n)].
*/
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

    return entropy; // max log2(n) = 8 (the entire sum)
}

double ShannonEntropy(const BufferView& buffer)
{
    std::array<char, MAX_NUMBER_OF_BYTES> frequency{};
    SetFrequencies(buffer, frequency);
    return ShannonEntropy_private(buffer, frequency);
}

/*
    Rényi entropy is defined as:
    H_α(p_1, p_2, ..., p_n) = 1/(1 - α) ln( sum_(i = 1)^n p_i^α), where α>0, α!=1.
    As α->1, H_α(p_1, p_2, ..., p_n) converges to H(p_1, p_2, ..., p_n), which is Shannon's measure of entropy.
    Rényi's measure satisfies
    H_α(p_1, p_2, ..., p_n)<=H_α'(p_1, p_2, ..., p_n)
    for α<=α'.
*/
double RenyiEntropy(const BufferView& buffer, double alpha)
{
    std::array<char, MAX_NUMBER_OF_BYTES> frequency{};
    SetFrequencies(buffer, frequency);

    if (alpha == 1.0) {
        return ShannonEntropy_private(buffer, frequency);
    }

    double sum = 0.0;
    for (auto f : frequency) {
        if (f > 0) {
            const double probability = static_cast<double>(f) / buffer.GetLength();
            sum += pow(probability, alpha);
        }
    }

    // Convert to bits if using log base e
    // return std::max(((1.0 / (1.0 - alpha)) * log(sum)) / log(2), 0.0);
    return ((1.0 / (1.0 - alpha)) * log(sum)) / log(2);
}
} // namespace GView::Entropy
