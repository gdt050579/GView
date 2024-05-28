#include "js.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view UnrollLoop::GetName()
{
    return "Unroll Loop";
}
std::string_view UnrollLoop::GetDescription()
{
    return "Unroll loop with a fixed amount of iterations.";
}
bool UnrollLoop::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    // Only on 'for' tokens.
    auto end = std::min<>(data.tokens.Len(), data.endIndex);

    return (end - data.startIndex >= 1 && data.tokens[data.startIndex].GetTypeID(TokenType::None) == TokenType::Keyword_For);
}
GView::View::LexicalViewer::PluginAfterActionRequest UnrollLoop::Execute(GView::View::LexicalViewer::PluginData& data)
{
    auto start = data.startIndex + 1; // for ( ...
                                      // 0   1 2

    auto index = start;
    AppCUI::uint32 type;

#define ADVANCE()                                                                                                                                              \
    do {                                                                                                                                                       \
        ++index;                                                                                                                                               \
        if (index >= data.tokens.Len()) {                                                                                                                      \
            return PluginAfterActionRequest::None;                                                                                                             \
        }                                                                                                                                                      \
        type = data.tokens[index].GetTypeID(TokenType::None);                                                                                                  \
    } while (false)
    // ADVANCE

#define EXPECT(typ)                                                                                                                                            \
    do {                                                                                                                                                       \
        if (type != TokenType::typ) {                                                                                                                          \
            return PluginAfterActionRequest::None;                                                                                                             \
        }                                                                                                                                                      \
    } while (false)
    // EXPECT

    ADVANCE();

    // var/let
    if (type == TokenType::DataType_Var || type == TokenType::DataType_Let) {
        ADVANCE();
    }

    // i
    EXPECT(Word);

    auto iteratorName = data.tokens[index];

    ADVANCE();

    // =
    EXPECT(Operator_Assignment);

    ADVANCE();

    // start
    EXPECT(Number);

    AppCUI::Utils::String iteratorStartStr;
    iteratorStartStr.Set(data.tokens[index].GetText());

    auto iteratorStartOpt = AppCUI::Utils::Number::ToInt32(iteratorStartStr);

    if (!iteratorStartOpt.has_value()) {
        return PluginAfterActionRequest::None;
    }

    auto iteratorStart = iteratorStartOpt.value();

    ADVANCE();

    // ;
    EXPECT(Semicolumn);

    ADVANCE();

    // i
    EXPECT(Word);

    if (iteratorName.GetText() != data.tokens[index].GetText()) {
        return PluginAfterActionRequest::None;
    }

    ADVANCE();

    // <
    EXPECT(Operator_Smaller);

    ADVANCE();

    // end
    EXPECT(Number);

    AppCUI::Utils::String iteratorEndStr;
    iteratorEndStr.Set(data.tokens[index].GetText());

    auto iteratorEndOpt = AppCUI::Utils::Number::ToInt32(iteratorEndStr);

    if (!iteratorEndOpt.has_value()) {
        return PluginAfterActionRequest::None;
    }

    auto iteratorEnd = iteratorEndOpt.value();

    ADVANCE();

    // ;
    EXPECT(Semicolumn);

    ADVANCE();

    // i
    EXPECT(Word);

    if (iteratorName.GetText() != data.tokens[index].GetText()) {
        return PluginAfterActionRequest::None;
    }

    ADVANCE();

    // ++
    EXPECT(Operator_Increment);

    ADVANCE();

    // )
    EXPECT(ExpressionClose);

    ADVANCE();

    bool block = false;
    auto bodyStartIndex = index;

    if (type == TokenType::BlockOpen) {
        block = true;
        ADVANCE();
    }

    auto blockStart = data.tokens[index];
    auto blockEnd   = blockStart;

    std::vector<AppCUI::uint32> iteratorApparitions;

    while (index < data.tokens.Len()) {
        if (block) {
            if (type == TokenType::BlockClose) {
                // Not including '}'
                blockEnd = data.tokens[index - 1];
                break;
            }
        } else {
            if (type == TokenType::Semicolumn) {
                // Including ';'
                blockEnd = data.tokens[index];
                break;
            }
        }

        if (type == TokenType::Word && data.tokens[index].GetText() == iteratorName.GetText()) {
            auto apparitionOp = data.tokens[index].GetTokenStartOffset();

            if (!apparitionOp.has_value()) {
                return PluginAfterActionRequest::None;
            }

            iteratorApparitions.push_back(apparitionOp.value());
        }

        ++index;
        type = data.tokens[index].GetTypeID(TokenType::None);
    }

    if (index == data.tokens.Len()) {
        return PluginAfterActionRequest::None;
    }

    if (iteratorEnd < iteratorStart) {
        return PluginAfterActionRequest::None;
    }

    auto blockStartOpt = blockStart.GetTokenStartOffset();
    auto blockEndOpt   = blockEnd.GetTokenEndOffset();

    if (!blockStartOpt.has_value() || !blockEndOpt.has_value()) {
        return PluginAfterActionRequest::None;
    }

    auto iterationBlockSize = (blockEndOpt.value() - blockStartOpt.value());

    // TODO: ask the user if they still want to unroll
    // Heuristic: the resulting code should have less than 5000 characters
    if ((iteratorEnd - iteratorStart) * iterationBlockSize > 10 * 500) {
        return PluginAfterActionRequest::None;
    }

    auto unrollOffset = 0;

    // Start unrolling
    while (iteratorStart < iteratorEnd) {
        // Convert iterator value from number to u16string
        AppCUI::Utils::UnicodeStringBuilder builder;

        auto n = iteratorStart;

        do {
            builder.AddChar('0' + (n % 10));
            n /= 10;
        } while (n != 0);

        std::u16string itString;
        builder.ToString(itString);

        std::reverse(itString.begin(), itString.end());

        auto written   = 0; // Index relative to for block start
        auto apparitionBase    = blockStartOpt.value();

        // Unroll
        for (auto apparition : iteratorApparitions) {
            std::u16string_view before(blockStart.GetText().data() + written, apparition - apparitionBase);

            // Before iterator apparition
            data.editor.Insert(blockStartOpt.value() + unrollOffset, before);
            unrollOffset += apparition - apparitionBase;
            written += apparition - apparitionBase;

            // Iterator apparition
            data.editor.Insert(blockStartOpt.value() + unrollOffset, itString);
            unrollOffset += itString.size();
            written += iteratorName.GetText().size(); // We replaced the iterator name with the value

            apparitionBase = apparition + 1;
        }

        // Flush text after the final apparition
        if (iterationBlockSize - written > 0) {
            std::u16string_view end(blockStart.GetText().data() + written, iterationBlockSize - written);

            data.editor.Insert(blockStartOpt.value() + unrollOffset, end);
            unrollOffset += iterationBlockSize - written;
        }

        ++iteratorStart;
    }

    // Remove original for body, including ending '}'
    data.editor.Delete(blockStartOpt.value() + unrollOffset, iterationBlockSize);

    auto originalStartOpt = data.tokens[data.startIndex].GetTokenStartOffset();

    if (!originalStartOpt.has_value()) {
        return PluginAfterActionRequest::None;
    }

    // Remove original for
    auto originalBodyOpt = data.tokens[bodyStartIndex].GetTokenStartOffset();

    if (!originalBodyOpt.has_value()) {
        return PluginAfterActionRequest::None;
    }

    data.editor.Delete(originalStartOpt.value(), originalBodyOpt.value() - originalStartOpt.value());

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins