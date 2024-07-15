#include "js.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view MarkAlwaysTrue::GetName()
{
    return "Mark Always True";
}
std::string_view MarkAlwaysTrue::GetDescription()
{
    return "Mark 'if' stamemet as always true.";
}
bool MarkAlwaysTrue::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    // Only on 'if' tokens.
    auto end = std::min<>(data.tokens.Len(), data.endIndex);

    return (end - data.startIndex >= 1 && data.tokens[data.startIndex].GetTypeID(TokenType::None) == TokenType::Keyword_If);
}
GView::View::LexicalViewer::PluginAfterActionRequest MarkAlwaysTrue::Execute(GView::View::LexicalViewer::PluginData& data)
{
    auto start = data.startIndex + 2; // if ( ...
                                      // 0  1 2

    auto index = start;
    auto paren = 1;

    while (index < data.tokens.Len()) {
        switch (data.tokens[index].GetTypeID(TokenType::None)) {
        case TokenType::ExpressionOpen: { // (
            ++paren;
            break;
        }
        case TokenType::ExpressionClose: { // )
            --paren;
            break;
        }
        default:
            break;
        }

        if (paren == 0) {
            break;
        }

        ++index;
    }

    auto left  = data.tokens[start].GetTokenStartOffset();
    auto right = data.tokens[index].GetTokenStartOffset();

    if ((left.has_value()) && (right.has_value())) {
        data.editor.Replace(left.value(), right.value() - left.value(), "true");
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins