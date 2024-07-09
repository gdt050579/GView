#include "Transformers/DynamicPropagator.hpp"

namespace GView::Type::JS::Transformers
{
AST::Action DynamicPropagator::OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
{
    if (map.find(node->name) != map.end()) {
        replacement = map[node->name]->Clone();

        return AST::Action::Replace;
    }

    return AST::Action::None;
}

void DynamicPropagator::AddVar(std::u16string_view name, AST::Expr* expr)
{
    map[name] = expr;
}
} // namespace GView::Type::JS::Transformers