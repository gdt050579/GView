#pragma once
#include "ast.hpp"

namespace GView::Type::JS::Transformers
{
class DynamicPropagator : public AST::Plugin
{
    std::unordered_map<std::u16string_view, AST::Expr*> map;

  public:
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);

    void AddVar(std::u16string_view name, AST::Expr* expr);
};
} // namespace GView::Type::JS::Transformers