#pragma once
#include "ast.hpp"

namespace GView::Type::JS::Transformer
{
class ConstFolder : public AST::Plugin
{
  public:
    virtual AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement) override;
    virtual AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement) override;
    virtual AST::Action OnExitMemberAccess(AST::MemberAccess* node, AST::Expr*& replacement) override;
    virtual AST::Action OnExitCall(AST::Call* node, AST::Expr*& replacement);

  private:
    AST::Expr* Fold(AST::Number* left, AST::Number* right, uint32 op);
    AST::Expr* Fold(AST::Number* left, AST::String* right, uint32 op);
    AST::Expr* Fold(AST::String* left, AST::Number* right, uint32 op);
    AST::Expr* Fold(AST::String* left, AST::String* right, uint32 op);
    AST::Expr* Fold(AST::Constant* left, AST::Constant* right, uint32 op);

    AST::Action FoldBinop(AST::Binop* node, AST::Expr*& replacement);
};
} // namespace GView::Type::JS