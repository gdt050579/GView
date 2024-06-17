#pragma once
#include "ast.hpp"

namespace GView::Type::JS::Transformer
{
class FunctionInliner : public AST::Plugin
{
    struct FunInfo {
        AST::Expr* returnValue = nullptr;

        std::vector<AST::Identifier*> params;
    };

    std::vector<std::unordered_map<std::u16string_view, FunInfo>> funs;

  public:
    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterCall(AST::Call* node, AST::Expr*& replacement);
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);
    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement);

  private:
    FunInfo* GetFun(std::u16string_view name);
};
}