#pragma once
#include "ast.hpp"

#include <stack>

namespace GView::Type::JS::Transformer
{
class FunctionHoister : public AST::Plugin
{
    std::vector<std::unordered_map<std::u16string_view, AST::VarDecl*>> vars;

    std::stack<AST::FunDecl*> funStack;
    std::vector<AST::Block*> blocks;

  public:
    struct FunInfo {
        AST::Node* anchor  = nullptr;
        size_t anchorLevel = 0;

        FunInfo() = default;
    };

    std::unordered_map<AST::FunDecl*, FunInfo> funs;

    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);
    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);
    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement);

  private:
    std::pair<AST::VarDecl*, size_t> GetVar(std::u16string_view name);
};
}