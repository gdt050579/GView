#pragma once
#include "ast.hpp"

namespace GView::Type::JS::Transformer
{
class DummyCodeRemover : public AST::Plugin
{
    struct VarInfo {
        bool used = false;
        AST::Node* node;
        AST::VarDeclList* parent = nullptr;

        std::vector<AST::Node*> assignments;
    };

    std::vector<std::unordered_map<std::u16string_view, VarInfo>> vars;

    bool exprStmtHasSideEffects = false;
    AST::VarDeclList* varDeclList = nullptr;

  public:
    std::vector<AST::Node*> dummy;

    AST::Action OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacement);
    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);
    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement);
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);
    AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement);
    AST::Action OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement);
    AST::Action OnExitExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterCall(AST::Call* node, AST::Expr*& replacement);

    VarInfo* GetVarValue(std::u16string_view name);

    std::unordered_map<std::u16string_view, VarInfo>* GetVarScope(std::u16string_view name);
};

class DummyCodePostRemover : public AST::Plugin
{
    std::vector<AST::Node*>& dummy;

  public:
    DummyCodePostRemover(std::vector<AST::Node*>& dummy);

    AST::Action OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacement);
    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement);

private:
    AST::Action CheckDummy(AST::Node* node);
};
} // namespace GView::Type::JS::Transformer