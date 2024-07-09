#pragma once
#include "ast.hpp"

namespace GView::Type::JS::Transformer
{
class DeadCodeRemover : public AST::Plugin
{
    bool dead = false;

    AST::Action CheckDead();

    bool IsConstIf(AST::IfStmt* node);

    bool IsConstWhile(AST::WhileStmt* node);

  public:
    AST::Action OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacemente);
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);
    AST::Action OnEnterIfStmt(AST::IfStmt* node, AST::Stmt*& replacement);

    AST::Action OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement);

    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement);
    AST::Action OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement);
    AST::Action OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement);
};
}