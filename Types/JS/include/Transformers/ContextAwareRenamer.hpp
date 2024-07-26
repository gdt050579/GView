#pragma once
#include "ast.hpp"
#include <unordered_set>

namespace GView::Type::JS::Transformer
{
class ContextAwareRenamer : public AST::Plugin
{
    enum class Context { Generic, Assignment, FunDecl };

    struct RenameInfo {
        std::u16string newName;
        bool initialized;

        std::vector<AST::Node*> lateReferences;
    };

    struct BlockInfo {
        std::unordered_map<std::u16string, RenameInfo> map;
        std::unordered_set<std::u16string> taken;
    };

    Context context;
    std::vector<BlockInfo> vars;

    // Context::Assignment
    std::u16string assignmentName;

  public:
    std::unordered_map<AST::Node*, std::u16string> lateRenameNodes;

    ContextAwareRenamer();

    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement);
    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement);

    AST::Action OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement);
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);
    AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement);
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement);

    AST::Action OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement);
    AST::Action OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement);

    virtual AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement) override;
    virtual AST::Action OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement) override;
    virtual AST::Action OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement) override;

  private:
    // Guess the variable purpose from its initialization expression
    const char16_t* NameBaseFromExpr(AST::Expr* expr);

    std::u16string GetNextFreeName(const char16_t* base);

    std::unordered_map<std::u16string, RenameInfo>* GetVariableBlock(std::u16string& name);

    bool VariableIsTaken(std::u16string& name);
};

class ContextAwareLateRenamer : public AST::Plugin
{
    std::unordered_map<AST::Node*, std::u16string>& lateReferences;

  public:
    ContextAwareLateRenamer(std::unordered_map<AST::Node*, std::u16string>& lateReferences);

    AST::Action OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement);

    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);
};
} // namespace GView::Type::JS::Transformer