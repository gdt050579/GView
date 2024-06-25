#include "Transformers/DummyCodeRemover.hpp"

namespace GView::Type::JS::Transformer
{
AST::Action DummyCodeRemover::OnEnterBlock(AST::Block* node, AST::Block*& replacement)
{
    vars.emplace_back();
    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnExitBlock(AST::Block* node, AST::Block*& replacement)
{
    for (auto& var : vars[vars.size() - 1]) {
        if (!var.second.used) {
            if (var.second.parent) {
                // TODO: support multiple declarations in the same list
                if (var.second.parent->decls.size() != 1) {
                    continue;
                }

                dummy.push_back(var.second.parent);
            } else {
                // Function decl
                dummy.push_back(var.second.node);
            }

            dummy.insert(dummy.end(), var.second.assignments.begin(), var.second.assignments.end());
        }
    }

    vars.pop_back();
    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
{
    if (node->stmt->GetStmtType() == AST::StmtType::Block) {
        auto block = (AST::Block*) node->stmt;

        if (block->decls.empty()) {
            return AST::Action::Remove;
        }
    }

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacement)
{
    varDeclList = node;
    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
{
    auto& entry = vars[vars.size() - 1][node->name];
    entry.node  = node;
    entry.parent = varDeclList;

    if (node->init) {
        // entry.assignments.emplace_back(node->init);
    }

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
{
    auto& entry = vars[vars.size() - 1][node->name];
    entry.node  = node;

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
{
    auto var = GetVarValue(node->name);

    if (var == nullptr) {
        return AST::Action::None;
    }

    if (inAssignment) {
        inAssignment = false;
    } else {
        var->used = true;
        var->assignments.clear();
    }

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterBinop(AST::Binop* node, AST::Expr*& replacement)
{
    if (node->type >= TokenType::Operator_Assignment && node->type < TokenType::Operator_LogicNullishAssignment) {
        inAssignment = true;
    }

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnExitBinop(AST::Binop* node, AST::Expr*& replacement)
{
    if (node->left == nullptr || node->left->GetExprType() != AST::ExprType::Identifier) {
        return AST::Action::None;
    }

    if (node->type < TokenType::Operator_Assignment || node->type > TokenType::Operator_LogicNullishAssignment) {
        return AST::Action::None;
    }

    exprStmtHasSideEffects = true;

    auto var = GetVarValue(((AST::Identifier*) node->left)->name);

    if (var == nullptr) {
        return AST::Action::None;
    }

    if (!var->assignments.empty() && node->type == TokenType::Operator_Assignment) {
        dummy.insert(dummy.end(), var->assignments.begin(), var->assignments.end());
        var->assignments.clear();
    }

    var->assignments.emplace_back(node);
    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
{
    exprStmtHasSideEffects = false;

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnExitExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
{
    if (!exprStmtHasSideEffects) {
        return AST::Action::Remove;
    }

    return AST::Action::None;
}

AST::Action DummyCodeRemover::OnEnterCall(AST::Call* node, AST::Expr*& replacement)
{
    exprStmtHasSideEffects = true;
    return AST::Action::None;
}

DummyCodeRemover::VarInfo* DummyCodeRemover::GetVarValue(std::u16string_view name)
{
    for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
        if (it->find(name) != it->end()) {
            return &(*it)[name];
        }
    }

    return nullptr;
}

std::unordered_map<std::u16string_view, DummyCodeRemover::VarInfo>* DummyCodeRemover::GetVarScope(std::u16string_view name)
{
    for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
        if (it->find(name) != it->end()) {
            return &(*it);
        }
    }

    return nullptr;
}

DummyCodePostRemover::DummyCodePostRemover(std::vector<AST::Node*>& dummy) : dummy(dummy)
{
}

AST::Action DummyCodePostRemover::OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacement)
{
    return CheckDummy(node);
}
AST::Action DummyCodePostRemover::OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
{
    return CheckDummy(node);
}
AST::Action DummyCodePostRemover::OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
{
    return CheckDummy(node);
}
AST::Action DummyCodePostRemover::OnEnterBinop(AST::Binop* node, AST::Expr*& replacement)
{
    return CheckDummy(node);
}

AST::Action DummyCodePostRemover::CheckDummy(AST::Node* node)
{
    auto n = std::find(dummy.begin(), dummy.end(), node);

    if (n != dummy.end()) {
        return AST::Action::Remove;
    }

    return AST::Action::None;
}
} // namespace GView::Type::JS::Transformer