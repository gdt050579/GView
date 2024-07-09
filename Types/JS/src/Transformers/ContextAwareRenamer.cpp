#include "Transformers/ContextAwareRenamer.hpp"

namespace GView::Type::JS::Transformer
{
ContextAwareRenamer::ContextAwareRenamer()
{
    context = Context::Generic;
    vars.emplace_back();
}

AST::Action ContextAwareRenamer::OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
{
    vars.emplace_back();
    context = Context::FunDecl;
    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
{
    context = Context::Generic;

    RenameInfo info;

    info.newName     = GetNextFreeName(u"fun");
    info.initialized = true;

    vars.pop_back();

    vars[vars.size() - 1].map[node->name] = info;
    vars[vars.size() - 1].taken.insert(info.newName);

    node->name = info.newName;

    return AST::Action::Update;
}

AST::Action ContextAwareRenamer::OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
{
    if (node->init) {
        RenameInfo info;

        info.newName     = GetNextFreeName(NameBaseFromExpr(node->init));
        info.initialized = true;

        vars[vars.size() - 1].map[node->name] = info;
        vars[vars.size() - 1].taken.insert(info.newName);

        node->name = info.newName;

        return AST::Action::Update;
    } else {
        RenameInfo info;
        info.initialized = false;
        info.lateReferences.emplace_back(node);

        vars[vars.size() - 1].map[node->name] = info;

        return AST::Action::None;
    }
}
AST::Action ContextAwareRenamer::OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
{
    if (context == Context::FunDecl) {
        RenameInfo info;

        info.newName     = GetNextFreeName(u"param");
        info.initialized = true;

        vars[vars.size() - 1].map[node->name] = info;
        vars[vars.size() - 1].taken.insert(info.newName);

        node->name = info.newName;

        return AST::Action::Update;
    }

    auto block = GetVariableBlock(node->name);

    if (block == nullptr) {
        return AST::Action::None;
    }

    auto info = (*block)[node->name];

    if (info.initialized) {
        node->name = info.newName;
        return AST::Action::Update;
    } else {
        switch (context) {
        case Context::Generic: {
            info.lateReferences.emplace_back(node);
            break;
        }
        case Context::Assignment: {
            node->name = assignmentName;

            info.newName     = assignmentName;
            info.initialized = true;

            vars[vars.size() - 1].taken.insert(assignmentName);

            for (auto node : info.lateReferences) {
                lateRenameNodes[node] = assignmentName;
            }

            info.lateReferences.clear();

            context = Context::Generic;

            return AST::Action::Update;
        }
        }
    }

    return AST::Action::None;
}
AST::Action ContextAwareRenamer::OnEnterBinop(AST::Binop* node, AST::Expr*& replacement)
{
    if (context == Context::Generic && node->type >= TokenType::Operator_Assignment && node->type <= TokenType::Operator_LogicNullishAssignment &&
        node->left->GetExprType() == AST::ExprType::Identifier) {
        context = Context::Assignment;

        // Prepare to rename left
        assignmentName = GetNextFreeName(NameBaseFromExpr(node->right));
    }

    return AST::Action::None;
}
AST::Action ContextAwareRenamer::OnEnterBlock(AST::Block* node, AST::Block*& replacement)
{
    vars.emplace_back();

    if (context == Context::FunDecl) {
        context = Context::Generic;
    }

    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnExitBlock(AST::Block* node, AST::Block*& replacement)
{
    vars.pop_back();
    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}
AST::Action ContextAwareRenamer::OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}
AST::Action ContextAwareRenamer::OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}
AST::Action ContextAwareRenamer::OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}

AST::Action ContextAwareRenamer::OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
{
    return AST::Action::None;
}

// Guess the variable purpose from its initialization expression
const char16_t* ContextAwareRenamer::NameBaseFromExpr(AST::Expr* expr)
{
    switch (expr->GetExprType()) {
    case AST::ExprType::Constant: {
        auto constant = (AST::Constant*) expr;

        switch (constant->GetConstType()) {
        case AST::ConstType::Number: {
            return u"num";
        }
        case AST::ConstType::String: {
            if (((AST::String*) constant)->value.find_first_of(u"\\x") != std::string::npos) {
                return u"buff";
            }
            return u"str";
        }
        }

        break;
    }
    case AST::ExprType::MemberAccess: {
        auto access = (AST::MemberAccess*) expr;

        switch (access->member->GetExprType()) {
        case AST::ExprType::Constant: {
            auto constant = (AST::Constant*) access->member;

            switch (constant->GetConstType()) {
            case AST::ConstType::Number: {
                // Array item
                return u"item";
            }
            case AST::ConstType::String: {
                auto str = ((AST::String*) constant)->value;

                if (str == u"length") {
                    return u"len";
                }
            }
            }
        }
        }
    }
    }

    return u"var";
}

std::u16string ContextAwareRenamer::GetNextFreeName(const char16_t* base)
{
    uint32 i = 1;

    do {
        AppCUI::Utils::UnicodeStringBuilder builder;
        AppCUI::Utils::NumericFormatter fmt;

        builder.Add(base);
        builder.Add(fmt.ToDec(i));

        std::u16string result;
        builder.ToString(result);

        if (!VariableIsTaken(result)) {
            return result;
        }

        i++;
    } while (i < 100000000); // Hard limit; no code will ever have that many vars

    return base;
}

std::unordered_map<std::u16string, ContextAwareRenamer::RenameInfo>* ContextAwareRenamer::GetVariableBlock(std::u16string& name)
{
    for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
        if (it->map.find(name) != it->map.end()) {
            return &(*it).map;
        }
    }

    return nullptr;
}

bool ContextAwareRenamer::VariableIsTaken(std::u16string& name)
{
    for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
        // Renamed
        if (it->taken.find(name) != it->taken.end()) {
            return true;
        }

        // Already in code
        if (it->map.find(name) != it->map.end()) {
            return true;
        }
    }

    return false;
}

ContextAwareLateRenamer::ContextAwareLateRenamer(std::unordered_map<AST::Node*, std::u16string>& lateReferences) : lateReferences(lateReferences)
{
}

AST::Action ContextAwareLateRenamer::OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
{
    auto it = lateReferences.find(node);

    if (it != lateReferences.end()) {
        node->name = (*it).second;
        return AST::Action::Update;
    }

    return AST::Action::None;
}

AST::Action ContextAwareLateRenamer::OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
{
    auto it = lateReferences.find(node);

    if (it != lateReferences.end()) {
        node->name = (*it).second;
        return AST::Action::Update;
    }

    return AST::Action::None;
}
} // namespace GView::Type::JS::Transformer