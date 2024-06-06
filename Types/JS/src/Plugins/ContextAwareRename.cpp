#include "js.hpp"
#include "ast.hpp"

#include <stack>
#include <unordered_set>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view ContextAwareRename::GetName()
{
    return "Context Aware Rename";
}
std::string_view ContextAwareRename::GetDescription()
{
    return "Rename variables.";
}
bool ContextAwareRename::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

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

    ContextAwareRenamer()
    {
        context = Context::Generic;
        vars.emplace_back();
    }

    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        vars.emplace_back();
        context = Context::FunDecl;
        return AST::Action::None;
    }

    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
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

    AST::Action OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
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
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
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
    AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement)
    {
        if (context == Context::Generic && node->type >= TokenType::Operator_Assignment && node->type <= TokenType::Operator_LogicNullishAssignment &&
            node->left->GetExprType() == AST::ExprType::Identifier) {

            context = Context::Assignment;

            // Prepare to rename left
            assignmentName = GetNextFreeName(NameBaseFromExpr(node->right));
        }

        return AST::Action::None;
    }
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.emplace_back();

        if (context == Context::FunDecl) {
            context = Context::Generic;
        }

        return AST::Action::None;
    }

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.pop_back();
        return AST::Action::None;
    }

    AST::Action OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
    {
        return AST::Action::None;
    }
    AST::Action OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
    {
        return AST::Action::None;
    }
    AST::Action OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
    {
        return AST::Action::None;
    }
    AST::Action OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
    {
        return AST::Action::None;
    }

    virtual AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement) override
    {
        return AST::Action::None;
    }

    virtual AST::Action OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement) override
    {
        return AST::Action::None;
    }

    virtual AST::Action OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement) override
    {
        return AST::Action::None;
    }

  private:
    // Guess the variable purpose from its initialization expression
    const char16_t* NameBaseFromExpr(AST::Expr* expr)
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

    std::u16string GetNextFreeName(const char16_t* base)
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

    std::unordered_map<std::u16string, RenameInfo>* GetVariableBlock(std::u16string& name)
    {
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->map.find(name) != it->map.end()) {
                return &(*it).map;
            }
        }

        return nullptr;
    }

    bool VariableIsTaken(std::u16string& name)
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
};

class ContextAwareLateRenamer : public AST::Plugin
{
    std::unordered_map<AST::Node*, std::u16string>& lateReferences;

    public:
    ContextAwareLateRenamer(std::unordered_map<AST::Node*, std::u16string>& lateReferences) : lateReferences(lateReferences)
    {
        
    }

    AST::Action OnExitVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
    {
        auto it = lateReferences.find(node);

        if (it != lateReferences.end()) {
            node->name = (*it).second;
            return AST::Action::Update;
        }

        return AST::Action::None;
    }

    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
    {
        auto it = lateReferences.find(node);

        if (it != lateReferences.end()) {
            node->name = (*it).second;
            return AST::Action::Update;
        }

        return AST::Action::None;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest ContextAwareRename::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    ContextAwareRenamer renamer;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&renamer, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_intermediary.json");
        i.script->AcceptConst(dump);
    }

    // Prepare AST for a second visitor
    i.script->AdjustSourceOffset(0);

    // Late rename
    ContextAwareLateRenamer lateRenamer(renamer.lateRenameNodes);
    visitor = AST::PluginVisitor(&lateRenamer, &data.editor);

    // TODO: instance should also handle the action for the script block
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins