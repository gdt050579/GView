#include "js.hpp"
#include "ast.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view ConstPropagation::GetName()
{
    return "Constant Propagation";
}
std::string_view ConstPropagation::GetDescription()
{
    return "Propagate constants.";
}
bool ConstPropagation::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class ConstPropagator : public AST::Plugin
{
    struct VarInfo {
        AST::Constant* value = nullptr;

        bool allocated = false;
        bool dirty     = false;

        void SetValue(AST::Constant* val, bool wasAllocated)
        {
            if (value != nullptr && allocated) {
                delete value;
            }

            value     = val;
            allocated = wasAllocated;
        }

        AST::Constant* GetValue()
        {
            return value;
        }

        AST::Constant* GetClone()
        {
            return ConstPropagator::Clone(value);
        }

        ~VarInfo()
        {
        }
    };

    bool inAssignment = false;

    std::vector<std::unordered_map<std::u16string_view, VarInfo>> vars;
    std::unordered_set<std::u16string_view> dirty;

    AST::IfStmt* uncertainIf = nullptr; // Unknown condition in IfStmt, so don't propagate further

  public:
    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
    {
        if (node->init && node->init->GetExprType() == AST::ExprType::Constant) {
            auto& entry = vars[vars.size() - 1][node->name];

            entry.SetValue((AST::Constant*) node->init, false);
            entry.dirty = false;
        }

        return AST::Action::None;
    }

    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
    {
        if (inAssignment) {
            inAssignment = false;
            return AST::Action::None;
        }

        auto val = GetVarValue(node->name);

        if (val && !val->dirty) {
            replacement = val->GetClone();
            return AST::Action::Replace;
        }

        return AST::Action::None;
    }

    AST::Action OnEnterIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
    {
        if (node->cond->GetExprType() == AST::ExprType::Constant) {
            auto cond = (AST::Constant*) node->cond;

            auto truthy = (cond->GetConstType() == AST::ConstType::Number && ((AST::Number*) cond)->value != 0) ||
                          (cond->GetConstType() == AST::ConstType::String && ((AST::String*) cond)->value.size() > 0);

            if (!truthy) {
                // if (false)
                return AST::Action::Skip;
            }

            return AST::Action::None;
        }

        // if (unknown)
        uncertainIf = node;

        return AST::Action::None;
    }

    AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
    {
        if (node == uncertainIf) {
            uncertainIf = nullptr;

            for (auto& var : dirty) {
                GetVarValue(var)->dirty = true;
            }

            dirty.clear();
        }

        return AST::Action::None;
    }

    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.emplace_back();
        return AST::Action::None;
    }

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.pop_back();
        return AST::Action::None;
    }

    AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement)
    {
        if (node->type >= TokenType::Operator_Assignment && node->type < TokenType::Operator_LogicNullishAssignment && node->left->GetExprType() == AST::ExprType::Identifier) {
            inAssignment = true;
        }

        return AST::Action::None;
    }

    AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement)
    {
        if (node->left->GetExprType() == AST::ExprType::Identifier && node->right->GetExprType() == AST::ExprType::Constant) {
            auto leftName = ((AST::Identifier*) node->left)->name;
            auto scope    = GetVarScope(leftName);
            auto right    = (AST::Constant*) node->right;

            auto val = GetVarValue(leftName);

            if (node->type == TokenType::Operator_Assignment) {
                switch (right->GetConstType()) {
                case AST::ConstType::Number: {
                    auto rightNum = (AST::Number*) right;

                    (*scope)[leftName].SetValue(rightNum, false);
                    break;
                }
                case AST::ConstType::String: {
                    auto rightStr = (AST::String*) right;

                    (*scope)[leftName].SetValue(rightStr, false);
                    break;
                }
                }
            } else if (node->type >= TokenType::Operator_PlusAssignment && node->type <= TokenType::Operator_LogicNullishAssignment) {
                auto leftVal = GetVarValue(leftName);

                switch (leftVal->value->GetConstType()) {
                case AST::ConstType::Number: {
                    auto leftNum = (AST::Number*) leftVal->value;

                    switch (right->GetConstType()) {
                    case AST::ConstType::Number: {
                        auto rightNum = (AST::Number*) right;

                        auto op = GetOpFromAssignment(node->type);

                        auto result = Eval(leftNum->value, rightNum->value, op);

                        if (result.has_value()) {
                            auto val = new AST::Number(result.value());

                            (*scope)[leftName].SetValue(val, true);
                        }

                        break;
                    }
                    case AST::ConstType::String: {
                        auto rightStr = (AST::String*) right;

                        auto op = GetOpFromAssignment(node->type);

                        auto result = Eval(leftNum->value, rightStr->value, op);

                        if (result.has_value()) {
                            auto val = new AST::String(result.value());

                            (*scope)[leftName].SetValue(val, true);
                        }

                        break;
                    }
                    }
                    break;
                }
                case AST::ConstType::String: {
                    auto leftStr = (AST::String*) leftVal->value;

                    switch (right->GetConstType()) {
                    case AST::ConstType::Number: {
                        auto rightNum = (AST::Number*) right;

                        auto op = GetOpFromAssignment(node->type);

                        auto result = Eval(leftStr->value, rightNum->value, op);

                        if (result.has_value()) {
                            auto val = new AST::String(result.value());

                            (*scope)[leftName].SetValue(val, true);
                        }

                        break;
                    }
                    case AST::ConstType::String: {
                        auto rightStr = (AST::String*) right;

                        auto op = GetOpFromAssignment(node->type);

                        auto result = Eval(leftStr->value, rightStr->value, op);

                        if (result.has_value()) {
                            auto val = new AST::String(result.value());

                            (*scope)[leftName].SetValue(val, true);
                        }

                        break;
                    }
                    }
                }
                }
            } else {
                return AST::Action::None;
            }

            if (uncertainIf != nullptr) {
                // Variable modified in if (unknown)
                // Mark it as dirty when exiting the if block
                dirty.insert(leftName);
            } else {
                val->dirty = false;
            }
        }

        return AST::Action::None;
    }

  private:
    VarInfo* GetVarValue(std::u16string_view name)
    {
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return &(*it)[name];
            }
        }

        return nullptr;
    }

    std::unordered_map<std::u16string_view, VarInfo>* GetVarScope(std::u16string_view name)
    {
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return &(*it);
            }
        }

        return nullptr;
    }

    static AST::Number* Clone(AST::Number* num)
    {
        return new AST::Number(num->value);
    }

    static AST::String* Clone(AST::String* str)
    {
        return new AST::String(str->value);
    }

    static AST::Constant* Clone(AST::Constant* constant)
    {
        switch (constant->GetConstType()) {
        case AST::ConstType::Number: {
            return Clone((AST::Number*) constant);
        }
        case AST::ConstType::String: {
            return Clone((AST::String*) constant);
        }
        }

        return nullptr;
    }

    uint32 GetOpFromAssignment(uint32 op)
    {
        switch (op) {
        case TokenType::Operator_PlusAssignment: {
            return TokenType::Operator_Plus;
        }
        case TokenType::Operator_MinusAssignment: {
            return TokenType::Operator_Minus;
        }
        case TokenType::Operator_MupliplyAssignment: {
            return TokenType::Operator_Multiply;
        }
        case TokenType::Operator_DivisionAssignment: {
            return TokenType::Operator_Division;
        }
        case TokenType::Operator_ModuloAssignment: {
            return TokenType::Operator_Modulo;
        }
        case TokenType::Operator_ExponentiationAssignment: {
            return TokenType::Operator_Exponential;
        }
        case TokenType::Operator_LeftShiftAssignment: {
            return TokenType::Operator_LeftShift;
        }
        case TokenType::Operator_RightShiftAssignment: {
            return TokenType::Operator_RightShift;
        }
        case TokenType::Operator_UnsignedRightShiftAssignment: {
            return TokenType::Operator_SignRightShift;
        }
        case TokenType::Operator_AndAssignment: {
            return TokenType::Operator_AND;
        }
        case TokenType::Operator_XorAssignment: {
            return TokenType::Operator_XOR;
        }
        case TokenType::Operator_OrAssignment: {
            return TokenType::Operator_OR;
        }
        case TokenType::Operator_LogicANDAssignment: {
            return TokenType::Operator_LogicAND;
        }
        case TokenType::Operator_LogicORAssignment: {
            return TokenType::Operator_LogicOR;
        }
        }

        return 0;
    }

    std::optional<int32> Eval(int32 left, int32 right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_LogicOR: {
            return left || right;
        }
        case TokenType::Operator_LogicAND: {
            return left && right;
        }
        case TokenType::Operator_OR: {
            return left | right;
        }
        case TokenType::Operator_XOR: {
            return left ^ right;
        }
        case TokenType::Operator_AND: {
            return left & right;
        }
        case TokenType::Operator_Equal:
        case TokenType::Operator_StrictEqual: {
            return left == right;
        }
        case TokenType::Operator_Different:
        case TokenType::Operator_StrictDifferent: {
            return left != right;
        }
        case TokenType::Operator_Smaller: {
            return left < right;
        }
        case TokenType::Operator_SmallerOrEQ: {
            return left <= right;
        }
        case TokenType::Operator_Bigger: {
            return left > right;
        }
        case TokenType::Operator_BiggerOrEq: {
            return left >= right;
        }
        case TokenType::Operator_LeftShift: {
            return left << right;
        }
        case TokenType::Operator_RightShift: {
            return left >> right;
        }
        case TokenType::Operator_SignRightShift: {
            return left >> right;
        }
        case TokenType::Operator_Plus: {
            return left + right;
        }
        case TokenType::Operator_Minus: {
            return left - right;
        }
        case TokenType::Operator_Multiply: {
            return left * right;
        }
        case TokenType::Operator_Division: {
            if (right == 0) {
                return std::nullopt;
            }
            return left / right;
        }
        case TokenType::Operator_Modulo: {
            if (right == 0) {
                return std::nullopt;
            }
            return left % right;
        }
        case TokenType::Operator_Exponential: {
            return (int32) pow(left, right);
        }
        default: {
            return std::nullopt;
        }
        }
    }

    std::optional<std::u16string> Eval(int32 left, std::u16string_view right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;

            builder.Add(fmt.ToDec(left));
            builder.Add(right);

            std::u16string result;
            builder.ToString(result);

            return result;
        }
        }

        return std::nullopt;
    }

    std::optional<std::u16string> Eval(std::u16string_view left, int32 right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;

            builder.Add(left);
            builder.Add(fmt.ToDec(right));

            std::u16string result;
            builder.ToString(result);

            return result;
        }
        }

        return std::nullopt;
    }

    std::optional<std::u16string> Eval(std::u16string_view left, std::u16string_view right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            std::u16string result;

            result += left;
            result += right;
            return result;
        }
        }

        return std::nullopt;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest ConstPropagation::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    ConstPropagator propagator;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&propagator, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins